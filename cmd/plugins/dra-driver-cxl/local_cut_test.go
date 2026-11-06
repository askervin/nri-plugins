// Copyright The NRI Plugins Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// A process stop inside a Prepare of a claim of the local memdev (a driver
// restart, a kill, a crash) leaves what the Prepare made of its region; the
// next start releases it, or keeps it for the claim when a region of
// another memdev lies above it in the decoders of the host bridge.

const (
	// aboveSerial is the serial of a memdev under the host bridge of the
	// local memdev that the driver does not use: its region, made after
	// the local one, lies above it in the decoders of the host bridge.
	aboveSerial = 0xc100a001
	// errDeviceDax is the failure of the bind of a dax device to
	// device_dax.
	errDeviceDax = "device_dax: enable failed"
)

// plugAbove plugs the memdev aboveSerial under the host bridge of the
// local memdev, unseen by the publisher, and returns its name.
func plugAbove(e *localTestEnv) string {
	return e.k.Plug(fake.MemdevSpec{Serial: aboveSerial})
}

// makeAbove makes a region on the memdev memdev, as another driver does,
// and returns it: it lies above the regions made before it on the ports of
// its host bridge.
func makeAbove(e *localTestEnv, memdev string) string {
	e.t.Helper()
	k := e.k.Kernel()
	d, err := k.RootDecoder(memdev, kernel.RegionRAM)
	noErr(e.t, err)
	region, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionRAM})
	noErr(e.t, err)
	return region
}

// releaseAbove releases a region that makeAbove made.
func releaseAbove(e *localTestEnv, region string) {
	e.t.Helper()
	noErr(e.t, e.k.Kernel().ReleaseRegion(context.Background(), region))
}

// makeAboveAfterCreate makes a region on the memdev memdev right after the
// next cxl create-region of the local memdev: it lies above the local
// region from then on. It returns the function that returns its name.
func makeAboveAfterCreate(e *localTestEnv, memdev string) func() string {
	var region string
	e.k.After("cxl create-region -t ram -d decoder0.0 -m mem0", func() { region = makeAbove(e, memdev) })
	return func() string { return region }
}

// failDeviceDax makes the next bind of a dax device to device_dax fail.
func failDeviceDax(e *localTestEnv) {
	err := errors.New(errDeviceDax)
	e.k.FailWrite("bus/dax/drivers/device_dax/new_id", err)
	e.k.FailWrite("bus/dax/drivers/device_dax/bind", err)
}

// localRegionCount returns how many times the driver created a region on
// the local memdev and destroyed region0.
func localRegionCount(e *localTestEnv) (created, destroyed int) {
	for _, line := range strings.Split(e.commands(), "\n") {
		switch {
		case strings.HasPrefix(line, "cxl create-region ") && strings.Contains(line, " -m mem0"):
			created++
		case line == "cxl destroy-region region0":
			destroyed++
		}
	}
	return created, destroyed
}

// wantLocalRegionCount checks how many times the local memdev got a region
// and region0 was destroyed.
func wantLocalRegionCount(t *testing.T, e *localTestEnv, created, destroyed int) {
	t.Helper()
	if c, d := localRegionCount(e); c != created || d != destroyed {
		t.Fatalf("region created %d and destroyed %d times, expected %d and %d:\n%s", c, d, created, destroyed, e.commands())
	}
}

// wantReleasedLast checks that the last commands of the driver released
// the region.
func wantReleasedLast(t *testing.T, e *localTestEnv, region string) {
	t.Helper()
	if !strings.HasSuffix(e.commands(), "cxl disable-region "+region+"\ncxl destroy-region "+region) {
		t.Fatalf("%s not released:\n%s", region, e.commands())
	}
}

// wantNoRegionRelease checks that no region was disabled or destroyed in
// the commands.
func wantNoRegionRelease(t *testing.T, cmds string) {
	t.Helper()
	if strings.Contains(cmds, "disable-region") || strings.Contains(cmds, "destroy-region") {
		t.Fatalf("a region was released:\n%s", cmds)
	}
}

// wantLocalDevice checks the local memdev in localDevices.json: its region,
// its first dax device ("" while the region is not set up: kept for a claim
// whose Prepare did not finish, until a Prepare sets it up again) and the
// number of uses of each claim (0 for a claim that holds the region without
// a use). No region, no dax device and no claims: the view has no memdev.
func wantLocalDevice(t *testing.T, e *localTestEnv, region, dax string, claims map[string]int) {
	t.Helper()
	d := e.localDevice(localSerial)
	if d == nil {
		if region != "" || dax != "" || len(claims) > 0 {
			t.Fatalf("no local memdev in the view, expected region %q dax %q claims %v", region, dax, claims)
		}
		return
	}
	got := map[string]int{}
	for uid, uses := range d.Claims {
		got[uid] = len(uses)
	}
	if d.Region != region || d.Dax != dax || !maps.Equal(got, claims) {
		t.Fatalf("view: region %q (creating %q) dax %q claims %v, expected %q %q %v", d.Region, d.Creating, d.Dax, got, region, dax, claims)
	}
}

// localPublished returns the local memdev as a scan publishes it now, with
// the regions that are on it in the kernel, nil if it is not published.
func localPublished(e *localTestEnv) *device.Memdev {
	e.t.Helper()
	memdev := e.memdevs[localSerial]
	devs := &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{memdev}}
	for _, r := range e.regions(localSerial) {
		devs.RegionDevices = append(devs.RegionDevices, &nricxl.RegionDevice{Name: r, Size: localRegionSize, Mode: "ram", Node: -1,
			Memories: []*nricxl.MemoryDevice{memdev}})
	}
	infos, err := buildDevInfos(e.config, devs, e.poolSerials, e.s.local.Snapshot())
	noErr(e.t, err)
	if d := infos[localDeviceName]; d != nil {
		m, _ := d.Dev.(*device.Memdev)
		return m
	}
	return nil
}

// cutLocalPrepare runs the Prepare of a claim that the process does not
// finish.
func cutLocalPrepare(t *testing.T, e *localTestEnv, claim *resourcev1.ResourceClaim) {
	t.Helper()
	if !e.cut(func() { _ = e.prepare(claim) }) {
		t.Fatalf("the Prepare of %s was not cut", claim.UID)
	}
}

// prepareKeptSliced prepares a claim whose region is kept for a claim
// after a slice of it was released, within a second: the set-up of the
// kept region does not wait for a dax device bound to a driver.
func prepareKeptSliced(t *testing.T, e *localTestEnv, claim *resourcev1.ResourceClaim) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	noErr(t, e.s.Prepare(ctx, claim))
	e.check("prepared " + string(claim.UID))
}

// localCutPoints are the points where the tests cut the creation of the
// region of the first claim of the local memdev.
var localCutPoints = []struct {
	name string
	cut  func(e *localTestEnv)
}{
	// in the address line probe: enabled, its dax device over all of it
	// bound to device_dax
	{"probe", func(e *localTestEnv) { e.k.CutProbe() }},
	// before the switch to device_dax: bound to kmem, memory offline
	{"kmem", func(e *localTestEnv) { e.k.CutBefore("write bus/dax/drivers/kmem/remove_id dax0.0") }},
	// in the rollback of a failed creation, after its cxl
	// disable-region: disabled, the decoders committed
	{"rollback", func(e *localTestEnv) {
		failDeviceDax(e)
		e.k.CutAfter("cxl disable-region")
	}},
}

// A cut creation of the region of the first claim of the local memdev:
// at the start nothing lies above the region in the decoders, so it is
// released, the memdev is published again, and the Prepare again of the
// claim makes a new region.
func TestLocalCutCreation(t *testing.T) {
	for _, tc := range localCutPoints {
		t.Run(tc.name, func(t *testing.T) {
			e := newLocalTestEnv(t)
			e.start()
			tc.cut(e)
			cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
			if rs := e.regions(localSerial); !slices.Equal(rs, []string{"region0"}) {
				t.Fatalf("regions %v after the cut", rs)
			}
			before := e.k.Commands()
			e.restart()
			if got := e.k.CommandsSince(before); got != "cxl disable-region region0\ncxl destroy-region region0" {
				t.Fatalf("commands at the start:\n%s", got)
			}
			if e.inUse() {
				t.Fatal("memdev in use after the start")
			}
			if localPublished(e) == nil {
				t.Fatal("the local memdev is not published after the start")
			}
			e.mustPrepare(localClaim("u1", localBlockSize))
			wantLocalRegionCount(t, e, 2, 1)
			if got := e.onlineBlocks(); !slices.Equal(got, []int{74}) {
				t.Fatalf("online blocks %v", got)
			}
		})
	}
}

// A cut creation whose region lies below a region of another memdev: its
// release at the start would leave a hole in the decoders. It is kept for
// the claim of the cut Prepare, also by a second start, the memdev is
// published, and the Prepare again of the claim sets the region up again
// (enabled again after a cut rollback, its dax device bound to device_dax,
// probed) and gets its slice; no region is made or destroyed.
func TestLocalCutCreationBelowNewer(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		cut  func(e *localTestEnv)
		// left makes what the cut leaves, after a cut in the probe
		left func(e *localTestEnv)
	}{
		{name: "probe", cut: func(e *localTestEnv) { e.k.CutProbe() }},
		{name: "kmem", cut: func(e *localTestEnv) { e.k.CutBefore("write bus/dax/drivers/kmem/remove_id dax0.0") }},
		// disabled by a cut rollback that began before the region above
		// came
		{name: "disabled", left: func(e *localTestEnv) {
			_, err := e.k.Exec(ctx, "cxl", "disable-region", "region0")
			noErr(t, err)
		}},
		// unbound by a cut driver switch
		{name: "unbound", left: func(e *localTestEnv) { noErr(t, e.k.Kernel().UnbindDax(ctx, "dax0.0")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLocalTestEnv(t)
			other := plugAbove(e)
			e.start()
			if tc.cut != nil {
				tc.cut(e)
			} else {
				e.k.CutProbe()
			}
			cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
			above := makeAbove(e, other)
			if tc.left != nil {
				tc.left(e)
			}
			for range 2 {
				before := e.k.Commands()
				e.restart()
				wantNoRegionRelease(t, e.k.CommandsSince(before))
				wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
				if localPublished(e) == nil {
					t.Fatal("the local memdev is not published after the start")
				}
			}
			e.restart()
			nprobes := len(e.k.Probed())
			e.mustPrepare(localClaim("u1", localBlockSize))
			wantLocalRegionCount(t, e, 1, 0)
			if len(e.k.Probed()) != nprobes+1 {
				t.Fatalf("the kept region was not probed: %v", e.k.Probed())
			}
			if tc.name == "disabled" && !strings.Contains(e.commands(), "cxl enable-region region0") {
				t.Fatalf("region0 not enabled again:\n%s", e.commands())
			}
			wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u1": 1})
			if got := e.onlineBlocks(); !slices.Equal(got, []int{74}) {
				t.Fatalf("online blocks %v", got)
			}
			e.mustUnprepare("u1")
			wantReleasedLast(t, e, "region0")
			releaseAbove(e, above)
		})
	}
}

// The claim of a cut Prepare whose region is kept goes before its Prepare
// again (its pod was deleted): its Unprepare, of a claim that is not
// prepared, releases the region. A region kept for a claim whose region
// above went before its Prepare again is set up again by it, not released
// and made anew.
func TestLocalCutCreationKeptGoes(t *testing.T) {
	e := newLocalTestEnv(t)
	other := plugAbove(e)
	e.start()
	e.k.CutProbe()
	cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
	above := makeAbove(e, other)
	e.restart()
	wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
	e.mustUnprepare("u1")
	wantReleasedLast(t, e, "region0")
	if e.inUse() || e.preparation("u1") != nil {
		t.Fatalf("memdev in use %v, preparation %+v after the Unprepare", e.inUse(), e.preparation("u1"))
	}
	// the region above goes before the Prepare again; the hole that the
	// release of region0 left below it goes with it
	releaseAbove(e, above)
	e.k.CutProbe()
	cutLocalPrepare(t, e, localClaim("u2", localBlockSize))
	above = makeAbove(e, other)
	e.restart()
	wantLocalDevice(t, e, "region0", "", map[string]int{"u2": 0})
	releaseAbove(e, above)
	e.mustPrepare(localClaim("u2", localBlockSize))
	wantLocalRegionCount(t, e, 2, 1)
	wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u2": 1})
	e.mustUnprepare("u2")
	e.wantClean()
}

// The regions of a Prepare cut while it created the region, on a memdev
// that is a pool device at the start, are not touched; a memdev without a
// region, whose creation was cut before cxl create-region, is forgotten
// without commands. A Prepare cut in the probe of its region has made the
// region already: the start releases it.
func TestLocalCutCreationPoolOrNone(t *testing.T) {
	for _, tc := range []struct {
		name string
		cut  func(e *localTestEnv)
	}{
		{"created", func(e *localTestEnv) { e.k.CutAfter("cxl create-region") }},
		{"probe", func(e *localTestEnv) { e.k.CutProbe() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLocalTestEnv(t)
			e.start()
			tc.cut(e)
			cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
			e.poolSerials[localSerial] = true
			before := e.k.Commands()
			e.restart()
			if got := e.k.CommandsSince(before); got != "" {
				t.Fatalf("the regions of a pool device were touched:\n%s", got)
			}
			if e.inUse() {
				t.Fatal("pool device in use")
			}
			if rs := e.regions(localSerial); !slices.Equal(rs, []string{"region0"}) {
				t.Fatalf("regions %v", rs)
			}
		})
	}

	e := newLocalTestEnv(t)
	e.start()
	e.k.CutBefore("cxl create-region")
	cutLocalPrepare(t, e, localClaim("u2", localBlockSize))
	if d := e.localDevice(localSerial); d == nil || d.Region != "" || d.Creating != "region0" || len(d.Claims) != 1 || d.Dax != "" {
		t.Fatalf("view after the cut: %+v", d)
	}
	before := e.k.Commands()
	e.restart()
	if got := e.k.CommandsSince(before); got != "" {
		t.Fatalf("a memdev without a region was touched:\n%s", got)
	}
	if e.inUse() {
		t.Fatal("memdev in use after the start")
	}
}

// A restart without a cut changes nothing: the region and the slices of
// the prepared claims stay, and no command runs; the view names the
// region and its first dax device.
func TestLocalRestartWithoutCut(t *testing.T) {
	e := newLocalTestEnv(t)
	other := plugAbove(e)
	e.start()
	e.mustPrepare(localClaim("u1", localBlockSize))
	makeAbove(e, other)
	e.mustPrepare(localClaim("u2", localBlockSize, localDaxConfig))
	for range 2 {
		before := e.k.Commands()
		e.restart()
		if got := e.k.CommandsSince(before); got != "" {
			t.Fatalf("commands at the start:\n%s", got)
		}
		wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u1": 1, "u2": 1})
	}
	if got := e.onlineBlocks(); !slices.Equal(got, []int{74}) {
		t.Fatalf("online blocks %v", got)
	}
}

// A Prepare cut after its slice was made, before the claim was prepared:
// at the start the slice of the claim is released. Its region is released
// when nothing lies above it, else kept for the claim (not set up), and set
// up and sliced again by its Prepare again. Next to prepared claims the
// region stays for them.
func TestLocalCutAfterSlice(t *testing.T) {
	for _, above := range []bool{false, true} {
		t.Run(map[bool]string{false: "free", true: "below"}[above], func(t *testing.T) {
			e := newLocalTestEnv(t)
			other := plugAbove(e)
			e.start()
			e.k.CutAfter("write devices/system/memory/memory74/state online_movable")
			cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
			if above {
				makeAbove(e, other)
			}
			before := e.k.Commands()
			e.restart()
			if got := e.onlineBlocks(); len(got) > 0 {
				t.Fatalf("online blocks %v after the start", got)
			}
			if !above {
				wantReleasedLast(t, e, "region0")
				if e.inUse() {
					t.Fatal("memdev in use after the start")
				}
				return
			}
			wantNoRegionRelease(t, e.k.CommandsSince(before))
			wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
			prepareKeptSliced(t, e, localClaim("u1", localBlockSize))
			wantLocalRegionCount(t, e, 1, 0)
			if got := e.onlineBlocks(); !slices.Equal(got, []int{74}) {
				t.Fatalf("online blocks %v", got)
			}
		})
	}
	t.Run("prepared claims", func(t *testing.T) {
		e := newLocalTestEnv(t)
		other := plugAbove(e)
		e.start()
		e.mustPrepare(localClaim("u1", localBlockSize))
		makeAbove(e, other)
		e.mustPrepare(localClaim("u2", localBlockSize, localDaxConfig))
		e.k.CutAfter("write devices/system/memory/memory")
		cutLocalPrepare(t, e, localClaim("u3", localBlockSize))
		e.restart()
		wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u1": 1, "u2": 1})
		if p := e.preparation("u3"); p == nil || p.State != state.PreparationPreparing {
			t.Fatalf("preparation of the cut claim %+v", p)
		}
		if got := e.onlineBlocks(); !slices.Equal(got, []int{74}) {
			t.Fatalf("online blocks %v", got)
		}
		wantLocalRegionCount(t, e, 1, 0)
	})
}

// A failed creation of the region of the first claim whose region lies
// below a region of another memdev keeps the region for the claim instead
// of leaving a hole; the Prepare again sets it up. So does a slice that
// fails on a region that the claim's failed Prepare created. The probe of
// a kept region that finds aliasing keeps it again, and it is made smaller
// once nothing lies above it.
func TestLocalFailedCreationBelowNewer(t *testing.T) {
	t.Run("creation", func(t *testing.T) {
		e := newLocalTestEnv(t)
		other := plugAbove(e)
		e.start()
		makeAboveAfterCreate(e, other)
		failDeviceDax(e)
		wantErr(t, e.prepare(localClaim("u1", localBlockSize)), errDeviceDax)
		wantNoRegionRelease(t, e.commands())
		wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
		if p := e.preparation("u1"); p == nil || p.State != state.PreparationKept {
			t.Fatalf("preparation %+v", p)
		}
		e.mustPrepare(localClaim("u1", localBlockSize))
		wantLocalRegionCount(t, e, 1, 0)
	})
	t.Run("slice", func(t *testing.T) {
		e := newLocalTestEnv(t)
		other := plugAbove(e)
		e.start()
		makeAboveAfterCreate(e, other)
		busy := errors.New("busy")
		e.k.FailWrite("devices/system/memory/memory74/state", busy)
		wantErr(t, e.prepare(localClaim("u2", localBlockSize)), "busy")
		wantNoRegionRelease(t, e.commands())
		wantLocalDevice(t, e, "region0", "", map[string]int{"u2": 0})
		prepareKeptSliced(t, e, localClaim("u2", localBlockSize))
		wantLocalRegionCount(t, e, 1, 0)
	})
	t.Run("aliased", func(t *testing.T) {
		e := newLocalTestEnv(t)
		other := plugAbove(e)
		e.start()
		above := makeAboveAfterCreate(e, other)
		failDeviceDax(e)
		wantErr(t, e.prepare(localClaim("u3", localBlockSize)), errDeviceDax)
		e.k.Aliasing = &kernel.Aliasing{Offset: localRegionSize / 2, Garbage: -1}
		wantErr(t, e.prepare(localClaim("u3", localBlockSize)),
			"region0 aliases: it is created again with its first 536870912 bytes only once no region of another memory device lies above it in the decoders")
		wantNoRegionRelease(t, e.commands())
		wantLocalDevice(t, e, "region0", "", map[string]int{"u3": 0})
		releaseAbove(e, above())
		// the memory of the region aliases at every probe
		e.k.Aliasing = &kernel.Aliasing{Offset: localRegionSize / 2, Garbage: -1}
		e.mustPrepare(localClaim("u3", localBlockSize))
		wantLocalRegionCount(t, e, 2, 1)
		if !strings.Contains(e.commands(), "cxl create-region -t ram -d decoder0.0 -m mem0 -s 536870912") {
			t.Fatalf("no smaller region:\n%s", e.commands())
		}
	})
}

// The shared device: a cut creation (in the probe) is released at the
// start and made anew, or kept below a region of another memdev, set up
// and zeroed again by the Prepare again of the claim.
func TestLocalCutSharedCreation(t *testing.T) {
	for _, above := range []bool{false, true} {
		e := newLocalTestEnv(t)
		other := plugAbove(e)
		e.config.SharedDevices = []string{"0xc100e2e1"}
		e.shared[localSerial] = true
		e.start()
		e.k.CutProbe()
		cutLocalPrepare(t, e, localClaim("u1", -1))
		if above {
			makeAbove(e, other)
		}
		before := e.k.Commands()
		e.restart()
		if !above {
			wantReleasedLast(t, e, "region0")
			if e.inUse() {
				t.Fatal("memdev in use after the start")
			}
		} else {
			wantNoRegionRelease(t, e.k.CommandsSince(before))
			wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
		}
		if m := localPublished(e); m == nil || !m.Shared {
			t.Fatalf("above %v: the shared memdev is not published after the start: %+v", above, m)
		}
		e.mustPrepare(localClaim("u1", -1))
		if above {
			wantLocalRegionCount(t, e, 1, 0)
		} else {
			wantLocalRegionCount(t, e, 2, 1)
		}
		if z := e.k.Zeroed(); len(z) != 1 {
			t.Fatalf("above %v: zeroed %v, expected the region once", above, z)
		}
		wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u1": 1})
		if d := e.localDevice(localSerial); !d.Shared {
			t.Fatalf("above %v: view %+v", above, d)
		}
	}
}

// The shared region kept for the claim of a cut Prepare, not set up, stays
// with the idle memdev when that claim is Unprepared while the memdev is
// configured shared, also when nothing lies above it any more and across a
// restart. A new claim then sets it up in its place and zeroes it once; a
// claim after it finds it as it was.
func TestLocalKeptSharedRegionIdle(t *testing.T) {
	for _, tc := range []struct {
		name string
		// gone: the region above goes before the Unprepare
		gone, restart bool
	}{
		{name: "below"},
		{name: "below restarted", restart: true},
		{name: "free", gone: true},
		{name: "free restarted", gone: true, restart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLocalTestEnv(t)
			other := plugAbove(e)
			e.config.SharedDevices = []string{"0xc100e2e1"}
			e.shared[localSerial] = true
			e.start()
			e.k.CutProbe()
			cutLocalPrepare(t, e, localClaim("u1", -1))
			above := makeAbove(e, other)
			e.restart()
			wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
			if tc.gone {
				releaseAbove(e, above)
			}
			before := e.k.Commands()
			e.mustUnprepare("u1")
			if tc.restart {
				e.restart()
			}
			wantNoRegionRelease(t, e.k.CommandsSince(before))
			if p := e.preparation("u1"); p != nil {
				t.Fatalf("preparation %+v after the Unprepare", p)
			}
			wantLocalDevice(t, e, "region0", "", map[string]int{})
			if m := localPublished(e); m == nil || !m.Shared {
				t.Fatalf("the idle shared memdev is not published: %+v", m)
			}
			if z := e.k.Zeroed(); len(z) != 0 {
				t.Fatalf("zeroed %v before a claim got the region", z)
			}
			e.mustPrepare(localClaim("u2", -1))
			wantLocalRegionCount(t, e, 1, 0)
			if z := e.k.Zeroed(); len(z) != 1 {
				t.Fatalf("zeroed %v, expected the region once", z)
			}
			if g := e.grant("u2", 0); g == nil || g.Got.Dax != "dax0.0" || g.Got.Size != localRegionSize {
				t.Fatalf("grant of the new claim %+v, expected dax0.0 of %d bytes", g, localRegionSize)
			}
			wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u2": 1})
			e.mustUnprepare("u2")
			wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{})
			e.mustPrepare(localClaim("u3", -1))
			wantLocalRegionCount(t, e, 1, 0)
			if z := e.k.Zeroed(); len(z) != 1 {
				t.Fatalf("zeroed %v, expected the region once", z)
			}
			e.mustUnprepare("u3")
			if !tc.gone {
				releaseAbove(e, above)
			}
			e.config.SharedDevices = nil
			e.shared = map[uint64]bool{}
			e.restart()
			e.wantClean()
		})
	}
}

// A region that a start kept for the claim of a cut Prepare and that a
// later start does not keep for it any more: that start forgets the claim
// as one whose Prepare did not finish, and the claim holds nothing after
// it (its Unprepare releases nothing, its Prepare again prepares it
// anew). A sliced region whose region above went is released at that
// start; a shared one stays with the idle memdev while the memdev is
// configured shared, and the Prepare again sets it up and zeroes it once.
func TestLocalKeptRegionForgottenAtALaterStart(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "sliced", true: "shared"}[shared], func(t *testing.T) {
			e := newLocalTestEnv(t)
			other := plugAbove(e)
			consumed := int64(localBlockSize)
			if shared {
				e.config.SharedDevices = []string{"0xc100e2e1"}
				e.shared[localSerial] = true
				consumed = -1
			}
			e.start()
			e.k.CutProbe()
			cutLocalPrepare(t, e, localClaim("u1", consumed))
			above := makeAbove(e, other)
			e.restart()
			wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
			if !shared {
				releaseAbove(e, above)
			}
			before := e.k.Commands()
			e.restart()
			if shared {
				wantNoRegionRelease(t, e.k.CommandsSince(before))
				wantLocalDevice(t, e, "region0", "", map[string]int{})
			} else {
				if got := e.k.CommandsSince(before); got != "cxl disable-region region0\ncxl destroy-region region0" {
					t.Fatalf("commands at the later start:\n%s", got)
				}
				wantLocalDevice(t, e, "", "", nil)
			}
			before = e.k.Commands()
			e.mustUnprepare("u1")
			if got := e.k.CommandsSince(before); got != "" {
				t.Fatalf("the Unprepare of the forgotten claim ran commands:\n%s", got)
			}
			if p := e.preparation("u1"); p != nil {
				t.Fatalf("preparation %+v after the Unprepare", p)
			}
			e.mustPrepare(localClaim("u1", consumed))
			if shared {
				wantLocalRegionCount(t, e, 1, 0)
				if z := e.k.Zeroed(); len(z) != 1 {
					t.Fatalf("zeroed %v, expected the region once", z)
				}
			} else {
				wantLocalRegionCount(t, e, 2, 1)
			}
			wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u1": 1})
			e.mustUnprepare("u1")
			if shared {
				releaseAbove(e, above)
				e.config.SharedDevices = nil
				e.shared = map[uint64]bool{}
				e.restart()
			}
			e.wantClean()
		})
	}
}

// A Prepare that fails below a region of another memdev rolls back without
// releasing the region that the claim held alone: it is kept for the
// claim, whose Prepare again reuses it and whose Unprepare releases it. A
// claim whose second result has no device fails before any device is
// touched.
func TestPrepareLocalFailedBelowNewer(t *testing.T) {
	e := newLocalTestEnv(t)
	other := plugAbove(e)
	e.start()
	makeAboveAfterCreate(e, other)
	failDeviceDax(e)
	wantErr(t, e.prepare(localClaim("u1", localBlockSize)), errDeviceDax)
	wantNoRegionRelease(t, e.commands())
	wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
	e.mustPrepare(localClaim("u1", localBlockSize))
	wantLocalRegionCount(t, e, 1, 0)
	e.mustUnprepare("u1")
	wantReleasedLast(t, e, "region0")

	c := localClaim("u2", localBlockSize)
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourcev1.DeviceRequestAllocationResult{Request: "other", Driver: device.DriverName, Pool: testNode, Device: "missing"})
	before := e.k.Commands()
	wantErr(t, e.prepare(c), "could not find allocatable device missing")
	if got := e.k.CommandsSince(before); got != "" {
		t.Fatalf("a refused claim touched the memdev:\n%s", got)
	}
	wantLocalDevice(t, e, "", "", nil)
	if got := e.onlineBlocks(); len(got) > 0 {
		t.Fatalf("online blocks %v", got)
	}
	e.mustUnprepare("u2")
	wantLocalRegionCount(t, e, 1, 1)
	if e.inUse() {
		t.Fatal("memdev in use after the Unprepare")
	}
}

// A kept region is not set up any more, and a cut release may have
// disabled it: the Unprepare of the claim of a kept region, cut after its
// cxl disable-region, leaves the region disabled; a restart keeps it again
// below the newer region (the claim's grant RELEASING), and the Prepares of
// another claim and of the kept claim set it up again (cxl enable-region).
// A kept shared device that is not configured shared any more gets all of
// its region again, zeroed.
func TestLocalKeptRegionSetUpAgain(t *testing.T) {
	for _, tc := range []struct {
		name string
		cut  func(e *localTestEnv)
	}{
		{"probe", func(e *localTestEnv) { e.k.CutProbe() }},
		{"slice", func(e *localTestEnv) { e.k.CutAfter("write devices/system/memory/memory74/state online_movable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLocalTestEnv(t)
			other := plugAbove(e)
			e.start()
			tc.cut(e)
			cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
			makeAbove(e, other)
			e.restart()
			wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
			e.k.CutAfter("cxl disable-region")
			if !e.cut(func() { _ = e.unprepare("u1") }) {
				t.Fatal("the Unprepare was not cut")
			}
			before := e.k.Commands()
			e.restart()
			wantNoRegionRelease(t, e.k.CommandsSince(before))
			// the view lists the use of the releasing grant; the disabled
			// region is not set up
			wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 1})
			if g := e.grant("u1", 0); g == nil || g.State != state.GrantReleasing {
				t.Fatalf("grant of the kept claim %+v", g)
			}
			prepareKeptSliced(t, e, localClaim("u2", localBlockSize))
			if !strings.Contains(e.commands(), "cxl enable-region region0") {
				t.Fatalf("region0 not enabled again:\n%s", e.commands())
			}
			e.mustPrepare(localClaim("u1", localBlockSize, localDaxConfig))
			wantLocalRegionCount(t, e, 1, 0)
			wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u1": 1, "u2": 1})
			if got := e.onlineBlocks(); !slices.Equal(got, []int{74}) {
				t.Fatalf("online blocks %v", got)
			}
		})
	}

	// a shared device that is not configured shared any more, whose last
	// claim fails below a newer region: result 0 is realised, result 1 on
	// a memdev under the other host bridge fails
	e := newLocalTestEnv(t, fake.MemdevSpec{Serial: 0x91, Ram: 512 * mib, HostBridge: 24})
	other := plugAbove(e)
	e.config.SharedDevices = []string{"0xc100e2e1"}
	e.shared[localSerial] = true
	e.start()
	makeAboveAfterCreate(e, other)
	c := localClaim("u1", -1)
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourcev1.DeviceRequestAllocationResult{Request: "other", Driver: device.DriverName, Pool: testNode, Device: memdevDeviceName(0x91)})
	e.k.Before("cxl create-region -t ram -d decoder0.1", func() { e.devices.setShared(nil) })
	e.k.FailCommand("cxl create-region -t ram -d decoder0.1", errors.New("cxl region: cmd_create_region: failed"))
	wantErr(t, e.prepare(c), "cmd_create_region: failed")
	wantNoRegionRelease(t, e.commands())
	wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
	if p := e.preparation("u1"); p == nil || p.State != state.PreparationKept {
		t.Fatalf("preparation %+v", p)
	}
	e.mustPrepare(localClaim("u1", -1))
	g := e.grant("u1", 0)
	if g.Got.Size != localRegionSize || g.Got.Dax != "dax0.0" {
		t.Fatalf("shared device %s of %d bytes, expected dax0.0 of %d", g.Got.Dax, g.Got.Size, localRegionSize)
	}
	if z := e.k.Zeroed(); len(z) != 2 {
		t.Fatalf("zeroed %v, expected the region twice", z)
	}
	wantLocalRegionCount(t, e, 1, 0)
}

// A claim cut after its slice whose slice cannot be released at the first
// try at the start (its memory busy) keeps its preparation (KEPT) and the
// grant with its part for its next release: its Unprepare releases the region
// without a region above, its Prepare again reuses the region below one.
func TestLocalCutAfterSliceOrphaned(t *testing.T) {
	for _, above := range []bool{false, true} {
		e := newLocalTestEnv(t)
		other := plugAbove(e)
		e.start()
		e.k.CutAfter("write devices/system/memory/memory74/state online_movable")
		cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
		if above {
			makeAbove(e, other)
		}
		e.k.FailWrite("devices/system/memory/memory74/state", syscall.EBUSY)
		before := e.k.Commands()
		e.restart()
		wantNoRegionRelease(t, e.k.CommandsSince(before))
		if p := e.preparation("u1"); p == nil || p.State != state.PreparationKept {
			t.Fatalf("above %v: preparation %+v", above, p)
		}
		if g := e.grant("u1", 0); g == nil || g.State != state.GrantRealising {
			t.Fatalf("above %v: grant %+v", above, g)
		}
		// the region stays set up, its first dax device the part that the
		// grant holds
		wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u1": 0})
		if !above {
			e.mustUnprepare("u1")
			wantReleasedLast(t, e, "region0")
			if e.inUse() || len(e.onlineBlocks()) > 0 {
				t.Fatalf("memdev in use %v, online blocks %v after the Unprepare", e.inUse(), e.onlineBlocks())
			}
			continue
		}
		prepareKeptSliced(t, e, localClaim("u1", localBlockSize))
		wantLocalRegionCount(t, e, 1, 0)
		wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u1": 1})
	}
}

// A region of another memdev that comes above the region of the local
// memdev during its release (a pool Prepare on the same host bridge makes
// it between the check and cxl destroy-region) keeps the region, disabled,
// for the claim: in the rollback of a failed creation, and when a new
// region aliases and is released to be made smaller. The next Prepare
// enables it again. A kept region whose region above went is set up again
// by the Prepare again of its claim, not released.
func TestLocalRegionComesAboveInRelease(t *testing.T) {
	for _, tc := range []string{"rollback", "kept", "aliased"} {
		t.Run(tc, func(t *testing.T) {
			e := newLocalTestEnv(t)
			other := plugAbove(e)
			e.start()
			var above string
			comes := func() { above = makeAbove(e, other) }
			if tc == "kept" {
				// u1 is kept below the region above, which then goes
				e.k.CutProbe()
				cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
				first := makeAbove(e, other)
				e.restart()
				wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
				releaseAbove(e, first)
			}
			before := e.k.Commands()
			e.k.Before("cxl disable-region", comes)
			switch tc {
			case "rollback":
				failDeviceDax(e)
				wantErr(t, e.prepare(localClaim("u1", localBlockSize)), errDeviceDax)
			case "aliased":
				e.k.Aliasing = &kernel.Aliasing{Offset: localRegionSize / 2, Garbage: -1}
				wantErr(t, e.prepare(localClaim("u1", localBlockSize)),
					"region0 aliases: it is created again with its first 536870912 bytes only once no region of another memory device lies above it in the decoders")
			default:
				e.mustPrepare(localClaim("u1", localBlockSize))
				wantNoRegionRelease(t, e.k.CommandsSince(before))
				wantLocalDevice(t, e, "region0", "dax0.0", map[string]int{"u1": 1})
				e.k.Before("cxl disable-region", func() {})
				e.mustUnprepare("u1")
				wantReleasedLast(t, e, "region0")
				return
			}
			cmds := e.k.CommandsSince(before)
			if !strings.Contains(cmds, "cxl disable-region region0") || strings.Contains(cmds, "destroy-region") {
				t.Fatalf("expected region0 disabled and not destroyed:\n%s", cmds)
			}
			wantLocalDevice(t, e, "region0", "", map[string]int{"u1": 0})
			e.mustPrepare(localClaim("u1", localBlockSize))
			if !strings.Contains(e.commands(), "cxl enable-region region0") {
				t.Fatalf("region0 not enabled again:\n%s", e.commands())
			}
			wantLocalRegionCount(t, e, 1, 0)
			if above == "" {
				t.Fatal("no region came above")
			}
		})
	}
}

// The creation notes the name of its region before cxl create-region
// runs, and what a cut creation left is that region only: a region on the
// memdev with another name is not the driver's and is not touched (the
// memdev is not published); a region that a cut cxl create-region left
// hollow is deleted. A region cut in its probe is still being created.
func TestLocalCutCreationRecordedRegion(t *testing.T) {
	ctx := context.Background()
	t.Run("noted", func(t *testing.T) {
		e := newLocalTestEnv(t)
		e.start()
		e.k.CutBefore("cxl create-region")
		cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
		if d := e.localDevice(localSerial); d == nil || d.Creating != "region0" || d.Region != "" || d.Dax != "" {
			t.Fatalf("view after the cut: %+v, expected region0 being created", d)
		}
	})
	t.Run("probe", func(t *testing.T) {
		e := newLocalTestEnv(t)
		e.start()
		e.k.CutProbe()
		cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
		d := e.localDevice(localSerial)
		if d == nil || d.Creating != "region0" || d.Region != "" || d.Dax != "" {
			t.Fatalf("view after the cut: %+v, expected region0 being created", d)
		}
	})
	t.Run("other", func(t *testing.T) {
		e := newLocalTestEnv(t)
		e.start()
		e.k.Write("bus/cxl/devices/decoder0.0/create_ram_region", "region5")
		e.k.CutBefore("cxl create-region")
		cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
		if d := e.localDevice(localSerial); d == nil || d.Creating != "region5" {
			t.Fatalf("view after the cut: %+v, expected region5 being created", d)
		}
		_, err := e.k.Exec(ctx, "cxl", "create-region", "-t", "ram", "-d", "decoder0.0", "-m", "mem0")
		noErr(t, err)
		before := e.k.Commands()
		e.restart()
		if got := e.k.CommandsSince(before); got != "" {
			t.Fatalf("a region that the driver did not create was touched:\n%s", got)
		}
		if e.inUse() {
			t.Fatal("memdev in use after the start")
		}
		if m := localPublished(e); m != nil {
			t.Fatalf("a memdev with a region of another creator is published: %+v", m)
		}
	})
	t.Run("hollow", func(t *testing.T) {
		e := newLocalTestEnv(t)
		e.start()
		e.k.CutBefore("cxl create-region")
		cutLocalPrepare(t, e, localClaim("u1", localBlockSize))
		if name := e.k.HollowRegion("decoder0.0", localRegionSize); name != "region0" {
			t.Fatalf("hollow region %s", name)
		}
		before := e.k.Commands()
		e.restart()
		if got := e.k.CommandsSince(before); got != "delete_region decoder0.0 region0" {
			t.Fatalf("commands at the start:\n%s", got)
		}
		if e.inUse() {
			t.Fatal("memdev in use after the start")
		}
		e.mustPrepare(localClaim("u1", localBlockSize))
		wantLocalRegionCount(t, e, 1, 0)
	})
}

// The Unprepare of a claim that the driver does not know returns without
// waiting for the Prepare of another claim, which holds the memdev for long
// when it zeroes a whole shared device.
func TestUnprepareUnknownClaimDoesNotWait(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	entered, release := make(chan struct{}), make(chan struct{})
	e.k.Before("cxl create-region", func() {
		close(entered)
		<-release
	})
	prepared := make(chan error, 1)
	go func() { prepared <- e.s.Prepare(context.Background(), localClaim("u1", localBlockSize)) }()
	<-entered
	done := make(chan error, 1)
	go func() { done <- e.s.Unprepare(context.Background(), "u2") }()
	select {
	case err := <-done:
		close(release)
		noErr(t, err)
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the Unprepare of an unknown claim waits for the Prepare of another claim")
	}
	noErr(t, <-prepared)
	e.mustUnprepare("u1")
	if e.inUse() {
		t.Fatal("memdev in use after the Unprepare")
	}
}
