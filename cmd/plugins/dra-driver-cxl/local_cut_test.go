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
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/memctl"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// The plugin stops while an Acquire creates the region of the first claim
// of a local memdev (a driver restart cuts a running Prepare, and so do a
// kill and a crash): the region stays on the memdev, and the state has the
// device without it (Region "") with the claim (plan-13 bug-22).

// cut runs fn, which the plugin does not finish: it is killed (errCut)
// where the fakes say (cutBefore, cutAfter, cutProbe), and nothing after
// that runs. The test then starts the allocator again on the same files
// and sysfs.
func cut(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		switch r := recover(); r {
		case errCut:
		case nil:
			t.Fatal("not cut")
		default:
			panic(r)
		}
	}()
	fn()
}

// testContext returns a context for a test that ends after testTimeout:
// a wait that never ends (memctl waits for a dax device bound to a driver)
// fails the test instead of hanging go test.
func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// testTimeout bounds the waits of a test (testContext).
const testTimeout = 20 * time.Second

// cutLocal cuts an Acquire of a numa slice of the local memdev for a
// claim.
func cutLocal(t *testing.T, a *localAllocator, uid string) {
	t.Helper()
	cut(t, func() {
		_, _, _ = a.Acquire(testContext(t), uid, "mem", localSerial, api.ModeNUMA, localBlockSize, false)
	})
}

// published tells whether the local memdev is published, with the regions
// that are on it now as the device scan finds them; shared: configured as a
// shared device.
func (f *fakeLocalSys) published(a *localAllocator, shared ...string) bool {
	memdev := localMemdev()
	devs := &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{memdev}}
	for _, r := range a.mem.Regions("mem0") {
		devs.RegionDevices = append(devs.RegionDevices, &nricxl.RegionDevice{Name: r, Size: f.regionSize, Mode: "ram", Node: -1, Memories: []*nricxl.MemoryDevice{memdev}})
	}
	infos, err := buildDevInfos(&DriverConfig{IgnoreDRAMNodes: true, SharedDevices: shared}, devs, nil, a.Snapshot())
	return err == nil && infos[localDeviceName] != nil
}

// wantDevice checks the record of the local memdev: its region, its first
// dax device and the number of slices of each claim.
func wantDevice(t *testing.T, a *localAllocator, region, dax string, claims map[string]int) {
	t.Helper()
	d := a.devices[localSerial]
	if d == nil {
		t.Fatalf("no record of the local memdev, expected region %q", region)
	}
	got := map[string]int{}
	for uid, s := range d.Claims {
		got[uid] = len(s)
	}
	if d.Region != region || d.Dax != dax || !maps.Equal(got, claims) {
		t.Fatalf("record: region %q dax %q claims %v, expected %q %q %v", d.Region, d.Dax, got, region, dax, claims)
	}
}

// wantNoRelease checks that no region was disabled or destroyed in the
// commands.
func wantNoRelease(t *testing.T, cmds string) {
	t.Helper()
	if strings.Contains(cmds, "disable-region") || strings.Contains(cmds, "destroy-region") {
		t.Fatalf("a region was released:\n%s", cmds)
	}
}

// localCuts are the points where the tests cut the creation of the region
// of the first claim of the local memdev, and the state of the region they
// leave.
var localCuts = []struct {
	name string
	cut  func(f *fakeLocalSys)
}{
	// in the address line probe: enabled, its dax device over all of it
	// bound to device_dax (the replay of bug-22)
	{"probe", func(f *fakeLocalSys) { f.cutProbe = true }},
	// before the switch to device_dax: bound to kmem, memory offline
	{"kmem", func(f *fakeLocalSys) { f.cutBefore = "daxctl reconfigure-device --mode=devdax" }},
	// in the rollback of a failed creation, after its cxl disable-region:
	// disabled, the decoders committed (FR2b)
	{"rollback", func(f *fakeLocalSys) {
		f.failDaxctl = errors.New("daxctl: enable failed")
		f.cutAfter = "cxl disable-region"
	}},
}

// A cut creation of the region of the first claim of the local memdev:
// the state has the claim and no region. At start nothing lies above the
// region in the decoders: the region is released, the memdev is published
// again, and the Prepare again of the claim makes a new region. Before
// bug-22 the start forgot the device and kept the region, and the memdev
// was never published again.
func TestLocalCutCreation(t *testing.T) {
	ctx := testContext(t)
	for _, tc := range localCuts {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeLocalSys(t)
			dir := t.TempDir()
			tc.cut(f)
			cutLocal(t, f.allocator(t, dir), "u1")
			f.failDaxctl = nil
			if rs := f.manager().Regions("mem0"); !slices.Equal(rs, []string{"region0"}) {
				t.Fatalf("regions %v after the cut", rs)
			}
			a := f.allocator(t, dir)
			wantDevice(t, a, "", "", map[string]int{"u1": 0})
			before := f.commands()
			a.Reconcile(ctx, nil, nil)
			if got := f.commandsSince(before); got != "cxl disable-region region0\ncxl destroy-region region0" {
				t.Fatalf("commands at start:\n%s", got)
			}
			wantUsed(t, a, false)
			if !f.published(a) {
				t.Fatal("the local memdev is not published after the start")
			}
			acquire(t, a, "u1", api.ModeNUMA, localBlockSize)
			f.wantRegionCount(t, 2, 1)
			f.wantMemoryBlocks(t, "online_movable", 74)
		})
	}
}

// A cut creation whose region lies below a region of another memdev (of a
// pool Prepare on the same host bridge that ran concurrently): its
// release at start would leave a hole in the decoders. It is kept for the
// claim of the cut Prepare, the memdev is published, and the Prepare again
// of the claim sets the region up as a new one (enabled again after a cut
// rollback, its dax device over all of it bound to device_dax, probed) and
// gets its slice; no region is made or destroyed. Kept again by a second
// restart. A cut driver switch left the dax device unbound: bound again.
func TestLocalCutCreationBelowNewer(t *testing.T) {
	ctx := testContext(t)
	for _, tc := range []struct {
		name string
		cut  func(f *fakeLocalSys)
		// left makes what the cut leaves, after a cut in the probe
		left func(f *fakeLocalSys)
	}{
		{name: "probe", cut: func(f *fakeLocalSys) { f.cutProbe = true }},
		{name: "kmem", cut: func(f *fakeLocalSys) { f.cutBefore = "daxctl reconfigure-device --mode=devdax" }},
		// disabled by a cut rollback that began before region9 came
		{name: "disabled", left: func(f *fakeLocalSys) {
			_, err := f.exec(ctx, "cxl", "disable-region", "region0")
			noErr(t, err)
		}},
		// unbound by a cut driver switch
		{name: "unbound", left: func(f *fakeLocalSys) { f.setDriver("dax0.0", "") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeLocalSys(t)
			f.stackPorts("region0", "region9")
			dir := t.TempDir()
			if tc.cut != nil {
				tc.cut(f)
			} else {
				f.cutProbe = true
			}
			cutLocal(t, f.allocator(t, dir), "u1")
			if tc.left != nil {
				tc.left(f)
			}
			for range 2 {
				a := f.allocator(t, dir)
				before := f.commands()
				a.Reconcile(ctx, nil, nil)
				wantNoRelease(t, f.commandsSince(before))
				wantDevice(t, a, "region0", "", map[string]int{"u1": 0})
				if !f.published(a) {
					t.Fatal("the local memdev is not published after the start")
				}
			}
			a := f.allocator(t, dir)
			a.Reconcile(ctx, nil, nil)
			nprobes := len(f.probed)
			acquire(t, a, "u1", api.ModeNUMA, localBlockSize)
			f.wantRegionCount(t, 1, 0)
			if len(f.probed) != nprobes+1 {
				t.Fatalf("the kept region was not probed: %v", f.probed)
			}
			if tc.name == "disabled" {
				f.wantCommand(t, "cxl enable-region region0")
			}
			wantDevice(t, a, "region0", "dax0.0", map[string]int{"u1": 1})
			f.wantMemoryBlocks(t, "online_movable", 74)
			noErr(t, a.Release(ctx, "u1"))
			f.wantRegionReleased(t, "region0")
		})
	}
}

// The claim of a cut Prepare whose region is kept goes before its Prepare
// again (its pod was deleted): its Unprepare, of a claim that is not
// prepared, releases the region. When the region above is gone before the
// claim's Prepare again, the kept region is released (in order now) and
// made anew.
func TestLocalCutCreationKeptGoes(t *testing.T) {
	ctx := testContext(t)
	e := newLocalTestState(t)
	e.f.stackPorts("region0", "region9")
	dir := filepath.Dir(e.local.stateFile)
	e.f.cutProbe = true
	cut(t, func() { _ = e.Prepare(ctx, localClaim("u1", localBlockSize)) })
	e.local = e.f.allocator(t, dir)
	e.local.Reconcile(ctx, nil, nil)
	wantDevice(t, e.local, "region0", "", map[string]int{"u1": 0})
	e.rescan()
	noErr(t, e.Unprepare(ctx, "u1"))
	e.f.wantRegionReleased(t, "region0")
	if e.inUse() {
		t.Fatal("memdev in use after the Unprepare")
	}
	// the region above goes before the Prepare again
	e.f.cutProbe = true
	cut(t, func() { _ = e.Prepare(ctx, localClaim("u2", localBlockSize)) })
	e.local = e.f.allocator(t, dir)
	e.local.Reconcile(ctx, nil, nil)
	wantDevice(t, e.local, "region0", "", map[string]int{"u2": 0})
	e.f.stackPorts("region0")
	e.rescan()
	noErr(t, e.Prepare(ctx, localClaim("u2", localBlockSize)))
	e.f.wantRegionCount(t, 3, 2)
	wantDevice(t, e.local, "region0", "dax0.0", map[string]int{"u2": 1})
}

// The regions on a memdev that is a pool device now are not touched at
// start, and a memdev without a region is forgotten without commands.
func TestLocalCutCreationPoolOrNone(t *testing.T) {
	ctx := testContext(t)
	f := newFakeLocalSys(t)
	dir := t.TempDir()
	f.cutProbe = true
	cutLocal(t, f.allocator(t, dir), "u1")
	a := f.allocator(t, dir)
	before := f.commands()
	a.Reconcile(ctx, nil, map[uint64]bool{localSerial: true})
	if got := f.commandsSince(before); got != "" {
		t.Fatalf("the regions of a pool device were touched:\n%s", got)
	}
	wantUsed(t, a, false)

	noErr(t, a.mem.ReleaseRegion(ctx, "region0"))
	f.cutBefore = "cxl create-region"
	cutLocal(t, a, "u2")
	a = f.allocator(t, dir)
	wantDevice(t, a, "", "", map[string]int{"u2": 0})
	before = f.commands()
	a.Reconcile(ctx, nil, nil)
	if got := f.commandsSince(before); got != "" {
		t.Fatalf("a memdev without a region was touched:\n%s", got)
	}
	wantUsed(t, a, false)
}

// A restart without a cut changes nothing: the region and the slices of
// the prepared claims stay, and no command runs.
func TestLocalRestartWithoutCut(t *testing.T) {
	ctx := testContext(t)
	f := newFakeLocalSys(t)
	f.stackPorts("region0", "region9")
	dir := t.TempDir()
	a := f.allocator(t, dir)
	acquire(t, a, "u1", api.ModeNUMA, localBlockSize)
	acquire(t, a, "u2", api.ModeDax, localBlockSize)
	for range 2 {
		a = f.allocator(t, dir)
		before := f.commands()
		a.Reconcile(ctx, map[string]bool{"u1": true, "u2": true}, nil)
		if got := f.commandsSince(before); got != "" {
			t.Fatalf("commands at start:\n%s", got)
		}
		wantDevice(t, a, "region0", "dax0.0", map[string]int{"u1": 1, "u2": 1})
	}
	f.wantMemoryBlocks(t, "online_movable", 74)
}

// A Prepare cut after its slice was saved, before the claim was prepared:
// at start the slice of the claim is released. Its region is released when
// nothing lies above it, else kept for the claim (not set up: its dax
// device has no memory), and set up and sliced again by its Prepare again.
func TestLocalCutAfterSlice(t *testing.T) {
	ctx := testContext(t)
	for _, above := range []bool{false, true} {
		f := newFakeLocalSys(t)
		if above {
			f.stackPorts("region0", "region9")
		}
		dir := t.TempDir()
		acquire(t, f.allocator(t, dir), "u1", api.ModeNUMA, localBlockSize)
		a := f.allocator(t, dir)
		before := f.commands()
		a.Reconcile(ctx, nil, nil)
		f.wantMemoryBlocks(t, "")
		if !above {
			f.wantRegionReleased(t, "region0")
			wantUsed(t, a, false)
			continue
		}
		wantNoRelease(t, f.commandsSince(before))
		wantDevice(t, a, "region0", "", map[string]int{"u1": 0})
		acquire(t, a, "u1", api.ModeNUMA, localBlockSize)
		f.wantRegionCount(t, 1, 0)
		f.wantMemoryBlocks(t, "online_movable", 74)
		// with a prepared claim the unprepared one goes
		acquire(t, a, "u2", api.ModeDax, localBlockSize)
		a = f.allocator(t, dir)
		a.Reconcile(ctx, map[string]bool{"u2": true}, nil)
		wantDevice(t, a, "region0", "dax0.0", map[string]int{"u2": 1})
	}
}

// A failed creation of the region of the first claim (in the plugin that
// runs on) whose region lies below a region of another memdev keeps the
// region for the claim instead of leaving a hole; the Prepare again sets
// it up. Without a region above, it is released as before.
func TestLocalFailedCreationBelowNewer(t *testing.T) {
	ctx := testContext(t)
	f := newFakeLocalSys(t)
	f.stackPorts("region0", "region9")
	a := f.allocator(t, t.TempDir())
	f.failDaxctl = errors.New("daxctl: enable failed")
	_, _, err := a.Acquire(ctx, "u1", "mem", localSerial, api.ModeNUMA, localBlockSize, false)
	wantErr(t, err, "enable failed")
	wantNoRelease(t, f.commands())
	wantDevice(t, a, "region0", "", map[string]int{"u1": 0})
	f.failDaxctl = nil
	acquire(t, a, "u1", api.ModeNUMA, localBlockSize)
	f.wantRegionCount(t, 1, 0)

	// a slice that fails on a region that the claim's failed Acquire
	// created: kept too
	noErr(t, a.Release(ctx, "u1"))
	f.fail = map[string]error{"devices/system/memory/memory74/state": errors.New("busy")}
	_, _, err = a.Acquire(ctx, "u2", "mem", localSerial, api.ModeNUMA, localBlockSize, false)
	wantErr(t, err, "busy")
	wantDevice(t, a, "region0", "", map[string]int{"u2": 0})
	acquire(t, a, "u2", api.ModeNUMA, localBlockSize)
	f.wantRegionCount(t, 2, 1)

	// the probe of the kept region finds aliasing: it stays kept, and is
	// made smaller once nothing lies above it
	noErr(t, a.Release(ctx, "u2"))
	f.failDaxctl = errors.New("daxctl: enable failed")
	_, _, err = a.Acquire(ctx, "u3", "mem", localSerial, api.ModeNUMA, localBlockSize, false)
	wantErr(t, err, "enable failed")
	f.failDaxctl = nil
	f.aliasing = &memctl.Aliasing{Offset: f.regionSize / 2, Garbage: -1}
	_, _, err = a.Acquire(ctx, "u3", "mem", localSerial, api.ModeNUMA, localBlockSize, false)
	wantErr(t, err, "region0 aliases: it is created again with its first 536870912 bytes only once")
	wantDevice(t, a, "region0", "", map[string]int{"u3": 0})
	f.stackPorts("region0")
	acquire(t, a, "u3", api.ModeNUMA, localBlockSize)
	f.wantRegionCount(t, 4, 3)
	f.wantCommand(t, "cxl create-region -t ram -d decoder0.0 -m mem0 -s 536870912")
}

// The shared device: a cut creation (in the probe, or in the zeroing of the
// whole device) is released at start and made anew, or kept below a region
// of another memdev, set up and zeroed again by the Prepare again of the
// claim. A leftover device without a region (an older plugin) releases what
// is on the memdev.
func TestLocalCutSharedCreation(t *testing.T) {
	ctx := testContext(t)
	for _, above := range []bool{false, true} {
		f := newFakeLocalSys(t)
		if above {
			f.stackPorts("region0", "region9")
		}
		dir := t.TempDir()
		a := f.allocator(t, dir)
		a.SetShared(map[uint64]bool{localSerial: true})
		f.cutProbe = true
		cut(t, func() { _, _ = a.AcquireShared(ctx, "u1", "mem", localSerial, false, "1 share") })
		a = f.allocator(t, dir)
		a.SetShared(map[uint64]bool{localSerial: true})
		wantDevice(t, a, "", "", map[string]int{"u1": 0})
		before := f.commands()
		a.Reconcile(ctx, nil, nil)
		if !above {
			f.wantRegionReleased(t, "region0")
			wantUse(t, a, nil)
		} else {
			wantNoRelease(t, f.commandsSince(before))
			wantDevice(t, a, "region0", "", map[string]int{"u1": 0})
		}
		if !f.published(a, "mem0") {
			t.Fatal("the shared memdev is not published after the start")
		}
		acquireShared(t, a, "u1", false)
		if above {
			f.wantRegionCount(t, 1, 0)
		} else {
			f.wantRegionCount(t, 2, 1)
		}
		if len(f.zeroed) != 1 {
			t.Fatalf("zeroed %v, expected the region once", f.zeroed)
		}
		wantDevice(t, a, "region0", "dax0.0", map[string]int{"u1": 1})
	}

	// a leftover without a region, with the region of its creation
	f := newFakeLocalSys(t)
	a := f.allocator(t, t.TempDir())
	_, err := f.exec(ctx, "cxl", "create-region", "-t", "ram", "-d", "decoder0.0", "-m", "mem0")
	noErr(t, err)
	a.devices[localSerial] = &localDevice{Serial: localSerial, SerialHex: "c100e2e1", Memdev: "mem0", Node: -1, Shared: true, Claims: map[string][]*localSlice{}}
	acquireShared(t, a, "u1", false)
	f.wantRegionCount(t, 2, 1)
	// and of a sliced device
	noErr(t, a.Release(ctx, "u1"))
	a.SetShared(nil)
	noErr(t, a.Release(ctx, "u1"))
	noErr(t, a.mem.ReleaseRegion(ctx, "region0"))
	_, err = f.exec(ctx, "cxl", "create-region", "-t", "ram", "-d", "decoder0.0", "-m", "mem0")
	noErr(t, err)
	a.devices[localSerial] = &localDevice{Serial: localSerial, SerialHex: "c100e2e1", Memdev: "mem0", Node: -1, Claims: map[string][]*localSlice{}}
	acquire(t, a, "u2", api.ModeNUMA, localBlockSize)
	f.wantRegionCount(t, 4, 3)
}

// A Prepare that fails below a region of another memdev (in its local
// Acquire, or after it: a missing second device) rolls back without
// releasing the region that the claim held alone: it is kept for the
// claim, whose Prepare again reuses it and whose Unprepare, of a claim
// that is not prepared, releases it.
func TestPrepareLocalFailedBelowNewer(t *testing.T) {
	ctx := testContext(t)
	e := newLocalTestState(t)
	e.f.stackPorts("region0", "region9")
	e.f.failDaxctl = errors.New("daxctl: enable failed")
	wantErr(t, e.Prepare(ctx, localClaim("u1", localBlockSize)), "enable failed")
	e.f.failDaxctl = nil
	wantNoRelease(t, e.f.commands())
	wantDevice(t, e.local, "region0", "", map[string]int{"u1": 0})
	noErr(t, e.Prepare(ctx, localClaim("u1", localBlockSize)))
	e.f.wantRegionCount(t, 1, 0)
	noErr(t, e.Unprepare(ctx, "u1"))
	e.f.wantRegionReleased(t, "region0")

	c := localClaim("u2", localBlockSize)
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourcev1.DeviceRequestAllocationResult{Request: "other", Driver: device.DriverName, Pool: testNode, Device: "missing"})
	wantErr(t, e.Prepare(ctx, c), "could not find allocatable device missing")
	wantDevice(t, e.local, "region0", "", map[string]int{"u2": 0})
	e.f.wantMemoryBlocks(t, "")
	noErr(t, e.Unprepare(ctx, "u2"))
	e.f.wantRegionReleased(t, "region0")
	e.f.wantRegionCount(t, 2, 2)
	if e.inUse() {
		t.Fatal("memdev in use after the Unprepare")
	}
}

// A kept region is not set up any more: its first dax device has no
// memory, and a cut release may have disabled it. The Unprepare of the
// claim of a kept region, cut after its cxl disable-region, leaves the
// region disabled; a restart keeps it again below the newer region, and
// the Acquires of another claim and of the kept claim set it up again
// (cxl enable-region). Before, the kept region had its dax device in the
// record, and every Acquire on the memdev failed on the missing dax
// region. A kept shared device gets all of its region again, zeroed.
func TestLocalKeptRegionSetUpAgain(t *testing.T) {
	ctx := testContext(t)
	f := newFakeLocalSys(t)
	f.stackPorts("region0", "region9")
	dir := t.TempDir()
	acquire(t, f.allocator(t, dir), "u1", api.ModeNUMA, localBlockSize)
	a := f.allocator(t, dir)
	a.Reconcile(ctx, nil, nil)
	wantDevice(t, a, "region0", "", map[string]int{"u1": 0})
	f.cutAfter = "cxl disable-region"
	cut(t, func() { _ = a.Release(ctx, "u1") })
	a = f.allocator(t, dir)
	before := f.commands()
	a.Reconcile(ctx, nil, nil)
	wantNoRelease(t, f.commandsSince(before))
	wantDevice(t, a, "region0", "", map[string]int{"u1": 0})
	acquire(t, a, "u2", api.ModeNUMA, localBlockSize)
	f.wantCommand(t, "cxl enable-region region0")
	acquire(t, a, "u1", api.ModeDax, localBlockSize)
	f.wantRegionCount(t, 1, 0)
	wantDevice(t, a, "region0", "dax0.0", map[string]int{"u1": 1, "u2": 1})
	f.wantMemoryBlocks(t, "online_movable", 74)

	// a shared device that is not configured shared any more, whose
	// last claim fails below a newer region
	f = newFakeLocalSys(t)
	f.stackPorts("region0", "region9")
	a = f.allocator(t, t.TempDir())
	acquireShared(t, a, "u1", false)
	a.SetShared(nil)
	noErr(t, a.ReleaseFailed(ctx, "u1"))
	wantNoRelease(t, f.commands())
	wantDevice(t, a, "region0", "", map[string]int{"u1": 0})
	s := acquireShared(t, a, "u1", false)
	if s.Size != localRegionSize || s.Dax != "dax0.0" {
		t.Fatalf("shared slice %s of %d bytes, expected dax0.0 of %d", s.Dax, s.Size, localRegionSize)
	}
	if len(f.zeroed) != 2 {
		t.Fatalf("zeroed %v, expected the region twice", f.zeroed)
	}
	f.wantRegionCount(t, 1, 0)
}

// A claim that is not prepared at start and whose slice cannot be released
// at the first try (its slice goes to orphanOwner, released again right
// away) still holds its region: kept below a newer region, released
// without one. Before, the claim was forgotten, and the region was released
// below the newer one.
func TestLocalCutAfterSliceOrphaned(t *testing.T) {
	ctx := testContext(t)
	for _, above := range []bool{false, true} {
		f := newFakeLocalSys(t)
		if above {
			f.stackPorts("region0", "region9")
		}
		dir := t.TempDir()
		acquire(t, f.allocator(t, dir), "u1", api.ModeNUMA, localBlockSize)
		f.failSeq = map[string][]error{blockPath(74) + "/state": {syscall.EBUSY}}
		a := f.allocator(t, dir)
		before := f.commands()
		a.Reconcile(ctx, nil, nil)
		f.wantMemoryBlocks(t, "")
		if !above {
			f.wantRegionReleased(t, "region0")
			wantUsed(t, a, false)
			continue
		}
		wantNoRelease(t, f.commandsSince(before))
		wantDevice(t, a, "region0", "", map[string]int{"u1": 0})
		acquire(t, a, "u1", api.ModeNUMA, localBlockSize)
		f.wantRegionCount(t, 1, 0)
	}
}

// A region of another memdev that comes above the region of the local
// memdev during its release (a pool Prepare on the same host bridge
// creates it between the first check and cxl destroy-region) keeps the
// region, disabled, for the claim: in the rollback of a failed creation;
// when the Prepare again of a kept claim releases the kept region because
// nothing lay above it; when a new region aliases and is released to be
// made smaller. The next Acquire enables it again.
func TestLocalRegionComesAboveInRelease(t *testing.T) {
	ctx := testContext(t)
	for _, tc := range []string{"rollback", "kept", "aliased"} {
		t.Run(tc, func(t *testing.T) {
			f := newFakeLocalSys(t)
			dir := t.TempDir()
			comes := func() { f.stackPorts("region0", "region9") }
			a := f.allocator(t, dir)
			if tc == "kept" {
				// u1 is kept below region9, which then goes
				f.stackPorts("region0", "region9")
				f.cutProbe = true
				cutLocal(t, a, "u1")
				a = f.allocator(t, dir)
				a.Reconcile(ctx, nil, nil)
				wantDevice(t, a, "region0", "", map[string]int{"u1": 0})
				f.stackPorts("region0")
			}
			before := f.commands()
			f.before = map[string]func(){"cxl disable-region": comes}
			switch tc {
			case "rollback":
				f.failDaxctl = errors.New("daxctl: enable failed")
				_, _, err := a.Acquire(ctx, "u1", "mem", localSerial, api.ModeNUMA, localBlockSize, false)
				wantErr(t, err, "enable failed")
				f.failDaxctl = nil
			case "aliased":
				f.aliasing = &memctl.Aliasing{Offset: f.regionSize / 2, Garbage: -1}
				_, _, err := a.Acquire(ctx, "u1", "mem", localSerial, api.ModeNUMA, localBlockSize, false)
				wantErr(t, err, "region0 aliases: it is created again with its first 536870912 bytes only once")
			default:
				// region9 comes again during the release of the
				// kept region: set up again for u1 instead
				acquire(t, a, "u1", api.ModeNUMA, localBlockSize)
				f.wantCommand(t, "cxl enable-region region0")
				wantDevice(t, a, "region0", "dax0.0", map[string]int{"u1": 1})
				noErr(t, a.Release(ctx, "u1"))
				f.wantRegionReleased(t, "region0")
				return
			}
			cmds := f.commandsSince(before)
			if !strings.Contains(cmds, "cxl disable-region region0") || strings.Contains(cmds, "destroy-region") {
				t.Fatalf("expected region0 disabled and not destroyed:\n%s", cmds)
			}
			wantDevice(t, a, "region0", "", map[string]int{"u1": 0})
			acquire(t, a, "u1", api.ModeNUMA, localBlockSize)
			f.wantCommand(t, "cxl enable-region region0")
			f.wantRegionCount(t, 1, 0)
		})
	}
}

// The creation records the name of its region before cxl create-region
// runs (Creating), and what a cut creation left is that region only: a
// region on the memdev with another name is not the plugin's and is not
// touched; a region that a cut cxl create-region left hollow is deleted.
// The one region that the creation left is taken as a region kept for its
// claim also by an Acquire without a start in between (adopt it, set it up
// below a newer region instead of releasing it).
func TestLocalCutCreationRecordedRegion(t *testing.T) {
	ctx := testContext(t)

	// recorded, and released at start
	f := newFakeLocalSys(t)
	dir := t.TempDir()
	f.cutProbe = true
	cutLocal(t, f.allocator(t, dir), "u1")
	if d := f.allocator(t, dir).devices[localSerial]; d == nil || d.Creating != "region0" || d.Region != "" {
		t.Fatalf("record after the cut: %+v, expected region0 being created", d)
	}

	// another region than the recorded one
	f = newFakeLocalSys(t)
	dir = t.TempDir()
	f.write("bus/cxl/devices/decoder0.0/create_ram_region", "region5")
	f.cutBefore = "cxl create-region"
	cutLocal(t, f.allocator(t, dir), "u1")
	_, err := f.exec(ctx, "cxl", "create-region", "-t", "ram", "-d", "decoder0.0", "-m", "mem0")
	noErr(t, err)
	a := f.allocator(t, dir)
	before := f.commands()
	a.Reconcile(ctx, nil, nil)
	if got := f.commandsSince(before); got != "" {
		t.Fatalf("a region that the plugin did not create was touched:\n%s", got)
	}
	wantUsed(t, a, false)
	if f.published(a) {
		t.Fatal("a memdev with a region of another creator is published")
	}

	// hollow
	f = newFakeLocalSys(t)
	dir = t.TempDir()
	f.cutBefore = "cxl create-region"
	cutLocal(t, f.allocator(t, dir), "u1")
	f.hollowRegion("region0", "ram")
	a = f.allocator(t, dir)
	before = f.commands()
	a.Reconcile(ctx, nil, nil)
	if got := f.commandsSince(before); got != "delete_region decoder0.0 region0" {
		t.Fatalf("commands at start:\n%s", got)
	}
	wantUsed(t, a, false)
	acquire(t, a, "u1", api.ModeNUMA, localBlockSize)
	f.wantRegionCount(t, 1, 0)

	// an Acquire of a record that still has the region being created
	f = newFakeLocalSys(t)
	f.stackPorts("region0", "region9")
	dir = t.TempDir()
	f.cutProbe = true
	cutLocal(t, f.allocator(t, dir), "u1")
	a = f.allocator(t, dir)
	acquire(t, a, "u1", api.ModeNUMA, localBlockSize)
	f.wantRegionCount(t, 1, 0)
	wantDevice(t, a, "region0", "dax0.0", map[string]int{"u1": 1})
}

// The Unprepare of a claim that the local allocator does not know returns
// without waiting for an Acquire of another claim, which holds the
// allocator for long when it zeroes a whole shared device.
func TestUnprepareUnknownClaimDoesNotWait(t *testing.T) {
	ctx := testContext(t)
	e := newLocalTestState(t)
	noErr(t, e.Prepare(ctx, localClaim("u1", localBlockSize)))
	e.local.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- e.Unprepare(ctx, "u2") }()
	select {
	case err := <-done:
		e.local.mu.Unlock()
		noErr(t, err)
	case <-time.After(5 * time.Second):
		e.local.mu.Unlock()
		t.Fatal("the Unprepare of an unknown claim waits for the local allocator")
	}
	noErr(t, e.Unprepare(ctx, "u1"))
	if e.inUse() {
		t.Fatal("memdev in use after the Unprepare")
	}
}
