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
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
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

// wantLocalDevice checks the record of the local memdev: its region, its
// first dax device ("" while the region is not set up: kept for a claim
// whose Prepare did not finish, until a Prepare sets it up again) and the
// number of uses of each claim (localUses). No region, no dax device and no
// claims: no record of the memdev, or one without them.
func wantLocalDevice(t *testing.T, e *localTestEnv, region, dax string, claims map[string]int) {
	t.Helper()
	gotRegion, creating, gotDax := e.localRegion(localSerial)
	got := e.localUses(localSerial)
	if gotRegion != region || gotDax != dax || !maps.Equal(got, claims) {
		t.Fatalf("records: region %q (creating %q) dax %q claims %v, expected %q %q %v", gotRegion, creating, gotDax, got, region, dax, claims)
	}
}

// wantLocalCreating checks that the record of the local memdev has the
// region being made and no region made or set up yet.
func wantLocalCreating(t *testing.T, e *localTestEnv, creating string) {
	t.Helper()
	region, got, dax := e.localRegion(localSerial)
	if region != "" || got != creating || dax != "" {
		t.Fatalf("records after the cut: region %q creating %q dax %q, expected region %s being created", region, got, dax, creating)
	}
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
	noErr(t, prepareOn(ctx, e.s, claim))
	e.check("prepared " + string(claim.UID))
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
	wantLocalCreating(t, e, "region0")
	if uses := e.localUses(localSerial); len(uses) != 1 {
		t.Fatalf("claims after the cut: %v", uses)
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
			// the records keep the use of the releasing grant; the
			// disabled region is not set up
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
	go func() { prepared <- prepareOn(context.Background(), e.s, localClaim("u1", localBlockSize)) }()
	<-entered
	done := make(chan error, 1)
	go func() { done <- unprepareOn(context.Background(), e.s, "u2") }()
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
