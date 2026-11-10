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
	"slices"
	"strconv"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

const (
	localDaxConfig = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"dax"}}`
	localROConfig  = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"dax","readOnly":true}}`
)

// wantNUMABlocks checks that exactly the memory blocks listed exist, all of
// them online movable in the region of the local memdev.
func wantNUMABlocks(e *localTestEnv, blocks ...int) {
	e.t.Helper()
	wantMovable(e, len(blocks))
	(&sliceTestEnv{e}).wantMemoryBlocks(blocks...)
}

// Slices of mode numa and dax of a local memdev share its region: numa
// slices go online movable on the node of the region, a dax slice is a
// devdax device; the region goes with the last slice.
func TestPrepareLocalNUMA(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	// 64Mi is rounded up to a memory block
	e.mustPrepare(localClaim("u1", 64*mib))
	if !e.inUse() {
		t.Fatal("memdev not in use")
	}
	res := e.prepared()["u1"]
	if len(res.Devices) != 1 || !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl=claim-u1-0"}) {
		t.Fatalf("prepared %+v", res.Devices)
	}
	if boot := e.s.ClaimInfo("u1").BootID; boot != e.k.BootID() {
		t.Fatalf("prepared in boot %q", boot)
	}
	// the node of the memory of the region in the kernel
	node := localRegionNode(e)
	if g := e.grant("u1", 0); state.NumaNodeOf(g.Got.NumaNode) != node {
		t.Fatalf("grant %+v, region node %d", g.Got, node)
	}
	e.wantDeviceInfo("u1", PreparedDeviceInfo{
		RequestName: "mem", DeviceName: localDeviceName, DeviceType: device.DeviceTypeMemdev, Mode: api.ModeNUMA,
		SysfsPath: e.k.P("bus/cxl/devices/region0"), NUMANodes: []int{node}, NodeAffinities: []int{0},
		TotalBytes: localBlockSize, ConsumedBytes: localBlockSize, Serial: "0xc100e2e1",
	})
	wantNUMABlocks(e, 74)
	e.wantCDIDevice("claim-u1-0", []string{"CXL_C100E2E1_MODE=numa", "CXL_C100E2E1_NODE=" + strconv.Itoa(node), "CXL_C100E2E1_SERIAL=0xc100e2e1",
		"CXL_C100E2E1_SHARED=0", "CXL_C100E2E1_SIZE=134217728", "CXL_CLAIM_u1_0=1"}, nil)
	// a dax claim on the same device, and another numa claim on the node
	e.mustPrepare(localClaim("u2", localBlockSize, localDaxConfig))
	e.mustPrepare(localClaim("u3", 2*localBlockSize))
	if got := e.s.ClaimInfo("u3").Devices[0]; !slices.Equal(got.NUMANodes, []int{node}) || got.TotalBytes != 2*localBlockSize || got.ConsumedBytes != 2*localBlockSize {
		t.Fatalf("device info %+v", got)
	}
	wantNUMABlocks(e, 74, 76, 77)
	e.mustUnprepare("u1")
	wantNUMABlocks(e, 76, 77)
	e.mustUnprepare("u3")
	wantNUMABlocks(e)
	e.mustUnprepare("u2")
	if e.inUse() || len(e.prepared()) != 0 || len(e.regions(localSerial)) != 0 {
		t.Fatalf("after unprepare: in use %v, prepared %v, regions %v", e.inUse(), e.prepared(), e.regions(localSerial))
	}
	// the whole memdev without consumed capacity
	e.mustPrepare(localClaim("u4", 0))
	if got := e.s.ClaimInfo("u4").Devices[0].ConsumedBytes; got != localRegionSize {
		t.Fatalf("consumed %d", got)
	}
	wantNUMABlocks(e, 74, 75, 76, 77, 78, 79, 80, 81)
	e.mustUnprepare("u4")
	e.wantClean()
	// an unknown claim
	e.mustUnprepare("u1")
}

// A shared local memdev: every claim gets the whole device of its region,
// zeroed once when the region is made; the idle device keeps its region
// while it is configured shared, also across restarts; without the
// configuration a start releases it.
func TestPrepareSharedLocalLifeCycle(t *testing.T) {
	e := newLocalTestEnv(t)
	e.config.SharedDevices = []string{"0xc100e2e1"}
	e.shared[localSerial] = true
	e.start()
	e.mustPrepare(localClaim("u1", -1, localROConfig))
	e.mustPrepare(localClaim("u2", -1, localDaxConfig))
	if z := e.k.Zeroed(); len(z) != 1 {
		t.Fatalf("zeroed %v", z)
	}
	region, _, dax := e.localRegion(localSerial)
	if m := e.localMemdev(localSerial); m == nil || !m.Facts.Shared || region != "region0" || dax != "dax0.0" || len(e.localUses(localSerial)) != 2 {
		t.Fatalf("memdev %+v: region %q dax %q claims %v", m, region, dax, e.localUses(localSerial))
	}
	info := e.s.ClaimInfo("u1").Devices[0]
	if !info.Shared || info.DaxDevice == "" || !info.ReadOnly || info.TotalBytes != localRegionSize {
		t.Fatalf("device info %+v", info)
	}
	e.restart()
	if uses := e.localUses(localSerial); len(uses) != 2 {
		t.Fatalf("claims after the restart: %v", uses)
	}
	e.mustUnprepare("u1")
	e.mustUnprepare("u2")
	region, _, _ = e.localRegion(localSerial)
	if m := e.localMemdev(localSerial); m == nil || !m.Facts.Shared || region != "region0" || len(e.localUses(localSerial)) != 0 {
		t.Fatalf("idle: memdev %+v region %q claims %v", m, region, e.localUses(localSerial))
	}
	e.restart()
	if len(e.regions(localSerial)) != 1 {
		t.Fatal("the idle shared device lost its region at the restart")
	}
	// a new claim finds the region as it was: not zeroed again
	e.mustPrepare(localClaim("u3", -1, localDaxConfig))
	if z := e.k.Zeroed(); len(z) != 1 {
		t.Fatalf("zeroed %v", z)
	}
	e.mustUnprepare("u3")
	e.config.SharedDevices = nil
	e.shared = map[uint64]bool{}
	e.restart()
	e.wantClean()
}

// A persistent local memdev: a writer of mode fs mounts its filesystem
// read-write, a reader of the node shares the node mount, the region goes
// with the last claim.
func TestPrepareLocalPersistentFs(t *testing.T) {
	e := newLocalTestEnv(t, fakeMemdevSpecPmem(0x91))
	e.formatPmem(0x91, "ext4")
	e.config.FsTypes = []string{"ext4"}
	e.start()
	dev := memdevDeviceName(0x91)
	w := memdevClaim("w1", dev, -int64(device.SharesUnlimited), memoryConfig(api.ModeFs, false, ""))
	e.mustPrepare(w)
	info := e.s.ClaimInfo("w1").Devices[0]
	if !info.Persistent || info.Mode != api.ModeFs || info.NodeMount == "" || info.FsType != "ext4" || info.BlockDevice == "" {
		t.Fatalf("device info %+v", info)
	}
	e.restart()
	if p := e.preparation("w1"); p == nil || p.State != "PREPARED" {
		t.Fatalf("after the restart: %+v", p)
	}
	e.mustUnprepare("w1")
	e.wantClean()
}
