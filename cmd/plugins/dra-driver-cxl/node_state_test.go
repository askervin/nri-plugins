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
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// localOtherSerial is a second local memdev of RAM, under host bridge 24.
const localOtherSerial = 0xc100e2e3

// The scan publishes free and used local memdevs of at least a memory block
// of a known size, not pooled, ignored or disabled ones.
func TestBuildDevInfosLocalMemdevs(t *testing.T) {
	memdev := func(name string, serial uint64) *nricxl.MemoryDevice {
		return &nricxl.MemoryDevice{Name: name, DevName: "cxl/" + name, RamSize: 1 << 30, Serial: serial, NodeAffinity: -1, Enabled: true}
	}
	free, foreign, pooled, ignored, used := memdev("mem1", 0xa1), memdev("mem2", 0xa2), memdev("mem3", 0xa3), memdev("mem4", 0xa4), memdev("mem5", 0xa5)
	free.NodeAffinity = 1
	disabled, noRAM := memdev("mem6", 0xa6), memdev("mem7", 0xa7)
	disabled.Enabled = false
	noRAM.RamSize = 0
	region := func(name string, node int, mem *nricxl.MemoryDevice) *nricxl.RegionDevice {
		return &nricxl.RegionDevice{Name: name, Size: 1 << 30, Mode: "ram", Node: node, Enabled: true, Memories: []*nricxl.MemoryDevice{mem}}
	}
	devices := &nricxl.Devices{
		MemoryDevices: []*nricxl.MemoryDevice{free, foreign, pooled, ignored, used, disabled, noRAM},
		RegionDevices: []*nricxl.RegionDevice{region("region0", 2, foreign), region("region1", 3, used)},
		MemoryNodes:   []*nricxl.MemoryNode{{ID: 0, Size: 1 << 30}, {ID: 2, Size: 1 << 30}, {ID: 3, Size: 1 << 30}},
	}
	cfg := &DriverConfig{IgnoreDevices: []string{"0xa4"}}
	local := &localSnapshot{Uses: map[uint64]localUse{0xa5: {}}, BlockSize: localBlockSize}
	devInfos, err := buildDevInfos(cfg, devices, map[uint64]bool{0xa3: true}, local)
	noErr(t, err)
	got := slices.Sorted(maps.Keys(devInfos))
	want := []string{"dram", "memdev-a1", "memdev-a5", "region0-node2"}
	if !slices.Equal(got, want) {
		t.Fatalf("published %v, expected %v", got, want)
	}
	for name, d := range devInfos {
		if d.Name != name {
			t.Fatalf("device %s named %s", name, d.Name)
		}
	}
	if m, ok := devInfos["memdev-a1"].Dev.(*device.Memdev); !ok || *m != (device.Memdev{Name: "mem1", Serial: 0xa1, Size: 1 << 30, NodeAffinity: 1, BlockSize: localBlockSize}) {
		t.Fatalf("free memdev %+v", devInfos["memdev-a1"].Dev)
	}
	if _, ok := devInfos["memdev-a5"].Dev.(*device.Memdev); !ok {
		t.Fatalf("used memdev %+v", devInfos["memdev-a5"].Dev)
	}
	// memdevs smaller than a block, or an unknown block size: none
	free.RamSize = localBlockSize - 2*mib
	devInfos, err = buildDevInfos(cfg, devices, map[uint64]bool{0xa3: true}, local)
	noErr(t, err)
	if _, ok := devInfos["memdev-a1"]; ok {
		t.Fatal("a memdev smaller than a memory block published")
	}
	free.RamSize = localBlockSize
	// a block of 512 MiB is not sure to fit 512 MiB
	devInfos, err = buildDevInfos(cfg, devices, map[uint64]bool{0xa3: true}, &localSnapshot{Uses: local.Uses, BlockSize: localBlockSize * 4})
	noErr(t, err)
	if _, ok := devInfos["memdev-a1"]; ok {
		t.Fatal("a memdev of one large block published")
	}
	m, ok := devInfos["memdev-a5"].Dev.(*device.Memdev)
	if !ok {
		t.Fatalf("used memdev %+v", devInfos["memdev-a5"])
	}
	if c := localMemdevDevice("x", m).Capacity["memory"]; c.Value.Value() != 512*mib {
		t.Fatalf("capacity %v of a 1 GiB memdev with 512 MiB blocks", c.Value)
	}
	devInfos, err = buildDevInfos(cfg, devices, map[uint64]bool{0xa3: true}, &localSnapshot{Uses: local.Uses})
	noErr(t, err)
	if got := slices.Sorted(maps.Keys(devInfos)); !slices.Equal(got, []string{"dram", "region0-node2"}) {
		t.Fatalf("published %v without a block size", got)
	}
	// the node of the plugin's region is not DRAM
	if dram, ok := devInfos["dram"].Dev.(*device.DRAM); !ok || !slices.Equal(dram.Nodes, []int{0}) {
		t.Fatalf("DRAM %+v", devInfos["dram"].Dev)
	}

	// manageMemdevs: false publishes regions only
	cfg.ManageMemdevs = ptr(false)
	devInfos, err = buildDevInfos(cfg, devices, map[uint64]bool{0xa3: true}, nil)
	noErr(t, err)
	if got := slices.Sorted(maps.Keys(devInfos)); !slices.Equal(got, []string{"dram", "region0-node2", "region1-node3"}) {
		t.Fatalf("published %v without managed memdevs", got)
	}
}

// The published device of a local memdev: its attributes, its capacity
// with the request policy of memory blocks, no nodeAffinity when unknown.
func TestGetResourcesLocalMemdev(t *testing.T) {
	devs, err := buildDevInfos(&DriverConfig{IgnoreDRAMNodes: true}, &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{localMemdev()}}, nil, &localSnapshot{BlockSize: localBlockSize})
	noErr(t, err)
	s := &nodeState{baseState: &baseState{Allocatable: devs, NodeName: testNode}}
	got := s.GetResources().Pools[testNode].Slices[0].Devices
	q := func(v int64) *resource.Quantity { return resource.NewQuantity(v, resource.BinarySI) }
	want := []resourcev1.Device{{
		Name: localDeviceName,
		Attributes: map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
			"type":            {StringValue: ptr("memdev")},
			"source":          {StringValue: ptr("local")},
			"serial":          {StringValue: ptr("0xc100e2e1")},
			"shared":          {BoolValue: ptr(false)},
			"persistent":      {BoolValue: ptr(false)},
			"size":            {IntValue: ptr(int64(localRegionSize))},
			"nodeAffinity":    {IntValue: ptr(int64(0))},
			"memoryBlockSize": {IntValue: ptr(int64(134217728))},
		},
		Capacity: map[resourcev1.QualifiedName]resourcev1.DeviceCapacity{
			"memory": {
				Value: *q(localRegionSize),
				RequestPolicy: &resourcev1.CapacityRequestPolicy{
					Default:    q(localRegionSize),
					ValidRange: &resourcev1.CapacityRequestPolicyRange{Min: q(134217728), Step: q(134217728)},
				},
			},
		},
		NodeAllocatableResources: memoryNodeAllocatableResources(),
		AllowMultipleAllocations: ptr(true),
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("published\n%+v\nexpected\n%+v", got, want)
	}
	if p := got[0].Capacity["memory"].RequestPolicy; p.Default.String() != "1Gi" || p.ValidRange.Min.String() != "128Mi" || p.ValidRange.Step.String() != "128Mi" {
		t.Fatalf("request policy %v %v %v", p.Default, p.ValidRange.Min, p.ValidRange.Step)
	}
	// no nodeAffinity when unknown
	d := localMemdevDevice("x", &device.Memdev{Size: localRegionSize, NodeAffinity: -1, BlockSize: localBlockSize})
	if _, ok := d.Attributes["nodeAffinity"]; ok {
		t.Fatalf("memdev %+v", d)
	}
}

// The devices of regions, DRAM and the lease device: every memory device
// has type, source and size.
func TestGetResourcesRegionDRAMLease(t *testing.T) {
	mem := func(affinity int) *nricxl.MemoryDevice {
		return &nricxl.MemoryDevice{Serial: 1, NodeAffinity: affinity, Enabled: true}
	}
	devices := &nricxl.Devices{
		RegionDevices: []*nricxl.RegionDevice{
			{Name: "region0", Size: 2 << 30, Mode: "ram", Node: 2, Enabled: true, Memories: []*nricxl.MemoryDevice{mem(0), mem(0)}},
			{Name: "region1", Size: 1 << 30, Mode: "ram", Node: 3, Enabled: true, Memories: []*nricxl.MemoryDevice{mem(0), mem(1)}},
		},
		MemoryNodes: []*nricxl.MemoryNode{{ID: 0, Size: 1 << 30}, {ID: 1, Size: 1 << 30}, {ID: 2, Size: 2 << 30}, {ID: 3, Size: 1 << 30}},
	}
	devs, err := buildDevInfos(&DriverConfig{PublishLeaseDevice: true, ManageMemdevs: ptr(false)}, devices, nil, nil)
	noErr(t, err)
	s := &nodeState{baseState: &baseState{Allocatable: devs, NodeName: testNode}}
	got := map[string]resourcev1.Device{}
	for _, d := range s.GetResources().Pools[testNode].Slices[0].Devices {
		got[d.Name] = d
	}
	if names := slices.Sorted(maps.Keys(got)); !slices.Equal(names, []string{"dram", "lease", "region0-node2", "region1-node3"}) {
		t.Fatalf("published %v", names)
	}
	wantAttrs := map[string]map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{
		"region0-node2": {"type": {StringValue: ptr("region")}, "source": {StringValue: ptr("local")}, "node": {IntValue: ptr(int64(2))},
			"size": {IntValue: ptr(int64(2 << 30))}, "nodeAffinity": {IntValue: ptr(int64(0))}},
		// the memdevs of the region do not agree: no nodeAffinity
		"region1-node3": {"type": {StringValue: ptr("region")}, "source": {StringValue: ptr("local")}, "node": {IntValue: ptr(int64(3))},
			"size": {IntValue: ptr(int64(1 << 30))}},
		"dram": {"type": {StringValue: ptr("dram")}, "source": {StringValue: ptr("local")}, "nodes": {StringValue: ptr("0-1")},
			"size": {IntValue: ptr(int64(2 << 30))}},
		"lease": {"type": {StringValue: ptr("lease")}},
	}
	for name, want := range wantAttrs {
		if !reflect.DeepEqual(got[name].Attributes, want) {
			t.Errorf("%s: attributes %+v, expected %+v", name, got[name].Attributes, want)
		}
	}
	for _, name := range []string{"region0-node2", "region1-node3", "dram"} {
		d := got[name]
		c := d.Capacity["memory"]
		if c.Value.Value() != *d.Attributes["size"].IntValue || d.NodeAllocatableResources == nil || !*d.AllowMultipleAllocations {
			t.Errorf("%s: capacity %+v", name, d)
		}
	}
	if l := got["lease"]; l.Capacity != nil || !*l.AllowMultipleAllocations {
		t.Errorf("lease device %+v", l)
	}
	if _, ok := regionNodeAffinity(&nricxl.RegionDevice{Memories: []*nricxl.MemoryDevice{mem(-1)}}); ok {
		t.Error("an unknown affinity is published")
	}
}

// The request policy of a local memdev: steps of the memory block size,
// the whole device (its blocks) by default.
func TestLocalRequestPolicy(t *testing.T) {
	q := func(v int64) *resource.Quantity { return resource.NewQuantity(v, resource.BinarySI) }
	for _, tc := range []struct {
		size, bs uint64
		want     *resourcev1.CapacityRequestPolicy
	}{
		{localRegionSize, localBlockSize, &resourcev1.CapacityRequestPolicy{Default: q(localRegionSize),
			ValidRange: &resourcev1.CapacityRequestPolicyRange{Min: q(localBlockSize), Step: q(localBlockSize)}}},
		// rounded down to whole blocks
		{localRegionSize + 64*mib, localBlockSize, &resourcev1.CapacityRequestPolicy{Default: q(localRegionSize),
			ValidRange: &resourcev1.CapacityRequestPolicyRange{Min: q(localBlockSize), Step: q(localBlockSize)}}},
		{2 * localBlockSize, localBlockSize, &resourcev1.CapacityRequestPolicy{Default: q(2 * localBlockSize),
			ValidRange: &resourcev1.CapacityRequestPolicyRange{Min: q(localBlockSize), Step: q(localBlockSize)}}},
		// one block: a range needs room for min and one step
		{localBlockSize + 64*mib, localBlockSize, &resourcev1.CapacityRequestPolicy{Default: q(localBlockSize),
			ValidValues: []resource.Quantity{*q(localBlockSize)}}},
		{localRegionSize, 2 << 30, nil},
		{localRegionSize, 0, nil},
		// blocks larger than the region alignment: the head that a
		// region can have (block size - 256 MiB) is not counted
		{2 << 30, 512 * mib, &resourcev1.CapacityRequestPolicy{Default: q(1536 * mib),
			ValidRange: &resourcev1.CapacityRequestPolicyRange{Min: q(512 * mib), Step: q(512 * mib)}}},
		{768 * mib, 512 * mib, &resourcev1.CapacityRequestPolicy{Default: q(512 * mib),
			ValidValues: []resource.Quantity{*q(512 * mib)}}},
		{512 * mib, 512 * mib, nil},
		{4 << 30, 2 << 30, &resourcev1.CapacityRequestPolicy{Default: q(2 << 30),
			ValidValues: []resource.Quantity{*q(2 << 30)}}},
	} {
		if got := localRequestPolicy(tc.size, tc.bs); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("size %d, block size %d: policy %+v, expected %+v", tc.size, tc.bs, got, tc.want)
		}
	}
}

// localRegionNode returns the NUMA node of the region of the local memdev
// in the kernel.
func localRegionNode(e *localTestEnv) int {
	e.t.Helper()
	rs := e.regions(localSerial)
	if len(rs) != 1 {
		e.t.Fatalf("regions %v", rs)
	}
	ri, err := e.k.Kernel().Region(rs[0])
	noErr(e.t, err)
	if ri.NumaNode < 0 {
		e.t.Fatalf("region %+v without a node", ri)
	}
	return ri.NumaNode
}

// wantMovable checks that n memory blocks are online, all movable and in
// the region of the local memdev.
func wantMovable(e *localTestEnv, n int) {
	e.t.Helper()
	online := e.onlineBlocks()
	if len(online) != n {
		e.t.Fatalf("%d blocks online %v, expected %d", len(online), online, n)
	}
	if n == 0 {
		return
	}
	blocks, err := e.k.Kernel().RegionBlocks(e.regions(localSerial)[0])
	noErr(e.t, err)
	for _, b := range online {
		if mb := e.k.Kernel().MemoryBlock(b); mb.Zones != "Movable" || !slices.Contains(blocks, b) {
			e.t.Fatalf("block %+v online, region blocks %v", mb, blocks)
		}
	}
}

// localDax returns the path of the device node of a dax device and its
// numbers.
func localDax(e *localTestEnv, dax string) (string, int, int) {
	e.t.Helper()
	major, minor, err := e.k.Kernel().DaxDevNumbers(dax)
	noErr(e.t, err)
	return filepath.Join(e.k.DevRoot(), dax), major, minor
}

// wantLocalCDIDevices checks the CDI devices of the first device of a
// prepared claim.
func wantLocalCDIDevices(e *localTestEnv, uid string, ids ...string) {
	e.t.Helper()
	e.s.Lock()
	res := e.s.Prepared[uid]
	e.s.Unlock()
	if len(res.Devices) == 0 || !slices.Equal(res.Devices[0].CDIDeviceIDs, ids) {
		e.t.Fatalf("claim %s: prepared %+v, expected CDI devices %v", uid, res.Devices, ids)
	}
}

// Dax slices of a local memdev: devdax devices of whole blocks, read-only
// device nodes, no device node of a slice gone at a start.
func TestPrepareLocalDax(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	e.mustPrepare(localClaim("u1", localBlockSize, localDaxConfig))
	// 32Mi is rounded up to a memory block
	e.mustPrepare(localClaim("u2", 32*mib, localROConfig))
	wantLocalCDIDevices(e, "u2", "nri.io/cxl=claim-u2-0")
	dax1, major, minor1 := localDax(e, "dax0.1")
	dax0, _, minor0 := localDax(e, "dax0.0")
	e.wantDeviceInfo("u2", PreparedDeviceInfo{
		RequestName: "mem", DeviceName: localDeviceName, DeviceType: device.DeviceTypeMemdev, Mode: api.ModeDax,
		SysfsPath: e.k.P("bus/cxl/devices/region0"), NodeAffinities: []int{0},
		TotalBytes: localBlockSize, ConsumedBytes: localBlockSize, Serial: "0xc100e2e1",
		DaxDevice: dax1, DaxMajor: major, DaxMinor: minor1, ReadOnly: true,
	})
	e.wantCDIDevice("claim-u2-0",
		[]string{"CXL_C100E2E1_DAX=" + dax1, "CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=1", "CXL_C100E2E1_SERIAL=0xc100e2e1",
			"CXL_C100E2E1_SHARED=0", "CXL_C100E2E1_SIZE=134217728", "CXL_CLAIM_u2_0=1"},
		[]*cdiSpecs.DeviceNode{{Path: dax1, Type: "c", Major: int64(major), Minor: int64(minor1), Permissions: "r"}})
	e.wantCDIDevice("claim-u1-0",
		[]string{"CXL_C100E2E1_DAX=" + dax0, "CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=0", "CXL_C100E2E1_SERIAL=0xc100e2e1",
			"CXL_C100E2E1_SHARED=0", "CXL_C100E2E1_SIZE=134217728", "CXL_CLAIM_u1_0=1"},
		[]*cdiSpecs.DeviceNode{{Path: dax0, Type: "c", Major: int64(major), Minor: int64(minor0)}})

	// the spec is rebuilt from the prepared claims at a start, without the
	// device node of a slice that is gone
	k := e.k.Kernel()
	noErr(t, k.UnbindDax(context.Background(), "dax0.1"))
	noErr(t, k.DeleteDaxDevice(context.Background(), "region0", "dax0.1"))
	noErr(t, os.RemoveAll(e.cdiDir))
	noErr(t, os.MkdirAll(e.cdiDir, 0o755))
	e.restart()
	if spec := e.cdiSpec(); spec == nil || len(spec.Devices) != 2 {
		t.Fatalf("rebuilt CDI spec %+v", spec)
	}
	e.wantCDIDevice("claim-u2-0", []string{"CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=1", "CXL_C100E2E1_SERIAL=0xc100e2e1",
		"CXL_C100E2E1_SHARED=0", "CXL_C100E2E1_SIZE=134217728", "CXL_CLAIM_u2_0=1"}, nil)
	// a numa claim on the same device gets the node
	e.mustPrepare(localClaim("u3", localBlockSize))
	if got := e.s.GetClaimInfo("u3").Devices[0]; got.DeviceType != device.DeviceTypeMemdev || got.Mode != api.ModeNUMA || !slices.Equal(got.NUMANodes, []int{localRegionNode(e)}) {
		t.Fatalf("numa claim %+v", got)
	}
	e.mustUnprepare("u3")

	e.mustUnprepare("u1")
	if cdiDeviceByName(e.cdiSpec(), "claim-u1-0") != nil {
		t.Fatal("CDI device of u1 not removed")
	}
	if e.k.DaxSize("dax0.0") != 0 || e.k.DaxDriver("dax0.0") != "" {
		t.Fatalf("dax0.0 of size %d bound to %q after its slice", e.k.DaxSize("dax0.0"), e.k.DaxDriver("dax0.0"))
	}
	e.mustUnprepare("u2")
	if e.cdiSpec() != nil || e.inUse() {
		t.Fatalf("after the last unprepare: in use %v", e.inUse())
	}
	e.wantClean()
}

// Two results of a claim on one memdev: a CDI device each with only its
// slice, the second one's env keys with _2.
func TestPrepareLocalTwoSlices(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	claim := localClaim("u1", 8*mib, localDaxConfig)
	r := claim.Status.Allocation.Devices.Results[0]
	r.Request = "mem2"
	claim.Status.Allocation.Devices.Results = append(claim.Status.Allocation.Devices.Results, r)
	ro := makeOpaqueConfig(device.DriverName, resourcev1.AllocationConfigSourceClaim, json.RawMessage(localROConfig))
	ro.Requests = []string{"mem2"}
	claim.Status.Allocation.Devices.Config = append(claim.Status.Allocation.Devices.Config, ro)
	e.mustPrepare(claim)
	devs := e.s.Prepared["u1"].Devices
	if len(devs) != 2 || !slices.Equal(devs[0].CDIDeviceIDs, []string{"nri.io/cxl=claim-u1-0"}) ||
		!slices.Equal(devs[1].CDIDeviceIDs, []string{"nri.io/cxl=claim-u1-1"}) {
		t.Fatalf("prepared %+v", devs)
	}
	dax0, major, minor0 := localDax(e, "dax0.0")
	dax1, _, minor1 := localDax(e, "dax0.1")
	e.wantCDIDevice("claim-u1-0", []string{
		"CXL_C100E2E1_DAX=" + dax0, "CXL_C100E2E1_MODE=dax", "CXL_C100E2E1_READONLY=0", "CXL_C100E2E1_SERIAL=0xc100e2e1",
		"CXL_C100E2E1_SHARED=0", "CXL_C100E2E1_SIZE=134217728", "CXL_CLAIM_u1_0=1"},
		[]*cdiSpecs.DeviceNode{{Path: dax0, Type: "c", Major: int64(major), Minor: int64(minor0)}})
	// the second slice of the memdev in the claim: <HEX>_2
	e.wantCDIDevice("claim-u1-1", []string{
		"CXL_C100E2E1_2_DAX=" + dax1, "CXL_C100E2E1_2_MODE=dax", "CXL_C100E2E1_2_READONLY=1", "CXL_C100E2E1_2_SERIAL=0xc100e2e1",
		"CXL_C100E2E1_2_SHARED=0", "CXL_C100E2E1_2_SIZE=134217728", "CXL_CLAIM_u1_1=1"},
		[]*cdiSpecs.DeviceNode{{Path: dax1, Type: "c", Major: int64(major), Minor: int64(minor1), Permissions: "r"}})
	if spec := e.cdiSpec(); len(spec.Devices) != 2 {
		t.Fatalf("CDI devices %+v", spec.Devices)
	}
	e.mustUnprepare("u1")
	e.wantClean()
}

// Refused MemoryConfigs and a result of a missing device touch no device;
// unmanaged memdevs are refused.
func TestPrepareLocalErrors(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	for _, tc := range []struct{ params, err string }{
		{`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"readOnly":true}}`, "MemoryConfig: device.readOnly needs mode dax"},
		{`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"ram"}}`, `MemoryConfig: device.mode: invalid mode "ram" (numa or dax)`},
		{`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"size":1}}`, `unknown field "device.size"`},
		{`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"LocalDeviceConfig","mode":"dax"}`, `claim demo/claim-u1: unknown kind "LocalDeviceConfig" (MemoryConfig)`},
		{`{"apiVersion":"cxl.nri.io/v1alpha1","kind":"LendConfig","lease":"l1"}`, `unknown kind "LendConfig" (MemoryConfig)`},
		{`{"apiVersion":"cxl.nri.io/v1alpha1","mode":"dax"}`, `unknown kind "" (MemoryConfig)`},
	} {
		wantErr(t, e.prepare(localClaim("u1", 2*mib, tc.params)), tc.err)
	}
	if strings.Contains(e.commands(), "create-region") || len(e.s.Prepared) != 0 {
		t.Fatalf("a refused config touched the memdev:\n%s", e.commands())
	}
	// a result on a device that is not there stops the claim before its
	// memdev is touched
	claim := localClaim("u1", 2*mib, localDaxConfig)
	claim.Status.Allocation.Devices.Results = append(claim.Status.Allocation.Devices.Results,
		resourcev1.DeviceRequestAllocationResult{Request: "other", Driver: device.DriverName, Pool: testNode, Device: "missing"})
	wantErr(t, e.prepare(claim), "could not find allocatable device missing")
	if strings.Contains(e.commands(), "create-region") || e.inUse() || len(e.s.Prepared) != 0 || e.preparation("u1") != nil {
		t.Fatalf("a refused claim touched the memdev:\n%s", e.commands())
	}
	// unmanaged memdevs
	e.s.local.managed = false
	wantErr(t, e.prepare(localClaim("u1", 2*mib)), "manageMemdevs: false")
	e.wantClean()
}

// newLocalLendEnv returns a started localTestEnv with the memdevs of specs
// too, whose companion claims are lent by the fake lender and told to the
// fake hooks.
func newLocalLendEnv(t *testing.T, specs ...fake.MemdevSpec) (*localTestEnv, *fakeLender, *fakeHooks) {
	t.Helper()
	e := newLocalTestEnv(t, specs...)
	e.start()
	lender, hooks := newFakeLender(), &fakeHooks{}
	e.s.lending.set(lender, hooks)
	return e, lender, hooks
}

// wantLog checks that a log of calls ends with want.
func wantLog(t *testing.T, log, want string) {
	t.Helper()
	if !strings.HasSuffix(log, want) {
		t.Fatalf("calls\n%s\nexpected to end with\n%s", log, want)
	}
}

// A companion claim of a numa slice: the node lent and told to the broker,
// no CDI device, told again by a Prepare again, revoked before the release.
func TestPrepareLocalLend(t *testing.T) {
	e, lender, hooks := newLocalLendEnv(t)
	// the lease gets the slice: 64Mi rounded up to a memory block
	e.mustPrepare(localCompanion("u1", 64*mib))
	node := localRegionNode(e)
	wantLog(t, lender.callLog(), "lend pod-uid-1/app "+strconv.Itoa(node))
	wantLog(t, hooks.log(), "lending l1 cxl-lease-l1\nprepared l1")
	wantDev := lentDevice{
		Driver: device.DriverName, Source: api.SourceLocal, Request: "mem", Device: localDeviceName, Pool: testNode,
		Serial: localSerial, Size: localBlockSize, Mode: api.ModeNUMA, Node: node,
	}
	if !reflect.DeepEqual(hooks.devs, []lentDevice{wantDev}) {
		t.Fatalf("lent devices %+v", hooks.devs)
	}
	if rec := e.s.GetClaimInfo("u1").Lend; rec == nil || rec.Lease != "l1" || !slices.Equal(rec.Nodes, []int{node}) {
		t.Fatalf("lend record %+v", rec)
	}
	// the companion's own containers get no CDI device, and the spec has
	// none of the companion
	wantLocalCDIDevices(e, "u1")
	if cdiDeviceByName(e.cdiSpec(), "claim-u1-0") != nil {
		t.Fatal("CDI device of a companion claim")
	}
	// the lend is in the claims info
	data, err := os.ReadFile(filepath.Join(e.dir, preparedClaimsInfoFileName))
	if err != nil || !strings.Contains(string(data), `"lease": "l1"`) {
		t.Fatalf("claims info lacks the lend: %v\n%s", err, data)
	}
	// a repeated Prepare tells the broker again
	e.mustPrepare(localCompanion("u1", 64*mib))
	wantLog(t, hooks.log(), "prepared l1\nlending l1 cxl-lease-l1\nprepared l1")

	e.mustUnprepare("u1")
	wantLog(t, lender.callLog(), "lend pod-uid-1/app "+strconv.Itoa(node)+"\nrevoke pod-uid-1/app "+strconv.Itoa(node))
	wantLog(t, hooks.log(), "releasing l1")
	e.wantClean()
}

// A companion claim of a dax slice: the broker passes the dax device, no
// node is lent.
func TestPrepareLocalLendDax(t *testing.T) {
	e, lender, hooks := newLocalLendEnv(t)
	e.mustPrepare(localCompanion("u1", 16*mib, localDaxConfig))
	dax0, _, _ := localDax(e, "dax0.0")
	if len(hooks.devs) != 1 || hooks.devs[0].Mode != api.ModeDax || hooks.devs[0].DaxDevice != dax0 || hooks.devs[0].Node != -1 {
		t.Fatalf("lent dax devices %+v", hooks.devs)
	}
	// the borrower gets the fd from the broker, the companion nothing
	wantLocalCDIDevices(e, "u1")
	e.mustUnprepare("u1")
	if len(lender.calls) != 0 {
		t.Fatalf("nodes lent for a dax lease: %v", lender.calls)
	}
	e.wantClean()
}

// The refusals of a companion claim: lending disabled, a failed lend rolled
// back, other devices than local memdevs, a companion the broker refuses.
func TestPrepareLocalLendErrors(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	wantErr(t, e.prepare(localCompanion("u1", 64*mib)), "lease l1: lending to running containers is disabled (--leases=false)")
	e.wantClean()

	e, lender, hooks := newLocalLendEnv(t)
	// a failed lend rolls back
	lender.lendErr = errors.New("container is steered")
	wantErr(t, e.prepare(localCompanion("u2", 64*mib)), "container is steered")
	failed := hooks.log()
	wantLog(t, failed, "failed l1: lease l1: lending node 2 to demo/borrower/app: container is steered")
	if e.inUse() || len(e.s.Prepared) != 0 || len(e.regions(localSerial)) != 0 {
		t.Fatal("not rolled back")
	}

	// only local memdevs are lent
	devs, err := e.s.allocatable()
	noErr(t, err)
	e.s.Lock()
	devs["dram"] = &device.DeviceInfo{Name: "dram", Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}}
	e.s.Unlock()
	claim := localCompanion("u4", 64*mib)
	claim.Status.Allocation.Devices.Results[0].Device = "dram"
	wantErr(t, e.prepare(claim), "the companion claim of lease l1 needs memdev devices only")

	// a refused companion claim: the device is not touched
	hooks.lendingErr = errors.New("claim demo/cxl-lease-l1: not the companion of lease l1")
	before := e.commands()
	wantErr(t, e.prepare(localCompanion("u5", 64*mib)), "not the companion of lease l1")
	if e.commands() != before {
		t.Fatalf("a refused companion touched the memdev:\n%s", strings.TrimPrefix(e.commands(), before))
	}
	e.wantClean()
	if !strings.Contains(failed, "\nfailed l1: lease l1: lending node ") {
		t.Fatalf("the broker hears %q, expected the lend error without the claim", failed[strings.LastIndex(failed, "failed l1: "):])
	}
}

// A prepared claim is returned as it is, also without an allocation; only a
// companion claim tells the broker again.
func TestPrepareAlreadyPrepared(t *testing.T) {
	e, lender, hooks := newLocalLendEnv(t)
	ctx := context.Background()
	d := &driver{state: *e.s}
	res := d.prepareResourceClaim(ctx, localCompanion("u1", 64*mib))
	noErr(t, res.Err)
	noErr(t, d.prepareResourceClaim(ctx, localClaim("u2", 16*mib)).Err)
	before := e.commands()

	again := localCompanion("u1", 64*mib)
	again.Status.Allocation = nil
	res2 := d.prepareResourceClaim(ctx, again)
	if res2.Err != nil || !reflect.DeepEqual(res2, res) {
		t.Fatalf("repeated prepare %+v, expected %+v", res2, res)
	}
	wantLog(t, hooks.log(), "lending l1 cxl-lease-l1\nprepared l1")
	again = localClaim("u2", 16*mib)
	again.Status.Allocation = nil
	noErr(t, d.prepareResourceClaim(ctx, again).Err)
	if e.commands() != before || len(lender.calls) != 1 {
		t.Fatalf("repeated prepare touched devices:\n%s\nlender %v", strings.TrimPrefix(e.commands(), before), lender.calls)
	}
	if n := strings.Count(hooks.log(), "prepared l1"); n != 2 {
		t.Fatalf("hooks %s", hooks.log())
	}
	e.check("prepared again")
	e.mustUnprepare("u1")
	e.mustUnprepare("u2")
	e.wantClean()
}

// blockingLender is a fakeLender whose LendNode waits until release is
// closed.
type blockingLender struct {
	*fakeLender
	entered chan struct{}
	release chan struct{}
}

func (b *blockingLender) LendNode(ctx context.Context, podUID, name string, node int, holder string) error {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return b.fakeLender.LendNode(ctx, podUID, name, node, holder)
}

// lends returns the number of calls of the lender.
func (b *blockingLender) lends() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.calls)
}

// The NRI readers, the publisher and other claims never wait for a Prepare
// that lends, and two Prepares of one claim run one after the other.
func TestPrepareDoesNotBlockReaders(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	bl := &blockingLender{fakeLender: newFakeLender(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	hooks := &fakeHooks{}
	e.s.lending.set(bl, hooks)
	ctx := context.Background()
	e.mustPrepare(localClaim("u0", 32*mib))

	done := make(chan error, 2)
	go func() { done <- e.s.Prepare(ctx, localCompanion("u1", 64*mib)) }()
	select {
	case <-bl.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("Prepare did not lend")
	}
	readers := make(chan error, 1)
	go func() {
		if e.s.GetClaimInfo("u0") == nil {
			readers <- errors.New("no claim info of u0")
			return
		}
		_, _, _ = e.s.preparedResult("u0", 0)
		_ = e.s.GetResources()
		err := e.s.Prepare(ctx, localClaim("u2", 2*mib))
		if err == nil {
			err = e.s.Unprepare(ctx, "u2")
		}
		readers <- err
	}()
	select {
	case err := <-readers:
		noErr(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("claim info, resources or another claim waited for a lend")
	}

	go func() { done <- e.s.Prepare(ctx, localCompanion("u1", 64*mib)) }()
	select {
	case err := <-done:
		t.Fatalf("a Prepare of u1 finished during the lend of u1: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(bl.release)
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			noErr(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("Prepare of u1 did not finish")
		}
	}
	e.check("prepared")
	if n := bl.lends(); n != 1 {
		t.Fatalf("%d lends of u1", n)
	}
	n := 0
	for _, g := range e.records().Grants {
		if g.Ref.Claim == "u1" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d grants of u1", n)
	}
	wantLog(t, hooks.log(), "lending l1 cxl-lease-l1\nprepared l1\nlending l1 cxl-lease-l1\nprepared l1")
	e.mustUnprepare("u1")
	e.mustUnprepare("u0")
	e.wantClean()
}

// A failed revoke keeps the companion claim and its memory; a failed slice
// release keeps the claim and its CDI device for the retry.
func TestUnprepareLocalFailures(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	hooks := &fakeHooks{}
	e.s.lending.set(revokeFailer{fakeLender: newFakeLender()}, hooks)

	// a revoke that fails keeps the claim and its memory
	e.mustPrepare(localCompanion("u1", 64*mib))
	wantErr(t, e.unprepare("u1"), "node "+strconv.Itoa(localRegionNode(e))+" busy")
	if _, found := e.s.Prepared["u1"]; !found || strings.Contains(e.commands(), "destroy-region") {
		t.Fatalf("claim released after a failed revoke:\n%s", e.commands())
	}
	wantLog(t, hooks.log(), "releasing l1")
	e.s.lending.set(newFakeLender(), hooks)
	e.mustUnprepare("u1")
	if len(e.regions(localSerial)) != 0 {
		t.Fatalf("regions %v", e.regions(localSerial))
	}

	// a slice that fails to delete keeps the claim and its CDI device
	e.mustPrepare(localClaim("u2", 8*mib, localDaxConfig))
	e.k.FailWrite("bus/dax/devices/dax0.0/size", syscall.EBUSY)
	wantErr(t, e.unprepare("u2"), "releasing slice dax0.0")
	if _, found := e.s.Prepared["u2"]; !found || cdiDeviceByName(e.cdiSpec(), "claim-u2-0") == nil {
		t.Fatal("claim or CDI device gone after a failed release")
	}
	e.mustUnprepare("u2")
	if e.cdiSpec() != nil || e.inUse() {
		t.Fatalf("after the retry: in use %v", e.inUse())
	}
	e.wantClean()
}

// A companion claim whose CDI spec cannot be written rolls back: the lend
// revoked, the broker told, the memory released.
func TestPrepareLocalPersistFailure(t *testing.T) {
	e, lender, hooks := newLocalLendEnv(t, fake.MemdevSpec{Serial: localOtherSerial, Ram: localRegionSize, HostBridge: 24})
	e.rescan()
	// a claim with a CDI device on the other memdev, then a CDI directory
	// that cannot be written
	e.mustPrepare(memdevClaim("u0", memdevDeviceName(localOtherSerial), localBlockSize))
	noErr(t, os.RemoveAll(e.cdiDir))
	noErr(t, os.WriteFile(e.cdiDir, nil, 0o644))
	err := e.prepare(localCompanion("u1", 64*mib))
	wantErr(t, err, "CDI spec")
	if calls := lender.callLog(); calls != "lend pod-uid-1/app 2\nrevoke pod-uid-1/app 2" {
		t.Fatalf("lender calls %q", calls)
	}
	if log := hooks.log(); !strings.HasSuffix(log, "\nfailed l1: "+err.Error()) || strings.Contains(log, "releasing") {
		t.Fatalf("hooks %s", log)
	}
	if _, found := e.s.Prepared["u1"]; found || e.s.GetClaimInfo("u1") != nil || e.preparation("u1") != nil || len(e.regions(localSerial)) != 0 {
		t.Fatalf("claim kept after the rollback, regions %v", e.regions(localSerial))
	}
	noErr(t, os.Remove(e.cdiDir))
	noErr(t, os.MkdirAll(e.cdiDir, 0o755))
	e.mustPrepare(localCompanion("u1", 64*mib))
	e.mustUnprepare("u1")
	e.mustUnprepare("u0")
	e.wantClean()
}

// A Prepare that fails after the lease was marked Lending (a region on the
// memdev that the driver did not make) leaves the lease to the retry.
func TestPrepareLocalFailsAfterCheck(t *testing.T) {
	e, _, hooks := newLocalLendEnv(t)
	k := e.k.Kernel()
	memdev := e.k.Memdev(localSerial)
	d, err := k.RootDecoder(memdev, kernel.RegionRAM)
	noErr(t, err)
	region, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionRAM})
	noErr(t, err)
	wantErr(t, e.prepare(localCompanion("u1", 64*mib)), "that the plugin did not create")
	if log := hooks.log(); log != "lending l1 cxl-lease-l1" {
		t.Fatalf("hooks %s", log)
	}
	noErr(t, k.ReleaseRegion(context.Background(), region))
	e.mustPrepare(localCompanion("u1", 64*mib))
	if log := hooks.log(); log != "lending l1 cxl-lease-l1\nlending l1 cxl-lease-l1\nprepared l1" {
		t.Fatalf("hooks %s", log)
	}
	e.mustUnprepare("u1")
	e.wantClean()
}

// The CDI devices of results on DRAM, a region and the lease device, none
// of a companion claim.
func TestClaimsCDISpec(t *testing.T) {
	s := &nodeState{
		baseState: &baseState{Prepared: claimPreparations{"u1": {}, "u2": {}, "u3": {}}},
		preparedClaims: PreparedClaimsInfo{
			// result 1 is of another driver
			"u1": {Devices: []PreparedDeviceInfo{
				{Result: 0, DeviceType: device.DeviceTypeDRAM, Mode: api.ModeNUMA, NUMANodes: []int{0, 1}, TotalBytes: 16 << 30, ConsumedBytes: 64 << 20},
				{Result: 2, DeviceType: device.DeviceTypeRegion, Mode: api.ModeNUMA, Region: "region0", NUMANodes: []int{2}, TotalBytes: 2 << 30, ConsumedBytes: 64 << 20},
			}},
			"u2": {Devices: []PreparedDeviceInfo{{DeviceType: device.DeviceTypeLease}}},
			// a companion claim
			"u3": {Devices: []PreparedDeviceInfo{{DeviceType: device.DeviceTypeMemdev, Mode: api.ModeNUMA, Serial: "0x1", NUMANodes: []int{2}}},
				Lend: &lendRecord{Lease: "l1"}},
		},
	}
	spec := s.buildClaimsCDISpec()
	want := []cdiSpecs.Device{
		{Name: "claim-u1-0", ContainerEdits: cdiSpecs.ContainerEdits{Env: []string{
			"CXL_CLAIM_u1_0=1", "CXL_DRAM_MODE=numa", "CXL_DRAM_NODES=0-1", "CXL_DRAM_SIZE=67108864"}}},
		{Name: "claim-u1-2", ContainerEdits: cdiSpecs.ContainerEdits{Env: []string{
			"CXL_CLAIM_u1_2=1", "CXL_REGION0_MODE=numa", "CXL_REGION0_NODE=2", "CXL_REGION0_SIZE=67108864"}}},
		{Name: "claim-u2-0", ContainerEdits: cdiSpecs.ContainerEdits{Env: []string{"CXL_CLAIM_u2_0=1"}}},
	}
	if spec.Kind != "nri.io/cxl" || !reflect.DeepEqual(spec.Devices, want) {
		t.Fatalf("CDI spec %+v", spec)
	}
}

// TestRemoveCXLSpecs removes the CDI specs of both drivers, also of their
// earlier names, and keeps the others.
func TestRemoveCXLSpecs(t *testing.T) {
	dir := t.TempDir()
	for name, kind := range map[string]string{"cxl-claims": "nri.io/cxl", "cxl-local": "nri.io/cxl", "cxl-pool": "nri.io/cxl-pool", "gpu": "example.com/gpu"} {
		data := "cdiVersion: 0.6.0\nkind: " + kind + "\ndevices:\n- name: " + name + "\n  containerEdits:\n    env: [A=1]\n"
		noErr(t, os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(data), 0o600))
	}
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(dir), cdiapi.WithAutoRefresh(false))
	noErr(t, err)
	noErr(t, removeCXLSpecs(cache))
	m, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(m) != 1 || filepath.Base(m[0]) != "gpu.yaml" {
		t.Fatalf("left %v", m)
	}
}

// injectDevices adds devices of regions, DRAM or the lease device to the
// devices of the scan of the node state of the env.
func injectDevices(e *localTestEnv, infos ...*device.DeviceInfo) {
	e.t.Helper()
	devs, err := e.s.allocatable()
	noErr(e.t, err)
	e.s.Lock()
	defer e.s.Unlock()
	for _, d := range infos {
		devs[d.Name] = d
	}
}

// A device section on a region or DRAM request fails unless it is numa.
func TestPrepareRegionDRAMNUMAOnly(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	injectDevices(e,
		&device.DeviceInfo{Name: "region0-node2", Dev: &nricxl.RegionDevice{Name: "region0", Node: 2, Size: 1 << 30, Enabled: true}},
		&device.DeviceInfo{Name: "dram", Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}})
	var unprefixed []string
	for _, tc := range []struct{ dev, params, err string }{
		{"region0-node2", localDaxConfig, "claim demo/claim-u1: request mem: MemoryConfig: device: a region is used as numa only"},
		{"region0-node2", localROConfig, "MemoryConfig: device: a region is used as numa only"},
		{"region0-node2", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"readOnly":true}}`, "MemoryConfig: device.readOnly needs mode dax"},
		{"dram", localDaxConfig, "claim demo/claim-u1: request mem: MemoryConfig: device: a dram is used as numa only"},
		{"dram", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"readOnly":true}}`, "MemoryConfig: device.readOnly needs mode dax"},
		{"dram", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"ram"}}`, `MemoryConfig: device.mode: invalid mode "ram" (numa or dax)`},
		{"region0-node2", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`, ""},
		{"dram", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`, ""},
	} {
		claim := localClaim("u1", 64*mib, tc.params)
		claim.Status.Allocation.Devices.Results[0].Device = tc.dev
		err := e.prepare(claim)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s %s: %v", tc.dev, tc.params, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), strings.TrimPrefix(tc.err, "claim demo/claim-u1: request mem: "))):
			t.Errorf("%s %s: expected error %q, got %v", tc.dev, tc.params, tc.err, err)
		case tc.err != "" && !strings.Contains(err.Error(), tc.err):
			unprefixed = append(unprefixed, err.Error())
		}
		if err == nil {
			e.mustUnprepare("u1")
		}
	}
	if len(e.s.Prepared) != 0 {
		t.Fatalf("prepared %v", e.s.Prepared)
	}
	e.wantClean()
	wantPrefixed(t, unprefixed)
}

// wantPrefixed fails the test when errors of the device settings of a
// region, the DRAM or the lease device lacked the claim and the request.
func wantPrefixed(t *testing.T, unprefixed []string) {
	t.Helper()
	if len(unprefixed) > 0 {
		t.Errorf("the error of the device settings of a region, the DRAM or the lease device does not name the claim and the request: %q", unprefixed)
	}
}

// fakeLeaseClaims records the lease claims whose sockets are open, with
// their records in the store st as the lease broker keeps them.
type fakeLeaseClaims struct {
	st   *store.Store
	open map[string]bool
}

func (f *fakeLeaseClaims) OpenClaim(claim *resourcev1.ResourceClaim) error {
	if f.open == nil {
		f.open = map[string]bool{}
	}
	f.open[string(claim.UID)] = true
	return f.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
		doc.LeaseClaims = append(doc.LeaseClaims, state.LeaseClaim{UID: string(claim.UID), Namespace: claim.Namespace, Name: claim.Name,
			State: state.LeaseClaimOpen})
		return nil
	})
}

func (f *fakeLeaseClaims) CloseClaim(ctx context.Context, uid string) error {
	delete(f.open, uid)
	return f.st.Commit(ctx, store.Durable, func(doc *store.Document) error {
		doc.LeaseClaims = slices.DeleteFunc(doc.LeaseClaims, func(c state.LeaseClaim) bool { return c.UID == uid })
		return nil
	})
}

// memoryConfigClaim returns a claim with the results numa (a slice of the
// local memdev), region, dram and lease, in this order, of the device
// classes cxl-local, cxl-region, cxl-dram and cxl-lease, with the configs.
func memoryConfigClaim(uid string, configs ...resourcev1.DeviceAllocationConfiguration) *resourcev1.ResourceClaim {
	c := localClaim(uid, localBlockSize)
	c.Status.Allocation.Devices.Results[0].Request = "numa"
	for _, r := range []struct{ request, dev string }{{"region", "region5-node4"}, {"dram", "dram"}, {"lease", device.LeaseDeviceName}} {
		c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
			resourcev1.DeviceRequestAllocationResult{Request: r.request, Driver: device.DriverName, Pool: testNode, Device: r.dev})
	}
	for _, i := range []int{1, 2} {
		c.Status.Allocation.Devices.Results[i].ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{
			device.CapacityMemory: *resource.NewQuantity(64*mib, resource.BinarySI)}
	}
	for _, r := range []struct{ request, class string }{{"numa", "cxl-local"}, {"region", "cxl-region"}, {"dram", "cxl-dram"}, {"lease", "cxl-lease"}} {
		c.Spec.Devices.Requests = append(c.Spec.Devices.Requests,
			resourcev1.DeviceRequest{Name: r.request, Exactly: &resourcev1.ExactDeviceRequest{DeviceClassName: r.class}})
	}
	c.Status.Allocation.Devices.Config = configs
	return c
}

// memoryConfigEntry returns an opaque config entry of cxl.nri.io.
func memoryConfigEntry(source resourcev1.AllocationConfigSource, requests []string, params string) resourcev1.DeviceAllocationConfiguration {
	e := makeOpaqueConfig(device.DriverName, source, json.RawMessage(params))
	e.Requests = requests
	return e
}

// The MemoryConfig entries of results of every device type: presets of
// classes, settings with origins, markers; refused entries touch no device.
func TestPrepareMemoryConfig(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	leases := &fakeLeaseClaims{st: e.st}
	e.s.leases = leases
	injectDevices(e,
		&device.DeviceInfo{Name: "region5-node4", Dev: &nricxl.RegionDevice{Name: "region5", Node: 4, Size: 1 << 30, Enabled: true}},
		&device.DeviceInfo{Name: "dram", Dev: &device.DRAM{Nodes: []int{0}, Size: 1 << 30}},
		&device.DeviceInfo{Name: device.LeaseDeviceName, Dev: &device.LeaseToken{}})
	const (
		class = resourcev1.AllocationConfigSourceClass
		claim = resourcev1.AllocationConfigSourceClaim
	)

	c := memoryConfigClaim("u1",
		// a claim entry before a class entry: classes come first
		memoryConfigEntry(claim, []string{"dram"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"first-dram","maxStep":"1Gi"}}}`),
		memoryConfigEntry(class, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"auto"}}}`),
		// null removes the preset of the class
		memoryConfigEntry(claim, []string{"numa"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":null}}}`),
	)
	e.mustPrepare(c)
	info := e.s.GetClaimInfo("u1")
	auto := func(origin string) config.ResultSettings {
		return config.ResultSettings{Container: &config.Container{Steering: &config.Steering{Policy: config.PolicyAuto}}, Origins: map[string]string{config.FieldPolicy: origin}}
	}
	for i, want := range []config.ResultSettings{
		{},
		auto("class cxl-region"),
		{Container: &config.Container{Steering: &config.Steering{Policy: config.PolicyFirstDRAM, MaxStep: "1Gi"}},
			Origins: map[string]string{config.FieldPolicy: "claim demo/claim-u1 request dram", config.FieldMaxStep: "claim demo/claim-u1 request dram"}},
		auto("class cxl-lease"),
	} {
		if d := info.Devices[i]; d.Result != i || !sameSettings(d.ResultSettings, want) {
			t.Errorf("result %d (%s): %d %+v %v, expected %+v %v", i, d.RequestName, d.Result, d.Container, d.Origins, want.Container, want.Origins)
		}
	}
	node := localRegionNode(e)
	if d := info.Devices[0]; d.Mode != api.ModeNUMA || !slices.Equal(d.NUMANodes, []int{node}) {
		t.Fatalf("numa slice %+v", d)
	}
	// one CDI device per result, with the marker of the result
	for n, wantID := range []string{"claim-u1-0", "claim-u1-1", "claim-u1-2", "claim-u1-3"} {
		d := cdiDeviceByName(e.cdiSpec(), wantID)
		marker := resultEnvVarName("u1", n) + "=1"
		if d == nil || !slices.Contains(d.ContainerEdits.Env, marker) {
			t.Fatalf("CDI device %s: %+v, expected %s", wantID, d, marker)
		}
		for _, env := range d.ContainerEdits.Env {
			if strings.HasPrefix(env, "CXL_CLAIM_") && env != marker {
				t.Fatalf("CDI device %s has the marker %s", wantID, env)
			}
		}
	}
	if !leases.open["u1"] {
		t.Fatal("no lease socket")
	}

	// a container gets the management of the results it uses
	p := &nriPlugin{state: e.s}
	for _, tc := range []struct {
		results []int
		want    string
	}{
		{[]int{0}, "fenced " + strconv.Itoa(node) + " none (default)"},
		{[]int{1}, "steered 4 auto from class cxl-region"},
		{[]int{2}, "steered  first-dram from claim demo/claim-u1 request dram"},
		{[]int{0, 1}, "steered " + strconv.Itoa(node) + ",4 auto from class cxl-region"},
		{[]int{3}, "fenced  auto from class cxl-lease"},
	} {
		var refs []resultRef
		for _, n := range tc.results {
			refs = append(refs, resultRef{"u1", n})
		}
		m, err := p.manage("demo/pod/ctr", p.containerResults("demo/pod/ctr", refs), true)
		noErr(t, err)
		if got := m.memory + " " + m.claimed.String() + " " + m.eff.PolicyText(); got != tc.want {
			t.Errorf("results %v: %q, expected %q", tc.results, got, tc.want)
		}
	}
	_, err := p.manage("demo/pod/ctr", p.containerResults("demo/pod/ctr", []resultRef{{"u1", 1}, {"u1", 2}}), true)
	wantErr(t, err, "container demo/pod/ctr: container.steering.policy: class cxl-region says auto, claim demo/claim-u1 request dram says first-dram")
	noErr(t, leases.CloseClaim(context.Background(), "u1"))
	e.mustUnprepare("u1")

	// the device rules of every result are checked before any device is
	// touched
	commands := e.commands()
	var unprefixed []string
	for _, tc := range []struct{ request, params, err string }{
		{"lease", `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`,
			"claim demo/claim-u9: request lease: MemoryConfig: device: the lease device has no device settings"},
		{"region", localDaxConfig, "claim demo/claim-u9: request region: MemoryConfig: device: a region is used as numa only"},
		{"dram", localROConfig, "claim demo/claim-u9: request dram: MemoryConfig: device: a dram is used as numa only"},
	} {
		err := e.prepare(memoryConfigClaim("u9", memoryConfigEntry(claim, []string{tc.request}, tc.params)))
		wantErr(t, err, strings.TrimPrefix(tc.err, "claim demo/claim-u9: request "+tc.request+": "))
		if !strings.Contains(err.Error(), tc.err) {
			unprefixed = append(unprefixed, err.Error())
		}
		if len(e.s.Prepared) != 0 || e.inUse() || leases.open["u9"] {
			t.Fatalf("%s: prepared %v, memdev in use %v", tc.err, e.s.Prepared, e.inUse())
		}
	}

	// the entries and the values of all results are checked before any
	// device is touched
	for _, tc := range []struct {
		configs []resourcev1.DeviceAllocationConfiguration
		err     string
	}{
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(class, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","pool":{"opaque":{"fake-cxl-pool":{"numaNode":1}}}}`)},
			"claim demo/claim-u9: MemoryConfig: pool: only for devices of cxl-pool.nri.io"},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(class, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"fencing":"none"}}`)},
			"claim demo/claim-u9: MemoryConfig: container.fencing: set by the driver configuration only (defaults.container.fencing)"},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"off"}}}`)},
			`claim demo/claim-u9: request numa: MemoryConfig: container.steering.policy: invalid policy "off" (none, auto, first-dram, first-cxl, start-interleaved, end-interleaved or waypoints)`},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, []string{"dram"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"none","maxStep":"1Gi"}}}`)},
			"claim demo/claim-u9: request dram: MemoryConfig: container.steering.maxStep needs a policy other than none"},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"DeviceConfig","mode":"dax"}`)},
			`claim demo/claim-u9: unknown kind "DeviceConfig" (MemoryConfig)`},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryPolicyConfig","memoryUseOrder":"first-dram"}`)},
			`claim demo/claim-u9: unknown kind "MemoryPolicyConfig" (MemoryConfig)`},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, nil, `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"MemoryConfig"}`)},
			`claim demo/claim-u9: MemoryConfig: apiVersion "cxl-pool.nri.io/v1alpha1", expected "cxl.nri.io/v1alpha1"`},
		// every entry of the driver is checked, also of other requests
		{[]resourcev1.DeviceAllocationConfiguration{
			memoryConfigEntry(class, nil, localDaxConfig),
			memoryConfigEntry(claim, []string{"other"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"online":"all"}}`)},
			`claim demo/claim-u9: MemoryConfig: FromClaim config 0: json: unknown field "device.online"`},
	} {
		wantErr(t, e.prepare(memoryConfigClaim("u9", tc.configs...)), tc.err)
		if len(e.s.Prepared) != 0 || e.inUse() || leases.open["u9"] {
			t.Fatalf("%s: prepared %v, memdev in use %v", tc.err, e.s.Prepared, e.inUse())
		}
	}
	if got := e.commands(); got != commands {
		t.Fatalf("a refused config touched the memdev:\n%s", strings.TrimPrefix(got, commands))
	}
	e.wantClean()
	wantPrefixed(t, unprefixed)
}

// sameSettings tells whether two container settings are equal, an empty
// map of origins as none.
func sameSettings(a, b config.ResultSettings) bool {
	if len(a.Origins) == 0 && len(b.Origins) == 0 {
		a.Origins, b.Origins = nil, nil
	}
	return reflect.DeepEqual(a, b)
}

// A Prepare again of a claim that a failed Prepare left KEPT, refused by
// its validation, rolls nothing back: the region kept for the claim stays
// for the next Prepare or the Unprepare.
func TestPrepareKeptRefusedKeepsItsRegion(t *testing.T) {
	for _, tc := range []struct {
		name  string
		claim func() *resourcev1.ResourceClaim
		err   string
	}{
		{"a device that is not allocatable", func() *resourcev1.ResourceClaim {
			claim := localClaim("u1", localBlockSize)
			claim.Status.Allocation.Devices.Results[0].Device = "memdev-deadbeef"
			return claim
		}, "could not find allocatable device memdev-deadbeef"},
		{"an invalid MemoryConfig", func() *resourcev1.ResourceClaim {
			return localClaim("u1", localBlockSize, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"bogus"}}`)
		}, "MemoryConfig: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLocalTestEnv(t)
			other := plugAbove(e)
			e.start()
			above := makeAboveAfterCreate(e, other)
			failDeviceDax(e)
			wantErr(t, e.prepare(localClaim("u1", localBlockSize)), errDeviceDax)
			releaseAbove(e, above())
			before := e.commands()
			wantErr(t, e.prepare(tc.claim()), tc.err)
			if got := strings.TrimPrefix(e.commands(), before); got != "" {
				t.Fatalf("the refused Prepare touched the memdev:\n%s", got)
			}
			if p := e.preparation("u1"); p == nil || p.State != state.PreparationKept {
				t.Fatalf("preparation %+v", p)
			}
			if d := e.localDevice(localSerial); d == nil || d.Region != "region0" {
				t.Fatalf("view %+v", d)
			} else if _, ok := d.Claims["u1"]; !ok {
				t.Fatalf("the region is not kept for u1: %+v", d)
			}
			e.mustPrepare(localClaim("u1", localBlockSize))
			wantLocalRegionCount(t, e, 1, 0)
			e.mustUnprepare("u1")
			e.wantClean()
		})
	}
}

// A companion claim of mode numa whose Prepare a process stop cut after its
// memory went online is kept at the start; its Prepare again refused by the
// lease broker revokes and releases nothing, and the next Prepare reuses its
// part.
func TestPrepareKeptCompanionRefused(t *testing.T) {
	e, _, _ := newLocalLendEnv(t)
	e.k.CutAfter("write devices/system/memory/memory74/state online_movable")
	cutLocalPrepare(t, e, localCompanion("u1", localBlockSize))
	e.restart()
	lender, hooks := newFakeLender(), &fakeHooks{}
	e.s.lending.set(lender, hooks)
	if p := e.preparation("u1"); p == nil || p.State != state.PreparationPreparing {
		t.Fatalf("preparation after the start %+v", p)
	}
	g := e.grant("u1", 0)
	if g == nil || g.Got.Dax == "" {
		t.Fatalf("grant after the start %+v", g)
	}
	kept := *g
	hooks.lendingErr = errors.New("claim demo/cxl-lease-l1: not the companion of lease l1")
	before := e.commands()
	wantErr(t, e.prepare(localCompanion("u1", localBlockSize)), "not the companion of lease l1")
	if got := strings.TrimPrefix(e.commands(), before); got != "" {
		t.Fatalf("the refused Prepare touched the memdev:\n%s", got)
	}
	if calls := lender.callLog(); calls != "" {
		t.Fatalf("the refused Prepare called the lender: %s", calls)
	}
	if p := e.preparation("u1"); p == nil || p.State != state.PreparationPreparing {
		t.Fatalf("preparation after the refusal %+v", p)
	}
	if g := e.grant("u1", 0); g == nil || g.State != kept.State || g.Got.Dax != kept.Got.Dax {
		t.Fatalf("grant after the refusal %+v, was %+v", g, kept)
	}
	hooks.lendingErr = nil
	before = e.commands()
	e.mustPrepare(localCompanion("u1", localBlockSize))
	if got := strings.TrimPrefix(e.commands(), before); strings.Contains(got, "create-region") || strings.Contains(got, "/size") {
		t.Fatalf("the Prepare again made its part anew:\n%s", got)
	}
	e.mustUnprepare("u1")
	e.wantClean()
}
