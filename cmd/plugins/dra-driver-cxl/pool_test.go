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
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

const (
	exclusiveData = `{"serial":"0xc1ee0001","shared":false,"size":268435456,"host":"n1"}`
	sharedData    = `{"serial":"0xc1ae0001","shared":true,"size":268435456}`
)

func TestPoolDeviceData(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		serial uint64
		shared bool
		err    string
	}{
		{raw: `{"serial":"0xc1ee0001","shared":false,"size":536870912}`, serial: 0xc1ee0001},
		{raw: `{"serial":"3253600257","shared":true,"size":1}`, serial: 3253600257, shared: true},
		{raw: `{"serial":"0xC1AE0001","shared":true,"size":1}`, serial: 0xc1ae0001, shared: true},
		{raw: `{"shared":true,"size":1}`, err: "required"},
		{raw: `{"serial":"0x1","size":1}`, err: "required"},
		{raw: `{"serial":"0x1","shared":true}`, err: "required"},
		{raw: `{"serial":"bogus","shared":true,"size":1}`, err: "invalid serial"},
		{raw: `{"serial":1,"shared":true,"size":1}`, err: "invalid device data"},
	} {
		d, err := parsePoolDeviceData([]byte(tc.raw))
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: expected error %q, got %v", tc.raw, tc.err, err)
			}
			continue
		}
		if err != nil || d.Serial != tc.serial || d.Shared != tc.shared {
			t.Errorf("%s: got %+v %v", tc.raw, d, err)
		}
	}

}

func TestPoolDataFor(t *testing.T) {
	claim := poolClaim("u1", "c1", "pooled0", exclusiveData)
	r := &claim.Status.Allocation.Devices.Results[0]
	if d, err := poolDataFor(claim, r); err != nil || d.Serial != 0xc1ee0001 || d.Shared || d.Size != 268435456 {
		t.Fatalf("poolDataFor: %+v %v", d, err)
	}
	// the entry of another device does not match
	claim.Status.Devices[1].Device = "pooled1"
	_, err := poolDataFor(claim, r)
	wantErr(t, err, "no entry")
	// missing entry, missing data
	_, err = poolDataFor(poolClaim("u1", "c1", "pooled0", ""), r)
	wantErr(t, err, "no entry")
	claim = poolClaim("u1", "c1", "pooled0", exclusiveData)
	claim.Status.Devices[1].Data = nil
	_, err = poolDataFor(claim, r)
	wantErr(t, err, "no data")
}

func TestPoolPrepareExclusive(t *testing.T) {
	e := newPoolTestEnv(t)
	memdev := e.plug(0xc1ee0001)
	p := e.driver(t)

	logs := captureKlog(t)
	res := prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	noErr(t, res.Err)
	// the line that test10 waits for
	prepared := false
	for _, line := range strings.Split(logs(), "\n") {
		ok, err := compat.MatchesRegexp(compat.LogDRAPoolDriverClaimPreparedPooled0, line)
		noErr(t, err)
		prepared = prepared || ok
	}
	if !prepared {
		t.Fatalf("no line %q in\n%s", compat.LogDRAPoolDriverClaimPreparedPooled0, logs())
	}
	want := []kubeletplugin.Device{{ // the cxl.nri.io result is not ours
		Requests:     []string{"mem"},
		PoolName:     "fake-cxl-pool",
		DeviceName:   "pooled0",
		CDIDeviceIDs: []string{"nri.io/cxl-pool=claim-u1-0"},
	}}
	if !reflect.DeepEqual(res.Devices, want) {
		t.Fatalf("unexpected devices %+v", res.Devices)
	}
	e.wantCommand(t, "cxl create-region -t ram -d decoder0.0 -m "+memdev)
	if n := e.onlineBlocks("region0"); n == 0 {
		t.Fatal("the memory of the region is not online")
	}
	if spec := e.cdiSpec(t); spec.Kind != "nri.io/cxl-pool" {
		t.Fatalf("CDI spec kind %q", spec.Kind)
	}
	cd := e.wantCDIDevice(t, "claim-u1-0", []string{"CXL_C1EE0001_MODE=numa", "CXL_C1EE0001_NODE=2", "CXL_C1EE0001_SERIAL=0xc1ee0001",
		"CXL_C1EE0001_SHARED=0", "CXL_C1EE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"})
	if len(cd.ContainerEdits.DeviceNodes) != 0 {
		t.Fatalf("unexpected device nodes %+v", cd.ContainerEdits.DeviceNodes)
	}
	if !p.Serials()[0xc1ee0001] {
		t.Fatalf("serial missing from %v", p.Serials())
	}
	data, err := os.ReadFile(e.stateFile)
	noErr(t, err)
	for _, want := range []string{`"memdev": "` + memdev + `"`, `"region": "region0"`, `"node": 2`, `"claimName": "default/c1"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("state file lacks %s:\n%s", want, data)
		}
	}

	// unprepare releases: offline, destroy, disable
	noErr(t, unprepare(t, p, "u1"))
	e.wantReleased(t, "region0", memdev)
	e.wantClean(t, p)
	// an unknown claim is fine
	noErr(t, unprepare(t, p, "u1"))

	// prepare again after a release (memdev disabled): enabled again
	noErr(t, prepare(t, p, poolClaim("u2", "c2", "pooled0", exclusiveData)).Err)
	e.wantCommand(t, "cxl enable-memdev "+memdev)
	noErr(t, unprepare(t, p, "u2"))
}

func TestPoolPrepareSharedTwoClaims(t *testing.T) {
	e := newPoolTestEnv(t)
	memdev := e.plug(0xc1ae0001)
	p := e.driver(t)

	res := prepare(t, p, poolClaim("u1", "c1", "shared0", sharedData))
	noErr(t, res.Err)
	if !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl-pool=claim-u1-0"}) {
		t.Fatalf("unexpected device %+v", res.Devices[0])
	}
	if n := e.onlineBlocks("region0"); n != 0 {
		t.Fatalf("%d blocks of shared memory online", n) // shared memory is never onlined
	}
	if d := e.k.DaxDriver("dax0.0"); d != "device_dax" {
		t.Fatalf("dax0.0 bound to %q", d)
	}
	sharedEnv := func(uid string) []string {
		return []string{"CXL_C1AE0001_DAX=/dev/dax0.0", "CXL_C1AE0001_MODE=dax", "CXL_C1AE0001_READONLY=0",
			"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=268435456", "CXL_CLAIM_" + uid + "_0=1"}
	}
	cd := e.wantCDIDevice(t, "claim-u1-0", sharedEnv("u1"))
	dev := e.device(p, "u1", 0)
	wantNodes := []*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: int64(dev.DaxMajor), Minor: int64(dev.DaxMinor)}}
	if dev.DaxMajor == 0 || !reflect.DeepEqual(cd.ContainerEdits.DeviceNodes, wantNodes) {
		t.Fatalf("unexpected device nodes %+v", cd.ContainerEdits.DeviceNodes)
	}

	// a second claim on the same device reuses the region and has a CDI
	// device of its own
	noErr(t, prepare(t, p, poolClaim("u2", "c2", "shared0", sharedData)).Err)
	if n := strings.Count(e.commands(), "create-region"); n != 1 {
		t.Fatalf("region created %d times", n)
	}
	if spec := e.cdiSpec(t); len(spec.Devices) != 2 {
		t.Fatalf("expected one CDI device per claim, got %+v", spec.Devices)
	}
	e.wantCDIDevice(t, "claim-u2-0", sharedEnv("u2"))
	// an exclusive claim on the shared serial is refused
	res = prepare(t, p, poolClaim("u3", "c3", "shared0", `{"serial":"0xc1ae0001","shared":false,"size":268435456}`))
	wantErr(t, res.Err, "another claim prepared it with shared=true")

	// unprepare of one keeps the device
	noErr(t, unprepare(t, p, "u1"))
	if strings.Contains(e.commands(), "disable-region") || !p.Serials()[0xc1ae0001] {
		t.Fatalf("device released while still used:\n%s", e.commands())
	}
	if cdiDeviceByName(e.cdiSpec(t), "claim-u1-0") != nil {
		t.Fatal("CDI device of an unprepared claim left")
	}
	e.wantCDIDevice(t, "claim-u2-0", sharedEnv("u2"))
	// unprepare of both releases
	noErr(t, unprepare(t, p, "u2"))
	e.wantReleased(t, "region0", memdev)
	e.wantClean(t, p)
}

func TestPoolRestart(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	p := e.driver(t)
	res := prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData))
	noErr(t, res.Err)
	cmds := e.commands()
	// a restart rewrites the CDI spec (newNodeState removes the specs of
	// both drivers)
	_ = os.RemoveAll(e.cdiDir)

	p2 := e.driver(t)
	if !p2.Serials()[0xc1ee0001] {
		t.Fatalf("restored serials %v", p2.Serials())
	}
	if cdiDeviceByName(e.cdiSpec(t), "claim-u1-0") == nil {
		t.Fatal("CDI spec not rewritten after restart")
	}
	res2 := prepare(t, p2, poolClaim("u1", "c1", "pooled0", exclusiveData))
	if res2.Err != nil || len(res2.Devices) != 1 || !slices.Equal(res2.Devices[0].CDIDeviceIDs, res.Devices[0].CDIDeviceIDs) {
		t.Fatalf("stored result not returned: %+v", res2)
	}
	if got := e.commands(); got != cmds {
		t.Fatalf("repeated Prepare ran commands:\n%s", strings.TrimPrefix(got, cmds))
	}

	// the memdev disappears while the driver is down: kept until Unprepare
	e.k.Unplug(0xc1ee0001)
	p3 := e.driver(t)
	if !p3.Serials()[0xc1ee0001] {
		t.Fatal("device of a gone memdev dropped")
	}
	noErr(t, unprepare(t, p3, "u1"))
	// its region is hollow, kept while its memory is online
	e.wantNoClaims(t, p3)
}

func TestPoolPrepareErrors(t *testing.T) {
	e := newPoolTestEnv(t)
	p := e.driver(t)
	// no status entry yet
	wantErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", "")).Err, "no entry")
	// memdev never appears
	wantErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err, "deadline exceeded")
	e.wantClean(t, p)

	// the second device of a claim fails: the first one is rolled back
	memdev := e.plug(0xc1ee0001)
	claim := addPoolDevice(poolClaim("u2", "c2", "pooled0", exclusiveData), "mem2", "pooled1", "")
	wantErr(t, prepare(t, p, claim).Err, "pooled1")
	e.wantClean(t, p)
	// the second device of a claim fails in the kernel: the first one is
	// rolled back
	claim = addPoolDevice(poolClaim("u3", "c3", "pooled0", exclusiveData), "mem2", "pooled1", `{"serial":"0xc1ee0002","shared":false,"size":268435456}`)
	wantErr(t, prepare(t, p, claim).Err, "pooled1")
	e.wantReleased(t, "region0", memdev)
	e.wantClean(t, p)
}

func TestBuildDevInfosSkipsPoolDevices(t *testing.T) {
	devices := nricxl.NewDevices()
	region := func(name string, node int, serial uint64) *nricxl.RegionDevice {
		return &nricxl.RegionDevice{
			Name: name, Size: 1 << 30, Mode: "ram", Node: node, Enabled: true,
			Memories: []*nricxl.MemoryDevice{{Name: "mem-" + name, Serial: serial, Enabled: true}},
		}
	}
	devices.RegionDevices = []*nricxl.RegionDevice{region("region0", 2, 0xc100e2e0), region("region1", 3, 0xc1ee0001)}
	devices.MemoryNodes = []*nricxl.MemoryNode{{ID: 0, Size: 1 << 30}, {ID: 2, Size: 1 << 30}, {ID: 3, Size: 1 << 30}}
	devInfos, err := buildDevInfos(&DriverConfig{}, devices, map[uint64]bool{0xc1ee0001: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := devInfos["region0-node2"]; !ok {
		t.Fatalf("local region missing: %v", devInfos)
	}
	if _, ok := devInfos["region1-node3"]; ok {
		t.Fatal("pool region published")
	}
	dram, ok := devInfos["dram"].Dev.(*device.DRAM)
	if !ok || !slices.Equal(dram.Nodes, []int{0}) {
		t.Fatalf("pool node counted as DRAM: %+v", devInfos["dram"])
	}
	if devInfos, _ := buildDevInfos(&DriverConfig{}, devices, nil, nil); devInfos["region1-node3"] == nil {
		t.Fatal("region1 skipped without the pool driver")
	}
}

const (
	daxConfig = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"dax"}}`
	roConfig  = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"readOnly":true}}`
)

// withConfig adds an opaque config of the pool driver to the allocation
// of a claim.
func withConfig(c *resourceapi.ResourceClaim, source resourceapi.AllocationConfigSource, requests []string, params string) *resourceapi.ResourceClaim {
	c.Status.Allocation.Devices.Config = append(c.Status.Allocation.Devices.Config, resourceapi.DeviceAllocationConfiguration{
		Source:   source,
		Requests: requests,
		DeviceConfiguration: resourceapi.DeviceConfiguration{Opaque: &resourceapi.OpaqueDeviceConfiguration{
			Driver: device.PoolDriverName, Parameters: runtime.RawExtension{Raw: []byte(params)},
		}},
	})
	return c
}

func TestPoolPrepareExclusiveDax(t *testing.T) {
	e := newPoolTestEnv(t)
	memdev := e.plug(0xc1ee0001)
	p := e.driver(t)

	claim := withConfig(poolClaim("u1", "c1", "pooled0", exclusiveData), resourceapi.AllocationConfigSourceClaim, nil, daxConfig)
	res := prepare(t, p, claim)
	noErr(t, res.Err)
	if !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl-pool=claim-u1-0"}) {
		t.Fatalf("unexpected device %+v", res.Devices[0])
	}
	if d := e.k.DaxDriver("dax0.0"); d != "device_dax" {
		t.Fatalf("dax0.0 bound to %q", d)
	}
	if n := e.onlineBlocks("region0"); n != 0 {
		t.Fatalf("%d blocks of a dax device online", n) // a dax device is never onlined
	}
	cd := e.wantCDIDevice(t, "claim-u1-0", []string{"CXL_C1EE0001_DAX=/dev/dax0.0", "CXL_C1EE0001_MODE=dax", "CXL_C1EE0001_READONLY=0",
		"CXL_C1EE0001_SERIAL=0xc1ee0001", "CXL_C1EE0001_SHARED=0", "CXL_C1EE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"})
	d := e.device(p, "u1", 0)
	wantNodes := []*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: int64(d.DaxMajor), Minor: int64(d.DaxMinor)}}
	if !reflect.DeepEqual(cd.ContainerEdits.DeviceNodes, wantNodes) {
		t.Fatalf("unexpected device nodes %+v", cd.ContainerEdits.DeviceNodes)
	}
	if d.Mode != api.ModeDax || d.NumaNode != -1 || d.DaxDevice != "/dev/dax0.0" {
		t.Fatalf("prepared device %+v", d)
	}

	// another claim on the serial in numa mode is refused
	res = prepare(t, p, poolClaim("u2", "c2", "pooled0", exclusiveData))
	wantErr(t, res.Err, "mode numa, but another claim prepared it in mode dax")

	noErr(t, unprepare(t, p, "u1"))
	e.wantReleased(t, "region0", memdev)
	e.wantClean(t, p)
}

func TestPoolReadOnlyCDIDevices(t *testing.T) {
	e := newPoolTestEnv(t)
	memdev := e.plug(0xc1ae0001)
	p := e.driver(t)

	res := prepare(t, p, withConfig(poolClaim("u1", "c1", "shared0", sharedData), resourceapi.AllocationConfigSourceClaim, nil, roConfig))
	noErr(t, res.Err)
	if !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl-pool=claim-u1-0"}) {
		t.Fatalf("unexpected device %+v", res.Devices[0])
	}
	ro := e.wantCDIDevice(t, "claim-u1-0", []string{"CXL_C1AE0001_DAX=/dev/dax0.0", "CXL_C1AE0001_MODE=dax", "CXL_C1AE0001_READONLY=1",
		"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"})
	d := e.device(p, "u1", 0)
	wantNodes := []*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: int64(d.DaxMajor), Minor: int64(d.DaxMinor), Permissions: "r"}}
	if !reflect.DeepEqual(ro.ContainerEdits.DeviceNodes, wantNodes) {
		t.Fatalf("unexpected read-only device nodes %+v", ro.ContainerEdits.DeviceNodes)
	}

	// a read-write claim of the same device: its own CDI device, the
	// region is reused
	res = prepare(t, p, poolClaim("u2", "c2", "shared0", sharedData))
	noErr(t, res.Err)
	if !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl-pool=claim-u2-0"}) {
		t.Fatalf("unexpected device %+v", res.Devices[0])
	}
	if n := strings.Count(e.commands(), "create-region"); n != 1 {
		t.Fatalf("region created %d times", n)
	}
	rw := e.wantCDIDevice(t, "claim-u2-0", []string{"CXL_C1AE0001_DAX=/dev/dax0.0", "CXL_C1AE0001_MODE=dax", "CXL_C1AE0001_READONLY=0",
		"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=268435456", "CXL_CLAIM_u2_0=1"})
	if rw.ContainerEdits.DeviceNodes[0].Permissions != "" {
		t.Fatalf("read-write device node %+v", rw.ContainerEdits.DeviceNodes[0])
	}

	// unprepare the read-only claim: its CDI device goes, the device stays
	noErr(t, unprepare(t, p, "u1"))
	if cdiDeviceByName(e.cdiSpec(t), "claim-u1-0") != nil || strings.Contains(e.commands(), "disable-region") {
		t.Fatalf("after the read-only unprepare: %+v\n%s", e.cdiSpec(t), e.commands())
	}
	noErr(t, unprepare(t, p, "u2"))
	e.wantReleased(t, "region0", memdev)
	e.wantClean(t, p)
}

func TestPoolConfigErrors(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ae0001)
	p := e.driver(t)
	for _, tc := range []struct {
		data, params, err string
	}{
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`, "MemoryConfig: device: a shared device is used as dax only"},
		{exclusiveData, roConfig, "MemoryConfig: device.readOnly needs mode dax, block or fs"},
		{exclusiveData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"ram"}}`, `MemoryConfig: device.mode: invalid mode "ram" (numa, dax, block or fs)`},
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"access":"cached"}}`, "MemoryConfig: device.access needs mode fs"},
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"fsType":"erofs"}}`, "MemoryConfig: device.fsType needs mode fs"},
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"fsTypes":["erofs"]}}`, `unknown field "device.fsTypes"`},
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block"}}`, "MemoryConfig: device.mode block needs a persistent device"},
		{exclusiveData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":true}}`, "MemoryConfig: device.mode fs needs a persistent device"},
		{sharedData, `{"apiVersion":"v1","kind":"MemoryConfig"}`, `MemoryConfig: apiVersion "v1", expected "cxl.nri.io/v1alpha1"`},
		{sharedData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"DeviceConfig","mode":"dax"}`, `unknown kind "DeviceConfig" (MemoryConfig)`},
		// an old kind would give a read-write device of a reader
		{sharedData, `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"PoolDeviceConfig","readOnly":true}`,
			`cxl-pool.nri.io: preparing claim default/c1: unknown kind "PoolDeviceConfig" (MemoryConfig)`},
		{sharedData, `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"MemoryPolicyConfig","memoryUseOrder":"first-dram"}`,
			`unknown kind "MemoryPolicyConfig" (MemoryConfig)`},
	} {
		claim := withConfig(poolClaim("u1", "c1", "shared0", tc.data), resourceapi.AllocationConfigSourceClaim, nil, tc.params)
		wantErr(t, prepare(t, p, claim).Err, tc.err)
		e.wantClean(t, p)
	}
	if strings.Contains(e.commands(), "create-region") {
		t.Fatalf("a refused config touched the device:\n%s", e.commands())
	}
}

// TestPoolCDISpecKeys builds the CDI devices of a claim with two devices
// of one serial, the second one read-only, and a third device: one CDI
// device per allocation result with its own env (the second device of the
// serial has the key <HEX>_2) and device node; none of a companion claim.
func TestPoolCDISpecKeys(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ae0001)
	e.plug(0xc1ee0001)
	p := e.driver(t)
	c := poolClaim("u1", "c1", "shared0", sharedData)
	// the results 0 and 1 of shared0, 2 of cxl.nri.io, 3 of pooled0
	c.Status.Allocation.Devices.Results = slices.Insert(c.Status.Allocation.Devices.Results, 1,
		resourceapi.DeviceRequestAllocationResult{Request: "mem1", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: "shared0",
			ConsumedCapacity: poolConsumed(sharedData)})
	addPoolDevice(c, "mem3", "pooled0", `{"serial":"0xc1ee0001","shared":false,"size":536870912}`)
	withConfig(c, resourceapi.AllocationConfigSourceClaim, []string{"mem1"}, roConfig)
	noErr(t, prepare(t, p, c).Err)
	spec := e.cdiSpec(t)
	dax := e.device(p, "u1", 0)
	node := e.device(p, "u1", 3).NumaNode
	want := []cdiSpecs.Device{
		{Name: "claim-u1-0", ContainerEdits: cdiSpecs.ContainerEdits{
			Env: []string{"CXL_C1AE0001_DAX=/dev/dax0.0", "CXL_C1AE0001_MODE=dax", "CXL_C1AE0001_READONLY=0", "CXL_C1AE0001_SERIAL=0xc1ae0001",
				"CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"},
			DeviceNodes: []*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: int64(dax.DaxMajor), Minor: int64(dax.DaxMinor)}},
		}},
		{Name: "claim-u1-1", ContainerEdits: cdiSpecs.ContainerEdits{
			Env: []string{"CXL_C1AE0001_2_DAX=/dev/dax0.0", "CXL_C1AE0001_2_MODE=dax", "CXL_C1AE0001_2_READONLY=1", "CXL_C1AE0001_2_SERIAL=0xc1ae0001",
				"CXL_C1AE0001_2_SHARED=1", "CXL_C1AE0001_2_SIZE=268435456", "CXL_CLAIM_u1_1=1"},
			DeviceNodes: []*cdiSpecs.DeviceNode{{Path: "/dev/dax0.0", Type: "c", Major: int64(dax.DaxMajor), Minor: int64(dax.DaxMinor), Permissions: "r"}},
		}},
		{Name: "claim-u1-3", ContainerEdits: cdiSpecs.ContainerEdits{
			Env: []string{"CXL_C1EE0001_MODE=numa", "CXL_C1EE0001_NODE=" + strconv.Itoa(node), "CXL_C1EE0001_SERIAL=0xc1ee0001", "CXL_C1EE0001_SHARED=0",
				"CXL_C1EE0001_SIZE=536870912", "CXL_CLAIM_u1_3=1"},
		}},
	}
	if spec.Kind != device.PoolCDIKind || !reflect.DeepEqual(spec.Devices, want) {
		t.Fatalf("CDI spec %+v", spec)
	}
	noErr(t, unprepare(t, p, "u1"))
	e.wantClean(t, p)
}

// A shared pool device needs at least one consumed share, checked before
// the device is touched: a claim of shares "0" fits next to an exclusive
// holder.
func TestPoolSharesGuard(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ae0001)
	p := e.driver(t)
	withShares := func(uid, shares string) *resourceapi.ResourceClaim {
		c := poolClaim(uid, "c-"+uid, "shared0", sharedData)
		c.Status.Allocation.Devices.Results[0].ConsumedCapacity = nil
		if shares != "" {
			c.Status.Allocation.Devices.Results[0].ConsumedCapacity = map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse(shares)}
		}
		return c
	}
	for _, tc := range []struct{ shares, text string }{{"0", `"0"`}, {"", `""`}} {
		wantErr(t, prepare(t, p, withShares("u0", tc.shares)).Err,
			"cxl-pool.nri.io: preparing claim default/c-u0: device 0xc1ae0001: consumed shares "+tc.text+" is less than 1: request shares: 1 (a share) or no shares (exclusive)")
	}
	if strings.Contains(e.commands(), "create-region") {
		t.Fatalf("a refused claim touched the device:\n%s", e.commands())
	}
	noErr(t, prepare(t, p, withShares("u1", "1")).Err)
	noErr(t, unprepare(t, p, "u1"))
	noErr(t, prepare(t, p, withShares("u2", "1M")).Err)
	noErr(t, unprepare(t, p, "u2"))
	// a device that is not shared has no shares
	e.plug(0xc1ee0001)
	noErr(t, prepare(t, p, poolClaim("u3", "c3", "pooled0", exclusiveData)).Err)
	noErr(t, unprepare(t, p, "u3"))
}

// TestPoolPrepareMemoryConfig prepares a pool claim with MemoryConfig
// entries of the pool driver: a class preset with a container and a pool
// section (the controller's, not read here), changed by a claim entry; the
// container settings of the result are in the prepared state and in the
// snapshot that the NRI plugin reads. Invalid entries and values touch no
// device.
func TestPoolPrepareMemoryConfig(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	p := e.driver(t)
	const (
		class = resourceapi.AllocationConfigSourceClass
		claim = resourceapi.AllocationConfigSourceClaim
	)
	c := poolClaim("u1", "c1", "pooled0", exclusiveData)
	c.Spec.Devices.Requests = []resourceapi.DeviceRequest{{Name: "mem", Exactly: &resourceapi.ExactDeviceRequest{DeviceClassName: "cxl-pool"}}}
	withConfig(c, claim, []string{"mem"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"maxStep":"64Mi"}}}`)
	withConfig(c, class, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"},"container":{"steering":{"policy":"auto"}},`+
		`"pool":{"opaque":{"fake-cxl-pool":{"numaNode":1},"other":{"x":1}}}}`)
	// an entry of cxl.nri.io is not read by the pool driver
	withDriverConfig(c, device.DriverName, claim, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"none"}}}`)
	res := prepare(t, p, c)
	noErr(t, res.Err)
	want := config.ResultSettings{
		Container: &config.Container{Steering: &config.Steering{Policy: config.PolicyAuto, MaxStep: "64Mi"}},
		Origins:   map[string]string{config.FieldPolicy: "class cxl-pool", config.FieldMaxStep: "claim default/c1 request mem"},
	}
	if d := e.device(p, "u1", 0); d.Mode != api.ModeNUMA || d.NumaNode != 2 || !reflect.DeepEqual(d.ResultSettings, want) {
		t.Fatalf("prepared device %+v", d)
	}
	got := p.ClaimResults("u1")
	if len(got) != 1 || got[0].Index != 0 || got[0].Request != "mem" || got[0].Mode != api.ModeNUMA || got[0].NumaNode != 2 ||
		got[0].Size != 256<<20 || !reflect.DeepEqual(got[0].Settings, want) {
		t.Fatalf("claim results %+v", got)
	}
	e.wantCDIDevice(t, "claim-u1-0", []string{"CXL_C1EE0001_MODE=numa", "CXL_C1EE0001_NODE=2", "CXL_C1EE0001_SERIAL=0xc1ee0001",
		"CXL_C1EE0001_SHARED=0", "CXL_C1EE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"})

	// the NRI plugin steers a container that uses the result: the plan
	// of policy auto of a CXL node is first-cxl, of the quota of the result
	ctr, err := createdContainer(t, e.st, nil, p, "u1", 0)
	noErr(t, err)
	if ctr.Management != containers.ManagementSteered || ctr.Steering != "auto from class cxl-pool" || ctr.Claimed.String() != "2" ||
		ctr.Plan == nil || ctr.Plan.String() != "waypoints=[[2:268435456]] minStep=67108864 maxStep=67108864" {
		t.Fatalf("container %+v, plan %v", ctr, ctr.Plan)
	}

	// the settings survive a restart of the driver
	p = e.driver(t)
	if got := p.ClaimResults("u1"); len(got) != 1 || !reflect.DeepEqual(got[0].Settings, want) {
		t.Fatalf("claim results after a restart %+v", got)
	}
	noErr(t, unprepare(t, p, "u1"))
	e.wantClean(t, p)

	commands := e.commands()
	for _, tc := range []struct {
		source      resourceapi.AllocationConfigSource
		params, err string
	}{
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"fencing":"none"}}`,
			"cxl-pool.nri.io: preparing claim default/c2: MemoryConfig: container.fencing: set by the driver configuration only (defaults.container.fencing)"},
		{class, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"waypoints","waypoints":[{"targetUsages":[{"memoryType":"HBM","usage":"1Gi"}]}]}}}`,
			`cxl-pool.nri.io: preparing claim default/c2: request mem: MemoryConfig: container.steering.waypoints[0].targetUsages[0].memoryType: invalid memory type "HBM" (DRAM or CXL)`},
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","pool":{"opaque":{"fake-cxl-pool":1}}}`,
			"cxl-pool.nri.io: preparing claim default/c2: request mem: MemoryConfig: pool.opaque.fake-cxl-pool: not a JSON object"},
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","pool":{"slot":"1"}}`,
			`cxl-pool.nri.io: preparing claim default/c2: MemoryConfig: FromClaim config 0: json: unknown field "pool.slot"`},
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"none","minStep":"1Gi"}}}`,
			"cxl-pool.nri.io: preparing claim default/c2: request mem: MemoryConfig: container.steering.minStep needs a policy other than none"},
	} {
		wantErr(t, prepare(t, p, withConfig(poolClaim("u2", "c2", "pooled0", exclusiveData), tc.source, nil, tc.params)).Err, tc.err)
		e.wantClean(t, p)
	}
	if got := e.commands(); got != commands {
		t.Fatalf("a refused config touched the device:\n%s", strings.TrimPrefix(got, commands))
	}
}
