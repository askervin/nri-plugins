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
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

const (
	exclusiveData = `{"serial":"0xc1ee0001","shared":false,"size":268435456,"host":"n1"}`
	sharedData    = `{"serial":"0xc1ae0001","shared":true,"size":268435456}`
)

func TestPoolPrepareSharedTwoClaims(t *testing.T) {
	e := newPoolTestEnv(t)
	dax0 := filepath.Join(e.k.DevRoot(), "dax0.0")
	memdev := e.plug(0xc1ae0001)
	p := e.driver(t)

	// the share of the claim's allocation result is in its record and in
	// the result for kubelet
	shareID := types.UID("share-1")
	c1 := poolClaim("u1", "c1", "shared0", sharedData)
	c1.Status.Allocation.Devices.Results[0].ShareID = &shareID
	c1.Status.Devices[1].ShareID = ptr(string(shareID))
	res := prepare(t, p, c1)
	noErr(t, res.Err)
	if !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"cxl-pool.nri.io/device=claim-u1-0"}) || res.Devices[0].ShareID == nil || *res.Devices[0].ShareID != shareID {
		t.Fatalf("unexpected device %+v", res.Devices[0])
	}
	if prep := e.preparation("u1"); prep == nil || prep.Results[0].ShareID != string(shareID) {
		t.Fatalf("preparation %+v", prep)
	}
	if n := e.onlineBlocks("region0"); n != 0 {
		t.Fatalf("%d blocks of shared memory online", n) // shared memory is never onlined
	}
	if d := e.k.DaxDriver("dax0.0"); d != "device_dax" {
		t.Fatalf("dax0.0 bound to %q", d)
	}
	sharedEnv := func(uid string) []string {
		return []string{"CXL_C1AE0001_DAX=" + dax0, "CXL_C1AE0001_MODE=dax", "CXL_C1AE0001_READONLY=0",
			"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=268435456", "CXL_CLAIM_" + uid + "_0=1"}
	}
	cd := e.wantCDIDevice(t, "claim-u1-0", sharedEnv("u1"))
	dev := e.device(p, "u1", 0)
	wantNodes := []*cdiSpecs.DeviceNode{{Path: dax0, Type: "c", Major: int64(dev.DaxMajor), Minor: int64(dev.DaxMinor)}}
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
	dax0 := filepath.Join(e.k.DevRoot(), "dax0.0")
	memdev := e.plug(0xc1ee0001)
	p := e.driver(t)

	claim := withConfig(poolClaim("u1", "c1", "pooled0", exclusiveData), resourceapi.AllocationConfigSourceClaim, nil, daxConfig)
	res := prepare(t, p, claim)
	noErr(t, res.Err)
	if !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"cxl-pool.nri.io/device=claim-u1-0"}) {
		t.Fatalf("unexpected device %+v", res.Devices[0])
	}
	if d := e.k.DaxDriver("dax0.0"); d != "device_dax" {
		t.Fatalf("dax0.0 bound to %q", d)
	}
	if n := e.onlineBlocks("region0"); n != 0 {
		t.Fatalf("%d blocks of a dax device online", n) // a dax device is never onlined
	}
	cd := e.wantCDIDevice(t, "claim-u1-0", []string{"CXL_C1EE0001_DAX=" + dax0, "CXL_C1EE0001_MODE=dax", "CXL_C1EE0001_READONLY=0",
		"CXL_C1EE0001_SERIAL=0xc1ee0001", "CXL_C1EE0001_SHARED=0", "CXL_C1EE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"})
	d := e.device(p, "u1", 0)
	major, minor, err := e.k.Kernel().DaxDevNumbers("dax0.0")
	noErr(t, err)
	wantNodes := []*cdiSpecs.DeviceNode{{Path: dax0, Type: "c", Major: int64(major), Minor: int64(minor)}}
	if !reflect.DeepEqual(cd.ContainerEdits.DeviceNodes, wantNodes) {
		t.Fatalf("unexpected device nodes %+v", cd.ContainerEdits.DeviceNodes)
	}
	if d.Mode != api.ModeDax || d.NumaNode != -1 || d.DaxDevice != dax0 || d.DaxMajor != major || d.DaxMinor != minor {
		t.Fatalf("prepared device %+v", d)
	}

	// another claim on the serial in numa mode is refused
	res = prepare(t, p, poolClaim("u2", "c2", "pooled0", exclusiveData))
	wantErr(t, res.Err, "mode numa, but another claim prepared it in mode dax")

	noErr(t, unprepare(t, p, "u1"))
	e.wantReleased(t, "region0", memdev)
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
			"cxl-pool.nri.io: claim default/c-u0: device 0xc1ae0001: consumed shares "+tc.text+" is less than 1: request shares: 1 (a share) or no shares (exclusive)")
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
	if _, got, ok := p.PreparedResult("u1", 0); !ok || got.Result != 0 || got.RequestName != "mem" || got.Mode != api.ModeNUMA ||
		!reflect.DeepEqual(got.NUMANodes, []int{2}) || got.ConsumedBytes != 256<<20 || !reflect.DeepEqual(got.ResultSettings, want) {
		t.Fatalf("prepared result %+v", got)
	}
	e.wantCDIDevice(t, "claim-u1-0", []string{"CXL_C1EE0001_MODE=numa", "CXL_C1EE0001_NODE=2", "CXL_C1EE0001_SERIAL=0xc1ee0001",
		"CXL_C1EE0001_SHARED=0", "CXL_C1EE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"})

	// the NRI plugin steers a container that uses the result: the plan
	// of policy auto of a CXL node is first-cxl, of the quota of the result
	ctr, err := createdContainer(t, e.st, p, "u1", 0)
	noErr(t, err)
	if ctr.Management != containers.ManagementSteered || ctr.Steering != "auto from class cxl-pool" || ctr.Claimed.String() != "2" ||
		ctr.Plan == nil || ctr.Plan.String() != "waypoints=[[2:268435456]] minStep=67108864 maxStep=67108864" {
		t.Fatalf("container %+v, plan %v", ctr, ctr.Plan)
	}

	// the settings survive a restart of the driver
	p = e.driver(t)
	if _, got, ok := p.PreparedResult("u1", 0); !ok || !reflect.DeepEqual(got.ResultSettings, want) {
		t.Fatalf("prepared result after a restart %+v", got)
	}
	noErr(t, unprepare(t, p, "u1"))
	e.wantClean(t, p)

	commands := e.commands()
	for _, tc := range []struct {
		source      resourceapi.AllocationConfigSource
		params, err string
	}{
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"fencing":"none"}}`,
			"cxl-pool.nri.io: claim default/c2: MemoryConfig: container.fencing: set by the driver configuration only (defaults.container.fencing)"},
		{class, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"waypoints","waypoints":[{"targetUsages":[{"memoryType":"HBM","usage":"1Gi"}]}]}}}`,
			`cxl-pool.nri.io: claim default/c2: request mem: MemoryConfig: container.steering.waypoints[0].targetUsages[0].memoryType: invalid memory type "HBM" (DRAM or CXL)`},
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","pool":{"opaque":{"fake-cxl-pool":1}}}`,
			"cxl-pool.nri.io: claim default/c2: request mem: MemoryConfig: pool.opaque.fake-cxl-pool: not a JSON object"},
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","pool":{"slot":"1"}}`,
			`cxl-pool.nri.io: claim default/c2: MemoryConfig: FromClaim config 0: json: unknown field "pool.slot"`},
		{claim, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","container":{"steering":{"policy":"none","minStep":"1Gi"}}}`,
			"cxl-pool.nri.io: claim default/c2: request mem: MemoryConfig: container.steering.minStep needs a policy other than none"},
	} {
		wantErr(t, prepare(t, p, withConfig(poolClaim("u2", "c2", "pooled0", exclusiveData), tc.source, nil, tc.params)).Err, tc.err)
		e.wantClean(t, p)
	}
	if got := e.commands(); got != commands {
		t.Fatalf("a refused config touched the device:\n%s", strings.TrimPrefix(got, commands))
	}
}
