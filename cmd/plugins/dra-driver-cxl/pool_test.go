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
	"strings"
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

const (
	exclusiveData = `{"serial":"0xc1ee0001","shared":false,"size":268435456,"host":"n1"}`
	sharedData    = `{"serial":"0xc1ae0001","shared":true,"size":268435456}`
)

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
