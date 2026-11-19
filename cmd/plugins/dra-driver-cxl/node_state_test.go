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
	"slices"
	"strconv"
	"strings"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

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

// injectDevices adds devices of regions, DRAM or the lease device to the
// devices of the scan of the node state of the env.
func injectDevices(e *localTestEnv, infos ...*dra.DeviceInfo) {
	e.t.Helper()
	devs, err := e.allocatable()
	noErr(e.t, err)
	for _, d := range infos {
		devs[d.Name] = d
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

func (f *fakeLeaseClaims) CDIEdits(uid string) cdiSpecs.ContainerEdits {
	return cdiSpecs.ContainerEdits{Env: []string{"LEASE_" + uid + "=1"}}
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

// A container gets the management of the prepared results that it uses,
// as the MemoryConfig entries of their requests say: the NRI plugin finds
// each result in the driver by the marker of the result in its env.
func TestContainerOfResultSettings(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	leases := &fakeLeaseClaims{st: e.st}
	e.s.SetLeases(leases)
	injectDevices(e,
		&dra.DeviceInfo{Name: "region5-node4", Dev: &dra.Region{Name: "region5", NumaNode: 4, Size: 1 << 30}},
		&dra.DeviceInfo{Name: "dram", Dev: &dra.DRAM{Nodes: []int{0}, Size: 1 << 30}},
		&dra.DeviceInfo{Name: device.LeaseDeviceName, Dev: &dra.LeaseToken{}})
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
	node := localRegionNode(e)
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
		c, err := createdContainer(t, e.st, e.s, "u1", tc.results...)
		noErr(t, err)
		if got := strings.ToLower(string(c.Management)) + " " + c.Claimed.String() + " " + c.Steering; got != tc.want {
			t.Errorf("results %v: %q, expected %q", tc.results, got, tc.want)
		}
	}
	_, err := createdContainer(t, e.st, e.s, "u1", 1, 2)
	wantErr(t, err, "container demo/pod/ctr: container.steering.policy: class cxl-region says auto, claim demo/claim-u1 request dram says first-dram")
	noErr(t, leases.CloseClaim(context.Background(), "u1"))
	e.mustUnprepare("u1")
	e.wantClean()
}
