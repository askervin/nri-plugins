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
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
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

// wantLog checks that a log of calls ends with want.
func wantLog(t *testing.T, log, want string) {
	t.Helper()
	if !strings.HasSuffix(log, want) {
		t.Fatalf("calls\n%s\nexpected to end with\n%s", log, want)
	}
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

// The NRI readers and the publisher never wait for a Prepare that lends.
func TestPrepareDoesNotBlockReaders(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	bl := &blockingLender{fakeLender: newFakeLender(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	hooks := &fakeHooks{}
	e.s.Lender().Set(bl, hooks)
	ctx := context.Background()
	e.mustPrepare(localClaim("u0", 32*mib))

	done := make(chan error, 1)
	go func() { done <- prepareOn(ctx, e.s, localCompanion("u1", 64*mib)) }()
	select {
	case <-bl.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("Prepare did not lend")
	}
	readers := make(chan error, 1)
	go func() {
		if e.s.ClaimInfo("u0") == nil {
			readers <- errors.New("no claim info of u0")
			return
		}
		_, _, _ = e.s.PreparedResult("u0", 0)
		_ = e.publisher.Resources()
		readers <- nil
	}()
	select {
	case err := <-readers:
		noErr(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("claim info or resources waited for a lend")
	}
	close(bl.release)
	select {
	case err := <-done:
		noErr(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Prepare of u1 did not finish")
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
	wantLog(t, hooks.log(), "lending l1 cxl-lease-l1\nprepared l1")
	e.mustUnprepare("u1")
	e.mustUnprepare("u0")
	e.wantClean()
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

// The MemoryConfig entries of results of every device type: presets of
// classes, settings with origins, markers; refused entries touch no device.
func TestPrepareMemoryConfig(t *testing.T) {
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
	info := e.s.ClaimInfo("u1")
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
		if len(e.prepared()) != 0 || e.inUse() || leases.open["u9"] {
			t.Fatalf("%s: prepared %v, memdev in use %v", tc.err, e.prepared(), e.inUse())
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
			`claim demo/claim-u9: MemoryConfig: FromClaim config 0: kind "DeviceConfig", expected "MemoryConfig"`},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, nil, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryPolicyConfig","memoryUseOrder":"first-dram"}`)},
			`claim demo/claim-u9: MemoryConfig: FromClaim config 0: kind "MemoryPolicyConfig", expected "MemoryConfig"`},
		{[]resourcev1.DeviceAllocationConfiguration{memoryConfigEntry(claim, nil, `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"MemoryConfig"}`)},
			`claim demo/claim-u9: MemoryConfig: FromClaim config 0: apiVersion "cxl-pool.nri.io/v1alpha1", expected "cxl.nri.io/v1alpha1"`},
		// every entry of the driver is checked, also of other requests
		{[]resourcev1.DeviceAllocationConfiguration{
			memoryConfigEntry(class, nil, localDaxConfig),
			memoryConfigEntry(claim, []string{"other"}, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"online":"all"}}`)},
			`claim demo/claim-u9: MemoryConfig: FromClaim config 0: json: unknown field "device.online"`},
	} {
		wantErr(t, e.prepare(memoryConfigClaim("u9", tc.configs...)), tc.err)
		if len(e.prepared()) != 0 || e.inUse() || leases.open["u9"] {
			t.Fatalf("%s: prepared %v, memdev in use %v", tc.err, e.prepared(), e.inUse())
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
