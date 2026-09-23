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
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// fakeHooks records the leaseHooks calls.
type fakeHooks struct {
	mu         sync.Mutex
	calls      []string
	lendingErr error
	devs       []lentDevice
	source     state.Source // of the devices
	fsDir      string       // FsDir of the lend records
	name       string       // Name of the lend records
	onPrepared func(string) // called by OnPrepared with the lease id
}

func (h *fakeHooks) OnLending(id string, claim *resourceapi.ResourceClaim) (*lendRecord, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "lending "+id+" "+claim.Name)
	if h.lendingErr != nil {
		return nil, h.lendingErr
	}
	return &lendRecord{Lease: id, Pod: podRef{Namespace: testNS, Name: testPod, UID: testPodUID}, Container: testCtr,
		FsDir: h.fsDir, Name: h.name}, nil
}

func (h *fakeHooks) OnPrepared(id string, source state.Source, devs []lentDevice) {
	h.mu.Lock()
	h.calls = append(h.calls, "prepared "+id)
	h.devs, h.source = devs, source
	fn := h.onPrepared
	h.mu.Unlock()
	if fn != nil {
		fn(id)
	}
}

func (h *fakeHooks) OnLendFailed(id string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "failed "+id+": "+err.Error())
}

func (h *fakeHooks) OnReleasing(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "releasing "+id)
}

func (h *fakeHooks) log() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.calls, "\n")
}

var _ leaseHooks = (*fakeHooks)(nil)

// revokeFailer is a nodeLender whose RevokeNode fails.
type revokeFailer struct {
	*fakeLender
}

func (r revokeFailer) RevokeNode(ctx context.Context, podUID, name string, node int, holder string) error {
	_ = r.fakeLender.RevokeNode(ctx, podUID, name, node, holder)
	return fmt.Errorf("node %d busy", node)
}

// companionClaim returns the companion claim of a lease as the broker
// creates it: name, namespace, label and owner.
func companionClaim(id string) *resourceapi.ResourceClaim {
	return &resourceapi.ResourceClaim{ObjectMeta: metav1.ObjectMeta{
		Name:            companionName(id),
		Namespace:       testNS,
		UID:             types.UID("uid-" + companionName(id)),
		Labels:          map[string]string{device.LeaseLabel: id},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: testPod, UID: testPodUID, Controller: ptr(true)}},
	}}
}

func testLendRecord() *lendRecord {
	return &lendRecord{Lease: "l1", Pod: podRef{Namespace: testNS, Name: testPod, UID: testPodUID}, Container: testCtr}
}

func TestLeaseOf(t *testing.T) {
	if id := leaseOf(companionClaim("1a2b3c4d")); id != "1a2b3c4d" {
		t.Fatalf("lease of a companion claim %q", id)
	}
	if id := leaseOf(&resourceapi.ResourceClaim{}); id != "" {
		t.Fatalf("lease of another claim %q", id)
	}
}

func TestCompanionLenderDisabled(t *testing.T) {
	claim := companionClaim("l1")
	c := dra.NewLender(device.DriverName)
	_, err := c.Check("l1", claim)
	wantErr(t, err, "lease l1: lending to running containers is disabled (--leases=false)")
	hooks := &fakeHooks{}
	c.Set(nil, hooks)
	if _, err := c.Check("l1", claim); !errors.Is(err, errLendingUnavailable) {
		t.Fatalf("check without NRI: %v", err)
	}
	// numa devices cannot be lent without NRI, dax devices need no lend
	rec := testLendRecord()
	if err := c.Lend(context.Background(), rec, []lentDevice{numaLent(3)}); !errors.Is(err, errLendingUnavailable) || len(rec.NumaNodes) != 0 {
		t.Fatalf("lend without NRI: %+v %v", rec, err)
	}
	noErr(t, c.Lend(context.Background(), rec, []lentDevice{{DeviceType: device.DeviceTypeMemdev, Mode: api.ModeDax, DaxDevice: "/dev/dax0.1"}}))
	if rec.Lease != "l1" || rec.Container != testCtr || len(rec.NumaNodes) != 0 {
		t.Fatalf("dax lend record %+v", rec)
	}
	// revoking without NRI only warns
	noErr(t, c.Revoke(context.Background(), &lendRecord{Lease: "l1", NumaNodes: []int{3}}, "ns/c"))
	if log := hooks.log(); log != "" {
		t.Fatalf("hooks called: %s", log)
	}

	// a nil companionLender is disabled and safe to use
	var n *companionLender
	n.Set(newFakeLender(), hooks)
	n.Prepared("l1", state.SourceLocal, nil)
	n.Failed("l1", errors.New("x"))
	n.Releasing("l1")
	n.Reprepared(&lendRecord{Lease: "l1"}, claim, state.SourceLocal, nil)
	if hooks.log() != "" {
		t.Fatalf("nil companionLender: hooks %s", hooks.log())
	}
	_, err = n.Check("l1", claim)
	wantErr(t, err, "disabled")
}

func TestCompanionLenderLendRevoke(t *testing.T) {
	ctx := context.Background()
	claim := companionClaim("l1")
	nodes := newFakeLender()
	hooks := &fakeHooks{}
	c := dra.NewLender(device.PoolDriverName)
	c.Set(nodes, hooks)

	rec, err := c.Check("l1", claim)
	noErr(t, err)
	if !reflect.DeepEqual(rec, testLendRecord()) {
		t.Fatalf("lend of the lease %+v", rec)
	}
	hooks.lendingErr = errors.New("lease l1 is Failed")
	_, err = c.Check("l1", claim)
	wantErr(t, err, "lease l1 is Failed")
	hooks.lendingErr = nil

	devs := []lentDevice{
		numaLent(2),
		{DeviceType: device.DeviceTypeMemdev, Mode: api.ModeDax, DaxDevice: "/dev/dax0.0"},
		{DeviceType: device.DeviceTypeMemdev, Mode: api.ModeNUMA},
		numaLent(3),
	}
	noErr(t, c.Lend(ctx, rec, devs))
	want := &lendRecord{Lease: "l1", Pod: rec.Pod, Container: testCtr, NumaNodes: []int{2, 3}}
	if !reflect.DeepEqual(rec, want) {
		t.Fatalf("lend record %+v", rec)
	}
	if got := nodes.LentNodes(testPodUID, testCtr); !reflect.DeepEqual(got, []int{2, 3}) {
		t.Fatalf("lent nodes %v", got)
	}
	noErr(t, c.Revoke(ctx, rec, "ns/c"))
	if got := nodes.LentNodes(testPodUID, testCtr); len(got) != 0 {
		t.Fatalf("still lent %v", got)
	}
	noErr(t, c.Revoke(ctx, nil, "ns/c"))

	// a failing LendNode leaves the nodes lent so far, including the
	// failed one, in the record, so that a revoke cleans up
	nodes.mu.Lock()
	nodes.lendErr = containers.ErrSteered
	nodes.mu.Unlock()
	rec = testLendRecord()
	if err := c.Lend(ctx, rec, devs); !errors.Is(err, containers.ErrSteered) || !reflect.DeepEqual(rec.NumaNodes, []int{2}) {
		t.Fatalf("failed lend: %+v %v", rec, err)
	}

	// revoke errors are joined
	c.Set(revokeFailer{nodes}, hooks)
	err = c.Revoke(ctx, &lendRecord{Lease: "l1", Pod: rec.Pod, Container: testCtr, NumaNodes: []int{2, 3}}, "ns/c")
	wantErr(t, err, "revoking node 2")
	wantErr(t, err, "node 3 busy")

	// hook forwarding
	hooks.calls = nil
	c.Prepared("l1", state.SourcePool, devs[:1])
	c.Failed("l1", errors.New("boom"))
	c.Releasing("l1")
	c.Reprepared(&lendRecord{Lease: "l2", Pod: rec.Pod, Container: testCtr}, companionClaim("l2"), state.SourcePool, devs[1:2])
	hooks.lendingErr = errors.New("unknown lease")
	c.Reprepared(&lendRecord{Lease: "l3"}, companionClaim("l3"), state.SourcePool, devs)
	if got, want := hooks.log(), "prepared l1\nfailed l1: boom\nreleasing l1\nlending l2 cxl-lease-l2\nprepared l2\nlending l3 cxl-lease-l3"; got != want {
		t.Fatalf("hook calls:\n%s\nexpected:\n%s", got, want)
	}
	if !reflect.DeepEqual(hooks.devs, devs[1:2]) || hooks.source != state.SourcePool {
		t.Fatalf("prepared devices %+v of %q", hooks.devs, hooks.source)
	}
}

// numaLent returns a memdev of a companion claim in mode numa on node.
func numaLent(node int) lentDevice {
	return lentDevice{DeviceType: device.DeviceTypeMemdev, Mode: api.ModeNUMA, NUMANodes: []int{node}}
}

func TestLendRecordJSON(t *testing.T) {
	enc := `{"lease":"000000a1","pod":{"namespace":"demo","name":"borrower","uid":"pod-uid-1"},"container":"app","nodes":[2]}`
	var rec lendRecord
	noErr(t, json.Unmarshal([]byte(enc), &rec))
	want := lendRecord{Lease: "000000a1", Pod: podRef{Namespace: testNS, Name: testPod, UID: testPodUID}, Container: testCtr, NumaNodes: []int{2}}
	if !reflect.DeepEqual(rec, want) {
		t.Fatalf("loaded %+v", rec)
	}
	data, err := json.Marshal(&rec)
	noErr(t, err)
	if string(data) != enc {
		t.Fatalf("encoded %s", data)
	}
}

// withDriverConfig appends an opaque config of driver to a claim's
// allocation.
func withDriverConfig(c *resourceapi.ResourceClaim, driver string, source resourceapi.AllocationConfigSource, requests []string, params string) *resourceapi.ResourceClaim {
	c.Status.Allocation.Devices.Config = append(c.Status.Allocation.Devices.Config, resourceapi.DeviceAllocationConfiguration{
		Source:   source,
		Requests: requests,
		DeviceConfiguration: resourceapi.DeviceConfiguration{Opaque: &resourceapi.OpaqueDeviceConfiguration{
			Driver: driver, Parameters: runtime.RawExtension{Raw: []byte(params)},
		}},
	})
	return c
}

func TestDaxDeviceNode(t *testing.T) {
	if got, want := daxDeviceNode("/dev/dax1.2", 252, 2, false), (&cdiSpecs.DeviceNode{Path: "/dev/dax1.2", Type: "c", Major: 252, Minor: 2}); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if got, want := daxDeviceNode("/dev/dax0.0", 251, 3, true), (&cdiSpecs.DeviceNode{Path: "/dev/dax0.0", Type: "c", Major: 251, Minor: 3, Permissions: "r"}); !reflect.DeepEqual(got, want) {
		t.Fatalf("read-only: got %+v", got)
	}
}
