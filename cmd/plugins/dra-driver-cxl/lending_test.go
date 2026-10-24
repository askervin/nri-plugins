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

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// fakeHooks records the leaseHooks calls.
type fakeHooks struct {
	mu         sync.Mutex
	calls      []string
	lendingErr error
	devs       []lentDevice
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

func (h *fakeHooks) OnPrepared(id string, devs []lentDevice) {
	h.mu.Lock()
	h.calls = append(h.calls, "prepared "+id)
	h.devs = devs
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
	c := newCompanionLender(device.DriverName)
	_, err := c.check("l1", claim)
	wantErr(t, err, "lease l1: lending to running containers is disabled (--leases=false)")
	hooks := &fakeHooks{}
	c.set(nil, hooks)
	if _, err := c.check("l1", claim); !errors.Is(err, errLendingUnavailable) {
		t.Fatalf("check without NRI: %v", err)
	}
	// numa devices cannot be lent without NRI, dax devices need no lend
	rec := testLendRecord()
	if err := c.lend(context.Background(), rec, []lentDevice{{Mode: api.ModeNUMA, Node: 3}}); !errors.Is(err, errLendingUnavailable) || len(rec.Nodes) != 0 {
		t.Fatalf("lend without NRI: %+v %v", rec, err)
	}
	noErr(t, c.lend(context.Background(), rec, []lentDevice{{Mode: api.ModeDax, Node: -1, DaxDevice: "/dev/dax0.1"}}))
	if rec.Lease != "l1" || rec.Container != testCtr || len(rec.Nodes) != 0 {
		t.Fatalf("dax lend record %+v", rec)
	}
	// revoking without NRI only warns
	noErr(t, c.revoke(context.Background(), &lendRecord{Lease: "l1", Nodes: []int{3}}, "ns/c"))
	if log := hooks.log(); log != "" {
		t.Fatalf("hooks called: %s", log)
	}

	// a nil companionLender is disabled and safe to use
	var n *companionLender
	n.set(newFakeLender(), hooks)
	n.prepared("l1", nil)
	n.failed("l1", errors.New("x"))
	n.releasing("l1")
	n.reprepared(&lendRecord{Lease: "l1"}, claim, nil)
	if hooks.log() != "" {
		t.Fatalf("nil companionLender: hooks %s", hooks.log())
	}
	_, err = n.check("l1", claim)
	wantErr(t, err, "disabled")
}

func TestCompanionLenderLendRevoke(t *testing.T) {
	ctx := context.Background()
	claim := companionClaim("l1")
	nodes := newFakeLender(testRef)
	hooks := &fakeHooks{}
	c := newCompanionLender(device.PoolDriverName)
	c.set(nodes, hooks)

	rec, err := c.check("l1", claim)
	noErr(t, err)
	if !reflect.DeepEqual(rec, testLendRecord()) {
		t.Fatalf("lend of the lease %+v", rec)
	}
	hooks.lendingErr = errors.New("lease l1 is Failed")
	_, err = c.check("l1", claim)
	wantErr(t, err, "lease l1 is Failed")
	hooks.lendingErr = nil

	devs := []lentDevice{
		{Mode: api.ModeNUMA, Node: 2},
		{Mode: api.ModeDax, Node: -1, DaxDevice: "/dev/dax0.0"},
		{Mode: api.ModeNUMA, Node: -1},
		{Mode: api.ModeNUMA, Node: 3},
	}
	noErr(t, c.lend(ctx, rec, devs))
	want := &lendRecord{Lease: "l1", Pod: rec.Pod, Container: testCtr, Nodes: []int{2, 3}}
	if !reflect.DeepEqual(rec, want) {
		t.Fatalf("lend record %+v", rec)
	}
	if got := nodes.LentNodes(testPodUID, testCtr); !reflect.DeepEqual(got, []int{2, 3}) {
		t.Fatalf("lent nodes %v", got)
	}
	noErr(t, c.revoke(ctx, rec, "ns/c"))
	if got := nodes.LentNodes(testPodUID, testCtr); len(got) != 0 {
		t.Fatalf("still lent %v", got)
	}
	noErr(t, c.revoke(ctx, nil, "ns/c"))

	// a failing LendNode leaves the nodes lent so far, including the
	// failed one, in the record, so that a revoke cleans up
	nodes.mu.Lock()
	nodes.lendErr = errSteered
	nodes.mu.Unlock()
	rec = testLendRecord()
	if err := c.lend(ctx, rec, devs); !errors.Is(err, errSteered) || !reflect.DeepEqual(rec.Nodes, []int{2}) {
		t.Fatalf("failed lend: %+v %v", rec, err)
	}

	// revoke errors are joined
	c.set(revokeFailer{nodes}, hooks)
	err = c.revoke(ctx, &lendRecord{Lease: "l1", Pod: rec.Pod, Container: testCtr, Nodes: []int{2, 3}}, "ns/c")
	wantErr(t, err, "revoking node 2")
	wantErr(t, err, "node 3 busy")

	// hook forwarding
	hooks.calls = nil
	c.prepared("l1", devs[:1])
	c.failed("l1", errors.New("boom"))
	c.releasing("l1")
	c.reprepared(&lendRecord{Lease: "l2", Pod: rec.Pod, Container: testCtr}, companionClaim("l2"), devs[1:2])
	hooks.lendingErr = errors.New("unknown lease")
	c.reprepared(&lendRecord{Lease: "l3"}, companionClaim("l3"), devs)
	if got, want := hooks.log(), "prepared l1\nfailed l1: boom\nreleasing l1\nlending l2 cxl-lease-l2\nprepared l2\nlending l3 cxl-lease-l3"; got != want {
		t.Fatalf("hook calls:\n%s\nexpected:\n%s", got, want)
	}
	if !reflect.DeepEqual(hooks.devs, devs[1:2]) {
		t.Fatalf("prepared devices %+v", hooks.devs)
	}
}

func TestLendRecordJSON(t *testing.T) {
	enc := `{"lease":"000000a1","pod":{"namespace":"demo","name":"borrower","uid":"pod-uid-1"},"container":"app","nodes":[2]}`
	var rec lendRecord
	noErr(t, json.Unmarshal([]byte(enc), &rec))
	want := lendRecord{Lease: "000000a1", Pod: podRef{Namespace: testNS, Name: testPod, UID: testPodUID}, Container: testCtr, Nodes: []int{2}}
	if !reflect.DeepEqual(rec, want) {
		t.Fatalf("loaded %+v", rec)
	}
	data, err := json.Marshal(&rec)
	noErr(t, err)
	if string(data) != enc {
		t.Fatalf("encoded %s", data)
	}
}

// TestPoolCompanionRefused prepares a companion claim through the pool
// driver without a broker or a lender: nothing is touched.
func TestPoolCompanionRefused(t *testing.T) {
	pe := newPoolTestEnv(t)
	pe.f.plug("0xc1ee0001")
	p := pe.driver(t)
	claim := poolClaim("u9", "c9", "pooled0", exclusiveData)
	claim.Namespace = testNS
	claim.Labels = map[string]string{device.LeaseLabel: "abc"}
	wantErr(t, prepare(t, p, claim).Err, "lending to running containers is disabled (--leases=false)")
	p.lender.set(nil, &broker{store: &leaseStore{Leases: map[string]*lease{}}, changed: make(chan struct{})})
	wantErr(t, prepare(t, p, claim).Err, "lending unavailable: NRI not connected")
	p.lender.set(newFakeLender(testRef), &broker{store: &leaseStore{Leases: map[string]*lease{}}, changed: make(chan struct{})})
	wantErr(t, prepare(t, p, claim).Err, "claim demo/c9: not the companion of lease abc")
	if strings.Contains(pe.f.commands(), "create-region") {
		t.Fatalf("device touched for a refused lend:\n%s", pe.f.commands())
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

func TestEnvKeys(t *testing.T) {
	keys := envKeys{}
	var got []string
	for _, base := range []string{"C100E2E1", "REGION0", "C100E2E1", "DRAM", "C100E2E1"} {
		got = append(got, keys.next(base))
	}
	if want := []string{"C100E2E1", "REGION0", "C100E2E1_2", "DRAM", "C100E2E1_3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("keys %v", got)
	}
}
