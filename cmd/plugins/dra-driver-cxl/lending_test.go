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
	"strings"
	"sync"
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

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

// numaLent returns a memdev of a companion claim in mode numa on node.
func numaLent(node int) lentDevice {
	return lentDevice{DeviceType: device.DeviceTypeMemdev, Mode: api.ModeNUMA, NUMANodes: []int{node}}
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
