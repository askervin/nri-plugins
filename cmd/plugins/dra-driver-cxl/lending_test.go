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
	"strings"
	"sync"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// fakeHooks records the leaseHooks calls.
type fakeHooks struct {
	mu    sync.Mutex
	calls []string
}

func (h *fakeHooks) OnLending(id string, claim *resourceapi.ResourceClaim) (*lendRecord, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "lending "+id+" "+claim.Name)
	return &lendRecord{Lease: id, Pod: podRef{Namespace: testNS, Name: testPod, UID: testPodUID}, Container: testCtr}, nil
}

func (h *fakeHooks) OnPrepared(id string, _ state.Source, _ []lentDevice) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "prepared "+id)
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
