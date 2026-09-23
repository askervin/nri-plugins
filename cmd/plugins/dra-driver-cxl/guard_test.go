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
	"strings"
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/provenance"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// poolSliceOf returns the ResourceSlice of the pool pool-c of the pool
// driver whose devices have the serials.
func poolSliceOf(serials ...string) *resourceapi.ResourceSlice {
	rs := &resourceapi.ResourceSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "pool-c"},
		Spec:       resourceapi.ResourceSliceSpec{Driver: device.PoolDriverName, Pool: resourceapi.ResourcePool{Name: "pool-c", ResourceSliceCount: 1}},
	}
	for i, s := range serials {
		rs.Spec.Devices = append(rs.Spec.Devices, resourceapi.Device{Name: "pool-c-" + string(rune('a'+i)),
			Attributes: map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{device.AttrSerial: {StringValue: ptr(s)}}})
	}
	return rs
}

// The local guard refuses a local claim on a memdev that a pool slice lists
// (a fresh list) before the memdev is touched, sliced and shared; once the
// slice no longer lists it (and nothing remembers it) the claim is
// prepared.
func TestPrepareLocalPoolDevice(t *testing.T) {
	ctx := context.Background()
	e := newLocalTestEnv(t)
	e.start()
	client := k8sfake.NewClientset()
	publish := func(serials ...string) {
		t.Helper()
		_ = client.ResourceV1().ResourceSlices().Delete(ctx, "pool-c", metav1.DeleteOptions{})
		_, err := client.ResourceV1().ResourceSlices().Create(ctx, poolSliceOf(serials...), metav1.CreateOptions{})
		noErr(t, err)
	}
	watcher := func() *provenance.Watcher {
		list, claims := provenance.ClientLists(client, "")
		return provenance.New(provenance.Options{List: list, Claims: claims, NodeName: testNode})
	}
	publish("0xc1ee2001", "0xc100e2e1")
	w := watcher()
	e.devices.setGuard(localPoolGuard(nil, w))
	const refusal = "memory device serial 0xc100e2e1 is a pool device of " + device.PoolDriverName + "/pool-c: it is not used as a local memory device"
	wantErr(t, e.prepare(localClaim("u1", 64*mib)), refusal)
	// shared
	e.config.SharedDevices = []string{"0xc100e2e1"}
	e.shared[localSerial] = true
	e.restart()
	e.devices.setGuard(localPoolGuard(nil, w))
	wantErr(t, e.prepare(localClaim("u2", -1, localDaxConfig)), "is a pool device")
	if e.inUse() || strings.Contains(e.commands(), "create-region") {
		t.Fatalf("the pool device was used:\n%s", e.commands())
	}
	// not listed: prepared
	publish("0xc1ee2001")
	e.devices.setGuard(localPoolGuard(nil, watcher()))
	e.mustPrepare(localClaim("u2", -1, localDaxConfig))
	e.mustUnprepare("u2")
	e.config.SharedDevices = nil
	e.shared = map[uint64]bool{}
	e.restart()
	e.mustPrepare(localClaim("u1", 64*mib))
	e.mustUnprepare("u1")
	e.wantClean()
}

// The local guard refuses a memdev that the pool driver prepares, before
// the watcher is asked.
func TestLocalPoolGuardPoolSerial(t *testing.T) {
	pe := newPoolTestEnv(t)
	pe.plug(0xc1ee0001)
	p := pe.driver(t)
	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	guard := localPoolGuard(p, nil)
	wantErr(t, guard(context.Background(), 0xc1ee0001),
		"memory device serial 0xc1ee0001 is prepared by the pool driver "+device.PoolDriverName+": it is not used as a local memory device")
	noErr(t, guard(context.Background(), localSerial))
	noErr(t, unprepare(t, p, "u1"))
	noErr(t, guard(context.Background(), 0xc1ee0001))
}
