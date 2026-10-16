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
	"reflect"
	"testing"

	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/memorypolicy"
)

func TestDefaultPolicy(t *testing.T) {
	for _, tc := range []struct {
		mem  cgmpolmgr.MemoryTypes
		want cgmpolmgr.MemoryUseOrder
	}{
		{cgmpolmgr.MemoryTypes{CXLNodes: []int{2}}, cgmpolmgr.MemoryUseFirstCXL},
		{cgmpolmgr.MemoryTypes{DRAMNodes: []int{0}}, cgmpolmgr.MemoryUseFirstDRAM},
		{cgmpolmgr.MemoryTypes{DRAMNodes: []int{0}, CXLNodes: []int{1}}, cgmpolmgr.MemoryUseStartInterleaved},
	} {
		if got := defaultPolicy(tc.mem).MemoryUseOrder; got != tc.want.String() {
			t.Errorf("memory %+v: order %q, expected %q", tc.mem, got, tc.want)
		}
	}
}

func TestClaimedMemory(t *testing.T) {
	policy := func(order string) *memorypolicy.MemoryPolicyConfig {
		return &memorypolicy.MemoryPolicyConfig{
			APIVersion: memorypolicy.APIVersion,
			Kind:       memorypolicy.Kind,
			Policy:     cgmpolmgr.Policy{MemoryUseOrder: order},
		}
	}
	claims := PreparedClaimsInfo{
		"dram": {ClaimName: "ns/dram", Devices: []PreparedDeviceInfo{
			{DeviceType: device.DeviceTypeDRAM, Mode: api.ModeNUMA, NUMANodes: []int{1, 0}, ConsumedBytes: 2 << 30},
		}},
		"cxl": {ClaimName: "ns/cxl", Devices: []PreparedDeviceInfo{
			{DeviceType: device.DeviceTypeMemdev, Mode: api.ModeNUMA, NUMANodes: []int{5}, ConsumedBytes: 1 << 30},
			{DeviceType: device.DeviceTypeRegion, Mode: api.ModeNUMA, NUMANodes: []int{4}, ConsumedBytes: 1 << 30},
			{DeviceType: device.DeviceTypeMemdev, Mode: api.ModeDax, NUMANodes: []int{6}, ConsumedBytes: 1 << 30},
			{DeviceType: device.DeviceTypeLease},
		}},
		"policy1": {ClaimName: "ns/policy1", Policy: policy("first-cxl")},
		"policy2": {ClaimName: "ns/policy2", Policy: policy("first-dram")},
	}
	p := &nriPlugin{state: &nodeState{baseState: &baseState{}, preparedClaims: claims}}

	// Dax devices and the lease device are not steered memory, and
	// unknown claims are skipped.
	mem, pol, err := p.claimedMemory("ns/pod/ctr", []string{"dram", "cxl", "unknown"})
	want := cgmpolmgr.MemoryTypes{DRAMNodes: []int{0, 1}, CXLNodes: []int{4, 5}, DRAMQuota: 2 << 30, CXLQuota: 2 << 30}
	if err != nil || pol != nil || !reflect.DeepEqual(mem, want) {
		t.Fatalf("memory %+v policy %v error %v, expected %+v", mem, pol, err, want)
	}

	mem, pol, err = p.claimedMemory("ns/pod/ctr", []string{"cxl", "policy1"})
	if err != nil || pol == nil || pol.MemoryUseOrder != "first-cxl" || !reflect.DeepEqual(mem.CXLNodes, []int{4, 5}) {
		t.Fatalf("memory %+v policy %v error %v, expected the policy of policy1", mem, pol, err)
	}

	if _, _, err := p.claimedMemory("ns/pod/ctr", []string{"policy1", "policy2"}); err == nil {
		t.Fatal("two claims with policies: expected an error")
	}
}

func TestExtractClaimUIDs(t *testing.T) {
	uid1 := "0a1b2c3d-0000-1111-2222-333344445555"
	uid2 := "6a1b2c3d-0000-1111-2222-333344445555"
	env := []string{"PATH=/bin", claimEnvVarName(uid1) + "=1", "CXL_C1EE0001_SIZE=1", claimEnvVarName(uid2) + "=1", claimEnvVarName(uid1) + "=1"}
	if got := extractClaimUIDs(env); !reflect.DeepEqual(got, []string{uid1, uid2}) {
		t.Fatalf("claim UIDs %v, expected [%s %s]", got, uid1, uid2)
	}
	if got := extractClaimUIDs([]string{"PATH=/bin"}); got != nil {
		t.Fatalf("claim UIDs %v of no markers", got)
	}
}

func TestSortedNodes(t *testing.T) {
	if got := sortedNodes(map[int]bool{5: true, 0: true, 2: true}); !reflect.DeepEqual(got, []int{0, 2, 5}) {
		t.Errorf("sorted nodes %v", got)
	}
	if got := sortedNodes(nil); len(got) != 0 {
		t.Errorf("sorted nodes of nil %v", got)
	}
}

func TestFormatBytes(t *testing.T) {
	for in, want := range map[uint64]string{
		0:               "0B",
		1023:            "1023B",
		1536:            "1.5KiB",
		128 << 20:       "128.0MiB",
		(5 << 30) / 2:   "2.5GiB",
		uint64(1) << 40: "1024.0GiB",
	} {
		if got := formatBytes(in); got != want {
			t.Errorf("formatBytes(%d) = %q, expected %q", in, got, want)
		}
	}
}
