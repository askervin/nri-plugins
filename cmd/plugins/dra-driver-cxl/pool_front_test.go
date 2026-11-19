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
	"slices"
	"testing"

	resourceapi "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
)

// numaCompanion returns the companion claim of the numa lease id on the
// pool device pooled0.
func numaCompanion(id string) *resourceapi.ResourceClaim {
	c := poolClaim("uid-"+companionName(id), companionName(id), "pooled0", exclusiveData)
	c.ObjectMeta = companionClaim(id).ObjectMeta
	return c
}

// The NUMA nodes of the claims whose Prepare did not finish are fenced at
// a start (numaNodes), they have no results for the NRI plugin.
func TestPoolUnfinishedNodes(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	p := e.driver(t)
	e.k.CutAfter("write devices/system/memory/memory")
	claim := numaCompanion("l1")
	hooks := &fakeHooks{}
	p.Lender().Set(newFakeLender(), hooks)
	cutPrepare(t, p, claim)
	p = e.driver(t)
	uid := "uid-cxl-lease-l1"
	node := state.NumaNodeOf(e.records().Region("region0").NumaNode)
	if node < 0 || !slices.Equal(poolNumaNodes(p), []int{node}) || p.ClaimInfo(uid) != nil {
		t.Fatalf("numa nodes %v (region on %d), results %v", poolNumaNodes(p), node, p.ClaimInfo(uid))
	}
	p.Lender().Set(newFakeLender(), hooks)
	noErr(t, unprepare(t, p, uid))
	if poolNumaNodes(p) != nil {
		t.Fatalf("numa nodes %v", poolNumaNodes(p))
	}
	e.wantClean(t, p)
}
