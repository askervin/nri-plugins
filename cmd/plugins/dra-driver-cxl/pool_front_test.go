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
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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

// A companion claim of mode fs whose node mount and lease bind a new mount
// namespace lost: its Prepare again fails, without telling the broker,
// while the device cannot be mounted, and then mounts the node mount and
// binds it again before the broker hears of the companion.
func TestPoolRemountCompanion(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	direct := e.nodeMount(0xc1ae0001, "direct")
	target := filepath.Join(hooks.fsDir, "models")
	uid := "uid-cxl-lease-l1"
	noErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err)
	k := e.k.Kernel()
	noErr(t, k.Unmount(target))
	noErr(t, k.Unmount(direct))
	e.k.SetMountError(e.pmem, syscall.EIO, "")
	p = e.leaseDriver(t, hooks)
	if prep := e.preparation(uid); prep.State != state.PreparationUnrestored {
		t.Fatalf("preparation %+v", prep)
	}
	calls := hooks.log()
	wantErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err, "its node mount "+direct+" is not mounted and cannot be mounted again")
	if log := hooks.log(); log != calls {
		t.Fatalf("the broker heard of an unrestored companion:\n%s", strings.TrimPrefix(log, calls))
	}
	e.k.SetMountError(e.pmem, nil, "")
	bound := false
	hooks.onPrepared = func(string) {
		mi, _ := e.mountedErr(target)
		bound = mi != nil
	}
	noErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err)
	if prep := e.preparation(uid); prep.State != state.PreparationPrepared || !bound {
		t.Fatalf("preparation %+v, bound before the broker heard: %v", prep, bound)
	}
	if log := strings.TrimPrefix(hooks.log(), calls); log != "\nlending l1 cxl-lease-l1\nprepared l1" {
		t.Fatalf("hooks:\n%s", log)
	}
	noErr(t, unprepare(t, p, uid))
	e.wantClean(t, p)
}

// A companion claim refused after the gate of the broker: the lease fails
// at once when the MemoryConfig of the claim does not fit its device, not
// while the pool has not written the status data of its device yet.
func TestPoolCompanionRefused(t *testing.T) {
	e := newPoolTestEnv(t)
	p := e.driver(t)
	hooks := &fakeHooks{}
	p.Lender().Set(newFakeLender(), hooks)
	c := numaCompanion("l1")
	c.Status.Devices = nil
	wantErr(t, prepare(t, p, c).Err, "not attached by the pool controller yet")
	c = persistentClaim("uid-"+companionName("l2"), exclusiveData, `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs"}}`)
	c.ObjectMeta = companionClaim("l2").ObjectMeta
	mismatch := "device llm0 serial 0xc1ee0001: MemoryConfig: device.mode fs needs a persistent device"
	wantErr(t, prepare(t, p, c).Err, mismatch)
	if log := hooks.log(); log != "lending l1 cxl-lease-l1\nlending l2 cxl-lease-l2\nfailed l2: "+mismatch {
		t.Fatalf("hooks:\n%s", log)
	}
	e.wantClean(t, p)
}
