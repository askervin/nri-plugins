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

package dra

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// The Prepares that are refused before any device is touched, of both
// drivers, in the words of each: no kernel command, no record.
func TestPrepareRefusedBeforeDevices(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()}, poolSpec(serialPoolX))
	noAlloc := func(c *resourcev1.ResourceClaim) *resourcev1.ResourceClaim {
		c.Status.Allocation = nil
		return c
	}
	badConfig := `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"memory"}}`
	for _, tc := range []struct {
		name  string
		p     *Plugin
		claim *resourcev1.ResourceClaim
		err   string
	}{
		{"local no allocation", e.local, noAlloc(localClaim("u1", localDev, 0)), "no allocation found in claim demo/claim-u1 status"},
		{"local unknown device", e.local, localClaim("u1", "memdev-77", 0), "could not find allocatable device memdev-77 (pool node1)"},
		{"local config", e.local, localClaim("u1", localDev, 0, badConfig),
			`claim demo/claim-u1: request mem: MemoryConfig: device.mode: invalid mode "memory" (numa or dax)`},
		{"local shares of a sliced memdev", e.local, localClaim("u1", localDev, -1),
			"claim demo/claim-u1: request mem: device 0xc100e2e1: allocated as a shared device, which it is not any more"},
		{"pool no allocation", e.pool, noAlloc(poolClaim("u1", "pooled0", poolExclusiveData)),
			"cxl-pool.nri.io: preparing claim demo/claim-u1: no allocation"},
		{"pool no status data", e.pool, poolClaim("u1", "pooled0", ""), "cxl-pool.nri.io: preparing claim demo/claim-u1: "},
		{"pool config", e.pool, poolClaim("u1", "pooled0", poolExclusiveData, badConfig),
			`cxl-pool.nri.io: preparing claim demo/claim-u1: device pooled0 serial 0xc1ee0001: MemoryConfig: device.mode: invalid mode "memory"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.t = t
			e.mark()
			wantErrText(t, e.prepare(tc.p, tc.claim).Err, tc.err)
			e.wantNoCommands("refused")
			e.wantState(tc.p, "u1", state.PreparationUnknown)
		})
	}
}

// A KEPT claim whose Prepare again is refused keeps its record and what it
// kept; its Prepare again with the status data reuses it.
func TestPrepareRefusedKeepsKept(t *testing.T) {
	e := newDriverEnv(t, nil, poolSpec(serialPoolX), poolSpec(0xc1ee0002))
	// a stop cuts the Prepare after its region, another memdev gets a
	// region above it: the start keeps the claim's region
	e.k.CutAfter("cxl create-region")
	e.cutPrepare(e.pool, poolClaim("u1", "pooled0", poolExclusiveData))
	k := e.k.Kernel()
	other := e.k.Memdev(0xc1ee0002)
	d, err := k.RootDecoder(other, kernel.RegionRAM)
	mustOK(t, err)
	above, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: other, Decoder: d, Type: kernel.RegionRAM})
	mustOK(t, err)
	e.restart()
	e.wantState(e.pool, "u1", state.PreparationKept)
	kept := e.records().Grant(state.GrantRef{Claim: "u1"})
	if kept == nil || kept.Intent.Region == "" || len(e.k.Kernel().Regions("mem0")) != 1 {
		t.Fatalf("kept grant %+v, regions %v", kept, e.k.Kernel().Regions("mem0"))
	}
	e.mark()
	wantErrText(t, e.prepare(e.pool, poolClaim("u1", "pooled0", "")).Err, "cxl-pool.nri.io: preparing claim demo/claim-u1: ")
	e.wantNoCommands("a refused Prepare of a KEPT claim")
	e.wantState(e.pool, "u1", state.PreparationKept)
	e.mustPrepare(e.pool, poolClaim("u1", "pooled0", poolExclusiveData))
	if g := e.records().Grant(state.GrantRef{Claim: "u1"}); g == nil || g.Got.Region != kept.Intent.Region {
		t.Fatalf("the kept region %s is not reused: %+v", kept.Intent.Region, g)
	}
	e.mustUnprepare(e.pool, "u1")
	mustOK(t, k.ReleaseRegion(context.Background(), above))
	e.wantClean()
}

// A claim whose Prepare a process stop cut is PREPARING after the start:
// a refused Prepare again keeps it, a Prepare again goes on with it, and
// the Unprepare of another cut one removes it.
func TestPrepareRefusedKeepsPreparing(t *testing.T) {
	e := newDriverEnv(t, nil, poolSpec(serialPoolX), poolSpec(0xc1ee0002))
	for _, uid := range []string{"u1", "u2"} {
		e.k.CutAfter("cxl create-region")
		e.cutPrepare(e.pool, poolClaim(uid, "pooled0", poolExclusiveData))
		e.restart()
		e.wantState(e.pool, uid, state.PreparationPreparing)
	}
	e.mark()
	wantErrText(t, e.prepare(e.pool, poolClaim("u1", "pooled0", "")).Err, "cxl-pool.nri.io: preparing claim demo/claim-u1: ")
	e.wantNoCommands("a refused Prepare of a PREPARING claim")
	e.wantState(e.pool, "u1", state.PreparationPreparing)
	e.mustUnprepare(e.pool, "u2")
	e.wantState(e.pool, "u2", state.PreparationUnknown)
	e.mustPrepare(e.pool, poolClaim("u1", "pooled0", poolExclusiveData))
	e.mustUnprepare(e.pool, "u1")
	e.wantClean()
}

// After a reboot the claims of the pool driver are PREPARED_STALE (those
// of cxl.nri.io are dropped): a refused Prepare again keeps one, a Prepare
// again prepares it anew, an Unprepare of another removes it without a
// revoke.
func TestPrepareRefusedKeepsStale(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()}, poolSpec(serialPoolX), fake.MemdevSpec{Serial: serialPoolS, HostBridge: 24})
	e.mustPrepare(e.pool, poolClaim("u1", "pooled0", poolExclusiveData))
	e.mustPrepare(e.pool, poolClaim("u2", "shared0", poolSharedData))
	e.mustPrepare(e.local, localClaim("l1", localDev, envBlockSize))
	logs := klogCapture(t)
	e.reboot()
	e.wantState(e.pool, "u1", state.PreparationStale)
	e.wantState(e.local, "l1", state.PreparationUnknown)
	if e.cdiDevice(e.pool, "claim-u1-0") != nil || e.pool.ClaimInfo("u1") != nil {
		t.Fatal("a stale claim has CDI devices")
	}
	wantErrText(t, e.prepare(e.pool, poolClaim("u1", "pooled0", "")).Err, "cxl-pool.nri.io: preparing claim demo/claim-u1: ")
	e.wantNoCommands("a refused Prepare of a stale claim")
	e.wantState(e.pool, "u1", state.PreparationStale)
	e.mustPrepare(e.pool, poolClaim("u1", "pooled0", poolExclusiveData))
	if e.cdiDevice(e.pool, "claim-u1-0") == nil {
		t.Fatal("no CDI device of the claim prepared anew")
	}
	e.mustUnprepare(e.pool, "u2")
	wantLogText(t, logs(), "cxl-pool.nri.io: unpreparing claim demo/claim-u2 (u2), not prepared any more (")
	e.mustUnprepare(e.pool, "u1")
	e.mustUnprepare(e.local, "l1")
	e.wantClean()
}

// A refused Prepare of the pool driver unmounts the stale lease binds
// again, as a failed one does; one of cxl.nri.io does not.
func TestPrepareRefusedRetriesStaleBinds(t *testing.T) {
	e := newDriverEnv(t, nil, poolPmemSpec(serialPoolP))
	e.formatPmem(serialPoolP, "erofs")
	_, hooks := e.lending()
	hooks.fsDir, hooks.name = filepath.Join(e.leaseFsRoot(), "lc1"), "data"
	target := filepath.Join(hooks.fsDir, hooks.name)
	c := companion(poolClaim("c1", "llm0", poolPmemData, cfgFsRO), "l1")
	e.mustPrepare(e.pool, c)
	if mi, _ := e.k.Kernel().Mounted(target); mi == nil {
		t.Fatalf("no lease bind at %s", target)
	}
	e.k.SetBusy(target, true)
	wantErrText(t, e.unprepare(e.pool, "c1"), "busy")
	e.wantState(e.pool, "c1", state.PreparationUnpreparing)
	e.k.SetBusy(target, false)
	logs := klogCapture(t)
	wantErrText(t, e.prepare(e.local, localClaim("x1", "memdev-77", 0)).Err, "could not find allocatable device")
	if strings.Contains(logs(), "stale lease bind") {
		t.Fatalf("cxl.nri.io retried the stale lease binds:\n%s", logs())
	}
	wantErrText(t, e.prepare(e.pool, poolClaim("x1", "llm0", "")).Err, "cxl-pool.nri.io: preparing claim demo/claim-x1: ")
	wantLogText(t, logs(), "unbound stale lease bind "+target)
	if mi, _ := e.k.Kernel().Mounted(target); mi != nil {
		t.Fatalf("the stale lease bind is mounted: %+v", mi)
	}
	e.mustUnprepare(e.pool, "c1")
	e.wantClean()
}

// A Prepare that fails after its intent: its record removed when its
// rollback released everything, in the words of each driver.
func TestPrepareFailedAfterIntent(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()})
	// a pool device that does not appear
	res := e.prepare(e.pool, poolClaim("u1", "pooled9", poolExclusiveData))
	wantErrText(t, res.Err, "cxl-pool.nri.io: preparing claim demo/claim-u1: device pooled9 serial 0xc1ee0001: ")
	e.wantState(e.pool, "u1", state.PreparationUnknown)
	// a local memdev with a region that the driver did not make
	k := e.k.Kernel()
	memdev := e.k.Memdev(serialSliced)
	d, err := k.RootDecoder(memdev, kernel.RegionRAM)
	mustOK(t, err)
	region, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionRAM})
	mustOK(t, err)
	res = e.prepare(e.local, localClaim("u2", localDev, envBlockSize))
	wantErrText(t, res.Err, "claim demo/claim-u2: device "+localDev+": ")
	wantErrText(t, res.Err, "that the plugin did not create")
	e.wantState(e.local, "u2", state.PreparationUnknown)
	mustOK(t, k.ReleaseRegion(context.Background(), region))
	if spec := e.cdiSpec(device.ClaimsCDISpecName); spec != nil {
		t.Fatalf("CDI spec %+v", spec)
	}
	e.wantClean()
}
