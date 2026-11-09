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
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// companionOf returns the companion claim c1 of lease l1 of the driver of
// the plugin on its device of the env: a slice of 64 MiB of the sliced
// local memdev, or the pool device pooled0, with the configs.
func (e *driverEnv) companionOf(p *Plugin, configs ...string) *resourcev1.ResourceClaim {
	if p == e.local {
		return companion(localClaim("c1", localDev, 64*mib, configs...), "l1")
	}
	return companion(poolClaim("c1", "pooled0", poolExclusiveData, configs...), "l1")
}

// lendEnv returns a node with the sliced local memdev and the pool device
// pooled0, without lending.
func lendEnv(t *testing.T) *driverEnv {
	return newDriverEnv(t, []fake.MemdevSpec{slicedSpec()}, poolSpec(serialPoolX))
}

// prefix returns the prefix of the errors of a Prepare of the companion
// claim c1 by the plugin.
func (e *driverEnv) prefix(p *Plugin) string {
	if p == e.local {
		return "claim demo/cxl-lease-l1: "
	}
	return "cxl-pool.nri.io: preparing claim demo/cxl-lease-l1: "
}

// The companion gate of both drivers before any device is touched: lending
// disabled, NRI not connected, the broker's refusal; cxl.nri.io lends
// local memdevs only. A claim without the label is no companion.
func TestCompanionGate(t *testing.T) {
	e := lendEnv(t)
	if LeaseOf(e.companionOf(e.local)) != "l1" || LeaseOf(localClaim("u1", localDev, 0)) != "" {
		t.Fatal("LeaseOf")
	}
	for _, p := range []*Plugin{e.local, e.pool} {
		e.t = t
		e.mark()
		wantErrText(t, e.prepare(p, e.companionOf(p)).Err, e.prefix(p)+"lease l1: lending to running containers is disabled (--leases=false)")
		hooks := &fakeHooks{e: e}
		e.lend(nil, hooks)
		res := e.prepare(p, e.companionOf(p))
		if !errors.Is(res.Err, lend.ErrLendingUnavailable) {
			t.Fatalf("%s: without NRI: %v", p.Name(), res.Err)
		}
		wantErrText(t, res.Err, e.prefix(p)+"lease l1: lending unavailable: NRI not connected")
		e.lend(&fakeNodes{e: e}, hooks)
		hooks.setLendingErr(errors.New("claim demo/cxl-lease-l1: not the companion of lease l1"))
		wantErrText(t, e.prepare(p, e.companionOf(p)).Err, e.prefix(p)+"claim demo/cxl-lease-l1: not the companion of lease l1")
		hooks.setLendingErr(nil)
		e.wantNoCommands(p.Name() + ": a refused companion")
		e.wantState(p, "c1", state.PreparationUnknown)
		e.wantEvents(p.Name(), "lending l1 cxl-lease-l1")
		e.lent, e.nodes, e.hooks = false, nil, nil
		e.local.Lender().Set(nil, nil)
		e.pool.Lender().Set(nil, nil)
	}
	e.lending()
	// cxl.nri.io: memdevs of the node only
	dram := companion(localClaim("c1", device.DRAMDeviceName, 64*mib), "l1")
	wantErrText(t, e.prepare(e.local, dram).Err, "claim demo/cxl-lease-l1: the companion claim of lease l1 needs memdev devices only")
	mixed := addLocalResult(companion(localClaim("c1", localDev, 64*mib), "l1"), "dram", device.DRAMDeviceName, 64*mib)
	wantErrText(t, e.prepare(e.local, mixed).Err, "needs memdev devices only")
	none := companion(poolClaim("c1", "pooled0", poolExclusiveData), "l1")
	none.Status.Allocation.Devices.Results = none.Status.Allocation.Devices.Results[:1]
	wantErrText(t, e.prepare(e.local, none).Err, "needs memdev devices only")
	e.wantNoCommands("refused companions")
	e.wantEvents("memdevs only")
}

// specClaim returns the companion claim c1 of the sliced local memdev with
// a spec.
func specClaim() *resourcev1.ResourceClaim {
	c := companion(localClaim("c1", localDev, 64*mib), "l1")
	c.Spec.Devices.Requests = []resourcev1.DeviceRequest{{Name: "mem", Exactly: &resourcev1.ExactDeviceRequest{DeviceClassName: "cxl-local"}}}
	return c
}

// The spec hash of a companion claim is compared only when the hooks tell
// it (SpecHasher), the lease waits for its first Prepare and the hash is of
// the version of SpecHash; a mismatch refuses the claim before OnLending
// and any device; a Prepare again does not compare.
func TestCompanionSpecHash(t *testing.T) {
	good := lend.SpecHash(&specClaim().Spec)
	if !strings.HasPrefix(good, "v1:") {
		t.Fatalf("hash %q", good)
	}
	bad := "v1:" + strings.Repeat("0", 64)
	for _, tc := range []struct {
		name    string
		hasher  bool
		hash    string
		first   bool
		refused bool
	}{
		{"no hasher", false, "", false, false},
		{"same hash", true, good, true, false},
		{"another hash", true, bad, true, true},
		{"another hash, not the first Prepare", true, bad, false, false},
		{"another version", true, "v2:" + strings.Repeat("0", 64), true, false},
		{"no hash", true, "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := lendEnv(t)
			hooks := &fakeHooks{e: e}
			var lh lend.LeaseHooks = hooks
			if tc.hasher {
				lh = &fakeSpecHooks{fakeHooks: hooks, hash: tc.hash, first: tc.first}
			}
			e.lend(&fakeNodes{e: e}, lh)
			e.mark()
			res := e.prepare(e.local, specClaim())
			var want []string
			if tc.hasher {
				want = append(want, "spec hash l1")
			}
			if tc.refused {
				wantErrText(t, res.Err, "claim demo/cxl-lease-l1: claim demo/cxl-lease-l1: not the companion of lease l1: its spec is not the one made for the lease")
				e.wantNoCommands("a refused companion")
				e.wantEvents("refused", want...)
				return
			}
			mustOK(t, res.Err)
			e.wantEvents("prepared", append(want, "lending l1 cxl-lease-l1", "lend pod-uid-1/app 2 l1", "prepared l1")...)
			if tc.hasher {
				// a Prepare again: the broker says first=false, a hash of
				// another spec
				spec := lh.(*fakeSpecHooks)
				spec.mu.Lock()
				spec.hash, spec.first = bad, false
				spec.mu.Unlock()
				again := e.mustPrepare(e.local, specClaim())
				if !reflect.DeepEqual(again, res) {
					t.Fatalf("again %+v", again)
				}
				e.wantEvents("again", "lending l1 cxl-lease-l1", "prepared l1")
			}
			e.mustUnprepare(e.local, "c1")
			e.wantClean()
		})
	}
}

// A companion claim of a numa slice of either driver: no CDI device, its
// node recorded before it is lent, the broker told the lent devices; a
// Prepare again announces it again; its Unprepare revokes the node with
// the memory online, then releases it.
func TestCompanionLendNUMA(t *testing.T) {
	for _, local := range []bool{true, false} {
		e := lendEnv(t)
		p := e.pool
		want := lend.LentDevice{Driver: device.PoolDriverName, Source: api.SourcePool, Request: "mem", Device: "pooled0", Pool: envPool,
			Serial: serialPoolX, Size: 256 << 20, Mode: api.ModeNUMA, NumaNode: 2}
		if local {
			p = e.local
			want = lend.LentDevice{Driver: device.DriverName, Source: api.SourceLocal, Request: "mem", Device: localDev, Pool: envNode,
				Serial: serialSliced, Size: uint64(envBlockSize), Mode: api.ModeNUMA, NumaNode: 2}
		}
		t.Run(p.Name(), func(t *testing.T) {
			e.t = t
			nodes, hooks := e.lending()
			var atLend []string
			nodes.onLend = func(node int) {
				g := e.records().Grant(state.GrantRef{Claim: "c1"})
				atLend = append(atLend, g.Got.Lend.Lease, string(rune('0'+state.NumaNodeOf(g.Got.Lend.NumaNode))))
			}
			logs := klogCapture(t)
			res := e.mustPrepare(p, e.companionOf(p))
			wantResult(t, res, resultDevice("mem", want.Pool, want.Device))
			if !slices.Equal(atLend, []string{"l1", "2"}) {
				t.Fatalf("the grant's lend at the lend: %v", atLend)
			}
			e.wantEvents("prepared", "lending l1 cxl-lease-l1", "lend pod-uid-1/app 2 l1", "prepared l1")
			if got := hooks.lentDevices(); !reflect.DeepEqual(got, []lend.LentDevice{want}) {
				t.Fatalf("lent devices %+v, expected %+v", got, want)
			}
			if e.cdiSpec(p.Rules().CDISpecName) != nil {
				t.Fatal("a CDI device of a companion claim")
			}
			if !local {
				wantLogText(t, logs(), "cxl-pool.nri.io: claim demo/cxl-lease-l1: companion of lease l1 of demo/borrower/app prepared (nodes [2], binds [])")
			}
			if info := p.ClaimInfo("c1"); info == nil || info.Lend == nil || info.Lend.Lease != "l1" || !slices.Equal(info.Lend.NumaNodes, []int{2}) ||
				info.Lend.Pod.UID != envPodUID || info.Lend.Container != envCtr {
				t.Fatalf("claim info %+v", info)
			}
			if got := NumaNodes(e.records(), p.Name()); !slices.Equal(got, []int{2}) {
				t.Fatalf("NUMA nodes %v", got)
			}
			e.mark()
			again := e.mustPrepare(p, e.companionOf(p))
			if !reflect.DeepEqual(again, res) {
				t.Fatalf("again %+v", again)
			}
			e.wantNoCommands("a Prepare again")
			e.wantEvents("a Prepare again", "lending l1 cxl-lease-l1", "prepared l1")
			var atRevoke []string
			nodes.onRevoke = func(int) {
				online := e.onlineBlocks() > 0
				atRevoke = append(atRevoke, string(e.stateOf(p, "c1")), map[bool]string{true: "online", false: "offline"}[online])
			}
			e.mustUnprepare(p, "c1")
			e.wantEvents("unprepared", "releasing l1", "revoke pod-uid-1/app 2 l1")
			if !slices.Equal(atRevoke, []string{"UNPREPARING", "online"}) || len(nodes.lentNodes()) != 0 {
				t.Fatalf("at the revoke: %v, lent %v", atRevoke, nodes.lentNodes())
			}
			e.wantClean()
		})
	}
}

// pluginOf returns the plugin of cxl.nri.io (local) or of the pool
// driver.
func (e *driverEnv) pluginOf(local bool) *Plugin {
	if local {
		return e.local
	}
	return e.pool
}

// onlineBlocks returns the number of the memory blocks of the kernel that
// are online.
func (e *driverEnv) onlineBlocks() int {
	snap, err := e.k.Kernel().Observe(context.Background())
	mustOK(e.t, err)
	n := 0
	for _, b := range snap.Blocks {
		if b.State == kernel.BlockOnline {
			n++
		}
	}
	return n
}

// A lend that fails rolls the companion claim back: the node revoked with
// the memory online, then the broker told, then the memory released.
func TestCompanionLendFails(t *testing.T) {
	for _, local := range []bool{true, false} {
		e := lendEnv(t)
		p := e.pool
		if local {
			p = e.local
		}
		t.Run(p.Name(), func(t *testing.T) {
			e.t = t
			nodes, _ := e.lending()
			nodes.setErrors(errSteered, nil)
			var online []bool
			nodes.onRevoke = func(int) { online = append(online, e.onlineBlocks() > 0) }
			res := e.prepare(p, e.companionOf(p))
			lendErr := "lease l1: lending node 2 to demo/borrower/app: " + errSteered.Error()
			wantErrText(t, res.Err, e.prefix(p)+lendErr)
			e.wantEvents("failed", "lending l1 cxl-lease-l1", "lend pod-uid-1/app 2 l1", "revoke pod-uid-1/app 2 l1", "failed l1: "+lendErr)
			if !slices.Equal(online, []bool{true}) {
				t.Fatalf("memory online at the revokes: %v", online)
			}
			e.wantState(p, "c1", state.PreparationUnknown)
			e.wantClean()
		})
	}
}

// A companion claim whose CDI spec cannot be written after the lend is
// rolled back: cxl.nri.io tells the broker that the lend failed, the pool
// driver does not (FailLeaseOnFinish).
func TestCompanionFinishFails(t *testing.T) {
	for _, local := range []bool{true, false} {
		e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()}, poolSpec(serialPoolX), fake.MemdevSpec{Serial: 0xc1ee0002, HostBridge: 24})
		p, other := e.pool, poolClaim("u0", "pooled1", `{"serial":"0xc1ee0002","shared":false,"size":268435456}`)
		if local {
			p, other = e.local, localClaim("u0", device.DRAMDeviceName, 64*mib)
		}
		t.Run(p.Name(), func(t *testing.T) {
			e.t = t
			e.lending()
			// a claim with a CDI device, then a CDI directory that cannot
			// be written
			e.mustPrepare(p, other)
			mustOK(t, os.RemoveAll(e.cdiDir))
			mustOK(t, os.WriteFile(e.cdiDir, nil, 0o644))
			e.takeEvents()
			res := e.prepare(p, e.companionOf(p))
			wantErrText(t, res.Err, "failed to write CDI spec")
			want := []string{"lending l1 cxl-lease-l1", "lend pod-uid-1/app 2 l1", "revoke pod-uid-1/app 2 l1"}
			if local {
				want = append(want, "failed l1: "+res.Err.Error())
			}
			e.wantEvents("failed", want...)
			e.wantState(p, "c1", state.PreparationUnknown)
			mustOK(t, os.Remove(e.cdiDir))
			mustOK(t, os.MkdirAll(e.cdiDir, 0o755))
			e.mustPrepare(p, e.companionOf(p))
			e.mustUnprepare(p, "c1")
			e.mustUnprepare(p, "u0")
			e.wantClean()
		})
	}
}

// The Unprepare of a numa companion whose Prepare a stop cut after the
// lend: either driver tells the broker and revokes the node before it
// releases the memory (L-55).
func TestCompanionUnfinishedRevoke(t *testing.T) {
	for _, local := range []bool{true, false} {
		e := lendEnv(t)
		p := e.pool
		if local {
			p = e.local
		}
		t.Run(p.Name(), func(t *testing.T) {
			e.t = t
			nodes, _ := e.lending()
			nodes.cut = true
			e.cutPrepare(p, e.companionOf(p))
			e.restart()
			p = e.pluginOf(local)
			e.wantState(p, "c1", state.PreparationPreparing)
			if got := NumaNodes(e.records(), p.Name()); !slices.Equal(got, []int{2}) {
				t.Fatalf("NUMA nodes of the unfinished companion %v", got)
			}
			e.takeEvents()
			e.mustUnprepare(p, "c1")
			e.wantEvents("unprepared", "releasing l1", "revoke pod-uid-1/app 2 l1")
			e.wantClean()
		})
	}
}
