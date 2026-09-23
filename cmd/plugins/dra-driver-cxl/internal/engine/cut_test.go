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

package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// cutScenario is a life cycle of claims on a node that the tests stop at
// every commit and at the kernel actions.
type cutScenario struct {
	name  string
	specs []fake.MemdevSpec
	// setup prepares the node before the life cycle (not cut).
	setup func(v *env)
	run   func(v *env)
	// done ends what the life cycle holds on the node (a busy mount) after
	// the start that follows a cut, nil for nothing.
	done func(v *env)
	// tune sets the options of the engines of the node, nil for none.
	tune func(v *env, o *Options)
	// idle releases what the node keeps for idle memdevs once every claim
	// is unprepared (a shared region kept idle), nil for nothing.
	idle func(v *env)
}

// companionTarget returns the lease bind of the companion claims of the
// scenarios.
func companionTarget(v *env) string {
	return filepath.Join(v.dir, localDriver, "lease-fs", "lc1", "data")
}

// cutScenarios are the life cycles of every kind of grant.
var cutScenarios = []cutScenario{
	{
		name:  "pool numa",
		specs: []fake.MemdevSpec{{Serial: serialA}},
		run: func(v *env) {
			_ = v.prepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeNUMA, state.KindExclusive))
			_ = v.unprepare(poolDriver, "c")
		},
	},
	{
		name:  "pool shared dax",
		specs: []fake.MemdevSpec{{Serial: serialA}},
		run: func(v *env) {
			_ = v.prepare(poolDriver, "c1", poolReq("c1", 0, serialA, state.ModeDax, state.KindShared))
			_ = v.prepare(poolDriver, "c2", poolReq("c2", 0, serialA, state.ModeDax, state.KindShared))
			_ = v.unprepare(poolDriver, "c1")
			_ = v.unprepare(poolDriver, "c2")
		},
	},
	{
		name:  "pool fs",
		specs: []fake.MemdevSpec{{Serial: serialP, Pmem: gib}},
		setup: func(v *env) { v.formatPmem("mem0", "ext4") },
		run: func(v *env) {
			_ = v.prepare(poolDriver, "w", fsGrant("w", false, ""))
			_ = v.prepare(poolDriver, "r", fsGrant("r", true, ""))
			_ = v.unprepare(poolDriver, "w")
			_ = v.unprepare(poolDriver, "r")
		},
	},
	{
		name:  "pool fs companion",
		specs: []fake.MemdevSpec{{Serial: serialP, Pmem: gib}},
		setup: func(v *env) { v.formatPmem("mem0", "ext4") },
		run: func(v *env) {
			req := fsGrant("comp", true, "")
			req.BindTarget = companionTarget(v)
			req.Lend = &state.GrantLend{Lease: "0123abcd", Name: "data"}
			_ = v.prepare(poolDriver, "comp", req)
			_ = v.unprepare(poolDriver, "comp")
		},
	},
	{
		// the Unprepare of a companion fails on its busy lease bind; the
		// release of another claim unbinds it again, and the companion
		name:  "pool busy companion bind",
		specs: []fake.MemdevSpec{{Serial: serialP, Pmem: gib}, {Serial: serialA}},
		setup: func(v *env) { v.formatPmem("mem0", "ext4") },
		run: func(v *env) {
			req := fsGrant("comp", true, "")
			req.BindTarget = companionTarget(v)
			req.Lend = &state.GrantLend{Lease: "0123abcd", Name: "data"}
			_ = v.prepare(poolDriver, "comp", req)
			v.f.SetBusy(companionTarget(v), true)
			_ = v.unprepare(poolDriver, "comp")
			v.f.SetBusy(companionTarget(v), false)
			_ = v.prepare(poolDriver, "a", poolReq("a", 0, serialA, state.ModeDax, state.KindExclusive))
			_ = v.unprepare(poolDriver, "a")
			_ = v.unprepare(poolDriver, "comp")
		},
		done: func(v *env) { v.f.SetBusy(companionTarget(v), false) },
	},
	{
		name:  "pool fs writer and reader of one claim",
		specs: []fake.MemdevSpec{{Serial: serialP, Pmem: gib}},
		setup: func(v *env) { v.formatPmem("mem0", "ext4") },
		run: func(v *env) {
			r := fsGrant("c", true, "")
			r.Ref.Result = 1
			_ = v.prepare(poolDriver, "c", fsGrant("c", false, ""), r)
			_ = v.unprepare(poolDriver, "c")
		},
	},
	{
		// the second grant fails: the rollback releases the first one
		name:  "pool rollback",
		specs: []fake.MemdevSpec{{Serial: serialP, Pmem: gib}, {Serial: serialA}},
		setup: func(v *env) { v.formatPmem("mem0", "ext4") },
		run: func(v *env) {
			v.f.FailCommand("cxl create-region", nil, errors.New("cxl region: cmd_create_region: failed"))
			reqs := []GrantRequest{fsGrant("c", true, ""), poolReq("c", 1, serialA, state.ModeDax, state.KindExclusive)}
			_ = v.prepare(poolDriver, "c", reqs...)
			_ = v.prepare(poolDriver, "c", reqs...)
			_ = v.unprepare(poolDriver, "c")
		},
	},
	{
		name:  "local sliced",
		specs: []fake.MemdevSpec{{Serial: serialL, Ram: gib}},
		run: func(v *env) {
			_ = v.prepare(localDriver, "n", localReq("n", 0, serialL, state.ModeNUMA, state.KindExclusive, 256*mib))
			_ = v.prepare(localDriver, "d", localReq("d", 0, serialL, state.ModeDax, state.KindExclusive, 256*mib))
			_ = v.unprepare(localDriver, "n")
			_ = v.unprepare(localDriver, "d")
		},
	},
}

// newCutEnv returns the node of a scenario.
func newCutEnv(t *testing.T, s cutScenario) *env {
	v := newEnv(t, s.specs...)
	if s.tune != nil {
		v.configure(func(o *Options) { s.tune(v, o) })
	}
	if s.setup != nil {
		s.setup(v)
	}
	return v
}

// finish unprepares every claim that the store has and checks that nothing
// is left.
func finish(t *testing.T, v *env, what string) {
	t.Helper()
	for _, p := range v.records().Preparations {
		if err := v.unprepare(p.Driver, p.UID); err != nil {
			t.Fatalf("%s: unprepare %s: %v", what, p.UID, err)
		}
	}
	v.check(what + ": finished")
	v.clean(what + ": finished")
}

// finishScenario unprepares every claim of the node of a scenario,
// releases what it keeps for idle memdevs and checks that nothing is left.
func finishScenario(t *testing.T, s cutScenario, v *env, what string) {
	t.Helper()
	if s.idle != nil {
		for _, p := range v.records().Preparations {
			if err := v.unprepare(p.Driver, p.UID); err != nil {
				t.Fatalf("%s: unprepare %s: %v", what, p.UID, err)
			}
		}
		s.idle(v)
	}
	finish(t, v, what)
}

// Every commit of the engine is a point where the process may stop: the
// start after it recovers records that the invariants accept (what the
// records name exists or is resolved), and the claims are released then
// without anything left.
func TestCutAtEveryCommit(t *testing.T) {
	cutAtEveryCommit(t, cutScenarios)
}

// cutSlots bound the life cycles that the cut tests run at once.
var cutSlots = make(chan struct{}, 16)

// parallel runs the rest of the test in parallel with the other cut tests
// of its parent, in a slot of cutSlots.
func parallel(t *testing.T) {
	t.Parallel()
	cutSlots <- struct{}{}
	t.Cleanup(func() { <-cutSlots })
}

// cutAtEveryCommit stops the life cycle of each of the scenarios after
// each of its commits, starts again and finishes it; the scenarios and the
// stops run in parallel.
func cutAtEveryCommit(t *testing.T, scenarios []cutScenario) {
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			var total int
			func() {
				cutSlots <- struct{}{}
				defer func() { <-cutSlots }()
				v := newCutEnv(t, s)
				before := v.commits
				s.run(v)
				total = v.commits - before
				finishScenario(t, s, v, "uncut")
			}()
			for n := 1; n <= total; n++ {
				what := fmt.Sprintf("cut after commit %d of %d", n, total)
				t.Run(what, func(t *testing.T) {
					parallel(t)
					v := newCutEnv(t, s)
					v.cutAfter(n)
					if !v.cut(func() { s.run(v) }) {
						t.Fatalf("commit %d of %d: not cut", n, total)
					}
					v.restart()
					v.check(what)
					if s.done != nil {
						s.done(v)
					}
					finishScenario(t, s, v, what)
				})
			}
		})
	}
}

// cutActions are the kernel actions where the tests stop the process
// before and after.
var cutActions = []string{
	"cxl create-region", "cxl disable-region", "cxl destroy-region", "cxl disable-memdev", "ndctl create-namespace",
	"write bus/dax/drivers/kmem/bind", "write bus/dax/drivers/device_dax/bind", "write devices/system/memory/memory",
	"write bus/dax/devices/dax0.0/size", "write bus/dax/devices/dax0.1/size",
}

// A process stop before or after a kernel action: the start recovers, and
// the claims are released then without anything left.
func TestCutAtKernelActions(t *testing.T) {
	cutAtActions(t, cutScenarios, cutActions)
}

// cutAtActions stops the life cycle of each of the scenarios before and
// after each of the actions (a prefix of a command or sysfs write; "zero"
// a zeroing, "probe" in an address line probe), starts again and finishes
// it; the stops run in parallel.
func cutAtActions(t *testing.T, scenarios []cutScenario, actions []string) {
	for _, s := range scenarios {
		for _, action := range actions {
			for _, after := range []bool{false, true} {
				if action == cutProbe && after {
					continue
				}
				name := fmt.Sprintf("%s/%s/after=%v", s.name, action, after)
				t.Run(name, func(t *testing.T) {
					parallel(t)
					v := newCutEnv(t, s)
					switch {
					case action == cutZero:
						v.cutZeroing(after)
					case action == cutProbe:
						v.f.CutProbe()
					case after:
						v.f.CutAfter(action)
					default:
						v.f.CutBefore(action)
					}
					if !v.cut(func() { s.run(v) }) {
						t.Skip("no such action")
					}
					v.restart()
					v.check(name)
					if s.done != nil {
						s.done(v)
					}
					finishScenario(t, s, v, name)
				})
			}
		}
	}
}

// The pseudo actions of cutAtActions: a zeroing of a dax device, an
// address line probe.
const (
	cutZero  = "zero"
	cutProbe = "probe"
)

// probeOptions sets the address line probe of the new regions of the local
// memdevs of the node, its results in the node's probes file.
func probeOptions(v *env, o *Options) {
	o.ProbeAddressing = true
	o.ProbesFile = filepath.Join(v.dir, "localProbes.json")
}

// sharedOptions configures every local memdev shared, the new regions
// probed.
func sharedOptions(v *env, o *Options) {
	probeOptions(v, o)
	o.Shared = func(state.Serial) bool { return true }
}

// releaseIdleShared starts the node again with no local memdev configured
// shared: the start releases the regions that idle shared memdevs kept.
func releaseIdleShared(v *env) {
	prev := v.tune
	v.tune = func(o *Options) {
		if prev != nil {
			prev(o)
		}
		o.Shared = nil
	}
	v.restart()
}

// sliceReq returns the request of a part of the local sliced memdev
// serialL for result n of the claim uid.
func sliceReq(uid string, n int, mode state.Mode, size uint64) GrantRequest {
	return localReq(uid, n, serialL, mode, state.KindExclusive, size)
}

// sharedReq returns the request of a grant of the local shared memdev
// serialL for the claim uid.
func sharedReq(uid string) GrantRequest {
	return localReq(uid, 0, serialL, state.ModeDax, state.KindShared, gib)
}

// localPmemReq returns the request of a grant of mode fs (access, readOnly)
// or block of the local persistent memdev serialP for result n of the
// claim uid.
func localPmemReq(uid string, n int, mode state.Mode, readOnly bool, access state.Access) GrantRequest {
	req := localReq(uid, n, serialP, mode, state.KindPersistent, 0)
	if mode == state.ModeFs {
		return fsReq(req, readOnly, access)
	}
	req.Asked.ReadOnly = readOnly
	return req
}

// localCutScenarios are the life cycles of every kind of local grant.
var localCutScenarios = []cutScenario{
	{
		name:  "local sliced numa",
		specs: []fake.MemdevSpec{{Serial: serialL, Ram: gib}},
		tune:  probeOptions,
		run: func(v *env) {
			_ = v.prepare(localDriver, "n1", sliceReq("n1", 0, state.ModeNUMA, 256*mib))
			_ = v.prepare(localDriver, "n2", sliceReq("n2", 0, state.ModeNUMA, 256*mib))
			_ = v.unprepare(localDriver, "n1")
			_ = v.unprepare(localDriver, "n2")
		},
	},
	{
		name:  "local sliced dax",
		specs: []fake.MemdevSpec{{Serial: serialL, Ram: gib}},
		run: func(v *env) {
			_ = v.prepare(localDriver, "d1", sliceReq("d1", 0, state.ModeDax, 256*mib))
			_ = v.prepare(localDriver, "d2", sliceReq("d2", 0, state.ModeDax, 256*mib))
			_ = v.unprepare(localDriver, "d2")
			_ = v.unprepare(localDriver, "d1")
		},
	},
	{
		name:  "local two parts of one claim",
		specs: []fake.MemdevSpec{{Serial: serialL, Ram: gib}},
		run: func(v *env) {
			_ = v.prepare(localDriver, "c", sliceReq("c", 0, state.ModeNUMA, 256*mib), sliceReq("c", 1, state.ModeDax, 256*mib))
			_ = v.unprepare(localDriver, "c")
		},
	},
	{
		// the second part fails: the rollback releases the first one; the
		// Prepare again makes both
		name:  "local sliced rollback",
		specs: []fake.MemdevSpec{{Serial: serialL, Ram: gib}},
		run: func(v *env) {
			v.f.FailWrite("bus/dax/devices/dax0.1/size", errBusy)
			reqs := []GrantRequest{sliceReq("c", 0, state.ModeNUMA, 256*mib), sliceReq("c", 1, state.ModeDax, 256*mib)}
			_ = v.prepare(localDriver, "c", reqs...)
			_ = v.prepare(localDriver, "c", reqs...)
			_ = v.unprepare(localDriver, "c")
		},
	},
	{
		// a region that does not start at a memory block boundary: parts
		// placed through the mapping
		name: "local slices on whole blocks",
		setup: func(v *env) {
			v.f.SetBlockSize(512 * mib)
			v.f.Plug(fake.MemdevSpec{Serial: serialL, Ram: 4 * gib})
		},
		run: func(v *env) {
			_ = v.prepare(localDriver, "n1", sliceReq("n1", 0, state.ModeNUMA, 512*mib))
			_ = v.prepare(localDriver, "n2", sliceReq("n2", 0, state.ModeDax, 512*mib))
			_ = v.unprepare(localDriver, "n1")
			_ = v.unprepare(localDriver, "n2")
		},
	},
	{
		name:  "local shared",
		specs: []fake.MemdevSpec{{Serial: serialL, Ram: gib}},
		tune:  sharedOptions,
		run: func(v *env) {
			_ = v.prepare(localDriver, "s1", sharedReq("s1"))
			_ = v.prepare(localDriver, "s2", sharedReq("s2"))
			_ = v.unprepare(localDriver, "s1")
			_ = v.unprepare(localDriver, "s2")
		},
		idle: releaseIdleShared,
	},
	{
		name:  "local persistent fs read-write",
		specs: []fake.MemdevSpec{{Serial: serialP, Pmem: gib}},
		setup: func(v *env) { v.formatPmem("mem0", "ext4") },
		run: func(v *env) {
			_ = v.prepare(localDriver, "w", localPmemReq("w", 0, state.ModeFs, false, ""))
			_ = v.prepare(localDriver, "r", localPmemReq("r", 0, state.ModeFs, true, ""))
			_ = v.unprepare(localDriver, "w")
			_ = v.unprepare(localDriver, "r")
		},
	},
	{
		name:  "local persistent fs read-only cached and direct",
		specs: []fake.MemdevSpec{{Serial: serialP, Pmem: gib}},
		setup: func(v *env) { v.formatPmem("mem0", "erofs") },
		run: func(v *env) {
			_ = v.prepare(localDriver, "rc", localPmemReq("rc", 0, state.ModeFs, true, state.AccessCached))
			_ = v.prepare(localDriver, "rd", localPmemReq("rd", 0, state.ModeFs, true, state.AccessDirect))
			_ = v.unprepare(localDriver, "rc")
			_ = v.unprepare(localDriver, "rd")
		},
	},
	{
		// a writer of mode block makes the fsdax namespace; a reader
		// after it
		name:  "local persistent block",
		specs: []fake.MemdevSpec{{Serial: serialP, Pmem: gib}},
		run: func(v *env) {
			_ = v.prepare(localDriver, "b", localPmemReq("b", 0, state.ModeBlock, false, ""))
			_ = v.unprepare(localDriver, "b")
			_ = v.prepare(localDriver, "r", localPmemReq("r", 0, state.ModeBlock, true, ""))
			_ = v.unprepare(localDriver, "r")
		},
	},
	{
		// a part of mode numa of a companion claim, its node recorded as
		// lent
		name:  "local numa companion",
		specs: []fake.MemdevSpec{{Serial: serialL, Ram: gib}},
		run: func(v *env) {
			req := sliceReq("comp", 0, state.ModeNUMA, 256*mib)
			req.Lend = &state.GrantLend{Lease: "0123abcd", Container: "c"}
			if v.prepare(localDriver, "comp", req) == nil {
				if g := v.records().Grant(req.Ref); g != nil {
					_ = v.e.RecordLend(context.Background(), req.Ref, state.NumaNodeOf(g.Got.NumaNode))
				}
			}
			_ = v.unprepare(localDriver, "comp")
		},
	},
}

// localCutActions are the kernel actions of the local grants where the
// tests stop the process before and after.
var localCutActions = []string{
	"cxl create-region", "cxl disable-region", "cxl destroy-region", "ndctl create-namespace",
	"write bus/cxl/devices/region0/dax_region0/dax_region/create", "write bus/cxl/devices/region0/dax_region0/dax_region/delete",
	"write bus/dax/devices/dax0.0/size", "write bus/dax/devices/dax0.1/size", "write bus/dax/devices/dax0.1/mapping",
	"write bus/dax/devices/dax0.2/mapping", "write bus/dax/drivers/kmem/unbind", "write bus/dax/drivers/kmem/bind",
	"write bus/dax/drivers/device_dax/new_id", "write bus/dax/drivers/device_dax/unbind", "write devices/system/memory/memory",
	cutZero, cutProbe,
}

// Every commit of the engine in the life cycles of the local grants is a
// point where the process may stop: the start recovers records that the
// invariants accept, and the claims are released then without anything
// left.
func TestLocalCutAtEveryCommit(t *testing.T) {
	cutAtEveryCommit(t, localCutScenarios)
}

// A process stop before or after a kernel action of a local grant (the
// dax devices, the drivers, the memory blocks, the zeroing, the probe):
// the start recovers, and the claims are released then without anything
// left.
func TestLocalCutAtKernelActions(t *testing.T) {
	cutAtActions(t, localCutScenarios, localCutActions)
}
