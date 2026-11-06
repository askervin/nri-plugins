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

// Every commit of the engine is a point where the process may stop: the
// start after it recovers records that the invariants accept (what the
// records name exists or is resolved), and the claims are released then
// without anything left.
func TestCutAtEveryCommit(t *testing.T) {
	for _, s := range cutScenarios {
		t.Run(s.name, func(t *testing.T) {
			v := newCutEnv(t, s)
			before := v.commits
			s.run(v)
			total := v.commits - before
			finish(t, v, "uncut")
			for n := 1; n <= total; n++ {
				v := newCutEnv(t, s)
				v.cutAfter(n)
				if !v.cut(func() { s.run(v) }) {
					t.Fatalf("commit %d of %d: not cut", n, total)
				}
				what := fmt.Sprintf("cut after commit %d of %d", n, total)
				v.restart()
				v.check(what)
				if s.done != nil {
					s.done(v)
				}
				finish(t, v, what)
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
	for _, s := range cutScenarios {
		for _, action := range cutActions {
			for _, after := range []bool{false, true} {
				name := fmt.Sprintf("%s/%s/after=%v", s.name, action, after)
				t.Run(name, func(t *testing.T) {
					v := newCutEnv(t, s)
					if after {
						v.f.CutAfter(action)
					} else {
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
					finish(t, v, name)
				})
			}
		}
	}
}
