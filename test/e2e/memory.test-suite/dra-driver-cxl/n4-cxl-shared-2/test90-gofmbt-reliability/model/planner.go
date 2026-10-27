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

// The gofmbt model of the State, and the planner interface that the
// on-line loop, the generator and the experiments use. planner_ext.go
// implements it (custom coverage, budgets, coverage rounds).

import (
	"math/rand"
	"runtime/debug"
	"time"

	m "github.com/askervin/gofmbt/gofmbt"
)

// gofmbtVersion is the version of gofmbt in the binary, printed in the
// headers and the log: model/go.mod's version, or "(devel)" when a
// go.work replaced it with a checkout.
var gofmbtVersion = func() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path != "github.com/askervin/gofmbt" {
				continue
			}
			if d.Replace != nil {
				return d.Replace.Path + "@" + d.Replace.Version
			}
			return d.Version
		}
	}
	return "unknown"
}()

// mbtModel is the gofmbt model: one action per action of the
// configuration, created once; an action is enabled when State.next
// returns non-nil. StepsFrom loops over the action table directly (no
// gofmbt Model and Transition closures); the planner walks a planWalk
// (canon.go), which caches the steps of canonical states per plan.
type mbtModel struct {
	cfg      *Config
	acts     []Act
	actions  []*m.Action
	all      []int // every action index
	forced   []int // settle, write and read: all a forced state allows
	byAction map[*m.Action]int
	byAct    map[Act]int
	formats  []string // C3: the format of each action
}

// actIndex returns the index of the action of a step.
func (mm *mbtModel) actIndex(st *m.Step) int { return mm.byAction[st.Action()] }

func newMbtModel(cfg *Config) *mbtModel {
	mm := &mbtModel{cfg: cfg, byAction: map[*m.Action]int{}, byAct: map[Act]int{}}
	for _, a := range allActs(cfg) {
		f, args := a.format(cfg)
		act := m.NewAction(f, args...)
		i := len(mm.acts)
		mm.byAction[act] = i
		mm.byAct[a] = i
		mm.acts = append(mm.acts, a)
		mm.actions = append(mm.actions, act)
		mm.all = append(mm.all, i)
		mm.formats = append(mm.formats, f)
		if a.Verb == VSettle || a.Verb == VWrite || a.Verb == VRead {
			mm.forced = append(mm.forced, i)
		}
	}
	return mm
}

// stepsOf returns the steps from a state in table order; intern, if not
// nil, maps every end state to its canonical object.
func (mm *mbtModel) stepsOf(st *State, intern func(*State) *State) []*m.Step {
	idx := mm.all
	if st.forced() {
		idx = mm.forced
	}
	var steps []*m.Step
	for _, i := range idx {
		n := st.next(mm.acts[i])
		if n == nil {
			continue
		}
		if intern != nil {
			n = intern(n)
		}
		steps = append(steps, m.NewStep(st, mm.actions[i], n))
	}
	return steps
}

// StepsFrom implements gofmbt's Walkable without caching.
func (mm *mbtModel) StepsFrom(s m.State) []*m.Step { return mm.stepsOf(s.(*State), nil) }

// enabledActs returns the enabled actions of a state in table order.
func (mm *mbtModel) enabledActs(s *State) []Act {
	var out []Act
	for _, a := range mm.acts {
		if s.enabled(a) {
			out = append(out, a)
		}
	}
	return out
}

// planBudget limits one plan.
type planBudget struct {
	Deadline time.Time     // zero: none
	MaxPaths int           // 0: none
	Stop     chan struct{} // closed: stop now
}

// planInfo tells how a plan went.
type planInfo struct {
	Depth    int  // depth completed
	Paths    int  // paths evaluated
	Increase int  // coverage increase of the path, 0 if none
	Reset    bool // a new coverage round was started
	Random   bool // no path increased coverage: a random step
	Elapsed  time.Duration
	States   int // canonical states of the plan's cache (planWalk)
	Expanded int // of them, states whose steps were computed
}

// planner chooses steps by coverage.
type planner interface {
	// plan returns the next action from s: the first step of the best
	// path of at most depth steps.
	plan(s *State, b planBudget) (Act, planInfo)
	// planAfter plans the step after a step that is being executed and
	// not marked yet: the second step of the best path of at most
	// depth+1 steps from "from" whose first step is the predicted one
	// (from, a, to). ok is false if there is no such path.
	planAfter(from *State, a Act, to *State, b planBudget) (next Act, info planInfo, ok bool)
	// mark marks a step covered: the step that happened, with the end
	// state that the observation decided.
	mark(from *State, a Act, to *State)
	// coverage is the number of covered strings in this round.
	coverage() int
	// rounds is the number of coverage rounds started.
	rounds() int
}

// forcedFirst is the walkable of planAfter: from the root only the step
// being executed, the inner walkable's steps elsewhere.
type forcedFirst struct {
	inner m.Walkable
	root  *State
	step  *m.Step
}

func (f *forcedFirst) StepsFrom(s m.State) []*m.Step {
	if st, ok := s.(*State); ok && st == f.root {
		return []*m.Step{f.step}
	}
	return f.inner.StepsFrom(s)
}

// forced1 returns the walkable of planAfter over an inner walkable (a
// planWalk with from and to as roots).
func (mm *mbtModel) forced1(inner m.Walkable, from *State, a Act, to *State) *forcedFirst {
	return &forcedFirst{inner: inner, root: from, step: m.NewStep(from, mm.actions[mm.byAct[a]], to)}
}

// randomEnabled returns a random enabled action, settle first if the
// state is forced to settle.
func randomEnabled(mm *mbtModel, s *State, rng *rand.Rand) Act {
	acts := mm.enabledActs(s)
	if len(acts) == 0 {
		// cannot happen: create of an absent slot or delete of a
		// present one is always possible, settle when unsettled
		return Act{Verb: VSettle, Slot: -1, VM: VMAny, Pool: noPool}
	}
	if s.forced() {
		return Act{Verb: VSettle, Slot: -1, VM: VMAny, Pool: noPool}
	}
	return acts[rng.Intn(len(acts))]
}
