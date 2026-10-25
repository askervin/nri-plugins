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
// implements it with the extended gofmbt (branch 5jo-mbt-cxl: custom
// coverage, budgets, coverage rounds), planner_stock.go (build tag
// gofmbtstock) with the stock library (C1 and C3 only, no budget).

import (
	"math/rand"
	"time"

	m "github.com/askervin/gofmbt/gofmbt"
)

// mbtModel is the gofmbt model: one transition per action of the
// configuration, created once; a transition is enabled when its state
// change returns non-nil.
type mbtModel struct {
	cfg      *Config
	acts     []Act
	actions  []*m.Action
	trans    []*m.Transition
	forced   []*m.Transition // settle, write and read: all a forced state allows
	byAction map[*m.Action]int
	byAct    map[Act]int
	model    *m.Model
	formats  []string // C3: the format of each action
}

// actIndex returns the index of the action of a step.
func (mm *mbtModel) actIndex(st *m.Step) int { return mm.byAction[st.Action()] }

func newMbtModel(cfg *Config) *mbtModel {
	mm := &mbtModel{cfg: cfg, byAction: map[*m.Action]int{}, byAct: map[Act]int{}}
	for _, a := range allActs(cfg) {
		a := a
		f, args := a.format(cfg)
		act := m.NewAction(f, args...)
		t := m.NewTransition(act, func(st m.State) m.State {
			if n := st.(*State).next(a); n != nil {
				return n
			}
			return nil
		})
		mm.byAction[act] = len(mm.acts)
		mm.byAct[a] = len(mm.acts)
		mm.acts = append(mm.acts, a)
		mm.actions = append(mm.actions, act)
		mm.trans = append(mm.trans, t)
		mm.formats = append(mm.formats, f)
		if a.Verb == VSettle || a.Verb == VWrite || a.Verb == VRead {
			mm.forced = append(mm.forced, t)
		}
	}
	mm.model = m.NewModel()
	mm.model.From(func(st m.State) []*m.Transition {
		if st.(*State).forced() {
			return mm.forced
		}
		return mm.trans
	})
	return mm
}

// StepsFrom implements gofmbt's Walkable.
func (mm *mbtModel) StepsFrom(s m.State) []*m.Step { return mm.model.StepsFrom(s) }

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
// being executed, the model's steps elsewhere.
type forcedFirst struct {
	mm   *mbtModel
	root *State
	step *m.Step
}

func (f *forcedFirst) StepsFrom(s m.State) []*m.Step {
	if st, ok := s.(*State); ok && st == f.root {
		return []*m.Step{f.step}
	}
	return f.mm.StepsFrom(s)
}

func (mm *mbtModel) forced1(from *State, a Act, to *State) *forcedFirst {
	return &forcedFirst{mm: mm, root: from, step: m.NewStep(from, mm.actions[mm.byAct[a]], to)}
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
