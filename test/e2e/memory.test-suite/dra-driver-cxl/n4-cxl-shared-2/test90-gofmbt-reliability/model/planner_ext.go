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

// The planner on gofmbt's incremental coverage and budgeted search
// (CoverSteps, CoverStartState, ResetCoverage, BestPathWithBudget; on
// gofmbt's main since bc12d42, plan-13-gofmbt/04-status-GOFMBT.txt):
// custom coverage (C2, C4), budgeted search, coverage rounds.

import (
	"math/rand"
	"time"

	m "github.com/askervin/gofmbt/gofmbt"
)

type extPlanner struct {
	mm     *mbtModel
	c      *m.Coverer
	depth  int
	rng    *rand.Rand
	nRound int
	cs     *covStrings
}

// covStrings are the coverage strings of the planner, precomputed
// (20-mbtopt-02-design.txt C1): per action (C1 names, C3 singles), per
// pair of actions (C3), and per plan per step and per end state (C1
// lease chances, C2, C4). The coverage functions only look them up.
type covStrings struct {
	mm      *mbtModel
	w       [4]int     // the weights of C1..C4
	names   [][]string // C1: per action, weighed
	singles [][]string // C3: per action, weighed
	pairs   [][]string // C3: per (previous, current) action, with the singles of the current; filled lazily
	plan    *planStrings
}

// planStrings are the strings of the steps and states of one plan: the
// steps and the states of a planWalk do not change, and their strings
// are the same however the search reaches them. Dropped with the plan,
// like the planWalk (F5 of 20-mbtopt-01-findings.txt).
type planStrings struct {
	walk    *planWalk            // strings are kept while it keeps states
	step    map[*m.Step][]string // C1, C2, C4 of a step
	chances map[*State][]string  // C1: leaseChances of an end state, weighed
}

func newCovStrings(mm *mbtModel, cov Coverage) *covStrings {
	cs := &covStrings{mm: mm, w: cov.W}
	n := len(mm.acts)
	cs.names = make([][]string, n)
	cs.singles = make([][]string, n)
	for i, a := range mm.acts {
		cs.names[i] = clip(c1Strings(mm.cfg, a, max(cov.W[0], 1)))
		// (weight 1: the strings of gofmbt's
		// CoverActionFormatCombinations(2))
		cs.singles[i] = clip(weigh(cov.W[2], "C3.", []string{mm.formats[i]}))
	}
	cs.pairs = make([][]string, n*n)
	return cs
}

// clip makes an append to xs copy it.
func clip(xs []string) []string { return xs[:len(xs):len(xs)] }

// startPlan starts the strings of a plan on a walk, endPlan drops them.
// Outside a plan (MarkCovered) the strings of a step are computed every
// time; so they are when the walk is full (its new steps and states are
// not shared then).
func (cs *covStrings) startPlan(w *planWalk) {
	cs.plan = &planStrings{walk: w, step: map[*m.Step][]string{}, chances: map[*State][]string{}}
}

func (cs *covStrings) endPlan() { cs.plan = nil }

// stepStrings returns the C1, C2 and C4 strings of a step (window 1).
func (cs *covStrings) stepStrings(st *m.Step) []string {
	ps := cs.plan
	if ps == nil {
		return cs.computeStep(st)
	}
	if x, ok := ps.step[st]; ok {
		return x
	}
	x := cs.computeStep(st)
	if !ps.walk.full() {
		ps.step[st] = x
	}
	return x
}

func (cs *covStrings) computeStep(st *m.Step) []string {
	i := cs.mm.actIndex(st)
	from, to := st.StartState().(*State), st.EndState().(*State)
	var out []string
	if cs.w[0] > 0 {
		out = cs.names[i]
		if ch := cs.chances(to); len(ch) > 0 {
			out = append(out, ch...) // (names are clipped: a copy)
		}
	}
	if w := cs.w[1]; w > 0 {
		if fc := faultContext(from, cs.mm.acts[i]); len(fc) > 0 {
			out = append(clip(out), weigh(w, "C2.", fc)...)
		}
	}
	if w := cs.w[3]; w > 0 {
		out = append(clip(out), weigh(w, "C4.", to.abstract())...)
	}
	return out
}

// chances returns the weighed leaseChances of an end state.
func (cs *covStrings) chances(to *State) []string {
	ps := cs.plan
	if ps == nil {
		return weigh(cs.w[0], "", leaseChances(to))
	}
	if x, ok := ps.chances[to]; ok {
		return x
	}
	x := weigh(cs.w[0], "", leaseChances(to))
	if !ps.walk.full() {
		ps.chances[to] = x
	}
	return x
}

// pairStrings returns the C3 strings of a step after another one (prev
// -1: the first step of the test).
func (cs *covStrings) pairStrings(prev, cur int) []string {
	if prev < 0 {
		return cs.singles[cur]
	}
	k := prev*len(cs.mm.acts) + cur
	if x := cs.pairs[k]; x != nil {
		return x
	}
	pair := cs.mm.formats[prev] + "\x00" + cs.mm.formats[cur]
	x := append(cs.singles[cur], weigh(cs.w[2], "C3.", []string{pair})...)
	cs.pairs[k] = x
	return x
}

func newPlanner(mm *mbtModel, cov Coverage, depth int, seed int64, randomness int) (planner, error) {
	c := m.NewCoverer()
	cs := newCovStrings(mm, cov)
	// C1, C2 and C4 of a step in one function: the number of new
	// strings of a step does not depend on their order
	if cov.on(1) || cov.on(2) || cov.on(4) {
		c.CoverSteps(1, func(steps m.Path) []string { return cs.stepStrings(steps[len(steps)-1]) })
	}
	if cov.on(3) {
		c.CoverSteps(2, func(steps m.Path) []string {
			prev := -1
			if len(steps) >= 2 {
				prev = mm.actIndex(steps[len(steps)-2])
			}
			return cs.pairStrings(prev, mm.actIndex(steps[len(steps)-1]))
		})
	}
	if w := cov.W[3]; w > 0 {
		c.CoverStartState(func(s m.State) []string { return weigh(w, "C4.", s.(*State).abstract()) })
	}
	if randomness > 0 {
		c.SetBestPathRandom(seed, randomness)
	}
	return &extPlanner{mm: mm, c: c, depth: depth, rng: rand.New(rand.NewSource(seed)), nRound: 1, cs: cs}, nil
}

func (p *extPlanner) plan(s *State, b planBudget) (Act, planInfo) {
	start := time.Now()
	info := planInfo{}
	// one cache for both attempts: the transitions do not depend on
	// the coverage
	w := newPlanWalk(p.mm, s)
	p.cs.startPlan(w)
	defer p.cs.endPlan()
	for attempt := 0; attempt < 2; attempt++ {
		budget := m.SearchBudget{Deadline: b.Deadline, MaxPaths: b.MaxPaths}
		if b.Stop != nil {
			budget.Stop = b.Stop
		}
		path, stats, si := p.c.BestPathWithBudget(w, s, p.depth, budget)
		info.Depth, info.Paths = si.Depth, info.Paths+si.Paths
		if len(path) > 0 {
			info.Increase = stats.MaxIncrease
			info.Elapsed = time.Since(start)
			info.States, info.Expanded = w.size()
			return p.mm.acts[p.mm.byAction[path[0].Action()]], info
		}
		if si.Depth < p.depth || attempt > 0 {
			break
		}
		// nothing new within the depth: a new coverage round
		p.c.ResetCoverage()
		p.nRound++
		info.Reset = true
	}
	info.Random = true
	info.Elapsed = time.Since(start)
	info.States, info.Expanded = w.size()
	return randomEnabled(p.mm, s, p.rng), info
}

func (p *extPlanner) planAfter(from *State, a Act, to *State, b planBudget) (Act, planInfo, bool) {
	start := time.Now()
	budget := m.SearchBudget{Deadline: b.Deadline, MaxPaths: b.MaxPaths}
	if b.Stop != nil {
		budget.Stop = b.Stop
	}
	w := newPlanWalk(p.mm, from, to)
	p.cs.startPlan(w)
	defer p.cs.endPlan()
	path, stats, si := p.c.BestPathWithBudget(p.mm.forced1(w, from, a, to), from, p.depth+1, budget)
	info := planInfo{Depth: si.Depth - 1, Paths: si.Paths, Elapsed: time.Since(start)}
	info.States, info.Expanded = w.size()
	if len(path) < 2 {
		return Act{}, info, false
	}
	info.Increase = stats.MaxIncrease
	return p.mm.acts[p.mm.byAction[path[1].Action()]], info, true
}

func (p *extPlanner) mark(from *State, a Act, to *State) {
	i, ok := p.mm.byAct[a]
	if !ok {
		return
	}
	p.c.MarkCovered(m.NewStep(from, p.mm.actions[i], to))
}

func (p *extPlanner) coverage() int { return p.c.Coverage() }

func (p *extPlanner) rounds() int { return p.nRound }
