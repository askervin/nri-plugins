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

//go:build !gofmbtstock

package main

// The planner on the extended gofmbt (local branch 5jo-mbt-cxl of
// github.com/askervin/gofmbt, plan-13-gofmbt/04-status-GOFMBT.txt):
// incremental custom coverage (C2, C4), budgeted search, coverage rounds.

import (
	"math/rand"
	"time"

	m "github.com/askervin/gofmbt/gofmbt"
)

const gofmbtFlavor = "extended"

type extPlanner struct {
	mm     *mbtModel
	c      *m.Coverer
	depth  int
	rng    *rand.Rand
	nRound int
}

func newPlanner(mm *mbtModel, cov Coverage, depth int, seed int64, randomness int) (planner, error) {
	c := m.NewCoverer()
	if w := cov.W[0]; w > 0 {
		names := make([][]string, len(mm.acts))
		for i, a := range mm.acts {
			names[i] = c1Strings(mm.cfg, a, w)
		}
		c.CoverSteps(1, func(steps m.Path) []string {
			st := steps[len(steps)-1]
			if ch := leaseChances(st.EndState().(*State)); len(ch) > 0 {
				return append(append([]string(nil), names[mm.actIndex(st)]...), weigh(w, "", ch)...)
			}
			return names[mm.actIndex(st)]
		})
	}
	switch w := cov.W[2]; {
	case w == 1:
		c.CoverActionFormatCombinations(2)
	case w > 1:
		singles := make([][]string, len(mm.acts))
		for i := range mm.acts {
			singles[i] = weigh(w, "C3.", []string{mm.formats[i]})
		}
		c.CoverSteps(2, func(steps m.Path) []string {
			cur := mm.actIndex(steps[len(steps)-1])
			if len(steps) < 2 {
				return singles[cur]
			}
			pair := mm.formats[mm.actIndex(steps[len(steps)-2])] + "\x00" + mm.formats[cur]
			return append(append([]string(nil), singles[cur]...), weigh(w, "C3.", []string{pair})...)
		})
	}
	if w := cov.W[1]; w > 0 {
		c.CoverSteps(1, func(steps m.Path) []string {
			st := steps[len(steps)-1]
			return weigh(w, "C2.", faultContext(st.StartState().(*State), st.EndState().(*State).Last))
		})
	}
	if w := cov.W[3]; w > 0 {
		c.CoverStartState(func(s m.State) []string { return weigh(w, "C4.", s.(*State).abstract()) })
		c.CoverSteps(1, func(steps m.Path) []string {
			return weigh(w, "C4.", steps[len(steps)-1].EndState().(*State).abstract())
		})
	}
	if randomness > 0 {
		c.SetBestPathRandom(seed, randomness)
	}
	return &extPlanner{mm: mm, c: c, depth: depth, rng: rand.New(rand.NewSource(seed)), nRound: 1}, nil
}

func (p *extPlanner) plan(s *State, b planBudget) (Act, planInfo) {
	start := time.Now()
	info := planInfo{}
	for attempt := 0; attempt < 2; attempt++ {
		budget := m.SearchBudget{Deadline: b.Deadline, MaxPaths: b.MaxPaths}
		if b.Stop != nil {
			budget.Stop = b.Stop
		}
		path, stats, si := p.c.BestPathWithBudget(p.mm, s, p.depth, budget)
		info.Depth, info.Paths = si.Depth, info.Paths+si.Paths
		if len(path) > 0 {
			info.Increase = stats.MaxIncrease
			info.Elapsed = time.Since(start)
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
	return randomEnabled(p.mm, s, p.rng), info
}

func (p *extPlanner) planAfter(from *State, a Act, to *State, b planBudget) (Act, planInfo, bool) {
	start := time.Now()
	budget := m.SearchBudget{Deadline: b.Deadline, MaxPaths: b.MaxPaths}
	if b.Stop != nil {
		budget.Stop = b.Stop
	}
	path, stats, si := p.c.BestPathWithBudget(p.mm.forced1(from, a, to), from, p.depth+1, budget)
	info := planInfo{Depth: si.Depth - 1, Paths: si.Paths, Elapsed: time.Since(start)}
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
