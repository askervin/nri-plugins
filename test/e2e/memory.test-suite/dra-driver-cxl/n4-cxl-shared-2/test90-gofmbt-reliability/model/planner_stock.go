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

//go:build gofmbtstock

package main

// The planner on stock gofmbt (the version in go.mod, no go.work): C1
// and C3 only, no budget (the search always completes the depth), a new
// coverage round is a new Coverer. For the comparison of P4 and for
// building without the local gofmbt checkout.

import (
	"fmt"
	"math/rand"
	"time"

	m "github.com/askervin/gofmbt/gofmbt"
)

const gofmbtFlavor = "stock"

type stockPlanner struct {
	mm         *mbtModel
	cov        Coverage
	c          *m.Coverer
	depth      int
	seed       int64
	randomness int
	rng        *rand.Rand
	nRound     int
}

func newPlanner(mm *mbtModel, cov Coverage, depth int, seed int64, randomness int) (planner, error) {
	if cov.on(2) || cov.on(4) || cov.weighted() {
		return nil, fmt.Errorf("coverage %s: C2, C4 and weights need the extended gofmbt (build without -tags gofmbtstock, with a go.work to the 5jo-mbt-cxl branch)", cov)
	}
	p := &stockPlanner{mm: mm, cov: cov, depth: depth, seed: seed, randomness: randomness, rng: rand.New(rand.NewSource(seed))}
	p.newRound()
	return p, nil
}

func (p *stockPlanner) newRound() {
	p.c = m.NewCoverer()
	if p.cov.on(1) {
		p.c.CoverActions()
	}
	if p.cov.on(3) {
		p.c.CoverActionFormatCombinations(2)
	}
	if p.randomness > 0 {
		p.c.SetBestPathRandom(p.seed+int64(p.nRound), p.randomness)
	}
	p.nRound++
}

func (p *stockPlanner) plan(s *State, b planBudget) (Act, planInfo) {
	start := time.Now()
	info := planInfo{Depth: p.depth}
	for attempt := 0; attempt < 2; attempt++ {
		path, stats := p.c.BestPath(p.mm, s, p.depth)
		if len(path) > 0 {
			info.Increase = stats.MaxIncrease
			info.Elapsed = time.Since(start)
			return p.mm.acts[p.mm.byAction[path[0].Action()]], info
		}
		if attempt == 0 {
			p.newRound()
			info.Reset = true
		}
	}
	info.Random = true
	info.Elapsed = time.Since(start)
	return randomEnabled(p.mm, s, p.rng), info
}

func (p *stockPlanner) planAfter(from *State, a Act, to *State, b planBudget) (Act, planInfo, bool) {
	start := time.Now()
	path, stats := p.c.BestPath(p.mm.forced1(from, a, to), from, p.depth+1)
	info := planInfo{Depth: p.depth, Elapsed: time.Since(start)}
	if len(path) < 2 {
		return Act{}, info, false
	}
	info.Increase = stats.MaxIncrease
	return p.mm.acts[p.mm.byAction[path[1].Action()]], info, true
}

func (p *stockPlanner) mark(from *State, a Act, to *State) {
	i, ok := p.mm.byAct[a]
	if !ok {
		return
	}
	p.c.MarkCovered(m.NewStep(from, p.mm.actions[i], to))
	p.c.UpdateCoverage()
}

func (p *stockPlanner) coverage() int { return p.c.Coverage() }

func (p *stockPlanner) rounds() int { return p.nRound }
