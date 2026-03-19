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

// cgmpolmgr package implements a dynamic memory policy manager for
// cgroups. It takes cgroup-specific "memory ladders" as an input. The
// ladders specify memory usage ranges and a memory policy to be
// applied on all processes in the cgroup when usage is in that range.

package cgmpolmgr

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	MiB int64 = 1024 * 1024
	GiB       = 1024 * MiB
)

// nm constructs a NodeMem from a usage list for use in tests.
// The index in the list is the node number and the value is its usage.
func nm(usage ...int64) *NodeMem {
	m := make(map[int]int64, len(usage))
	for node, u := range usage {
		m[node] = u
	}
	return &NodeMem{nodeMem: m}
}

func TestNextStepSteeringTowardsPath(t *testing.T) {
	//node1
	//   △ ctpY                     nwp
	//80Gx╴                      ╭───x
	//   │        ctpB      3──4─╯
	//  7├╴        x   ╭─1─2╯      x
	//   │  pwp   ╭────╯ctpL      ctpC
	//  6├╴  x────╯
	//   │
	//  5├╴
	//   │
	//  4├╴  x
	//   │  ctpA
	//  3├╴
	//   │
	//  2├╴
	//   │
	//  1├╴
	//   │ ╷ ╷ ╷ ╷ ╷ ╷ ╷ ╷ ╷ ╷ ╷ ╷ ╷ctpX
	//   ╰─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─x▷ node0
	//     1 2 3 4 5 6 7 8 910111213140G
	pwp := nm(20*GiB, 60*GiB)
	nwp := nm(140*GiB, 80*GiB)

	tcases := []struct {
		name         string
		ctp          *NodeMem
		minLimit     int64
		maxLimit     int64
		nextNodes    []int
		nextLimit    int64
		nextLimitMax int64
	}{
		{
			name:      "ctpA-1-2: small step towards pwp",
			ctp:       nm(20*GiB+1, 40*GiB),
			minLimit:  1 * GiB,
			maxLimit:  2 * GiB,
			nextNodes: []int{1},
			nextLimit: 2 * GiB,
		},
		{
			name:      "ctpA-1-20: practically catch pwp",
			ctp:       nm(20*GiB+1, 40*GiB),
			minLimit:  1 * GiB,
			maxLimit:  20 * GiB,
			nextNodes: []int{1},
			nextLimit: 20 * GiB,
		},
		{
			name:         "ctpA-30-100: catch line between pwp and nwp",
			ctp:          nm(20*GiB+1, 40*GiB),
			minLimit:     30 * GiB,
			maxLimit:     100 * GiB,
			nextNodes:    []int{0, 1},
			nextLimit:    35 * GiB,
			nextLimitMax: 55 * GiB,
		},
		{
			name:      "ctpB-1-1: small step towards line between pwp and nwp",
			ctp:       nm(50*GiB, 70*GiB),
			minLimit:  1 * GiB,
			maxLimit:  1 * GiB,
			nextNodes: []int{0},
			nextLimit: 1 * GiB,
		},
		{
			name:         "ctpB-1-100: catch line between pwp and nwp",
			ctp:          nm(50*GiB, 70*GiB),
			minLimit:     1 * GiB,
			maxLimit:     100 * GiB,
			nextNodes:    []int{0},
			nextLimit:    28 * GiB,
			nextLimitMax: 32 * GiB,
		},
		{
			name:      "ctpC-1-1: small step towards line between pwp and nwp",
			ctp:       nm(130*GiB, 70*GiB),
			minLimit:  1 * GiB,
			maxLimit:  1 * GiB,
			nextNodes: []int{1},
			nextLimit: 1 * GiB,
		},
		{
			name:         "ctpC-1-10: just reach the line between pwp and nwp",
			ctp:          nm(130*GiB, 70*GiB),
			minLimit:     1 * GiB,
			maxLimit:     10 * GiB,
			nextNodes:    []int{1},
			nextLimit:    8500 * MiB,
			nextLimitMax: 9500 * MiB,
		},
		{
			name:      "ctpC-1-20: hit exactly nwp on maxLimit",
			ctp:       nm(130*GiB, 70*GiB),
			minLimit:  1 * GiB,
			maxLimit:  20 * GiB,
			nextNodes: []int{0, 1},
			nextLimit: 20 * GiB,
		},
		{
			name:      "ctpC-20-20: hit exactly nwp on limit",
			ctp:       nm(130*GiB, 70*GiB),
			minLimit:  20 * GiB,
			maxLimit:  20 * GiB,
			nextNodes: []int{0, 1},
			nextLimit: 20 * GiB,
		},
		{
			name:      "ctpC-20-100: hit exactly nwp on minLimit",
			ctp:       nm(130*GiB, 70*GiB),
			minLimit:  20 * GiB,
			maxLimit:  100 * GiB,
			nextNodes: []int{0, 1},
			nextLimit: 20 * GiB,
		},
		{
			name:      "ctpL1-10-100: exactly on the line, grow x, go below the line",
			ctp:       nm(80*GiB, 70*GiB),
			minLimit:  10 * GiB,
			maxLimit:  100 * GiB,
			nextNodes: []int{0},
			nextLimit: 10 * GiB,
		},
		{
			name:      "ctpL2-10-100: continuing right below the line, grow x,y, go above the line",
			ctp:       nm(90*GiB, 70*GiB),
			minLimit:  10 * GiB,
			maxLimit:  100 * GiB,
			nextNodes: []int{0, 1},
			nextLimit: 10 * GiB,
		},
		{
			name:         "ctpL3-10-100: continuing right above the line, grow x again, find back exactly on line",
			ctp:          nm(95*GiB, 75*GiB),
			minLimit:     10 * GiB,
			maxLimit:     100 * GiB,
			nextNodes:    []int{0},
			nextLimit:    15 * GiB,
			nextLimitMax: 17 * GiB,
		},
		{
			name:      "ctpY-1-100: max step towards npw",
			ctp:       nm(0*GiB, 80*GiB),
			minLimit:  1 * GiB,
			maxLimit:  100 * GiB,
			nextNodes: []int{0},
			nextLimit: 100 * GiB,
		},
		{
			name:      "ctpY-1-200: max step to npw and no longer",
			ctp:       nm(0*GiB, 80*GiB),
			minLimit:  1 * GiB,
			maxLimit:  200 * GiB,
			nextNodes: []int{0},
			nextLimit: 140 * GiB,
		},
		{
			name:      "ctpX-1-42: max step towards npw",
			ctp:       nm(140*GiB, 0*GiB),
			minLimit:  1 * GiB,
			maxLimit:  42 * GiB,
			nextNodes: []int{1},
			nextLimit: 42 * GiB,
		},
		{
			name:      "ctpX-1-200: max step to npw and no longer",
			ctp:       nm(140*GiB, 0*GiB),
			minLimit:  1 * GiB,
			maxLimit:  200 * GiB,
			nextNodes: []int{1},
			nextLimit: 80 * GiB,
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			nextNodes, nextLimit, err := nextStep(tc.ctp, pwp, nwp, tc.minLimit, tc.maxLimit)
			t.Logf("%s: nextNodes: %v, nextLimit: %.3f GiB", tc.name, nextNodes, float64(nextLimit)/float64(GiB))
			require.Equal(t, tc.nextNodes, nextNodes)
			if tc.nextLimitMax != 0 {
				require.GreaterOrEqual(t, nextLimit, tc.nextLimit)
				require.LessOrEqual(t, nextLimit, tc.nextLimitMax)
			} else {
				require.Equal(t, tc.nextLimit, nextLimit)
			}
			require.Equal(t, nil, err)
		})
	}
}

func TestInterestingNextSteps(t *testing.T) {
	t.Run("all-in one lagging node", func(t *testing.T) {
		// n0: pwp→nwp increase, ctp→nwp flat already there
		// n1: pwp→nwp flat, ctp→nwp a lot behind (n1 needs to grow)
		// n2: pwp→nwp flat, ctp→nwp flat
		// n3: pwp→nwp big increase, ctp→nwp tiny increase (n3 has no urgency to grow)
		pwp := nm(00*GiB, 10*GiB, 20*GiB, 0*GiB)
		nwp := nm(10*GiB, 10*GiB, 20*GiB, 30*GiB)
		ctp := nm(10*GiB, 7*GiB, 20*GiB, 29*GiB)
		nextNodes, nextLimit, err := nextStep(ctp, pwp, nwp, 1*GiB, 4*GiB)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		require.Equal(t, nextNodes, []int{1}, "nextNodes should increase usage only on node1")
		require.Equal(t, nextLimit, 3*GiB)

	})

	t.Run("split on two lagging nodes", func(t *testing.T) {
		// n0: pwp→nwp increase, ctp→nwp flat already there
		// n1: pwp→nwp flat, ctp→nwp a lot behind (n1 needs to grow)
		// n2: pwp→nwp flat, ctp→nwp flat
		// n3: pwp→nwp big increase, ctp→nwp tiny increase (n3 has no urgency to grow)
		pwp := nm(00*GiB, 10*GiB, 20*GiB, 0*GiB)
		nwp := nm(10*GiB, 10*GiB, 20*GiB, 30*GiB)
		ctp := nm(10*GiB, 8*GiB, 20*GiB, 29*GiB)
		nextNodes, nextLimit, err := nextStep(ctp, pwp, nwp, 1*GiB, 4*GiB)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// Node 1 alone gets closest to the pwp→nwp line.
		require.Equal(t, nextNodes, []int{1}, "nextNodes should increase usage only on node1 to get closest to pwp-nwp line")
		require.Equal(t, nextLimit, 2*GiB)

	})

	t.Run("join to optimal pwp-nwp track rather than minimize square error to nwp", func(t *testing.T) {
		// n0: pwp→nwp increase, ctp→nwp flat already there
		// n1: pwp→nwp flat, ctp→nwp a lot behind (n1 needs to grow)
		// n2: pwp→nwp flat, ctp→nwp flat
		// n3: pwp→nwp big increase, ctp→nwp tiny increase (n3 has no urgency to grow)
		pwp := nm(0, 2, 6, 0)
		nwp := nm(0, 14, 8, 0)
		ctp := nm(0, 6, 4, 0)
		nextNodes, nextLimit, err := nextStep(ctp, pwp, nwp, 1, 2)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		require.Equal(t, nextNodes, []int{2}, "nextNodes should prefer pwp-nwp path over directly reaching nwp")
		require.Equal(t, nextLimit, int64(2))
	})
}

func TestPlannerFollow(t *testing.T) {
	plan := &Plan{
		Waypoints: []Waypoint{
			{Usage: nm(0*GiB, 2*GiB, 0*GiB, 5*GiB)},
			{Usage: nm(1*GiB, 3*GiB, 1*GiB, 5*GiB)},
			{Usage: nm(2*GiB, 10*GiB, 2*GiB, 5*GiB)},
			{Usage: nm(2*GiB, 12*GiB, 10*GiB, 5*GiB)},
		},
		MinLimit: 1 * GiB,
		MaxLimit: 4 * GiB,
	}

	p := NewPlanner()
	p.SetPlan(plan)

	// Current simulated usage, starts at zero.
	cur := nm(0, 0, 0, 0)

	// Run the simulation loop. We stop after going two full
	// UpdateRoute rounds beyond the last waypoint.
	lastWP := plan.Waypoints[len(plan.Waypoints)-1].Usage
	lastWPTotal := lastWP.TotalMem()
	roundsBeyond := 0
	maxIter := 200
	for i := 0; i < maxIter; i++ {
		err := p.UpdateRoute()
		require.NoError(t, err, "UpdateRoute iteration %d", i)

		nextNodes := p.NextNodes()
		nextLimit := p.NextLimit()

		t.Logf("iter %3d: cur=(%d,%d,%d,%d) GiB  nextNodes=%v  nextLimit=%.1f GiB",
			i,
			cur.nodeMem[0]/GiB, cur.nodeMem[1]/GiB,
			cur.nodeMem[2]/GiB, cur.nodeMem[3]/GiB,
			nextNodes,
			float64(nextLimit)/float64(GiB))

		if nextNodes == nil {
			t.Logf("iter %3d: nextNodes is nil, stopping", i)
			break
		}

		require.Greater(t, nextLimit, int64(0),
			"nextLimit must be positive at iteration %d", i)
		require.GreaterOrEqual(t, nextLimit, plan.MinLimit,
			"nextLimit must be >= MinLimit at iteration %d", i)
		require.LessOrEqual(t, nextLimit, plan.MaxLimit,
			"nextLimit must be <= MaxLimit at iteration %d", i)

		// Simulate: spread nextLimit evenly on nextNodes.
		perNode := nextLimit / int64(len(nextNodes))
		for _, n := range nextNodes {
			cur.nodeMem[n] += perNode
		}

		p.UpdateUsage(cur)

		if cur.TotalMem() > lastWPTotal {
			roundsBeyond++
			if roundsBeyond >= 2 {
				t.Logf("iter %3d: two rounds beyond last waypoint, done", i)
				break
			}
		}
	}

	// Verify: every node's usage should be at least the last
	// waypoint's value (with a tolerance of MaxLimit, since
	// steering is approximate and we may overshoot on some
	// nodes while lagging on others).
	for n, target := range lastWP.nodeMem {
		require.InDelta(t, target, cur.nodeMem[n], float64(plan.MaxLimit),
			"node %d usage should be close to last waypoint target", n)
	}

	// Verify: we actually went beyond the last waypoint's total.
	require.Greater(t, cur.TotalMem(), lastWPTotal,
		"total usage should exceed the last waypoint total")
}
