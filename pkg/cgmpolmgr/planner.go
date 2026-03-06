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

package cgmpolmgr

import (
	"fmt"
	"maps"
	"math"
	"math/bits"
	"sort"
	"time"
)

type NodeMem struct {
	nodeMem map[int]int64 // Memory usage on each node
}

func NewNodeMem() *NodeMem {
	return &NodeMem{make(map[int]int64)}
}

func (nm *NodeMem) Copy() *NodeMem {
	newNodeMem := make(map[int]int64)
	maps.Copy(newNodeMem, nm.nodeMem)
	return &NodeMem{nodeMem: newNodeMem}
}

type Waypoint struct {
	Usage *NodeMem
}

type Plan struct {
	// Plan is a sequence of waypoints. Each waypoint specifies
	// memory usage on every allowed node at the point where total
	// memory usage equals the sum of memory usages in the nodes.
	//
	// Between any two waypoints wpi and wpj, if i<j then memory
	// usage of any node n in wpi never exceeds memory usage of
	// the the same node n in wpj. In other words, memory usage
	// can only grow in next waypoints for each node.
	Waypoints []Waypoint
	// NextWaypointIndex is the index of the waypoint in the plan.
	// While Waypoints is the "master plan", NextWaypointIndex is
	// the next step.
	NextWaypointIndex int
	// Nodes is the set of nodes from which new memory allocations
	// are allowed in the current plan, on the way to the next
	// waypoint.
	NextNodes []int
	// NextLimit (in bytes) specifies the next checkpoint, in case
	// of increased memory consumption, where the plan should be
	// updated.
	NextLimit int64
}

type Trackpoint struct {
	Usage *NodeMem
	Time  int64
}

type Planner struct {
	Plan  *Plan
	Track []Trackpoint
	// MinLimit (bytes) is the minimum future memory allocation after which
	// memory allocations are throttled in order to update the plan.
	MinLimit int64
	// MaxLimit (bytes) is the maximum future memory allocations after which
	// memory allocations must be throttled and plan updated.
	MaxLimit int64
	// AllowedUsage specifies if memory usage on each node is allowed
	// and if it is limited.
	// -1: unlimited usage
	// 0: node unavailable
	// positive value: usage limit in bytes.
	AllowedUsage *NodeMem
}

// NewPlanner creates a new Planner with the given plan.
func NewPlanner() *Planner {
	return &Planner{
		AllowedUsage: NewNodeMem(),
		MinLimit:     100 * 1024 * 1024,      // Default to 100 Mi
		MaxLimit:     1 * 1024 * 1024 * 1024, // Default to 1 Gi
	}
}

// UpdateUsage updates the current memory usage in the planner.
func (p *Planner) UpdateUsage(usage *NodeMem) {
	p.Track = append(p.Track, Trackpoint{
		Usage: usage.Copy(),
		Time:  time.Now().UnixNano(),
	})
}

// nextStep calculates the next allocation nodes (nextNodes) and limit
// (nextLimit) to steer memory usage from the current trackpoint (ctp)
// toward the next waypoint (nwp), or towards the route from the
// previous waypoint (pwp) to nwp if ctp is off the track.
//
// Parameters:
//
//   - ctp: current trackpoint (most recent observed memory usage per node)
//
//   - pwp: previous waypoint (last waypoint whose usage has been reached,
//     or will be reached no matter how minLimit of memory is spread to nextNodes)
//
//   - nwp: next waypoint (first waypoint whose usage has not yet been reached
//     and will not be reached no matter how minLimit of memory is spread to nextNodes)
//
//   - minLimit: minimum value for the returned nextLimit
//
//   - maxLimit: maximum value for the returned nextLimit
//
// Returns:
//
//   - nextNodes: the nodes where future memory usage will be spread.
//     The increase in the usage is assumed to be distributed equally among
//     all the nodes in nextNodes, and equal to zero on all other nodes.
//
//   - nextLimit: total memory usage (bytes), clamped to [minLimit, maxLimit]
//     at which the plan should be re-evaluated.
//
//   - err: error if any of the parameters are invalid.
//
//     Total memory usage increase expected to be spread on nextNodes
//     is the difference between nextLimit and total memory usage at
//     ctp.
//
//     If no memory has been freed while memory usage has increased up to
//     nextLimit, it is guaranteed that memory usage on any of nextNodes
//     has not exceeded the usage in nwp, while it is possible that one
//     or more of nextNodes has reached the usage in nwp.
func nextStep(ctp, pwp, nwp *NodeMem, minLimit, maxLimit int64) (nextNodes []int, nextLimit int64, err error) {
	if ctp == nil || pwp == nil || nwp == nil {
		return nil, 0, fmt.Errorf("nextStep: nil input")
	}

	// Gather all node IDs present in any of the three NodeMems.
	nodeSet := make(map[int]bool)
	for n := range ctp.nodeMem {
		nodeSet[n] = true
	}
	for n := range pwp.nodeMem {
		nodeSet[n] = true
	}
	for n := range nwp.nodeMem {
		nodeSet[n] = true
	}

	// Validate: nwp[n] >= pwp[n] for all nodes.
	for n := range nodeSet {
		if nwp.nodeMem[n] < pwp.nodeMem[n] {
			return nil, 0, fmt.Errorf("nextStep: nwp[%d]=%d < pwp[%d]=%d: waypoints must be non-decreasing",
				n, nwp.nodeMem[n], n, pwp.nodeMem[n])
		}
	}

	// Precompute v = nwp − pwp, c = ctp − pwp, and their dot products.
	v := make(map[int]float64, len(nodeSet))
	c := make(map[int]float64, len(nodeSet))
	var vDotV, cDotV, cDotC float64
	for n := range nodeSet {
		v[n] = float64(nwp.nodeMem[n] - pwp.nodeMem[n])
		c[n] = float64(ctp.nodeMem[n] - pwp.nodeMem[n])
		vDotV += v[n] * v[n]
		cDotV += c[n] * v[n]
		cDotC += c[n] * c[n]
	}

	// Compute gap[n] = max(0, nwp[n] - ctp[n]) for each node.
	// Nodes with gap > 0 are "lagging" and are candidates for allocation.
	type nodeGap struct {
		node int
		gap  int64
	}
	var lagging []nodeGap
	for n := range nodeSet {
		g := nwp.nodeMem[n] - ctp.nodeMem[n]
		if g > 0 {
			lagging = append(lagging, nodeGap{n, g})
		}
	}
	// Sort: nodes with largest gap in the beginning.
	sort.Slice(lagging, func(i, j int) bool {
		return lagging[i].gap > lagging[j].gap
	})

	// Minimize the number of lagging nodes by removing nodes that
	// cannot fit minLimit even if it would be shared among all
	// remaining lagging nodes.
	//
	// With k lagging nodes and equal distribution, each gets at
	// least minLimit/k bytes. If the smallest gap < minLimit/k
	// (equivalently k*gap < minLimit), that node would exceed nwp
	// in any subset of size k. Since it also can't help in any
	// smaller subset (perNode would only grow), it's safe to drop.
	for len(lagging) > 0 {
		k := int64(len(lagging))
		if k*lagging[len(lagging)-1].gap >= minLimit {
			break
		}
		lagging = lagging[:len(lagging)-1]
	}

	if len(lagging) == 0 {
		return nil, 0, nil
	}

	// Enumerate all non-empty subsets of lagging nodes. For each
	// subset (mask / direction), find the total limit that brings
	// ctp closest to the pwp→nwp line, clamp it to [minLimit,
	// min(maxLimit, s·minGap)], and pick the mask with the
	// smallest squared distance.
	k := len(lagging)
	bestSE := math.MaxFloat64
	bestCount := 0
	var bestNodes uint64
	var bestLimit int64

	for mask := uint64(1); mask < (1 << k); mask++ {
		var nodesInMask uint64
		minGap := int64(math.MaxInt64)
		numNodes := int64(0)
		var sumC, sumV float64
		for i := 0; i < k; i++ {
			if mask&(1<<i) != 0 {
				n := lagging[i].node
				nodesInMask |= 1 << uint(n)
				numNodes++
				if lagging[i].gap < minGap {
					minGap = lagging[i].gap
				}
				sumC += c[n]
				sumV += v[n]
			}
		}

		// Feasible total-limit range.
		lower := minLimit
		upper := min(maxLimit, numNodes*minGap)
		if lower > upper {
			continue
		}

		// Optimal total limit in this direction: the limit L hat minimizes
		// squared distance from (ctp + L/s on selected) to line(pwp, nwp).
		fnumNodes := float64(numNodes)
		denom := fnumNodes*vDotV - sumV*sumV
		var optLimit float64
		if math.Abs(denom) > 1e-6 {
			optLimit = fnumNodes * (cDotV*sumV - sumC*vDotV) / denom
		} else {
			optLimit = float64(lower)
		}

		// Clamp to feasible range.
		limit := int64(math.Round(math.Max(float64(lower), math.Min(optLimit, float64(upper)))))
		// if limit < lower {
		// 	limit = lower
		// }
		// if limit > upper {
		// 	limit = upper
		// }

		// Squared distance from (ctp + limit/nodes on selected) to
		// line(pwp, nwp): |q|² − (q·v)²/|v|²
		// where q[n] = c[n] + limit/s (selected) or c[n].
		perNode := float64(limit) / fnumNodes
		qDotQ := cDotC + 2*perNode*sumC + fnumNodes*perNode*perNode
		qDotV := cDotV + perNode*sumV
		se := qDotQ
		if vDotV > 0 {
			se -= qDotV * qDotV / vDotV
		}

		count := int(numNodes)
		if se < bestSE || (se == bestSE && count > bestCount) {
			bestSE = se
			bestCount = count
			bestNodes = nodesInMask
			bestLimit = limit
		}
	}

	if bestNodes == 0 {
		return nil, 0, fmt.Errorf("nextStep: no feasible allocation within [%d, %d]", minLimit, maxLimit)
	}

	var resultNodes []int
	for nodeBit := 0; nodeBit < bits.Len64(bestNodes); nodeBit++ {
		if bestNodes&(1<<uint(nodeBit)) != 0 {
			resultNodes = append(resultNodes, nodeBit)
		}
	}
	return resultNodes, bestLimit, nil
}

func (p *Planner) UpdatePlan() {
	// The algorithm is as follows:
	//
	// 1. Find out previous and next waypoints based on current memory usage.
	//    - Previous waypoint (pwp) is the last waypoint in the plan whose memory
	//      usage has been reached or exceeded.
	//    - Next waypoint (nwp) is the first waypoint in the plan whose memory
	//      usage has not been reached yet.
	//    - p.Plan.NextWaypointIndex is likely to make this quick, given that
	//      usage has not changed much.
	//    - Update p.Plan.NextWaypointIndex accordingly, if necessary.
	//
	// 2. Calculate linear route from pwp to nwp.
	//    - What is the target ratio of memory usage from each of the nodes
	//      where memory usage increases between pwp and nwp?
	//    - Example: if there are two nodes, x and y, then pwp and nwp can be
	//      drawn as two points in xy-coordinates, and the route as the direct
	//      line connecting these points.
	//
	// 3. Calculate linear route from current trackpoint ctp to nwp.
	//    - Current trackpoint is the last (most recent) usage point in
	//      p.Track, that is, ctp=p.Track(len(p.Track)-1).
	//    - Similar calculation as from pwp to nwp.
	//
	// 4. Compare these two routes to find out course correction.
	//    - Example: consider two memory nodes, x and y.
	//      1. If the slope is of pwp-nwp line is steeper than ctp-nwp,
	//      then ctp is "to the left" or "on top of" the optimal pwp-nwp line,
	//      and next allocations should increase consumption only on node x
	//      until crossing pwp-nwp line.
	//      2. If pwp-nwp slope is flatter than ctp-nwp slope,
	//      then ctp is "to the right" or "below" the optimal pwp-nwp line,
	//      and next allocations should increase consumption only on node y
	//      until crossing pwp-nwp line.
	//      3. If the slopes are equivalent, the usage is on optimal track between
	//      waypoints, so keep target
	//    - Based on nodes where memory usage should be increased in order to
	//      get back to planned route (cases 1 and 2), or keep on track (case 3)
	//      calculate the best set of nodes in NextNodes. If there are multiple
	//      NextNodes, then expect equal amount of increased usage in all of them.
	//      If there is only one node in NextNodes, then expect memory usage to
	//      increase only on that node.
	//      The combination of NextNodes and NextLimit (that must be equal or
	//      between MinLimit and MaxLimit) should result in minimal square error
	//      from the optimal pwp-nwp route.
}
