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

// NodeMem is a named map type representing memory amount or usage per
// NUMA node. As a map, nil is a valid zero value for read-only use;
// use NewNodeMem() to create a writable instance.
type NodeMem map[int]int64

func NewNodeMem() NodeMem {
	return make(NodeMem)
}

// Mem returns the memory amount for the given node.
func (nm NodeMem) Mem(node int) int64 {
	return nm[node]
}

func (nm NodeMem) TotalMem() int64 {
	var s int64
	for _, v := range nm {
		s += v
	}
	return s
}

func (nm NodeMem) Copy() NodeMem {
	if nm == nil {
		return nil
	}
	newNodeMem := make(NodeMem, len(nm))
	maps.Copy(newNodeMem, nm)
	return newNodeMem
}

type Waypoint struct {
	Name  string
	Usage NodeMem
}

type Plan struct {
	// Plan is a sequence of waypoints. Each waypoint specifies
	// target memory usage per node when total memory usage equals
	// the sum of memory usages in the waypoint.
	//
	// Waypoints direct only memory allocations, never freeing or
	// moving memory.  Therefore, between any two waypoints wpi
	// and wpj, if i<j then wpi.Usage[n] <= wpj.Usage[n] for any
	// node n. In other words, memory usage can only grow in next
	// waypoints for each node.
	Waypoints []Waypoint
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
	// If nil, then all nodes are allowed with unlimited usage.
	AllowedUsage NodeMem
}

type Trackpoint struct {
	Usage NodeMem
	Time  int64
}

type Planner struct {
	// plan is the current plan being followed.
	plan *Plan
	// track is a history of observed memory usage per node, with timestamps.
	// The last element is the most recent trackpoint, representing the
	// current memory usage.
	track []Trackpoint
	// nextWaypointIndex is the index of the waypoint in the plan.
	// While Waypoints is the "master plan", nextWaypointIndex is
	// the next step.
	nextWaypointIndex int
	// nextNodes is the set of nodes from which new memory
	// allocations are allowed in the current plan, when
	// navigating towards the next waypoint.
	nextNodes []int
	// nextLimit (in bytes) specifies the next checkpoint, in case
	// of increased memory consumption, where the plan should be
	// updated.
	nextLimit int64
}

// NewPlanner creates a new Planner with the given plan.
func NewPlanner() *Planner {
	return &Planner{}
}

// SetPlan sets the plan for the planner and resets the track and next step.
func (p *Planner) SetPlan(plan *Plan) {
	p.plan = plan
	p.track = nil
	p.nextWaypointIndex = -1
	p.nextNodes = nil
	p.nextLimit = 0
}

// UpdateUsage updates the current memory usage in the planner.
func (p *Planner) UpdateUsage(usage NodeMem) {
	p.track = append(p.track, Trackpoint{
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
//   - ctp: current trackpoint (most recent observed memory usage per
//     node).  If ctp is nil, it is treated as an all-zeroes
//     trackpoint (zero usage on all nodes).
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
func nextStep(ctp, pwp, nwp NodeMem, minLimit, maxLimit int64) (nextNodes []int, nextLimit int64, err error) {
	if ctp == nil || pwp == nil || nwp == nil {
		return nil, 0, fmt.Errorf("nextStep: nil input")
	}

	// Gather all node IDs present in any of the three NodeMems.
	nodeSet := make(map[int]bool)
	for n := range ctp {
		nodeSet[n] = true
	}
	for n := range pwp {
		nodeSet[n] = true
	}
	for n := range nwp {
		nodeSet[n] = true
	}

	// Validate: nwp[n] >= pwp[n] for all nodes.
	for n := range nodeSet {
		if nwp[n] < pwp[n] {
			return nil, 0, fmt.Errorf("nextStep: nwp[%d]=%d < pwp[%d]=%d: waypoints must be non-decreasing",
				n, nwp[n], n, pwp[n])
		}
	}

	// Precompute v = nwp − pwp, c = ctp − pwp, and their dot products.
	v := make(map[int]float64, len(nodeSet))
	c := make(map[int]float64, len(nodeSet))
	var vDotV, cDotV, cDotC float64
	for n := range nodeSet {
		v[n] = float64(nwp[n] - pwp[n])
		c[n] = float64(ctp[n] - pwp[n])
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
		g := nwp[n] - ctp[n]
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

// waypointReached reports whether the current memory usage has
// reached the given waypoint. The waypoint is considered reached if
// any node's usage strictly exceeds the waypoint target, or if the
// remaining gap across all lagging nodes is less than minLimit (so
// the next step cannot fit without overshooting).
func waypointReached(ctp, wpUsage NodeMem, minLimit int64) bool {
	var remainingGap int64
	for n, target := range wpUsage {
		if ctp[n] > target {
			return true
		}
		remainingGap += target - ctp[n]
	}
	return remainingGap < minLimit
}

// extrapolateWaypoint generates a waypoint beyond the current usage
// by extending the direction from prev to last. The returned waypoint
// is far enough ahead of ctp that nextStep can take a full maxLimit
// step forward on every node with a positive direction component
// without exceeding the waypoint.
func extrapolateWaypoint(prev, last, ctp NodeMem, maxLimit int64) NodeMem {
	nwp := NewNodeMem()

	nodeSet := make(map[int]bool)
	for n := range prev {
		nodeSet[n] = true
	}
	for n := range last {
		nodeSet[n] = true
	}
	for n := range ctp {
		nodeSet[n] = true
	}

	// Direction vector: d[n] = last[n] − prev[n].
	// Find the smallest integer multiplier t ≥ 1 such that
	// last[n] + t·d[n] ≥ ctp[n] + maxLimit for every node
	// where d[n] > 0. This guarantees the gap nwp[n] − ctp[n]
	// is at least maxLimit, so nextStep can take a full
	// MaxLimit-sized step without re-steering.
	t := int64(1)
	for n := range nodeSet {
		d := last[n] - prev[n]
		if d > 0 {
			needed := ctp[n] + maxLimit - last[n]
			if needed > 0 {
				tNeeded := (needed + d - 1) / d // ceiling division
				if tNeeded > t {
					t = tNeeded
				}
			}
		}
	}

	for n := range nodeSet {
		d := last[n] - prev[n]
		nwp[n] = last[n] + t*d
	}

	return nwp
}

// UpdateRoute updates the nextNodes and nextLimit based on the
// current memory usage and plan.
func (p *Planner) UpdateRoute() error {
	if p.plan == nil {
		return fmt.Errorf("UpdateRoute: no plan set")
	}
	if len(p.plan.Waypoints) == 0 {
		return fmt.Errorf("UpdateRoute: plan has no waypoints")
	}
	if p.plan.MinLimit <= 0 {
		return fmt.Errorf("UpdateRoute: MinLimit must be positive, got %d", p.plan.MinLimit)
	}
	if p.plan.MaxLimit <= 0 {
		return fmt.Errorf("UpdateRoute: MaxLimit must be positive, got %d", p.plan.MaxLimit)
	}
	if p.plan.MaxLimit < p.plan.MinLimit {
		return fmt.Errorf("UpdateRoute: MaxLimit (%d) must be >= MinLimit (%d)", p.plan.MaxLimit, p.plan.MinLimit)
	}

	// 1. Get the current trackpoint (ctp).
	var ctp NodeMem
	if len(p.track) > 0 {
		ctp = p.track[len(p.track)-1].Usage
	} else {
		ctp = NewNodeMem()
	}

	// Find the next waypoint (nwp): the first waypoint whose usage
	// has not been reached on every node yet. Start from the cached
	// nextWaypointIndex for efficiency, scanning backward first in
	// case memory was freed, then forward past reached waypoints.
	nwpIdx := max(p.nextWaypointIndex, 0)
	nwpIdx = min(nwpIdx, len(p.plan.Waypoints))
	minDistToWp := p.plan.MinLimit
	for nwpIdx > 0 && !waypointReached(ctp, p.plan.Waypoints[nwpIdx-1].Usage, minDistToWp) {
		nwpIdx--
	}
	for nwpIdx < len(p.plan.Waypoints) && waypointReached(ctp, p.plan.Waypoints[nwpIdx].Usage, minDistToWp) {
		nwpIdx++
	}

	var pwp, nwp NodeMem

	if nwpIdx >= len(p.plan.Waypoints) {
		// All waypoints have been exceeded. Extrapolate a new
		// waypoint by continuing in the direction of the last
		// segment.
		lastIdx := len(p.plan.Waypoints) - 1
		var prevUsage NodeMem
		if lastIdx > 0 {
			prevUsage = p.plan.Waypoints[lastIdx-1].Usage
		} else {
			prevUsage = NewNodeMem()
		}
		pwp = p.plan.Waypoints[lastIdx].Usage
		nwp = extrapolateWaypoint(prevUsage, pwp, ctp, p.plan.MaxLimit)
	} else {
		nwp = p.plan.Waypoints[nwpIdx].Usage
		if nwpIdx > 0 {
			pwp = p.plan.Waypoints[nwpIdx-1].Usage
		} else {
			pwp = NewNodeMem()
		}
	}

	p.nextWaypointIndex = nwpIdx

	// 2. Calculate the next step.
	nextNodes, nextLimit, err := nextStep(ctp, pwp, nwp, p.plan.MinLimit, p.plan.MaxLimit)
	if err != nil {
		return fmt.Errorf("UpdateRoute: %w", err)
	}

	// 3. Store the results.
	p.nextNodes = nextNodes
	p.nextLimit = nextLimit

	return nil
}

func (p *Planner) String() string {
	return fmt.Sprintf("Plan: %+v, Track: %+v, NextWaypointIndex: %d, nextNodes: %+v, nextLimit: %d",
		p.plan, p.track, p.nextWaypointIndex, p.nextNodes, p.nextLimit)
}

func (p *Planner) Usage() NodeMem {
	if len(p.track) == 0 {
		return nil
	}
	return p.track[len(p.track)-1].Usage
}

func (p *Planner) NextNodes() []int {
	return p.nextNodes
}

func (p *Planner) NextLimit() int64 {
	return p.nextLimit
}

func (p *Planner) NextWaypoint() *Waypoint {
	if p.plan == nil || p.nextWaypointIndex < 0 || p.nextWaypointIndex >= len(p.plan.Waypoints) {
		return nil
	}
	return &(p.plan.Waypoints[p.nextWaypointIndex])
}
