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
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
)

// MemoryUseOrder is the order in which DRAM and CXL quotas are consumed.
type MemoryUseOrder int

const (
	// MemoryUseFirstDRAM consumes the DRAM quota first, then CXL.
	MemoryUseFirstDRAM MemoryUseOrder = iota
	// MemoryUseFirstCXL consumes the CXL quota first, then DRAM.
	MemoryUseFirstCXL
	// MemoryUseStartInterleaved interleaves DRAM and CXL until the
	// smaller quota is used, then consumes the rest of the other.
	MemoryUseStartInterleaved
	// MemoryUseEndInterleaved consumes the excess of the larger
	// quota first, then interleaves DRAM and CXL.
	MemoryUseEndInterleaved
	// MemoryUseWaypoints follows user-specified waypoints.
	MemoryUseWaypoints
)

var memoryUseOrderNames = map[MemoryUseOrder]string{
	MemoryUseFirstDRAM:        "first-dram",
	MemoryUseFirstCXL:         "first-cxl",
	MemoryUseStartInterleaved: "start-interleaved",
	MemoryUseEndInterleaved:   "end-interleaved",
	MemoryUseWaypoints:        "waypoints",
}

// ParseMemoryUseOrder returns the MemoryUseOrder named by s. Names
// are matched without regard to case.
func ParseMemoryUseOrder(s string) (MemoryUseOrder, error) {
	name := strings.ToLower(strings.TrimSpace(s))
	for order, orderName := range memoryUseOrderNames {
		if name == orderName {
			return order, nil
		}
	}
	return 0, fmt.Errorf("unknown memory use order %q (valid: first-dram, first-cxl, start-interleaved, end-interleaved, waypoints)", s)
}

// String returns the name of the order.
func (o MemoryUseOrder) String() string {
	if name, ok := memoryUseOrderNames[o]; ok {
		return name
	}
	return fmt.Sprintf("MemoryUseOrder(%d)", int(o))
}

// MemoryUseWaypointEntry is the target usage of one memory type in a
// waypoint. MemoryType is "DRAM" or "CXL" and Usage is a memory size
// such as "20Gi".
type MemoryUseWaypointEntry struct {
	MemoryType string `json:"memoryType" yaml:"memoryType"`
	Usage      string `json:"usage" yaml:"usage"`
}

// MemoryUseWaypoint is one waypoint of a user-specified memory use
// order. A memory type that is not listed keeps its usage from the
// previous waypoint. Usages must be non-decreasing across waypoints.
type MemoryUseWaypoint struct {
	TargetUsages []MemoryUseWaypointEntry `json:"targetUsages" yaml:"targetUsages"`
}

// Policy is the user-facing description of how DRAM and CXL quotas
// are consumed. It is JSON and YAML serializable.
type Policy struct {
	// MemoryUseOrder is a MemoryUseOrder name.
	MemoryUseOrder string `json:"memoryUseOrder" yaml:"memoryUseOrder"`
	// MemoryUseWaypoints are the waypoints of the "waypoints" order.
	MemoryUseWaypoints []MemoryUseWaypoint `json:"memoryUseWaypoints,omitempty" yaml:"memoryUseWaypoints,omitempty"`
	// MinStep is the smallest amount of new allocations after which
	// the route is re-evaluated. Defaults to MaxStep.
	MinStep string `json:"minStep,omitempty" yaml:"minStep,omitempty"`
	// MaxStep is the largest amount of new allocations after which
	// the route is re-evaluated. Defaults to the total quota.
	MaxStep string `json:"maxStep,omitempty" yaml:"maxStep,omitempty"`
}

// MemoryTypes lists the NUMA nodes and the byte quota of each memory
// type. A type with no nodes or a zero quota is absent.
type MemoryTypes struct {
	DRAMNodes []int
	CXLNodes  []int
	DRAMQuota int64
	CXLQuota  int64
}

// typeUsage is an absolute target usage per memory type.
type typeUsage struct {
	dram int64
	cxl  int64
}

// ParseMemorySize returns the number of bytes in a Kubernetes
// quantity such as "16Mi", "1G" or "1048576".
func ParseMemorySize(s string) (int64, error) {
	q, err := resource.ParseQuantity(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid memory size %q: %w", s, err)
	}
	if q.Sign() < 0 {
		return 0, fmt.Errorf("invalid memory size %q: must not be negative", s)
	}
	return q.Value(), nil
}

// Validate returns an error if the policy is not usable.
func (pol Policy) Validate() error {
	order, err := ParseMemoryUseOrder(pol.MemoryUseOrder)
	if err != nil {
		return fmt.Errorf("invalid memoryUseOrder: %w", err)
	}
	if order == MemoryUseWaypoints {
		if len(pol.MemoryUseWaypoints) == 0 {
			return fmt.Errorf("memoryUseWaypoints must be specified when memoryUseOrder is %q", pol.MemoryUseOrder)
		}
		if _, err := parseMemoryUseWaypoints(pol.MemoryUseWaypoints); err != nil {
			return fmt.Errorf("invalid memoryUseWaypoints: %w", err)
		}
	} else if len(pol.MemoryUseWaypoints) > 0 {
		return fmt.Errorf("memoryUseWaypoints must not be specified when memoryUseOrder is %q", pol.MemoryUseOrder)
	}
	minStep, err := parseStep("minStep", pol.MinStep)
	if err != nil {
		return err
	}
	maxStep, err := parseStep("maxStep", pol.MaxStep)
	if err != nil {
		return err
	}
	if minStep > 0 && maxStep > 0 && minStep > maxStep {
		return fmt.Errorf("minStep (%s) must not exceed maxStep (%s)", pol.MinStep, pol.MaxStep)
	}
	return nil
}

// Plan returns the plan that consumes the memory types according to
// the policy.
func (pol Policy) Plan(mem MemoryTypes) (*Plan, error) {
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	if err := mem.validate(); err != nil {
		return nil, err
	}
	total := mem.quota()

	maxStep, err := parseStep("maxStep", pol.MaxStep)
	if err != nil {
		return nil, err
	}
	if maxStep == 0 {
		maxStep = total
	}
	minStep, err := parseStep("minStep", pol.MinStep)
	if err != nil {
		return nil, err
	}
	if minStep == 0 {
		minStep = maxStep
	}
	maxStep = max(maxStep, minStep)

	order, _ := ParseMemoryUseOrder(pol.MemoryUseOrder)
	var waypoints []Waypoint
	if order == MemoryUseWaypoints {
		waypoints, err = userWaypoints(pol.MemoryUseWaypoints, mem)
	} else {
		waypoints, err = generateWaypoints(order, mem)
	}
	if err != nil {
		return nil, err
	}

	plan := &Plan{
		Waypoints: waypoints,
		MinStep:   minStep,
		MaxStep:   maxStep,
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return plan, nil
}

// parseStep returns the step size in bytes, or 0 for an empty string.
func parseStep(name, s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	step, err := ParseMemorySize(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	if step <= 0 {
		return 0, fmt.Errorf("invalid %s: must be positive", name)
	}
	return step, nil
}

// hasDRAM reports whether DRAM has nodes and a quota.
func (mem MemoryTypes) hasDRAM() bool {
	return len(mem.DRAMNodes) > 0 && mem.DRAMQuota > 0
}

// hasCXL reports whether CXL has nodes and a quota.
func (mem MemoryTypes) hasCXL() bool {
	return len(mem.CXLNodes) > 0 && mem.CXLQuota > 0
}

// quota returns the total quota of the present memory types.
func (mem MemoryTypes) quota() int64 {
	var total int64
	if mem.hasDRAM() {
		total += mem.DRAMQuota
	}
	if mem.hasCXL() {
		total += mem.CXLQuota
	}
	return total
}

// validate returns an error if the memory types are not usable.
func (mem MemoryTypes) validate() error {
	if mem.DRAMQuota < 0 || mem.CXLQuota < 0 {
		return fmt.Errorf("memory quotas must not be negative")
	}
	if !mem.hasDRAM() && !mem.hasCXL() {
		return fmt.Errorf("no memory type has both nodes and a quota")
	}
	seen := make(map[int]bool)
	for _, node := range append(append([]int{}, mem.DRAMNodes...), mem.CXLNodes...) {
		if node < 0 {
			return fmt.Errorf("invalid node %d", node)
		}
		if seen[node] {
			return fmt.Errorf("node %d listed more than once", node)
		}
		seen[node] = true
	}
	return nil
}

// spread returns a NodeMem with total divided evenly over the nodes.
func spread(nodes []int, total int64) NodeMem {
	nm := NodeMem{}
	if len(nodes) == 0 {
		return nm
	}
	perNode := total / int64(len(nodes))
	for _, node := range nodes {
		nm[node] = perNode
	}
	return nm
}

// typeWaypoint returns a waypoint that spreads the type usages over
// the nodes of the present memory types.
func typeWaypoint(mem MemoryTypes, usage typeUsage) Waypoint {
	nm := NodeMem{}
	if mem.hasDRAM() {
		maps.Copy(nm, spread(mem.DRAMNodes, usage.dram))
	}
	if mem.hasCXL() {
		maps.Copy(nm, spread(mem.CXLNodes, usage.cxl))
	}
	return Waypoint{Usage: nm}
}

// generateWaypoints returns the waypoints of a built-in memory use
// order for the memory types.
func generateWaypoints(order MemoryUseOrder, mem MemoryTypes) ([]Waypoint, error) {
	all := typeUsage{dram: mem.DRAMQuota, cxl: mem.CXLQuota}
	if !mem.hasDRAM() {
		all.dram = 0
	}
	if !mem.hasCXL() {
		all.cxl = 0
	}

	// With a single memory type every order consumes it alone.
	if !mem.hasDRAM() || !mem.hasCXL() {
		return []Waypoint{typeWaypoint(mem, all)}, nil
	}

	var first typeUsage
	switch order {
	case MemoryUseFirstDRAM:
		first = typeUsage{dram: all.dram}
	case MemoryUseFirstCXL:
		first = typeUsage{cxl: all.cxl}
	case MemoryUseStartInterleaved:
		smaller := min(all.dram, all.cxl)
		first = typeUsage{dram: smaller, cxl: smaller}
	case MemoryUseEndInterleaved:
		if all.dram > all.cxl {
			first = typeUsage{dram: all.dram - all.cxl}
		} else {
			first = typeUsage{cxl: all.cxl - all.dram}
		}
	default:
		return nil, fmt.Errorf("cannot generate waypoints for memory use order %s", order)
	}
	return []Waypoint{typeWaypoint(mem, first), typeWaypoint(mem, all)}, nil
}

// parseMemoryUseWaypoints returns the absolute usage per memory type
// of each user-specified waypoint.
func parseMemoryUseWaypoints(wps []MemoryUseWaypoint) ([]typeUsage, error) {
	usages := make([]typeUsage, 0, len(wps))
	var prev typeUsage
	for i, wp := range wps {
		if len(wp.TargetUsages) == 0 {
			return nil, fmt.Errorf("waypoint %d: no target usages specified", i)
		}
		usage := prev
		for j, entry := range wp.TargetUsages {
			bytes, err := ParseMemorySize(entry.Usage)
			if err != nil {
				return nil, fmt.Errorf("waypoint %d entry %d: %w", i, j, err)
			}
			switch strings.ToUpper(strings.TrimSpace(entry.MemoryType)) {
			case "DRAM":
				usage.dram = bytes
			case "CXL":
				usage.cxl = bytes
			default:
				return nil, fmt.Errorf("waypoint %d entry %d: unknown memory type %q (valid: DRAM, CXL)", i, j, entry.MemoryType)
			}
		}
		if usage.dram < prev.dram {
			return nil, fmt.Errorf("waypoint %d: DRAM usage %d is less than %d in the previous waypoint", i, usage.dram, prev.dram)
		}
		if usage.cxl < prev.cxl {
			return nil, fmt.Errorf("waypoint %d: CXL usage %d is less than %d in the previous waypoint", i, usage.cxl, prev.cxl)
		}
		usages = append(usages, usage)
		prev = usage
	}
	return usages, nil
}

// userWaypoints returns the waypoints of user-specified target usages
// spread over the nodes of the memory types.
func userWaypoints(wps []MemoryUseWaypoint, mem MemoryTypes) ([]Waypoint, error) {
	usages, err := parseMemoryUseWaypoints(wps)
	if err != nil {
		return nil, fmt.Errorf("invalid memoryUseWaypoints: %w", err)
	}
	waypoints := make([]Waypoint, 0, len(usages))
	for i, usage := range usages {
		if usage.dram > 0 && !mem.hasDRAM() {
			return nil, fmt.Errorf("invalid memoryUseWaypoints: waypoint %d: DRAM usage specified but no DRAM memory", i)
		}
		if usage.cxl > 0 && !mem.hasCXL() {
			return nil, fmt.Errorf("invalid memoryUseWaypoints: waypoint %d: CXL usage specified but no CXL memory", i)
		}
		waypoints = append(waypoints, typeWaypoint(mem, usage))
	}
	return waypoints, nil
}
