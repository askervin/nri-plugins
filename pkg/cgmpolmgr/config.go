// Copyright The NRI Plugins Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cgmpolmgr

import (
	"fmt"
	"strconv"
	"strings"
)

// CgMemoryPolicy represents a parsed memory policy with computed values
type CgMemoryPolicy struct {
	Nodes                []int
	LimitBytes           uint64
	ReactivateLimitBytes uint64
	PolicyType           string
}

// MemoryPolicy represents a NUMA memory policy configuration (raw from config file)
type MemoryPolicy struct {
	Nodeset         string `json:"nodeset" yaml:"nodeset"`
	Limit           string `json:"limit,omitempty" yaml:"limit,omitempty"`
	ReactivateLimit string `json:"reactivateLimit,omitempty" yaml:"reactivateLimit,omitempty"`
	Policy          string `json:"policy,omitempty" yaml:"policy,omitempty"`
}

// MemoryUseOrder describes the strategy for consuming DRAM and CXL memory
// quotas. For all values except MemoryUseWaypoints, waypoints are
// automatically generated based on the available DRAM and CXL memory
// quotas. For MemoryUseWaypoints, the user provides explicit waypoints
// as memory type / usage pairs.
type MemoryUseOrder int

const (
	// MemoryUseFirstDRAM prefers DRAM over CXL: consume the DRAM quota
	// first, then fall back to CXL once DRAM is exhausted.
	MemoryUseFirstDRAM MemoryUseOrder = iota
	// MemoryUseFirstCXL prefers CXL over DRAM: consume the CXL quota
	// first, then fall back to DRAM once CXL is exhausted.
	MemoryUseFirstCXL
	// MemoryUseStartInterleaved prefers interleaving DRAM and CXL at the
	// beginning. Once the smaller quota has been fully used,
	// the remaining memory type is consumed alone.
	MemoryUseStartInterleaved
	// MemoryUseEndInterleaved is the opposite of MemoryUseStartInterleaved:
	// consume the excess of the larger quota first, then interleave DRAM
	// and CXL for the remainder.
	MemoryUseEndInterleaved
	// MemoryUseWaypoints follows a user-specified sequence of waypoints,
	// where each waypoint is a memory type / usage pair.
	MemoryUseWaypoints
)

// ParseMemoryUseOrder parses a user-facing string into a MemoryUseOrder.
func ParseMemoryUseOrder(s string) (MemoryUseOrder, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "first-dram":
		return MemoryUseFirstDRAM, nil
	case "first-cxl":
		return MemoryUseFirstCXL, nil
	case "start-interleaved":
		return MemoryUseStartInterleaved, nil
	case "end-interleaved":
		return MemoryUseEndInterleaved, nil
	case "waypoints":
		return MemoryUseWaypoints, nil
	default:
		return 0, fmt.Errorf("unknown memory use order %q (valid: first-DRAM, first-CXL, start-interleaved, end-interleaved, waypoints)", s)
	}
}

// MemoryUseWaypoint specifies a single waypoint in a user-defined
// memory use order. MemoryType is "DRAM" or "CXL", and Usage is
// a human-readable size string (e.g. "20G").
type MemoryUseWaypoint struct {
	MemoryType string `json:"memoryType" yaml:"memoryType"`
	Usage      string `json:"usage" yaml:"usage"`
}

// GenerateWaypoints builds Planner-compatible waypoints from a
// MemoryUseOrder and DRAM/CXL quotas and node IDs.
//
// dramNodes/cxlNodes are the NUMA node IDs for each memory type.
// dramQuota/cxlQuota are the total byte quotas for DRAM and CXL.
//
// For MemoryUseWaypoints the caller must convert user-supplied
// MemoryUseWaypoint entries separately.
func GenerateWaypoints(order MemoryUseOrder, dramNodes, cxlNodes []int, dramQuota, cxlQuota int64) ([]Waypoint, error) {
	if len(dramNodes) == 0 {
		return nil, fmt.Errorf("GenerateWaypoints: no DRAM nodes")
	}
	if len(cxlNodes) == 0 {
		return nil, fmt.Errorf("GenerateWaypoints: no CXL nodes")
	}
	if dramQuota <= 0 {
		return nil, fmt.Errorf("GenerateWaypoints: DRAM quota must be positive")
	}
	if cxlQuota <= 0 {
		return nil, fmt.Errorf("GenerateWaypoints: CXL quota must be positive")
	}

	// Helper: build a NodeMem that spreads total evenly across nodes.
	spread := func(nodes []int, total int64) NodeMem {
		nm := NewNodeMem()
		if total == 0 || len(nodes) == 0 {
			return nm
		}
		perNode := total / int64(len(nodes))
		for _, n := range nodes {
			nm[n] = perNode
		}
		return nm
	}

	// Helper: merge two NodeMems (disjoint node sets).
	merge := func(a, b NodeMem) NodeMem {
		nm := a.Copy()
		for n, v := range b {
			nm[n] = v
		}
		return nm
	}

	switch order {
	case MemoryUseFirstDRAM:
		// wp0: all DRAM used, no CXL yet
		// wp1: all DRAM + all CXL
		wp0 := merge(spread(dramNodes, dramQuota), spread(cxlNodes, 0))
		wp1 := merge(spread(dramNodes, dramQuota), spread(cxlNodes, cxlQuota))
		return []Waypoint{{Usage: wp0}, {Usage: wp1}}, nil

	case MemoryUseFirstCXL:
		// wp0: no DRAM, all CXL used
		// wp1: all DRAM + all CXL
		wp0 := merge(spread(dramNodes, 0), spread(cxlNodes, cxlQuota))
		wp1 := merge(spread(dramNodes, dramQuota), spread(cxlNodes, cxlQuota))
		return []Waypoint{{Usage: wp0}, {Usage: wp1}}, nil

	case MemoryUseStartInterleaved:
		// Interleave both types until the smaller quota is exhausted,
		// then use the remaining type alone.
		smallerQuota := min(dramQuota, cxlQuota)
		wp0 := merge(spread(dramNodes, smallerQuota), spread(cxlNodes, smallerQuota))
		wp1 := merge(spread(dramNodes, dramQuota), spread(cxlNodes, cxlQuota))
		return []Waypoint{{Usage: wp0}, {Usage: wp1}}, nil

	case MemoryUseEndInterleaved:
		// Use the excess of the larger quota first, then interleave.
		var wp0 NodeMem
		if dramQuota > cxlQuota {
			excess := dramQuota - cxlQuota
			wp0 = merge(spread(dramNodes, excess), spread(cxlNodes, 0))
		} else {
			excess := cxlQuota - dramQuota
			wp0 = merge(spread(dramNodes, 0), spread(cxlNodes, excess))
		}
		wp1 := merge(spread(dramNodes, dramQuota), spread(cxlNodes, cxlQuota))
		return []Waypoint{{Usage: wp0}, {Usage: wp1}}, nil

	case MemoryUseWaypoints:
		return nil, fmt.Errorf("GenerateWaypoints: MemoryUseWaypoints requires caller to convert waypoints directly")

	default:
		return nil, fmt.Errorf("GenerateWaypoints: unknown order %d", order)
	}
}

// ParseNodeset parses a cpuset list syntax string (e.g., "1,3-5,7") into a slice of node IDs
func ParseNodeset(nodeset string) ([]int, error) {
	nodeset = strings.TrimSpace(nodeset)
	if nodeset == "" {
		return nil, fmt.Errorf("nodeset cannot be empty")
	}

	nodes := make([]int, 0)
	parts := strings.Split(nodeset, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check if it's a range (e.g., "3-5")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range format: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid range start: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid range end: %s", rangeParts[1])
			}

			if start > end {
				return nil, fmt.Errorf("invalid range: start %d > end %d", start, end)
			}

			for i := start; i <= end; i++ {
				nodes = append(nodes, i)
			}
		} else {
			// Single node
			node, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid node ID: %s", part)
			}
			nodes = append(nodes, node)
		}
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("nodeset resulted in empty list")
	}

	return nodes, nil
}

// ParseMemorySize parses a memory size string (e.g., "4G", "1024k", "1048576") into bytes
func ParseMemorySize(size string) (uint64, error) {
	size = strings.TrimSpace(size)
	if size == "" {
		return 0, nil
	}

	// Check for unit suffix
	var multiplier uint64 = 1
	var numStr string

	lastChar := size[len(size)-1]
	switch lastChar {
	case 'T', 't':
		multiplier = 1024 * 1024 * 1024 * 1024
		numStr = size[:len(size)-1]
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
		numStr = size[:len(size)-1]
	case 'M', 'm':
		multiplier = 1024 * 1024
		numStr = size[:len(size)-1]
	case 'k', 'K':
		multiplier = 1024
		numStr = size[:len(size)-1]
	case 'B', 'b':
		multiplier = 1
		numStr = size[:len(size)-1]
	default:
		// No suffix, assume bytes
		numStr = size
	}

	numStr = strings.TrimSpace(numStr)
	value, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory size: %s", size)
	}

	return value * multiplier, nil
}

// ParseMemoryPolicy parses a MemoryPolicy configuration into a CgMemoryPolicy
func ParseMemoryPolicy(mp MemoryPolicy) (*CgMemoryPolicy, error) {
	// Parse nodeset
	nodes, err := ParseNodeset(mp.Nodeset)
	if err != nil {
		return nil, fmt.Errorf("invalid nodeset: %w", err)
	}

	// Parse limit
	limitBytes, err := ParseMemorySize(mp.Limit)
	if err != nil {
		return nil, fmt.Errorf("invalid limit: %w", err)
	}

	// Parse reactivateLimit (optional, defaults to limit / 2)
	var reactivateLimitBytes uint64
	if mp.ReactivateLimit != "" {
		reactivateLimitBytes, err = ParseMemorySize(mp.ReactivateLimit)
		if err != nil {
			return nil, fmt.Errorf("invalid reactivateLimit: %w", err)
		}
	} else {
		reactivateLimitBytes = limitBytes / 2
	}

	if reactivateLimitBytes > limitBytes {
		return nil, fmt.Errorf("reactivateLimit (%d) must be less or equal than limit (%d)", reactivateLimitBytes, limitBytes)
	}

	// Determine policy type
	policyType := mp.Policy
	if policyType == "" {
		// Default policy based on number of nodes
		if len(nodes) == 1 {
			policyType = "preferred"
		} else {
			policyType = "interleave"
		}
	}

	// Validate policy type
	validPolicies := map[string]bool{
		"default":             true,
		"bind":                true,
		"interleave":          true,
		"weighted_interleave": true,
		"preferred":           true,
		"local":               true,
	}
	if !validPolicies[policyType] {
		return nil, fmt.Errorf("invalid policy type: %s (must be one of: default, bind, interleave, weighted_interleave, preferred, local)", policyType)
	}

	return &CgMemoryPolicy{
		Nodes:                nodes,
		LimitBytes:           limitBytes,
		ReactivateLimitBytes: reactivateLimitBytes,
		PolicyType:           policyType,
	}, nil
}
