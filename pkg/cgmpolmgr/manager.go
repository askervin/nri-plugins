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
// cgroups. It uses a Planner to steer memory allocations across NUMA
// nodes according to configurable waypoints, and a CgroupWatcher to
// detect when memory usage crosses configurable bounds.
package cgmpolmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containers/nri-plugins/pkg/cgmemnotify"
	"github.com/containers/nri-plugins/pkg/mpolinject"
)

// CgroupConfig represents configuration for a single cgroup
type CgroupConfig struct {
	Path               string              `json:"path" yaml:"path"`
	MemoryUseOrder     string              `json:"memoryUseOrder" yaml:"memoryUseOrder"`
	MemoryUseWaypoints []MemoryUseWaypoint `json:"memoryUseWaypoints,omitempty" yaml:"memoryUseWaypoints,omitempty"`
	DRAMNodes          string              `json:"dramNodes,omitempty" yaml:"dramNodes,omitempty"`
	CXLNodes           string              `json:"cxlNodes,omitempty" yaml:"cxlNodes,omitempty"`
	DRAMQuota          string              `json:"dramQuota" yaml:"dramQuota"`
	CXLQuota           string              `json:"cxlQuota" yaml:"cxlQuota"`
	MinLimit           string              `json:"minLimit" yaml:"minLimit"`
	MaxLimit           string              `json:"maxLimit" yaml:"maxLimit"`
}

// Manager manages a single cgroup's memory policy
type Manager struct {
	config  CgroupConfig
	planner *Planner
	watcher *cgmemnotify.CgroupWatcher
	mu      sync.Mutex
}

// LogDebug prints debug messages to stderr with a consistent prefix,
// starting with epoch time (including milliseconds) for easier log
// correlation.
func LogDebug(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprintf(os.Stderr, "%.06f DEBUG cgmpolmgr: %s", float64(time.Now().UnixNano())/1e9, msg)
}

// LogError prints error messages to stderr with a consistent prefix,
// starting with epoch time (including milliseconds) for easier log
// correlation.
func LogError(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprintf(os.Stderr, "%.06f ERROR cgmpolmgr: %s", float64(time.Now().UnixNano())/1e9, msg)
}

// NewManager creates a new cgroup manager.
func NewManager(config CgroupConfig) (*Manager, error) {
	// Parse memory use order.
	order, err := ParseMemoryUseOrder(config.MemoryUseOrder)
	if err != nil {
		return nil, fmt.Errorf("invalid memoryUseOrder: %w", err)
	}

	// Parse node sets.
	dramNodes, err := ParseNodeset(config.DRAMNodes)
	if err != nil {
		return nil, fmt.Errorf("invalid dramNodes: %w", err)
	}
	cxlNodes, err := ParseNodeset(config.CXLNodes)
	if err != nil {
		return nil, fmt.Errorf("invalid cxlNodes: %w", err)
	}

	// Parse quotas.
	dramQuota, err := ParseMemorySize(config.DRAMQuota)
	if err != nil {
		return nil, fmt.Errorf("invalid dramQuota: %w", err)
	}
	cxlQuota, err := ParseMemorySize(config.CXLQuota)
	if err != nil {
		return nil, fmt.Errorf("invalid cxlQuota: %w", err)
	}

	// Parse limits.
	minLimitU, err := ParseMemorySize(config.MinLimit)
	if err != nil {
		return nil, fmt.Errorf("invalid minLimit: %w", err)
	}
	maxLimitU, err := ParseMemorySize(config.MaxLimit)
	if err != nil {
		return nil, fmt.Errorf("invalid maxLimit: %w", err)
	}
	minLimit := int64(minLimitU)
	maxLimit := int64(maxLimitU)

	// Generate waypoints.
	var waypoints []Waypoint
	if order == MemoryUseWaypoints {
		waypoints, err = convertUserWaypoints(config.MemoryUseWaypoints, dramNodes, cxlNodes)
		if err != nil {
			return nil, fmt.Errorf("invalid memoryUseWaypoints: %w", err)
		}
	} else {
		waypoints, err = GenerateWaypoints(order, dramNodes, cxlNodes, int64(dramQuota), int64(cxlQuota))
		if err != nil {
			return nil, fmt.Errorf("failed to generate waypoints: %w", err)
		}
	}

	// Build the plan and planner.
	plan := &Plan{
		Waypoints: waypoints,
		MinLimit:  minLimit,
		MaxLimit:  maxLimit,
	}
	planner := NewPlanner()
	planner.SetPlan(plan)

	// Perform the initial route calculation.
	if err := planner.UpdateRoute(); err != nil {
		return nil, fmt.Errorf("initial UpdateRoute failed: %w", err)
	}

	// Derive initial memory bounds from the planner's first step.
	// UpperKB throttles the cgroup; the watcher will notify us when
	// memory reaches this threshold so we can re-steer.
	bounds := cgmemnotify.MemoryBounds{
		UpperKB: uint64(planner.NextLimit()) / 1024,
	}

	watcher, err := cgmemnotify.NewCgroupWatcher(config.Path, bounds)
	if err != nil {
		return nil, err
	}

	return &Manager{
		config:  config,
		planner: planner,
		watcher: watcher,
	}, nil
}

// convertUserWaypoints converts user-supplied MemoryUseWaypoint entries
// into Planner Waypoints. Each waypoint accumulates memory on the
// appropriate nodes.
func convertUserWaypoints(userWPs []MemoryUseWaypoint, dramNodes, cxlNodes []int) ([]Waypoint, error) {
	if len(userWPs) == 0 {
		return nil, fmt.Errorf("no waypoints specified")
	}

	// Accumulate per-node usage across waypoints (usage is monotonically increasing).
	dramUsage := int64(0)
	cxlUsage := int64(0)
	waypoints := make([]Waypoint, 0, len(userWPs))

	for i, uwp := range userWPs {
		usageBytes, err := ParseMemorySize(uwp.Usage)
		if err != nil {
			return nil, fmt.Errorf("waypoint %d: invalid usage: %w", i, err)
		}

		switch strings.ToUpper(strings.TrimSpace(uwp.MemoryType)) {
		case "DRAM":
			dramUsage += int64(usageBytes)
		case "CXL":
			cxlUsage += int64(usageBytes)
		default:
			return nil, fmt.Errorf("waypoint %d: unknown memory type %q (valid: DRAM, CXL)", i, uwp.MemoryType)
		}

		nm := NewNodeMem()
		// Spread DRAM usage evenly across DRAM nodes.
		if dramUsage > 0 {
			perNode := dramUsage / int64(len(dramNodes))
			for _, n := range dramNodes {
				nm.nodeMem[n] = perNode
			}
		}
		// Spread CXL usage evenly across CXL nodes.
		if cxlUsage > 0 {
			perNode := cxlUsage / int64(len(cxlNodes))
			for _, n := range cxlNodes {
				nm.nodeMem[n] = perNode
			}
		}
		waypoints = append(waypoints, Waypoint{Usage: nm})
	}

	return waypoints, nil
}

// Initialize applies the initial memory policy for the cgroup based
// on the planner's first route and sets the initial memory.high threshold.
func (m *Manager) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.applyCurrentPolicy(); err != nil {
		return err
	}
	m.updateWatcherBounds()
	return nil
}

// applyCurrentPolicy applies the memory policy dictated by the
// planner's current NextNodes.
func (m *Manager) applyCurrentPolicy() error {
	nodes := m.planner.NextNodes()
	if len(nodes) == 0 {
		LogDebug("applyCurrentPolicy: no next nodes from planner for %s\n", m.config.Path)
		return nil
	}

	// Get all PIDs in the cgroup.
	pids, err := cgmemnotify.GetPIDs(m.config.Path)
	if err != nil {
		return fmt.Errorf("failed to get PIDs: %w", err)
	}

	// Get NUMA statistics.
	numaStats, err := m.watcher.NumaStat(cgmemnotify.LmcAnon | cgmemnotify.LmcShmem)
	if err != nil {
		LogDebug("applyCurrentPolicy: failed to get NUMA stats: %v\n", err)
		return fmt.Errorf("failed to get NUMA stats: %w", err)
	}

	// Build the set of allowed nodes: planner's NextNodes plus any
	// node that already has usage (to avoid stranding memory).
	allowedNodes := make(map[int]bool)
	for _, node := range nodes {
		allowedNodes[node] = true
	}
	for node, usage := range numaStats {
		if usage > 0 {
			allowedNodes[node] = true
		}
	}

	// Write cpuset.mems.
	cpusetMemsPath := filepath.Join(m.config.Path, "cpuset.mems")
	nodesStr := ""
	sep := ""
	for node := range allowedNodes {
		nodesStr += fmt.Sprintf("%s%d", sep, node)
		sep = ","
	}
	if err := os.WriteFile(cpusetMemsPath, []byte(nodesStr), 0644); err != nil {
		LogError("Failed to write cpuset.mems for %s: %v\n", m.config.Path, err)
		return fmt.Errorf("failed to write cpuset.mems: %w", err)
	}
	LogDebug("Updated cpuset.mems for %s to %s\n", m.config.Path, nodesStr)

	if len(pids) == 0 {
		LogDebug("applyCurrentPolicy: no processes in cgroup %s\n", m.config.Path)
		return nil
	}

	// Apply memory policy to all processes.
	LogDebug("applyCurrentPolicy: setting memory policy for %s on nodes %v (%d processes)\n",
		filepath.Base(m.config.Path), nodes, len(pids))

	if err := mpolinject.SetMemoryPolicy(pids, nodes); err != nil {
		return fmt.Errorf("failed to set memory policy: %w", err)
	}

	logNumaStats(numaStats)
	return nil
}

// logNumaStats logs NUMA memory distribution.
func logNumaStats(numaStats map[int]uint64) {
	if numaStats == nil {
		return
	}
	maxNode := -1
	for node := range numaStats {
		if node > maxNode {
			maxNode = node
		}
	}
	if maxNode < 0 {
		return
	}
	var nodeStrs []string
	for node := 0; node <= maxNode; node++ {
		if bytes, ok := numaStats[node]; ok {
			mb := bytes / (1024 * 1024)
			nodeStrs = append(nodeStrs, fmt.Sprintf("node%d:%dMB", node, mb))
		} else {
			nodeStrs = append(nodeStrs, fmt.Sprintf("node%d:NA", node))
		}
	}
	LogDebug("NUMA memory distribution: %s\n", strings.Join(nodeStrs, " "))
}

// Start starts watching the cgroup
func (m *Manager) Start() error {
	if err := m.watcher.Start(); err != nil {
		return err
	}

	// Start monitoring goroutine
	go m.monitorLoop()

	return nil
}

// monitorLoop monitors notifications from the watcher and steers
// memory policy using the planner.
func (m *Manager) monitorLoop() {
	notifyCh := m.watcher.Notifications()

	for notification := range notifyCh {
		m.handleNotification(notification)
	}
}

// handleNotification handles a memory threshold crossing by updating
// the planner and applying the new policy.
func (m *Manager) handleNotification(notification cgmemnotify.Notification) {
	m.mu.Lock()
	defer m.mu.Unlock()

	LogDebug("Notification: bound %d crossed, memory %d KB\n",
		notification.BoundCrossed, notification.MemoryCurrentKB)

	// Read current NUMA usage and feed it to the planner.
	numaStats, err := m.watcher.NumaStat(cgmemnotify.LmcAnon | cgmemnotify.LmcShmem)
	if err != nil {
		LogError("Failed to get NUMA stats: %v\n", err)
		return
	}
	usage := NewNodeMem()
	for node, bytes := range numaStats {
		usage.nodeMem[node] = int64(bytes)
	}
	m.planner.UpdateUsage(usage)

	// Re-evaluate the route.
	if err := m.planner.UpdateRoute(); err != nil {
		LogError("UpdateRoute failed: %v\n", err)
		return
	}

	// Apply the new policy for NextNodes.
	if err := m.applyCurrentPolicy(); err != nil {
		LogError("Failed to apply policy: %v\n", err)
	}

	// Update the watcher's bounds so the next notification fires
	// at the right threshold. This also sets the new memory.high,
	// unblocking the throttled cgroup.
	m.updateWatcherBounds()
}

// updateWatcherBounds reconfigures the CgroupWatcher with new memory
// bounds so that memory.high is set to (current usage + NextLimit).
// A lower bound is also set so that significant memory drops (e.g.
// process frees) trigger a re-evaluation of the route.
func (m *Manager) updateWatcherBounds() {
	nextLimit := m.planner.NextLimit()
	if nextLimit <= 0 {
		LogDebug("updateWatcherBounds: nextLimit=%d, skipping\n", nextLimit)
		return
	}

	// Compute the new upper bound: current total usage + nextLimit.
	var currentTotal uint64
	if len(m.planner.track) > 0 {
		currentTotal = uint64(m.planner.track[len(m.planner.track)-1].Usage.TotalMem())
	}
	upperKB := (currentTotal + uint64(nextLimit)) / 1024

	// Set lower bound to detect significant memory drops.
	// If memory drops by more than nextLimit from the current level,
	// the watcher notifies us so we can re-steer and lower memory.high.
	var lowerKB uint64
	if currentTotal > uint64(nextLimit) {
		lowerKB = (currentTotal - uint64(nextLimit)) / 1024
	}

	bounds := cgmemnotify.MemoryBounds{
		LowerKB: lowerKB,
		UpperKB: upperKB,
	}

	if err := m.watcher.SetBounds(bounds); err != nil {
		LogError("updateWatcherBounds: SetBounds failed: %v\n", err)
		return
	}
	LogDebug("updateWatcherBounds: bounds lower=%d KB upper=%d KB (current=%d KB)\n",
		lowerKB, upperKB, currentTotal/1024)
}

// Stop stops watching the cgroup
func (m *Manager) Stop() {
	m.watcher.Stop()
}

// GetConfig returns the cgroup configuration.
func (m *Manager) GetConfig() CgroupConfig {
	return m.config
}

// GetPlanner returns the planner used by this manager.
func (m *Manager) GetPlanner() *Planner {
	return m.planner
}
