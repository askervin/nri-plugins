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
// nodes according to configurable waypoints, and a MemNotifier to
// detect when memory usage crosses configurable bounds.
package cgmpolmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containers/nri-plugins/pkg/cgmemnotify"
	"github.com/containers/nri-plugins/pkg/mpolinject"
)

// ManagerConfig represents configuration for a single cgroup manager.
type ManagerConfig struct {
	CgroupPath         string              `json:"cgroupPath" yaml:"cgroupPath"`
	CgroupName         string              `json:"cgroupName,omitempty" yaml:"cgroupName,omitempty"` // Pretty name for the cgroup, used in log messages
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
	config              ManagerConfig
	planner             *Planner
	notifier            *cgmemnotify.MemNotifier
	allowedNodes        map[int]bool
	allowedNodesWritten int
	mu                  sync.Mutex
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

// LogDebug logs a debug message prefixed with the cgroup name.
func (m *Manager) LogDebug(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprintf(os.Stderr, "%.06f DEBUG cgmpolmgr %s: %s", float64(time.Now().UnixNano())/1e9, m.config.CgroupName, msg)
}

// LogError logs an error message prefixed with the cgroup name.
func (m *Manager) LogError(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprintf(os.Stderr, "%.06f ERROR cgmpolmgr %s: %s", float64(time.Now().UnixNano())/1e9, m.config.CgroupName, msg)
}

// LogWarning logs a warning message prefixed with the cgroup name.
func (m *Manager) LogWarning(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprintf(os.Stderr, "%.06f WARNING cgmpolmgr %s: %s", float64(time.Now().UnixNano())/1e9, m.config.CgroupName, msg)
}

// NewManager creates a new cgroup manager.
func NewManager(config ManagerConfig) (*Manager, error) {
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
	// Upper throttles the cgroup; the notifier will notify us when
	// memory reaches this threshold so we can re-steer.
	bounds := cgmemnotify.MemoryBounds{
		Upper: uint64(planner.NextLimit()),
	}

	notifier, err := cgmemnotify.NewMemNotifier(cgmemnotify.MemNotifierConfig{
		CgroupPath: config.CgroupPath,
		CgroupName: config.CgroupName,
		Bounds:     bounds,
	})
	if err != nil {
		return nil, err
	}

	m := &Manager{
		config:       config,
		planner:      planner,
		notifier:     notifier,
		allowedNodes: make(map[int]bool),
	}

	m.LogDebug("NewManager: created with waypoints %v for cgroup %s\n", waypoints, config.CgroupPath)
	return m, nil
}

// convertUserWaypoints converts user-supplied MemoryUseWaypoint entries
// into Planner Waypoints. Each waypoint specifies absolute per-type
// memory usage. Usage values must be non-decreasing across waypoints
// for each memory type.
func convertUserWaypoints(userWPs []MemoryUseWaypoint, dramNodes, cxlNodes []int) ([]Waypoint, error) {
	if len(userWPs) == 0 {
		return nil, fmt.Errorf("no waypoints specified")
	}

	prevDRAM := int64(0)
	prevCXL := int64(0)
	waypoints := make([]Waypoint, 0, len(userWPs))

	for i, uwp := range userWPs {
		if len(uwp.TargetUsages) == 0 {
			return nil, fmt.Errorf("waypoint %d: no target usages specified", i)
		}

		dramUsage := prevDRAM
		cxlUsage := prevCXL

		for j, entry := range uwp.TargetUsages {
			usageBytes, err := ParseMemorySize(entry.Usage)
			if err != nil {
				return nil, fmt.Errorf("waypoint %d entry %d: invalid usage: %w", i, j, err)
			}

			switch strings.ToUpper(strings.TrimSpace(entry.MemoryType)) {
			case "DRAM":
				dramUsage = int64(usageBytes)
			case "CXL":
				cxlUsage = int64(usageBytes)
			default:
				return nil, fmt.Errorf("waypoint %d entry %d: unknown memory type %q (valid: DRAM, CXL)", i, j, entry.MemoryType)
			}
		}

		if dramUsage < prevDRAM {
			return nil, fmt.Errorf("waypoint %d: DRAM usage %d is less than previous waypoint's %d (must be non-decreasing)", i, dramUsage, prevDRAM)
		}
		if cxlUsage < prevCXL {
			return nil, fmt.Errorf("waypoint %d: CXL usage %d is less than previous waypoint's %d (must be non-decreasing)", i, cxlUsage, prevCXL)
		}

		nm := NewNodeMem()
		if dramUsage > 0 && len(dramNodes) > 0 {
			memPerNode := dramUsage / int64(len(dramNodes))
			for _, node := range dramNodes {
				nm[node] = memPerNode
			}
		}
		if cxlUsage > 0 && len(cxlNodes) > 0 {
			memPerNode := cxlUsage / int64(len(cxlNodes))
			for _, node := range cxlNodes {
				nm[node] = memPerNode
			}
		}
		waypoints = append(waypoints, Waypoint{
			Name:  strconv.Itoa(i),
			Usage: nm,
		})

		prevDRAM = dramUsage
		prevCXL = cxlUsage
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
		m.LogDebug("applyCurrentPolicy: no next nodes from planner for %s\n", m.config.CgroupPath)
		return nil
	}

	// Get all PIDs in the cgroup.
	pids, err := cgmemnotify.GetPIDs(m.config.CgroupPath)
	if err != nil {
		return fmt.Errorf("failed to get PIDs: %w", err)
	}

	// Get NUMA statistics.

	// Build the set of allowed nodes: planner's NextNodes plus any
	// node that already has usage (to avoid stranding memory).
	if m.allowedNodes == nil {
		m.allowedNodes = make(map[int]bool)
	}
	for _, node := range nodes {
		m.allowedNodes[node] = true
	}

	if m.allowedNodesWritten < len(m.allowedNodes) {
		// New nodes have been enabled. Nodes can never be disabled,
		// therefore comparing the number of allowed nodes is enough.
		cpusetMemsPath := filepath.Join(m.config.CgroupPath, "cpuset.mems")
		nodesStr := ""
		sep := ""
		for node := range m.allowedNodes {
			nodesStr += fmt.Sprintf("%s%d", sep, node)
			sep = ","
		}
		if err := os.WriteFile(cpusetMemsPath, []byte(nodesStr), 0644); err != nil {
			m.LogError("Failed to write cpuset.mems for %s: %v\n", m.config.CgroupPath, err)
			return fmt.Errorf("failed to write cpuset.mems: %w", err)
		}
		m.LogDebug("Updated cpuset.mems for %s to %s\n", m.config.CgroupPath, nodesStr)
	}

	if len(pids) == 0 {
		m.LogDebug("applyCurrentPolicy: no processes in cgroup %s\n", m.config.CgroupPath)
		return nil
	}

	// Apply memory policy to all processes.
	m.LogDebug("applyCurrentPolicy: setting memory policy for %s on nodes %v (%d processes)\n",
		filepath.Base(m.config.CgroupPath), nodes, len(pids))

	if err := mpolinject.SetMemoryPolicy(pids, nodes); err != nil {
		return fmt.Errorf("failed to set memory policy: %w", err)
	}
	return nil
}

// logNumaStats logs NUMA memory distribution.
func (m *Manager) logNumaStats(numaStats map[int]uint64) {
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
			nodeStrs = append(nodeStrs, fmt.Sprintf("node%d:%d", node, bytes))
		} else {
			nodeStrs = append(nodeStrs, fmt.Sprintf("node%d:NA", node))
		}
	}
	m.LogDebug("NUMA memory distribution: %s\n", strings.Join(nodeStrs, " "))
}

// Start starts watching the cgroup
func (m *Manager) Start() error {
	// TODO / TO CONSIDER

	// - When starting with a cgroup with already running
	// processes (that is, with non-zero memory.current), we
	// should figure out numastats, and do Planner.UpdateUsage() +
	// Planner.UpdateRoute() to start steering towards valid waypoint.

	// - When starting with a cgroup without processes, we could
	// add a minimal (for instance 1 MB) memory.high, so that we
	// could immediately apply suitable memory policies instead of
	// playing with cpuset.mems.

	// If the cgroup already exists, check all nodes already contain data to avoid
	// memory moves by restricting cpuset.mems.
	if numaStats, err := m.notifier.NumaStat(cgmemnotify.LmcAnon | cgmemnotify.LmcShmem); err == nil {
		for node, usage := range numaStats {
			if usage > 0 {
				m.allowedNodes[node] = true
			}
		}
		m.logNumaStats(numaStats)
	}

	if err := m.notifier.Start(); err != nil {
		return err
	}

	// Start monitoring goroutine
	go m.monitorLoop()

	return nil
}

// monitorLoop monitors notifications from the watcher and steers
// memory policy using the planner.
func (m *Manager) monitorLoop() {
	notifyCh := m.notifier.Notifications()

	for notification := range notifyCh {
		m.handleNotification(notification)
	}
}

// handleNotification handles a memory threshold crossing by updating
// the planner and applying the new policy.
func (m *Manager) handleNotification(notification cgmemnotify.Notification) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LogDebug("Notification: bound %d crossed, memory %d bytes\n",
		notification.BoundCrossed, notification.MemoryCurrent)

	// Read current NUMA usage and feed it to the planner.
	numaStats, err := m.notifier.NumaStat(cgmemnotify.LmcAnon | cgmemnotify.LmcShmem)
	if err != nil {
		m.LogError("Failed to get NUMA stats: %v\n", err)
		return
	}
	usage := NewNodeMem()
	for node, bytes := range numaStats {
		usage[node] = int64(bytes)
	}
	m.planner.UpdateUsage(usage)

	// Re-evaluate the route.
	if err := m.planner.UpdateRoute(); err != nil {
		m.LogError("UpdateRoute failed: %v\n", err)
		return
	}

	// Apply the new policy for NextNodes.
	if err := m.applyCurrentPolicy(); err != nil {
		m.LogError("Failed to apply policy: %v\n", err)
	}

	// Update the watcher's bounds so the next notification fires
	// at the right threshold. This also sets the new memory.high,
	// unblocking the throttled cgroup.
	m.updateWatcherBounds()

	// Log the new NUMA distribution after applying the policy.
	m.logNumaStats(numaStats)
}

// updateWatcherBounds reconfigures the MemNotifier with new memory
// bounds so that memory.high is set to (current usage + NextLimit).
// A lower bound is also set so that significant memory drops (e.g.
// process frees) trigger a re-evaluation of the route.
func (m *Manager) updateWatcherBounds() {
	nextLimit := m.planner.NextLimit()
	if nextLimit <= 0 {
		m.LogDebug("updateWatcherBounds: nextLimit=%d, skipping\n", nextLimit)
		return
	}

	// Compute the new upper bound: current total usage + nextLimit.
	var currentTotal uint64
	if len(m.planner.track) > 0 {
		currentTotal = uint64(m.planner.track[len(m.planner.track)-1].Usage.TotalMem())
	}
	upper := currentTotal + uint64(nextLimit)

	// Set lower bound to detect significant memory drops.
	// If memory drops by more than nextLimit from the current level,
	// the notifier tells us so we can re-steer and lower memory.high.
	var lower uint64
	if currentTotal > uint64(nextLimit) {
		lower = currentTotal - uint64(nextLimit)
	}

	bounds := cgmemnotify.MemoryBounds{
		Lower: lower,
		Upper: upper,
	}

	if err := m.notifier.SetBounds(bounds); err != nil {
		m.LogError("updateWatcherBounds: SetBounds failed: %v\n", err)
		return
	}
	m.LogDebug("updateWatcherBounds: bounds lower=%d bytes upper=%d bytes (current=%d bytes)\n",
		lower, upper, currentTotal)
}

// Stop stops watching the cgroup
func (m *Manager) Stop() {
	m.notifier.Stop()
}

// GetConfig returns the manager configuration.
func (m *Manager) GetConfig() ManagerConfig {
	return m.config
}

// GetPlanner returns the planner used by this manager.
func (m *Manager) GetPlanner() *Planner {
	return m.planner
}
