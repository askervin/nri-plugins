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
	Path           string         `json:"path" yaml:"path"`
	MemoryPolicies []MemoryPolicy `json:"memoryPolicies" yaml:"memoryPolicies"`
}

// Manager manages a single cgroup's memory policy
type Manager struct {
	config           CgroupConfig
	policies         []*CgMemoryPolicy
	watcher          *cgmemnotify.CgroupWatcher
	currentPolicyIdx int
	mu               sync.Mutex
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

// NewManager creates a new cgroup manager
func NewManager(config CgroupConfig) (*Manager, error) {
	// Parse all memory policies
	policies := make([]*CgMemoryPolicy, len(config.MemoryPolicies))
	for i, mp := range config.MemoryPolicies {
		parsed, err := ParseMemoryPolicy(mp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse memory policy %d: %w", i, err)
		}
		policies[i] = parsed
	}

	// Construct memory ladders from policies
	// Each ladder i has:
	//   LowWatermarkKB: ReactivateLimit of policy i-1 (or 0 for first ladder)
	//   HighWatermarkKB: Limit of policy i
	ladders := make(cgmemnotify.MemoryLadders, len(policies))
	for i, policy := range policies {
		ladders[i].HighWatermarkKB = policy.LimitBytes / 1024

		if i == 0 {
			ladders[i].LowWatermarkKB = 0 // First ladder starts at 0
		} else {
			ladders[i].LowWatermarkKB = policies[i-1].ReactivateLimitBytes / 1024
		}
	}

	watcher, err := cgmemnotify.NewCgroupWatcher(config.Path, &ladders)
	if err != nil {
		return nil, err
	}

	return &Manager{
		config:           config,
		policies:         policies,
		watcher:          watcher,
		currentPolicyIdx: -1, // Will be set during initialization
	}, nil
}

// Initialize initializes the memory policy for the cgroup
func (m *Manager) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Start with the first policy
	m.currentPolicyIdx = 0
	return m.applyMemoryPolicy(0)
}

// applyMemoryPolicy applies the memory policy at the given index
func (m *Manager) applyMemoryPolicy(policyIdx int) error {
	if policyIdx < 0 || policyIdx >= len(m.policies) {
		return fmt.Errorf("invalid policy index: %d", policyIdx)
	}

	policy := m.policies[policyIdx]

	// Get all PIDs in the cgroup
	pids, err := cgmemnotify.GetPIDs(m.config.Path)
	if err != nil {
		return fmt.Errorf("failed to get PIDs: %w", err)
	}

	// Get and log NUMA statistics after applying policy
	numaStats, err := m.watcher.NumaStat(cgmemnotify.LmcAnon | cgmemnotify.LmcShmem)
	if err != nil {
		LogDebug("applyMemoryPolicy: failed to get NUMA stats: %v\n", err)
		return fmt.Errorf("failed to get NUMA stats: %w", err)
	}

	// Write policy.Nodes that from this and previous ladders to cpuset.mems
	cpusetMemsPath := filepath.Join(m.config.Path, "cpuset.mems")
	allowedNodes := make(map[int]bool)
	for _, node := range policy.Nodes {
		LogDebug("applyMemoryPolicy: policy %d allows node %d\n", policyIdx, node)
		allowedNodes[node] = true
	}
	for node, usage := range numaStats {
		if usage > 0 {
			LogDebug("applyMemoryPolicy: node %d has usage %d bytes, allowing it in cpuset.mems\n", node, usage)
			allowedNodes[node] = true
		}
	}
	nodesStr := ""
	sep := ""
	for node := range allowedNodes {
		nodesStr += fmt.Sprintf("%s%d", sep, node)
		sep = ","
	}
	if err := os.WriteFile(cpusetMemsPath, []byte(nodesStr), 0644); err != nil {
		LogError("Failed to write cpuset.mems for %s: %v\n", m.config.Path, err)
		return fmt.Errorf("failed to write cpuset.mems: %w", err)
	} else {
		LogDebug("Updated cpuset.mems for %s to %s\n", m.config.Path, nodesStr)
	}

	if len(pids) == 0 {
		LogDebug("applyMemoryPolicy: no processes in cgroup %s\n", m.config.Path)
		return nil
	}

	// Apply memory policy using the configured nodes
	LogDebug("applyMemoryPolicy: setting memory policy for %s to %s on nodes %v (%d processes)\n",
		filepath.Base(m.config.Path), policy.PolicyType, policy.Nodes, len(pids))

	if err := mpolinject.SetMemoryPolicy(pids, policy.Nodes); err != nil {
		return fmt.Errorf("failed to set memory policy: %w", err)
	}

	// Log NUMA statistics after applying policy
	if numaStats != nil {
		// Find the highest node number to determine how many nodes to show
		maxNode := -1
		for node := range numaStats {
			if node > maxNode {
				maxNode = node
			}
		}

		if maxNode >= 0 {
			// Build the log string: "node0:400MB node1:NA node2:250MB"
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
	}

	return nil
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

// monitorLoop monitors notifications from the watcher
func (m *Manager) monitorLoop() {
	notifyCh := m.watcher.Notifications()

	for notification := range notifyCh {
		m.handleLadderCrossing(notification)
	}
}

// handleLadderCrossing handles ladder crossing events
func (m *Manager) handleLadderCrossing(notification cgmemnotify.Notification) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ladderIdx := notification.LadderIndex
	if ladderIdx < 0 || ladderIdx >= len(m.policies) {
		LogError("Unexpected LadderIndex in notification %+v\n", notification)
		return
	}

	LogDebug("Policy switch from %d to %d\n", notification.OldLadderIndex, notification.LadderIndex)

	m.currentPolicyIdx = ladderIdx
	if err := m.applyMemoryPolicy(ladderIdx); err != nil {
		LogError("Failed to apply new memory policy: %v\n", err)
	}
}

// Stop stops watching the cgroup
func (m *Manager) Stop() {
	m.watcher.Stop()
}

// GetConfig returns the cgroup configuration
func (m *Manager) GetConfig() CgroupConfig {
	return m.config
}

// GetParsedPolicies returns the parsed memory policies
func (m *Manager) GetParsedPolicies() []*CgMemoryPolicy {
	return m.policies
}
