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
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/containers/nri-plugins/pkg/mpolinject"
)

func main() {
	var (
		nodesStr string
		showHelp bool
		dryRun   bool
	)

	flag.StringVar(&nodesStr, "nodes", "", "Comma-separated list of NUMA nodes (e.g., 0,1,2)")
	flag.StringVar(&nodesStr, "n", "", "Comma-separated list of NUMA nodes (shorthand)")
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&showHelp, "h", false, "Show help message (shorthand)")
	flag.BoolVar(&dryRun, "dry-run", false, "Validate inputs without making changes")

	flag.Usage = printUsage
	flag.Parse()

	if showHelp {
		printUsage()
		os.Exit(0)
	}

	// Check for root privileges (required for ptrace)
	if os.Geteuid() != 0 && !dryRun {
		fmt.Fprintf(os.Stderr, "Error: This program must be run as root (required for ptrace)\n")
		fmt.Fprintf(os.Stderr, "Try: sudo %s\n", strings.Join(os.Args, " "))
		os.Exit(1)
	}

	// Parse NUMA nodes
	if nodesStr == "" {
		fmt.Fprintf(os.Stderr, "Error: --nodes is required\n\n")
		printUsage()
		os.Exit(1)
	}

	nodes, err := parseNodes(nodesStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing nodes: %v\n", err)
		os.Exit(1)
	}

	if len(nodes) == 0 {
		fmt.Fprintf(os.Stderr, "Error: At least one NUMA node must be specified\n")
		os.Exit(1)
	}

	// Validate NUMA nodes exist
	if err := mpolinject.ValidateNumaNodes(nodes); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Available nodes: ls /sys/devices/system/node/\n")
		os.Exit(1)
	}

	// Parse PIDs from remaining arguments
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: At least one PID must be specified\n\n")
		printUsage()
		os.Exit(1)
	}

	pids, err := parsePIDs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing PIDs: %v\n", err)
		os.Exit(1)
	}

	// Validate PIDs exist
	validPIDs := make([]int, 0, len(pids))
	for _, pid := range pids {
		if pidExists(pid) {
			validPIDs = append(validPIDs, pid)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: PID %d does not exist, skipping\n", pid)
		}
	}

	if len(validPIDs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No valid PIDs to process\n")
		os.Exit(1)
	}

	// Print what we're about to do
	fmt.Printf("Setting MPOL_PREFERRED memory policy:\n")
	fmt.Printf("  NUMA nodes: %v\n", nodes)
	fmt.Printf("  PIDs: %v\n", validPIDs)

	if len(nodes) == 1 {
		fmt.Printf("  Policy: MPOL_PREFERRED (prefer node %d)\n", nodes[0])
	} else {
		fmt.Printf("  Policy: MPOL_INTERLEAVE (interleave across %d nodes)\n", len(nodes))
	}

	if dryRun {
		fmt.Println("\n[DRY RUN] No changes made")
		os.Exit(0)
	}

	fmt.Println()

	// Set memory policy
	if err := mpolinject.SetMemoryPolicy(validPIDs, nodes); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Successfully set memory policy on %d process(es)\n", len(validPIDs))

	// Show verification instructions
	fmt.Println("\nTo verify the change:")
	for _, pid := range validPIDs {
		fmt.Printf("  cat /proc/%d/numa_maps | head -5\n", pid)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `mpolinject - Set NUMA memory policy on running processes

Usage:
  mpolinject --nodes <nodes> [options] <pid1> [pid2] [pid3] ...

Options:
  -n, --nodes <nodes>   Comma-separated list of NUMA node IDs (required)
                        Examples: --nodes 0
                                  --nodes 0,1,2

  --dry-run             Validate inputs without making changes
  -h, --help            Show this help message
  -v, --version         Show version information

Arguments:
  <pid>                 Process IDs to apply memory policy to

Examples:
  # Set MPOL_PREFERRED to node 0 for PID 1234
  sudo mpolinject --nodes 0 1234

  # Set MPOL_INTERLEAVE across nodes 0,1 for multiple processes
  sudo mpolinject --nodes 0,1 1234 5678 9012

  # Apply to all processes in a cgroup
  sudo mpolinject --nodes 0 $(cat /sys/fs/cgroup/myapp.slice/cgroup.procs)

  # Dry run to validate before applying
  mpolinject --nodes 0 --dry-run 1234

Description:
  This tool uses ptrace to inject set_mempolicy() syscalls into running
  processes, changing their NUMA memory allocation preferences.

  - Single node: Uses MPOL_PREFERRED (prefer allocations from that node)
  - Multiple nodes: Uses MPOL_INTERLEAVE (round-robin across nodes)

  The policy affects future memory allocations, not existing pages.
  To migrate existing pages, use numactl or mbind separately.

Requirements:
  - Root privileges (for ptrace)
  - Target processes must be ptrace-able
  - NUMA-capable system

Notes:
  - Check /proc/sys/kernel/yama/ptrace_scope if ptrace fails
  - Some processes (e.g., kernel threads) cannot be ptraced
  - Memory policy is per-process and inherited by child processes

`)
}

func parseNodes(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	nodes := make([]int, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		node, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid node ID '%s': %w", part, err)
		}

		if node < 0 {
			return nil, fmt.Errorf("node ID must be non-negative: %d", node)
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

func parsePIDs(args []string) ([]int, error) {
	pids := make([]int, 0, len(args))

	for _, arg := range args {
		pid, err := strconv.Atoi(arg)
		if err != nil {
			return nil, fmt.Errorf("invalid PID '%s': %w", arg, err)
		}

		if pid <= 0 {
			return nil, fmt.Errorf("PID must be positive: %d", pid)
		}

		pids = append(pids, pid)
	}

	return pids, nil
}

func pidExists(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}
