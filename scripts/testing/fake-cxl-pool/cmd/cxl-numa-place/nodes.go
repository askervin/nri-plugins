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

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// maxNode bounds the node numbers of a node list.
const maxNode = 1 << 16

// parseNodeList returns the NUMA nodes of a list like "1,3-5", sorted and
// without duplicates.
func parseNodeList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty node list")
	}
	seen := map[int]bool{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		lo, hi, isRange := strings.Cut(item, "-")
		first, err := parseNode(lo)
		if err != nil {
			return nil, fmt.Errorf("node list %q: %w", s, err)
		}
		last := first
		if isRange {
			if last, err = parseNode(hi); err != nil {
				return nil, fmt.Errorf("node list %q: %w", s, err)
			}
			if last < first {
				return nil, fmt.Errorf("node list %q: range %s ends before it starts", s, item)
			}
		}
		for n := first; n <= last; n++ {
			seen[n] = true
		}
	}
	nodes := make([]int, 0, len(seen))
	for n := range seen {
		nodes = append(nodes, n)
	}
	sort.Ints(nodes)
	return nodes, nil
}

// parseNode returns the node number of s.
func parseNode(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n >= maxNode {
		return 0, fmt.Errorf("%q is not a node number", s)
	}
	return n, nil
}

// formatNodeList returns sorted nodes as a list with ranges, like "1,3-5".
func formatNodeList(nodes []int) string {
	var b strings.Builder
	for i := 0; i < len(nodes); {
		j := i
		for j+1 < len(nodes) && nodes[j+1] == nodes[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		if j == i {
			fmt.Fprintf(&b, "%d", nodes[i])
		} else {
			fmt.Fprintf(&b, "%d-%d", nodes[i], nodes[j])
		}
		i = j + 1
	}
	return b.String()
}

// memoryNodes returns the NUMA nodes with memory, read from
// devices/system/node/has_memory under the sysfs directory sysfs.
func memoryNodes(sysfs string) ([]int, error) {
	path := filepath.Join(sysfs, "devices/system/node/has_memory")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the NUMA nodes with memory: %w", err)
	}
	nodes, err := parseNodeList(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return nodes, nil
}

// checkNodes returns an error naming the first of nodes that is not in
// have, the nodes with memory.
func checkNodes(nodes, have []int) error {
	ok := map[int]bool{}
	for _, n := range have {
		ok[n] = true
	}
	for _, n := range nodes {
		if !ok[n] {
			return fmt.Errorf("node %d has no memory (the nodes with memory: %s)", n, formatNodeList(have))
		}
	}
	return nil
}

// hasCapSysNice returns true if the effective capabilities in the
// /proc/PID/status file statusPath include CAP_SYS_NICE.
func hasCapSysNice(statusPath string) (bool, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return false, fmt.Errorf("cannot read the capabilities: %w", err)
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		hex, found := strings.CutPrefix(s.Text(), "CapEff:")
		if !found {
			continue
		}
		caps, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
		if err != nil {
			return false, fmt.Errorf("%s: CapEff %q: %w", statusPath, strings.TrimSpace(hex), err)
		}
		return caps&(1<<unix.CAP_SYS_NICE) != 0, nil
	}
	if err := s.Err(); err != nil {
		return false, fmt.Errorf("cannot read %s: %w", statusPath, err)
	}
	return false, fmt.Errorf("%s has no CapEff", statusPath)
}
