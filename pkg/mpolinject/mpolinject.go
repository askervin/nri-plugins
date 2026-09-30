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

// Package mpolinject sets the NUMA memory policy of running processes
// by injecting a set_mempolicy system call into every thread of the
// process with ptrace. The processes must be ptraceable by the
// caller. Injection is implemented for linux/amd64 only.
package mpolinject

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Mode is a set_mempolicy mode. The values are the MPOL_* constants
// of the Linux kernel.
type Mode int

const (
	Default            Mode = 0
	Preferred          Mode = 1
	Bind               Mode = 2
	Interleave         Mode = 3
	Local              Mode = 4
	PreferredMany      Mode = 5
	WeightedInterleave Mode = 6
)

// String returns the name of the mode.
func (m Mode) String() string {
	switch m {
	case Default:
		return "default"
	case Preferred:
		return "preferred"
	case Bind:
		return "bind"
	case Interleave:
		return "interleave"
	case Local:
		return "local"
	case PreferredMany:
		return "preferred-many"
	case WeightedInterleave:
		return "weighted-interleave"
	}
	return "Mode(" + strconv.Itoa(int(m)) + ")"
}

// ErrUnsupported is returned by SetMemoryPolicy on platforms without
// an injection implementation.
var ErrUnsupported = errors.New("memory policy injection is not supported on this platform")

// maxNodes is the largest nodemask size in bits that is passed to
// set_mempolicy.
const maxNodes = 1024

// nodeMask returns the set_mempolicy nodemask for the mode and nodes
// as 64-bit words. The mask is nil for modes without nodes.
func nodeMask(mode Mode, nodes []int) ([]uint64, error) {
	needsNodes := mode != Default && mode != Local
	if needsNodes && len(nodes) == 0 {
		return nil, fmt.Errorf("mode %s requires nodes", mode)
	}
	if !needsNodes && len(nodes) > 0 {
		return nil, fmt.Errorf("mode %s does not take nodes", mode)
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	maxNode := 0
	for _, node := range nodes {
		if node < 0 || node >= maxNodes {
			return nil, fmt.Errorf("invalid node %d", node)
		}
		maxNode = max(maxNode, node)
	}
	mask := make([]uint64, maxNode/64+1)
	for _, node := range nodes {
		mask[node/64] |= 1 << (node % 64)
	}
	return mask, nil
}

// ValidateNumaNodes returns an error if any of the nodes does not
// exist in /sys/devices/system/node.
func ValidateNumaNodes(nodes []int) error {
	for _, node := range nodes {
		path := "/sys/devices/system/node/node" + strconv.Itoa(node)
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("NUMA node %d does not exist: %w", node, err)
		}
	}
	return nil
}
