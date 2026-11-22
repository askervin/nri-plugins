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
)

// ErrUnsupported is returned by SetMemoryPolicy on platforms without
// an injection implementation.
var ErrUnsupported = errors.New("memory policy injection is not supported on this platform")

// maxNodes is the limit of the node IDs in a nodemask.
const maxNodes = 1024

// nodeMask returns the set_mempolicy nodemask of the nodes as 64-bit
// words.
func nodeMask(nodes []int) ([]uint64, error) {
	if len(nodes) == 0 {
		return nil, errors.New("no nodes")
	}
	maxNode := 0
	for _, node := range nodes {
		if node < 0 || node >= maxNodes {
			return nil, fmt.Errorf("invalid NUMA node %d", node)
		}
		maxNode = max(maxNode, node)
	}
	mask := make([]uint64, maxNode/64+1)
	for _, node := range nodes {
		mask[node/64] |= 1 << (node % 64)
	}
	return mask, nil
}
