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
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	MiB int64 = 1024 * 1024
	GiB       = 1024 * MiB
)

// nm constructs a NodeMem from a usage list for use in tests.
// The index in the list is the node number and the value is its usage.
func nm(usage ...int64) *NodeMem {
	m := make(map[int]int64, len(usage))
	for node, u := range usage {
		m[node] = u
	}
	return &NodeMem{nodeMem: m}
}

func TestInterestingNextSteps(t *testing.T) {
	t.Run("all-in one lagging node", func(t *testing.T) {
		// n0: pwp→nwp increase, ctp→nwp flat already there
		// n1: pwp→nwp flat, ctp→nwp a lot behind (n1 needs to grow)
		// n2: pwp→nwp flat, ctp→nwp flat
		// n3: pwp→nwp big increase, ctp→nwp tiny increase (n3 has no urgency to grow)
		pwp := nm(00*GiB, 10*GiB, 20*GiB, 0*GiB)
		nwp := nm(10*GiB, 10*GiB, 20*GiB, 30*GiB)
		ctp := nm(10*GiB, 7*GiB, 20*GiB, 29*GiB)
		nextNodes, nextLimit, err := nextStep(ctp, pwp, nwp, 1*GiB, 4*GiB)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		require.Equal(t, nextNodes, []int{1}, "nextNodes should increase usage only on node1")
		require.Equal(t, nextLimit, 3*GiB)

	})

	t.Run("split on two lagging nodes", func(t *testing.T) {
		// n0: pwp→nwp increase, ctp→nwp flat already there
		// n1: pwp→nwp flat, ctp→nwp a lot behind (n1 needs to grow)
		// n2: pwp→nwp flat, ctp→nwp flat
		// n3: pwp→nwp big increase, ctp→nwp tiny increase (n3 has no urgency to grow)
		pwp := nm(00*GiB, 10*GiB, 20*GiB, 0*GiB)
		nwp := nm(10*GiB, 10*GiB, 20*GiB, 30*GiB)
		ctp := nm(10*GiB, 8*GiB, 20*GiB, 29*GiB)
		nextNodes, nextLimit, err := nextStep(ctp, pwp, nwp, 1*GiB, 4*GiB)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		require.Equal(t, nextNodes, []int{1, 3}, "nextNodes should fill node3 and bring node1 to 9 GiB")
		require.Equal(t, nextLimit, 2*GiB)

	})
}

func TestNextSteps(t *testing.T) {
	// Implement me
}
