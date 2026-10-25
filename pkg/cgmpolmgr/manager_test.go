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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeNodes makes a sysfs with the nodes of has_normal_memory and the
// distances of node 3 (a movable-only CXL node).
func writeNodes(t *testing.T, normal, distance3 string) string {
	root := t.TempDir()
	dir := filepath.Join(root, "devices", "system", "node")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "node3"), 0o755))
	if normal != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "has_normal_memory"), []byte(normal+"\n"), 0o644))
	}
	if distance3 != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "node3", "distance"), []byte(distance3+"\n"), 0o644))
	}
	return root
}

func TestNormalMemoryFallback(t *testing.T) {
	for _, tc := range []struct {
		name      string
		normal    string
		distance3 string
		allowed   []int
		node      int
		ok        bool
	}{
		{"only movable node allowed: nearest normal node", "0-2", "17 14 15 10", []int{3}, 1, true},
		{"equal distances: lowest normal node", "0-2", "14 14 14 10", []int{3}, 0, true},
		{"no distances: lowest normal node", "1-2", "", []int{3}, 1, true},
		{"a normal node allowed already", "0-2", "17 14 15 10", []int{2, 3}, 0, false},
		{"has_normal_memory unknown", "", "17 14 15 10", []int{3}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeNodes(t, tc.normal, tc.distance3)
			allowed := map[int]bool{}
			for _, n := range tc.allowed {
				allowed[n] = true
			}
			node, ok := normalMemoryFallback(root, allowed, 3)
			require.Equal(t, tc.ok, ok)
			if ok {
				require.Equal(t, tc.node, node)
			}
		})
	}
}

func TestAllowNodesFirstWrite(t *testing.T) {
	cg := t.TempDir()
	mems := filepath.Join(cg, "cpuset.mems")
	m := &Manager{
		cgroupPath: cg,
		sysRoot:    writeNodes(t, "0-1", ""),
		name:       "test",
		log:        log,
		// the cgroup holds memory on its DRAM nodes already
		allowed: map[int]bool{0: true, 1: true},
	}
	// the first step adds no node and still confines the cgroup
	require.NoError(t, m.allowNodes([]int{0, 1}))
	data, err := os.ReadFile(mems)
	require.NoError(t, err)
	require.Equal(t, "0-1\n", string(data))
	// a later step that adds no node writes nothing
	require.NoError(t, os.WriteFile(mems, []byte("unchanged\n"), 0o644))
	require.NoError(t, m.allowNodes([]int{1}))
	data, err = os.ReadFile(mems)
	require.NoError(t, err)
	require.Equal(t, "unchanged\n", string(data))
	// a step that adds a node writes all of them
	require.NoError(t, m.allowNodes([]int{2}))
	data, err = os.ReadFile(mems)
	require.NoError(t, err)
	require.Equal(t, "0-2\n", string(data))
}

// TestRelease removes the memory.high that a killed manager left, leaves
// max as it is and creates no file.
func TestRelease(t *testing.T) {
	cg := t.TempDir()
	high := filepath.Join(cg, "memory.high")
	readHigh := func() string {
		data, err := os.ReadFile(high)
		require.NoError(t, err)
		return string(data)
	}

	require.NoError(t, os.WriteFile(high, []byte("140668928\n"), 0o644))
	was, err := Release(cg)
	require.NoError(t, err)
	require.Equal(t, "140668928", was)
	require.Equal(t, "max\n", readHigh())

	// max already (a manager stopped gracefully): nothing to write
	require.NoError(t, os.WriteFile(high, []byte("max\n"), 0o444))
	was, err = Release(cg)
	require.NoError(t, err)
	require.Equal(t, "", was)
	require.Equal(t, "max\n", readHigh())

	// a cgroup without memory.high, or gone
	require.NoError(t, os.Remove(high))
	_, err = Release(cg)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(high)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = Release(filepath.Join(cg, "gone"))
	require.ErrorIs(t, err, os.ErrNotExist)
}
