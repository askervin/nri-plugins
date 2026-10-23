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
