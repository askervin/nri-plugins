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

// Fenced nodes (containerMemory allowed-mems): the NUMA nodes on which the
// driver onlines CXL memory, numa slices of local memdevs and pool devices
// in mode numa. A container that cgmpolmgr does not steer has a fenced
// node in cpuset.mems only when it claimed memory on it or borrows it
// (wantMems, lend.go). The set starts from the prepared claims and only
// grows. A node is fenced before its memory goes online: Fence returns
// after the containers have been updated through NRI.
//
// Locking: f.mu protects the set and is never held while calling out.
// f.fenceMu serializes Fence across the check, the add and the pass, so
// that every Fence of a node returns after the pass that fenced it. Fence
// is called with the lock of the local allocator or the pool driver held;
// the pass that it runs takes lendMu and p.mu of the NRI plugin
// (lend.go), which never wait for those locks or for f.fenceMu. Lock
// order: f.fenceMu, lendMu, p.mu, f.mu.

import (
	"context"
	"sync"

	"k8s.io/klog/v2"
	"k8s.io/utils/cpuset"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// fenceApplier keeps the containers off the fenced nodes.
type fenceApplier interface {
	// fenceContainers updates cpuset.mems of the containers whose memory
	// nodes the fenced nodes change, once fencing of running containers
	// is ready.
	fenceContainers(ctx context.Context)
}

// nodeFence is the set of fenced nodes. A nil nodeFence is
// containerMemory none: it fences nothing.
type nodeFence struct {
	fenceMu sync.Mutex // serializes Fence
	mu      sync.Mutex
	nodes   cpuset.CPUSet
	applier fenceApplier // nil until NRI runs
	noNRI   bool         // NRI did not start
}

// newNodeFence returns the fenced nodes of containerMemory mode, nil for
// a mode that fences nothing.
func newNodeFence(mode string) *nodeFence {
	if mode != containerMemoryAllowedMems {
		return nil
	}
	return &nodeFence{nodes: cpuset.New()}
}

// mode returns the containerMemory mode of the fence.
func (f *nodeFence) mode() string {
	if f == nil {
		return containerMemoryNone
	}
	return containerMemoryAllowedMems
}

// Nodes returns the fenced nodes.
func (f *nodeFence) Nodes() cpuset.CPUSet {
	if f == nil {
		return cpuset.New()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nodes
}

// Fence adds node to the fenced nodes and updates the containers through
// NRI. Adding a fenced node does nothing, after the update by the Fence
// that added it. Before fencing of running containers is ready, and
// without NRI, the node is only recorded.
func (f *nodeFence) Fence(ctx context.Context, node int) {
	if f == nil || node < 0 {
		return
	}
	f.fenceMu.Lock()
	defer f.fenceMu.Unlock()
	f.mu.Lock()
	if f.nodes.Contains(node) {
		f.mu.Unlock()
		return
	}
	f.nodes = f.nodes.Union(cpuset.New(node))
	nodes, applier, noNRI := f.nodes, f.applier, f.noNRI
	f.mu.Unlock()

	klog.Infof("NRI fence: fencing CXL node %d (fenced nodes %s)", node, nodes)
	if noNRI {
		klog.Warningf("NRI fence: NRI not connected, containers are not fenced from CXL node %d", node)
		return
	}
	if applier != nil {
		applier.fenceContainers(ctx)
	}
}

// seed adds the nodes to the fenced nodes without updating containers.
func (f *nodeFence) seed(nodes cpuset.CPUSet) {
	if f == nil || nodes.IsEmpty() {
		return
	}
	klog.Infof("NRI fence: fencing CXL nodes %s of prepared claims", nodes)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes = f.nodes.Union(nodes)
}

// setApplier sets what updates the containers when a node is fenced.
func (f *nodeFence) setApplier(a fenceApplier) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applier = a
}

// setNoNRI records that NRI did not start: containers are not fenced.
func (f *nodeFence) setNoNRI() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noNRI = true
}

// preparedNodes returns the NUMA nodes on which prepared claims of both
// drivers have memory that the driver onlined: numa slices of local
// memdevs and pool devices in mode numa.
func preparedNodes(state *nodeState, pool *poolDriver) cpuset.CPUSet {
	nodes := cpuset.New(pool.numaNodes()...)
	if state == nil || state.baseState == nil {
		return nodes
	}
	state.Lock()
	defer state.Unlock()
	for _, info := range state.preparedClaims {
		if info == nil {
			continue
		}
		for _, d := range info.Devices {
			if d.DeviceType == device.DeviceTypeMemdev && d.Mode == api.ModeNUMA {
				nodes = nodes.Union(cpuset.New(nonNegative(d.NUMANodes)...))
			}
		}
	}
	return nodes
}

// nonNegative returns the nodes that are not negative.
func nonNegative(nodes []int) []int {
	out := make([]int, 0, len(nodes))
	for _, n := range nodes {
		if n >= 0 {
			out = append(out, n)
		}
	}
	return out
}
