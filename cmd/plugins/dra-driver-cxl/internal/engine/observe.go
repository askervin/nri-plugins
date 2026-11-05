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

package engine

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/fsm"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// UnknownTransition is the start of the debug log line of an observed
// change of a kernel object that is not a row of its table.
const UnknownTransition = "kernel transition not in table: "

// Observe returns a new observation of the kernel objects. A region of
// ours that is hollow is logged once per process with the command that
// deletes it. Every change of the state of a kernel object since the last
// observation of the engine that its table does not have is logged at klog
// V(4) (UnknownTransition); it is never an error.
func (e *Engine) Observe(ctx context.Context) (*kernel.Snapshot, error) {
	snap, err := e.k.Observe(ctx)
	if err != nil {
		return nil, err
	}
	e.qmu.Lock()
	prev := e.last
	e.last = snap
	e.qmu.Unlock()
	if prev != nil {
		for _, line := range UnknownTransitions(prev, snap) {
			klog.V(4).Info(UnknownTransition + line)
		}
	}
	e.logHollow(snap)
	return snap, nil
}

// verify is the verify step after a Prepare or a release of grants: a new
// observation (Observe), the objects of the grants refs that are REALISED
// checked in it (an error logged for one that does not verify), and at
// klog V(4) every invariant of the records and the kernel ("engine
// invariant: ...").
func (e *Engine) verify(ctx context.Context, refs []state.GrantRef) {
	snap, err := e.Observe(ctx)
	if err != nil {
		klog.Errorf("engine: observing the kernel: %v", err)
		return
	}
	c := &checker{r: e.records(), s: snap, opts: CheckOptions{Sources: e.opts.Sources}, inv: "I3"}
	for _, ref := range refs {
		if g := c.r.Grant(ref); g != nil && g.State == state.GrantRealised {
			checkI3Grant(c, g)
		}
	}
	for _, v := range c.out {
		klog.Errorf("engine: a grant does not verify: %s", v)
	}
	if !klog.V(4).Enabled() {
		return
	}
	for _, v := range e.Check(snap, e.opts.Sources, nil) {
		klog.V(4).Info("engine invariant: " + v.String())
	}
}

// logHollow logs each hollow region of ours of the snapshot once per
// process, with the command that deletes it.
func (e *Engine) logHollow(snap *kernel.Snapshot) {
	r := e.records()
	for _, ri := range snap.Regions {
		if ri.State != kernel.RegionHollow {
			continue
		}
		reg := r.Region(state.RegionRef(ri.Name))
		if reg == nil || !reg.Ours() {
			continue
		}
		e.qmu.Lock()
		logged := e.hollowLogged[ri.Name]
		e.hollowLogged[ri.Name] = true
		e.qmu.Unlock()
		if logged {
			continue
		}
		decoder := ri.RootDecoder
		if decoder == "" {
			decoder = "<its root decoder>"
		}
		klog.Warningf("engine: %s is hollow (NUMA node %d): it is deleted when its memory blocks are offline: echo %s > /sys/bus/cxl/devices/%s/delete_region",
			ri.Name, ri.NumaNode, ri.Name, decoder)
	}
}

// UnknownTransitions returns the changes of the states of the kernel
// objects from prev to cur that the kernel's tables do not have, in words:
// "<table> <object>: FROM -> TO: transition not in the table".
func UnknownTransitions(prev, cur *kernel.Snapshot) []string {
	var out []string
	add := func(name string, err error) {
		if err != nil {
			out = append(out, name+": "+err.Error())
		}
	}
	memdevs := map[uint64][2]kernel.MemdevState{}
	for _, m := range prev.Memdevs {
		memdevs[m.Serial] = [2]kernel.MemdevState{m.State, kernel.MemdevAbsent}
	}
	for _, m := range cur.Memdevs {
		s, ok := memdevs[m.Serial]
		if !ok {
			s[0] = kernel.MemdevAbsent
		}
		s[1] = m.State
		memdevs[m.Serial] = s
	}
	for _, serial := range sortedKeys(memdevs) {
		s := memdevs[serial]
		add(fmt.Sprintf("memdev 0x%x", serial), kernel.MemdevTransitions.Check(s[0], s[1], fsm.AnyTrigger))
	}
	diff(&out, "region", kernel.RegionTransitions, kernel.RegionAbsent, prev.Regions, cur.Regions,
		func(r kernel.RegionInfo) (string, kernel.RegionState) { return r.Name, r.State })
	diff(&out, "dax device", kernel.DaxTransitions, kernel.DaxAbsent, prev.DaxDevices, cur.DaxDevices,
		func(d kernel.DaxDeviceInfo) (string, kernel.DaxState) { return d.Name, d.State })
	diff(&out, "memory block", kernel.BlockTransitions, kernel.BlockAbsent, prev.Blocks, cur.Blocks,
		func(b kernel.MemoryBlock) (string, kernel.BlockState) {
			return "memory" + strconv.Itoa(b.Index), b.State
		})
	diff(&out, "nd region", kernel.NdRegionTransitions, kernel.NdAbsent, prev.Pmem, cur.Pmem,
		func(n kernel.NdRegion) (string, kernel.NdRegionState) { return n.Name, n.State })
	diff(&out, "namespace", kernel.NamespaceTransitions, kernel.NsAbsent, namespaces(prev), namespaces(cur),
		func(n kernel.Namespace) (string, kernel.NamespaceState) { return n.Name, n.State })
	return out
}

// diff adds the changes of the objects from prev to cur that the table does
// not have; an object that is missing has the state absent.
func diff[T any, S comparable](out *[]string, kind string, table kernel.Table[S], absent S, prev, cur []T, key func(T) (string, S)) {
	states := map[string][2]S{}
	for _, o := range prev {
		name, s := key(o)
		states[name] = [2]S{s, absent}
	}
	for _, o := range cur {
		name, s := key(o)
		st, ok := states[name]
		if !ok {
			st[0] = absent
		}
		st[1] = s
		states[name] = st
	}
	for _, name := range sortedKeys(states) {
		st := states[name]
		if err := table.Check(st[0], st[1], fsm.AnyTrigger); err != nil {
			*out = append(*out, kind+" "+name+": "+err.Error())
		}
	}
}

// namespaces returns the namespaces of the nd regions of a snapshot.
func namespaces(s *kernel.Snapshot) []kernel.Namespace {
	var out []kernel.Namespace
	for _, nd := range s.Pmem {
		out = append(out, nd.Namespaces...)
	}
	return out
}

// sortedKeys returns the keys of a map in order.
func sortedKeys[K interface{ ~string | ~uint64 }, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
