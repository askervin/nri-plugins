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
	e.last, e.observed = snap, e.started
	e.qmu.Unlock()
	if prev != nil {
		lines := UnknownTransitions(prev, snap)
		for _, line := range lines {
			klog.V(4).Info(UnknownTransition + line)
		}
		e.addUnknown(lines)
	}
	e.logHollow(snap)
	return snap, nil
}

// unknownKept is how many of the latest unknown changes of kernel objects
// the engine keeps until UnknownSeen.
const unknownKept = 32

// addUnknown keeps the unknown changes lines, the latest unknownKept of
// them.
func (e *Engine) addUnknown(lines []string) {
	if len(lines) == 0 {
		return
	}
	e.qmu.Lock()
	defer e.qmu.Unlock()
	e.unknown = append(e.unknown, lines...)
	if n := len(e.unknown) - unknownKept; n > 0 {
		e.unknown = slices.Delete(e.unknown, 0, n)
	}
}

// UnknownSeen returns the changes of kernel objects that no row of their
// tables has that Observe logged since the last call (the latest
// unknownKept of them), and forgets them.
func (e *Engine) UnknownSeen() []string {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	out := e.unknown
	e.unknown = nil
	return out
}

// requestKey is the key of the engine of a request in its context.
type requestKey struct{}

// Request marks a request of a front-end in progress (a Prepare or an
// Unprepare of a claim, whose calls of the engine get the context that it
// returns) until the function that it returns is called. The invariants of
// the records and the kernel hold between requests: at the end of a request
// they are logged at klog V(4) ("engine invariant: ...") when no other
// request is in progress. A call of PrepareGrants or ReleaseGrants outside
// a request is a request of its own.
func (e *Engine) Request(ctx context.Context) (context.Context, func()) {
	if ctx.Value(requestKey{}) == e {
		return ctx, func() {}
	}
	e.qmu.Lock()
	e.running++
	e.started++
	seq := e.started
	e.qmu.Unlock()
	return context.WithValue(ctx, requestKey{}, e), func() {
		e.checkBetween(seq)
		e.qmu.Lock()
		e.running--
		e.qmu.Unlock()
	}
}

// checkBetween logs the violations of the invariants at the end of the
// request seq at klog V(4), by the latest observation of the kernel, when no
// other request is in progress or starts meanwhile and the request observed
// the kernel (the observation is of its end).
func (e *Engine) checkBetween(seq int) {
	if !klog.V(4).Enabled() {
		return
	}
	e.qmu.Lock()
	snap, started, others, observed := e.last, e.started, e.running-1, e.observed
	e.qmu.Unlock()
	switch {
	case snap == nil || observed < seq:
		return
	case others > 0:
		klog.V(5).Infof("engine: invariants not checked: %d other requests in progress", others)
		return
	}
	violations := e.Check(snap, e.opts.Sources, nil)
	e.qmu.Lock()
	again := e.started != started || e.running > 1
	e.qmu.Unlock()
	if again {
		klog.V(5).Info("engine: invariants not checked: another request started")
		return
	}
	for _, v := range violations {
		klog.V(4).Info("engine invariant: " + v.String())
	}
}

// verify is the verify step after a Prepare or a release of grants: a new
// observation (Observe), the FOREIGN records of the regions that are gone
// removed, and the objects of the grants refs that are REALISED checked in
// it (an error logged for one that does not verify). The end of the
// request checks the invariants (Request).
func (e *Engine) verify(ctx context.Context, refs []state.GrantRef, trigger state.Trigger) {
	snap, err := e.Observe(ctx)
	if err != nil {
		klog.Errorf("engine: observing the kernel: %v", err)
		return
	}
	if err := e.forgetGoneForeign(ctx, snap, trigger); err != nil {
		klog.Errorf("engine: %v", err)
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
