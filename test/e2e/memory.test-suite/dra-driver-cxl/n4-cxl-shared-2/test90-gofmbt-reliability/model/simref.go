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

// The simulated SUT with the independent reference of the pool side
// (refpool.go): the pool facts of every observation (pool pods' claims,
// allocation, Attached, binding and node; attachments; pool slices;
// controllers) are the reference's, never the model's. The node side
// (regions, stacks, state files, fencing, env) still comes from the
// model's truth, which is the outcome of the model's settle closest to
// the reference, resolved by it. Where no outcome of the model fits the
// reference, the observation shows the reference's facts anyway and the
// oracle has to say so: that is a disagreement.

import (
	"fmt"
	"time"
)

// refEpoch is the wall time of the reference's clock 0.
var refEpoch = time.Unix(1800000000, 0)

// withRef gives the simulated SUT the reference of the pool side.
func (s *sim) withRef(seed int64) *sim {
	s.ref = newRefPool(s.cfg, seed)
	return s
}

// refWall is the reference's virtual clock as wall time.
func (s *sim) refWall() time.Time { return refEpoch.Add(time.Duration(s.ref.Now()) * time.Millisecond) }

// freesClaim: the action deletes a pod whose claim that is not a pool
// claim is allocated (its deallocation requeues pending pods).
func freesClaim(st *State, a Act) bool {
	if a.Verb != VDelete {
		return false
	}
	sl := st.slot(int(a.Slot))
	ss := &st.Slots[a.Slot]
	return sl.Kind.claimed() && !sl.Kind.pooled() && ss.Phase != Pending && ss.Phase != Absent
}

// releasesPLease: the action released the persistent lease of a plse
// slot (its companion goes).
func releasesPLease(from, to *State, i int) bool {
	if i < 0 || from.slot(i).Kind != KPlse {
		return false
	}
	f, t := from.Slots[i].Lease, to.Slots[i].Lease
	return (f == LeaseHeld || f == LeaseBusy) && t == LeaseReleasing && from.Slots[i].LeaseMode.persistent()
}

// refPoll advances the reference to the poll of a settle (bash observes
// about 0.5 s after the step, then every MBT_POLL 3 s) and resolves the
// prediction against it.
func (s *sim) refPoll(poll int) {
	gap := int64(3000)
	if poll == 1 {
		gap = s.ref.rnd(400, 900)
	}
	s.ref.advance(s.ref.now + gap)
	if s.pend != nil {
		s.truth = s.resolveRef(s.pend)
	}
}

// refMismatch counts the pool facts in which a settled outcome of the
// model differs from the reference.
func (s *sim) refMismatch(st *State) int {
	r := s.ref
	n := 0
	for i := range st.Slots {
		sl := st.slot(i)
		if !sl.Kind.pooled() {
			continue
		}
		ss := &st.Slots[i]
		rp := r.pod(i)
		ph := rp.phase()
		if rp != nil && rp.gen != ss.Gen {
			n++
			continue
		}
		nodeOK := rp == nil || !rp.alloc || ss.Node == VMAny || ss.Node == rp.node
		switch ss.Phase {
		case Absent:
			if ph != rpNone || r.deletingPod(i) != nil {
				n++
			}
		case Running, Blocked, Unblocking:
			if ph != rpBound || !nodeOK {
				n++
			}
		case Attaching:
			if ph != rpAlloc || !nodeOK {
				n++
			}
		case Either:
			if ph != rpAlloc && ph != rpBound || !nodeOK {
				n++
			}
			// its prepare was optional: the outcome with its region
			// iff it is bound
			if si, key, ok := st.userRegion(int16(i)); ok && st.Stacks[si].contains(key) != (ph == rpBound) && !s.otherUser(st, i, si, key) {
				n++
			}
		case Pending, Unsched:
			if ph != rpUnalloc {
				n++
			}
		case Stalled:
			if ph == rpNone || !nodeOK {
				n++
			}
		default:
			n++
		}
	}
	for p := Pool(0); p < nPools; p++ {
		c := &st.Ctrl[p]
		rc := &r.ctrl[p]
		if c.Up != rc.running {
			n++
		}
		if (c.Slices == SlicesPresent) != rc.slices || c.Slices == SlicesUnknown {
			n++
		}
		for d, dev := range poolDevs(p) {
			for v := VM(0); v < nVMs; v++ {
				got := r.attState(dev, v)
				switch c.Att[d][v] {
				case TriYes:
					if got != "attached" {
						n++
					}
				case TriNo:
					if got != "" {
						n++
					}
				case TriMaybe:
					if got != "attached" && got != "" {
						n++
					}
				}
			}
		}
	}
	return n
}

// otherUser: another settled user of a region on the stack holds it.
func (s *sim) otherUser(st *State, i, si int, key RKey) bool {
	for j := range st.Slots {
		if j == i {
			continue
		}
		ph := st.Slots[j].Phase
		if ph != Running && ph != Restarting && ph != Unblocking {
			continue
		}
		if sj, kj, ok := st.userRegion(int16(j)); ok && sj == si && kj == key {
			return true
		}
	}
	return false
}

// resolveRef returns the outcome of a settle's prediction that fits the
// reference best, with what the model leaves open decided by the
// reference (the pool facts) or at random (the node side).
func (s *sim) resolveRef(pred *State) *State {
	r := s.ref
	cands := append([]*State{pred}, pred.Alts...)
	var best []*State
	bestN := -1
	for _, c := range cands {
		n := s.refMismatch(c)
		switch {
		case bestN < 0 || n < bestN:
			best, bestN = []*State{c}, n
		case n == bestN:
			best = append(best, c)
		}
	}
	n := best[s.rng.Intn(len(best))].clone()
	for i := range n.Slots {
		ss := &n.Slots[i]
		sl := n.slot(i)
		if !sl.Kind.pooled() {
			continue
		}
		rp := r.pod(i)
		ph := rp.phase()
		if ph == rpAlloc && rp.attached {
			// PreBind binds it at its next poll: as bound
			ph = rpBound
		}
		if rp != nil && rp.alloc && ss.Node == VMAny && (ph == rpBound || ss.Phase == Either) {
			ss.Node = rp.node
		}
		switch ss.Phase {
		case Either:
			switch {
			case ph != rpBound:
				ss.Phase = Attaching
			case ss.Refuse:
				ss.Phase = Refused
			default:
				ss.Phase = Running
			}
		case Stalled:
			if ph != rpAlloc && ph != rpBound {
				break
			}
			// promoted (A19)
			n.setUnblockAt(i, 0)
			switch {
			case !n.Ctrl[sl.Pool].Up && ph == rpAlloc:
				ss.Phase = Attaching
			case ph == rpBound:
				if ss.Node == VMAny {
					ss.Node = rp.node
				}
				ss.Phase = Running
				// its Prepare: the region, unless a hole is in
				// the way (A9)
				if si, key, ok := n.userRegion(int16(i)); ok && !n.Stacks[si].contains(key) {
					switch {
					case n.Stacks[si].hasHole() && sl.Kind != KPBad:
						ss.Phase = Blocked
					case ss.Refuse:
					default:
						n.Stacks[si].push(key)
					}
				}
				if ss.Refuse && ss.Phase == Running {
					ss.Phase = Refused
				}
			}
		}
	}
	// a binding timeout handed the device of a claim waiting for the
	// attach to its waiter
	for i := range n.Slots {
		sl := n.slot(i)
		if n.Slots[i].Phase != Attaching || !sl.Kind.pooled() || r.pod(i).phase() != rpUnalloc {
			continue
		}
		if w := n.waiter(sl.Res); w >= 0 && r.pod(w).phase() != rpUnalloc && r.pod(w).phase() != rpNone {
			n.Slots[i].Phase, n.Slots[w].Phase = Pending, Attaching
		}
	}
	for i := range n.Slots {
		ss := &n.Slots[i]
		if ss.Phase == Unblocking && s.rng.Intn(2) == 0 {
			ss.Phase = Running
			n.setUnblockAt(i, 0)
			if si, key, ok := n.userRegion(int16(i)); ok && !n.Stacks[si].contains(key) {
				n.Stacks[si].push(key)
			}
		}
		if ss.Steer == SteerAny && ss.Phase == Running {
			if s.rng.Intn(2) == 0 {
				ss.Steer = SteerOn
			} else {
				ss.Steer = SteerOff
			}
		}
	}
	for p := Pool(0); p < nPools; p++ {
		if n.Ctrl[p].Up {
			n.deriveAtt(p)
		}
	}
	s.refAtts(n)
	for v := VM(0); v < nVMs; v++ {
		d := &n.Drv[v]
		if d.Pod == "" || d.PodBefore != "" {
			d.Pod = fmt.Sprintf("nri-dra-driver-cxl-%s-%d", v, d.PodGen)
			d.PodBefore = ""
		}
	}
	n.growFence()
	// a namespace that the truth leaves maybe was not made if the
	// reference let no writer of the device prepare (fuzz, pmem seeds
	// 9442, 9762: the truth's own window had the writer's Prepare that
	// the reference never allowed)
	for x := range n.PDev {
		if pd := &n.PDev[x]; pd.NS == TriMaybe && s.prev != nil && !s.refWriterPrepared(n, cPmem0+DevID(x)) {
			p := &s.prev.PDev[x]
			pd.NS, pd.LsaSha, pd.HeadSha = p.NS, p.LsaSha, p.HeadSha
		}
	}
	s.fixPDev(n)
	for v := range n.Drv {
		n.Drv[v].KillAt, n.Drv[v].KillAtAt = 0, 0
	}
	return n
}

// refWriterPrepared: the reference may have let a writer of device d
// prepare (its claim attached or its pod bound, also a deleted one), or
// a pbw lease is in the state.
func (s *sim) refWriterPrepared(n *State, d DevID) bool {
	r := s.ref
	for i := range n.Slots {
		sl := n.slot(i)
		if sl.Kind == KPlse && n.Slots[i].LeaseMode == ModePBW {
			return true
		}
		if !sl.Kind.writer() || sl.Dev != d {
			continue
		}
		if p := r.pod(i); p != nil && (p.attached || p.bound) {
			return true
		}
		for _, p := range r.old {
			if p.slot == i && (p.attached || p.bound) {
				return true
			}
		}
	}
	return false
}

// refAtts sets the attachments of a state to the reference's (attached
// and detaching ones have their memdev in the VM).
func (s *sim) refAtts(st *State) {
	for p := Pool(0); p < nPools; p++ {
		for d, dev := range poolDevs(p) {
			for v := VM(0); v < nVMs; v++ {
				switch s.ref.attState(dev, v) {
				case "attached", "detaching":
					st.Ctrl[p].Att[d][v] = TriYes
				default:
					st.Ctrl[p].Att[d][v] = TriNo
				}
			}
		}
	}
}

// refOverride puts the reference's pool facts into an observation.
func (s *sim) refOverride(o *Observation) {
	r := s.ref
	t, f := true, false
	var pods []ObsPod
	seen := map[int]bool{}
	for _, p := range o.Pods {
		i := s.cfg.slotIndex(p.Slot)
		if i < 0 || !s.cfg.Slots[i].Kind.pooled() {
			pods = append(pods, p)
			continue
		}
		sl := &s.cfg.Slots[i]
		rp := r.pod(i)
		if rp == nil || int(rp.gen) != p.Gen {
			// the reference has no such pod (any more)
			continue
		}
		seen[i] = true
		claim := &ObsClaim{Name: p.Name + "-c0", UID: claimUID(sl, rp.gen)}
		switch rp.phase() {
		case rpUnalloc, rpAlloc:
			p.Phase, p.Ready, p.Node, p.Waiting, p.Event, p.Events = "Pending", false, nil, nil, nil, nil
			p.Unschedulable = rp.unsched && !rp.alloc
			delete(o.Inspect, sl.Name)
			if rp.alloc {
				claim.Allocated = true
				claim.Devices = []ObsClaimDevice{{Driver: "cxl-pool.nri.io", Pool: "pool-" + sl.Pool.String(), Device: devices[sl.Dev].Name}}
				if rp.attached {
					claim.Attached = &t
				} else {
					claim.Attached = &f
				}
			}
		case rpBound:
			node := rp.node.String()
			if p.Node == nil {
				// the model has it not bound: as the reference says
				p.Phase, p.Ready, p.Unschedulable = "Running", true, false
			}
			p.Node = &node
			claim.Allocated, claim.Attached = true, &t
			claim.Devices = []ObsClaimDevice{{Driver: "cxl-pool.nri.io", Pool: "pool-" + sl.Pool.String(), Device: devices[sl.Dev].Name}}
		}
		p.Claim = claim
		pods = append(pods, p)
	}
	for i := range s.cfg.Slots {
		sl := &s.cfg.Slots[i]
		if !sl.Kind.pooled() {
			continue
		}
		if rp := r.pod(i); rp != nil && !seen[i] {
			// a pod the model's truth does not have
			p := ObsPod{Slot: sl.Name, Name: podName(sl, rp.gen), UID: podUID(sl, rp.gen), Gen: int(rp.gen), Phase: "Pending", Unschedulable: rp.unsched && !rp.alloc,
				Claim: &ObsClaim{Name: podName(sl, rp.gen) + "-c0", UID: claimUID(sl, rp.gen), Allocated: rp.alloc}}
			if rp.bound {
				node := rp.node.String()
				p.Phase, p.Ready, p.Node = "Running", true, &node
			}
			pods = append(pods, p)
		}
		if dp := r.deletingPod(i); dp != nil {
			p := ObsPod{Slot: sl.Name, Name: podName(sl, dp.gen), UID: podUID(sl, dp.gen), Gen: int(dp.gen), Phase: "Pending", Deleting: true}
			if dp.bound {
				node := dp.node.String()
				p.Phase, p.Node = "Running", &node
			}
			pods = append(pods, p)
		}
	}
	o.Pods = pods
	for p := Pool(0); p < nPools; p++ {
		var list []ObsAttachment
		for _, a := range o.Attachments[p.String()] {
			if !k8sOwned(&a) {
				list = append(list, a)
			}
		}
		for _, a := range r.atts {
			if devices[a.dev].Pool == p {
				list = append(list, ObsAttachment{Device: devices[a.dev].Name, Host: a.host.String(), State: a.state, Exclusive: a.excl, Owner: "k8s:resourceclaim/x"})
			}
		}
		o.Attachments[p.String()] = list
		if r.ctrl[p].running {
			o.Controllers[p.String()] = "active"
		} else {
			o.Controllers[p.String()] = "failed"
		}
		if _, ok := o.PoolSlices[p.String()]; ok {
			list := []ObsPoolSlice{}
			if r.ctrl[p].slices {
				var nodes []string
				for _, v := range poolHosts[p] {
					nodes = append(nodes, v.String())
				}
				list = append(list, ObsPoolSlice{Name: "pool-" + p.String() + "-slice", Nodes: nodes})
			}
			o.PoolSlices[p.String()] = list
		}
	}
}
