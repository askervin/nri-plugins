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

// Actions (04-contract.txt 4): their preconditions and what they change
// in the model. The rules and the code and documents they rest on are in
// plan-13-gofmbt/04-status-MODEL.txt ("Prediction rules").

import (
	"fmt"
	"strings"
)

// Verb is the verb of an action.
type Verb uint8

const (
	VNone Verb = iota
	VSettle
	VCreate
	VDelete
	VCrash
	VWrite
	VRead
	VLeaseGet
	VLeasePut
	VDriverKill
	VDriverRestart
	VCtrlKill
	VCtrlStart
	VCtrlRestart
	VServerRestart
	VKubeletRestart
	VContainerdRestart
	nVerbs
)

var verbNames = [nVerbs]string{"", "settle", "create", "delete", "crash", "write", "read",
	"lease-get", "lease-put", "driver-kill", "driver-restart", "ctrl-kill", "ctrl-start",
	"ctrl-restart", "server-restart", "kubelet-restart", "containerd-restart"}

func (v Verb) String() string { return verbNames[v] }

func parseVerb(s string) (Verb, bool) {
	for v := VSettle; v < nVerbs; v++ {
		if verbNames[v] == s {
			return v, true
		}
	}
	return VNone, false
}

// slotVerb: the verb takes a slot.
func (v Verb) slotVerb() bool { return v >= VCreate && v <= VLeasePut }

// vmFault: the verb is a fault of a VM.
func (v Verb) vmFault() bool {
	return v == VDriverKill || v == VDriverRestart || v == VKubeletRestart || v == VContainerdRestart
}

// poolFault: the verb is a fault of a pool.
func (v Verb) poolFault() bool {
	return v == VCtrlKill || v == VCtrlStart || v == VCtrlRestart || v == VServerRestart
}

func (v Verb) fault() bool { return v.vmFault() || v.poolFault() }

// observes: the step returns an observation that the oracle checks.
func (v Verb) observes() bool { return v == VWrite || v == VRead || v == VLeaseGet }

// Act is an action.
type Act struct {
	Verb Verb
	Slot int16 // slot verbs: the slot index
	VM   VM    // VM faults
	Pool Pool  // pool faults
	Mode LeaseMode
}

// name is the action line (VERB ARGS...).
func (a Act) name(cfg *Config) string {
	switch {
	case a.Verb == VSettle:
		return "settle"
	case a.Verb == VLeaseGet:
		return fmt.Sprintf("lease-get %s %s", cfg.Slots[a.Slot].Name, a.Mode)
	case a.Verb.slotVerb():
		return a.Verb.String() + " " + cfg.Slots[a.Slot].Name
	case a.Verb.vmFault():
		return a.Verb.String() + " " + a.VM.String()
	case a.Verb.poolFault():
		return a.Verb.String() + " " + a.Pool.String()
	}
	return "none"
}

// format is the action format of gofmbt (C3 pairs): the verb and the kind
// family, without the pool, the node and the index.
func (a Act) format(cfg *Config) (string, []any) {
	switch {
	case a.Verb == VSettle:
		return "settle", nil
	case a.Verb.slotVerb():
		sl := &cfg.Slots[a.Slot]
		f := a.Verb.String() + " " + sl.Kind.String()
		args := []any{}
		if sl.Kind.pooled() {
			f += "-%s"
			args = append(args, sl.Pool.String())
		}
		f += "@%s#%d"
		args = append(args, sl.VM.String(), sl.Index)
		if a.Verb == VLeaseGet {
			f += " " + a.Mode.String()
		}
		return f, args
	case a.Verb.vmFault():
		return a.Verb.String() + " %s", []any{a.VM.String()}
	case a.Verb.poolFault():
		return a.Verb.String() + " %s", []any{a.Pool.String()}
	}
	return "none", nil
}

// parseAct parses an action line.
func parseAct(cfg *Config, line string) (Act, error) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return Act{}, fmt.Errorf("empty action")
	}
	v, ok := parseVerb(f[0])
	if !ok {
		return Act{}, fmt.Errorf("unknown verb %q", f[0])
	}
	a := Act{Verb: v, Slot: -1, VM: VMAny, Pool: noPool}
	want := 1
	switch {
	case v == VSettle:
		want = 0
	case v.slotVerb():
		if len(f) < 2 {
			return Act{}, fmt.Errorf("%s: no slot", f[0])
		}
		i := cfg.slotIndex(f[1])
		if i < 0 {
			return Act{}, fmt.Errorf("%s: slot %q is not in profile %s", f[0], f[1], cfg.Profile)
		}
		a.Slot = int16(i)
		if v == VLeaseGet {
			want = 2
			if len(f) < 3 {
				return Act{}, fmt.Errorf("lease-get: no mode")
			}
			switch f[2] {
			case "numa":
				a.Mode = ModeNuma
			case "dax":
				a.Mode = ModeDax
			default:
				return Act{}, fmt.Errorf("lease-get: invalid mode %q", f[2])
			}
		}
	case v.vmFault():
		if len(f) < 2 {
			return Act{}, fmt.Errorf("%s: no VM", f[0])
		}
		vm, err := parseVM(f[1])
		if err != nil || vm == VMAny {
			return Act{}, fmt.Errorf("%s: invalid VM %q", f[0], f[1])
		}
		a.VM = vm
	case v.poolFault():
		if len(f) < 2 {
			return Act{}, fmt.Errorf("%s: no pool", f[0])
		}
		p, err := parsePool(f[1])
		if err != nil {
			return Act{}, fmt.Errorf("%s: %w", f[0], err)
		}
		a.Pool = p
	}
	if len(f) != want+1 {
		return Act{}, fmt.Errorf("%q: %d arguments, want %d", line, len(f)-1, want)
	}
	return a, nil
}

// allActs is every action of the configuration, MBT_AVOID rules left
// out. Faults of pools are those of the pools of the profile.
func allActs(cfg *Config) []Act {
	var acts []Act
	add := func(a Act) {
		if !cfg.avoided(a) {
			acts = append(acts, a)
		}
	}
	add(Act{Verb: VSettle, Slot: -1, VM: VMAny, Pool: noPool})
	for i := range cfg.Slots {
		sl := &cfg.Slots[i]
		for _, v := range []Verb{VCreate, VDelete, VCrash} {
			add(Act{Verb: v, Slot: int16(i), VM: VMAny, Pool: noPool})
		}
		if sl.Kind.dax() {
			add(Act{Verb: VWrite, Slot: int16(i), VM: VMAny, Pool: noPool})
			add(Act{Verb: VRead, Slot: int16(i), VM: VMAny, Pool: noPool})
		}
		if sl.Kind == KLease {
			add(Act{Verb: VLeaseGet, Slot: int16(i), VM: VMAny, Pool: noPool, Mode: ModeNuma})
			add(Act{Verb: VLeaseGet, Slot: int16(i), VM: VMAny, Pool: noPool, Mode: ModeDax})
			add(Act{Verb: VLeasePut, Slot: int16(i), VM: VMAny, Pool: noPool})
		}
	}
	for _, v := range []Verb{VDriverKill, VDriverRestart, VKubeletRestart, VContainerdRestart} {
		for vm := VM(0); vm < nVMs; vm++ {
			add(Act{Verb: v, Slot: -1, VM: vm, Pool: noPool})
		}
	}
	for _, v := range []Verb{VCtrlKill, VCtrlStart, VCtrlRestart, VServerRestart} {
		for _, p := range cfg.poolsUsed() {
			add(Act{Verb: v, Slot: -1, VM: VMAny, Pool: p})
		}
	}
	return acts
}

// avoided tells if an MBT_AVOID rule leaves an action out. A rule is a
// verb ("containerd-restart") or VERB:ARG, where ARG is the first
// argument (a slot, VM or pool), the kind of the slot with or without
// its pool (xnuma-a, xnuma), the VM of the slot, or the mode of a
// lease-get. The verb "settle" cannot be avoided.
func (c *Config) avoided(a Act) bool {
	if a.Verb == VSettle {
		return false
	}
	for _, rule := range c.Avoid {
		verb, arg, hasArg := strings.Cut(strings.TrimSpace(rule), ":")
		if verb != a.Verb.String() {
			continue
		}
		if !hasArg {
			return true
		}
		for _, x := range a.args(c) {
			if x == arg {
				return true
			}
		}
	}
	return false
}

// args are the strings an MBT_AVOID argument may match.
func (a Act) args(c *Config) []string {
	switch {
	case a.Verb.slotVerb():
		sl := &c.Slots[a.Slot]
		xs := []string{sl.Name, sl.KindName(), sl.Kind.String(), sl.VM.String()}
		if a.Verb == VLeaseGet {
			xs = append(xs, a.Mode.String())
		}
		return xs
	case a.Verb.vmFault():
		return []string{a.VM.String()}
	case a.Verb.poolFault():
		return []string{a.Pool.String()}
	}
	return nil
}

// checkAvoid returns an error for rules that match no verb.
func checkAvoid(rules []string) error {
	for _, rule := range rules {
		verb, _, _ := strings.Cut(strings.TrimSpace(rule), ":")
		if _, ok := parseVerb(verb); !ok {
			return fmt.Errorf("--avoid: %q: unknown verb %q", rule, verb)
		}
	}
	return nil
}

// --- preconditions ---

// forced: the number of unsettled operations allows only a settle.
func (s *State) forced() bool { return int(s.Unsettled) >= s.cfg.Unsettled }

// enabled tells if the generator may take an action in the state.
func (s *State) enabled(a Act) bool { return s.next(a) != nil }

// next returns the state after an action that the generator may take,
// nil if it may not: the preconditions (allowed), the limit of unsettled
// operations, and the rules of the decoder stacks (stackRulesOK).
func (s *State) next(a Act) *State {
	if a.Verb == VSettle {
		if s.Unsettled == 0 {
			return nil
		}
		return s.apply(a)
	}
	if s.forced() && a.Verb != VWrite && a.Verb != VRead {
		return nil
	}
	if !s.allowed(a) {
		return nil
	}
	n := s.apply(a)
	if !s.stackRulesOK(a, n) {
		return nil
	}
	return n
}

// stackRulesOK checks what an action does to the decoder stacks (A9):
// nothing on a stack where a pod waits for its retry after its hole
// cleared (but deleting that pod); off-line, every stack has one
// outcome (no race for the order); with --avoid-holes, no outcome
// leaves a new hole.
func (s *State) stackRulesOK(a Act, n *State) bool {
	for _, si := range changedStacks(s.Ev, n.Ev) {
		if si < 0 {
			// an "any" pod: its node is not known yet, every host of
			// its pool may get its region (R3)
			if s.unblockingAnyHost(a) {
				return false
			}
			continue
		}
		if s.unblockingOn(si) && !s.deletesLastUnblocking(a, si) {
			return false
		}
		// a window that clears a hole with pods blocked behind it
		// makes no region: their retries (at kubelet's resync, any
		// time) would race with it for the order (R4, A12)
		for _, o := range n.outcomes(si) {
			if o.Cleared && o.Pushed && (len(o.Blocked) > 0 || s.blockedOn(si)) {
				return false
			}
		}
		if s.cfg.Online && !s.cfg.AvoidHoles {
			continue
		}
		outs := n.outcomes(si)
		if !s.cfg.Online && len(outs) != 1 {
			return false
		}
		if s.cfg.AvoidHoles {
			for _, o := range outs {
				if o.S.holes() > n.Stacks[si].holes() {
					return false
				}
			}
		}
	}
	return true
}

// unblockingAnyHost: the action is on an "any" pod, and a stack of a
// host of its pool has an unblocking pod.
func (s *State) unblockingAnyHost(a Act) bool {
	if !a.Verb.slotVerb() {
		return false
	}
	sl := s.slot(int(a.Slot))
	if !sl.Kind.pooled() {
		return false
	}
	for _, v := range poolHosts[sl.Pool] {
		if s.unblockingOn(stackIndex(v, poolBridge[sl.Pool])) {
			return true
		}
	}
	return false
}

// changedStacks returns the stacks of events that an action added or
// changed (-1 for an unknown node).
func changedStacks(before, after []stackEvent) []int {
	seen := map[int]bool{}
	var out []int
	for j, e := range after {
		if j < len(before) && before[j] == e {
			continue
		}
		if si := int(e.Stack); !seen[si] {
			seen[si] = true
			out = append(out, si)
		}
	}
	return out
}

// deletesLastUnblocking: the action deletes the only unblocking pod of a
// stack, and nothing else is in flight there (its region, if its retry
// made one, is the top: no hole either way).
func (s *State) deletesLastUnblocking(a Act, si int) bool {
	if a.Verb != VDelete || s.Slots[a.Slot].Phase != Unblocking || len(s.eventsOn(si)) > 0 {
		return false
	}
	for i := range s.Slots {
		if i != int(a.Slot) && s.Slots[i].Phase == Unblocking {
			if ssi, _, ok := s.userRegion(int16(i)); ok && ssi == si {
				return false
			}
		}
	}
	return true
}

// leaseRegionOK: a lease slice of a VM gets its region now: nothing in
// flight on the VM's hb0 stack, and the local region exists or can be
// made (else the lease-get would fail after its --wait).
func (s *State) leaseRegionOK(v VM) bool {
	si := stackIndex(v, HB0)
	if len(s.eventsOn(si)) > 0 || s.unblockingOn(si) {
		return false
	}
	st := &s.Stacks[si]
	return st.contains(rkLocal) || !st.hasHole()
}

// allowed tells if an action may be taken in the state when the limit of
// unsettled operations is not applied (the teardown, and replays of it).
// A settle is always allowed.
func (s *State) allowed(a Act) bool {
	if a.Verb == VSettle {
		return true
	}
	if a.Verb.slotVerb() {
		return s.slotEnabled(a)
	}
	switch a.Verb {
	case VDriverKill, VContainerdRestart:
		// a containerd restart restarts the driver container in
		// place too (contract A8): the same back-off
		d := &s.Drv[a.VM]
		return int(d.Restarts) < s.cfg.MaxRestarts && !d.Killed
	case VDriverRestart:
		return !s.Drv[a.VM].Killed
	case VCtrlKill:
		// off-line, a kill right after a graceful restart would leave
		// open whether the slices came back (A18)
		return s.Ctrl[a.Pool].Up && !s.anyUnknownHolder(a.Pool) && (s.cfg.Online || s.Ctrl[a.Pool].Slices != SlicesUnknown)
	case VCtrlStart:
		return !s.Ctrl[a.Pool].Up
	case VCtrlRestart:
		// not while a claim of the pool is being allocated: it may or
		// may not have been allocated before the slices went (A18)
		return s.Ctrl[a.Pool].Up && !s.poolStarting(a.Pool)
	case VServerRestart, VKubeletRestart:
		return true
	}
	return false
}

func (s *State) slotEnabled(a Act) bool {
	i := int(a.Slot)
	ss := &s.Slots[i]
	sl := s.slot(i)
	switch a.Verb {
	case VCreate:
		if ss.Phase != Absent {
			return false
		}
		if sl.Res == resNone {
			return true
		}
		// a claim that waits for its pool's slices is the only
		// candidate for its device when they are back (A18)
		return s.occ().waiter[sl.Res] < 0 && !s.contested(sl.Res) && !s.unschedHolder(sl.Res)
	case VDelete:
		return ss.Phase != Absent && ss.Phase != Deleting
	case VCrash:
		return ss.Phase == Running && int(ss.Restarts) < s.cfg.MaxRestarts
	case VWrite, VRead:
		return ss.Phase == Running
	case VLeaseGet:
		if ss.Phase != Running || ss.Lease != LeaseNone || s.Drv[sl.VM].Killed {
			return false
		}
		r := localRes(sl.VM)
		o := s.occ()
		return int(o.localAll[sl.VM])+1 <= s.cfg.LocalBlocks[sl.VM] && o.waiter[r] < 0 && !s.contested(r) && s.leaseRegionOK(sl.VM)
	case VLeasePut:
		return ss.Phase == Running && ss.Lease == LeaseHeld && !s.Drv[sl.VM].Killed
	}
	return false
}

// --- state changes ---

// apply returns the state after an enabled action.
func (s *State) apply(a Act) *State {
	n := s.clone()
	n.Steps++
	n.Last = a
	switch a.Verb {
	case VSettle:
		return n.settleAll()
	case VCreate:
		n.create(int(a.Slot))
	case VDelete:
		n.delete(int(a.Slot))
	case VCrash:
		n.crash(int(a.Slot))
	case VWrite:
		n.write(int(a.Slot))
		return n
	case VRead:
		return n
	case VLeaseGet:
		n.leaseGet(int(a.Slot), a.Mode)
	case VLeasePut:
		n.leasePut(int(a.Slot))
	case VDriverKill:
		d := &n.Drv[a.VM]
		d.Restarts++
		d.Inc++
		d.Killed = true
		n.driverRestarted(a.VM, SteerOff)
	case VContainerdRestart:
		// The driver exits on the loss of its NRI connection and its
		// container restarts in place (contract A8, bug-01): like
		// driver-kill (A17: also for steering). The containers keep
		// running.
		d := &n.Drv[a.VM]
		d.Restarts++
		d.Inc++
		d.Killed = true
		n.driverRestarted(a.VM, SteerOff)
	case VDriverRestart:
		d := &n.Drv[a.VM]
		d.PodGen++
		d.Restarts = 0
		d.Inc++
		d.Restarted = true
		if d.PodBefore == "" {
			d.PodBefore = d.Pod
		}
		n.driverRestarted(a.VM, SteerOff)
	case VCtrlKill:
		n.ctrlKill(a.Pool)
	case VCtrlStart:
		n.ctrlStart(a.Pool)
	case VKubeletRestart:
		// A kubelet restart keeps the containers; one that it was
		// creating is created again by the new kubelet: restarts +1
		// without a crash (04-status-EXEC M2). The node's cxl.nri.io
		// slice is gone for ~30 s (S3): local claims wait, which the
		// settle waits for.
		for i := range n.Slots {
			if ss := &n.Slots[i]; ss.Node == a.VM && (ss.Phase == Starting || ss.Phase == Restarting) && ss.Slack < 255 {
				ss.Slack++
			}
		}
	case VCtrlRestart:
		// A graceful stop deletes the pool's slices, the new
		// controller publishes them again (A18): unknown until a
		// settle sees the controller up (then present), kept by a kill.
		// The attachments stay.
		n.Ctrl[a.Pool].Slices = SlicesUnknown
	case VServerRestart:
		// The specification: nothing observable changes: the pool
		// server reloads its state file.
	}
	n.Unsettled++
	return n
}

// create creates the pod of a slot.
func (n *State) create(i int) {
	ss := &n.Slots[i]
	sl := n.slot(i)
	*ss = SlotState{Gen: ss.Gen + 1, Node: sl.VM}
	n.setLeaseID(i, "")
	if sl.Res == resNone {
		n.start(i, -1)
		return
	}
	now, later := n.fits(i)
	switch {
	case now:
		n.start(i, -1)
	case later:
		// the only candidate for what is being released: a pool
		// device is allocated to it after the old claims are gone
		n.handover(i, n.start(i, -1))
		n.Contested |= 1 << uint(sl.Res)
	default:
		ss.Phase = Pending
	}
}

// start makes a slot Starting: it holds its resource. Its Prepare comes
// in this window (a region event) unless it is a pool claim whose
// controller is down; after is the event that released what it gets.
func (n *State) start(i int, after int16) int16 {
	ss := &n.Slots[i]
	sl := n.slot(i)
	ss.RaceKill = false
	if sl.Kind.pooled() && n.Ctrl[sl.Pool].Slices == SlicesAbsent {
		// no slices: the scheduler cannot allocate it (A18)
		ss.Phase = Unsched
		return -1
	}
	ss.Phase = Starting
	seq := int16(-1)
	if sl.Kind.local() || (sl.Kind.pooled() && n.Ctrl[sl.Pool].Up) {
		seq = n.addEvent(int16(i), evPrepare, false, after)
	}
	switch sl.Kind {
	case KLSteer:
		ss.Steer = n.newSteer(sl.VM)
	case KXNuma:
		// onlined as system RAM: the bytes are gone
		n.Data[sl.Dev] = tokUnknown
	case KLDax:
		// a new slice is zeroed before the claim gets it
		n.setSlotData(i, tokZero)
	}
	return seq
}

// handover marks the prepare of a pool claim that got its device after
// the old holders: after every earlier unprepare of its region (R1).
// The local memdev keeps the plain rule: one release is enough.
func (n *State) handover(i int, seq int16) {
	if n.slot(i).Kind.pooled() {
		n.setHandover(seq)
	}
}

// newSteer is the steering of an lsteer container that starts now.
func (n *State) newSteer(v VM) Steer {
	if n.Drv[v].Killed {
		return SteerAny
	}
	return SteerOn
}

// delete deletes the pod of a slot; a waiter of what it held gets it.
func (n *State) delete(i int) {
	ss := &n.Slots[i]
	sl := n.slot(i)
	prev := ss.Phase
	ss.Phase = Deleting
	ss.Prev = prev
	ss.RaceKill = false
	u := int16(i)
	seq := int16(-1)
	switch prev {
	case Running, Restarting:
		seq = n.addEvent(u, evUnprepare, false, -1)
	case Starting:
		// its Prepare may or may not come before the delete
		n.setOptional(u)
		seq = n.addEvent(u, evUnprepare, false, -1)
	case Unblocking:
		// its retry may have made its region
		n.addEvent(u, evPrepare, false, -1)
		n.setOptional(u)
		seq = n.addEvent(u, evUnprepare, false, -1)
	}
	released, lseq := false, int16(-1)
	if sl.Kind == KLease && ss.Lease == LeaseHeld {
		// released when the requester pod is deleted
		ss.Lease = LeaseReleasing
		released = true
		lseq = n.addEvent(n.leaseUser(i), evUnprepare, false, -1)
	}
	if prev.holding() {
		n.promote(sl.Res, seq)
	}
	if released {
		n.promote(localRes(sl.VM), lseq)
	}
}

// promote gives a resource to its waiter if it fits when the holders
// that are going away are gone; its Prepare comes after the event that
// released the resource.
func (n *State) promote(r Res, after int16) {
	if r == resNone {
		return
	}
	w := n.waiter(r)
	if w < 0 {
		return
	}
	if _, later := n.fits(w); later {
		n.handover(w, n.start(w, after))
		n.Contested |= 1 << uint(r)
	}
}

// crash kills the workload of a running pod: the container restarts.
func (n *State) crash(i int) {
	ss := &n.Slots[i]
	ss.Phase = Restarting
	ss.Restarts++
	if n.slot(i).Kind == KLSteer {
		// a new container gets a new manager
		ss.Steer = n.newSteer(n.slot(i).VM)
	}
}

// write writes "mbt-<step>" at offset 0 of the dax device of a slot. A
// read-only claim refuses it.
func (n *State) write(i int) {
	sl := n.slot(i)
	tok := Token{Known: true, Text: fmt.Sprintf("mbt-%d", n.Steps)}
	switch {
	case sl.Kind == KSRo:
	case sl.Kind == KLDax:
		n.setSlotData(i, tok)
	default:
		n.Data[sl.Dev] = tok
	}
}

// leaseGet takes a lease of a local block (cxl-request request --source
// local --wait: Ready when it returns).
func (n *State) leaseGet(i int, m LeaseMode) {
	ss := &n.Slots[i]
	ss.Lease = LeaseHeld
	ss.LeaseMode = m
	n.setLeaseID(i, "")
	n.addEvent(n.leaseUser(i), evPrepare, true, -1)
	if m == ModeNuma {
		// the companion's slice is fenced before it goes online
		d := &n.Drv[n.slot(i).VM]
		d.F |= n.fenceBit(n.cfg.bridgeNode(HB0))
	}
}

// leasePut releases the lease of a slot.
func (n *State) leasePut(i int) {
	n.Slots[i].Lease = LeaseReleasing
	seq := n.addEvent(n.leaseUser(i), evUnprepare, false, -1)
	n.promote(localRes(n.slot(i).VM), seq)
}

// driverRestarted applies a new driver incarnation on a VM: the fenced
// nodes are seeded from the claims prepared at its start (uncertain for
// claims in flux), and steering managers of running containers are gone:
// the new driver sets their memory.high to max and fences them with
// their claims (bug-04 fix, A17), running says it (SteerOff). A
// container (re)started in the window is steered or not by timing.
func (n *State) driverRestarted(v VM, running Steer) {
	var def, maybe uint8
	for i := range n.Slots {
		ss := &n.Slots[i]
		sl := n.slot(i)
		if sl.Kind == KLease && sl.VM == v && ss.Lease != LeaseNone && ss.LeaseMode == ModeNuma {
			bit := n.fenceBit(n.cfg.bridgeNode(HB0))
			if ss.Lease == LeaseHeld {
				def |= bit
			} else {
				maybe |= bit
			}
		}
		if ss.Node != v {
			continue
		}
		if sl.Kind.numa() {
			bit := n.fenceBit(sl.numaNode(n.cfg))
			switch ss.Phase {
			case Running, Restarting:
				def |= bit
			case Starting, Either:
				maybe |= bit
			case Deleting:
				if ss.Prev.holding() && ss.Prev != Attaching {
					maybe |= bit
				}
			}
		}
		if sl.Kind == KLSteer {
			switch ss.Phase {
			case Running:
				ss.Steer = running
			case Starting, Restarting:
				ss.Steer = SteerAny
			}
		}
	}
	d := &n.Drv[v]
	d.F = def
	d.FMaybe = maybe &^ def
}

// poolStarting: a claim of the pool is being allocated (Starting).
func (s *State) poolStarting(p Pool) bool {
	for i := range s.Slots {
		if sl := s.slot(i); sl.Kind.pooled() && sl.Pool == p && s.Slots[i].Phase == Starting {
			return true
		}
	}
	return false
}

// unschedHolder: a claim of the resource waits for its pool's slices.
func (s *State) unschedHolder(r Res) bool {
	for i := range s.Slots {
		if s.Slots[i].Phase == Unsched && s.slot(i).Res == r {
			return true
		}
	}
	return false
}

// ctrlKill kills the controller of a pool: attachments that were being
// changed may or may not have changed, pods that were starting may or
// may not have got their Attached condition.
func (n *State) ctrlKill(p Pool) {
	c := &n.Ctrl[p]
	c.Up = false
	want, _ := n.desiredAtt(p)
	for d := 0; d < 2; d++ {
		for v := VM(0); v < nVMs; v++ {
			cur := c.Att[d][v]
			if cur == TriMaybe || (cur == TriYes) != want[d][v] {
				c.Att[d][v] = TriMaybe
			}
		}
	}
	for i := range n.Slots {
		sl := n.slot(i)
		if sl.Kind.pooled() && sl.Pool == p && n.Slots[i].Phase == Starting {
			n.Slots[i].RaceKill = true
			n.setOptional(int16(i))
		}
	}
}

// ctrlStart starts the controller of a pool: pods waiting for the attach
// get it, and prepare.
func (n *State) ctrlStart(p Pool) {
	n.Ctrl[p].Up = true
	for i := range n.Slots {
		sl := n.slot(i)
		ss := &n.Slots[i]
		if !sl.Kind.pooled() || sl.Pool != p {
			continue
		}
		switch {
		case ss.Phase == Attaching || ss.Phase == Either || ss.Phase == Unsched:
			// (Unsched: the new controller publishes the slices)
			ss.Phase = Starting
			ss.RaceKill = false
			n.addEvent(int16(i), evPrepare, false, -1)
		case ss.Phase == Starting && !n.hasPrepare(int16(i)):
			// created while the controller was down
			n.addEvent(int16(i), evPrepare, false, -1)
		case ss.Phase == Starting && ss.RaceKill:
			// its Prepare comes now for sure
			ss.RaceKill = false
			n.setRequired(int16(i))
		}
	}
}

// settle is the stable state that the SUT reaches after the operations
// in flight.
func (n *State) settle() {
	for i := range n.Slots {
		ss := &n.Slots[i]
		sl := n.slot(i)
		switch ss.Phase {
		case Deleting:
			*ss = SlotState{Gen: ss.Gen, Node: sl.VM}
			n.setLeaseID(i, "")
			n.setUnblockAt(i, 0)
			if sl.Kind == KLDax {
				n.setSlotData(i, tokUnknown)
			}
			continue
		case Starting:
			switch {
			case sl.Kind.pooled() && !n.Ctrl[sl.Pool].Up && ss.RaceKill:
				ss.Phase = Either
			case sl.Kind.pooled() && !n.Ctrl[sl.Pool].Up:
				ss.Phase = Attaching
			default:
				ss.Phase = Running
			}
		case Restarting:
			ss.Phase = Running
		case Attaching, Either:
			if n.Ctrl[sl.Pool].Up {
				ss.Phase = Running
			}
		}
		ss.RaceKill = false
		if ss.Lease == LeaseReleasing {
			ss.Lease = LeaseNone
			n.setLeaseID(i, "")
		}
	}
	for p := Pool(0); p < nPools; p++ {
		if n.Ctrl[p].Up {
			// a controller that runs publishes its slices
			n.Ctrl[p].Slices = SlicesPresent
			n.deriveAtt(p)
		}
	}
	n.growFence()
	n.Ev = nil
	n.Contested = 0
	for v := range n.Drv {
		n.Drv[v].Killed = false
		n.Drv[v].Restarted = false
	}
	n.Unsettled = 0
}

// deriveAtt sets the attachments of a pool whose controller is up to
// those that its claims want.
func (n *State) deriveAtt(p Pool) {
	want, _ := n.desiredAtt(p)
	for d := 0; d < 2; d++ {
		for v := VM(0); v < nVMs; v++ {
			if want[d][v] {
				n.Ctrl[p].Att[d][v] = TriYes
			} else {
				n.Ctrl[p].Att[d][v] = TriNo
			}
		}
	}
}

// growFence adds the nodes of the numa memory prepared on each VM to its
// fenced nodes (they only grow until the driver restarts).
func (n *State) growFence() {
	for i := range n.Slots {
		ss := &n.Slots[i]
		sl := n.slot(i)
		if sl.Kind == KLease && ss.Lease == LeaseHeld && ss.LeaseMode == ModeNuma {
			n.Drv[sl.VM].F |= n.fenceBit(n.cfg.bridgeNode(HB0))
		}
		if !sl.Kind.numa() || ss.Node == VMAny {
			continue
		}
		bit := n.fenceBit(sl.numaNode(n.cfg))
		switch ss.Phase {
		case Running:
			n.Drv[ss.Node].F |= bit
		case Either:
			n.Drv[ss.Node].FMaybe |= bit
		}
	}
	for v := range n.Drv {
		n.Drv[v].FMaybe &^= n.Drv[v].F
	}
}
