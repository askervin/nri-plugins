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

// The oracle (04-contract.txt 7): the checks O1-O8 of a settle
// observation against the model state, and of done observations.
//
// The "stable" rule: a difference that the SUT may still be on its way
// out of is "pending" (the verdict is wait, the settle polls again, and
// after MBT_SETTLE_TIMEOUT the last wait becomes the failure); a
// difference that can never become right is "fatal" (the verdict is
// fail at once): restarts above the prediction, a pod running that must
// be pending, a Failed pod, an adopted or failed attachment, a wrong env
// or read, a pod on the wrong node, a pod of an unknown slot.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// VStatus is the status of a verdict.
type VStatus int

const (
	VOK VStatus = iota
	VWait
	VFail
)

func (v VStatus) String() string { return [...]string{"ok", "wait", "fail"}[v] }

// Verdict is the answer of the oracle.
type Verdict struct {
	Status VStatus
	Msg    string   // one line
	Diffs  []string // every difference, fatal ones first
	Notes  []string // what was not observed, so not checked
}

// checker collects the differences of one check.
type checker struct {
	now     time.Time     // for the deadline of unblocking pods (A9)
	unblock time.Duration // their timeout
	st      *State        // the prediction
	rs      *State        // the prediction with what the observation resolved
	cfg     *Config
	o       *Observation
	cur     []*ObsPod // the pod of the predicted generation of each slot
	fatal   []string
	pending []string
	notes   []string // fields not observed (not checked)
	// attachments predicted per pool, device (0, 1) and VM, after
	// resolution, and the exclusive flag (controller up only)
	att  [nPools][2][nVMs]Tri
	excl [nPools][2][nVMs]bool
}

func (k *checker) failf(format string, args ...any) {
	k.fatal = append(k.fatal, fmt.Sprintf(format, args...))
}

func (k *checker) waitf(format string, args ...any) {
	k.pending = append(k.pending, fmt.Sprintf(format, args...))
}

func (k *checker) notef(format string, args ...any) {
	n := fmt.Sprintf(format, args...)
	for _, x := range k.notes {
		if x == n {
			return
		}
	}
	k.notes = append(k.notes, n)
}

func (k *checker) verdict(prefix string) Verdict {
	v := Verdict{Diffs: append(append([]string(nil), k.fatal...), k.pending...), Notes: k.notes}
	var first []string
	switch {
	case len(k.fatal) > 0:
		v.Status, first = VFail, k.fatal
	case len(k.pending) > 0:
		v.Status, first = VWait, k.pending
	default:
		v.Status, v.Msg = VOK, prefix+"ok"
		return v
	}
	v.Msg = prefix + first[0]
	if n := len(v.Diffs) - 1; n > 0 {
		v.Msg += fmt.Sprintf(" (+%d more)", n)
	}
	return v
}

// checkSettle checks a settle observation against an expectation (the
// off-line check).
func checkSettle(e *Expectation, o *Observation) Verdict {
	st, err := e.state()
	if err != nil {
		return Verdict{Status: VFail, Msg: err.Error(), Diffs: []string{err.Error()}}
	}
	prefix := ""
	if e.Final {
		prefix = "teardown: "
	}
	v, _ := checkState(st, o, prefix)
	return v
}

// stallTimeout is how long a contender may stall (A19: 360 s from the
// delete; counted from the settle that first saw it).
const stallTimeout = 360 * time.Second

// defaultUnblock is MBT_UNBLOCK_TIMEOUT (A9).
const defaultUnblock = 330 * time.Second

// checkState checks a settle observation against the predicted state and
// its alternatives (the outcomes of races for the decoder stacks, A9).
// It returns the verdict of the alternative that fits best and the state
// with what the observation resolved (the adopted state, meaningful when
// the verdict is ok).
// heldSeconds: a device whose claim was deleted before its pod was bound
// is free in the scheduler this long after the settle that ended the
// delete's window (PreBind polls every 5 s; A19).
const heldSeconds = 6

// bindingExpiry: from this long after the first settle that saw a claim
// waiting for the attach with its controller down, its binding timeout
// (600 s from its allocation, which came at most a window and a settle
// earlier) may have handed its device to its waiter.
const bindingExpiry = 600 - 180

func checkState(st *State, o *Observation, prefix string) (Verdict, *State) {
	return checkStateAt(st, o, prefix, time.Now(), defaultUnblock)
}

func checkStateAt(st *State, o *Observation, prefix string, now time.Time, unblock time.Duration) (Verdict, *State) {
	v, rs, _ := checkAlts(st, o, prefix, now, unblock)
	return v, rs
}

// checkAlts is checkStateAt that also tells which alternative fitted
// (0: the state itself, j: Alts[j-1]).
func checkAlts(st *State, o *Observation, prefix string, now time.Time, unblock time.Duration) (Verdict, *State, int) {
	best, bestRS := checkOne(st, o, prefix, now, unblock)
	bestJ := 0
	for j, alt := range st.Alts {
		if best.Status == VOK {
			break
		}
		v, rs := checkOne(alt, o, prefix, now, unblock)
		if v.Status < best.Status || (v.Status == best.Status && len(v.Diffs) < len(best.Diffs)) {
			best, bestRS, bestJ = v, rs, j+1
		}
	}
	if best.Status != VOK && st.Truncated {
		// R10: say it, do not hide it
		best.Msg += " (the outcomes of this settle's races were not all enumerated: the observed one may be legal)"
	}
	return best, bestRS, bestJ
}

func checkOne(st *State, o *Observation, prefix string, now time.Time, unblock time.Duration) (Verdict, *State) {
	k := &checker{st: st, cfg: st.cfg, o: o, now: now, unblock: unblock}
	for _, e := range o.Errors {
		k.waitf("observation: %s", e)
	}
	k.indexPods()
	k.resolve()
	k.checkPods()
	k.checkCompanions()
	if len(o.Others) > 0 {
		k.waitf("other pods: %s", strings.Join(o.Others, " "))
	}
	k.checkControllers()
	k.checkPoolSlices()
	k.checkDrivers()
	k.checkAttachments()
	for v := VM(0); v < nVMs; v++ {
		k.checkVM(v)
	}
	k.checkInspect()
	return k.verdict(prefix), k.rs
}

// indexPods finds the pod of the predicted generation of every slot.
func (k *checker) indexPods() {
	k.cur = make([]*ObsPod, len(k.st.Slots))
	for j := range k.o.Pods {
		p := &k.o.Pods[j]
		i := k.cfg.slotIndex(p.Slot)
		if i < 0 {
			i = k.cfg.slotByLabel(p.Slot)
		}
		if i < 0 {
			k.failf("pod %s: unknown slot %q", p.Name, p.Slot)
			continue
		}
		gen := int(k.st.Slots[i].Gen)
		switch {
		case p.Gen > gen:
			k.failf("pod %s: generation %d of slot %s, the model created %d", p.Name, p.Gen, p.Slot, gen)
		case p.Gen < gen && !p.Deleting:
			k.failf("pod %s: generation %d of slot %s is not being deleted (current %d)", p.Name, p.Gen, p.Slot, gen)
		case p.Gen < gen:
			k.waitf("pod %s: old generation still terminating", p.Name)
		case k.cur[i] != nil:
			k.failf("pods %s and %s: two pods of generation %d of slot %s", k.cur[i].Name, p.Name, gen, p.Slot)
		default:
			k.cur[i] = p
		}
	}
}

// resolve sets what the model leaves open from the observation: the node
// of "any" slots, Either outcomes, maybe attachments of a stopped
// controller, steering of containers started in a driver restart
// window, driver pod names and lease IDs.
func (k *checker) resolve() {
	rs := k.st.clone()
	k.rs = rs
	unblocked := map[int][]RKey{} // stack -> regions made by unblocked pods
	for i := range rs.Slots {
		ss := &rs.Slots[i]
		sl := rs.slot(i)
		p := k.cur[i]
		if p == nil {
			continue
		}
		// (a stalled contender seen bound: promoted, on its node)
		if ss.Node == VMAny && p.Node != nil && (ss.Phase == Running || ss.Phase == Either || ss.Phase == Stalled) {
			v, err := parseVM(*p.Node)
			switch {
			case err != nil || v == VMAny:
				k.failf("pod %s: unknown node %q", p.Name, *p.Node)
			case !sl.hostOK(v):
				k.failf("pod %s of slot %s: on %s, not a host of pool %s", p.Name, sl.Name, v, sl.Pool)
			default:
				ss.Node = v
			}
		}
		if ss.Phase == Either {
			if p.Phase == "Running" || (p.Claim != nil && p.Claim.Attached != nil && *p.Claim.Attached) {
				ss.Phase = Running
			} else {
				ss.Phase = Attaching
			}
		}
		if ss.Slack > 0 && p.Restarts >= int(ss.Restarts) && p.Restarts <= int(ss.Restarts)+int(ss.Slack) && p.Phase == "Running" && p.Ready {
			// adopt the restarts that a kubelet restart gave (M2)
			ss.Restarts, ss.Slack = uint8(p.Restarts), 0
		}
		if ss.Phase == Stalled {
			switch {
			case p.Claim != nil && p.Claim.Allocated && !p.Deleting:
				// promoted: the scheduler allocated it (A19)
				rs.setUnblockAt(i, 0)
				// (bound also with the controller down: it was
				// attached before a kill of this window)
				bound := p.Node != nil || (p.Claim.Attached != nil && *p.Claim.Attached)
				if rs.Ctrl[sl.Pool].Up || bound {
					ss.Phase = Running
					if si, key, ok := rs.userRegion(int16(i)); ok && !rs.Stacks[si].contains(key) && !containsKey(unblocked[si], key) {
						if rs.Stacks[si].hasHole() {
							// its Prepare needs a new region
							// through a hole (A9)
							ss.Phase = Blocked
						} else {
							unblocked[si] = append(unblocked[si], key)
						}
					}
				} else {
					ss.Phase = Attaching
				}
			case rs.unblockAt(i) == 0 && !k.now.IsZero():
				rs.setUnblockAt(i, k.now.Unix())
			}
		}
		if ss.Phase == Unblocking {
			switch {
			case p.Phase == "Running" && p.Ready && !p.Deleting:
				// its retry made its region, on top of its stack;
				// the order of several is adopted below
				ss.Phase = Running
				rs.setUnblockAt(i, 0)
				// (users of one region: the local memdev, the shares
				// of a node, make it once)
				if si, key, ok := rs.userRegion(int16(i)); ok && !rs.Stacks[si].contains(key) && !containsKey(unblocked[si], key) {
					unblocked[si] = append(unblocked[si], key)
				}
			case rs.unblockAt(i) == 0 && !k.now.IsZero():
				rs.setUnblockAt(i, k.now.Unix())
			}
		}
		if sl.Kind == KLease && ss.Lease == LeaseHeld && rs.LeaseIDs[i] == "" {
			for _, c := range k.o.Companions {
				if c.Requester != nil && (*c.Requester == sl.Name || *c.Requester == sl.Label()) && c.Lease != "" {
					rs.setLeaseID(i, c.Lease)
				}
			}
		}
	}
	// a claim that waits for the attach with its controller down times
	// out in PreBind after 600 s (bindingTimeout): it is deallocated and
	// tried again, and the waiter of its device, requeued by that, may
	// take the device first. Timed from the first settle that saw it
	// waiting (UnblockAt), accepted from bindingExpiry on.
	for i := range rs.Slots {
		ss := &rs.Slots[i]
		sl := rs.slot(i)
		if ss.Phase != Attaching || !sl.Kind.pooled() || rs.Ctrl[sl.Pool].Up || k.now.IsZero() {
			continue
		}
		if rs.unblockAt(i) == 0 {
			rs.setUnblockAt(i, k.now.Unix())
			continue
		}
		w := rs.waiter(sl.Res)
		if w < 0 || k.now.Unix()-rs.unblockAt(i) < bindingExpiry {
			continue
		}
		p, pw := k.cur[i], k.cur[w]
		if p == nil || pw == nil || (p.Claim != nil && p.Claim.Allocated) || pw.Claim == nil || !pw.Claim.Allocated || rs.holders(sl.Res) != 1 {
			continue
		}
		ss.Phase = Pending
		rs.setUnblockAt(i, 0)
		rs.Slots[w].Phase = Attaching
		rs.setUnblockAt(w, k.now.Unix())
	}
	// the scheduler's hold of a device whose claim was deleted before
	// its pod was bound ends within 5.5 s of the delete (A19): timed
	// from the settle that ended its window, cleared 6 s after it
	for d := DevID(0); d < nDevs; d++ {
		if !rs.held(Res(d)) || k.now.IsZero() {
			continue
		}
		switch {
		case rs.HeldAt[d] == 0:
			rs.HeldAt[d] = k.now.Unix()
		case k.now.Unix()-rs.HeldAt[d] >= heldSeconds:
			rs.Held &^= 1 << uint(d)
			rs.HeldAt[d] = 0
		}
	}
	// kubelet retries every blocked pod at its own resync (A12): the
	// order of their regions is the observed one, if it is one
	for si, keys := range unblocked {
		st := &rs.Stacks[si]
		if got, ok, _ := k.observedStack(stackVM(si), stackBridge(si)); ok && got.N == st.N+int8(len(keys)) && prefixOf(st, &got) && sameKeys(got.E[st.N:got.N], keys) {
			*st = got
			continue
		}
		for _, key := range keys {
			st.push(key)
		}
	}
	for p := Pool(0); p < nPools; p++ {
		c := &rs.Ctrl[p]
		if c.Up {
			rs.deriveAtt(p)
			continue
		}
		for d := 0; d < 2; d++ {
			for v := VM(0); v < nVMs; v++ {
				if c.Att[d][v] != TriMaybe {
					continue
				}
				switch k.obsAttState(p, DevID(2*int(p)+d), v) {
				case "attached":
					c.Att[d][v] = TriYes
				case "":
					c.Att[d][v] = TriNo
				}
			}
		}
	}
	for v := VM(0); v < nVMs; v++ {
		if od := k.o.Drivers[v.String()]; od != nil && od.Ready && od.Pod != rs.Drv[v].PodBefore {
			rs.Drv[v].Pod = od.Pod
			rs.Drv[v].PodBefore = ""
		}
	}
	for i := range rs.Slots {
		ss := &rs.Slots[i]
		if ss.Steer != SteerAny || ss.Phase != Running || k.cur[i] == nil {
			continue
		}
		if c := k.container(ss.Node, k.cur[i].Name); c != nil {
			if c.MemoryHigh == "max" {
				ss.Steer = SteerOff
			} else if c.MemoryHigh != "" {
				ss.Steer = SteerOn
			}
		}
	}
	rs.growFence()
}

// obsAttState returns the state of the observed attachment of a device
// on a VM, "" if there is none.
func (k *checker) obsAttState(p Pool, d DevID, v VM) string {
	for _, a := range k.o.Attachments[p.String()] {
		if k8sOwned(&a) && (a.Device == devices[d].Name || a.Device == shortDevName(d)) && a.Host == v.String() {
			return a.State
		}
	}
	return ""
}

// k8sOwned: the attachment is the pool controller's (owner k8s:...);
// others are the setup's (contract A3). An attachment without an owner
// is taken as the controller's, so that nothing goes unchecked.
func k8sOwned(a *ObsAttachment) bool {
	return a.Owner == "" || strings.HasPrefix(a.Owner, "k8s:")
}

// container returns the main container of a pod observed in a VM.
func (k *checker) container(v VM, pod string) *ObsContainer {
	if v == VMAny {
		return nil
	}
	ov := k.o.VMs[v.String()]
	if ov == nil {
		return nil
	}
	for j := range ov.Containers {
		if ov.Containers[j].Pod == pod {
			return &ov.Containers[j]
		}
	}
	return nil
}

func waitingOf(p *ObsPod) string {
	if p.Waiting != nil && *p.Waiting != "" {
		return " (" + *p.Waiting + ")"
	}
	return ""
}

func nodeOf(p *ObsPod) string {
	if p.Node == nil {
		return "-"
	}
	return *p.Node
}

// O1: pods per slot.
func (k *checker) checkPods() {
	for i := range k.rs.Slots {
		ss := &k.rs.Slots[i]
		sl := k.rs.slot(i)
		p := k.cur[i]
		name := "pod " + sl.Name
		if p != nil {
			// a deleted pod's workload exits 0 on SIGTERM: terminal
			// phases are normal while deleting (contract A7)
			if (p.Phase == "Failed" || p.Phase == "Succeeded") && !p.Deleting {
				k.failf("%s: phase %s (restartPolicy Always)", name, p.Phase)
				continue
			}
			// a pod that is going away may have restarted after a
			// crash in the same window: only the others count
			if ss.Phase != Absent && p.Restarts > int(ss.Restarts)+int(ss.Slack) {
				k.failf("%s: %d restarts, the model crashed it %d times%s", name, p.Restarts, ss.Restarts, slackNote(ss))
			}
		}
		switch ss.Phase {
		case Absent:
			if p != nil {
				if p.Deleting {
					k.waitf("%s: still being deleted", name)
				} else {
					k.failf("%s: pod %s exists, want none", name, p.Name)
				}
			}
		case Running:
			k.checkRunning(i, name)
		case Pending:
			switch {
			case p == nil:
				k.waitf("%s: no pod, want Pending", name)
			case p.Deleting:
				k.failf("%s: being deleted, want Pending", name)
			case p.Phase == "Running":
				k.failf("%s: Running on %s, want Pending (its %s is held by %s)", name, nodeOf(p), sl.Res, k.holderNames(sl.Res, i))
			case p.Phase != "Pending":
				k.waitf("%s: phase %s, want Pending", name, p.Phase)
			case p.Restarts > 0:
				k.failf("%s: %d restarts while Pending", name, p.Restarts)
			case p.Claim != nil && p.Claim.Allocated:
				k.waitf("%s: claim allocated, want unallocated (its %s is held by %s)", name, sl.Res, k.holderNames(sl.Res, i))
			case p.Node != nil:
				k.waitf("%s: bound to %s, want unschedulable", name, *p.Node)
			case !p.Unschedulable:
				k.waitf("%s: not unschedulable yet", name)
			}
		case Attaching:
			switch {
			case p == nil:
				k.waitf("%s: no pod, want Pending for the attach", name)
			case p.Deleting:
				k.failf("%s: being deleted, want Pending for the attach", name)
			case p.Phase == "Running":
				k.failf("%s: Running on %s while the controller of pool %s is down", name, nodeOf(p), sl.Pool)
			case p.Phase != "Pending":
				k.waitf("%s: phase %s, want Pending for the attach", name, p.Phase)
			case p.Claim == nil || !p.Claim.Allocated:
				k.waitf("%s: claim not allocated, want allocated and waiting for the attach", name)
			case p.Claim.Attached != nil && *p.Claim.Attached:
				k.waitf("%s: claim attached while the controller of pool %s is down", name, sl.Pool)
			}
		case Blocked:
			k.checkBlocked(i, name)
		case Unblocking:
			k.checkUnblocking(i, name)
		case Stalled:
			at := k.rs.unblockAt(i)
			switch {
			case p == nil:
				k.waitf("%s: no pod, want Pending or allocated (a stalled contender)", name)
			case p.Deleting:
				k.failf("%s: being deleted, want Pending or allocated", name)
			case p.Phase != "Pending":
				k.waitf("%s: phase %s, want Pending (stalled) or allocated", name, p.Phase)
			case at > 0 && k.now.Sub(time.Unix(at, 0)) > stallTimeout:
				k.failf("%s: still not allocated %s after the delete of the claim it waits for (A19)", name, k.now.Sub(time.Unix(at, 0)).Round(time.Second))
			}
		case Unsched:
			switch {
			case p == nil:
				k.waitf("%s: no pod, want Pending for the slices of pool %s", name, sl.Pool)
			case p.Deleting:
				k.failf("%s: being deleted, want Pending for the slices of pool %s", name, sl.Pool)
			case p.Phase == "Running":
				k.failf("%s: Running on %s, but pool %s has no ResourceSlices", name, nodeOf(p), sl.Pool)
			case p.Phase != "Pending":
				k.waitf("%s: phase %s, want Pending for the slices of pool %s", name, p.Phase, sl.Pool)
			case p.Claim != nil && p.Claim.Allocated:
				k.waitf("%s: claim allocated, but pool %s has no ResourceSlices", name, sl.Pool)
			case !p.Unschedulable:
				k.waitf("%s: not unschedulable yet (pool %s has no ResourceSlices)", name, sl.Pool)
			}
		case Either:
			k.waitf("%s: no pod to decide Running or Pending for the attach", name)
		default:
			k.waitf("%s: phase %s at a settle (model)", name, ss.Phase)
		}
	}
}

// blockedText is the driver's message of a Prepare refused by a decoder
// hole (pkg/cxl/memctl/decoders.go).
const blockedText = "CXL decoders released out of order"

// checkBlocked: a pod whose Prepare a decoder hole refuses (A9): Pending,
// bound, ContainerCreating, its claim allocated (and Attached), its
// newest Warning event the driver's message.
func (k *checker) checkBlocked(i int, name string) {
	ss := &k.rs.Slots[i]
	sl := k.rs.slot(i)
	p := k.cur[i]
	si, _, _ := k.rs.userRegion(int16(i))
	switch {
	case p == nil:
		k.waitf("%s: no pod, want blocked by the decoder hole of %s", name, stackName(si))
	case p.Deleting:
		k.failf("%s: being deleted, want blocked", name)
	case p.Phase == "Running":
		k.failf("%s: Running, but its decoder stack %s %s has a hole", name, stackName(si), k.rs.Stacks[si])
	case p.Phase != "Pending":
		k.waitf("%s: phase %s, want Pending blocked by a decoder hole", name, p.Phase)
	case p.Node != nil && *p.Node != ss.Node.String():
		k.failf("%s: on %s, want %s", name, *p.Node, ss.Node)
	case p.Node == nil:
		k.waitf("%s: not bound yet, want blocked on %s", name, ss.Node)
	case p.Claim == nil || !p.Claim.Allocated:
		k.waitf("%s: claim not allocated, want blocked in its Prepare", name)
	case sl.Kind.pooled() && k.rs.Ctrl[sl.Pool].Up && (p.Claim.Attached == nil || !*p.Claim.Attached):
		k.waitf("%s: claim not Attached, want blocked in its Prepare", name)
	case !p.blockedEvent():
		msg := "none"
		if p.Event != nil {
			msg = firstLine(p.Event.Reason + ": " + p.Event.Message)
		}
		k.waitf("%s: no Warning event with %q (newest %q; decoder hole of %s %s)", name, blockedText, msg, stackName(si), k.rs.Stacks[si])
	}
}

// blockedEvent: a Warning event of the pod has the driver's text (A12:
// every event of "events", and "event").
func (p *ObsPod) blockedEvent() bool {
	if p.Event != nil && strings.Contains(p.Event.Message, blockedText) {
		return true
	}
	for _, e := range p.Events {
		if strings.Contains(e.Message, blockedText) {
			return true
		}
	}
	return false
}

// checkDriverLog: no panic in the log of the current driver container
// (A13).
func (k *checker) checkDriverLog(v VM, ov *ObsVM) {
	if ov.DriverLog == nil {
		k.notef("vms.%s.driverLog not observed: no check of driver panics", v)
		return
	}
	dl := ov.DriverLog
	ctr := "?"
	if dl.Container != nil {
		ctr = *dl.Container
	}
	if dl.Panics > 0 {
		first := ""
		if len(dl.Errors) > 0 {
			first = ": " + firstLine(dl.Errors[0])
		}
		k.failf("driver %s: %d panics in the log of container %s%s", v, dl.Panics, ctr, first)
	}
	// A15: a driver is ready when it runs with NRI, lending and its
	// sockets up
	switch {
	case dl.Container == nil || *dl.Container == "":
		k.waitf("driver %s: no running driver container", v)
	case dl.LendsRestored != nil && !*dl.LendsRestored:
		k.waitf("driver %s: \"NRI fence: lends restored\" not logged yet", v)
	case dl.Sockets != nil && !*dl.Sockets:
		k.waitf("driver %s: its dra.sock sockets are not there", v)
	}
	if dl.LendsRestored == nil {
		k.notef("vms.%s.driverLog.lendsRestored not observed", v)
	}
}

// checkMissing: the executor's list of running containers that the VM's
// containers lack (A11).
func (k *checker) checkMissing(v VM, ov *ObsVM) {
	raw := bytes.TrimSpace(ov.Missing)
	switch {
	case len(raw) == 0:
		k.notef("vms.%s.missing not observed", v)
		return
	case string(raw) == "null":
		k.waitf("%s: containers not read (missing: null)", v)
		return
	}
	var list []struct {
		Pod    string `json:"pod"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		k.waitf("%s: missing: %v", v, err)
		return
	}
	for _, m := range list {
		k.waitf("%s: container of pod %s missing: %s", v, m.Pod, m.Reason)
	}
}

// checkSlices: the cxl.nri.io ResourceSlice of a node publishes the
// local memdev and no pool serial (A13, D I12).
func (k *checker) checkSlices(v VM) {
	if k.o.Slices == nil {
		k.notef("slices not observed: no check of the cxl.nri.io ResourceSlices")
		return
	}
	devs, ok := k.o.Slices[v.String()]
	if !ok {
		k.waitf("%s: no cxl.nri.io ResourceSlice observed", v)
		return
	}
	local := "memdev-" + strconv.FormatUint(localSerial, 16)
	found := false
	for _, d := range devs {
		if d.Name == local {
			found = true
		}
		if x, ok := parseSerial(d.Serial); ok {
			if pd := devBySerial(x); pd >= 0 {
				k.waitf("%s: cxl.nri.io slice publishes %s (serial %s of pool device %s)", v, d.Name, d.Serial, pd)
			}
		}
	}
	if !found {
		k.waitf("%s: cxl.nri.io slice without %s", v, local)
	}
}

// checkLeaseStore: leases.json of a VM has the claims of its running
// lease pods and their leases (A13, D I11).
func (k *checker) checkLeaseStore(v VM, ov *ObsVM) {
	if ov.State == nil {
		return
	}
	raw := bytes.TrimSpace(ov.State.Leases)
	if len(raw) == 0 || string(raw) == "null" {
		k.notef("vms.%s.state.leases not observed: no check of leases.json", v)
		return
	}
	var store struct {
		Claims map[string]json.RawMessage `json:"claims"`
		Leases map[string]struct {
			ID    string `json:"id"`
			Mode  string `json:"mode"`
			State string `json:"state"`
			Node  int    `json:"node"`
			Pod   struct {
				Name string `json:"name"`
			} `json:"pod"`
		} `json:"leases"`
	}
	if err := json.Unmarshal(raw, &store); err != nil {
		k.waitf("%s: leases.json: %v", v, err)
		return
	}
	want := map[string]bool{} // lease claims of running lease pods
	byPod := map[string]int{} // lease pod name -> slot
	for i, p := range k.cur {
		sl := k.rs.slot(i)
		if p == nil || sl.Kind != KLease || sl.VM != v || k.rs.Slots[i].Phase != Running {
			continue
		}
		if p.Claim != nil && p.Claim.UID != "" {
			want[p.Claim.UID] = true
		}
		byPod[p.Name] = i
	}
	got := map[string]bool{}
	for uid := range store.Claims {
		got[uid] = true
	}
	if !sameSet(got, want) {
		k.waitf("%s: leases.json has lease claims %v, want %v", v, sortedKeys(got), sortedKeys(want))
	}
	held := map[int]bool{}
	for id, l := range store.Leases {
		i, ok := byPod[l.Pod.Name]
		switch {
		case !ok:
			k.waitf("%s: leases.json: lease %s of pod %s, no lease pod of the model holds it", v, id, l.Pod.Name)
			continue
		case k.rs.Slots[i].Lease != LeaseHeld:
			k.waitf("%s: leases.json: lease %s (%s) of %s, want none", v, id, l.State, k.rs.slot(i).Name)
			continue
		case l.State != "Ready":
			k.waitf("%s: leases.json: lease %s of %s %s, want Ready", v, id, k.rs.slot(i).Name, l.State)
		case l.Mode != "" && l.Mode != k.rs.Slots[i].LeaseMode.String():
			k.waitf("%s: leases.json: lease %s of %s mode %s, want %s", v, id, k.rs.slot(i).Name, l.Mode, k.rs.Slots[i].LeaseMode)
		}
		if lid := k.rs.LeaseIDs[i]; lid != "" && lid != id {
			k.waitf("%s: leases.json: lease %s of %s, want %s", v, id, k.rs.slot(i).Name, lid)
		}
		held[i] = true
	}
	for _, i := range byPod {
		if k.rs.Slots[i].Lease == LeaseHeld && !held[i] {
			k.waitf("%s: leases.json has no lease of %s", v, k.rs.slot(i).Name)
		}
	}
}

// checkUnblocking: the hole has cleared; ContainerCreating is accepted
// until --unblock-timeout after the settle that saw it clear (on-line).
func (k *checker) checkUnblocking(i int, name string) {
	p := k.cur[i]
	switch {
	case p == nil:
		k.waitf("%s: no pod, want it to start after its decoder hole cleared", name)
	case p.Deleting:
		k.failf("%s: being deleted, want it to start after its decoder hole cleared", name)
	case p.Phase != "Pending":
		k.waitf("%s: phase %s, want Running (or ContainerCreating for its retry)", name, p.Phase)
	case p.Node == nil:
		// (F13) a pool pod is bound only at PreBind's next poll after
		// its claim is Attached (up to 5 s): until then its delete is
		// that of an unbound claim (A19)
		k.waitf("%s: not bound yet, want it on %s (its retry after its decoder hole cleared)", name, k.rs.Slots[i].Node)
	case k.rs.unblockAt(i) > 0 && k.unblock > 0 && k.now.Sub(time.Unix(k.rs.unblockAt(i), 0)) > k.unblock:
		k.failf("%s: not Running %s after its decoder hole cleared%s", name, k.now.Sub(time.Unix(k.rs.unblockAt(i), 0)).Round(time.Second), waitingOf(p))
	}
}

func slackNote(ss *SlotState) string {
	if ss.Slack == 0 {
		return ""
	}
	return fmt.Sprintf(" (+%d for kubelet or containerd restarts while it was being created)", ss.Slack)
}

// holderNames lists the slots that hold a resource, but slot i.
func (k *checker) holderNames(r Res, i int) string {
	var names []string
	for j := range k.rs.Slots {
		if j != i && k.rs.slot(j).Res == r && k.rs.Slots[j].holds() {
			names = append(names, k.rs.slot(j).Name)
		}
	}
	if r >= resLocal0 {
		v := VM(r - resLocal0)
		for j := range k.rs.Slots {
			sl := k.rs.slot(j)
			if sl.Kind == KLease && sl.VM == v && k.rs.Slots[j].Lease != LeaseNone {
				names = append(names, "the lease of "+sl.Name)
			}
		}
	}
	if len(names) == 0 {
		return "nobody"
	}
	return strings.Join(names, ",")
}

func (k *checker) checkRunning(i int, name string) {
	ss := &k.rs.Slots[i]
	sl := k.rs.slot(i)
	p := k.cur[i]
	switch {
	case p == nil:
		k.waitf("%s: no pod, want Running", name)
		return
	case p.Deleting:
		k.failf("%s: being deleted, want Running", name)
		return
	}
	if p.Node != nil && ss.Node != VMAny && *p.Node != ss.Node.String() {
		k.failf("%s: on %s, want %s", name, *p.Node, ss.Node)
		return
	}
	if p.Phase != "Running" || !p.Ready {
		k.waitf("%s: phase %s ready %v%s, want Running", name, p.Phase, p.Ready, waitingOf(p))
		return
	}
	if p.Restarts < int(ss.Restarts) {
		k.waitf("%s: %d restarts, want %d", name, p.Restarts, ss.Restarts)
		return
	}
	if !sl.Kind.claimed() {
		return
	}
	c := p.Claim
	switch {
	case c == nil:
		k.waitf("%s: no claim", name)
	case !c.Allocated:
		k.waitf("%s: claim not allocated", name)
	case sl.Kind.pooled():
		for _, d := range c.Devices {
			if d.Device != "" && d.Device != devices[sl.Dev].Name && d.Device != shortDevName(sl.Dev) {
				k.failf("%s: claim has device %s, want %s", name, d.Device, devices[sl.Dev].Name)
			}
		}
		if c.Attached == nil || !*c.Attached {
			k.waitf("%s: claim not Attached", name)
		}
	}
}

// shortDevName is the name of a device in its pool (pooled0, shared0).
func shortDevName(d DevID) string {
	_, n, _ := strings.Cut(devices[d].Name, "-")
	return n
}

// companions expected: the held leases.
func (k *checker) checkCompanions() {
	type want struct {
		slot  int
		found bool
	}
	var wants []*want
	for i := range k.rs.Slots {
		if k.rs.slot(i).Kind == KLease && k.rs.Slots[i].Lease == LeaseHeld {
			wants = append(wants, &want{slot: i})
		}
	}
	match := func(c *ObsCompanion) *want {
		for _, w := range wants {
			if w.found {
				continue
			}
			sl := k.rs.slot(w.slot)
			id := k.rs.LeaseIDs[w.slot]
			switch {
			case c.Requester != nil && *c.Requester != "":
				if *c.Requester == sl.Name || *c.Requester == sl.Label() {
					return w
				}
			case id != "":
				if c.Lease == id {
					return w
				}
			case c.Node == sl.VM.String():
				return w
			}
		}
		return nil
	}
	for j := range k.o.Companions {
		c := &k.o.Companions[j]
		w := match(c)
		if w == nil {
			k.waitf("companion %s (lease %s): no lease of the model", c.Name, c.Lease)
			continue
		}
		w.found = true
		sl := k.rs.slot(w.slot)
		if c.Node != sl.VM.String() {
			k.failf("companion %s of %s: on %s, want %s", c.Name, sl.Name, c.Node, sl.VM)
		}
		if c.Phase != "Running" {
			k.waitf("companion %s of %s: phase %s", c.Name, sl.Name, c.Phase)
		}
		if id := k.rs.LeaseIDs[w.slot]; id != "" && c.Lease != id {
			k.waitf("companion %s of %s: lease %s, want %s", c.Name, sl.Name, c.Lease, id)
		}
	}
	for _, w := range wants {
		if !w.found {
			k.waitf("lease of %s: no companion pod", k.rs.slot(w.slot).Name)
		}
	}
}

// O8 (controllers): as the model says.
func (k *checker) checkControllers() {
	for p := Pool(0); p < nPools; p++ {
		got, ok := k.o.Controllers[p.String()]
		switch {
		case !ok:
			k.waitf("controller %s: not observed", p)
		case k.rs.Ctrl[p].Up && got != "active":
			k.waitf("controller %s: %s, want active", p, got)
		case !k.rs.Ctrl[p].Up && got != "failed" && got != "inactive":
			k.waitf("controller %s: %s, want down (failed or inactive)", p, got)
		}
	}
}

// checkPoolSlices: a pool's ResourceSlices are there or not as the
// model says (A18).
func (k *checker) checkPoolSlices() {
	if k.o.PoolSlices == nil {
		k.notef("poolSlices not observed: no check of the pools' ResourceSlices")
		return
	}
	for _, p := range k.cfg.poolsUsed() {
		list, ok := k.o.PoolSlices[p.String()]
		if !ok {
			k.waitf("pool %s: slices not observed", p)
			continue
		}
		switch st := k.rs.Ctrl[p].Slices; {
		case st == SlicesPresent && len(list) == 0:
			k.waitf("pool %s: no ResourceSlices, want them published", p)
		case st == SlicesAbsent && len(list) > 0:
			k.waitf("pool %s: %d ResourceSlices, want none (its controller is down after a graceful restart)", p, len(list))
		}
	}
}

// O8 (drivers): Ready, restarts only from driver-kill, a new pod after
// driver-restart.
func (k *checker) checkDrivers() {
	for v := VM(0); v < nVMs; v++ {
		d := &k.st.Drv[v]
		od := k.o.Drivers[v.String()]
		switch {
		case od == nil:
			k.waitf("driver %s: not observed", v)
		case d.PodBefore != "" && od.Pod == d.PodBefore:
			k.waitf("driver %s: still pod %s, want a new one", v, od.Pod)
		case d.PodBefore == "" && d.Pod != "" && od.Pod != d.Pod:
			k.waitf("driver %s: pod %s, want %s (no driver-restart)", v, od.Pod, d.Pod)
		case !od.Ready:
			k.waitf("driver %s: pod %s not Ready", v, od.Pod)
		case od.Restarts != int(d.Restarts):
			k.waitf("driver %s: pod %s has %d restarts, want %d", v, od.Pod, od.Restarts, d.Restarts)
		}
	}
}

// O2: pool attachments.
func (k *checker) checkAttachments() {
	for p := Pool(0); p < nPools; p++ {
		c := &k.rs.Ctrl[p]
		if c.Up {
			want, excl := k.rs.desiredAtt(p)
			for d := 0; d < 2; d++ {
				for v := VM(0); v < nVMs; v++ {
					if want[d][v] {
						k.att[p][d][v] = TriYes
					}
				}
			}
			k.excl[p] = excl
		} else {
			k.att[p] = c.Att
		}
		list, ok := k.o.Attachments[p.String()]
		if !ok {
			k.waitf("attachments of pool %s: not observed", p)
			continue
		}
		var seen [2][nVMs]*ObsAttachment
		for j := range list {
			a := &list[j]
			if a.Adopted {
				k.failf("attachment %s@%s of pool %s: adopted (owner %q)", a.Device, a.Host, p, a.Owner)
			}
			if !k8sOwned(a) {
				continue // the setup's local memdevs (contract A3)
			}
			if a.State == "failed" {
				k.failf("attachment %s@%s of pool %s: failed", a.Device, a.Host, p)
			}
			d := -1
			for x := 0; x < 2; x++ {
				if a.Device == devices[2*int(p)+x].Name || a.Device == shortDevName(DevID(2*int(p)+x)) {
					d = x
				}
			}
			if d < 0 {
				k.waitf("attachment %s@%s of pool %s: owner %q, a device the model does not know", a.Device, a.Host, p, a.Owner)
				continue
			}
			v, err := parseVM(a.Host)
			if err != nil || v == VMAny {
				k.waitf("attachment %s@%s of pool %s: unknown host", a.Device, a.Host, p)
				continue
			}
			if seen[d][v] != nil {
				k.waitf("attachment %s@%s of pool %s: listed twice", a.Device, a.Host, p)
			}
			switch a.State {
			case "attached":
				seen[d][v] = a
			case "attaching", "detaching":
				k.waitf("attachment %s@%s: %s", a.Device, a.Host, a.State)
				seen[d][v] = a
			default:
				k.waitf("attachment %s@%s: state %q", a.Device, a.Host, a.State)
				seen[d][v] = a
			}
		}
		for d := 0; d < 2; d++ {
			dev := devices[2*int(p)+d].Name
			for v := VM(0); v < nVMs; v++ {
				a := seen[d][v]
				switch k.att[p][d][v] {
				case TriYes:
					switch {
					case a == nil:
						k.waitf("attachment %s@%s: missing", dev, v)
					case c.Up && a.State == "attached" && a.Exclusive != k.excl[p][d][v]:
						k.waitf("attachment %s@%s: exclusive %v, want %v", dev, v, a.Exclusive, k.excl[p][d][v])
					}
				case TriNo:
					if a != nil && a.State == "attached" {
						k.waitf("attachment %s@%s: attached, no claim wants it", dev, v)
					}
				}
			}
		}
	}
}

// predicted per-VM facts, after resolution
type vmPred struct {
	poolMode  [nDevs]int8 // 0 not prepared, 1 numa, 2 dax
	slicesN   int         // local numa slices (pods and leases)
	slicesD   int         // local dax slices
	memdev    [nDevs]Tri  // pool memdevs present
	memTotal  map[int]uint64
	localUIDs map[string]bool // claims of local and lease slots prepared here
	poolUIDs  map[string]bool // pool claims prepared here
	leaseUIDs map[string]bool // lease claims prepared here
	leases    int             // companions prepared here
}

func (k *checker) predictVM(v VM) *vmPred {
	rs := k.rs
	pr := &vmPred{memTotal: map[int]uint64{}, localUIDs: map[string]bool{}, poolUIDs: map[string]bool{}, leaseUIDs: map[string]bool{}}
	for _, n := range k.cfg.cxlNodes() {
		pr.memTotal[n] = 0
	}
	hb0 := k.cfg.bridgeNode(HB0)
	for i := range rs.Slots {
		ss := &rs.Slots[i]
		sl := rs.slot(i)
		if sl.Kind == KLease && sl.VM == v && ss.Lease == LeaseHeld {
			pr.leases++
			if ss.LeaseMode == ModeNuma {
				pr.slicesN++
				pr.memTotal[hb0] += blockSize
			} else {
				pr.slicesD++
			}
		}
		if ss.Phase != Running || ss.Node != v {
			continue
		}
		uid := ""
		if p := k.cur[i]; p != nil && p.Claim != nil {
			uid = p.Claim.UID
		}
		switch {
		case sl.Kind.pooled():
			mode := int8(2)
			if sl.Kind == KXNuma {
				mode = 1
				pr.memTotal[k.cfg.bridgeNode(poolBridge[sl.Pool])] += devices[sl.Dev].Size
			}
			pr.poolMode[sl.Dev] = mode
			if uid != "" {
				pr.poolUIDs[uid] = true
			}
		case sl.Kind.local():
			if sl.Kind == KLDax {
				pr.slicesD++
			} else {
				pr.slicesN++
				pr.memTotal[hb0] += blockSize
			}
			if uid != "" {
				pr.localUIDs[uid] = true
			}
		case sl.Kind == KLease:
			if uid != "" {
				pr.localUIDs[uid] = true
				pr.leaseUIDs[uid] = true
			}
		}
	}
	for p := Pool(0); p < nPools; p++ {
		for d := 0; d < 2; d++ {
			pr.memdev[2*int(p)+d] = k.att[p][d][v]
		}
	}
	return pr
}

// O3, O4, O5 of a VM.
func (k *checker) checkVM(v VM) {
	ov := k.o.VMs[v.String()]
	if ov == nil {
		k.waitf("%s: not observed", v)
		return
	}
	for _, e := range ov.Errors {
		k.waitf("%s: %s", v, e)
	}
	// A11: a part that is null was not read: wait
	for _, part := range []struct {
		name string
		null bool
	}{{"regions", ov.Regions == nil}, {"containers", ov.Containers == nil}, {"cdi", ov.CDI == nil}} {
		if part.null {
			k.waitf("%s: %s not observed (null)", v, part.name)
		}
	}
	pr := k.predictVM(v)
	k.checkMemdevs(v, ov, pr)
	k.checkRegions(v, ov, pr)
	k.checkNodes(v, ov, pr)
	k.checkStateFiles(v, ov, pr)
	k.checkFencing(v, ov, pr)
	k.checkPorts(v, ov)
	k.checkDriverLog(v, ov)
	k.checkMissing(v, ov)
	k.checkSlices(v)
	k.checkLeaseStore(v, ov)
}

// checkPorts compares the committed decoders of the host bridges of a VM
// with the predicted decoder stacks (A9, A10). Regions of pods that wait
// for their retry may be there or not, on top.
func (k *checker) checkPorts(v VM, ov *ObsVM) {
	if ov.Ports == nil {
		k.notef("vms.%s.ports not observed: no check of the decoder stacks", v)
		return
	}
	for b := Bridge(0); b < nBridges; b++ {
		si := stackIndex(v, b)
		want := k.rs.Stacks[si]
		got, ok, unknown := k.observedStack(v, b)
		switch {
		case unknown != "":
			k.waitf("stack %s: decoder of %s, a region of no known serial", stackName(si), unknown)
			continue
		case !ok:
			if want.N > 0 {
				k.waitf("stack %s: no host bridge port, want %s", stackName(si), want)
			}
			continue
		}
		// the regions of unblocking pods may be on top already
		for got.N > want.N && k.unblockingKey(si, got.top()) {
			got.N--
		}
		if !got.equal(&want) {
			k.waitf("stack %s: committed decoders %s, want %s", stackName(si), got, want)
		}
	}
}

// observedStack returns the committed decoders of the host bridge port
// of hb b of a VM as a stack (region names mapped through the regions'
// serials, "" a hole); ok is false without the port, unknown names a
// region of no known serial.
func (k *checker) observedStack(v VM, b Bridge) (Stack, bool, string) {
	var got Stack
	ov := k.o.VMs[v.String()]
	if ov == nil || ov.Ports == nil {
		return got, false, ""
	}
	regionKey := map[string]RKey{}
	for _, r := range ov.Regions {
		for _, sx := range r.Serials {
			if x, ok := parseSerial(sx); ok {
				if x == localSerial {
					regionKey[r.Name] = rkLocal
				} else if d := devBySerial(x); d >= 0 {
					regionKey[r.Name] = devKey(d)
				}
			}
		}
	}
	var port *ObsPort
	hb := "hb" + string(rune('0'+b))
	for j := range ov.Ports {
		if ov.Ports[j].Kind == "hostbridge" && ov.Ports[j].HB != nil && *ov.Ports[j].HB == hb {
			port = &ov.Ports[j]
		}
	}
	if port == nil {
		return got, false, ""
	}
	decs := append([]ObsDecoder(nil), port.Decoders...)
	sort.SliceStable(decs, func(x, y int) bool { return decoderIndex(decs[x].Name) < decoderIndex(decs[y].Name) })
	for _, d := range decs {
		if d.Region == "" {
			got.push(rkHole)
			continue
		}
		key, ok := regionKey[d.Region]
		if !ok {
			return got, true, d.Region
		}
		got.push(key)
	}
	return got, true, ""
}

// prefixOf: the entries of p begin s.
func prefixOf(p, s *Stack) bool {
	if p.N > s.N {
		return false
	}
	for i := int8(0); i < p.N; i++ {
		if p.E[i] != s.E[i] {
			return false
		}
	}
	return true
}

func containsKey(keys []RKey, k RKey) bool {
	for _, x := range keys {
		if x == k {
			return true
		}
	}
	return false
}

// sameKeys: two lists have the same keys (any order).
func sameKeys(a, b []RKey) bool {
	if len(a) != len(b) {
		return false
	}
	n := map[RKey]int{}
	for _, x := range a {
		n[x]++
	}
	for _, x := range b {
		n[x]--
	}
	for _, c := range n {
		if c != 0 {
			return false
		}
	}
	return true
}

// unblockingKey: a pod of the stack that waits for its retry has the key.
func (k *checker) unblockingKey(si int, key RKey) bool {
	for i := range k.rs.Slots {
		if !k.rs.Slots[i].Phase.waitsRetry() {
			continue
		}
		if ssi, kk, ok := k.rs.userRegion(int16(i)); ok && ssi == si && kk == key {
			return true
		}
	}
	return false
}

// decoderIndex is K of decoderP.K.
func decoderIndex(name string) int {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return 1 << 30
	}
	n, err := strconv.Atoi(name[i+1:])
	if err != nil {
		return 1 << 30
	}
	return n
}

func (k *checker) checkMemdevs(v VM, ov *ObsVM, pr *vmPred) {
	if ov.Memdevs == nil {
		k.waitf("%s: memdevs not observed", v)
		return
	}
	var seen [nDevs]bool
	local := false
	for _, md := range ov.Memdevs {
		serial, ok := parseSerial(md.Serial)
		switch {
		case !ok:
			k.waitf("%s: memdev %s: invalid serial %q", v, md.Name, md.Serial)
		case serial == localSerial:
			local = true
		default:
			d := devBySerial(serial)
			if d < 0 {
				k.waitf("%s: memdev %s: unexpected serial %s", v, md.Name, md.Serial)
				continue
			}
			seen[d] = true
		}
	}
	if !local {
		k.waitf("%s: no local memdev %s", v, formatSerial(localSerial))
	}
	for d := DevID(0); d < nDevs; d++ {
		switch {
		case pr.memdev[d] == TriYes && !seen[d]:
			k.waitf("%s: no memdev of %s (attached)", v, d)
		case pr.memdev[d] == TriNo && seen[d]:
			k.waitf("%s: memdev of %s present, not attached", v, d)
		}
	}
}

func devBySerial(serial uint64) DevID {
	for d := DevID(0); d < nDevs; d++ {
		if devices[d].Serial == serial {
			return d
		}
	}
	return -1
}

// daxSummary counts the dax devices of a region with memory.
func daxSummary(r *ObsRegion) (kmem, ddax int, kmemSizes, ddaxSizes []uint64, online []uint64, other int) {
	for _, d := range r.Dax {
		if d.Size == 0 {
			continue
		}
		drv := ""
		if d.Driver != nil {
			drv = *d.Driver
		}
		switch drv {
		case "kmem":
			kmem++
			kmemSizes = append(kmemSizes, d.Size)
			online = append(online, d.Online)
		case "device_dax":
			ddax++
			ddaxSizes = append(ddaxSizes, d.Size)
			if d.Online != 0 {
				other++
			}
		default:
			other++
		}
	}
	return
}

func (k *checker) checkRegions(v VM, ov *ObsVM, pr *vmPred) {
	if ov.Regions == nil {
		return
	}
	matched := make([]bool, len(ov.Regions))
	find := func(serial uint64) *ObsRegion {
		for j := range ov.Regions {
			for _, s := range ov.Regions[j].Serials {
				if x, ok := parseSerial(s); ok && x == serial {
					matched[j] = true
					return &ov.Regions[j]
				}
			}
		}
		return nil
	}
	for d := DevID(0); d < nDevs; d++ {
		mode := pr.poolMode[d]
		r := find(devices[d].Serial)
		switch {
		case mode == 0 && r != nil:
			k.waitf("%s: region %s of %s, no claim of it is prepared here", v, r.Name, d)
		case mode == 0:
		case r == nil:
			k.waitf("%s: no region of %s", v, d)
		default:
			k.checkPoolRegion(v, d, mode == 1, r)
		}
	}
	r := find(localSerial)
	n := pr.slicesN + pr.slicesD
	switch {
	case n == 0 && r != nil:
		if km, dd, _, _, _, _ := daxSummary(r); km+dd > 0 {
			k.waitf("%s: local region %s has %d slices, want none", v, r.Name, km+dd)
		} else {
			k.waitf("%s: local region %s not released", v, r.Name)
		}
	case n == 0:
	case r == nil:
		k.waitf("%s: no local region, want %d slices", v, n)
	default:
		km, dd, kms, dds, online, other := daxSummary(r)
		if km != pr.slicesN || dd != pr.slicesD || other > 0 {
			k.waitf("%s: local region %s: %d numa and %d dax slices (%d others), want %d and %d", v, r.Name, km, dd, other, pr.slicesN, pr.slicesD)
		}
		for _, s := range append(kms, dds...) {
			if s != blockSize {
				k.waitf("%s: local region %s: a slice of %d bytes, want %d", v, r.Name, s, blockSize)
				break
			}
		}
		for _, o := range online {
			if o != blockSize {
				k.waitf("%s: local region %s: a numa slice with %d bytes online, want %d", v, r.Name, o, blockSize)
				break
			}
		}
		if km > 0 && r.Node != nil && *r.Node != k.cfg.bridgeNode(HB0) {
			k.waitf("%s: local region %s on node %d, want %d (--node-hb0)", v, r.Name, *r.Node, k.cfg.bridgeNode(HB0))
		}
	}
	for j := range ov.Regions {
		if !matched[j] {
			k.waitf("%s: unexpected region %s (serials %s)", v, ov.Regions[j].Name, strings.Join(ov.Regions[j].Serials, ","))
		}
	}
}

func (pr *vmPred) anyPool() bool {
	for _, m := range pr.poolMode {
		if m != 0 {
			return true
		}
	}
	return false
}

func (k *checker) checkPoolRegion(v VM, d DevID, numa bool, r *ObsRegion) {
	dev := devices[d]
	if r.Mode == "pmem" {
		k.waitf("%s: region %s of %s: mode pmem", v, r.Name, d)
	}
	if r.Size != 0 && r.Size != dev.Size {
		k.waitf("%s: region %s of %s: size %d, want %d", v, r.Name, d, r.Size, dev.Size)
	}
	km, dd, _, _, online, other := daxSummary(r)
	if numa {
		want := k.cfg.bridgeNode(poolBridge[dev.Pool])
		switch {
		case km != 1 || dd != 0 || other != 0:
			k.waitf("%s: region %s of %s: %d kmem and %d device_dax devices, want numa (one kmem)", v, r.Name, d, km, dd)
		case online[0] != dev.Size:
			k.waitf("%s: region %s of %s: %d bytes online, want %d", v, r.Name, d, online[0], dev.Size)
		case r.Node != nil && *r.Node != want:
			k.waitf("%s: region %s of %s on node %d, want %d (--node-hb%d)", v, r.Name, d, *r.Node, want, poolBridge[dev.Pool])
		}
		return
	}
	if km != 0 || dd != 1 || other != 0 {
		k.waitf("%s: region %s of %s: %d kmem and %d device_dax devices (%d others), want dax (one device_dax, nothing online)", v, r.Name, d, km, dd, other)
	}
}

func (k *checker) checkNodes(v VM, ov *ObsVM, pr *vmPred) {
	if ov.Nodes == nil {
		k.waitf("%s: nodes not observed", v)
		return
	}
	for _, n := range k.cfg.cxlNodes() {
		got := ov.Nodes[strconv.Itoa(n)].MemTotal
		if got != pr.memTotal[n] {
			k.waitf("%s: node %d MemTotal %d (%dMi), want %d (%dMi)", v, n, got, got>>20, pr.memTotal[n], pr.memTotal[n]>>20)
		}
	}
}

// O4: the driver's state files and CDI specs.
func (k *checker) checkStateFiles(v VM, ov *ObsVM, pr *vmPred) {
	st := ov.State
	if st == nil {
		k.waitf("%s: driver state not observed", v)
		return
	}
	prep, info := setOf(st.Prepared), setOf(st.Info)
	if !sameSet(prep, info) {
		k.waitf("%s: preparedClaims.json %v != preparedClaimsInfo.json %v", v, sortedKeys(prep), sortedKeys(info))
	}
	for uid := range pr.localUIDs {
		if !prep[uid] {
			k.waitf("%s: claim %s not in preparedClaims.json", v, uid)
		}
	}
	if want := len(pr.localUIDs) + pr.leases; len(prep) != want {
		k.waitf("%s: %d claims in preparedClaims.json, want %d (%d of pods, %d companions)", v, len(prep), want, len(pr.localUIDs), pr.leases)
	}
	if pool := setOf(st.Pool); !sameSet(pool, pr.poolUIDs) {
		k.waitf("%s: preparedPoolClaims.json %v, want %v", v, sortedKeys(pool), sortedKeys(pr.poolUIDs))
	}
	if ld := st.LocalDevices; ld != nil {
		if ov.BootID != "" && ld.BootID != "" && ld.BootID != ov.BootID {
			k.waitf("%s: localDevices.json of boot %s, the VM runs %s", v, ld.BootID, ov.BootID)
		}
		n := pr.slicesN + pr.slicesD
		found := false
		for j := range ld.Devices {
			dev := &ld.Devices[j]
			serial, ok := dev.serial()
			if !ok || serial != localSerial {
				k.waitf("%s: localDevices.json has device %s", v, string(dev.Serial))
				continue
			}
			found = true
			claims := 0
			for uid := range dev.Claims {
				if uid == "-" {
					k.waitf("%s: localDevices.json: orphan slices (owner -)", v)
					continue
				}
				claims++
				if !prep[uid] {
					k.waitf("%s: localDevices.json: claim %s is not prepared", v, uid)
				}
				if s := dev.slices(uid); s != 1 {
					k.waitf("%s: localDevices.json: claim %s has %d slices, want 1", v, uid, s)
				}
			}
			if claims != n {
				k.waitf("%s: localDevices.json: %d claims, want %d", v, claims, n)
			}
		}
		if !found && n > 0 {
			k.waitf("%s: localDevices.json has no local memdev, want %d slices", v, n)
		}
	}
	if ov.CDI == nil {
		return
	}
	var claims, pool, leases map[string]bool
	for file, names := range ov.CDI {
		switch {
		case strings.Contains(file, "cxl-claims"):
			claims = cdiUIDs(names, "claim-", true)
		case strings.Contains(file, "cxl-pool"):
			pool = cdiUIDs(names, "claim-", true)
		case strings.Contains(file, "cxl-leases"):
			leases = cdiUIDs(names, "lease-", false)
		}
	}
	if claims == nil {
		claims = map[string]bool{}
	}
	if pool == nil {
		pool = map[string]bool{}
	}
	if leases == nil {
		leases = map[string]bool{}
	}
	if !sameSet(claims, pr.localUIDs) {
		k.waitf("%s: cxl-claims.yaml has claims %v, want %v", v, sortedKeys(claims), sortedKeys(pr.localUIDs))
	}
	if !sameSet(pool, pr.poolUIDs) {
		k.waitf("%s: cxl-pool.yaml has claims %v, want %v", v, sortedKeys(pool), sortedKeys(pr.poolUIDs))
	}
	if !sameSet(leases, pr.leaseUIDs) {
		k.waitf("%s: cxl-leases.yaml has claims %v, want %v", v, sortedKeys(leases), sortedKeys(pr.leaseUIDs))
	}
}

// cdiUIDs returns the claim UIDs of CDI device names PREFIX<uid>[-<n>].
func cdiUIDs(names []string, prefix string, indexed bool) map[string]bool {
	uids := map[string]bool{}
	for _, n := range names {
		if i := strings.LastIndex(n, "="); i >= 0 {
			n = n[i+1:] // a qualified name nri.io/cxl=claim-...
		}
		rest, ok := strings.CutPrefix(n, prefix)
		if !ok {
			continue
		}
		if indexed {
			if j := strings.LastIndexByte(rest, '-'); j > 0 {
				rest = rest[:j]
			}
		}
		uids[rest] = true
	}
	return uids
}

func setOf(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for x := range a {
		if !b[x] {
			return false
		}
	}
	return true
}

// O5: fencing and memory.high of the containers of the test's pods.
func (k *checker) checkFencing(v VM, ov *ObsVM, pr *vmPred) {
	rs := k.rs
	d := &rs.Drv[v]
	memNodes := map[int]bool{}
	for n, b := range pr.memTotal {
		if b > 0 {
			memNodes[n] = true
		}
	}
	fenced := map[int]bool{}
	for _, n := range rs.bitNodes(d.F) {
		fenced[n] = true
	}
	podSlot := map[string]int{}
	for i, p := range k.cur {
		if p != nil {
			podSlot[p.Name] = i
		}
	}
	companions := map[string]bool{}
	for _, c := range k.o.Companions {
		companions[c.Name] = true
	}
	// A11: every running container of the test's pods is observed
	listed := map[string]bool{}
	for _, c := range ov.Containers {
		listed[c.Pod] = true
	}
	for i, p := range k.cur {
		ss := &rs.Slots[i]
		if p == nil || ss.Phase != Running || ss.Node != v || p.Phase != "Running" || p.Deleting || listed[p.Name] {
			continue
		}
		k.waitf("%s: no container of %s (pod %s) observed", v, rs.slot(i).Name, p.Name)
	}
	for _, c := range k.o.Companions {
		if c.Node == v.String() && c.Phase == "Running" && !listed[c.Name] {
			k.waitf("%s: no container of companion %s observed", v, c.Name)
		}
	}
	for j := range ov.Containers {
		c := &ov.Containers[j]
		i, isSlot := podSlot[c.Pod]
		if !isSlot && !companions[c.Pod] {
			continue
		}
		entitled := map[int]bool{}
		name := "companion " + c.Pod
		steer := SteerNone
		if isSlot {
			ss := &rs.Slots[i]
			sl := rs.slot(i)
			name = sl.Name
			if ss.Phase != Running || ss.Node != v {
				continue
			}
			if sl.Kind.numa() {
				entitled[sl.numaNode(k.cfg)] = true
			}
			if sl.Kind == KLease && ss.Lease == LeaseHeld && ss.LeaseMode == ModeNuma {
				entitled[k.cfg.bridgeNode(HB0)] = true
			}
			steer = ss.Steer
			if sl.Kind == KLSteer && steer == SteerNone {
				steer = SteerOn
			}
		}
		// A11: cpuset.mems.effective of a live cgroup is never empty;
		// cpuset.mems is empty when the container inherits its
		// parent's (no NRI adjustment), so only effective is required
		memsStr := c.MemsEffective
		if memsStr == "" {
			k.waitf("%s: container of %s: cpuset.mems.effective not observed", v, name)
			continue
		}
		mems, err := parseNodeList(memsStr)
		if err != nil {
			k.waitf("%s: container %s: %v", v, name, err)
			continue
		}
		for _, n := range k.cfg.cxlNodes() {
			switch {
			case entitled[n] && !mems[n]:
				k.waitf("%s: container of %s: cpuset.mems %q lacks its node %d", v, name, memsStr, n)
			case !entitled[n] && mems[n] && (fenced[n] || memNodes[n]):
				k.waitf("%s: container of %s: cpuset.mems %q has fenced CXL node %d", v, name, memsStr, n)
			}
		}
		switch steer {
		case SteerOn:
			if c.MemoryHigh == "max" || c.MemoryHigh == "" {
				k.waitf("%s: container of %s: memory.high %q, want set (steered)", v, name, c.MemoryHigh)
			}
		case SteerAny:
		default:
			if c.MemoryHigh != "max" && c.MemoryHigh != "" {
				k.waitf("%s: container of %s: memory.high %q, want max", v, name, c.MemoryHigh)
			}
		}
	}
}

// O6: env and leases of inspected pods. Fatal: an inspection is not
// repeated.
func (k *checker) checkInspect() {
	for _, key := range sortedKeys(k.o.Inspect) {
		in := k.o.Inspect[key]
		i := k.cfg.slotIndex(key)
		if i < 0 {
			i = k.cfg.slotByLabel(key)
		}
		if i < 0 {
			k.failf("inspect: unknown slot %q", key)
			continue
		}
		p := k.cur[i]
		ss := &k.rs.Slots[i]
		if p == nil || in.UID != p.UID || ss.Phase != Running {
			continue
		}
		sl := k.rs.slot(i)
		for _, d := range envDiffs(k.cfg, sl, in.Env) {
			k.failf("env of %s: %s", sl.Name, d)
		}
		if sl.Kind == KLease {
			k.checkInspectLeases(i, in)
		}
	}
}

func (k *checker) checkInspectLeases(i int, in *ObsInspect) {
	ss := &k.rs.Slots[i]
	sl := k.rs.slot(i)
	list, ok := in.leases()
	if !ok {
		return
	}
	held := 0
	for _, l := range list {
		switch l.State {
		case "Releasing", "Released":
			continue
		case "Failed":
			k.failf("leases of %s: lease %s Failed", sl.Name, l.Lease)
			continue
		}
		held++
		if ss.Lease != LeaseHeld {
			k.failf("leases of %s: lease %s %s, want none", sl.Name, l.Lease, l.State)
			continue
		}
		if l.Mode != "" && l.Mode != ss.LeaseMode.String() {
			k.failf("leases of %s: lease %s mode %s, want %s", sl.Name, l.Lease, l.Mode, ss.LeaseMode)
		}
		if id := k.rs.LeaseIDs[i]; id != "" && l.Lease != id {
			k.failf("leases of %s: lease %s, want %s", sl.Name, l.Lease, id)
		}
	}
	if ss.Lease == LeaseHeld && held != 1 {
		k.failf("leases of %s: %d leases listed, want 1", sl.Name, held)
	}
}

// envWant is the expected env of a kind: exact values, and "/dev/dax"
// for a prefix.
func envWant(cfg *Config, sl *Slot) map[string]string {
	w := map[string]string{}
	add := func(serial uint64, mode string, size uint64, shared, readOnly bool, node int) {
		p := "CXL_" + serialKey(serial) + "_"
		w[p+"MODE"] = mode
		w[p+"SIZE"] = strconv.FormatUint(size, 10)
		w[p+"SERIAL"] = formatSerial(serial)
		w[p+"SHARED"] = boolEnv(shared)
		if mode == "dax" {
			w[p+"DAX"] = "/dev/dax*"
			w[p+"READONLY"] = boolEnv(readOnly)
		} else {
			w[p+"NODE"] = strconv.Itoa(node)
		}
	}
	switch k := sl.Kind; {
	case k.pooled():
		dev := devices[sl.Dev]
		mode := "dax"
		if k == KXNuma {
			mode = "numa"
		}
		add(dev.Serial, mode, dev.Size, dev.Shared, k == KSRo, cfg.bridgeNode(poolBridge[sl.Pool]))
	case k == KLDax:
		add(localSerial, "dax", blockSize, false, false, 0)
	case k.local():
		add(localSerial, "numa", blockSize, false, false, cfg.bridgeNode(HB0))
	case k == KLease:
		w["CXL_LEASE_SOCKET"] = "/run/cxl/cxl.sock"
	}
	return w
}

func boolEnv(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// envDiffs compares the CXL_* variables of an env with the kind's.
func envDiffs(cfg *Config, sl *Slot, env map[string]string) []string {
	want := envWant(cfg, sl)
	var diffs []string
	for _, key := range sortedKeys(want) {
		w := want[key]
		got, ok := env[key]
		switch {
		case !ok:
			diffs = append(diffs, key+" missing, want "+w)
		case strings.HasSuffix(w, "*"):
			if !strings.HasPrefix(got, strings.TrimSuffix(w, "*")) {
				diffs = append(diffs, fmt.Sprintf("%s=%s, want %s", key, got, w))
			}
		case key[len(key)-len("_SERIAL"):] == "_SERIAL" && strings.EqualFold(got, w):
		case got != w:
			diffs = append(diffs, fmt.Sprintf("%s=%s, want %s", key, got, w))
		}
	}
	var extra []string
	for key := range env {
		if !strings.HasPrefix(key, "CXL_") || strings.HasPrefix(key, "CXL_CLAIM_") {
			continue
		}
		if _, ok := want[key]; !ok {
			extra = append(extra, key+"="+env[key])
		}
	}
	sort.Strings(extra)
	for _, x := range extra {
		diffs = append(diffs, "unexpected "+x)
	}
	return diffs
}

// checkDone checks what a non-settle step returned (O7 for write, read
// and lease-get; the exit status for every step).
func checkDone(e *Expectation, d *DoneObs) Verdict {
	k := &checker{}
	want := e.Done
	if want == nil {
		want = &DoneJSON{Status: "zero"}
	}
	what := e.Action
	switch want.Status {
	case "nonzero":
		if d.Status == 0 {
			k.failf("%s: succeeded, want refused (read-only)", what)
		}
	default:
		if d.Status != 0 {
			msg := fmt.Sprintf("%s: exit status %d", what, d.Status)
			if d.Status == 2 && !e.verbIsObserved() {
				msg += " (unknown verb or arguments?)"
			}
			if d.Stderr != "" {
				msg += ": " + firstLine(d.Stderr)
			}
			k.failf("%s", msg)
		}
	}
	if len(k.fatal) == 0 {
		switch want.Verb {
		case "read":
			switch {
			case d.Text == nil:
				k.failf("%s: no text read", what)
			case want.Text != nil && *d.Text != *want.Text:
				k.failf("%s: read %q, want %q", what, *d.Text, *want.Text)
			}
		case "lease-get":
			if d.Lease == nil || *d.Lease == "" {
				k.failf("%s: no lease", what)
			}
		}
	}
	return k.verdict("")
}

func (e *Expectation) verbIsObserved() bool {
	return e.Done != nil && (e.Done.Verb == "write" || e.Done.Verb == "read" || e.Done.Verb == "lease-get")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// adoptDone returns the state after a done observation: the lease ID of
// a lease-get, the content read from an unknown device.
func adoptDone(s *State, a Act, d *DoneObs) *State {
	switch {
	case a.Verb == VLeaseGet && d.Lease != nil:
		n := s.clone()
		n.setLeaseID(int(a.Slot), *d.Lease)
		return n
	case a.Verb == VRead && d.Text != nil && !s.token(int(a.Slot)).Known:
		n := s.clone()
		t := Token{Known: true, Text: *d.Text}
		if sl := n.slot(int(a.Slot)); sl.Kind == KLDax {
			n.setSlotData(int(a.Slot), t)
		} else {
			n.Data[sl.Dev] = t
		}
		return n
	}
	return s
}
