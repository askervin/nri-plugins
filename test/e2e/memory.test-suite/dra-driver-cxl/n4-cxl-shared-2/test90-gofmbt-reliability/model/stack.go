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

// Decoder stacks (contract A9, bug-02): Linux allocates the HDM decoders
// of a CXL port as a stack. Per (VM, host bridge) the model keeps the
// regions through it in creation order: a new region is pushed (only if
// there is no hole), destroying the top pops it and every hole below,
// destroying another one leaves a hole. A Prepare that needs a new
// region through a stack with a hole fails: the pod is blocked until
// the hole clears.
//
// Region lifetimes on a VM: an exclusive pool device = its claim; a
// shared pool device = its first to last claim on the VM; the local
// memdev = its first to last slice (pods and leases). Users prepare and
// unprepare regions; the transitions record these events, and the
// settle plays them in every order that can happen (async operations of
// one window race for the order) to get the outcomes.

import (
	"sort"
	"strconv"
	"strings"
)

// RKey is a region of a stack: the local memdev or a pool device.
type RKey int8

const (
	rkHole  RKey = -1
	rkLocal RKey = 0
)

func devKey(d DevID) RKey { return RKey(1 + d) }

func (k RKey) String() string {
	switch {
	case k == rkHole:
		return "hole"
	case k == rkLocal:
		return "local"
	}
	return DevID(k - 1).String()
}

// kind is the abstraction of a key in C4: local, pooled or shared.
func (k RKey) kind() string {
	switch {
	case k == rkHole:
		return "hole"
	case k == rkLocal:
		return "local"
	case devices[k-1].Shared:
		return "shared"
	}
	return "pooled"
}

// serial of the region of a key.
func (k RKey) serial() uint64 {
	if k == rkLocal {
		return localSerial
	}
	return devices[k-1].Serial
}

const maxStack = 8

// Stack is the decoder stack of one host bridge of one VM.
type Stack struct {
	N int8
	E [maxStack]RKey
}

const nStacks = nVMs * nBridges

func stackIndex(v VM, b Bridge) int { return int(v)*nBridges + int(b) }

func stackVM(si int) VM         { return VM(si / nBridges) }
func stackBridge(si int) Bridge { return Bridge(si % nBridges) }

func stackName(si int) string {
	return stackVM(si).String() + "/hb" + string(rune('0'+stackBridge(si)))
}

func (s *Stack) hasHole() bool {
	for i := int8(0); i < s.N; i++ {
		if s.E[i] == rkHole {
			return true
		}
	}
	return false
}

func (s *Stack) holes() int {
	n := 0
	for i := int8(0); i < s.N; i++ {
		if s.E[i] == rkHole {
			n++
		}
	}
	return n
}

func (s *Stack) contains(k RKey) bool {
	for i := int8(0); i < s.N; i++ {
		if s.E[i] == k {
			return true
		}
	}
	return false
}

func (s *Stack) top() RKey {
	if s.N == 0 {
		return rkHole
	}
	return s.E[s.N-1]
}

func (s *Stack) push(k RKey) {
	if s.N < maxStack {
		s.E[s.N] = k
		s.N++
	}
}

// destroy destroys the region of a key: the top is popped with every
// hole below it, another one becomes a hole.
func (s *Stack) destroy(k RKey) {
	for i := s.N - 1; i >= 0; i-- {
		if s.E[i] != k {
			continue
		}
		if i == s.N-1 {
			s.N--
			s.E[s.N] = 0
			for s.N > 0 && s.E[s.N-1] == rkHole {
				s.N--
				s.E[s.N] = 0
			}
		} else {
			s.E[i] = rkHole
		}
		return
	}
}

// equal compares the entries of two stacks.
func (s *Stack) equal(o *Stack) bool {
	if s.N != o.N {
		return false
	}
	for i := int8(0); i < s.N; i++ {
		if s.E[i] != o.E[i] {
			return false
		}
	}
	return true
}

// keys returns the entries.
func (s *Stack) keys() []RKey { return append([]RKey(nil), s.E[:s.N]...) }

func (s Stack) String() string {
	parts := make([]string, 0, s.N)
	for i := int8(0); i < s.N; i++ {
		parts = append(parts, s.E[i].String())
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// --- users and events ---

// A user of a region is the claim of a slot's pod (user = slot index) or
// the companion slice of the lease of a lease slot (user = nSlots +
// slot index).
func (s *State) leaseUser(i int) int16 { return int16(len(s.Slots) + i) }

// userSlot returns the slot of a user and whether it is a lease.
func (s *State) userSlot(u int16) (int, bool) {
	if int(u) >= len(s.Slots) {
		return int(u) - len(s.Slots), true
	}
	return int(u), false
}

// userRegion returns the stack and region of a user on its node, false
// if the user has no region (plain, lease claims) or no known node.
func (s *State) userRegion(u int16) (int, RKey, bool) {
	i, lease := s.userSlot(u)
	sl := s.slot(i)
	if lease {
		if sl.Kind != KLease {
			return 0, 0, false
		}
		return stackIndex(sl.VM, HB0), rkLocal, true
	}
	v := s.Slots[i].Node
	switch {
	case v == VMAny:
		return 0, 0, false
	case sl.Kind.pooled():
		return stackIndex(v, poolBridge[sl.Pool]), devKey(sl.Dev), true
	case sl.Kind.local():
		return stackIndex(v, HB0), rkLocal, true
	}
	return 0, 0, false
}

type evKind uint8

const (
	evPrepare evKind = iota
	evUnprepare
)

// stackEvent is a prepare or unprepare of a user in the current window.
type stackEvent struct {
	Stack int8
	Key   RKey
	User  int16
	Kind  evKind
	Opt   bool  // a prepare that may not happen (a controller kill)
	Sync  bool  // done before the next action was sent (lease-get)
	Seq   int16 // issue order
	After int16 // happens after the event of this Seq (a handover), -1
	// Handover: the claim got its device only when the earlier
	// holders of it were gone: its prepare comes after every earlier
	// unprepare of the same region (R1 of 05-review: the scheduler
	// allocates it after their claims are deallocated, which is after
	// their Unprepare)
	Handover bool
}

// addEvent records an event of a user (copy on write). The stack of an
// "any" pod whose node is not known yet is -1 (the settle tries every
// host).
func (n *State) addEvent(u int16, kind evKind, sync bool, after int16) int16 {
	si, k, ok := n.userRegion(u)
	if !ok {
		i, lease := n.userSlot(u)
		sl := n.slot(i)
		if lease || !sl.Kind.pooled() || n.Slots[i].Node != VMAny {
			return -1
		}
		si, k = -1, devKey(sl.Dev)
	}
	seq := int16(len(n.Ev))
	n.Ev = append(n.Ev[:len(n.Ev):len(n.Ev)], stackEvent{Stack: int8(si), Key: k, User: u, Kind: kind, Sync: sync, Seq: seq, After: after})
	return seq
}

// setHandover marks the event of a seq as a handover.
func (n *State) setHandover(seq int16) {
	if seq < 0 || int(seq) >= len(n.Ev) {
		return
	}
	n.Ev = append([]stackEvent(nil), n.Ev...)
	n.Ev[seq].Handover = true
}

// hasPrepare tells if a user has a prepare event in this window.
func (s *State) hasPrepare(u int16) bool {
	for _, e := range s.Ev {
		if e.User == u && e.Kind == evPrepare {
			return true
		}
	}
	return false
}

// setOptional makes the prepare events of a user optional.
func (n *State) setOptional(u int16) {
	for j := range n.Ev {
		if n.Ev[j].User == u && n.Ev[j].Kind == evPrepare && !n.Ev[j].Opt {
			n.Ev = append([]stackEvent(nil), n.Ev...)
			n.Ev[j].Opt = true
		}
	}
}

// eventsOn returns the events of a stack.
func (s *State) eventsOn(si int) []stackEvent {
	var out []stackEvent
	for _, e := range s.Ev {
		if int(e.Stack) == si {
			out = append(out, e)
		}
	}
	return out
}

// preparedAtStart tells if a user had its region at the start of the
// window (before its events).
func (s *State) preparedAtStart(u int16) bool {
	i, lease := s.userSlot(u)
	ss := &s.Slots[i]
	if lease {
		return (ss.Lease == LeaseHeld || ss.Lease == LeaseReleasing) && !s.hasPrepare(u)
	}
	if s.hasPrepare(u) {
		return false
	}
	switch ss.Phase {
	case Running, Restarting:
		return true
	case Deleting:
		return ss.Prev == Running || ss.Prev == Restarting
	}
	return false
}

// blockedAtStart tells if a user was blocked at the start of the window
// and still holds its claim (it keeps retrying).
func (s *State) blockedAtStart(u int16) bool {
	i, lease := s.userSlot(u)
	return !lease && s.Slots[i].Phase == Blocked
}

// stackOutcome is what a window did to a stack.
type stackOutcome struct {
	S        Stack
	Prepared map[int16]bool // users with their region at the end
	Blocked  map[int16]bool // users whose prepare failed and that wait
	Cleared  bool           // the stack had a hole, it has none at the end
	Pushed   bool           // a region was made in the window
}

func (o *stackOutcome) key() string {
	var b strings.Builder
	b.WriteString(o.S.String())
	for _, m := range []map[int16]bool{o.Prepared, o.Blocked} {
		b.WriteByte('|')
		for _, u := range sortedUsers(m) {
			b.WriteString(strconv.Itoa(int(u)))
			b.WriteByte(',')
		}
	}
	return b.String()
}

func sortedUsers(m map[int16]bool) []int16 {
	us := make([]int16, 0, len(m))
	for u, on := range m {
		if on {
			us = append(us, u)
		}
	}
	sort.Slice(us, func(i, j int) bool { return us[i] < us[j] })
	return us
}

// maxEvents is the most events of one stack whose orders are enumerated
// (with memoization); more are played in issue order only, and the
// settle says so (Truncated).
const maxEvents = 24

// userSet is a set of users (slots and leases of up to 96 slots).
type userSet [3]uint64

func (u *userSet) has(x int16) bool { return u[x/64]&(1<<uint(x%64)) != 0 }
func (u *userSet) set(x int16)      { u[x/64] |= 1 << uint(x%64) }
func (u *userSet) clear(x int16)    { u[x/64] &^= 1 << uint(x%64) }

func (u *userSet) toMap() map[int16]bool {
	m := map[int16]bool{}
	for x := int16(0); x < 192; x++ {
		if u.has(x) {
			m[x] = true
		}
	}
	return m
}

// playState is the state of a stack while the events of a window are
// played.
type playState struct {
	S        Stack
	ref      [1 + nDevs]int8
	prepared userSet
	blocked  userSet
	pushed   bool
}

func (p *playState) apply(e *stackEvent) {
	switch e.Kind {
	case evPrepare:
		switch {
		case p.ref[e.Key] > 0:
			p.ref[e.Key]++
			p.prepared.set(e.User)
		case p.S.hasHole():
			p.blocked.set(e.User)
		default:
			p.S.push(e.Key)
			p.ref[e.Key] = 1
			p.prepared.set(e.User)
			p.pushed = true
		}
	case evUnprepare:
		p.blocked.clear(e.User)
		if p.prepared.has(e.User) {
			p.prepared.clear(e.User)
			p.ref[e.Key]--
			if p.ref[e.Key] == 0 {
				p.S.destroy(e.Key)
			}
		}
	}
}

func (p *playState) memoKey(mask uint32) string {
	b := make([]byte, 0, 4+maxStack+len(p.ref)+48)
	b = append(b, byte(mask), byte(mask>>8), byte(mask>>16), byte(mask>>24), byte(p.S.N))
	for _, k := range p.S.E[:p.S.N] {
		b = append(b, byte(k+1))
	}
	for _, r := range p.ref {
		b = append(b, byte(r))
	}
	for _, w := range append(p.prepared[:], p.blocked[:]...) {
		for i := 0; i < 8; i++ {
			b = append(b, byte(w>>(8*i)))
		}
	}
	if p.pushed {
		b = append(b, 1)
	}
	return string(b)
}

// outcomes returns the distinct outcomes of the window on a stack, the
// one of the issue order (every optional prepare done) first, and
// whether the enumeration was cut (too many events: issue order only).
func (s *State) outcomes(si int) []*stackOutcome {
	outs, _ := s.outcomesCut(si)
	return outs
}

func (s *State) outcomesCut(si int) ([]*stackOutcome, bool) {
	evs := s.eventsOn(si)
	var start playState
	start.S = s.Stacks[si]
	// every user of the stack, also those without events
	for u := int16(0); int(u) < 2*len(s.Slots); u++ {
		if ssi, k, ok := s.userRegion(u); ok && ssi == si {
			if s.preparedAtStart(u) {
				start.prepared.set(u)
				start.ref[k]++
			}
			if s.blockedAtStart(u) {
				start.blocked.set(u)
			}
		}
	}
	hadHole := start.S.hasHole()
	var outs []*stackOutcome
	seen := map[string]bool{}
	add := func(p *playState) {
		o := &stackOutcome{S: p.S, Prepared: p.prepared.toMap(), Blocked: p.blocked.toMap(),
			Cleared: hadHole && !p.S.hasHole(), Pushed: p.pushed}
		if k := o.key(); !seen[k] {
			seen[k] = true
			outs = append(outs, o)
		}
	}
	// the issue order first
	issue := start
	for j := range evs {
		issue.apply(&evs[j])
	}
	add(&issue)
	if len(evs) == 0 {
		return outs, false
	}
	if len(evs) > maxEvents {
		return outs, true
	}
	bySeq := map[int16]int{}
	for j, e := range evs {
		bySeq[e.Seq] = j
	}
	full := uint32(1)<<uint(len(evs)) - 1
	memo := map[string]bool{}
	var dfs func(mask uint32, p playState)
	dfs = func(mask uint32, p playState) {
		if mask == full {
			add(&p)
			return
		}
		k := p.memoKey(mask)
		if memo[k] {
			return
		}
		memo[k] = true
		for j := range evs {
			bit := uint32(1) << uint(j)
			if mask&bit != 0 || !ready(evs, mask, bySeq, j) {
				continue
			}
			q := p
			q.apply(&evs[j])
			dfs(mask|bit, q)
			if evs[j].Opt {
				// the optional prepare does not happen
				dfs(mask|bit, p)
			}
		}
	}
	dfs(0, start)
	return outs, false
}

// ready tells if event j may come next (mask: the events placed): sync
// events issued before it, the event it comes after, the prepare of its
// user and, for a handover, the earlier unprepares of its region are
// placed.
func ready(evs []stackEvent, mask uint32, bySeq map[int16]int, j int) bool {
	e := &evs[j]
	for x := range evs {
		f := &evs[x]
		if x == j || mask&(1<<uint(x)) != 0 {
			continue
		}
		// a sync event (lease-get) was done before anything issued
		// after it; async events issued before it may come later
		if f.Sync && f.Seq < e.Seq {
			return false
		}
		if e.Kind == evUnprepare && f.User == e.User && f.Kind == evPrepare {
			return false
		}
		if e.Kind == evPrepare && e.Handover && f.Kind == evUnprepare && f.Key == e.Key && f.Seq < e.Seq {
			return false
		}
	}
	if e.After >= 0 {
		if x, ok := bySeq[e.After]; ok && mask&(1<<uint(x)) == 0 {
			return false
		}
	}
	return true
}

// unblockingOn tells if a stack has a user that waits for kubelet's retry
// or the scheduler's requeue (a stalled contender, also of an "any" slot)
// after its hole cleared.
func (s *State) unblockingOn(si int) bool {
	for i := range s.Slots {
		if !s.Slots[i].Phase.waitsRetry() {
			continue
		}
		if ssi, _, ok := s.userRegion(int16(i)); ok && ssi == si {
			return true
		}
		// an "any" pod whose node is not known yet: any host of its
		// pool
		if sl := s.slot(i); sl.Kind.pooled() && s.Slots[i].Node == VMAny && poolBridge[sl.Pool] == stackBridge(si) && poolHasHost(sl.Pool, stackVM(si)) {
			return true
		}
	}
	return false
}

// stacksTouched returns the stacks with events.
func (s *State) stacksTouched() []int {
	var touched [nStacks]bool
	for _, e := range s.Ev {
		touched[e.Stack] = true
	}
	var out []int
	for si := range touched {
		if touched[si] {
			out = append(out, si)
		}
	}
	return out
}

// setRequired makes the prepare events of a user happen for sure (its
// controller is up again).
func (n *State) setRequired(u int16) {
	for j := range n.Ev {
		if n.Ev[j].User == u && n.Ev[j].Kind == evPrepare && n.Ev[j].Opt {
			n.Ev = append([]stackEvent(nil), n.Ev...)
			n.Ev[j].Opt = false
		}
	}
}

// maxAlts bounds the outcomes of one settle.
const maxAlts = 64

// settleAll returns the settled state of a window, and in its Alts the
// other outcomes that its races for the decoder stacks (and the node of
// an "any" pod) can have. The first state is the issue order with the
// first host of every "any" pod.
func (n *State) settleAll() *State {
	var alts []*State
	seen := map[string]bool{}
	truncated := false
	var bases []*State
	for _, w := range n.expandSlices() {
		bases = append(bases, w.expandAnyNodes()...)
	}
	for _, b := range bases {
		var sis []int
		var outs [][]*stackOutcome
		for si := 0; si < nStacks; si++ {
			if len(b.eventsOn(si)) == 0 && !b.blockedOn(si) {
				continue
			}
			o, cut := b.outcomesCut(si)
			truncated = truncated || cut
			sis = append(sis, si)
			outs = append(outs, o)
		}
		idx := make([]int, len(sis))
		for {
			a := b.clone()
			for j, si := range sis {
				a.applyOutcome(si, outs[j][idx[j]])
			}
			a.settle()
			if k := a.altKey(); !seen[k] {
				seen[k] = true
				alts = append(alts, a)
			}
			if len(alts) >= maxAlts {
				truncated = true
				break
			}
			// the next combination
			j := len(idx) - 1
			for ; j >= 0; j-- {
				idx[j]++
				if idx[j] < len(outs[j]) {
					break
				}
				idx[j] = 0
			}
			if j < 0 {
				break
			}
		}
		if len(alts) >= maxAlts {
			break
		}
	}
	p := alts[0]
	p.Alts = alts[1:]
	p.Truncated = truncated
	return p
}

// expandSlices returns a state per world of the pools whose controller is
// down while it is not known whether it published its slices again
// after a graceful restart (A18): present (as is) and absent (the claims
// of the pool that are being allocated cannot be: Unsched, no prepare).
func (n *State) expandSlices() []*State {
	states := []*State{n}
	for p := Pool(0); p < nPools; p++ {
		if n.Ctrl[p].Up || n.Ctrl[p].Slices != SlicesUnknown {
			continue
		}
		var next []*State
		for _, b := range states {
			present := b.clone()
			present.Ctrl[p].Slices = SlicesPresent
			absent := b.clone()
			absent.Ctrl[p].Slices = SlicesAbsent
			var ev []stackEvent
			for i := range absent.Slots {
				sl := absent.slot(i)
				if ss := &absent.Slots[i]; sl.Kind.pooled() && sl.Pool == p && ss.Phase == Starting {
					ss.Phase, ss.RaceKill = Unsched, false
				}
			}
			for _, e := range absent.Ev {
				if i, lease := absent.userSlot(e.User); !lease && absent.Slots[i].Phase == Unsched {
					continue
				}
				ev = append(ev, e)
			}
			absent.Ev = ev
			next = append(next, present, absent)
		}
		states = next
	}
	return states
}

// blockedOn tells if a stack has a blocked pod.
func (s *State) blockedOn(si int) bool {
	for i := range s.Slots {
		if s.Slots[i].Phase == Blocked {
			if ssi, _, ok := s.userRegion(int16(i)); ok && ssi == si {
				return true
			}
		}
	}
	return false
}

// expandAnyNodes returns a state per combination of hosts of the "any"
// pods that prepare in this window on a node that is not known yet.
func (n *State) expandAnyNodes() []*State {
	var anys []int
	for _, e := range n.Ev {
		if e.Stack >= 0 {
			continue
		}
		i, _ := n.userSlot(e.User)
		dup := false
		for _, x := range anys {
			dup = dup || x == i
		}
		if !dup {
			anys = append(anys, i)
		}
	}
	states := []*State{n}
	for _, i := range anys {
		var next []*State
		sl := n.slot(i)
		for _, b := range states {
			for _, v := range poolHosts[sl.Pool] {
				c := b.clone()
				c.Slots[i].Node = v
				c.Ev = append([]stackEvent(nil), b.Ev...)
				for j := range c.Ev {
					if c.Ev[j].Stack < 0 && int(c.Ev[j].User) == i {
						c.Ev[j].Stack = int8(stackIndex(v, poolBridge[sl.Pool]))
					}
				}
				next = append(next, c)
			}
		}
		states = next
	}
	return states
}

// applyOutcome sets the stack and the phases of its pods by an outcome:
// prepared -> Running, a failed prepare -> Blocked, or Unblocking when
// no hole is left; a prepare that did not happen (a controller kill) ->
// Attaching. Pods being deleted are left to the settle.
func (a *State) applyOutcome(si int, o *stackOutcome) {
	a.Stacks[si] = o.S
	hole := o.S.hasHole()
	users := map[int16]bool{}
	for _, e := range a.eventsOn(si) {
		users[e.User] = true
	}
	for u := range o.Blocked {
		users[u] = true
	}
	for _, u := range sortedUsers(users) {
		i, lease := a.userSlot(u)
		if lease {
			continue
		}
		ss := &a.Slots[i]
		sl := a.slot(i)
		if ss.Phase == Deleting || ss.Phase == Absent {
			continue
		}
		switch {
		case o.Prepared[u]:
			ss.Phase = Running
		case o.Blocked[u] && hole:
			ss.Phase = Blocked
		case o.Blocked[u]:
			if ss.Phase != Unblocking {
				a.setUnblockAt(i, 0)
			}
			ss.Phase = Unblocking
		case ss.Phase == Starting && sl.Kind.pooled() && !a.Ctrl[sl.Pool].Up:
			ss.Phase = Attaching
		}
		ss.RaceKill = false
	}
}

// altKey identifies a settled outcome.
func (s *State) altKey() string {
	b := make([]byte, 0, 4*len(s.Slots)+nStacks*(maxStack+1))
	for i := range s.Slots {
		b = append(b, byte(s.Slots[i].Phase), byte(s.Slots[i].Node+1))
	}
	for si := range s.Stacks {
		st := &s.Stacks[si]
		b = append(b, byte(st.N))
		for _, k := range st.E[:st.N] {
			b = append(b, byte(k+1))
		}
	}
	// the pools: worlds that differ only in the slices or the
	// attachments of a pool are different outcomes (L3, M4)
	for p := range s.Ctrl {
		c := &s.Ctrl[p]
		b = append(b, byte(c.Slices))
		for _, row := range c.Att {
			for _, t := range row {
				b = append(b, byte(t))
			}
		}
	}
	return string(b)
}
