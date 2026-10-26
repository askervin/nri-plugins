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

// The model state: the slot model of 02-design.txt 4 (M1). Every slot
// holds at most one pod; what the pods hold (pool devices, local blocks,
// leases) is derived from the slots. The state is immutable once a
// transition has returned it; String() and the coverage abstraction are
// memoized (race-free: the planner and the oracle share states).

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
)

// Phase is the phase of the pod of a slot.
type Phase uint8

const (
	// Absent: no pod.
	Absent Phase = iota
	// Starting: created (or promoted from Pending) in the current
	// window; Running at the next settle, or Attaching if its pool
	// controller is down then. Holds its resource.
	Starting
	// Restarting: crashed in the current window; Running again at the
	// next settle with one more restart. Holds its resource.
	Restarting
	// Running: settled, Running and Ready.
	Running
	// Pending: unschedulable, waits for its resource (at most one per
	// resource). Holds nothing.
	Pending
	// Attaching: allocated, waits for the attach of its pool device
	// while the pool controller is down. Holds its device.
	Attaching
	// Either: Running or Attaching, the outcome of a pool controller
	// killed while the pod was starting. Resolved by the observation.
	Either
	// Deleting: deleted in the current window; absent at the next
	// settle. Holds its resource if Prev did.
	Deleting
	// Blocked: allocated (and attached), but its Prepare needs a new
	// region through a decoder stack with a hole (A9): Pending,
	// ContainerCreating, retried by kubelet. Holds its resource.
	Blocked
	// Unblocking: was blocked, the hole has cleared: Running at
	// kubelet's next retry (within --unblock-timeout); ContainerCreating
	// is accepted meanwhile. Holds its resource.
	Unblocking
	// Unsched: a pool claim that the scheduler cannot allocate because
	// its pool has no ResourceSlices (a controller killed before it
	// published them again, A18): Pending, unschedulable, until the
	// controller is back. Holds its resource in the model (it is the
	// only candidate for it then).
	Unsched
	// Stalled: the contender of a device whose holder was deleted
	// while its claim waited for the binding conditions (A19, bug-08):
	// the scheduler may keep it Pending (claim not allocated) until a
	// requeueing event or 5:30 after the delete, or promote it at once.
	// Both are accepted for 360 s; the observation decides. Holds the
	// device in the model (the only candidate).
	Stalled
	nPhases
)

var phaseNames = [nPhases]string{"absent", "starting", "restarting", "running", "pending", "attaching", "either", "deleting", "blocked", "unblocking", "unsched", "stalled"}

func (p Phase) String() string { return phaseNames[p] }

func parsePhase(s string) (Phase, error) {
	for p := Phase(0); p < nPhases; p++ {
		if phaseNames[p] == s {
			return p, nil
		}
	}
	return 0, fmt.Errorf("invalid phase %q", s)
}

// holding: the pod of the phase holds (or will hold) its resource and is
// not being deleted.
func (p Phase) holding() bool {
	return p == Starting || p == Restarting || p == Running || p == Attaching || p == Either || p == Blocked || p == Unblocking || p == Unsched || p == Stalled
}

// unbound: a pool pod of the phase may have its claim allocated while
// it is not bound yet (PreBind waits for the binding conditions).
func (p Phase) unbound() bool {
	return p == Starting || p == Attaching || p == Either || p == Stalled
}

// waitsRetry: the pod gets its region at a time the model does not know
// (kubelet's retry, the scheduler's requeue): nothing else may change its
// decoder stack meanwhile.
func (p Phase) waitsRetry() bool { return p == Unblocking || p == Stalled }

// Steer is what memory.high of an lsteer container is.
type Steer uint8

const (
	SteerNone Steer = iota // not an lsteer slot, or no container
	SteerOn                // steered by the running driver: memory.high != max
	SteerOff               // its manager died with an earlier driver: max
	SteerAny               // started in a driver restart window: either
)

var steerNames = []string{"", "on", "off", "any"}

func (s Steer) String() string { return steerNames[s] }

// LeaseSt is the lease of a lease slot.
type LeaseSt uint8

const (
	LeaseNone      LeaseSt = iota
	LeaseHeld              // Ready, with its companion pod
	LeaseReleasing         // released in the current window: gone at the settle
)

// LeaseMode is the mode of a lease.
type LeaseMode uint8

const (
	ModeNuma LeaseMode = iota
	ModeDax
)

func (m LeaseMode) String() string {
	if m == ModeDax {
		return "dax"
	}
	return "numa"
}

// Token is what offset 0 of a dax device holds.
type Token struct {
	Known bool
	Text  string
}

func (t Token) String() string {
	if !t.Known {
		return "?"
	}
	return fmt.Sprintf("%q", t.Text)
}

var (
	tokUnknown = Token{}
	tokZero    = Token{Known: true}
)

// Tri is a three-valued attachment.
type Tri uint8

const (
	TriNo Tri = iota
	TriYes
	TriMaybe
)

// SlotState is the pod of a slot. The data of ldax slices and the lease
// IDs are in State.SlotData and State.LeaseIDs (shared between states
// until changed), so that copying the slots of a state is cheap.
type SlotState struct {
	Phase     Phase
	Prev      Phase // Deleting: the phase when deleted
	Node      VM    // the VM of the pod; VMAny until known (any slots)
	Gen       uint16
	Restarts  uint8
	RaceKill  bool // Starting when its pool controller was killed
	Steer     Steer
	Lease     LeaseSt
	LeaseMode LeaseMode
	// Slack: restarts the pod may have more than its crashes (M2: a
	// kubelet restart while its container is being created)
	Slack uint8
}

// holds: the slot holds its resource now (also while deleting).
func (ss *SlotState) holds() bool {
	return ss.Phase.holding() || (ss.Phase == Deleting && ss.Prev.holding())
}

// DriverState is the driver of a VM.
type DriverState struct {
	PodGen    uint16 // driver pods replaced by driver-restart
	Restarts  uint8  // container restarts of the current pod (driver-kill)
	Inc       uint16 // incarnations: kills and restarts
	Killed    bool   // driver-kill in the current window
	Restarted bool   // driver-restart in the current window
	F, FMaybe uint8  // fenced host bridges (bit b: node NodeHB[b]); maybe
	Pod       string // the pod name, learnt at a settle
	PodBefore string // driver-restart: the pod that must be gone
}

// CtrlState is the controller of a pool, and what is known of the
// attachments of its devices (index 0 pooled, 1 shared) per VM when it
// is down; when it is up, the attachments are derived from the claims at
// every settle.
type CtrlState struct {
	Up     bool
	Att    [2][nVMs]Tri
	Slices SliceSt // the pool's ResourceSlices (A18)
}

// SliceSt tells if a pool's controller has published its ResourceSlices.
type SliceSt uint8

const (
	SlicesPresent SliceSt = iota
	SlicesAbsent          // deleted by a graceful stop, not published again
	SlicesUnknown         // a graceful restart: published again soon, or not
)

var sliceNames = []string{"present", "absent", "unknown"}

func (s SliceSt) String() string { return sliceNames[s] }

// State is the model state.
type State struct {
	cfg       *Config
	Slots     []SlotState
	Ctrl      [nPools]CtrlState
	Drv       [nVMs]DriverState
	Data      [nDevs]Token // pool devices
	SlotData  []Token      // ldax slots: the content of the slice (copy on write)
	LeaseIDs  []string     // lease slots: the lease ID if known (copy on write)
	UnblockAt []int64      // Unblocking, Stalled, Attaching slots: Unix time first seen so on-line (copy on write)
	Stacks    [nStacks]Stack
	Ev        []stackEvent // region events of the current window (copy on write)
	Alts      []*State     // a settle: the other possible outcomes (A9 races)
	Truncated bool         // a settle: its outcomes were not all enumerated
	Contested uint16       // resources with an unsettled transfer: no creates
	// Held: pool devices whose claim was deleted before its pod was
	// bound, in a window that a settle ended: kube-scheduler may still
	// hold the device in flight (up to 5 s after the delete, A19): a
	// contender created now may stall. HeldAt: the Unix time of the
	// settle that ended that window (on-line; the oracle clears the
	// bit 6 s after it).
	Held   uint16
	HeldAt [nDevs]int64
	// Released: pool devices whose claim was deleted in the window that
	// the last settle ended: the claim may still be deallocated a
	// moment after its pod is gone (0.1-0.3 s); a claim created now may
	// fail its first attempt and wait for that event, and a second one
	// would race with it: one candidate (contested) per such device
	Released  uint16
	Unsettled uint8
	Steps     int32 // steps executed: the next step is Steps+1
	Last      Act   // the action that led to this state
	memo      atomic.Pointer[stateMemo]
	occMemo   atomic.Pointer[occupancy]
}

type stateMemo struct {
	abstract []string
	str      string
}

// newState is the state at the start of a test: nothing allocated, the
// controllers up, nothing fenced, the content of pool devices unknown.
func newState(cfg *Config) *State {
	s := &State{
		cfg:       cfg,
		Slots:     make([]SlotState, len(cfg.Slots)),
		SlotData:  make([]Token, len(cfg.Slots)),
		LeaseIDs:  make([]string, len(cfg.Slots)),
		UnblockAt: make([]int64, len(cfg.Slots)),
	}
	for i := range s.Slots {
		s.Slots[i].Node = cfg.Slots[i].VM
	}
	for p := range s.Ctrl {
		s.Ctrl[p].Up = true
	}
	s.Last = Act{Verb: VNone, Slot: -1}
	return s
}

func (s *State) clone() *State {
	n := &State{
		cfg:       s.cfg,
		Slots:     append([]SlotState(nil), s.Slots...),
		Ctrl:      s.Ctrl,
		Drv:       s.Drv,
		Data:      s.Data,
		SlotData:  s.SlotData,
		LeaseIDs:  s.LeaseIDs,
		UnblockAt: s.UnblockAt,
		Stacks:    s.Stacks,
		Ev:        s.Ev,
		Contested: s.Contested,
		Held:      s.Held,
		Released:  s.Released,
		HeldAt:    s.HeldAt,
		Unsettled: s.Unsettled,
		Steps:     s.Steps,
		Last:      s.Last,
	}
	return n
}

// setSlotData sets the data of an ldax slot (copy on write: call only
// on a state that a transition is building).
func (s *State) setSlotData(i int, t Token) {
	if s.SlotData[i] == t {
		return
	}
	s.SlotData = append([]Token(nil), s.SlotData...)
	s.SlotData[i] = t
}

// setLeaseID sets the lease ID of a lease slot (copy on write).
func (s *State) setLeaseID(i int, id string) {
	if s.LeaseIDs[i] == id {
		return
	}
	s.LeaseIDs = append([]string(nil), s.LeaseIDs...)
	s.LeaseIDs[i] = id
}

// unblockAt is when an Unblocking slot was first seen so (0: unknown).
func (s *State) unblockAt(i int) int64 { return s.UnblockAt[i] }

// setUnblockAt sets it (copy on write).
func (s *State) setUnblockAt(i int, t int64) {
	if s.UnblockAt[i] == t {
		return
	}
	s.UnblockAt = append([]int64(nil), s.UnblockAt...)
	s.UnblockAt[i] = t
}

// slot returns the static slot i.
func (s *State) slot(i int) *Slot { return &s.cfg.Slots[i] }

// --- derived occupancy ---

// occupancy counts what the slots hold. Holders "held" are not going
// away, "all" includes those that are being deleted or released.
type occupancy struct {
	exclHeld, exclAll   [nDevs]int8 // exclusive users of a pool device
	shareHeld, shareAll [nDevs]int8 // shares of a pool device
	localHeld, localAll [nVMs]int8  // blocks of the local memdev
	waiter              [nRes]int16 // the Pending slot of a resource, -1
}

func (s *State) computeOcc() *occupancy {
	o := &occupancy{}
	for r := range o.waiter {
		o.waiter[r] = -1
	}
	for i := range s.Slots {
		ss := &s.Slots[i]
		sl := s.slot(i)
		if sl.Kind == KLease {
			switch ss.Lease {
			case LeaseHeld:
				o.localHeld[sl.VM]++
				o.localAll[sl.VM]++
			case LeaseReleasing:
				o.localAll[sl.VM]++
			}
			continue
		}
		if sl.Res == resNone {
			continue
		}
		if ss.Phase == Pending {
			o.waiter[sl.Res] = int16(i)
			continue
		}
		held, all := ss.Phase.holding(), ss.holds()
		switch {
		case sl.Kind.local():
			if held {
				o.localHeld[sl.VM]++
			}
			if all {
				o.localAll[sl.VM]++
			}
		case sl.Kind.share():
			if held {
				o.shareHeld[sl.Dev]++
			}
			if all {
				o.shareAll[sl.Dev]++
			}
		default:
			if held {
				o.exclHeld[sl.Dev]++
			}
			if all {
				o.exclAll[sl.Dev]++
			}
		}
	}
	return o
}

// occ returns the memoized occupancy of a state that no transition
// changes any more.
func (s *State) occ() *occupancy {
	if o := s.occMemo.Load(); o != nil {
		return o
	}
	o := s.computeOcc()
	s.occMemo.Store(o)
	return o
}

// localUse counts the blocks of the local memdev of a VM.
func (s *State) localUse(v VM) (held, all int) {
	o := s.computeOcc()
	return int(o.localHeld[v]), int(o.localAll[v])
}

// fitsIn tells if slot i would get its resource: now (counting holders
// that are going away) and later (when they are gone).
func (s *State) fitsIn(o *occupancy, i int) (now, later bool) {
	sl := s.slot(i)
	switch {
	case sl.Res == resNone:
		return true, true
	case sl.Kind.local():
		b := s.cfg.LocalBlocks[sl.VM]
		return int(o.localAll[sl.VM])+1 <= b, int(o.localHeld[sl.VM])+1 <= b
	case sl.Kind.share():
		return o.exclAll[sl.Dev] == 0, o.exclHeld[sl.Dev] == 0
	default: // exclusive use of a pool device
		d := sl.Dev
		return o.exclAll[d]+o.shareAll[d] == 0, o.exclHeld[d]+o.shareHeld[d] == 0
	}
}

// fits is fitsIn with fresh counts (for states being built).
func (s *State) fits(i int) (now, later bool) { return s.fitsIn(s.computeOcc(), i) }

// holders counts the slots that hold a resource and are not going away.
func (s *State) holders(r Res) int {
	n := 0
	for i := range s.Slots {
		if s.slot(i).Res == r && s.Slots[i].Phase.holding() {
			n++
		}
	}
	return n
}

// waiter returns the Pending slot of a resource, -1 if none.
func (s *State) waiter(r Res) int {
	for i := range s.Slots {
		if s.Slots[i].Phase == Pending && s.slot(i).Res == r {
			return i
		}
	}
	return -1
}

func (s *State) contested(r Res) bool { return r >= 0 && s.Contested&(1<<uint(r)) != 0 }

// held tells if a pool device may still be held in flight by the
// scheduler for a claim deleted before its pod was bound (A19).
func (s *State) held(r Res) bool { return r >= 0 && r < resLocal0 && s.Held&(1<<uint(r)) != 0 }

// desiredAtt are the attachments that the claims of a pool want: the
// device (0 pooled, 1 shared) on the VM of every holder that is not going
// away, and if one of them uses the shared device exclusively.
func (s *State) desiredAtt(p Pool) (att [2][nVMs]bool, excl [2][nVMs]bool) {
	for i := range s.Slots {
		sl := s.slot(i)
		if !sl.Kind.pooled() || sl.Pool != p {
			continue
		}
		ss := &s.Slots[i]
		if !ss.Phase.holding() || ss.Phase == Unsched || ss.Phase == Stalled || ss.Node == VMAny {
			continue
		}
		d := int(sl.Dev) - 2*int(p)
		att[d][ss.Node] = true
		if sl.Kind == KSExcl {
			excl[d][ss.Node] = true
		}
	}
	return
}

// anyUnknownHolder: an "any" slot of the pool holds its device on a node
// that is not known yet.
func (s *State) anyUnknownHolder(p Pool) bool {
	for i := range s.Slots {
		sl := s.slot(i)
		if sl.Kind.pooled() && sl.Pool == p && s.Slots[i].Node == VMAny && s.Slots[i].holds() {
			return true
		}
	}
	return false
}

// fenceBit is the bit of a NUMA node in DriverState.F.
func (s *State) fenceBit(node int) uint8 {
	b := s.cfg.nodeBridge(node)
	if b < 0 {
		return 0
	}
	return 1 << uint(b)
}

// bitNodes returns the nodes of fence bits.
func (s *State) bitNodes(bits uint8) []int {
	var nodes []int
	for b := Bridge(0); b < nBridges; b++ {
		if bits&(1<<uint(b)) != 0 {
			nodes = append(nodes, s.cfg.NodeHB[b])
		}
	}
	return nodes
}

// --- abstraction (C4) and String ---

// abstract returns the coverage abstraction of the state (C4 of
// 02-design.txt 6): per pool device its users by kind and phase class,
// per local memdev its fill and users, per driver and controller their
// state. Memoized.
func (s *State) abstract() []string {
	if m := s.memo.Load(); m != nil {
		return m.abstract
	}
	m := &stateMemo{abstract: s.computeAbstract()}
	m.str = strings.Join(m.abstract, "; ")
	s.memo.Store(m)
	return m.abstract
}

// String is the canonical abstraction of the state (the C4 strings),
// not the full state: see dump for that.
func (s *State) String() string {
	s.abstract()
	return s.memo.Load().str
}

// phaseClass is the class of a phase in the abstraction.
func phaseClass(p Phase) string {
	switch p {
	case Starting:
		return "new"
	case Restarting, Running:
		return "run"
	case Attaching, Either:
		return "att"
	case Pending:
		return "wait"
	case Deleting:
		return "gone"
	case Blocked:
		return "blk"
	case Unblocking:
		return "unb"
	case Unsched:
		return "uns"
	case Stalled:
		return "stl"
	}
	return ""
}

func (s *State) computeAbstract() []string {
	var out []string
	var devUsed [nDevs]bool
	var vmLocal [nVMs]bool
	var poolUsed [nPools]bool
	for i := range s.cfg.Slots {
		sl := s.slot(i)
		switch {
		case sl.Kind.pooled():
			devUsed[sl.Dev] = true
			poolUsed[sl.Pool] = true
		case sl.Kind.local() || sl.Kind == KLease:
			vmLocal[sl.VM] = true
		}
	}
	set := func(prefix string, items []string) string {
		sort.Strings(items)
		items = uniq(items)
		if len(items) == 0 {
			return prefix + " free"
		}
		return prefix + " " + strings.Join(items, ",")
	}
	for d := DevID(0); d < nDevs; d++ {
		if !devUsed[d] {
			continue
		}
		var items []string
		for i := range s.Slots {
			sl := s.slot(i)
			if sl.Dev == d && sl.Kind.pooled() && s.Slots[i].Phase != Absent {
				items = append(items, sl.Kind.String()+"."+phaseClass(s.Slots[i].Phase))
			}
		}
		str := set("dev "+d.String(), items)
		if s.held(Res(d)) {
			str += " held"
		}
		if !s.Ctrl[devices[d].Pool].Up {
			str += " ctrl-down"
		}
		out = append(out, str)
	}
	for v := VM(0); v < nVMs; v++ {
		if !vmLocal[v] {
			continue
		}
		var items []string
		for i := range s.Slots {
			sl := s.slot(i)
			ss := &s.Slots[i]
			if sl.Kind.local() && sl.VM == v && ss.Phase != Absent {
				items = append(items, sl.Kind.String()+"."+phaseClass(ss.Phase))
			}
			if sl.Kind == KLease && sl.VM == v && ss.Lease != LeaseNone {
				st := "held"
				if ss.Lease == LeaseReleasing {
					st = "gone"
				}
				items = append(items, "lease-"+ss.LeaseMode.String()+"."+st)
			}
		}
		held, _ := s.localUse(v)
		fill := "room"
		if held >= s.cfg.LocalBlocks[v] {
			fill = "full"
		}
		out = append(out, set("local "+v.String()+" "+fill, items))
	}
	for v := VM(0); v < nVMs; v++ {
		d := &s.Drv[v]
		st := "up"
		switch {
		case d.Killed:
			st = "killed"
		case d.Restarted:
			st = "restarted"
		}
		out = append(out, fmt.Sprintf("drv %s %s F=%d", v, st, d.F))
	}
	for si := 0; si < nStacks; si++ {
		st := &s.Stacks[si]
		if st.N == 0 && !s.stackUsed(si) {
			continue
		}
		kinds := make([]string, 0, st.N)
		for _, k := range st.keys() {
			kinds = append(kinds, k.kind())
		}
		out = append(out, "stack "+stackName(si)+" "+strings.Join(kinds, ","))
	}
	for p := Pool(0); p < nPools; p++ {
		if !poolUsed[p] {
			continue
		}
		st := "up"
		if s.Ctrl[p].Slices != SlicesPresent {
			st = "up-" + s.Ctrl[p].Slices.String()
		}
		if !s.Ctrl[p].Up {
			st = "down"
			if s.Ctrl[p].Slices != SlicesPresent {
				st += "-slices-" + s.Ctrl[p].Slices.String()
			}
			for _, row := range s.Ctrl[p].Att {
				for _, t := range row {
					if t == TriMaybe {
						st = "down-maybe"
					}
				}
			}
		}
		out = append(out, "ctrl "+p.String()+" "+st)
	}
	return out
}

func uniq(sorted []string) []string {
	out := sorted[:0]
	for i, x := range sorted {
		if i == 0 || x != sorted[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// dump is the full state, for files and messages.
func (s *State) dump() string {
	var b strings.Builder
	fmt.Fprintf(&b, "steps %d, unsettled %d, contested %s", s.Steps, s.Unsettled, s.contestedString())
	for d := DevID(0); d < nDevs; d++ {
		if s.held(Res(d)) {
			fmt.Fprintf(&b, ", held %s since %d", d, s.HeldAt[d])
		}
	}
	b.WriteString("\n")
	for i := range s.Slots {
		ss := &s.Slots[i]
		if ss.Phase == Absent && ss.Gen == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %-14s %-10s", s.slot(i).Name, ss.Phase)
		if ss.Phase == Deleting {
			fmt.Fprintf(&b, " (was %s)", ss.Prev)
		}
		fmt.Fprintf(&b, " node %s gen %d restarts %d", ss.Node, ss.Gen, ss.Restarts)
		if ss.RaceKill {
			b.WriteString(" race-kill")
		}
		if ss.Steer != SteerNone {
			fmt.Fprintf(&b, " steer %s", ss.Steer)
		}
		if ss.Lease != LeaseNone {
			fmt.Fprintf(&b, " lease %s %s %q", map[LeaseSt]string{LeaseHeld: "held", LeaseReleasing: "releasing"}[ss.Lease], ss.LeaseMode, s.LeaseIDs[i])
		}
		if s.slot(i).Kind == KLDax && ss.Phase != Absent {
			fmt.Fprintf(&b, " data %s", s.SlotData[i])
		}
		b.WriteString("\n")
	}
	for p := Pool(0); p < nPools; p++ {
		c := &s.Ctrl[p]
		fmt.Fprintf(&b, "  pool %s: controller up %v", p, c.Up)
		if c.Slices != SlicesPresent {
			fmt.Fprintf(&b, " slices %s", c.Slices)
		}
		if !c.Up {
			for d := 0; d < 2; d++ {
				for v := VM(0); v < nVMs; v++ {
					if c.Att[d][v] != TriNo {
						fmt.Fprintf(&b, " %s@%s=%s", devices[2*int(p)+d].Name, v, map[Tri]string{TriYes: "yes", TriMaybe: "maybe"}[c.Att[d][v]])
					}
				}
			}
		}
		b.WriteString("\n")
	}
	for v := VM(0); v < nVMs; v++ {
		d := &s.Drv[v]
		fmt.Fprintf(&b, "  driver %s: pod gen %d restarts %d inc %d killed %v F %v maybe %v pod %q",
			v, d.PodGen, d.Restarts, d.Inc, d.Killed, s.bitNodes(d.F), s.bitNodes(d.FMaybe), d.Pod)
		if d.PodBefore != "" {
			fmt.Fprintf(&b, " not %q", d.PodBefore)
		}
		b.WriteString("\n")
	}
	for si := 0; si < nStacks; si++ {
		if s.Stacks[si].N > 0 {
			fmt.Fprintf(&b, "  stack %s %s\n", stackName(si), s.Stacks[si])
		}
	}
	for _, e := range s.Ev {
		i, lease := s.userSlot(e.User)
		who := s.slot(i).Name
		if lease {
			who = "lease of " + who
		}
		fmt.Fprintf(&b, "  event %d %s %s of %s on %d opt %v sync %v after %d\n", e.Seq, map[evKind]string{evPrepare: "prepare", evUnprepare: "unprepare"}[e.Kind], e.Key, who, e.Stack, e.Opt, e.Sync, e.After)
	}
	if len(s.Alts) > 0 {
		fmt.Fprintf(&b, "  %d other possible outcomes\n", len(s.Alts))
	}
	b.WriteString("  data:")
	for d := DevID(0); d < nDevs; d++ {
		fmt.Fprintf(&b, " %s=%s", d, s.Data[d])
	}
	b.WriteString("\n")
	return b.String()
}

// stackUsed tells if a stack has users in the profile.
func (s *State) stackUsed(si int) bool {
	v, b := stackVM(si), stackBridge(si)
	for i := range s.cfg.Slots {
		sl := s.slot(i)
		switch {
		case sl.Kind.pooled():
			if poolBridge[sl.Pool] == b && (sl.VM == v || (sl.Any() && poolHasHost(sl.Pool, v))) {
				return true
			}
		case sl.Kind.local() || sl.Kind == KLease:
			if b == HB0 && sl.VM == v {
				return true
			}
		}
	}
	return false
}

func (s *State) contestedString() string {
	var rs []string
	for r := Res(0); r < nRes; r++ {
		if s.contested(r) {
			rs = append(rs, r.String())
		}
	}
	if len(rs) == 0 {
		return "-"
	}
	return strings.Join(rs, ",")
}
