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
	"fmt"
	"slices"
	"strings"

	"github.com/askervin/gofmbt/gofmbt"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// The core model: a gofmbt model of the engine and the store over the fake
// kernel, its actors being kubelet's Prepare and Unprepare of claims in a
// fixed set of slots, the kernel's one-shot faults, the process stopping in
// a request or in the recovery of its start, restarts and reboots, and the
// pool appliance and other tools changing the CXL topology. Its predictions
// are written from 03-design 5.4 (the release policy), 5.6 (the recovery)
// and 03a (the transition tables), never from the engine's code: where the
// documents leave a choice open, the prediction is a list of alternatives
// and the observation picks one.

// serialS is the local memdev that the core model configures shared.
const serialS = 0x51

// coreMemdev is a memdev of the node of the core model.
type coreMemdev struct {
	id     string
	serial uint64
	source state.Source
	// kind is the row of the release policy (with source).
	kind state.GrantKind
	// hb is the index of its host bridge in coreHostBridges.
	hb   int
	spec fake.MemdevSpec
}

// The memdevs of the core model, by index.
const (
	mdA = iota
	mdB
	mdL
	mdS
	mdC
	mdQ
	mdP
)

// coreHostBridges are the uids of the host bridges of the node.
var coreHostBridges = []int{12, 24}

// coreMemdevs are the memdevs of the node: host bridge 12 has the pool
// devices A and B, the local sliced L and the local shared S; host bridge 24
// the shared pool device C, the persistent pool device Q and the local
// persistent P. Each has one region at most, so that a port's decoder stack
// never exceeds the 4 decoders of the fake.
var coreMemdevs = []coreMemdev{
	{"A", serialA, state.SourcePool, state.KindExclusive, 0, fake.MemdevSpec{Serial: serialA}},
	{"B", serialB, state.SourcePool, state.KindExclusive, 0, fake.MemdevSpec{Serial: serialB}},
	{"L", serialL, state.SourceLocal, state.KindExclusive, 0, fake.MemdevSpec{Serial: serialL, Ram: gib}},
	{"S", serialS, state.SourceLocal, state.KindShared, 0, fake.MemdevSpec{Serial: serialS, Ram: gib}},
	{"C", serialC, state.SourcePool, state.KindShared, 1, fake.MemdevSpec{Serial: serialC, HostBridge: 24}},
	{"Q", serialQ, state.SourcePool, state.KindPersistent, 1, fake.MemdevSpec{Serial: serialQ, Pmem: gib, HostBridge: 24}},
	{"P", serialP, state.SourceLocal, state.KindPersistent, 1, fake.MemdevSpec{Serial: serialP, Pmem: gib, HostBridge: 24}},
}

// coreSlot is a slot of claims of one kind: it holds one claim at a time,
// whose uid is the slot's name and generation.
type coreSlot struct {
	id       string
	md       int
	mode     state.Mode
	readOnly bool
	// kind names the kind of the claims in the coverage.
	kind string
}

// coreSlots are the slots of the core model.
var coreSlots = []coreSlot{
	{"pnuma", mdA, state.ModeNUMA, false, "pool-numa"},
	{"pdax", mdB, state.ModeDax, false, "pool-dax"},
	{"psh0", mdC, state.ModeDax, false, "pool-shared"},
	{"psh1", mdC, state.ModeDax, false, "pool-shared"},
	{"pfsw", mdQ, state.ModeFs, false, "pool-fs-rw"},
	{"pfsr", mdQ, state.ModeFs, true, "pool-fs-ro"},
	{"lnuma", mdL, state.ModeNUMA, false, "local-numa"},
	{"ldax", mdL, state.ModeDax, false, "local-dax"},
	{"lsh0", mdS, state.ModeDax, false, "local-shared"},
	{"lsh1", mdS, state.ModeDax, false, "local-shared"},
	{"lfsw", mdP, state.ModeFs, false, "local-fs-rw"},
	{"lfsr", mdP, state.ModeFs, true, "local-fs-ro"},
	{"lblk", mdP, state.ModeBlock, false, "local-block-rw"},
}

// driver returns the driver of the claims of the slot.
func (sl *coreSlot) driver() string {
	return driverOf(coreMemdevs[sl.md].source)
}

// uid returns the uid of the claim of the slot in its generation gen.
func (sl *coreSlot) uid(gen int) string {
	return fmt.Sprintf("%s-%d", sl.id, gen)
}

// The states of a kernel region in the model: none, enabled, disabled,
// hollow.
const (
	kregNone   = ""
	kregOn     = "on"
	kregOff    = "off"
	kregHollow = "hollow"
)

// coreSlotState is what the store has of the claim of a slot: its
// preparation and the state of its grant, "" for none.
type coreSlotState struct {
	prep  state.PreparationState
	grant state.GrantState
	// user: a dax device or a node mount of a region of ours lists the
	// grant as a user (03-design 5.2 Users), for mode block its Got names
	// its region; the RELEASING grant of an UNPREPARING claim that is none
	// holds no region (its objects released, its region gone).
	user bool
}

// coreMemdevState is what the store and the kernel have of a memdev:
//   - rec: the state of the memdev record, "" for none
//   - reg: the state of the record of our region, "" for none
//   - kreg: the kernel region on the memdev (kregNone, ...)
//   - online: memory of the region is online
//   - mount: the node mount, "" for none, "ro" or "rw" (the superblock and
//     the read-only flag of the block device agree)
//   - plugged: the memdev is present
//   - foreign: the kernel region is another tool's (not observed: the
//     model knows it)
//   - est: the region is established (not observed)
type coreMemdevState struct {
	rec     state.MemdevState
	reg     state.RegionState
	kreg    string
	online  bool
	mount   string
	plugged bool
	foreign bool
	// est: the region of ours is established, set up or KEPT by an
	// earlier release (the matrix of the release policy; not observed).
	est bool
}

// coreState is a state of the core model. It is immutable once made: every
// change is a copy (clone).
type coreState struct {
	slots []coreSlotState
	// gens are the generations of the claims of the slots.
	gens []int
	mds  []coreMemdevState
	// stacks are the decoder stacks of the host bridge ports: the ids of
	// the memdevs of the regions, "_" for a hole, from the bottom.
	stacks [2][]string
	// arm is the fault or cut armed for the next request or start, an
	// index of coreArms plus one; 0 for none.
	arm int
	// err is the error class of the last request: "", "hole", "refused",
	// "failed", or "cut" when the process stopped in it.
	err string
	// str and obs memoize String and observable.
	str, obs string
}

// newCoreState returns the state of a node with every memdev plugged and
// nothing prepared.
func newCoreState() *coreState {
	s := &coreState{
		slots: make([]coreSlotState, len(coreSlots)),
		gens:  make([]int, len(coreSlots)),
		mds:   make([]coreMemdevState, len(coreMemdevs)),
	}
	for i := range s.mds {
		s.mds[i].plugged = true
	}
	return s
}

// clone returns a copy of the state that can be changed.
func (s *coreState) clone() *coreState {
	c := &coreState{
		slots: slices.Clone(s.slots),
		gens:  slices.Clone(s.gens),
		mds:   slices.Clone(s.mds),
		arm:   s.arm,
		err:   s.err,
	}
	for i := range s.stacks {
		c.stacks[i] = slices.Clone(s.stacks[i])
	}
	return c
}

// components returns the observable parts of the state, each as a string
// that names its part: what the oracle compares with an observation.
func (s *coreState) components() []string {
	out := make([]string, 0, len(s.slots)+len(s.mds)+3)
	for i, ss := range s.slots {
		user := ""
		if ss.user {
			user = "/user"
		}
		out = append(out, fmt.Sprintf("%s=%s/%s%s", coreSlots[i].id, ss.prep, ss.grant, user))
	}
	for i, m := range s.mds {
		out = append(out, fmt.Sprintf("%s=%s/%s/%s/online=%v/mount=%s/plugged=%v", coreMemdevs[i].id, m.rec, m.reg, m.kreg,
			m.online, m.mount, m.plugged))
	}
	for i, st := range s.stacks {
		out = append(out, fmt.Sprintf("hb%d=[%s]", coreHostBridges[i], strings.Join(st, ",")))
	}
	return append(out, "err="+s.err)
}

// observable returns the observable parts of the state in one string.
func (s *coreState) observable() string {
	if s.obs == "" {
		s.obs = strings.Join(s.components(), " ")
	}
	return s.obs
}

// String returns the state for the coverage: its observable parts, the
// foreign regions and the armed fault.
func (s *coreState) String() string {
	if s.str != "" {
		return s.str
	}
	var b strings.Builder
	b.WriteString(s.observable())
	for i, m := range s.mds {
		if m.foreign {
			b.WriteString(" foreign=" + coreMemdevs[i].id)
		}
	}
	if s.arm > 0 {
		b.WriteString(" armed=" + coreArms[s.arm-1].name)
	}
	s.str = b.String()
	return s.str
}

// coreArm is a fault or a process stop that an action arms for the next
// request (or start) that reaches it.
type coreArm struct {
	name string
	// verb is the name of the arm in the coverage of actions.
	verb string
	// fail is the kernel action that fails once (EBUSY for a memory block
	// write): "create-region", "destroy-region", "disable-region",
	// "online", "offline"; "" for a cut.
	fail string
	// cut is the process stop: "commit" after the k-th commit of the
	// engine in the request; "before" or "after" the command cmd; "start"
	// after the j-th commit of the recovery of the next start; "" for a
	// fault.
	cut string
	cmd string
	// k is the commit of the request; j the commit of the recovery of the
	// start after it, 0 for none.
	k, j int
}

// coreArms are the faults and cuts of the core model.
var coreArms = []coreArm{
	{name: "fail create-region", verb: "fail create-region", fail: "create-region"},
	{name: "fail destroy-region", verb: "fail destroy-region", fail: "destroy-region"},
	{name: "fail disable-region", verb: "fail disable-region", fail: "disable-region"},
	{name: "fail online", verb: "fail online", fail: "online"},
	{name: "fail offline", verb: "fail offline", fail: "offline"},
	{name: "cut commit 1", verb: "cut commit", cut: "commit", k: 1},
	{name: "cut commit 2", verb: "cut commit", cut: "commit", k: 2},
	{name: "cut commit 3", verb: "cut commit", cut: "commit", k: 3},
	{name: "cut commit 5", verb: "cut commit", cut: "commit", k: 5},
	{name: "cut commit 8", verb: "cut commit", cut: "commit", k: 8},
	{name: "cut before create-region", verb: "cut before create-region", cut: "before", cmd: "create-region"},
	{name: "cut after create-region", verb: "cut after create-region", cut: "after", cmd: "create-region"},
	{name: "cut before destroy-region", verb: "cut before destroy-region", cut: "before", cmd: "destroy-region"},
	{name: "cut after destroy-region", verb: "cut after destroy-region", cut: "after", cmd: "destroy-region"},
	{name: "cut commit 2 start 1", verb: "cut commit and start", cut: "commit", k: 2, j: 1},
	{name: "cut commit 4 start 2", verb: "cut commit and start", cut: "commit", k: 4, j: 2},
	{name: "cut start 1", verb: "cut start", cut: "start", j: 1},
	{name: "cut start 2", verb: "cut start", cut: "start", j: 2},
	{name: "cut start 4", verb: "cut start", cut: "start", j: 4},
}

// coreAction is an action of the core model.
type coreAction struct {
	// verb is "prepare", "unprepare", "arm", "restart", "reboot",
	// "foreign", "unforeign", "plug", "unplug".
	verb string
	slot int
	md   int
	arm  int
	a    *gofmbt.Action
}

// isRequest tells whether the action is a request of kubelet.
func (ca *coreAction) isRequest() bool {
	return ca.verb == "prepare" || ca.verb == "unprepare"
}

// coreActions returns the actions of the core model, each made once.
func coreActions() []*coreAction {
	var out []*coreAction
	for i := range coreSlots {
		out = append(out,
			&coreAction{verb: "prepare", slot: i, a: gofmbt.NewAction("prepare %s", coreSlots[i].id)},
			&coreAction{verb: "unprepare", slot: i, a: gofmbt.NewAction("unprepare %s", coreSlots[i].id)})
	}
	for i := range coreArms {
		out = append(out, &coreAction{verb: "arm", arm: i + 1, a: gofmbt.NewAction("%s", coreArms[i].name)})
	}
	out = append(out,
		&coreAction{verb: "restart", a: gofmbt.NewAction("restart")},
		&coreAction{verb: "reboot", a: gofmbt.NewAction("reboot")})
	for _, md := range []int{mdA, mdB, mdC} {
		out = append(out,
			&coreAction{verb: "foreign", md: md, a: gofmbt.NewAction("foreign %s", coreMemdevs[md].id)},
			&coreAction{verb: "unforeign", md: md, a: gofmbt.NewAction("unforeign %s", coreMemdevs[md].id)})
	}
	for _, md := range []int{mdA, mdB, mdC, mdQ} {
		out = append(out,
			&coreAction{verb: "unplug", md: md, a: gofmbt.NewAction("unplug %s", coreMemdevs[md].id)},
			&coreAction{verb: "plug", md: md, a: gofmbt.NewAction("plug %s", coreMemdevs[md].id)})
	}
	return out
}

// newCoreModel returns the gofmbt model of the actions: a transition of an
// enabled action goes to the first alternative of its prediction.
func newCoreModel(actions []*coreAction) *gofmbt.Model {
	m := gofmbt.NewModel()
	m.From(func(cur gofmbt.State) []*gofmbt.Transition {
		s := cur.(*coreState)
		var out []*gofmbt.Transition
		for _, ca := range actions {
			if !s.enabled(ca) {
				continue
			}
			out = append(out, gofmbt.NewTransition(ca.a, func(gofmbt.State) gofmbt.State {
				return s.next(ca)
			}))
		}
		return out
	})
	return m
}

// enabled tells whether the action may be taken in the state. While a
// fault or a cut is armed, only the requests (or the starts) that reach it
// are.
func (s *coreState) enabled(ca *coreAction) bool {
	if s.arm > 0 {
		arm := &coreArms[s.arm-1]
		switch {
		case arm.cut == "start":
			return ca.verb == "restart" || ca.verb == "reboot"
		case ca.isRequest():
			return s.requestEnabled(ca) && s.reaches(arm, ca)
		}
		return false
	}
	switch ca.verb {
	case "prepare", "unprepare":
		return s.requestEnabled(ca)
	case "arm":
		return s.armEnabled(&coreArms[ca.arm-1]) && !s.avoided(ca)
	case "restart", "reboot":
		return !s.avoided(ca)
	case "foreign":
		m := &s.mds[ca.md]
		hb := coreMemdevs[ca.md].hb
		return m.plugged && m.rec == "" && m.kreg == kregNone && !s.hasHole(hb) && len(s.stacks[hb]) < 4 &&
			len(s.usersOf(ca.md)) == 0
	case "unforeign":
		return s.mds[ca.md].foreign
	case "unplug":
		m := &s.mds[ca.md]
		return m.plugged && m.rec == "" && m.kreg == kregNone
	case "plug":
		return !s.mds[ca.md].plugged
	}
	return false
}

// requestEnabled tells whether kubelet may send the request of the action:
// a Prepare of a slot without a claim, or of a claim whose Prepare did not
// finish (KEPT, PREPARING) or of another boot (PREPARED_STALE); an
// Unprepare of a slot with a claim.
func (s *coreState) requestEnabled(ca *coreAction) bool {
	prep := s.slots[ca.slot].prep
	if ca.verb == "prepare" {
		// not modelled: a Prepare of a claim whose memdev is GONE (03a T1
		// and T3 do not say what it does)
		return (prep == "" || prep == state.PreparationKept || prep == state.PreparationPreparing ||
			prep == state.PreparationStale) && s.mds[coreSlots[ca.slot].md].rec != state.MemdevGone && !s.avoided(ca)
	}
	return prep != "" && !s.avoided(ca)
}

// coreFindings are the findings of the core model that are not fixed yet,
// by name: each tells whether a request runs into it. The requests that do
// are not generated unless -core.known leaves the finding out.
var coreFindings = map[string]func(s *coreState, ca *coreAction) bool{
	// F7: a memdev with the grant of an unfinished release whose region is
	// gone (UNPREPARING, RELEASING) keeps a region that a later Prepare
	// made when its last user goes (the recovery of a cut Prepare leaves
	// the cut grant's dax device without a user: I2); only the retry of
	// that release is generated.
	"F7": func(s *coreState, ca *coreAction) bool {
		return s.unfinishedWithoutRegion(ca, false)
	},
	// F10: the next Prepare of a local persistent memdev whose idle region
	// has nothing above reuses the region instead of destroying it first
	// (5.4 the idle row, T3 IDLE_KEPT -> UNUSED): a hole below it stays.
	"F10": func(s *coreState, ca *coreAction) bool {
		md := coreSlots[ca.slot].md
		st := s.stacks[coreMemdevs[md].hb]
		i := slices.Index(st, coreMemdevs[md].id)
		return ca.verb == "prepare" && s.mds[md].rec == state.MemdevIdleKept && coreMemdevs[md].kind == state.KindPersistent &&
			!s.regionsAbove(md) && i > 0 && slices.Contains(st[:i], "_")
	},
	// F11: a start downgrades the node mount of a pool persistent memdev
	// that the writer of an unfinished Unprepare still lists, when a reader
	// of a prepared claim has it too (the unfinished uses are counted for
	// local memdevs only): D1 and D2 keep it read-write.
	"F11": func(s *coreState, ca *coreAction) bool {
		if ca.verb != "restart" && (ca.verb != "arm" || coreArms[ca.arm-1].cut == "") {
			return false
		}
		for i, ss := range s.slots {
			sl := &coreSlots[i]
			if coreMemdevs[sl.md].source == state.SourcePool && sl.mode == state.ModeFs && !sl.readOnly &&
				ss.prep == state.PreparationUnpreparing && ss.grant == state.GrantReleasing && ss.user {
				return true
			}
		}
		return false
	},
	// F9: the same for mode block: the grant of an unfinished Unprepare of
	// mode block holds the region also when its Got names none any more
	// (its region gone and forgotten at a start).
	"F9": func(s *coreState, ca *coreAction) bool {
		return s.unfinishedWithoutRegion(ca, true)
	},
	// F8: a kept region that a Prepare enabled again and a cut stopped
	// before its set-up is kept again by the recovery with its daxN.0
	// recorded as the seed while the kernel has it whole: I2.
	"F8": func(s *coreState, ca *coreAction) bool {
		md := coreSlots[ca.slot].md
		return ca.verb == "prepare" && s.arm > 0 && coreArms[s.arm-1].cut != "" && s.mds[md].kreg == kregOff &&
			s.regionsAbove(md)
	},
}

// unfinishedWithoutRegion tells whether the request is on a memdev with the
// grant of another slot's unfinished Unprepare (UNPREPARING, RELEASING) that
// holds no region of it by the 5.2 Users (no dax device or node mount lists
// it; mode block: its Got names none), of mode block or of the others.
func (s *coreState) unfinishedWithoutRegion(ca *coreAction, block bool) bool {
	md := coreSlots[ca.slot].md
	for i, ss := range s.slots {
		if i != ca.slot && coreSlots[i].md == md && (coreSlots[i].mode == state.ModeBlock) == block &&
			ss.prep == state.PreparationUnpreparing && ss.grant == state.GrantReleasing && !ss.user {
			return true
		}
	}
	return false
}

// coreAvoid are the findings whose requests are not generated.
var coreAvoid = map[string]bool{}

// avoided tells whether the request runs into a finding that is avoided.
func (s *coreState) avoided(ca *coreAction) bool {
	for name, hits := range coreFindings {
		if coreAvoid[name] && hits(s, ca) {
			return true
		}
	}
	return false
}

// armEnabled tells whether the fault or cut may be armed: some request (or
// start) reaches it.
func (s *coreState) armEnabled(arm *coreArm) bool {
	if arm.cut == "start" {
		return true
	}
	for i := range coreSlots {
		for _, verb := range []string{"prepare", "unprepare"} {
			ca := &coreAction{verb: verb, slot: i}
			if s.requestEnabled(ca) && s.reaches(arm, ca) {
				return true
			}
		}
	}
	return false
}

// reaches tells whether the request reaches the armed fault or cut, by the
// steps of 03-design 5.3 (a Prepare: journal, the memdev, the region, the
// set-up, per mode) and 5.5 (a release: unmount, offline, the dax device,
// the region per 5.4).
func (s *coreState) reaches(arm *coreArm, ca *coreAction) bool {
	sl := &coreSlots[ca.slot]
	if arm.cut == "commit" {
		// a Prepare journals its grant first; an Unprepare commits only
		// when there is a grant
		return ca.verb == "prepare" || s.slots[ca.slot].grant != ""
	}
	what := arm.fail
	if what == "" {
		what = arm.cmd
	}
	if ca.verb == "prepare" {
		made, class := s.leftoverReleased(ca.slot).prepareRegion(ca.slot)
		switch what {
		case "create-region":
			return made == madeCreated
		case "online":
			return sl.mode == state.ModeNUMA && class == ""
		}
		return false
	}
	ss := s.slots[ca.slot]
	if ss.grant == "" || ss.prep == state.PreparationStale {
		return false
	}
	m := &s.mds[sl.md]
	switch what {
	case "offline":
		return sl.mode == state.ModeNUMA && m.online && ss.grant == state.GrantRealised
	case "destroy-region", "disable-region":
		if len(s.regionUsers(sl.md, ca.slot)) > 0 || m.kreg == kregNone || m.foreign {
			return false
		}
		if what == "disable-region" && m.kreg != kregOn {
			return false
		}
		return unprepareDestroys(s, sl.md) == policyDestroy
	}
	return false
}

// usersOf returns the slots whose claims of this boot have a grant on the
// memdev, but those of except.
func (s *coreState) usersOf(md int, except ...int) []int {
	var out []int
	for i, ss := range s.slots {
		if coreSlots[i].md != md || ss.grant == "" || ss.prep == state.PreparationStale || slices.Contains(except, i) {
			continue
		}
		out = append(out, i)
	}
	return out
}

// nextToBlock tells whether the slot is of mode fs and a writer of mode
// block of this boot has a use of its memdev (blockUses): it needs the
// device alone (P9c).
func (s *coreState) nextToBlock(i int) bool {
	if coreSlots[i].mode != state.ModeFs {
		return false
	}
	for o, ss := range s.slots {
		sl := &coreSlots[o]
		if sl.md == coreSlots[i].md && sl.mode == state.ModeBlock && !sl.readOnly && ss.prep != state.PreparationStale &&
			(ss.grant == state.GrantRealised && ss.prep == state.PreparationPrepared ||
				ss.prep == state.PreparationUnpreparing && ss.grant == state.GrantReleasing) {
			return true
		}
	}
	return false
}

// regionUsers returns the slots of usersOf whose grants hold the region of
// the memdev: all but those of unfinished Unprepares that no dax device or
// node mount lists as a user (5.2 Users).
func (s *coreState) regionUsers(md int, except ...int) []int {
	var out []int
	for _, i := range s.usersOf(md, except...) {
		if ss := s.slots[i]; ss.prep != state.PreparationUnpreparing || ss.grant != state.GrantReleasing || ss.user {
			out = append(out, i)
		}
	}
	return out
}

// hasHole tells whether a port of the host bridge has a hole in its
// decoder stack.
func (s *coreState) hasHole(hb int) bool {
	return slices.Contains(s.stacks[hb], "_")
}

// regionsAbove tells whether a region of another memdev lies above the
// region of the memdev in its decoder stack (03-design 5.4 "in order").
func (s *coreState) regionsAbove(md int) bool {
	st := s.stacks[coreMemdevs[md].hb]
	i := slices.Index(st, coreMemdevs[md].id)
	if i < 0 {
		return false
	}
	for _, e := range st[i+1:] {
		if e != "_" {
			return true
		}
	}
	return false
}

// push puts a new region of the memdev on top of its decoder stack.
func (s *coreState) push(md int) {
	hb := coreMemdevs[md].hb
	s.stacks[hb] = append(s.stacks[hb], coreMemdevs[md].id)
}

// destroy removes the region of the memdev from the kernel: popped with the
// holes below it when on top of its stack, else a hole left. No grant is a
// user of it then, and the memdev record stays only for the grants of
// unfinished releases.
func (s *coreState) destroy(md int) {
	hb := coreMemdevs[md].hb
	st := s.stacks[hb]
	if i := slices.Index(st, coreMemdevs[md].id); i >= 0 {
		if i == len(st)-1 {
			st = st[:i]
			for len(st) > 0 && st[len(st)-1] == "_" {
				st = st[:len(st)-1]
			}
		} else {
			st[i] = "_"
		}
	}
	s.stacks[hb] = st
	m := &s.mds[md]
	m.kreg, m.reg, m.online, m.foreign, m.est = kregNone, "", false, false, false
	m.rec = ""
	s.detach(md)
}

// detach makes no grant of the memdev a user of a region, and keeps the
// memdev record for the grants of unfinished releases.
func (s *coreState) detach(md int) {
	for i := range s.slots {
		if coreSlots[i].md != md {
			continue
		}
		s.slots[i].user = false
		if s.slots[i].grant == state.GrantReleasing && s.slots[i].prep != state.PreparationStale {
			s.mds[md].rec = state.MemdevActive
		}
	}
}

// fsUsers tells whether the memdev has realised grants of mode fs of this
// boot, or grants of unfinished Unprepares that its node mount lists
// (5.2 Users), and whether one of them writes.
func (s *coreState) fsUsers(md int) (users, writer bool) {
	for i, ss := range s.slots {
		sl := &coreSlots[i]
		if sl.md != md || sl.mode != state.ModeFs || ss.prep == state.PreparationStale {
			continue
		}
		if ss.grant == state.GrantRealised || ss.grant == state.GrantReleasing && ss.user {
			users, writer = true, writer || !sl.readOnly
		}
	}
	return users, writer
}

// mountAfter returns the node mount of the memdev after a grant of mode fs
// left it (5.5 as ruled, D2): unmounted when no grant is a user of it,
// downgraded when no listed writer remains, else as it is.
func (s *coreState) mountAfter(md int) string {
	users, writer := s.fsUsers(md)
	switch mount := s.mds[md].mount; {
	case !users:
		return ""
	case !writer:
		return "ro"
	case mount == "":
		return "rw"
	default:
		return mount
	}
}

// blockUses tells whether a grant of the persistent memdev but the slot's
// is a use that a block writer must be alone of (5.3 P9c): a realised one
// of this boot, or one of an unfinished Unprepare that a node mount lists
// or of mode block.
func (s *coreState) blockUses(md, except int) bool {
	for i, ss := range s.slots {
		sl := &coreSlots[i]
		if i == except || sl.md != md || ss.prep == state.PreparationStale {
			continue
		}
		if ss.grant == state.GrantRealised && ss.prep == state.PreparationPrepared ||
			ss.prep == state.PreparationUnpreparing && ss.grant == state.GrantReleasing && (ss.user || sl.mode == state.ModeBlock) {
			return true
		}
	}
	return false
}

// The release policy of 03-design 5.4 for the last grant of a memdev.
const (
	policyDestroy = "destroy"
	policyKeep    = "keep"
	// policyInOrder destroys a region on top of its stack, else keeps it
	// disabled.
	policyInOrder = "in order"
)

// unprepareDestroys returns the policy of the Unprepare of the last grant
// of the memdev (5.4, column Unprepare): pool devices and local sliced
// memdevs destroy always (a hole is ok), a local shared memdev keeps its
// region while configured shared, a local persistent memdev keeps its
// region idle while regions lie above it.
func unprepareDestroys(s *coreState, md int) string {
	d := &coreMemdevs[md]
	switch {
	case d.source == state.SourcePool, d.kind == state.KindExclusive:
		return policyDestroy
	case d.kind == state.KindShared:
		return policyKeep
	case s.regionsAbove(md):
		return policyKeep
	}
	return policyDestroy
}

// rollbackPolicy returns the policy of the rollback of a failed Prepare
// (5.4, column rollback): pool devices destroy always, local memdevs in
// order.
func rollbackPolicy(md int) string {
	if coreMemdevs[md].source == state.SourcePool {
		return policyDestroy
	}
	return policyInOrder
}

// What a Prepare does with the region of its memdev.
const (
	madeNone    = iota // the Prepare fails before the region
	madeCreated        // a new region
	madeEnabled        // a kept region enabled again
	madeUsed           // the region of other grants, or an idle kept one
)

// prepareRegion returns what the Prepare of the slot does with the region
// of its memdev (5.3), and the error class of a Prepare that fails before
// it: a pool grant waits for its absent memdev, then fails; a FOREIGN
// region refuses the memdev; a decoder hole is a typed error.
func (s *coreState) prepareRegion(i int) (int, string) {
	md := coreSlots[i].md
	m := &s.mds[md]
	switch {
	case !m.plugged:
		return madeNone, "failed"
	case m.foreign:
		return madeNone, "refused"
	}
	switch m.kreg {
	case kregNone:
		if s.hasHole(coreMemdevs[md].hb) {
			return madeNone, "hole"
		}
		return madeCreated, ""
	case kregOff:
		return madeEnabled, ""
	}
	if m.reg == state.RegionKept {
		// a kept region left enabled (D6): KEPT -> OWNED, set up again
		return madeEnabled, ""
	}
	return madeUsed, ""
}

// prepareOutcome returns the state after the Prepare of the claim of the
// slot without a fault (03a T1, T2, T4; 03-design 5.3), and what it did
// with the region. A failure is rolled back (rollback).
func (s *coreState) prepareOutcome(i int) (*coreState, int) {
	w := s.leftoverReleased(i)
	w.err = ""
	sl := &coreSlots[i]
	md := sl.md
	m := &w.mds[md]
	made, class := w.prepareRegion(i)
	w.preparing(i)
	switch made {
	case madeNone:
		w.rollback(i, madeNone, class)
		return w, madeNone
	case madeCreated:
		w.push(md)
		m.kreg, m.reg = kregOn, state.RegionOwned
	case madeEnabled:
		// KEPT -> OWNED: the kept region enabled and set up again
		m.kreg, m.reg = kregOn, state.RegionOwned
	}
	m.rec = state.MemdevActive
	if sl.mode == state.ModeBlock && !sl.readOnly && w.blockUses(md, i) || w.nextToBlock(i) {
		// mode block read-write needs the device alone on this node (P9c)
		w.rollback(i, made, "failed")
		return w, made
	}
	w.slots[i] = coreSlotState{prep: state.PreparationPrepared, grant: state.GrantRealised, user: true}
	m.est = true
	if sl.mode == state.ModeNUMA {
		m.online = true
	}
	if sl.mode == state.ModeFs {
		// joins the node mount as it is; a writer makes it read-write
		switch {
		case !sl.readOnly:
			m.mount = "rw"
		case m.mount == "":
			m.mount = "ro"
		}
	}
	return w, made
}

// leftoverReleased returns the state before the Prepare of the slot
// journals: a RELEASING grant of the claim (a failed or cut release of a KEPT
// claim) is released first, as a rollback (5.3 "its leftovers are released
// first"; the rollback column of the release policy).
func (s *coreState) leftoverReleased(i int) *coreState {
	w := s.clone()
	if w.slots[i].grant != state.GrantReleasing || w.slots[i].prep == state.PreparationStale {
		// a grant of another boot is dropped with the PREPARING commit (T1)
		return w
	}
	prep := w.slots[i].prep
	w.rollback(i, madeUsed, "")
	if w.slots[i].prep == "" {
		w.slots[i].prep = prep
	}
	return w
}

// preparing commits the preparation of the slot PREPARING with its grant
// JOURNALED and its memdev ACTIVE, the grant of another boot dropped
// (03a T1 PREPARED_STALE -> PREPARING).
func (w *coreState) preparing(i int) {
	md := coreSlots[i].md
	if w.slots[i].prep == "" {
		w.gens[i]++
	}
	w.slots[i] = coreSlotState{prep: state.PreparationPreparing, grant: state.GrantJournaled}
	w.mds[md].rec = state.MemdevActive
}

// rollback releases the grant of the failed Prepare of the slot (03a T2
// REALISING -> RELEASING -> RELEASED, or -> JOURNALED with the region KEPT)
// per the rollback column of 5.4 when it was the last user of the region,
// and ends the Prepare with the error class (T1 PREPARING -> UNKNOWN or
// KEPT).
func (w *coreState) rollback(i, made int, class string) {
	md := coreSlots[i].md
	m := &w.mds[md]
	w.err = class
	w.slots[i] = coreSlotState{}
	if coreSlots[i].mode == state.ModeNUMA {
		m.online = false
	}
	if coreSlots[i].mode == state.ModeFs {
		m.mount = w.mountAfter(md)
	}
	if len(w.regionUsers(md)) > 0 {
		return
	}
	if made == madeNone || m.foreign || m.kreg == kregNone {
		w.dropIdle(md)
		return
	}
	if rollbackPolicy(md) == policyDestroy || !w.regionsAbove(md) {
		w.destroy(md)
		return
	}
	// in order refused: the region kept disabled for the claim
	w.slots[i] = coreSlotState{prep: state.PreparationKept, grant: state.GrantJournaled}
	m.kreg, m.reg, m.rec, m.est = kregOff, state.RegionKept, state.MemdevActive, true
}

// dropIdle removes the record of a memdev without grants: none is left
// when it has no region of ours either, else it is IDLE_KEPT.
func (w *coreState) dropIdle(md int) {
	m := &w.mds[md]
	switch {
	case len(w.usersOf(md)) > 0:
	case m.kreg == kregNone || m.foreign:
		m.rec = ""
	default:
		m.rec = state.MemdevIdleKept
	}
}

// next returns a state after the action for the planner: the first
// alternative of the prediction, the request uncut for a cut.
func (s *coreState) next(ca *coreAction) *coreState {
	if s.arm > 0 && ca.isRequest() && coreArms[s.arm-1].cut != "" {
		var w *coreState
		if ca.verb == "prepare" {
			w, _ = s.prepareOutcome(ca.slot)
		} else {
			w = s.unprepareOutcome(ca.slot)
		}
		w.arm = 0
		return w
	}
	return s.alternatives(ca)[0]
}

// predict returns the alternative states after the action, the most
// likely first, each once.
func (s *coreState) predict(ca *coreAction) []*coreState {
	return dedup(s.alternatives(ca))
}

// alternatives returns the alternative states after the action, the most
// likely first.
func (s *coreState) alternatives(ca *coreAction) []*coreState {
	var out []*coreState
	switch ca.verb {
	case "prepare":
		out = s.predictPrepare(ca.slot)
	case "unprepare":
		out = s.predictUnprepare(ca.slot)
	case "arm":
		w := s.clone()
		w.arm = ca.arm
		out = []*coreState{w}
	case "restart":
		w := s.clone()
		w.arm = 0
		out = w.restarted()
	case "reboot":
		w := s.clone()
		w.arm = 0
		w.rebooted()
		out = w.restarted()
	case "foreign":
		w := s.clone()
		w.push(ca.md)
		w.mds[ca.md].kreg, w.mds[ca.md].foreign = kregOn, true
		out = []*coreState{w}
	case "unforeign":
		w := s.clone()
		w.destroy(ca.md)
		out = []*coreState{w}
	case "plug", "unplug":
		w := s.clone()
		w.mds[ca.md].plugged = ca.verb == "plug"
		out = []*coreState{w}
	}
	return out
}

// dedup returns the states without those whose observable parts equal an
// earlier one's.
func dedup(states []*coreState) []*coreState {
	seen := map[string]bool{}
	out := states[:0:0]
	for _, w := range states {
		if k := w.observable(); !seen[k] {
			seen[k] = true
			out = append(out, w)
		}
	}
	return out
}

// predictPrepare returns the states after the Prepare of the slot, with
// the armed fault or cut.
func (s *coreState) predictPrepare(i int) []*coreState {
	var arm *coreArm
	if s.arm > 0 {
		arm = &coreArms[s.arm-1]
	}
	w, made := s.prepareOutcome(i)
	w.arm = 0
	switch {
	case arm == nil:
		md := coreSlots[i].md
		if m := &s.mds[md]; m.rec == state.MemdevIdleKept && coreMemdevs[md].kind == state.KindPersistent &&
			!s.regionsAbove(md) {
			// the keep reason of an idle persistent region is gone: the
			// next Prepare destroys it first (5.4 the idle row, T3
			// IDLE_KEPT -> UNUSED)
			d := s.clone()
			d.destroy(md)
			anew, _ := d.prepareOutcome(i)
			anew.arm = 0
			return []*coreState{anew}
		}
		return []*coreState{w}
	case arm.fail == "create-region":
		f := s.leftoverReleased(i)
		f.arm, f.err = 0, ""
		f.preparing(i)
		f.rollback(i, madeNone, "failed")
		return []*coreState{f}
	case arm.fail == "online":
		f := s.clone()
		f.arm = 0
		f, _ = f.prepareOutcome(i)
		f.rollback(i, made, "failed")
		if f.slots[i].prep != state.PreparationKept {
			return []*coreState{f}
		}
		// kept in order: disabled (5.4), or as it was when the regions
		// above were there before (D6)
		on := f.clone()
		on.mds[coreSlots[i].md].kreg = kregOn
		return []*coreState{f, on}
	}
	// a cut: the process stopped at a commit or a command of the Prepare
	// (or of its rollback) and started again at once
	cuts := s.cutPrepare(i, arm, w, made)
	if arm.cut == "commit" {
		cuts = append(cuts, w)
	}
	return cuts
}

// cutPrepare returns the states after a cut of the Prepare of the slot and
// the start after it: the cut came before the region (the grant journaled)
// or after it was made (the grant realising or realised, the region set up
// or not yet); w is the state of the Prepare uncut and made what it did with
// the region.
func (s *coreState) cutPrepare(i int, arm *coreArm, w *coreState, made int) []*coreState {
	var mids []*coreState
	if arm.cmd != "after" {
		mid := s.leftoverReleased(i)
		mid.arm, mid.err = 0, "cut"
		mid.preparing(i)
		mids = append(mids, mid)
		if !s.mds[coreSlots[i].md].plugged {
			// cut in the rollback after the wait for the memdev
			r := mid.clone()
			r.slots[i].grant = state.GrantReleasing
			mids = append(mids, r)
		}
		if m := &s.mds[coreSlots[i].md]; m.reg == state.RegionOwned && m.kreg == kregOff {
			// a region left disabled by a failed release is recorded KEPT
			// before it is enabled again (T4)
			k := mid.clone()
			k.mds[coreSlots[i].md].reg = state.RegionKept
			k.mds[coreSlots[i].md].est = true
			mids = append(mids, k)
		}
		if w.err != "" {
			// cut at the last commit of the rollback
			r := w.clone()
			r.err = "cut"
			r.slots[i] = coreSlotState{prep: state.PreparationPreparing}
			mids = append(mids, r)
		}
	}
	if arm.cmd != "before" && w.err == "" {
		mid := w.clone()
		mid.err = "cut"
		mid.slots[i] = coreSlotState{prep: state.PreparationPreparing, grant: state.GrantRealised, user: true}
		mids = append(mids, mid)
		// cut before the set-up of a region that the Prepare made or
		// enabled again: not established (a shared region in use is set
		// up again with its zeroing, D-100)
		md := coreSlots[i].md
		if made != madeUsed || coreMemdevs[md].kind == state.KindShared && coreMemdevs[md].source == state.SourceLocal {
			n := mid.clone()
			n.mds[md].est = false
			mids = append(mids, n)
		}
	}
	var out []*coreState
	for _, mid := range mids {
		out = append(out, mid.restarted()...)
	}
	return out
}

// predictUnprepare returns the states after the Unprepare of the slot,
// with the armed fault or cut.
func (s *coreState) predictUnprepare(i int) []*coreState {
	var arm *coreArm
	if s.arm > 0 {
		arm = &coreArms[s.arm-1]
	}
	ws := []*coreState{s.unprepareOutcome(i)}
	for _, x := range ws {
		x.arm = 0
	}
	switch {
	case arm == nil:
		return ws
	case arm.fail != "":
		return []*coreState{s.failedRelease(i, arm.fail)}
	}
	cuts := s.cutUnprepare(i, arm, ws)
	if arm.cut == "commit" {
		cuts = append(cuts, ws...)
	}
	return cuts
}

// unprepareOutcome returns the state after the Unprepare of the claim of
// the slot without a fault (03a T1 -> UNKNOWN; T2 -> RELEASED; 03-design
// 5.5, the region per the Unprepare column of 5.4).
func (s *coreState) unprepareOutcome(i int) *coreState {
	w := s.clone()
	w.err = ""
	sl := &coreSlots[i]
	md := sl.md
	m := &w.mds[md]
	ss := w.slots[i]
	w.slots[i] = coreSlotState{}
	if ss.grant == "" || ss.prep == state.PreparationStale {
		// a stale grant has nothing of this boot (a serial-level release)
		return w
	}
	if sl.mode == state.ModeNUMA {
		m.online = false
	}
	if sl.mode == state.ModeFs {
		m.mount = w.mountAfter(md)
	}
	if len(w.regionUsers(md)) > 0 || m.foreign {
		return w
	}
	if m.kreg == kregNone {
		w.dropIdle(md)
		return w
	}
	if unprepareDestroys(s, md) == policyDestroy {
		w.destroy(md)
		return w
	}
	m.rec = state.MemdevIdleKept
	if len(w.usersOf(md)) > 0 {
		m.rec = state.MemdevActive
	}
	if m.kreg == kregOff {
		// T4 OWNED -> KEPT: kept, the region stays disabled
		m.reg = state.RegionKept
	}
	return w
}

// failedRelease returns the state after an Unprepare of the slot whose
// release failed at the kernel action fail (03a T2 RELEASING -> RELEASING,
// T1 UNPREPARING -> UNPREPARING: the records in their last committed state,
// an error to kubelet). Before the region: the mounts are unmounted and the
// memory offline (5.5).
func (s *coreState) failedRelease(i int, fail string) *coreState {
	w := s.clone()
	w.arm, w.err = 0, "failed"
	sl := &coreSlots[i]
	m := &w.mds[sl.md]
	ss := &w.slots[i]
	if ss.prep == state.PreparationPrepared {
		ss.prep = state.PreparationUnpreparing
	}
	ss.grant = state.GrantReleasing
	if fail == "offline" {
		return w
	}
	// a part's own dax device deleted, a node mount unmounted; the Whole
	// device of a region lists every grant of the memdev until the region
	// goes (5.2)
	d := &coreMemdevs[sl.md]
	if sl.mode == state.ModeFs || d.source == state.SourceLocal && d.kind == state.KindExclusive {
		ss.user = false
	}
	if sl.mode == state.ModeNUMA {
		m.online = false
	}
	if sl.mode == state.ModeFs {
		m.mount = w.mountAfter(sl.md)
	}
	if fail == "destroy-region" {
		m.kreg = kregOff
	}
	return w
}

// cutUnprepare returns the states after a cut of the Unprepare of the slot
// and the start after it; ws are the states of the Unprepare uncut. The
// preparation stays (UNPREPARING for a prepared one), its grant RELEASING
// or released, the kernel objects anywhere between their state before and
// after the release; the start finishes nothing of an UNPREPARING
// preparation (5.6).
func (s *coreState) cutUnprepare(i int, arm *coreArm, ws []*coreState) []*coreState {
	sl := &coreSlots[i]
	md := sl.md
	w := ws[0]
	before, after := s.mds[md], w.mds[md]
	prep := s.slots[i].prep
	if prep == state.PreparationPrepared {
		prep = state.PreparationUnpreparing
	}
	// the grant is removed after the region is released (T2 RELEASING ->
	// RELEASED): a cut after it leaves the kernel as the release does
	var out []*coreState
	for _, x := range ws {
		if arm.cmd == "destroy-region" {
			break
		}
		done := x.clone()
		done.arm, done.err = 0, "cut"
		done.slots[i] = coreSlotState{prep: prep}
		out = append(out, done.restarted()...)
	}
	if s.slots[i].grant == "" {
		return out
	}
	kregs := uniq(before.kreg, after.kreg)
	if before.kreg == kregOn && after.kreg == kregNone {
		// disabled, then destroyed
		kregs = append(kregs, kregOff)
	}
	stacks := [][2][]string{s.stacks, w.stacks}
	switch {
	case arm.cmd == "destroy-region" && arm.cut == "before":
		kregs, stacks = []string{kregOff}, stacks[:1]
	case arm.cmd == "destroy-region":
		kregs, stacks = []string{kregNone}, stacks[1:]
	}
	for _, kreg := range kregs {
		for _, st := range stacks {
			for _, online := range uniq(before.online, after.online) {
				for _, mount := range uniq(before.mount, after.mount) {
					users := uniq(s.slots[i].user, false)
					if sl.mode == state.ModeBlock {
						users = []bool{s.slots[i].user}
					}
					for _, user := range users {
						mid := s.clone()
						mid.arm, mid.err = 0, "cut"
						mid.slots[i] = coreSlotState{prep: prep, grant: state.GrantReleasing, user: user && kreg != kregNone}
						for h := range st {
							mid.stacks[h] = slices.Clone(st[h])
						}
						mm := &mid.mds[md]
						mm.kreg, mm.online, mm.mount = kreg, online, mount
						for _, reg := range uniq(before.reg, after.reg) {
							if reg == "" && kreg != kregNone {
								continue
							}
							r := mid.clone()
							r.mds[md].reg = reg
							out = append(out, r.restarted()...)
						}
					}
				}
			}
		}
	}
	return out
}

// uniq returns the values without repeats.
func uniq[T comparable](vals ...T) []T {
	var out []T
	for _, v := range vals {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// rebooted changes the state as a reboot does (03-design 4.4): the kernel
// has no region, memory or mount of the old boot; the preparations of the
// old boot are PREPARED_STALE, their grants kept (Got cleared); the memdev
// and region records of the old boot are dropped.
func (w *coreState) rebooted() {
	for i := range w.slots {
		if w.slots[i].prep != "" {
			w.slots[i].prep = state.PreparationStale
		}
	}
	for i := range w.mds {
		w.mds[i] = coreMemdevState{plugged: w.mds[i].plugged}
	}
	w.stacks = [2][]string{}
}

// restarted returns the states after a start of the process (03-design 5.6
// phase 1 in its order; 03a T1-T4 on a-recover): memdevs absent at load are
// GONE (T3); a region of ours recorded but gone is forgotten; the grants of
// cut Prepares (PREPARING) and the kept grants of KEPT claims are released
// per the recovery column of the release policy (releaseKept, releaseCut);
// the node mounts that no
// realised grant of a prepared claim and no grant of an unfinished release
// lists are swept (D1); an idle persistent region with nothing above goes
// (T3 IDLE_KEPT -> UNUSED).
func (w *coreState) restarted() []*coreState {
	w.arm = 0
	for md := range w.mds {
		m := &w.mds[md]
		if m.kreg == kregNone {
			// a region of ours recorded but gone: the record cleared,
			// the grants kept for kubelet
			m.reg, m.est = "", false
			rec := m.rec
			w.detach(md)
			m.rec = rec
		}
		// T3 any -> GONE: the memdev ABSENT at load, its grants kept for
		// kubelet's Unprepare; GONE -> ACTIVE: present again
		switch {
		case !m.plugged && m.rec != "":
			m.rec = state.MemdevGone
		case m.plugged && m.rec == state.MemdevGone:
			m.rec = state.MemdevActive
		}
	}
	alts := w.releaseKept()
	for i, ss := range w.slots {
		if ss.prep != state.PreparationPreparing || ss.grant == "" || !w.mds[coreSlots[i].md].plugged {
			continue
		}
		var next []*coreState
		for _, a := range alts {
			next = append(next, a.releaseCut(i)...)
		}
		alts = next
	}
	out := alts
	for _, a := range out {
		for md := range a.mds {
			m := &a.mds[md]
			if coreMemdevs[md].kind == state.KindPersistent {
				if users, _ := a.fsUsers(md); !users {
					m.mount = ""
				}
			}
			if m.rec == state.MemdevIdleKept && coreMemdevs[md].kind == state.KindPersistent && !a.regionsAbove(md) &&
				len(a.usersOf(md)) == 0 {
				a.destroy(md)
			}
		}
	}
	return out
}

// releaseKept returns the states after the start released the KEPT claims
// as the grants of cut Prepares are (5.6; the code table's KEPT -> UNKNOWN on
// a-recover, D8): a KEPT claim whose region another grant holds, or with a
// cut Prepare's grant on its memdev, is not the region's last holder and is
// released; one that holds the region alone goes by the recovery column of
// the release policy: kept for the claim below newer regions in order
// (pool, local sliced), released with the region destroyed on top; on a
// local shared or persistent memdev released, the region kept idle (while
// regions lie above it, persistent) or destroyed.
func (w *coreState) releaseKept() []*coreState {
	alts := []*coreState{w}
	for md := range w.mds {
		var kept []int
		for i, ss := range w.slots {
			if coreSlots[i].md == md && ss.prep == state.PreparationKept && ss.grant == state.GrantJournaled && w.mds[md].plugged {
				kept = append(kept, i)
			}
		}
		if len(kept) == 0 {
			continue
		}
		var next []*coreState
		for _, a := range alts {
			next = append(next, a.releaseKeptOf(md, kept)...)
		}
		alts = next
	}
	return alts
}

// releaseKeptOf returns the states after the start released the KEPT claims
// kept of the memdev (releaseKept); when none of them is released for
// another holder, each may be the last of them, which the policy decides.
func (w *coreState) releaseKeptOf(md int, kept []int) []*coreState {
	others := w.hasCut(md)
	for _, i := range w.regionUsers(md) {
		if !slices.Contains(kept, i) {
			others = true
		}
	}
	if others {
		r := w.clone()
		for _, i := range kept {
			r.slots[i] = coreSlotState{}
		}
		return []*coreState{r}
	}
	var out []*coreState
	for _, last := range kept {
		r := w.clone()
		for _, i := range kept {
			if i != last {
				r.slots[i] = coreSlotState{}
			}
		}
		m := &r.mds[md]
		d := &coreMemdevs[md]
		switch {
		case d.source == state.SourceLocal && d.kind != state.KindExclusive:
			r.slots[last] = coreSlotState{}
			if d.kind == state.KindShared || r.regionsAbove(md) {
				m.rec = state.MemdevIdleKept
			} else {
				r.destroy(md)
			}
		case r.regionsAbove(md):
		default:
			r.slots[last] = coreSlotState{}
			r.destroy(md)
		}
		out = append(out, r)
	}
	return out
}

// hasCut tells whether a cut Prepare (PREPARING) has a grant on the
// memdev.
func (w *coreState) hasCut(md int) bool {
	for i, ss := range w.slots {
		if coreSlots[i].md == md && ss.prep == state.PreparationPreparing && ss.grant != "" {
			return true
		}
	}
	return false
}

// releaseCut returns the states after the recovery released the grant of
// the cut Prepare of the slot (5.6) per the recovery column of the release
// policy (the matrix that rules 5.4, D3): pool devices and local sliced in
// order; local shared established keep idle; local persistent established
// in order idle; a new (not established) local region in order. A region
// kept in order is KEPT for the claim, the preparation KEPT (D4), the
// region disabled or as it was (D6); one kept idle stays as it is for the
// memdev, the claim PREPARING.
func (w *coreState) releaseCut(i int) []*coreState {
	md := coreSlots[i].md
	r := w.clone()
	m := &r.mds[md]
	r.slots[i] = coreSlotState{prep: state.PreparationPreparing}
	if coreSlots[i].mode == state.ModeNUMA {
		m.online = false
	}
	if coreSlots[i].mode == state.ModeFs {
		m.mount = r.mountAfter(md)
	}
	if len(r.regionUsers(md)) > 0 {
		return []*coreState{r}
	}
	if m.kreg == kregNone || m.foreign {
		r.dropIdle(md)
		return []*coreState{r}
	}
	d := &coreMemdevs[md]
	idle := d.source == state.SourceLocal && d.kind != state.KindExclusive && m.est
	switch {
	case idle && d.kind == state.KindPersistent && !r.regionsAbove(md):
		r.destroy(md)
		return []*coreState{r}
	case idle:
		m.rec = state.MemdevIdleKept
		if len(r.usersOf(md)) > 0 {
			m.rec = state.MemdevActive
		}
		if m.kreg == kregOff {
			m.reg = state.RegionKept
		}
		return []*coreState{r}
	case !r.regionsAbove(md):
		r.destroy(md)
		return []*coreState{r}
	}
	var out []*coreState
	for _, kreg := range uniq(kregOff, m.kreg) {
		k := r.clone()
		k.slots[i] = coreSlotState{prep: state.PreparationKept, grant: state.GrantJournaled}
		km := &k.mds[md]
		km.kreg, km.reg, km.rec, km.est = kreg, state.RegionKept, state.MemdevActive, true
		out = append(out, k)
	}
	return out
}
