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

import (
	"strings"
	"testing"
)

func testConfig(t *testing.T, profile string, online bool) *Config {
	t.Helper()
	cfg := defaultConfig()
	cfg.Online = online
	cfg.Unsettled = 100 // the tests settle when they want
	if err := cfg.loadProfile(profile); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// steps applies action lines; "!line" must be disabled.
func steps(t *testing.T, s *State, lines ...string) *State {
	t.Helper()
	for _, line := range lines {
		want := true
		if strings.HasPrefix(line, "!") {
			want, line = false, line[1:]
		}
		a, err := parseAct(s.cfg, line)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if got := s.enabled(a); got != want {
			t.Fatalf("%q: enabled %v, want %v in\n%s", line, got, want, s.dump())
		}
		if want {
			s = s.apply(a)
		}
	}
	return s
}

func slotOf(t *testing.T, s *State, name string) *SlotState {
	t.Helper()
	i := s.cfg.slotIndex(name)
	if i < 0 {
		t.Fatalf("no slot %s", name)
	}
	return &s.Slots[i]
}

func wantPhase(t *testing.T, s *State, name string, ph Phase) {
	t.Helper()
	if got := slotOf(t, s, name).Phase; got != ph {
		t.Fatalf("%s: phase %s, want %s in\n%s", name, got, ph, s.dump())
	}
}

func TestExclusivePoolDevice(t *testing.T) {
	s := newState(testConfig(t, "full", false))
	s = steps(t, s, "create xnuma-a@vm1#0", "create xdax-a@vm2#0", "!create xdax-a@vm1#0")
	wantPhase(t, s, "xnuma-a@vm1#0", Starting)
	wantPhase(t, s, "xdax-a@vm2#0", Pending)
	s = steps(t, s, "settle")
	wantPhase(t, s, "xnuma-a@vm1#0", Running)
	wantPhase(t, s, "xdax-a@vm2#0", Pending)
	if s.Ctrl[PoolA].Att[0][VM1] != TriYes || s.Ctrl[PoolA].Att[0][VM2] != TriNo {
		t.Fatalf("attachments %v", s.Ctrl[PoolA].Att)
	}
	if s.Data[pooledDev(PoolA)].Known {
		t.Fatalf("a numa use must make the content unknown")
	}
	// the holder goes: the waiter gets the device, nobody else may ask
	s = steps(t, s, "delete xnuma-a@vm1#0", "!create xdax-a@vm1#0")
	wantPhase(t, s, "xdax-a@vm2#0", Starting)
	if !s.contested(Res(pooledDev(PoolA))) {
		t.Fatalf("not contested")
	}
	s = steps(t, s, "settle", "create xdax-a@vm1#0")
	wantPhase(t, s, "xdax-a@vm2#0", Running)
	wantPhase(t, s, "xnuma-a@vm1#0", Absent)
	wantPhase(t, s, "xdax-a@vm1#0", Pending)
	// moved from vm1 to vm2: detach then attach
	if s.Ctrl[PoolA].Att[0][VM1] != TriNo || s.Ctrl[PoolA].Att[0][VM2] != TriYes {
		t.Fatalf("attachments %v", s.Ctrl[PoolA].Att)
	}
}

func TestMoveInOneWindow(t *testing.T) {
	s := newState(testConfig(t, "full", false))
	s = steps(t, s, "create xdax-a@vm1#0", "settle", "delete xdax-a@vm1#0", "create xdax-a@vm2#0")
	// the only candidate for the device being released
	wantPhase(t, s, "xdax-a@vm2#0", Starting)
	s = steps(t, s, "!create xnuma-a@vm2#0", "settle")
	wantPhase(t, s, "xdax-a@vm2#0", Running)
}

func TestSharedDevice(t *testing.T) {
	s := newState(testConfig(t, "full", false))
	s = steps(t, s, "create sdax-a@vm1#0", "create sdax-a@vm2#0", "create sro-a@vm2#0", "create sexcl-a@vm2#0", "settle")
	for _, n := range []string{"sdax-a@vm1#0", "sdax-a@vm2#0", "sro-a@vm2#0"} {
		wantPhase(t, s, n, Running)
	}
	wantPhase(t, s, "sexcl-a@vm2#0", Pending)
	att, excl := s.desiredAtt(PoolA)
	if !att[1][VM1] || !att[1][VM2] || excl[1][VM2] {
		t.Fatalf("desired %v excl %v", att, excl)
	}
	// a waiter blocks new users of the device
	s = steps(t, s, "!create sdax-a@vm2#1", "delete sdax-a@vm1#0", "delete sdax-a@vm2#0")
	wantPhase(t, s, "sexcl-a@vm2#0", Pending)
	s = steps(t, s, "delete sro-a@vm2#0")
	wantPhase(t, s, "sexcl-a@vm2#0", Starting)
	s = steps(t, s, "settle")
	_, excl = s.desiredAtt(PoolA)
	if !excl[1][VM2] || s.Ctrl[PoolA].Att[1][VM1] != TriNo {
		t.Fatalf("excl %v att %v", excl, s.Ctrl[PoolA].Att)
	}
	// shares wait for the exclusive user
	s = steps(t, s, "create sdax-a@vm1#0", "settle")
	wantPhase(t, s, "sdax-a@vm1#0", Pending)
}

func TestLocalCapacity(t *testing.T) {
	s := newState(testConfig(t, "full", false))
	s = steps(t, s, "create lnuma@vm0#0", "create ldax@vm0#0", "create lnuma@vm0#1", "!create lnuma@vm0#1", "settle")
	wantPhase(t, s, "lnuma@vm0#0", Running)
	wantPhase(t, s, "ldax@vm0#0", Running)
	wantPhase(t, s, "lnuma@vm0#1", Pending)
	if got := s.SlotData[s.cfg.slotIndex("ldax@vm0#0")]; got != tokZero {
		t.Fatalf("a new dax slice reads %v, want zero", got)
	}
	s = steps(t, s, "create lease@vm0#0", "settle", "!lease-get lease@vm0#0 numa")
	s = steps(t, s, "delete ldax@vm0#0")
	wantPhase(t, s, "lnuma@vm0#1", Starting)
	// the block of the deleted slice is promised: no lease
	s = steps(t, s, "!lease-get lease@vm0#0 dax", "settle")
	wantPhase(t, s, "lnuma@vm0#1", Running)
	held, all := s.localUse(VM0)
	if held != 2 || all != 2 {
		t.Fatalf("local use %d/%d", held, all)
	}
}

func TestLease(t *testing.T) {
	s := newState(testConfig(t, "full", false))
	s = steps(t, s, "!lease-get lease@vm0#0 numa", "create lease@vm0#0", "!lease-get lease@vm0#0 numa", "settle",
		"lease-get lease@vm0#0 numa", "!lease-get lease@vm0#0 dax")
	ss := slotOf(t, s, "lease@vm0#0")
	if ss.Lease != LeaseHeld || ss.LeaseMode != ModeNuma {
		t.Fatalf("lease %v %v", ss.Lease, ss.LeaseMode)
	}
	if s.Drv[VM0].F&s.fenceBit(2) == 0 {
		t.Fatalf("a numa lease fences its node")
	}
	// one block left on vm0
	s = steps(t, s, "settle", "create lnuma@vm0#0", "create lnuma@vm0#1", "settle")
	wantPhase(t, s, "lnuma@vm0#0", Running)
	wantPhase(t, s, "lnuma@vm0#1", Pending)
	// kept across a crash of the requester
	s = steps(t, s, "crash lease@vm0#0", "settle")
	if slotOf(t, s, "lease@vm0#0").Lease != LeaseHeld {
		t.Fatalf("lease not kept across a crash")
	}
	// released with the requester pod; its block goes to the waiter
	s = steps(t, s, "delete lease@vm0#0")
	wantPhase(t, s, "lnuma@vm0#1", Starting)
	s = steps(t, s, "settle")
	if ss := slotOf(t, s, "lease@vm0#0"); ss.Lease != LeaseNone || ss.Phase != Absent {
		t.Fatalf("lease %v phase %v", ss.Lease, ss.Phase)
	}
	// lease-put
	s = steps(t, s, "create lease@vm2#0", "settle", "lease-get lease@vm2#0 dax", "settle", "lease-put lease@vm2#0", "!lease-put lease@vm2#0", "settle")
	if slotOf(t, s, "lease@vm2#0").Lease != LeaseNone {
		t.Fatalf("lease-put")
	}
}

func TestCrash(t *testing.T) {
	cfg := testConfig(t, "full", false)
	s := newState(cfg)
	s = steps(t, s, "!crash plain@vm0#0", "create plain@vm0#0", "!crash plain@vm0#0", "settle", "crash plain@vm0#0", "!crash plain@vm0#0")
	wantPhase(t, s, "plain@vm0#0", Restarting)
	s = steps(t, s, "settle", "crash plain@vm0#0", "settle", "!crash plain@vm0#0")
	if r := slotOf(t, s, "plain@vm0#0").Restarts; r != 2 {
		t.Fatalf("restarts %d", r)
	}
	// crash keeps the content of a dax slice
	s = steps(t, s, "create ldax@vm1#0", "settle", "write ldax@vm1#0", "crash ldax@vm1#0", "settle")
	if got := s.SlotData[cfg.slotIndex("ldax@vm1#0")]; !got.Known || !strings.HasPrefix(got.Text, "mbt-") {
		t.Fatalf("data %v", got)
	}
}

// alts returns the settled state and its alternatives.
func alts(s *State) []*State { return append([]*State{s}, s.Alts...) }

func TestControllerKill(t *testing.T) {
	// off-line a kill may not leave a prepare open
	off := steps(t, newState(testConfig(t, "full", false)), "create sdax-c@vm0#0", "settle", "create xnuma-c@vm1#0", "!ctrl-kill c")
	_ = off
	s := newState(testConfig(t, "full", true))
	s = steps(t, s, "create sdax-c@vm0#0", "settle", "create xnuma-c@vm1#0", "delete sdax-c@vm0#0", "ctrl-kill c", "!ctrl-kill c",
		"create sdax-c@vm2#0", "settle")
	// created before the kill: running (prepared before it) or waiting
	// for the attach; after it: waits for the attach
	var phases []Phase
	for _, a := range alts(s) {
		phases = append(phases, slotOf(t, a, "xnuma-c@vm1#0").Phase)
		wantPhase(t, a, "sdax-c@vm2#0", Attaching)
	}
	if len(phases) != 2 || phases[0] != Running || phases[1] != Attaching {
		t.Fatalf("outcomes of xnuma-c@vm1#0: %v", phases)
	}
	s = s.Alts[0]
	s.Alts = nil
	c := s.Ctrl[PoolC]
	if c.Up || c.Att[0][VM1] != TriMaybe || c.Att[1][VM0] != TriMaybe || c.Att[1][VM2] != TriNo {
		t.Fatalf("controller %+v", c)
	}
	// an Attaching pod holds its device
	s = steps(t, s, "create sexcl-c@vm1#0", "settle")
	wantPhase(t, s, "sexcl-c@vm1#0", Pending)
	s = steps(t, s, "ctrl-start c", "settle")
	wantPhase(t, s, "xnuma-c@vm1#0", Running)
	wantPhase(t, s, "sdax-c@vm2#0", Running)
	c = s.Ctrl[PoolC]
	if c.Att[0][VM1] != TriYes || c.Att[1][VM0] != TriNo || c.Att[1][VM2] != TriYes {
		t.Fatalf("controller %+v", c)
	}
	// deleted while the controller is down: the attachment stays
	s = steps(t, s, "ctrl-kill c", "settle", "delete sdax-c@vm2#0", "settle")
	if s.Ctrl[PoolC].Att[1][VM2] != TriYes {
		t.Fatalf("attachment of a deleted pod must stay while the controller is down: %+v", s.Ctrl[PoolC])
	}
	s = steps(t, s, "ctrl-start c", "settle")
	if s.Ctrl[PoolC].Att[1][VM2] != TriNo {
		t.Fatalf("attachment not detached after ctrl-start: %+v", s.Ctrl[PoolC])
	}
}

func TestDriverRestart(t *testing.T) {
	s := newState(testConfig(t, "full", false))
	s = steps(t, s, "create lsteer@vm2#0", "!create xnuma-a@vm2#0", "create xnuma-c@vm1#0", "settle", "create xnuma-a@vm2#0", "settle")
	if got := slotOf(t, s, "lsteer@vm2#0").Steer; got != SteerOn {
		t.Fatalf("steer %v", got)
	}
	if s.Drv[VM2].F != s.fenceBit(2) || s.Drv[VM1].F != s.fenceBit(3) {
		t.Fatalf("F %v %v", s.Drv[VM2].F, s.Drv[VM1].F)
	}
	// the local region exists: lnuma reuses it, no race with the
	// destroy of a-pooled0's region
	s = steps(t, s, "delete xnuma-a@vm2#0", "create lnuma@vm2#0", "driver-kill vm2", "!driver-kill vm2", "!driver-restart vm2")
	d := s.Drv[VM2]
	if d.Restarts != 1 || !d.Killed || d.F != s.fenceBit(2) {
		t.Fatalf("driver %+v", d)
	}
	if got := slotOf(t, s, "lsteer@vm2#0").Steer; got != SteerOff {
		t.Fatalf("a manager does not survive its driver: steer %v", got)
	}
	s = steps(t, s, "!lease-get lease@vm2#0 numa", "settle", "crash lsteer@vm2#0", "driver-kill vm2", "!driver-kill vm2", "settle")
	if got := slotOf(t, s, "lsteer@vm2#0").Steer; got != SteerAny {
		t.Fatalf("restarted in a driver restart window: steer %v", got)
	}
	s = steps(t, s, "driver-restart vm2", "settle")
	if d := s.Drv[VM2]; d.Restarts != 0 || d.PodGen != 1 {
		t.Fatalf("driver %+v", d)
	}
	// F is reseeded from what is prepared: xnuma-a was deleted
	s = steps(t, s, "delete lnuma@vm2#0", "delete lsteer@vm2#0", "settle", "driver-restart vm2", "settle")
	if s.Drv[VM2].F != 0 || s.Drv[VM2].FMaybe != 0 {
		t.Fatalf("F %v maybe %v", s.Drv[VM2].F, s.Drv[VM2].FMaybe)
	}
	// in flux at a restart: maybe
	s = steps(t, s, "create lnuma@vm2#0", "driver-restart vm2")
	if s.Drv[VM2].FMaybe != s.fenceBit(2) {
		t.Fatalf("maybe %v", s.Drv[VM2].FMaybe)
	}
	s = steps(t, s, "settle")
	if s.Drv[VM2].F != s.fenceBit(2) || s.Drv[VM2].FMaybe != 0 {
		t.Fatalf("F %v maybe %v", s.Drv[VM2].F, s.Drv[VM2].FMaybe)
	}
}

func TestContainerdRestart(t *testing.T) {
	s := newState(testConfig(t, "full", false))
	s = steps(t, s, "create lsteer@vm1#0", "create xnuma-c@vm1#0", "settle", "containerd-restart vm1", "!containerd-restart vm1",
		"!driver-kill vm1", "!lease-get lease@vm1#0 numa")
	d := s.Drv[VM1]
	if d.Restarts != 1 || !d.Killed || d.F != s.fenceBit(2)|s.fenceBit(3) {
		t.Fatalf("driver %+v", d)
	}
	// A17: steering ends as after driver-kill: memory.high max
	if got := slotOf(t, s, "lsteer@vm1#0").Steer; got != SteerOff {
		t.Fatalf("steer %v", got)
	}
	s = steps(t, s, "settle", "containerd-restart vm1", "settle", "!containerd-restart vm1", "!driver-kill vm1", "driver-restart vm1", "settle", "containerd-restart vm1")
}

func TestData(t *testing.T) {
	cfg := testConfig(t, "full", false)
	s := newState(cfg)
	s = steps(t, s, "create sdax-c@vm0#0", "create sro-c@vm2#0", "settle", "write sdax-c@vm0#0")
	tok := s.Data[sharedDev(PoolC)]
	if !tok.Known || tok.Text != "mbt-4" {
		t.Fatalf("token %v", tok)
	}
	s = steps(t, s, "write sro-c@vm2#0", "read sro-c@vm2#0")
	if s.Data[sharedDev(PoolC)] != tok {
		t.Fatalf("a read-only write changed the content")
	}
	e := expectDone(s, s.next(mustAct(t, cfg, "read sro-c@vm2#0")), mustAct(t, cfg, "read sro-c@vm2#0"), 7)
	if e.Done.Text == nil || *e.Done.Text != "mbt-4" {
		t.Fatalf("read expectation %+v", e.Done)
	}
	w := mustAct(t, cfg, "write sro-c@vm2#0")
	if e := expectDone(s, s.next(w), w, 7); e.Done.Status != "nonzero" {
		t.Fatalf("write on a read-only claim must be refused: %+v", e.Done)
	}
	// pool dax devices keep their bytes between claims and nodes
	s = steps(t, s, "create xdax-c@vm2#0", "settle", "write xdax-c@vm2#0", "delete xdax-c@vm2#0", "settle", "create xnuma-c@vm1#0", "settle")
	if s.Data[pooledDev(PoolC)].Known {
		t.Fatalf("numa use must make it unknown")
	}
	s = steps(t, s, "delete xnuma-c@vm1#0", "settle", "create xdax-c@vm2#0", "settle", "write xdax-c@vm2#0", "delete xdax-c@vm2#0", "settle")
	if tok := s.Data[pooledDev(PoolC)]; !tok.Known {
		t.Fatalf("token %v", tok)
	}
}

func mustAct(t *testing.T, cfg *Config, line string) Act {
	t.Helper()
	a, err := parseAct(cfg, line)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestForcedSettleAndAvoid(t *testing.T) {
	cfg := testConfig(t, "small", false)
	cfg.Unsettled = 2
	cfg.Avoid = []string{"containerd-restart", "driver-kill:vm1", "crash:lnuma"}
	s := newState(cfg)
	s = steps(t, s, "!settle", "create plain@vm0#0", "create sdax-c@vm0#0", "!create lnuma@vm0#0", "!driver-kill vm0", "settle",
		"write sdax-c@vm0#0", "read sdax-c@vm0#0")
	mm := newMbtModel(cfg)
	for _, a := range mm.acts {
		n := a.name(cfg)
		if strings.HasPrefix(n, "containerd-restart") || n == "driver-kill vm1" || strings.HasPrefix(n, "crash lnuma") {
			t.Fatalf("%s not avoided", n)
		}
	}
	if err := checkAvoid([]string{"no-such-verb"}); err == nil {
		t.Fatalf("unknown verb accepted")
	}
}

func TestAnySlots(t *testing.T) {
	cfg := testConfig(t, "full", true)
	s := newState(cfg)
	// unknown node: no controller kill until the settle
	s = steps(t, s, "create xdax-c@any#0", "!ctrl-kill c", "settle")
	// the settle tries every host: vm0 first, the others in Alts
	var nodes []VM
	for _, a := range alts(s) {
		ss := slotOf(t, a, "xdax-c@any#0")
		if ss.Phase != Running {
			t.Fatalf("any slot %+v", ss)
		}
		nodes = append(nodes, ss.Node)
	}
	if len(nodes) != 3 || nodes[0] != VM0 || nodes[1] != VM1 || nodes[2] != VM2 {
		t.Fatalf("nodes %v", nodes)
	}
	s = steps(t, s, "ctrl-kill c")
	off := testConfig(t, "full", false)
	if off.slotIndex("xdax-c@any#0") >= 0 {
		t.Fatalf("off-line profile has an any slot")
	}
}

func TestAbstractionMemo(t *testing.T) {
	s := newState(testConfig(t, "small", false))
	s = steps(t, s, "create lnuma@vm0#0", "create xnuma-a@vm1#0")
	a := s.String()
	if a != s.String() || !strings.Contains(a, "dev a-pooled0 xnuma.new") || !strings.Contains(a, "local vm0 room lnuma.new") {
		t.Fatalf("abstraction %q", a)
	}
	if s.apply(mustAct(t, s.cfg, "settle")).String() == a {
		t.Fatalf("settle does not change the abstraction")
	}
}

func TestParseRoundTrip(t *testing.T) {
	cfg := testConfig(t, "full", true)
	for _, a := range allActs(cfg) {
		b, err := parseAct(cfg, a.name(cfg))
		if err != nil || b != a {
			t.Fatalf("%q: %+v %v, want %+v", a.name(cfg), b, err, a)
		}
	}
	for _, bad := range []string{"", "create", "create nosuch@vm0#0", "lease-get lease@vm0#0", "lease-get lease@vm0#0 fs",
		"driver-kill any", "ctrl-kill d", "settle now", "frobnicate"} {
		if _, err := parseAct(cfg, bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	for _, bad := range []string{"xnuma-b@vm1#0", "lnuma@any#0", "plain@any#0", "xnuma@vm1#0", "lnuma-a@vm0#0", "xnuma-a@vm1#01"} {
		if _, err := parseSlot(bad); err == nil {
			t.Fatalf("slot %q accepted", bad)
		}
	}
}
