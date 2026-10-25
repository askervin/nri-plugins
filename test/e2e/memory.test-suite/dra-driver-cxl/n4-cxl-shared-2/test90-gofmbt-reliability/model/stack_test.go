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
	"time"
)

func wantStack(t *testing.T, s *State, si int, want string) {
	t.Helper()
	if got := s.Stacks[si].String(); got != want {
		t.Fatalf("stack %s %s, want %s in\n%s", stackName(si), got, want, s.dump())
	}
}

func TestStackPrimitives(t *testing.T) {
	var st Stack
	for _, k := range []RKey{rkLocal, devKey(2), devKey(3)} {
		st.push(k)
	}
	st.destroy(devKey(2))
	if st.String() != "[local,hole,b-shared0]" || !st.hasHole() {
		t.Fatalf("%s", st)
	}
	st.destroy(devKey(3))
	if st.String() != "[local]" || st.hasHole() {
		t.Fatalf("the top pops the hole below it: %s", st)
	}
	var other Stack
	other.push(rkLocal)
	if !st.equal(&other) || st != other {
		t.Fatalf("%v != %v", st, other)
	}
}

// TestBlockedUntilHoleClears: bug-02's sequence on vm0 hb0. A pod that
// needs a new region through a stack with a hole is blocked; it starts
// only after the region above the hole is gone.
func TestBlockedUntilHoleClears(t *testing.T) {
	cfg := testConfig(t, "full", false)
	s := steps(t, newState(cfg), "create ldax@vm0#0", "settle", "create xdax-b@vm0#0", "settle", "create sdax-b@vm0#0", "settle")
	si := stackIndex(VM0, HB0)
	wantStack(t, s, si, "[local,b-pooled0,b-shared0]")
	s = steps(t, s, "delete xdax-b@vm0#0", "settle")
	wantStack(t, s, si, "[local,hole,b-shared0]")
	s = steps(t, s, "create xnuma-b@vm0#0", "settle")
	wantPhase(t, s, "xnuma-b@vm0#0", Blocked)
	// a lease would need no new region: the local one exists
	s = steps(t, s, "create lease@vm0#0", "settle", "lease-get lease@vm0#0 dax", "settle")

	// the oracle: blocked as predicted
	o := observation(t, s)
	v, _ := checkState(s, o, "")
	wantVerdict(t, v, VOK, "ok")
	p := podOf(t, o, "xnuma-b@vm0#0")
	ev, evs := p.Event, p.Events
	// the text is in an older event (A12): found
	p.Event = &ObsEvent{Reason: "FailedPrepareDynamicResources", Message: "rpc error: code = Unavailable"}
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VOK, "ok")
	p.Event, p.Events = nil, nil
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, "no Warning event with \"CXL decoders released out of order\" (newest \"none\"")
	p.Event, p.Events = ev, evs
	node := "vm0"
	p.Phase, p.Ready, p.Node = "Running", true, &node
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VFail, "Running, but its decoder stack vm0/hb0 [local,hole,b-shared0] has a hole")
	// the ports show the hole
	o = observation(t, s)
	o.VMs["vm0"].Ports[0].Decoders[1].Region = "region9"
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, "stack vm0/hb0: committed decoders [local,local,b-shared0], want [local,hole,b-shared0]")
	o.VMs["vm0"].Ports[0].Decoders[1].Region = "region77"
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, "stack vm0/hb0: decoder of region77, a region of no known serial")

	// the region above the hole goes: the hole clears, the blocked pod
	// starts at kubelet's next retry
	s = steps(t, s, "delete sdax-b@vm0#0", "settle")
	wantStack(t, s, si, "[local]")
	wantPhase(t, s, "xnuma-b@vm0#0", Unblocking)
	// nothing else on the stack while it waits (the order would be
	// unknown), but its deletion
	s = steps(t, s, "!create sdax-b@vm0#0", "!lease-put lease@vm0#0", "!delete ldax@vm0#0")

	// still ContainerCreating: accepted, until the timeout
	o = observation(t, s)
	p = podOf(t, o, "xnuma-b@vm0#0")
	w := "ContainerCreating"
	p.Phase, p.Ready, p.Waiting = "Pending", false, &w
	now := time.Unix(time.Now().Unix(), 0)
	v, adopted := checkStateAt(s, o, "", now, time.Minute)
	wantVerdict(t, v, VOK, "ok")
	if ss := slotOf(t, adopted, "xnuma-b@vm0#0"); ss.Phase != Unblocking || adopted.unblockAt(cfg.slotIndex("xnuma-b@vm0#0")) != now.Unix() {
		t.Fatalf("adopted %+v", ss)
	}
	v, _ = checkStateAt(adopted, o, "", now.Add(2*time.Minute), time.Minute)
	wantVerdict(t, v, VFail, "not Running 2m0s after its decoder hole cleared (ContainerCreating)")
	// Running: adopted with its region on top
	sm := newSim(cfg, 1)
	sm.truth = adopted.clone()
	sm.truth.Slots[cfg.slotIndex("xnuma-b@vm0#0")].Phase = Running
	sm.truth.Stacks[si].push(devKey(pooledDev(PoolB)))
	v, adopted2 := checkStateAt(adopted, sm.observe(int(s.Steps), 1), "", now, time.Minute)
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted2, "xnuma-b@vm0#0", Running)
	wantStack(t, adopted2, si, "[local,b-pooled0]")
	// and the stack is free again
	steps(t, adopted2, "create sdax-b@vm0#0")
	// deleting the waiting pod is allowed, whatever its retry did
	s = steps(t, s, "delete xnuma-b@vm0#0", "settle")
	wantStack(t, s, si, "[local]")
}

// TestAdoptedOrder: two regions made in one window on one stack race for
// the order; on-line the observed order is adopted, and what a later
// destroy does depends on it.
func TestAdoptedOrder(t *testing.T) {
	cfg := testConfig(t, "full", true)
	si := stackIndex(VM2, HB0)
	s := steps(t, newState(cfg), "create lnuma@vm2#0", "create xdax-a@vm2#0", "settle")
	var orders []string
	for _, a := range alts(s) {
		orders = append(orders, a.Stacks[si].String())
	}
	if strings.Join(orders, " ") != "[local,a-pooled0] [a-pooled0,local]" {
		t.Fatalf("outcomes %v", orders)
	}
	seen := map[string]bool{}
	for seed := int64(1); seed <= 20 && len(seen) < 2; seed++ {
		sm := newSim(cfg, seed)
		sm.truth = sm.resolve(s)
		v, adopted := checkState(s, sm.observe(int(s.Steps), 1), "")
		wantVerdict(t, v, VOK, "ok")
		got := adopted.Stacks[si].String()
		if got != sm.truth.Stacks[si].String() {
			t.Fatalf("adopted %s, the SUT has %s", got, sm.truth.Stacks[si])
		}
		seen[got] = true
		// deleting lnuma: a hole only if local is not the top
		after := steps(t, adopted, "delete lnuma@vm2#0", "settle")
		want := "[a-pooled0]"
		if got == "[local,a-pooled0]" {
			want = "[hole,a-pooled0]"
		}
		wantStack(t, after, si, want)
		// without the ports the oracle cannot tell: it takes the issue
		// order
		o := sm.observe(int(s.Steps), 1)
		for _, ov := range o.VMs {
			ov.Ports = nil
		}
		v, adopted = checkState(s, o, "")
		wantVerdict(t, v, VOK, "ok")
		wantStack(t, adopted, si, "[local,a-pooled0]")
	}
	if len(seen) != 2 {
		t.Fatalf("the simulated SUT took one order only: %v", seen)
	}
	// off-line the race is not generated
	off := testConfig(t, "full", false)
	steps(t, newState(off), "create lnuma@vm2#0", "!create xdax-a@vm2#0", "create xdax-c@vm2#0")
}

func TestAvoidHoles(t *testing.T) {
	cfg := testConfig(t, "full", false)
	cfg.AvoidHoles = true
	s := steps(t, newState(cfg), "create lnuma@vm2#0", "settle", "create xdax-a@vm2#0", "settle")
	// lnuma's region is below a-pooled0's: no; with another user of the
	// local region, deleting one destroys nothing
	s = steps(t, s, "!delete lnuma@vm2#0", "create lnuma@vm2#1", "settle", "delete lnuma@vm2#1", "settle", "!delete lnuma@vm2#0",
		"delete xdax-a@vm2#0", "settle", "delete lnuma@vm2#0", "settle")
	wantStack(t, s, stackIndex(VM2, HB0), "[]")
}

func TestLeaseNeedsRegion(t *testing.T) {
	cfg := testConfig(t, "full", false)
	s := steps(t, newState(cfg), "create xdax-b@vm0#0", "settle", "create sdax-b@vm0#0", "settle", "delete xdax-b@vm0#0", "settle",
		"create lease@vm0#0", "settle")
	wantStack(t, s, stackIndex(VM0, HB0), "[hole,b-shared0]")
	// the companion's slice would need the local region: refused, the
	// lease-get would fail after its --wait
	s = steps(t, s, "!lease-get lease@vm0#0 numa", "!lease-get lease@vm0#0 dax", "create ldax@vm0#0", "settle")
	wantPhase(t, s, "ldax@vm0#0", Blocked)
}

// TestStackUsersOfOneRegion: shares of one device on one node use one
// region; the last one destroys it.
func TestStackUsersOfOneRegion(t *testing.T) {
	cfg := testConfig(t, "full", false)
	si := stackIndex(VM2, HB0)
	s := steps(t, newState(cfg), "create sdax-a@vm2#0", "settle", "create lnuma@vm2#0", "settle", "create sdax-a@vm2#1", "create sro-a@vm2#0", "settle")
	wantStack(t, s, si, "[a-shared0,local]")
	s = steps(t, s, "delete sdax-a@vm2#0", "settle", "delete sro-a@vm2#0", "settle")
	wantStack(t, s, si, "[a-shared0,local]")
	s = steps(t, s, "delete sdax-a@vm2#1", "settle")
	wantStack(t, s, si, "[hole,local]")
	// a lease slice on vm2 reuses the local region: fine with the hole
	s = steps(t, s, "create lease@vm2#0", "settle", "lease-get lease@vm2#0 numa", "settle", "delete lnuma@vm2#0", "settle")
	wantStack(t, s, si, "[hole,local]")
	s = steps(t, s, "lease-put lease@vm2#0", "settle")
	wantStack(t, s, si, "[]")
}
