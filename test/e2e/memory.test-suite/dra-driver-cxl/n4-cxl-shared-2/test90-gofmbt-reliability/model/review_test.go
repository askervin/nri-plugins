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

// Regression tests of the counterexamples of plan-13-gofmbt/05-review.txt
// (the reviewer's /tmp/rev/model/rev_test.go), with the behaviour the
// fixes give.

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func revState(t *testing.T, profile string, online bool, lines ...string) *State {
	t.Helper()
	return steps(t, newState(testConfig(t, profile, online)), lines...)
}

func dumpAlts(s *State) string {
	var b strings.Builder
	for j, a := range alts(s) {
		b.WriteString("alt " + strconv.Itoa(j) + ":\n" + a.dump())
	}
	return b.String()
}

// R1: a claim that gets an exclusive device only once the old holder's
// claim is gone prepares after its Unprepare: the region is destroyed
// (here: a hole), never reused.
func TestReviewR1CreateAfterHolder(t *testing.T) {
	s := revState(t, "full", true,
		"create xnuma-a@vm1#0", "settle", "create lnuma@vm1#0", "settle", // vm1/hb0 [a-pooled0,local]
		"delete xnuma-a@vm1#0", "create xdax-a@vm1#0", "settle")
	if len(s.Alts) != 0 || slotOf(t, s, "xdax-a@vm1#0").Phase != Blocked {
		t.Fatalf("want one outcome, xdax-a blocked behind the hole:\n%s", dumpAlts(s))
	}
	wantStack(t, s, stackIndex(VM1, HB0), "[hole,local]")
	// the SUT that leaked the region and reused it fails at once
	leaked := s.clone()
	leaked.Slots[leaked.cfg.slotIndex("xdax-a@vm1#0")].Phase = Running
	leaked.Stacks[stackIndex(VM1, HB0)] = Stack{}
	leaked.Stacks[stackIndex(VM1, HB0)].push(devKey(pooledDev(PoolA)))
	leaked.Stacks[stackIndex(VM1, HB0)].push(rkLocal)
	v, _ := checkState(s, observation(t, leaked), "")
	wantVerdict(t, v, VFail, "Running, but its decoder stack vm1/hb0 [hole,local] has a hole")
}

// R1 for sexcl taking the shared device over from the last share.
func TestReviewR1SexclAfterShare(t *testing.T) {
	s := revState(t, "full", true,
		"create sdax-c@vm1#0", "settle", "create xnuma-c@vm1#0", "settle", // vm1/hb1 [c-shared0,c-pooled0]
		"delete sdax-c@vm1#0", "create sexcl-c@vm1#0", "settle")
	for _, a := range alts(s) {
		if slotOf(t, a, "sexcl-c@vm1#0").Phase == Running && a.Stacks[stackIndex(VM1, HB1)].String() == "[c-shared0,c-pooled0]" {
			t.Fatalf("sexcl running on the old region:\n%s", dumpAlts(s))
		}
	}
	wantPhase(t, s, "sexcl-c@vm1#0", Blocked)
}

// R1 through promote: the waiter of a shared device prepares after every
// share's Unprepare, not only after the last delete's.
func TestReviewR1PromoteAfterAllShares(t *testing.T) {
	s := revState(t, "full", true,
		"create sdax-a@vm2#0", "create sdax-a@vm2#1", "settle",
		"create lnuma@vm2#0", "settle", // vm2/hb0 [a-shared0,local]
		"create sexcl-a@vm2#0", "settle") // pending
	n := steps(t, s, "delete sdax-a@vm2#0", "delete sdax-a@vm2#1", "settle")
	for _, a := range alts(n) {
		if slotOf(t, a, "sexcl-a@vm2#0").Phase == Running && a.Stacks[stackIndex(VM2, HB0)].String() == "[a-shared0,local]" {
			t.Fatalf("sexcl running on the old region:\n%s", dumpAlts(n))
		}
	}
	if len(n.Alts) != 0 || slotOf(t, n, "sexcl-a@vm2#0").Phase != Blocked {
		t.Fatalf("want one outcome, blocked:\n%s", dumpAlts(n))
	}
}

// R2 (A11): a container that is not observed, or whose effective
// cpuset is empty, is a wait, never ok.
func TestReviewR2FencingNeedsContainers(t *testing.T) {
	s := revState(t, "full", false, "create lnuma@vm0#0", "create plain@vm0#0", "settle")
	o := observation(t, s)
	ov := o.VMs["vm0"]
	var keep []ObsContainer
	for _, c := range ov.Containers {
		if !strings.Contains(c.Pod, "plain") {
			keep = append(keep, c)
		}
	}
	ov.Containers = keep
	v, _ := checkState(s, o, "")
	wantVerdict(t, v, VWait, "vm0: no container of plain@vm0#0 (pod mbt-plain-vm0-0-g1) observed")
	for _, c := range []struct{ mems, eff, want string }{
		{"", "", "cpuset.mems.effective not observed"},
		{"", "0-2", "has fenced CXL node 2"},
		{"", "0-1", "ok"}, // inherits: cpuset.mems may be empty
	} {
		o := observation(t, s)
		for j := range o.VMs["vm0"].Containers {
			if x := &o.VMs["vm0"].Containers[j]; strings.Contains(x.Pod, "plain") {
				x.Mems, x.MemsEffective = c.mems, c.eff
			}
		}
		v, _ := checkState(s, o, "")
		status := VWait
		if c.want == "ok" {
			status = VOK
		}
		wantVerdict(t, v, status, c.want)
	}
	// a null part of a VM is a wait too
	o = observation(t, s)
	o.VMs["vm0"].CDI = nil
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, "vm0: cdi not observed (null)")
}

// R3: an "any" pod is not created while a stack of its pool's hosts has
// an unblocking pod.
func TestReviewR3AnyPodOnUnblockingStack(t *testing.T) {
	s := revState(t, "full", true,
		"create xnuma-c@vm1#0", "settle", "create sdax-c@vm1#0", "settle", // vm1/hb1 [c-pooled0,c-shared0]
		"delete xnuma-c@vm1#0", "settle", // [hole,c-shared0]
		"create xnuma-c@vm1#0", "settle", // blocked
		"delete sdax-c@vm1#0", "settle") // [] unblocking
	wantPhase(t, s, "xnuma-c@vm1#0", Unblocking)
	// (xdax-c@any#0 waits for c-pooled0: no region event, allowed)
	n := steps(t, s, "!create sdax-c@vm1#0", "!create sdax-c@any#0", "create xdax-c@any#0", "create sdax-a@vm1#0")
	wantPhase(t, n, "xdax-c@any#0", Pending)
}

// R4a: kubelet retries blocked pods independently: their order is
// adopted from the decoders.
func TestReviewR4TwoUnblockingOrders(t *testing.T) {
	s := revState(t, "full", true,
		"create xnuma-b@vm0#0", "settle", "create lnuma@vm0#0", "settle", "create sdax-b@vm0#0", "settle", // vm0/hb0 [b-pooled0,local,b-shared0]
		"delete xnuma-b@vm0#0", "settle", // [hole,local,b-shared0]
		"create xdax-b@vm0#0", "settle", // blocked
		"delete lnuma@vm0#0", "settle", // [hole,hole,b-shared0]
		"create ldax@vm0#0", "settle", // blocked
		"delete sdax-b@vm0#0", "settle") // [] both unblocking
	for _, sl := range []string{"xdax-b@vm0#0", "ldax@vm0#0"} {
		wantPhase(t, s, sl, Unblocking)
	}
	n := steps(t, s, "create plain@vm0#0", "settle")
	si := stackIndex(VM0, HB0)
	for _, order := range [][]RKey{{rkLocal, devKey(pooledDev(PoolB))}, {devKey(pooledDev(PoolB)), rkLocal}} {
		truth := n.clone()
		for _, sl := range []string{"xdax-b@vm0#0", "ldax@vm0#0"} {
			truth.Slots[truth.cfg.slotIndex(sl)].Phase = Running
		}
		truth.Stacks[si] = Stack{}
		for _, k := range order {
			truth.Stacks[si].push(k)
		}
		truth.growFence()
		v, adopted := checkStateAt(n, observation(t, truth), "", time.Now(), defaultUnblock)
		wantVerdict(t, v, VOK, "ok")
		if !adopted.Stacks[si].equal(&truth.Stacks[si]) {
			t.Fatalf("adopted %s, the SUT has %s", adopted.Stacks[si], truth.Stacks[si])
		}
	}
}

// R4b: no region is made in the window that clears a hole with a pod
// blocked behind it (its retry could come first).
func TestReviewR4NoPushInClearingWindow(t *testing.T) {
	s := revState(t, "full", true,
		"create xnuma-c@vm1#0", "settle", "create sdax-c@vm1#0", "settle", // [c-pooled0,c-shared0]
		"delete xnuma-c@vm1#0", "settle", // [hole,c-shared0]
		"create xnuma-c@vm1#0", "settle") // blocked
	wantPhase(t, s, "xnuma-c@vm1#0", Blocked)
	n := steps(t, s, "delete sdax-c@vm1#0", "!create sexcl-c@vm1#0", "!create sdax-c@vm1#0", "settle")
	wantPhase(t, n, "xnuma-c@vm1#0", Unblocking)
}

// R5: generate --from with the adoption records follows the run; without
// them it stops at the first open choice.
func TestReviewR5FromAnyNode(t *testing.T) {
	cfg := defaultConfig()
	cfg.Online = true
	if err := cfg.loadProfile("full"); err != nil {
		t.Fatal(err)
	}
	cov, _ := parseCoverage(defaultCoverage)
	o := runOpts{cfg: cfg, cov: cov, depth: 1, seed: 1, header: "rev"}
	acts := []string{"settle", "create sdax-c@any#0", "settle", "create plain@vm0#0", "settle"}
	var b bytes.Buffer
	if err := generate(o, stepLines(acts), &b); err == nil || !strings.Contains(err.Error(), "step 3 settle leaves 3 outcomes of races open") {
		t.Fatalf("want a stop at step 3, got %v", err)
	}
	lines, _ := readSteps("settle\n#adopt 1\ncreate sdax-c@any#0\nsettle\n#adopt 3 alt=1\ncreate plain@vm0#0\nsettle\n#adopt 5\n")
	b.Reset()
	if err := generate(o, lines, &b); err != nil {
		t.Fatal(err)
	}
	g, err := parseGenScript(b.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, sj := range g.Expects[5].Slots {
		if sj.Slot == "sdax-c@any#0" && (sj.Node != "vm1" || len(g.Expects[5].Alts) != 0) {
			t.Fatalf("step 5: %+v, %d alternatives", sj, len(g.Expects[5].Alts))
		}
	}
}

// R7 (A17): after driver-kill and containerd-restart alike, a running
// lsteer container has memory.high max; restarted, it is steered again.
func TestReviewR7SteeringAfterRestarts(t *testing.T) {
	for _, fault := range []string{"driver-kill vm2", "containerd-restart vm2", "driver-restart vm2"} {
		s := revState(t, "full", false, "create lsteer@vm2#0", "settle", fault, "settle")
		if got := slotOf(t, s, "lsteer@vm2#0").Steer; got != SteerOff {
			t.Fatalf("%s: steer %s, want off (max)", fault, got)
		}
		s = steps(t, s, "crash lsteer@vm2#0", "settle")
		if got := slotOf(t, s, "lsteer@vm2#0").Steer; got != SteerOn {
			t.Fatalf("%s, crash: steer %s, want on", fault, got)
		}
	}
}

// R10: a settle whose outcomes are not all enumerated says so in a
// failure.
func TestReviewR10Truncated(t *testing.T) {
	s := revState(t, "full", false, "create plain@vm0#0", "settle")
	s.Truncated = true
	o := observation(t, s)
	podOf(t, o, "plain@vm0#0").Restarts = 3
	v, _ := checkState(s, o, "")
	wantVerdict(t, v, VFail, "not all enumerated")
}

// A13: panics, slices, leases.json.
func TestReviewA13Checks(t *testing.T) {
	s := revState(t, "full", false, "create lease@vm1#0", "create xnuma-a@vm1#0", "settle", "lease-get lease@vm1#0 numa", "settle")
	o := observation(t, s)
	v, _ := checkState(s, o, "")
	wantVerdict(t, v, VOK, "ok")
	o.VMs["vm1"].DriverLog.Panics = 1
	o.VMs["vm1"].DriverLog.Errors = []string{"panic: runtime error: nil pointer"}
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VFail, "driver vm1: 1 panics in the log of container drv-vm1-0: panic: runtime error")
	o = observation(t, s)
	o.Slices["vm1"] = append(o.Slices["vm1"], ObsSliceDev{Name: "memdev-c1ee0001", Serial: "0xc1ee0001"})
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, "vm1: cxl.nri.io slice publishes memdev-c1ee0001 (serial 0xc1ee0001 of pool device a-pooled0)")
	o = observation(t, s)
	o.Slices["vm2"] = o.Slices["vm2"][1:]
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, "vm2: cxl.nri.io slice without memdev-c100e2e1")
	o = observation(t, s)
	o.VMs["vm1"].State.Leases = []byte(`{"claims":{},"leases":{}}`)
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, "vm1: leases.json has lease claims [], want")
	// missing fields are notes, not differences
	o = observation(t, s)
	o.Slices = nil
	o.VMs["vm1"].DriverLog = nil
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VOK, "ok")
	if len(v.Notes) != 2 {
		t.Fatalf("notes %v", v.Notes)
	}
}

// A16: a replay and --from take the model of the steps file's header.
func TestReviewA16Header(t *testing.T) {
	fs := flag.NewFlagSet("online", flag.ContinueOnError)
	var c commonFlags
	c.register(fs, true)
	if err := fs.Parse([]string{"--profile", "full", "--steps", "7", "--avoid", "crash"}); err != nil {
		t.Fatal(err)
	}
	_, header := readSteps("# mbt-cxl online seed=1\n# --profile small --seed 9 --avoid \"\" --avoid-holes=true --local-blocks vm2=8,vm1=1,vm0=2 --steps 40 --plan-ahead=true\nsettle\n")
	var msgs bytes.Buffer
	if err := applyHeader(fs, header, &msgs); err != nil {
		t.Fatal(err)
	}
	if c.profile != "small" || c.avoid != "" || !c.avoidHoles || c.localBlocks != "vm2=8,vm1=2,vm0=2" || c.steps != 7 || c.seed != 0 {
		t.Fatalf("flags %+v", c)
	}
	if !strings.Contains(msgs.String(), `--profile "full" of the command line replaced by "small"`) {
		t.Fatalf("no warning: %q", msgs.String())
	}
}

// M2 (04-status-EXEC): a kubelet restart while a container is being
// created may restart it once.
func TestReviewM2KubeletRestartSlack(t *testing.T) {
	s := revState(t, "full", true, "create lease@vm2#0", "create plain@vm1#0", "kubelet-restart vm2", "settle")
	if ss := slotOf(t, s, "lease@vm2#0"); ss.Slack != 1 || slotOf(t, s, "plain@vm1#0").Slack != 0 {
		t.Fatalf("slack %+v", ss)
	}
	for _, c := range []struct {
		restarts int
		status   VStatus
		msg      string
	}{{0, VOK, "ok"}, {1, VOK, "ok"}, {2, VFail, "2 restarts, the model crashed it 0 times (+1 for kubelet or containerd restarts"}} {
		o := observation(t, s)
		podOf(t, o, "lease@vm2#0").Restarts = c.restarts
		v, adopted := checkState(s, o, "")
		wantVerdict(t, v, c.status, c.msg)
		if c.status == VOK {
			if ss := slotOf(t, adopted, "lease@vm2#0"); int(ss.Restarts) != c.restarts || ss.Slack != 0 {
				t.Fatalf("adopted %+v", ss)
			}
		}
	}
}

// A11 and A15 from the executor: its "missing" list, the driver's
// readiness.
func TestReviewA11A15Executor(t *testing.T) {
	s := revState(t, "full", false, "create plain@vm0#0", "settle")
	o := observation(t, s)
	o.VMs["vm0"].Missing = []byte(`[{"pod":"mbt-plain-vm0-0-g1","kind":"pod","container":"main","reason":"its cpuset cannot be read"}]`)
	v, _ := checkState(s, o, "")
	wantVerdict(t, v, VWait, "vm0: container of pod mbt-plain-vm0-0-g1 missing: its cpuset cannot be read")
	o.VMs["vm0"].Missing = []byte(`null`)
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, "vm0: containers not read (missing: null)")
	o = observation(t, s)
	no := false
	o.VMs["vm1"].DriverLog.LendsRestored = &no
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, `driver vm1: "NRI fence: lends restored" not logged yet`)
	o = observation(t, s)
	o.VMs["vm1"].DriverLog.Container = nil
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, "driver vm1: no running driver container")
}

// A18 (run L1): ctrl-restart b, ctrl-kill b before the new controller
// published the slices, create sro-b and xdax-b: unschedulable, not
// waiting for the attach; back when the controller is.
func TestReviewA18SlicesAfterRestart(t *testing.T) {
	s := revState(t, "full", true, "create xnuma-b@vm0#0", "create sdax-b@vm0#1", "settle", "create xdax-b@vm0#0", "settle")
	wantPhase(t, s, "xdax-b@vm0#0", Pending)
	// not while a claim of the pool is being allocated
	steps(t, s, "create sro-b@vm0#0", "!ctrl-restart b")
	s = steps(t, s, "ctrl-restart b", "ctrl-kill b", "create sro-b@vm0#0", "settle")
	var phases []string
	for _, a := range alts(s) {
		phases = append(phases, slotOf(t, a, "sro-b@vm0#0").Phase.String()+"/"+a.Ctrl[PoolB].Slices.String())
		wantPhase(t, a, "xdax-b@vm0#0", Pending)
	}
	if strings.Join(phases, " ") != "attaching/present unsched/absent" {
		t.Fatalf("outcomes %v", phases)
	}
	// the L1 observation: no slices, the claim not allocated
	truth := s.Alts[0]
	o := observation(t, truth)
	v, adopted := checkState(s, o, "")
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted, "sro-b@vm0#0", Unsched)
	if adopted.Ctrl[PoolB].Slices != SlicesAbsent {
		t.Fatalf("slices %s", adopted.Ctrl[PoolB].Slices)
	}
	// without poolSlices the pod's state decides
	o.PoolSlices = nil
	v, adopted = checkState(s, o, "")
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted, "sro-b@vm0#0", Unsched)
	// slices present while predicted absent: wait
	o = observation(t, truth)
	o.PoolSlices["b"] = []ObsPoolSlice{{Name: "x"}}
	v, _ = checkState(adopted, o, "")
	wantVerdict(t, v, VWait, "pool b: 1 ResourceSlices, want none")
	// a new claim of the pool is unschedulable at once; nothing else
	// may ask for a device that such a claim waits for
	steps(t, adopted, "!create sexcl-b@vm0#0", "!create sdax-b@vm0#0")
	n := steps(t, adopted, "delete xnuma-b@vm0#0")
	wantPhase(t, n, "xdax-b@vm0#0", Unsched)
	n = steps(t, n, "settle", "!create xnuma-b@vm0#0", "ctrl-start b", "settle")
	wantPhase(t, n, "sro-b@vm0#0", Running)
	// xnuma-b's region was below b-shared0's: a hole (A9)
	wantPhase(t, n, "xdax-b@vm0#0", Blocked)
	wantStack(t, n, stackIndex(VM0, HB0), "[hole,b-shared0]")
	if n.Ctrl[PoolB].Slices != SlicesPresent || len(n.Alts) != 0 {
		t.Fatalf("after ctrl-start: slices %s, %d alternatives", n.Ctrl[PoolB].Slices, len(n.Alts))
	}
	// off-line a kill does not follow a restart in one window
	steps(t, revState(t, "full", false, "create plain@vm0#0", "settle", "ctrl-restart b"), "!ctrl-kill b", "settle", "ctrl-kill b")
}

// Two unblocking users of one region (the local memdev of a VM): one
// region when they run, whatever the order of their retries.
func TestReviewUnblockingUsersOfOneRegion(t *testing.T) {
	s := revState(t, "full", true,
		"create xnuma-a@vm2#0", "settle", "create sdax-a@vm2#0", "settle", // vm2/hb0 [a-pooled0,a-shared0]
		"delete xnuma-a@vm2#0", "settle", // [hole,a-shared0]
		"create lnuma@vm2#0", "settle", "create lsteer@vm2#0", "settle", // both blocked
		"delete sdax-a@vm2#0", "settle") // [] both unblocking
	wantPhase(t, s, "lnuma@vm2#0", Unblocking)
	wantPhase(t, s, "lsteer@vm2#0", Unblocking)
	truth := s.clone()
	for _, sl := range []string{"lnuma@vm2#0", "lsteer@vm2#0"} {
		truth.Slots[truth.cfg.slotIndex(sl)].Phase = Running
	}
	truth.Slots[truth.cfg.slotIndex("lsteer@vm2#0")].Steer = SteerOn
	truth.Stacks[stackIndex(VM2, HB0)].push(rkLocal)
	truth.growFence()
	v, adopted := checkState(s, observation(t, truth), "")
	wantVerdict(t, v, VOK, "ok")
	wantStack(t, adopted, stackIndex(VM2, HB0), "[local]")
}

// A19 (run L2, bug-08): a claim deleted while it waited for the binding
// conditions holds its device in the scheduler: the contender may stall
// (Pending, claim not allocated) or be promoted; both are accepted for
// 360 s, then the promotion is required.
func TestReviewA19StalledContender(t *testing.T) {
	s := revState(t, "full", true, "ctrl-kill a", "create xnuma-a@vm1#0", "settle", "create xdax-a@vm1#0", "settle")
	wantPhase(t, s, "xnuma-a@vm1#0", Attaching)
	wantPhase(t, s, "xdax-a@vm1#0", Pending)
	// off-line it is not generated
	off := revState(t, "full", false, "ctrl-kill a", "create xnuma-a@vm1#0", "settle", "create xdax-a@vm1#0", "settle")
	steps(t, off, "!delete xnuma-a@vm1#0")
	s = steps(t, s, "delete xnuma-a@vm1#0", "settle")
	wantPhase(t, s, "xdax-a@vm1#0", Stalled)
	// the device stays its: nothing else asks for it
	steps(t, s, "!create xnuma-a@vm2#0")
	now := time.Unix(time.Now().Unix(), 0)
	// stalled (L2): ok, and the time is kept
	o := observation(t, s)
	v, adopted := checkStateAt(s, o, "", now, defaultUnblock)
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted, "xdax-a@vm1#0", Stalled)
	v, _ = checkStateAt(adopted, o, "", now.Add(400*time.Second), defaultUnblock)
	wantVerdict(t, v, VFail, "still not allocated 6m40s after the delete")
	// promoted: allocated, waiting for the attach (controller down)
	truth := s.clone()
	truth.Slots[truth.cfg.slotIndex("xdax-a@vm1#0")].Phase = Attaching
	v, adopted = checkStateAt(s, observation(t, truth), "", now, defaultUnblock)
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted, "xdax-a@vm1#0", Attaching)
	// stalled, then the controller comes back: promoted later, Running
	st := steps(t, s, "ctrl-start a", "settle")
	wantPhase(t, st, "xdax-a@vm1#0", Stalled)
	truth = st.clone()
	truth.Slots[truth.cfg.slotIndex("xdax-a@vm1#0")].Phase = Running
	truth.Ctrl[PoolA].Att[0][VM1] = TriYes
	truth.Stacks[stackIndex(VM1, HB0)].push(devKey(pooledDev(PoolA)))
	v, adopted = checkStateAt(st, observation(t, truth), "", now, defaultUnblock)
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted, "xdax-a@vm1#0", Running)
	wantStack(t, adopted, stackIndex(VM1, HB0), "[a-pooled0]")
	// a holder that was bound hands over at once
	b := revState(t, "full", true, "create xnuma-a@vm1#0", "settle", "create xdax-a@vm1#0", "settle", "delete xnuma-a@vm1#0", "settle")
	wantPhase(t, b, "xdax-a@vm1#0", Running)
}

// L3 (M4): ctrl-restart a, ctrl-kill a before the new controller
// published, server-restart a, settle with no pod of the pool starting:
// the slices may be absent (the outcomes differ only in them: they must
// not be merged); absent is adopted, a new claim of the pool is then
// unschedulable until ctrl-start.
func TestReviewL3SlicesAbsentAfterKill(t *testing.T) {
	s := revState(t, "full", true, "create sexcl-a@vm2#0", "settle", "ctrl-restart a", "write sexcl-a@vm2#0", "ctrl-kill a", "server-restart a", "settle")
	var worlds []string
	for _, a := range alts(s) {
		worlds = append(worlds, a.Ctrl[PoolA].Slices.String())
	}
	if strings.Join(worlds, " ") != "present absent" {
		t.Fatalf("outcomes %v", worlds)
	}
	o := observation(t, s.Alts[0])
	if len(o.PoolSlices["a"]) != 0 {
		t.Fatalf("simulated slices %v", o.PoolSlices["a"])
	}
	v, adopted := checkState(s, o, "")
	wantVerdict(t, v, VOK, "ok")
	if adopted.Ctrl[PoolA].Slices != SlicesAbsent {
		t.Fatalf("adopted slices %s", adopted.Ctrl[PoolA].Slices)
	}
	// nothing but ctrl-start brings them back
	n := steps(t, adopted, "server-restart a", "kubelet-restart vm2", "driver-kill vm2", "containerd-restart vm1", "settle")
	if n.Ctrl[PoolA].Slices != SlicesAbsent {
		t.Fatalf("slices %s after other faults", n.Ctrl[PoolA].Slices)
	}
	n = steps(t, n, "create xnuma-a@vm1#0")
	wantPhase(t, n, "xnuma-a@vm1#0", Unsched)
	n = steps(t, n, "settle", "ctrl-start a", "settle")
	wantPhase(t, n, "xnuma-a@vm1#0", Running)
	if n.Ctrl[PoolA].Slices != SlicesPresent {
		t.Fatalf("slices %s after ctrl-start", n.Ctrl[PoolA].Slices)
	}
}

// replaySteps replays the first n steps of a steps file with its
// adoption records (as generate --from does).
func replaySteps(t *testing.T, cfg *Config, file string, n int) *State {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	lines, _ := readSteps(string(data))
	st := newState(cfg)
	for j, l := range lines[:n] {
		a, err := parseAct(cfg, l.Action)
		if err != nil {
			t.Fatalf("step %d: %v", j+1, err)
		}
		if !st.allowed(a) {
			t.Fatalf("step %d %q not allowed in\n%s", j+1, l.Action, st.dump())
		}
		st = st.apply(a)
		if l.Has {
			if st, err = applyAdoption(st, l.Adopt); err != nil {
				t.Fatalf("step %d: %v", j+1, err)
			}
		}
	}
	return st
}

// L4 (M5): ctrl-restart a and ctrl-kill a left pool a's slices absent;
// ctrl-start a, then the holder of a-pooled0 deleted: the new controller
// publishes the slices within seconds, the waiter of a-pooled0 and the
// claim that waited for the slices are allocated, attached and Running
// at the settle. The run's own observation of step 131 is ok now.
func TestReviewL4SlicesBackAfterStart(t *testing.T) {
	cfg := testConfig(t, "full", true)
	cfg.Unsettled = 3
	st := replaySteps(t, cfg, "recorded/l4-mbt-steps.txt", 130)
	if st.Ctrl[PoolA].Slices != SlicesUnknown {
		t.Fatalf("after ctrl-start a: slices %s, want unknown (published within seconds)", st.Ctrl[PoolA].Slices)
	}
	wantPhase(t, st, "xdax-a@vm1#0", Starting)
	pred := steps(t, st, "settle")
	js, err := os.ReadFile("recorded/l4-fail-131.json")
	if err != nil {
		t.Fatal(err)
	}
	o, err := parseObservation(js)
	if err != nil {
		t.Fatal(err)
	}
	v, adopted := checkState(pred, o, "")
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted, "xdax-a@vm1#0", Running)
	wantPhase(t, adopted, "sro-a@vm1#0", Running)
	if adopted.Ctrl[PoolA].Slices != SlicesPresent {
		t.Fatalf("adopted slices %s", adopted.Ctrl[PoolA].Slices)
	}
	// the same in short: a claim of the pool waits for the slices, the
	// holder of the device that another one waits for is deleted
	s := revState(t, "full", true, "create xnuma-a@vm2#0", "settle", "create xdax-a@vm1#0", "settle",
		"ctrl-restart a", "ctrl-kill a", "settle")
	s = adoptSlices(t, s, PoolA, SlicesAbsent)
	s = steps(t, s, "create sro-a@vm1#0", "settle")
	wantPhase(t, s, "sro-a@vm1#0", Unsched)
	s = steps(t, s, "ctrl-start a", "delete xnuma-a@vm2#0", "settle")
	for _, a := range alts(s) { // (the order of their two regions races)
		wantPhase(t, a, "xdax-a@vm1#0", Running)
		wantPhase(t, a, "sro-a@vm1#0", Running)
		if a.Ctrl[PoolA].Slices != SlicesPresent {
			t.Fatalf("slices %s", a.Ctrl[PoolA].Slices)
		}
	}
	// killed again before the publish: present or absent
	k := steps(t, adoptSlices(t, revState(t, "full", true, "ctrl-restart a", "ctrl-kill a", "settle"), PoolA, SlicesAbsent), "ctrl-start a", "ctrl-kill a", "settle")
	var worlds []string
	for _, a := range alts(k) {
		worlds = append(worlds, a.Ctrl[PoolA].Slices.String())
	}
	if strings.Join(worlds, " ") != "present absent" {
		t.Fatalf("ctrl-start, ctrl-kill: outcomes %v", worlds)
	}
}

// adoptSlices returns the outcome of a settle with the given slices.
func adoptSlices(t *testing.T, s *State, p Pool, st SliceSt) *State {
	t.Helper()
	for _, a := range alts(s) {
		if a.Ctrl[p].Slices == st {
			return a
		}
	}
	t.Fatalf("no outcome with the slices of pool %s %s:\n%s", p, st, dumpAlts(s))
	return nil
}

// The model errors that the fuzz against the reference of the pool side
// found (refpool.go, TestRefPoolFuzz; 04-status-MODEL.txt section 16);
// TestRefPoolRegressions replays the fuzz's own sequences.

// F2 (A19): a claim deleted before its pod was bound holds its device in
// the scheduler up to 5 s after the delete, also past a short settle: a
// contender created in the next window may stall. The oracle ends the
// hold 6 s after the settle that ended the delete's window (adoption
// record held=DEV:off). Off-line nothing would end it: no such delete.
func TestReviewF2HoldAfterSettle(t *testing.T) {
	s := revState(t, "full", true, "ctrl-kill a", "create xnuma-a@vm1#0", "settle", "delete xnuma-a@vm1#0", "settle")
	d := pooledDev(PoolA)
	if !s.held(Res(d)) {
		t.Fatalf("a-pooled0 not held:\n%s", s.dump())
	}
	now := time.Unix(time.Now().Unix(), 0)
	v, adopted := checkStateAt(s, observation(t, s), "", now, defaultUnblock)
	wantVerdict(t, v, VOK, "ok")
	if adopted.HeldAt[d] != now.Unix() {
		t.Fatalf("held since %d, want %d", adopted.HeldAt[d], now.Unix())
	}
	n := steps(t, adopted, "create xdax-a@vm1#0", "!create xnuma-a@vm2#0")
	wantPhase(t, n, "xdax-a@vm1#0", Stalled)
	// a settle 6 s later ends it: a contender gets the device at once
	pred := steps(t, adopted, "create plain@vm0#0", "settle")
	v, later := checkStateAt(pred, observation(t, pred), "", now.Add(7*time.Second), defaultUnblock)
	wantVerdict(t, v, VOK, "ok")
	if later.held(Res(d)) {
		t.Fatalf("still held after 7 s")
	}
	if rec := adoptionRecord(pred, 0, later); !strings.Contains(rec, "held=a-pooled0:off") {
		t.Fatalf("adoption record %q", rec)
	}
	if back, err := applyAdoption(pred, adoptionRecord(pred, 0, later)); err != nil || back.held(Res(d)) {
		t.Fatalf("record not applied: %v", err)
	}
	wantPhase(t, steps(t, later, "create xdax-a@vm1#0"), "xdax-a@vm1#0", Starting)
	// a holder deleted while it was starting holds it too (L4-like
	// create and delete in one window)
	if h := revState(t, "full", true, "create xdax-b@vm0#0", "delete xdax-b@vm0#0", "settle"); !h.held(Res(pooledDev(PoolB))) {
		t.Fatalf("b-pooled0 not held:\n%s", h.dump())
	}
	// a bound holder does not
	if b := revState(t, "full", true, "create xdax-b@vm0#0", "settle", "delete xdax-b@vm0#0", "settle"); b.held(Res(pooledDev(PoolB))) {
		t.Fatalf("b-pooled0 held after a bound holder")
	}
	steps(t, revState(t, "full", false, "ctrl-kill a", "create xnuma-a@vm1#0", "settle"), "!delete xnuma-a@vm1#0")
	steps(t, revState(t, "full", false, "create xdax-b@vm0#0"), "!delete xdax-b@vm0#0")
}

// F1, F3, F6 (A19): a stalled contender seen allocated: an "any" one
// on the node it was bound to; through a decoder hole Blocked; bound
// before a controller kill of the same window: Running.
func TestReviewF1F3F6StalledPromoted(t *testing.T) {
	s := revState(t, "full", true, "ctrl-kill c", "create xnuma-c@vm1#0", "settle", "create xdax-c@any#0", "settle",
		"delete xnuma-c@vm1#0", "ctrl-start c", "settle")
	wantPhase(t, s, "xdax-c@any#0", Stalled)
	truth := s.clone()
	i := truth.cfg.slotIndex("xdax-c@any#0")
	truth.Slots[i].Phase, truth.Slots[i].Node = Running, VM2
	truth.Stacks[stackIndex(VM2, HB1)].push(devKey(pooledDev(PoolC)))
	v, adopted := checkState(s, observation(t, truth), "")
	wantVerdict(t, v, VOK, "ok")
	if ss := slotOf(t, adopted, "xdax-c@any#0"); ss.Phase != Running || ss.Node != VM2 {
		t.Fatalf("adopted %s on %s", ss.Phase, ss.Node)
	}
	// F3: vm1/hb0 [hole,local]: its Prepare needs a new region
	h := revState(t, "full", true, "create xnuma-a@vm1#0", "settle", "create lnuma@vm1#0", "settle", "delete xnuma-a@vm1#0", "settle",
		"ctrl-kill a", "create xnuma-a@vm2#0", "settle", "create xdax-a@vm1#0", "settle", "delete xnuma-a@vm2#0", "ctrl-start a", "settle")
	wantPhase(t, h, "xdax-a@vm1#0", Stalled)
	wantStack(t, h, stackIndex(VM1, HB0), "[hole,local]")
	truth = h.clone()
	truth.Slots[truth.cfg.slotIndex("xdax-a@vm1#0")].Phase = Blocked
	v, adopted = checkState(h, observation(t, truth), "")
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted, "xdax-a@vm1#0", Blocked)
	// F6: promoted and bound, then the controller killed
	k := steps(t, revState(t, "full", true, "ctrl-kill a", "create xnuma-a@vm1#0", "settle", "create xdax-a@vm1#0", "settle",
		"delete xnuma-a@vm1#0", "ctrl-start a", "settle"), "ctrl-kill a", "settle")
	wantPhase(t, k, "xdax-a@vm1#0", Stalled)
	if k.Ctrl[PoolA].Att[0][VM1] != TriMaybe {
		t.Fatalf("a-pooled0@vm1 %v after the kill, want maybe (F5)", k.Ctrl[PoolA].Att[0][VM1])
	}
	truth = k.clone()
	truth.Slots[truth.cfg.slotIndex("xdax-a@vm1#0")].Phase = Running
	truth.Ctrl[PoolA].Att[0][VM1] = TriYes
	truth.Stacks[stackIndex(VM1, HB0)].push(devKey(pooledDev(PoolA)))
	v, adopted = checkState(k, observation(t, truth), "")
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted, "xdax-a@vm1#0", Running)
}

// F4 (A18): claims that tried while the pool had no slices are requeued
// together when they are published: the scheduler picks one. While the
// slices are not known to be back, a claim of the pool is the only
// candidate for its device.
func TestReviewF4OneCandidateWhileSlicesComeBack(t *testing.T) {
	steps(t, revState(t, "full", true, "ctrl-restart a", "create xdax-a@vm2#0"), "!create xnuma-a@vm1#0", "create sdax-a@vm1#0")
	s := adoptSlices(t, revState(t, "full", true, "ctrl-restart a", "ctrl-kill a", "settle"), PoolA, SlicesAbsent)
	s = steps(t, s, "create sdax-a@vm1#0", "settle", "ctrl-start a", "!create sexcl-a@vm2#0", "settle", "create sexcl-a@vm2#0")
	wantPhase(t, s, "sexcl-a@vm2#0", Pending)
}

// F5: at a controller kill the attachments that may have changed since
// the last settle are open: the attach of a claim deleted before it was
// bound (in flight at the server), and an attachment that only claims
// being allocated want (a reconcile may have detached it before them).
func TestReviewF5KillOpensAttachments(t *testing.T) {
	s := revState(t, "full", true, "create sdax-b@vm0#1", "delete sdax-b@vm0#1", "ctrl-kill b")
	if got := s.Ctrl[PoolB].Att[1][VM0]; got != TriMaybe {
		t.Fatalf("b-shared0@vm0 %v, want maybe", got)
	}
	o := revState(t, "full", true, "create sro-c@vm2#0", "settle", "ctrl-kill c", "delete sro-c@vm2#0", "settle")
	if o.Ctrl[PoolC].Att[1][VM2] != TriYes {
		t.Fatalf("orphan c-shared0@vm2 %v", o.Ctrl[PoolC].Att[1][VM2])
	}
	o = steps(t, o, "create sdax-c@vm2#0", "ctrl-start c", "ctrl-kill c")
	if got := o.Ctrl[PoolC].Att[1][VM2]; got != TriMaybe {
		t.Fatalf("c-shared0@vm2 %v, want maybe", got)
	}
}

// F8: the claim of a pod that was gone at the last settle may be
// deallocated a moment later: a claim created now may wait for that and
// race with a second one: one candidate per such device in the window.
func TestReviewF8ReleasedDevice(t *testing.T) {
	s := revState(t, "full", true, "create xnuma-c@vm1#0", "settle", "delete xnuma-c@vm1#0", "settle")
	s = steps(t, s, "create xnuma-c@vm1#0", "!create xdax-c@vm2#0", "settle")
	if s.Released != 0 {
		t.Fatalf("released %b after a settle without deletes", s.Released)
	}
}

// F9 (A19): a contender promoted when a bound holder goes, in a window
// in which (or before whose last settle) an unbound claim of the device
// was deleted, may stall.
func TestReviewF9PromotionAfterUnboundDelete(t *testing.T) {
	s := revState(t, "full", true, "create sdax-a@vm2#1", "settle", "ctrl-kill a", "create sro-a@vm2#0", "settle",
		"create sexcl-a@vm2#0", "settle")
	wantPhase(t, s, "sro-a@vm2#0", Attaching)
	wantPhase(t, s, "sexcl-a@vm2#0", Pending)
	n := steps(t, s, "delete sro-a@vm2#0", "delete sdax-a@vm2#1")
	wantPhase(t, n, "sexcl-a@vm2#0", Stalled)
	// held since the last settle, a later fit
	h := revState(t, "full", true, "create sdax-c@vm2#0", "settle", "create sro-c@vm0#0", "delete sro-c@vm0#0", "settle")
	h = steps(t, h, "delete sdax-c@vm2#0", "create sexcl-c@vm1#0")
	wantPhase(t, h, "sexcl-c@vm1#0", Stalled)
}

// F7, F10, F11 (A19): a stalled contender gets its region whenever the
// scheduler requeues it: no other region event on the stacks it may get
// it on (also when ctrl-start makes it for an "any" pod, and for the
// hosts of a stalled "any" pod), and no contender stalls into a window
// that has one.
func TestReviewF7F10F11StalledStacksQuiet(t *testing.T) {
	held := revState(t, "full", true, "create xdax-c@vm2#0", "delete xdax-c@vm2#0", "settle")
	steps(t, held, "create sro-c@vm2#0", "!create xdax-c@vm2#0")
	steps(t, held, "create xdax-c@vm2#0", "!create sro-c@vm2#0")
	a := steps(t, held, "create xdax-c@any#0", "settle")
	wantPhase(t, a, "xdax-c@any#0", Stalled)
	steps(t, a, "!create sdax-c@vm0#0", "create sdax-a@vm1#0")
	k := steps(t, held, "create xnuma-c@vm1#0", "settle", "ctrl-kill c", "create sdax-c@any#0")
	wantPhase(t, k, "xnuma-c@vm1#0", Stalled)
	steps(t, k, "!ctrl-start c")
}

// F12: a claim that waits for the attach with its controller down
// times out in PreBind (600 s): it is deallocated, and the waiter of its
// device may get it. Accepted from bindingExpiry after the first settle
// that saw it waiting.
func TestReviewF12BindingTimeout(t *testing.T) {
	s := revState(t, "full", true, "ctrl-kill a", "create xnuma-a@vm1#0", "settle", "create xdax-a@vm1#0", "settle")
	now := time.Unix(time.Now().Unix(), 0)
	v, adopted := checkStateAt(s, observation(t, s), "", now, defaultUnblock)
	wantVerdict(t, v, VOK, "ok")
	truth := adopted.clone()
	truth.Slots[truth.cfg.slotIndex("xnuma-a@vm1#0")].Phase = Pending
	truth.Slots[truth.cfg.slotIndex("xdax-a@vm1#0")].Phase = Attaching
	v, _ = checkStateAt(adopted, observation(t, truth), "", now.Add(100*time.Second), defaultUnblock)
	if v.Status == VOK {
		t.Fatalf("the swap accepted 100 s after")
	}
	v, swapped := checkStateAt(adopted, observation(t, truth), "", now.Add(bindingExpiry*time.Second), defaultUnblock)
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, swapped, "xnuma-a@vm1#0", Pending)
	wantPhase(t, swapped, "xdax-a@vm1#0", Attaching)
	// ctrl-start: no binding timeout any more
	n := steps(t, swapped, "ctrl-start a")
	if n.unblockAt(n.cfg.slotIndex("xdax-a@vm1#0")) != 0 {
		t.Fatalf("binding time kept after ctrl-start")
	}
}

// F13: a pool pod is bound only at PreBind's next poll after its claim
// is Attached (up to 5 s later): an unblocking pod seen without a node
// is not settled (its delete would be that of an unbound claim).
func TestReviewF13UnblockingNotBound(t *testing.T) {
	s := revState(t, "full", true,
		"create xnuma-a@vm2#0", "settle", "create sdax-a@vm2#0", "settle", // vm2/hb0 [a-pooled0,a-shared0]
		"delete xnuma-a@vm2#0", "settle", // [hole,a-shared0]
		"create xdax-a@vm2#0", "settle", // blocked
		"delete sdax-a@vm2#0", "settle") // unblocking
	wantPhase(t, s, "xdax-a@vm2#0", Unblocking)
	o := observation(t, s)
	podOf(t, o, "xdax-a@vm2#0").Node = nil
	v, _ := checkState(s, o, "")
	wantVerdict(t, v, VWait, "xdax-a@vm2#0: not bound yet")
}

// M6 (run L5 step 26): crash lease@vm2#0, then containerd-restart vm2
// while kubelet re-created its container: "Failed: Error: error reading
// from server: EOF", kubelet created it again: 2 restarts for one
// crash. A containerd restart, like a kubelet restart (M2), allows one
// more restart of every container of the VM being created or started
// (starting, restarting, unblocking pods), adopted from the observation.
func TestReviewM6ContainerdRestartSlack(t *testing.T) {
	s := revState(t, "full", true, "create lease@vm2#0", "create sdax-a@vm2#0", "settle", "lease-get lease@vm2#0 numa",
		"crash lease@vm2#0", "write sdax-a@vm2#0", "create lnuma@vm2#1", "create plain@vm1#0", "containerd-restart vm2", "settle")
	if ss := slotOf(t, s, "lease@vm2#0"); ss.Restarts != 1 || ss.Slack != 1 {
		t.Fatalf("lease@vm2#0 %+v", ss)
	}
	if slotOf(t, s, "lnuma@vm2#1").Slack != 1 || slotOf(t, s, "sdax-a@vm2#0").Slack != 0 || slotOf(t, s, "plain@vm1#0").Slack != 0 {
		t.Fatalf("slack: lnuma %d sdax %d plain@vm1 %d", slotOf(t, s, "lnuma@vm2#1").Slack, slotOf(t, s, "sdax-a@vm2#0").Slack, slotOf(t, s, "plain@vm1#0").Slack)
	}
	for _, c := range []struct {
		restarts int
		status   VStatus
		msg      string
	}{{1, VOK, "ok"}, {2, VOK, "ok"}, {3, VFail, "3 restarts, the model crashed it 1 times (+1 for kubelet or containerd restarts"}} {
		o := observation(t, s)
		podOf(t, o, "lease@vm2#0").Restarts = c.restarts
		for k := range o.Inspect {
			delete(o.Inspect, k)
		}
		v, adopted := checkState(s, o, "")
		wantVerdict(t, v, c.status, c.msg)
		if c.status == VOK {
			if ss := slotOf(t, adopted, "lease@vm2#0"); int(ss.Restarts) != c.restarts || ss.Slack != 0 {
				t.Fatalf("adopted %+v", ss)
			}
		}
	}
	// the run's own observation of step 26 (L5): ok now
	cfg := testConfig(t, "full", true)
	cfg.Unsettled = 3
	st := replaySteps(t, cfg, "recorded/l5-mbt-steps.txt", 25)
	js, err := os.ReadFile("recorded/l5-fail-26.json")
	if err != nil {
		t.Fatal(err)
	}
	o, err := parseObservation(js)
	if err != nil {
		t.Fatal(err)
	}
	v, adopted := checkState(steps(t, st, "settle"), o, "")
	wantVerdict(t, v, VOK, "ok")
	if ss := slotOf(t, adopted, "lease@vm2#0"); ss.Restarts != 2 || ss.Slack != 0 {
		t.Fatalf("adopted %+v", ss)
	}
}

// M7 (run L7 step 1529): an lsteer pod unblocking (blocked by a decoder
// hole before) when its VM's driver restarts: its container is created
// while the driver is away, the new driver's Synchronize sees it CREATED
// and manages it fenced, memory.high max ("steering not restarted, memory
// fenced", the bug-04 rule), or it comes after the restart: steered.
// Either is accepted and adopted; off stays off until its container
// restarts under a running driver.
func TestReviewM7SteeringOfUnblockingPod(t *testing.T) {
	s := revState(t, "full", true,
		"create xnuma-a@vm2#0", "settle", "create sdax-a@vm2#0", "settle", // vm2/hb0 [a-pooled0,a-shared0]
		"delete xnuma-a@vm2#0", "settle", // [hole,a-shared0]
		"create lsteer@vm2#0", "settle", // blocked
		"delete sdax-a@vm2#0", "settle") // unblocking
	wantPhase(t, s, "lsteer@vm2#0", Unblocking)
	for _, verb := range []string{"driver-restart vm2", "driver-kill vm2", "containerd-restart vm2"} {
		n := steps(t, s, verb, "settle")
		if st := slotOf(t, n, "lsteer@vm2#0").Steer; st != SteerAny {
			t.Fatalf("%s: steering %s, want either", verb, st)
		}
		for _, steer := range []Steer{SteerOff, SteerOn} {
			truth := n.clone()
			ss := &truth.Slots[truth.cfg.slotIndex("lsteer@vm2#0")]
			ss.Phase, ss.Steer = Running, steer
			truth.setUnblockAt(truth.cfg.slotIndex("lsteer@vm2#0"), 0)
			truth.Stacks[stackIndex(VM2, HB0)].push(rkLocal)
			truth.growFence()
			v, adopted := checkState(n, observation(t, truth), "")
			wantVerdict(t, v, VOK, "ok")
			got := slotOf(t, adopted, "lsteer@vm2#0")
			if got.Phase != Running || got.Steer != steer {
				t.Fatalf("%s: adopted %s steer %s, want running %s", verb, got.Phase, got.Steer, steer)
			}
			if steer == SteerOff {
				// off stays off; a crash under a running driver
				// steers it again
				if st := steps(t, adopted, "create plain@vm2#0", "settle"); slotOf(t, st, "lsteer@vm2#0").Steer != SteerOff {
					t.Fatalf("off not kept")
				}
				if st := steps(t, adopted, "crash lsteer@vm2#0", "settle"); slotOf(t, st, "lsteer@vm2#0").Steer != SteerOn {
					t.Fatalf("not steered after a crash")
				}
			}
		}
	}
	// the run's own observation of step 1529 (L7): ok now, adopted off
	cfg := testConfig(t, "full", true)
	cfg.Unsettled = 3
	st := replaySteps(t, cfg, "recorded/l7-mbt-steps.txt", 1528)
	js, err := os.ReadFile("recorded/l7-fail-1529.json")
	if err != nil {
		t.Fatal(err)
	}
	o, err := parseObservation(js)
	if err != nil {
		t.Fatal(err)
	}
	v, adopted := checkState(steps(t, st, "settle"), o, "")
	wantVerdict(t, v, VOK, "ok")
	if got := slotOf(t, adopted, "lsteer@vm2#0"); got.Phase != Running || got.Steer != SteerOff {
		t.Fatalf("adopted %s steer %s", got.Phase, got.Steer)
	}
}

// simSteps drives the simulated SUT of seed through action lines as
// expRun does (the model's state adopted from every check), each line
// enabled in the model's state, with a clock that advances dt per
// action. It returns the first step whose check is not ok ("" if none),
// the model's and the simulator's states.
func simSteps(t *testing.T, cfg *Config, seed int64, dt time.Duration, lines ...string) (string, *State, *sim) {
	t.Helper()
	s := newSim(cfg, seed)
	st := newState(cfg)
	now := time.Unix(1800000000, 0)
	for j, line := range lines {
		n := j + 1
		a := mustAct(t, cfg, line)
		if !st.enabled(a) {
			t.Fatalf("seed %d step %d %q: not enabled in\n%s", seed, n, line, st.dump())
		}
		now = now.Add(dt)
		next := st.apply(a)
		if a.Verb == VSettle {
			s.do(n, a)
			v, adopted := checkStateAt(next, s.observe(n, 1), "", now, defaultUnblock)
			if v.Status != VOK {
				return fmt.Sprintf("step %d %s: %s", n, line, v.Msg), st, s
			}
			st = adopted
			continue
		}
		d := s.do(n, a)
		if v := checkDone(expectDone(st, next, a, n), d); v.Status != VOK {
			return fmt.Sprintf("step %d %s: %s", n, line, v.Msg), st, s
		}
		st = adoptDone(next, a, d)
	}
	return "", st, s
}

// M8 (20-mbtopt, seed 1 growth run, step 330): the simulated SUT kept the
// scheduler's hold of b-shared0 (sro-b's claim deleted before its pod was
// bound, A19) for ever, while the oracle ends it 6 s after the settle:
// sro-b created again long after was Starting in the model (its Prepare
// through vm0/hb0 [hole,local]: Blocked) and Stalled in the simulator,
// which then promoted it Running with its region pushed above the hole.
// The real hold ends within 5 s of the delete (bug-08); a promoted
// contender's Prepare through a hole is refused like any other (A9).
// Both are the simulator's errors; the model was right.
func TestReviewM8SimHoldAndHole(t *testing.T) {
	cfg := testConfig(t, "full", true)
	hole := []string{
		"create xnuma-b@vm0#0", "settle", "create lnuma@vm0#0", "settle", // vm0/hb0 [b-pooled0,local]
		"delete xnuma-b@vm0#0", "settle", // [hole,local]
	}
	held := []string{
		"ctrl-kill b", "create sro-b@vm0#0", "settle", // waits for the attach
		"delete sro-b@vm0#0", "ctrl-start b", "settle", // b-shared0 held
	}
	// the M8 sequence in short: the hold ends, sro-b blocked by the
	// hole, in the model and in every simulated SUT
	m8 := append(append(append([]string{}, hole...), held...), "create plain@vm0#0", "settle", "create sro-b@vm0#0", "settle")
	for seed := int64(1); seed <= 16; seed++ {
		msg, st, s := simSteps(t, cfg, seed, 4*time.Second, m8...)
		if msg != "" {
			t.Fatalf("seed %d: %s\nsimulated:\n%s", seed, msg, s.truth.dump())
		}
		wantPhase(t, st, "sro-b@vm0#0", Blocked)
		wantPhase(t, s.truth, "sro-b@vm0#0", Blocked)
		wantStack(t, s.truth, stackIndex(VM0, HB0), "[hole,local]")
		if s.truth.held(Res(sharedDev(PoolB))) {
			t.Fatalf("seed %d: the simulator still holds b-shared0", seed)
		}
	}
	// still held in the window after the settle: a contender created
	// then stalls in the model; the simulator may hold it as long (it
	// promotes it or not), and never beyond the oracle
	pre := append(append([]string{}, hole...), held...)
	for seed := int64(1); seed <= 16; seed++ {
		msg, st, s := simSteps(t, cfg, seed, time.Second, append(append([]string{}, pre...), "create sro-b@vm0#0", "settle", "create plain@vm0#0", "settle")...)
		if msg != "" {
			t.Fatalf("seed %d: %s\nsimulated:\n%s", seed, msg, s.truth.dump())
		}
		if ph := slotOf(t, st, "sro-b@vm0#0").Phase; ph != Stalled && ph != Blocked {
			t.Fatalf("seed %d: sro-b %s, want stalled or blocked (promoted through the hole)", seed, ph)
		}
	}
	// a contender stalled behind an unbound holder in its window,
	// promoted by the simulator: blocked by the hole, never Running
	promoted := 0
	for seed := int64(1); seed <= 16; seed++ {
		msg, st, s := simSteps(t, cfg, seed, 4*time.Second, append(append([]string{}, hole...),
			"ctrl-kill b", "create xdax-b@vm0#0", "settle", "create xnuma-b@vm0#0", "settle", // a waiter of b-pooled0
			"delete xdax-b@vm0#0", "ctrl-start b", "settle")...) // stalled
		if msg != "" {
			t.Fatalf("seed %d: %s\nsimulated:\n%s", seed, msg, s.truth.dump())
		}
		switch ph := slotOf(t, s.truth, "xnuma-b@vm0#0").Phase; ph {
		case Blocked:
			promoted++
			wantPhase(t, st, "xnuma-b@vm0#0", Blocked)
		case Stalled:
		default:
			t.Fatalf("seed %d: simulated xnuma-b %s through vm0/hb0 %s", seed, ph, s.truth.Stacks[stackIndex(VM0, HB0)])
		}
	}
	if promoted == 0 {
		t.Fatalf("no seed promoted the stalled contender")
	}
	// an "any" contender promoted by the simulator: its region on the
	// stack of the host it was bound to
	promoted = 0
	for seed := int64(1); seed <= 16; seed++ {
		msg, st, s := simSteps(t, cfg, seed, 4*time.Second, "ctrl-kill c", "create xnuma-c@vm1#0", "settle", "create xdax-c@any#0", "settle",
			"delete xnuma-c@vm1#0", "ctrl-start c", "settle")
		if msg != "" {
			t.Fatalf("seed %d: %s\nsimulated:\n%s", seed, msg, s.truth.dump())
		}
		if ss := slotOf(t, s.truth, "xdax-c@any#0"); ss.Phase == Running {
			promoted++
			wantStack(t, s.truth, stackIndex(ss.Node, HB1), "[c-pooled0]")
			if got := slotOf(t, st, "xdax-c@any#0"); got.Phase != Running || got.Node != ss.Node {
				t.Fatalf("seed %d: adopted %s on %s", seed, got.Phase, got.Node)
			}
		}
	}
	if promoted == 0 {
		t.Fatalf("no seed promoted the stalled any contender")
	}
}

// M8: the seed 1 growth run itself (experiment --steps-out), replayed
// with experiment --from's code and its recorded oracle clock: the
// settle of step 330 failed with the simulator's never-ending hold.
func TestReviewM8RecordedRun(t *testing.T) {
	data, err := os.ReadFile("recorded/m8-mbt-steps.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines, _ := readSteps(string(data))
	cfg := testConfig(t, "full", true)
	cfg.Unsettled = 3
	cov, err := parseCoverage(defaultCoverage)
	if err != nil {
		t.Fatal(err)
	}
	o := runOpts{cfg: cfg, cov: cov, depth: 1, seed: 1, randomness: 1, replayNow: readNow(string(data))}
	for _, l := range lines {
		o.replay = append(o.replay, l.Action)
	}
	if len(o.replay) != 330 || len(o.replayNow) != 72 {
		t.Fatalf("%d steps, %d clock records", len(o.replay), len(o.replayNow))
	}
	r, err := expRun(o, len(o.replay), planBudget{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.failures) > 0 || r.steps != 330 {
		t.Fatalf("after %d steps: %v", r.steps, r.failures)
	}
}

// M9 (20-mbtopt, depth-2 soak after the M8 fix, seeds 3 9 15 16 30): a
// numa contender stalled by the scheduler's hold of its device (A19) may
// be promoted at any time, and its Prepare onlines the device as system
// RAM: the bytes are gone. The model kept them known (only start set
// them unknown), the simulator, whose hold had ended, started the
// contender and lost them; a later read of the device saw junk.
func TestReviewM9StalledNumaData(t *testing.T) {
	cfg := testConfig(t, "full", true)
	held := []string{
		"create xdax-c@vm2#0", "settle", "write xdax-c@vm2#0", "delete xdax-c@vm2#0", "settle", // c-pooled0 "mbt-3"
		"ctrl-kill c", "create xdax-c@vm2#0", "settle", "delete xdax-c@vm2#0", "ctrl-start c", "settle", // held
	}
	s := revState(t, "full", true, held...)
	if !s.held(Res(pooledDev(PoolC))) || s.Data[pooledDev(PoolC)] != (Token{Known: true, Text: "mbt-3"}) {
		t.Fatalf("held %v, data %s", s.held(Res(pooledDev(PoolC))), s.Data[pooledDev(PoolC)])
	}
	s = steps(t, s, "create xnuma-c@vm1#0")
	wantPhase(t, s, "xnuma-c@vm1#0", Stalled)
	if s.Data[pooledDev(PoolC)].Known {
		t.Fatalf("data of c-pooled0 %s with a stalled numa contender, want unknown", s.Data[pooledDev(PoolC)])
	}
	// the run: the simulator's hold ends a window earlier than the
	// model's, the contender starts there; the read is accepted
	for seed := int64(1); seed <= 16; seed++ {
		msg, _, sm := simSteps(t, cfg, seed, time.Second, append(append([]string{}, held...),
			"create plain@vm0#0", "settle", "create xnuma-c@vm1#0", "settle",
			"delete xnuma-c@vm1#0", "settle", "create xdax-c@vm2#0", "settle", "read xdax-c@vm2#0")...)
		if msg != "" {
			t.Fatalf("seed %d: %s\nsimulated:\n%s", seed, msg, sm.truth.dump())
		}
	}
}

// M9 (seeds 2 and 26): a contender stalled only by the scheduler's hold
// (it fits now) may be allocated at once (the hold is 0-5 s after the
// delete), so its Prepare races with the release of another share of
// its device on its node: before it the region stays (above a hole),
// after it the region is destroyed and made again on top, or blocked by
// a hole. The oracle adopts a promotion after every event of the window
// only. Such a window is not generated (A21); a contender that waits for
// the releases of its device still may have them in its window.
func TestReviewM9StalledShareRace(t *testing.T) {
	s := revState(t, "full", true,
		"create xnuma-b@vm0#0", "settle", "create sro-b@vm0#0", "settle", // vm0/hb0 [b-pooled0,b-shared0]
		"delete xnuma-b@vm0#0", "settle", // [hole,b-shared0]
		"ctrl-kill b", "create sdax-b@vm0#1", "settle", "delete sdax-b@vm0#1", "ctrl-start b", "settle") // b-shared0 held
	wantStack(t, s, stackIndex(VM0, HB0), "[hole,b-shared0]")
	if !s.held(Res(sharedDev(PoolB))) {
		t.Fatalf("b-shared0 not held")
	}
	// the release first, then the contender: refused (it was enabled)
	steps(t, s, "delete sro-b@vm0#0", "!create sdax-b@vm0#0", "create plain@vm0#0")
	// the contender first, then the release: refused as before (its
	// stack has a pod that waits for the scheduler)
	n := steps(t, s, "create sdax-b@vm0#0", "!delete sro-b@vm0#0")
	wantPhase(t, n, "sdax-b@vm0#0", Stalled)
	// a waiter of an exclusive device behind a holder deleted before its
	// pod was bound: the holder's events are what it waits for
	w := revState(t, "full", true, "ctrl-kill b", "create xnuma-b@vm0#0", "settle", "create xdax-b@vm0#0", "settle")
	w = steps(t, w, "ctrl-start b", "delete xnuma-b@vm0#0")
	wantPhase(t, w, "xdax-b@vm0#0", Stalled)
}

// M9 (seed 33): a waiter promoted while its pool's controller is down
// prepares at ctrl-start. Its claim was allocated after the released
// claim's Unprepare (the controller only delayed the attach), so its
// prepare is a handover (R1) also then: an sexcl after the last share of
// the device on its node, through the hole that share's release leaves.
// The model let it come first and share the departing share's region.
func TestReviewM9HandoverAtCtrlStart(t *testing.T) {
	s := revState(t, "full", true,
		"create sdax-a@vm2#0", "settle", "create lnuma@vm2#0", "settle", // vm2/hb0 [a-shared0,local]
		"create sexcl-a@vm2#0", "settle", // waits for the share
		"ctrl-kill a", "delete sdax-a@vm2#0", "ctrl-start a", "settle")
	for _, a := range alts(s) {
		wantPhase(t, a, "sexcl-a@vm2#0", Blocked)
		wantStack(t, a, stackIndex(VM2, HB0), "[hole,local]")
	}
	// a share that fits now waits for no release: either order
	s = revState(t, "full", true,
		"create sdax-a@vm2#0", "settle", "create lnuma@vm2#0", "settle",
		"ctrl-kill a", "delete sdax-a@vm2#0", "create sro-a@vm2#0", "ctrl-start a", "settle")
	var got []string
	for _, a := range alts(s) {
		got = append(got, slotOf(t, a, "sro-a@vm2#0").Phase.String()+" "+a.Stacks[stackIndex(VM2, HB0)].String())
	}
	if strings.Join(got, "; ") != "blocked [hole,local]; running [a-shared0,local]" {
		t.Fatalf("outcomes %v", got)
	}
}
