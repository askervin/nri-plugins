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
	}{{0, VOK, "ok"}, {1, VOK, "ok"}, {2, VFail, "2 restarts, the model crashed it 0 times (+1 for kubelet restarts"}} {
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
