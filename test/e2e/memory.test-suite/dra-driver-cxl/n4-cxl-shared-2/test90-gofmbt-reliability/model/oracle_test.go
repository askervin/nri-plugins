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
	"encoding/json"
	"strings"
	"testing"
)

// richState is a settled state with something of every kind on vm0, vm1
// and vm2.
func richState(t *testing.T, online bool) *State {
	t.Helper()
	cfg := testConfig(t, "full", online)
	s := newState(cfg)
	return steps(t, s,
		"create xnuma-a@vm1#0", "create xdax-a@vm2#0", "create sdax-c@vm0#0", "create sdax-c@vm2#0",
		"create sro-c@vm2#0", "create lnuma@vm0#0", "create ldax@vm0#0", "create lnuma@vm0#1",
		"create lsteer@vm2#0", "create lease@vm1#0", "create plain@vm0#0", "create xnuma-c@vm1#0",
		"settle", "lease-get lease@vm1#0 numa", "settle")
}

// observation returns the observation of a simulated SUT in state s (a
// copy that a test may change).
func observation(t *testing.T, s *State) *Observation {
	t.Helper()
	sm := newSim(s.cfg, 1)
	sm.truth = sm.resolve(s)
	o := sm.observe(int(s.Steps), 1)
	js, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseObservation(js)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func podOf(t *testing.T, o *Observation, slot string) *ObsPod {
	t.Helper()
	for j := range o.Pods {
		if o.Pods[j].Slot == slot {
			return &o.Pods[j]
		}
	}
	t.Fatalf("no pod of %s", slot)
	return nil
}

func ctrOf(t *testing.T, o *Observation, vm, podPrefix string) *ObsContainer {
	t.Helper()
	for j := range o.VMs[vm].Containers {
		if strings.HasPrefix(o.VMs[vm].Containers[j].Pod, podPrefix) {
			return &o.VMs[vm].Containers[j]
		}
	}
	t.Fatalf("no container of %s on %s", podPrefix, vm)
	return nil
}

func wantVerdict(t *testing.T, v Verdict, status VStatus, substr string) {
	t.Helper()
	if v.Status != status || !strings.Contains(v.Msg, substr) {
		t.Fatalf("verdict %s %q, want %s with %q; diffs:\n  %s", v.Status, v.Msg, status, substr, strings.Join(v.Diffs, "\n  "))
	}
}

func TestOracleStable(t *testing.T) {
	s := richState(t, false)
	v, _ := checkState(s, observation(t, s), "")
	wantVerdict(t, v, VOK, "ok")
	// and through the JSON expectation, as `check` does
	e := s.expect(int(s.Steps), "settle")
	js, _ := json.Marshal(e)
	e2 := &Expectation{}
	if err := json.Unmarshal(js, e2); err != nil {
		t.Fatal(err)
	}
	wantVerdict(t, checkSettle(e2, observation(t, s)), VOK, "ok")
}

func TestOracleDeviations(t *testing.T) {
	s := richState(t, false)
	str := func(x string) *string { return &x }
	cases := []struct {
		name   string
		change func(o *Observation)
		status VStatus
		msg    string
	}{
		// O1
		{"pod not running yet", func(o *Observation) {
			p := podOf(t, o, "lnuma@vm0#0")
			p.Phase, p.Ready, p.Waiting = "Pending", false, str("ContainerCreating")
		}, VWait, "lnuma@vm0#0: phase Pending ready false (ContainerCreating)"},
		{"restart not seen yet", func(o *Observation) {}, VOK, "ok"},
		{"restarts above the model", func(o *Observation) { podOf(t, o, "plain@vm0#0").Restarts = 1 }, VFail, "1 restarts, the model crashed it 0 times"},
		{"pod failed", func(o *Observation) { podOf(t, o, "plain@vm0#0").Phase = "Failed" }, VFail, "phase Failed"},
		{"pod on another node", func(o *Observation) { podOf(t, o, "sdax-c@vm2#0").Node = str("vm1") }, VFail, "on vm1, want vm2"},
		{"pod of an unknown slot", func(o *Observation) {
			o.Pods = append(o.Pods, ObsPod{Slot: "bogus_vm0_0", Name: "x", Phase: "Running"})
		}, VFail, "unknown slot"},
		{"pod of a newer generation", func(o *Observation) { podOf(t, o, "plain@vm0#0").Gen = 2 }, VFail, "generation 2"},
		{"old pod terminating", func(o *Observation) {
			o.Pods = append(o.Pods, ObsPod{Slot: "plain@vm0#0", Name: "old", Gen: 0, Phase: "Running", Deleting: true})
		}, VWait, "old generation still terminating"},
		{"old pod not deleted", func(o *Observation) {
			o.Pods = append(o.Pods, ObsPod{Slot: "plain@vm0#0", Name: "old", Gen: 0, Phase: "Running"})
		}, VFail, "is not being deleted"},
		{"pod of a slot that was never created", func(o *Observation) {
			o.Pods = append(o.Pods, ObsPod{Slot: "plain@vm1#0", Name: "x", Gen: 1, Phase: "Running"})
		}, VFail, "generation 1 of slot plain@vm1#0, the model created 0"},
		{"pending pod running", func(o *Observation) {
			p := podOf(t, o, "lnuma@vm0#1")
			p.Phase, p.Ready, p.Node = "Running", true, str("vm0")
		}, VFail, "want Pending"},
		{"pending pod not yet unschedulable", func(o *Observation) { podOf(t, o, "lnuma@vm0#1").Unschedulable = false }, VWait, "not unschedulable"},
		{"claim not attached", func(o *Observation) {
			f := false
			podOf(t, o, "sdax-c@vm0#0").Claim.Attached = &f
		}, VWait, "claim not Attached"},
		{"other pods", func(o *Observation) { o.Others = []string{"intruder"} }, VWait, "other pods: intruder"},
		// companions
		{"no companion", func(o *Observation) { o.Companions = nil }, VWait, "no companion"},
		{"companion elsewhere", func(o *Observation) { o.Companions[0].Node = "vm0" }, VFail, "on vm0, want vm1"},
		// O2
		{"attachment missing", func(o *Observation) {
			o.Attachments["a"] = o.Attachments["a"][1:]
		}, VWait, "attachment a-pooled0@vm1: missing"},
		{"attachment extra", func(o *Observation) {
			o.Attachments["b"] = append(o.Attachments["b"], ObsAttachment{Device: "b-pooled0", Host: "vm0", State: "attached"})
		}, VWait, "b-pooled0@vm0: attached, no claim wants it"},
		{"attachment detaching", func(o *Observation) {
			o.Attachments["b"] = append(o.Attachments["b"], ObsAttachment{Device: "b-pooled0", Host: "vm0", State: "detaching"})
		}, VWait, "detaching"},
		{"attachment adopted", func(o *Observation) { o.Attachments["c"][0].Adopted = true }, VFail, "adopted"},
		{"setup attachment adopted", func(o *Observation) {
			for j := range o.Attachments["a"] {
				if o.Attachments["a"][j].Owner == "e2e:dra-local-device" {
					o.Attachments["a"][j].Adopted = true
				}
			}
		}, VFail, "adopted (owner \"e2e:dra-local-device\")"},
		{"setup attachment ignored (A3)", func(o *Observation) {
			o.Attachments["b"] = append(o.Attachments["b"], ObsAttachment{Device: "b-pooled0", Host: "vm0", State: "failed", Owner: "e2e:other"})
		}, VOK, "ok"},
		{"attachment failed", func(o *Observation) { o.Attachments["c"][0].State = "failed" }, VFail, "failed"},
		{"attachment exclusive", func(o *Observation) {
			for j := range o.Attachments["c"] {
				o.Attachments["c"][j].Exclusive = true
			}
		}, VWait, "exclusive true, want false"},
		// O3
		{"region missing", func(o *Observation) { o.VMs["vm1"].Regions = o.VMs["vm1"].Regions[1:] }, VWait, "vm1: no region of"},
		{"region leaked", func(o *Observation) {
			o.VMs["vm0"].Regions = append(o.VMs["vm0"].Regions, ObsRegion{Name: "region77", Serials: []string{"0xc1ee1001"}})
		}, VWait, "region region77 of b-pooled0, no claim of it is prepared here"},
		{"local slices", func(o *Observation) {
			r := &o.VMs["vm0"].Regions[len(o.VMs["vm0"].Regions)-1]
			r.Dax = r.Dax[:len(r.Dax)-1]
		}, VWait, "local region region9: 1 numa and 0 dax slices (0 others), want 1 and 1"},
		{"memtotal", func(o *Observation) { o.VMs["vm0"].Nodes["2"] = ObsNode{MemTotal: 0} }, VWait, "vm0: node 2 MemTotal 0"},
		{"memdev not detached", func(o *Observation) {
			o.VMs["vm0"].Memdevs = append(o.VMs["vm0"].Memdevs, ObsMemdev{Name: "mem9", Serial: "0xc1ee1001"})
		}, VWait, "memdev of b-pooled0 present"},
		{"pool region numa node", func(o *Observation) {
			n := 2
			for j := range o.VMs["vm1"].Regions {
				if o.VMs["vm1"].Regions[j].Serials[0] == "0xc1ee2001" {
					o.VMs["vm1"].Regions[j].Node = &n
				}
			}
		}, VWait, "on node 2, want 3 (--node-hb1)"},
		// O4
		{"prepared != info", func(o *Observation) { o.VMs["vm0"].State.Info = nil }, VWait, "preparedClaims.json"},
		{"pool claims", func(o *Observation) { o.VMs["vm1"].State.Pool = nil }, VWait, "preparedPoolClaims.json"},
		{"orphan slices", func(o *Observation) {
			o.VMs["vm0"].State.LocalDevices.Devices[0].Claims["-"] = json.RawMessage(`[{}]`)
		}, VWait, "orphan slices"},
		{"cdi", func(o *Observation) { o.VMs["vm2"].CDI["/etc/cdi/cxl-pool.yaml"] = nil }, VWait, "cxl-pool.yaml"},
		{"state unreadable", func(o *Observation) {
			o.VMs["vm2"].State = nil
			o.VMs["vm2"].Errors = []string{"state: permission denied"}
		}, VWait, "vm2: state: permission denied"},
		// O5
		{"fenced node visible", func(o *Observation) {
			c := ctrOf(t, o, "vm0", "mbt-plain")
			c.MemsEffective = "0-2"
		}, VWait, "has fenced CXL node 2"},
		{"numa claimer without its node", func(o *Observation) {
			ctrOf(t, o, "vm1", "mbt-xnuma-c").MemsEffective = "0-1"
		}, VWait, "lacks its node 3"},
		{"lease node not lent", func(o *Observation) {
			ctrOf(t, o, "vm1", "mbt-lease").MemsEffective = "0-1"
		}, VWait, "lacks its node 2"},
		{"companion has the lent node", func(o *Observation) {
			ctrOf(t, o, "vm1", "cxl-lease").MemsEffective = "0-2"
		}, VWait, "has fenced CXL node 2"},
		{"steered without memory.high", func(o *Observation) {
			ctrOf(t, o, "vm2", "mbt-lsteer").MemoryHigh = "max"
		}, VWait, "want set (steered)"},
		{"unsteered with memory.high", func(o *Observation) {
			ctrOf(t, o, "vm0", "mbt-lnuma").MemoryHigh = "100000"
		}, VWait, "want max"},
		// O6
		{"env value", func(o *Observation) { o.Inspect["xnuma-a@vm1#0"].Env["CXL_C1EE0001_NODE"] = "3" }, VFail, "CXL_C1EE0001_NODE=3, want 2"},
		{"env missing", func(o *Observation) { delete(o.Inspect["ldax@vm0#0"].Env, "CXL_C100E2E1_DAX") }, VFail, "CXL_C100E2E1_DAX missing"},
		{"env extra", func(o *Observation) { o.Inspect["plain@vm0#0"].Env["CXL_C100E2E1_MODE"] = "numa" }, VFail, "unexpected CXL_C100E2E1_MODE"},
		{"env read-only", func(o *Observation) { o.Inspect["sro-c@vm2#0"].Env["CXL_C1AE2001_READONLY"] = "0" }, VFail, "READONLY=0, want 1"},
		{"env of an old pod", func(o *Observation) {
			o.Inspect["sro-c@vm2#0"].UID = "old"
			o.Inspect["sro-c@vm2#0"].Env = nil
		}, VOK, "ok"},
		{"lease list", func(o *Observation) { o.Inspect["lease@vm1#0"].Leases = json.RawMessage(`[]`) }, VFail, "0 leases listed, want 1"},
		// O8
		{"driver not ready", func(o *Observation) { o.Drivers["vm1"].Ready = false }, VWait, "driver vm1"},
		{"driver restarts", func(o *Observation) { o.Drivers["vm1"].Restarts = 1 }, VWait, "1 restarts, want 0"},
		{"controller", func(o *Observation) { o.Controllers["b"] = "failed" }, VWait, "controller b: failed, want active"},
		{"observation errors", func(o *Observation) { o.Errors = []string{"attachments of pool c: timeout"} }, VWait, "observation: attachments"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := observation(t, s)
			c.change(o)
			v, _ := checkState(s, o, "")
			wantVerdict(t, v, c.status, c.msg)
		})
	}
}

func TestOracleAbsent(t *testing.T) {
	s := richState(t, false)
	s = steps(t, s, "delete plain@vm0#0", "settle")
	o := observation(t, s)
	o.Pods = append(o.Pods, ObsPod{Slot: "plain@vm0#0", Name: "mbt-plain-vm0-0-g1", Gen: 1, Phase: "Running", Deleting: true})
	v, _ := checkState(s, o, "")
	wantVerdict(t, v, VWait, "still being deleted")
	// a terminal phase while deleting is normal (A7)
	for _, ph := range []string{"Succeeded", "Failed"} {
		o.Pods[len(o.Pods)-1].Phase = ph
		v, _ = checkState(s, o, "")
		wantVerdict(t, v, VWait, "still being deleted")
	}
	o.Pods[len(o.Pods)-1].Phase = "Running"
	o.Pods[len(o.Pods)-1].Deleting = false
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VFail, "exists, want none")
}

func TestOracleResolve(t *testing.T) {
	cfg := testConfig(t, "full", true)
	s := newState(cfg)
	s = steps(t, s, "create sdax-c@any#0", "create lsteer@vm1#0", "!ctrl-kill c")
	pre := steps(t, s, "settle")
	s = pre
	// adopt the node of the any slot
	sm0 := newSim(cfg, 3)
	sm0.truth = sm0.resolve(s)
	v, s := checkState(s, sm0.observe(int(s.Steps), 1), "")
	wantVerdict(t, v, VOK, "ok")
	if slotOf(t, s, "sdax-c@any#0").Node == VMAny {
		t.Fatalf("node not adopted")
	}
	s = steps(t, s, "create xnuma-c@vm1#0", "ctrl-kill c", "crash lsteer@vm1#0", "driver-kill vm1", "settle")
	var phases []Phase
	for _, a := range alts(s) {
		phases = append(phases, slotOf(t, a, "xnuma-c@vm1#0").Phase)
	}
	if len(phases) < 2 || phases[0] != Running || phases[1] != Attaching {
		t.Fatalf("outcomes %v", phases)
	}
	if slotOf(t, s, "lsteer@vm1#0").Steer != SteerAny {
		t.Fatalf("steer")
	}
	for seed := int64(1); seed <= 8; seed++ {
		sm := newSim(cfg, seed)
		sm.truth = sm.resolve(s)
		o := sm.observe(int(s.Steps), 1)
		v, adopted := checkState(s, o, "")
		wantVerdict(t, v, VOK, "ok")
		// the adopted state predicts what the SUT does
		if got, want := adopted.dump(), sm.truth.dump(); got != want {
			t.Fatalf("seed %d: adopted\n%s\nthe SUT\n%s", seed, got, want)
		}
	}
	// an "any" pod on a node that is no host of its pool
	sm := newSim(cfg, 1)
	sm.truth = sm.resolve(pre)
	o := sm.observe(int(pre.Steps), 1)
	bad := "vm7"
	podOf(t, o, "sdax-c@any#0").Node = &bad
	v, _ = checkState(pre, o, "")
	wantVerdict(t, v, VFail, "pod sdax-c@any#0: on vm7")
	// not scheduled yet
	o = sm.observe(int(pre.Steps), 1)
	p := podOf(t, o, "sdax-c@any#0")
	p.Node, p.Phase, p.Ready = nil, "Pending", false
	v, _ = checkState(pre, o, "")
	wantVerdict(t, v, VWait, "sdax-c@any#0")
	// an Either pod whose claim got Attached: on its way to Running
	sm = newSim(cfg, 1)
	sm.truth = sm.resolve(s)
	o = sm.observe(int(s.Steps), 1)
	p = podOf(t, o, "xnuma-c@vm1#0")
	if p.Phase == "Pending" {
		tr := true
		p.Claim.Attached = &tr
		v, _ = checkState(s, o, "")
		wantVerdict(t, v, VWait, "xnuma-c@vm1#0")
	}
}

func TestOracleDriverPod(t *testing.T) {
	cfg := testConfig(t, "small", true)
	s := newState(cfg)
	s = steps(t, s, "create plain@vm0#0", "settle")
	sm := newSim(cfg, 1)
	sm.truth = sm.resolve(s)
	v, adopted := checkState(s, sm.observe(2, 1), "")
	wantVerdict(t, v, VOK, "ok")
	if adopted.Drv[VM0].Pod == "" {
		t.Fatalf("driver pod not learnt")
	}
	s = steps(t, adopted, "driver-restart vm0", "settle")
	o := sm.observe(4, 1) // the sim still shows the old pod
	v, _ = checkState(s, o, "")
	wantVerdict(t, v, VWait, "still pod nri-dra-driver-cxl-vm0-0, want a new one")
}

func TestCheckDone(t *testing.T) {
	cfg := testConfig(t, "full", false)
	s := steps(t, newState(cfg), "create sdax-a@vm1#0", "create sro-a@vm2#0", "settle", "write sdax-a@vm1#0")
	str := func(x string) *string { return &x }
	cases := []struct {
		act    string
		done   DoneObs
		status VStatus
		msg    string
	}{
		{"read sro-a@vm2#0", DoneObs{Text: str("mbt-4")}, VOK, "ok"},
		{"read sro-a@vm2#0", DoneObs{Text: str("mbt-3")}, VFail, `read "mbt-3", want "mbt-4"`},
		{"read sro-a@vm2#0", DoneObs{}, VFail, "no text"},
		{"read sro-a@vm2#0", DoneObs{Status: 1, Stderr: "boom\nmore"}, VFail, "exit status 1: boom"},
		{"write sro-a@vm2#0", DoneObs{Status: 1}, VOK, "ok"},
		{"write sro-a@vm2#0", DoneObs{}, VFail, "succeeded, want refused"},
		{"write sdax-a@vm1#0", DoneObs{}, VOK, "ok"},
		{"delete sdax-a@vm1#0", DoneObs{Status: 2}, VFail, "exit status 2 (unknown verb"},
	}
	for _, c := range cases {
		a := mustAct(t, cfg, c.act)
		d := c.done
		wantVerdict(t, checkDone(expectDone(s, s.next(a), a, int(s.Steps)+1), &d), c.status, c.msg)
	}
	// unknown content: anything, and learnt
	s2 := steps(t, newState(cfg), "create xdax-b@vm0#0", "settle")
	a := mustAct(t, cfg, "read xdax-b@vm0#0")
	d := &DoneObs{Text: str("whatever")}
	wantVerdict(t, checkDone(expectDone(s2, s2.next(a), a, 3), d), VOK, "ok")
	if tok := adoptDone(s2.next(a), a, d).Data[pooledDev(PoolB)]; tok != (Token{Known: true, Text: "whatever"}) {
		t.Fatalf("not learnt: %v", tok)
	}
	// lease-get
	s3 := steps(t, newState(cfg), "create lease@vm2#0", "settle")
	a = mustAct(t, cfg, "lease-get lease@vm2#0 dax")
	wantVerdict(t, checkDone(expectDone(s3, s3.next(a), a, 3), &DoneObs{}), VFail, "no lease")
	d = &DoneObs{Lease: str("L1")}
	wantVerdict(t, checkDone(expectDone(s3, s3.next(a), a, 3), d), VOK, "ok")
	if id := adoptDone(s3.next(a), a, d).LeaseIDs[cfg.slotIndex("lease@vm2#0")]; id != "L1" {
		t.Fatalf("lease id %q", id)
	}
}

func TestEnvWant(t *testing.T) {
	cfg := testConfig(t, "full", false)
	sl := cfg.Slots[cfg.slotIndex("xnuma-c@vm1#0")]
	w := envWant(cfg, &sl)
	want := map[string]string{"CXL_C1EE2001_MODE": "numa", "CXL_C1EE2001_SIZE": "268435456", "CXL_C1EE2001_SERIAL": "0xc1ee2001",
		"CXL_C1EE2001_SHARED": "0", "CXL_C1EE2001_NODE": "3"}
	if len(w) != len(want) {
		t.Fatalf("env %v", w)
	}
	for k, v := range want {
		if w[k] != v {
			t.Fatalf("%s=%s, want %s", k, w[k], v)
		}
	}
	sl = cfg.Slots[cfg.slotIndex("sexcl-a@vm2#0")]
	if w := envWant(cfg, &sl); w["CXL_C1AE0001_SHARED"] != "1" || w["CXL_C1AE0001_READONLY"] != "0" || w["CXL_C1AE0001_SIZE"] != "268435456" {
		t.Fatalf("env %v", w)
	}
	// the serial in any case
	sl = cfg.Slots[cfg.slotIndex("lnuma@vm0#0")]
	env := map[string]string{}
	for k, v := range envWant(cfg, &sl) {
		env[k] = v
	}
	env["CXL_C100E2E1_SERIAL"] = "0xC100E2E1"
	if d := envDiffs(cfg, &sl, env); len(d) != 0 {
		t.Fatalf("diffs %v", d)
	}
}

func TestParseObservedFile(t *testing.T) {
	for _, in := range []string{`done 3 1 {"text":"x"}`, `{"status":1,"text":"x"}`} {
		o, d, err := parseObservedFile([]byte(in))
		if err != nil || o != nil || d == nil || d.Status != 1 || d.Text == nil || *d.Text != "x" {
			t.Fatalf("%q: %v %v %v", in, o, d, err)
		}
	}
	for _, in := range []string{`observe 3 {"step":3,"pods":[]}`, `{"step":3,"pods":[],"vms":{}}`} {
		o, d, err := parseObservedFile([]byte(in))
		if err != nil || o == nil || d != nil || o.Step != 3 {
			t.Fatalf("%q: %v %v %v", in, o, d, err)
		}
	}
	nodes, err := parseNodeList("0-1,3")
	if err != nil || !nodes[0] || !nodes[1] || nodes[2] || !nodes[3] {
		t.Fatalf("nodes %v %v", nodes, err)
	}
}

func TestLocalDeviceSerial(t *testing.T) {
	for _, js := range []string{`{"serial":3238060769}`, `{"serial":"0xc100e2e1"}`, `{"serial":"3238060769"}`, `{"serialHex":"c100e2e1"}`} {
		var d ObsLocalDevice
		if err := json.Unmarshal([]byte(js), &d); err != nil {
			t.Fatal(err)
		}
		if v, ok := d.serial(); !ok || v != localSerial {
			t.Fatalf("%s: %x %v", js, v, ok)
		}
	}
	in := &ObsInspect{Leases: json.RawMessage(`{"leases":[{"lease":"L1","state":"Ready"}]}`)}
	if ls, ok := in.leases(); !ok || len(ls) != 1 || ls[0].Lease != "L1" {
		t.Fatalf("leases %v %v", ls, ok)
	}
	in.Leases = json.RawMessage(`null`)
	if _, ok := in.leases(); ok {
		t.Fatalf("null leases accepted")
	}
}
