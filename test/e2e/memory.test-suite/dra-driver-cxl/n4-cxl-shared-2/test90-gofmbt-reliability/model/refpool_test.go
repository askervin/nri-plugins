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

// The fuzz of the model's pool rules against the independent reference
// (refpool.go): many short random sequences heavy in controller and
// server faults mixed with creates, deletes and crashes of the pool
// kinds of all three pools, every settle polled like bash does (0.5 s,
// then every 3 s of the reference's clock) and checked by the oracle,
// with the settle timeout of 180 s on that clock.

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

var (
	refSeqs    = flag.Int("refpool-seqs", 400, "random sequences of TestRefPoolFuzz")
	refSeed    = flag.Int64("refpool-seed", 1, "first seed of TestRefPoolFuzz")
	refMax     = flag.Int("refpool-len", 60, "longest sequence of TestRefPoolFuzz")
	refSlow    = flag.Bool("refpool-slow", false, "TestRefPoolFuzz: controllers stay down long (ctrl-start rare)")
	refProfile = flag.String("refpool-profile", "full", "TestRefPoolFuzz: the profile (pmem, fullp: persistent devices)")
	refStall   = flag.Duration("refpool-stall-window", 0, "TestRefPoolFuzz: --stall-window (0: the default); not above 180 s: settles wait for stalled contenders, the reference's scheduler has the bug-08 fix")
)

type fuzzStats struct {
	ref                                  map[string]int
	seqs, steps, settles, polls          int
	stalled, unsched, absent, eitherSeen int
	verbs                                map[Verb]int
}

type fuzzFailure struct {
	seed  int64
	steps []string
	msg   string
	diffs []string
	model string
	ref   string
	hist  []string
}

func (f *fuzzFailure) String() string {
	return fmt.Sprintf("seed %d: %s\nsteps:\n  %s\ndifferences:\n  %s\nmodel before the step:\n%s\n%s\nreference log:\n  %s",
		f.seed, f.msg, strings.Join(f.steps, "\n  "), strings.Join(f.diffs, "\n  "), f.model, f.ref, strings.Join(f.hist, "\n  "))
}

// fuzzWeight is the weight of an action in the fuzz.
func fuzzWeight(cfg *Config, a Act) float64 {
	switch a.Verb {
	case VSettle:
		return 4
	case VCtrlStart:
		if *refSlow {
			return 0.02
		}
		return 2.5
	case VCtrlKill, VCtrlRestart:
		return 2.5
	case VServerRestart:
		return 1
	case VKubeletRestart:
		return 0.4
	case VDriverKill, VDriverRestart, VContainerdRestart:
		return 0.15
	case VPWrite, VLeaseGet, VLeasePut:
		return 1.5
	case VPRead, VPWipe, VDriverKillAt:
		return 0.5
	case VHold, VUnhold:
		return 1
	case VCreate, VDelete, VCrash:
		sl := &cfg.Slots[a.Slot]
		w := 1.0
		if a.Verb == VDelete {
			w = 2.5
		}
		if a.Verb == VCrash {
			w = 0.3
		}
		if !sl.Kind.pooled() {
			w *= 0.25
		}
		return w
	}
	return 0
}

// fuzzSequence runs one random sequence; nil if every step was ok.
func fuzzSequence(cfg *Config, acts []Act, seed int64, maxLen int, st *fuzzStats) *fuzzFailure {
	return refSequence(cfg, acts, seed, maxLen, nil, st)
}

// refSequence runs a sequence against the simulated SUT with the
// reference: random (script nil) or the actions of a script (each must
// be enabled in the model; then a final settle).
func refSequence(cfg *Config, acts []Act, seed int64, maxLen int, script []string, st *fuzzStats) *fuzzFailure {
	rng := rand.New(rand.NewSource(seed))
	sm := newSim(cfg, seed).withRef(seed * 7919)
	sm.ref.RequeueOnUnreserve = cfg.StallStrict && !refUnfixedScheduler
	model := newState(cfg)
	length := len(script)
	if script == nil {
		length = 4 + rng.Intn(maxLen-3)
	}
	var lines []string
	settle := Act{Verb: VSettle, Slot: -1, VM: VMAny, Pool: noPool}
	defer func() {
		for k, v := range sm.ref.Count {
			st.ref[k] += v
		}
	}()
	fail := func(msg string, diffs []string, before *State) *fuzzFailure {
		return &fuzzFailure{seed: seed, steps: lines, msg: msg, diffs: diffs, model: before.dump(), ref: sm.ref.String(), hist: sm.ref.History()}
	}
	for n := 1; ; n++ {
		var a Act
		var pred *State
		switch {
		case len(sm.ref.Anomalies) > 0:
			return fail("reference anomaly: "+sm.ref.Anomalies[0], sm.ref.Anomalies, model)
		case n > length && model.Unsettled == 0:
			st.seqs++
			return nil
		case n > length:
			a, pred = settle, model.next(settle)
		case script != nil:
			x, err := parseAct(cfg, script[n-1])
			if err != nil {
				return fail(err.Error(), nil, model)
			}
			a, pred = x, model.next(x)
			if pred == nil {
				lines = append(lines, a.name(cfg))
				return fail("not enabled: "+script[n-1], nil, model)
			}
		default:
			var cand []Act
			var preds []*State
			var ws []float64
			total := 0.0
			for _, x := range acts {
				w := fuzzWeight(cfg, x)
				if w == 0 {
					continue
				}
				if p := model.next(x); p != nil {
					cand, preds, ws = append(cand, x), append(preds, p), append(ws, w)
					total += w
				}
			}
			if len(cand) == 0 {
				a, pred = settle, model.next(settle)
				break
			}
			x := rng.Float64() * total
			j := 0
			for ; j < len(ws)-1 && x >= ws[j]; j++ {
				x -= ws[j]
			}
			a, pred = cand[j], preds[j]
		}
		if pred == nil {
			return fail("no enabled action and no settle", nil, model)
		}
		lines = append(lines, a.name(cfg))
		st.steps++
		st.verbs[a.Verb]++
		if a.Verb != VSettle {
			d := sm.do(n, a)
			if v := checkDone(expectDone(model, pred, a, n), d); v.Status != VOK {
				return fail(v.Msg, v.Diffs, model)
			}
			model = adoptDone(pred, a, d)
			continue
		}
		st.settles++
		if dbgPred != nil {
			dbgPred(pred, sm)
		}
		sm.do(n, a)
		start := sm.ref.Now()
		since := sm.refWall()
		for poll := 1; ; poll++ {
			st.polls++
			sm.refPoll(poll)
			o := sm.observe(n, poll)
			v, adopted, _ := checkAltsSince(pred, o, "", sm.refWall(), since, defaultUnblock)
			elapsed := time.Duration(sm.ref.Now()-start) * time.Millisecond
			if v.Status == VWait && elapsed >= 180*time.Second {
				return fail("settle timeout after "+elapsed.Round(time.Second).String()+": "+v.Msg, v.Diffs, model)
			}
			if v.Status == VFail {
				return fail(v.Msg, v.Diffs, model)
			}
			if v.Status == VOK {
				for i := range adopted.Slots {
					switch adopted.Slots[i].Phase {
					case Stalled:
						st.stalled++
					case Unsched:
						st.unsched++
					}
				}
				for p := range adopted.Ctrl {
					if adopted.Ctrl[p].Slices == SlicesAbsent {
						st.absent++
					}
				}
				if len(pred.Alts) > 0 {
					st.eitherSeen++
				}
				model = adopted
				break
			}
		}
		sm.pend = nil
	}
}

var dbgPred func(*State, *sim)

// refUnfixedScheduler: the reference's scheduler without the bug-08 fix
// also in strict stall mode (a test of the mode's failure).
var refUnfixedScheduler bool

var reNums = regexp.MustCompile(`[0-9]+(\.[0-9]+)?`)

// runRefFuzz runs sequences and returns the failures by message kind.
func runRefFuzz(t *testing.T, profile string, seqs int, seed0 int64, maxLen int) (map[string][]*fuzzFailure, *fuzzStats) {
	t.Helper()
	cfg := testConfig(t, profile, true)
	cfg.Unsettled = 3 // MBT_UNSETTLED of the runs
	if *refStall > 0 {
		cfg.StallWindow, cfg.StallStrict = *refStall, *refStall <= 180*time.Second
	}
	acts := allActs(cfg)
	st := &fuzzStats{verbs: map[Verb]int{}, ref: map[string]int{}}
	kinds := map[string][]*fuzzFailure{}
	for k := 0; k < seqs; k++ {
		if f := fuzzSequence(cfg, acts, seed0+int64(k), maxLen, st); f != nil {
			key := reNums.ReplaceAllString(f.msg, "N")
			kinds[key] = append(kinds[key], f)
		}
	}
	return kinds, st
}

// TestRefPoolFuzz: the model agrees with the reference of the pool side
// in random sequences of pool faults (-refpool-seqs N for more).
func TestRefPoolFuzz(t *testing.T) {
	seqs := *refSeqs
	if testing.Short() {
		seqs = 50
	}
	kinds, st := runRefFuzz(t, *refProfile, seqs, *refSeed, *refMax)
	t.Logf("%d sequences (%d failed), %d steps, %d settles, %d polls; adopted: stalled %d, unsched %d, slices absent %d; settles with alternatives %d; verbs %v; reference %v",
		seqs, seqs-st.seqs, st.steps, st.settles, st.polls, st.stalled, st.unsched, st.absent, st.eitherSeen, st.verbs, st.ref)
	var keys []string
	for k := range kinds {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(kinds[keys[i]]) > len(kinds[keys[j]]) })
	for _, k := range keys {
		fs := kinds[k]
		sort.Slice(fs, func(i, j int) bool { return len(fs[i].steps) < len(fs[j].steps) })
		t.Errorf("%d x %s\nshortest:\n%s", len(fs), k, fs[0])
	}
}

// refScript runs a script against the reference; the failure if any.
func refScript(t *testing.T, seed int64, lines ...string) *fuzzFailure {
	t.Helper()
	return refScriptWindow(t, seed, 0, lines...)
}

// refScriptWindow is refScript with a --stall-window (0: the default; not
// above 180 s: strict, and the reference's scheduler has the bug-08 fix).
func refScriptWindow(t *testing.T, seed int64, window time.Duration, lines ...string) *fuzzFailure {
	t.Helper()
	return refScriptIn(t, "full", seed, window, lines...)
}

// refScriptIn is refScriptWindow with the profile.
func refScriptIn(t *testing.T, profile string, seed int64, window time.Duration, lines ...string) *fuzzFailure {
	t.Helper()
	cfg := testConfig(t, profile, true)
	cfg.Unsettled = 3
	if window > 0 {
		cfg.StallWindow, cfg.StallStrict = window, window <= 180*time.Second
	}
	return refSequence(cfg, allActs(cfg), seed, 0, lines, &fuzzStats{verbs: map[Verb]int{}, ref: map[string]int{}})
}

func repeat(n int, lines ...string) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, lines...)
	}
	return out
}

// The controller down for longer than the binding timeout (600 s) with
// a contender of the waiting claim's device.
func TestRefPoolBindingTimeout(t *testing.T) {
	for _, start := range [][]string{
		{"ctrl-kill a", "create xnuma-a@vm1#0", "settle", "create xdax-a@vm1#0", "settle"},
		{"ctrl-kill a", "create xnuma-a@vm1#0", "settle"}, // no waiter: allocated again
		{"ctrl-kill c", "create sexcl-c@vm1#0", "settle", "create sdax-c@vm2#0", "settle"},
		{"ctrl-kill c", "create sdax-c@vm0#0", "settle", "create sexcl-c@vm1#0", "settle"},
	} {
		for seed := int64(1); seed <= 10; seed++ {
			lines := append(append([]string{"create plain@vm0#0"}, start...), repeat(120, "server-restart b", "settle")...)
			lines = append(lines, "ctrl-start "+strings.Fields(start[0])[1], "settle")
			if f := refScript(t, seed, lines...); f != nil {
				t.Errorf("%s", f)
				return
			}
		}
	}
}

// refRegressions are the shortest sequences of the fuzz's disagreements
// (plan-13-gofmbt/04-status-MODEL.txt section 16), with their seeds:
// they run without disagreement now, or the model refuses the step
// given (1-based) and the sequence before it runs without one.
var refRegressions = []struct {
	why     string
	seed    int64
	refused int
	steps   string
}{
	{"F2: hold after the settle: an \"any\" contender created in the next window stalls", 40, 0,
		"create xnuma-c@vm1#0 | create sdax-b@vm0#1 | ctrl-kill c | settle | create xnuma-a@vm1#0 | " +
			"create sro-b@vm0#0 | settle | create sdax-a@vm2#1 | ctrl-restart b | delete xnuma-a@vm1#0 " +
			"| settle | ctrl-kill a | delete xnuma-c@vm1#0 | create xdax-a@vm1#0 | settle | create " +
			"xdax-c@any#0 | create sexcl-a@vm2#0 | delete sdax-a@vm2#1 | settle"},
	{"F2: hold after the settle (an attaching holder deleted)", 106, 0,
		"create xdax-c@any#0 | create lnuma@vm2#0 | create sdax-b@vm0#1 | settle | create " +
			"lnuma@vm2#1 | delete sdax-b@vm0#1 | create plain@vm1#0 | settle | create sdax-b@vm0#0 | " +
			"create xnuma-a@vm1#0 | ctrl-kill a | settle | create sexcl-a@vm2#0 | delete xnuma-a@vm1#0 " +
			"| create lnuma@vm0#0 | settle | create xdax-a@vm1#0 | create xdax-b@vm0#0 | driver-kill " +
			"vm0 | settle"},
	{"F2: hold after the settle (a holder deleted while starting)", 782, 0,
		"create xdax-b@vm0#0 | delete xdax-b@vm0#0 | ctrl-restart c | settle | create sdax-c@vm1#0 " +
			"| driver-kill vm1 | create xnuma-b@vm0#0 | settle"},
	{"F3: a stalled contender promoted through a hole is blocked", 660, 0,
		"create sdax-a@vm2#1 | create lsteer@vm2#0 | create plain@vm2#0 | settle | kubelet-restart " +
			"vm0 | create xdax-a@vm1#0 | ctrl-kill a | settle | delete sdax-a@vm2#1 | server-restart c " +
			"| create xnuma-c@vm1#0 | settle | create lease@vm1#0 | create sexcl-a@vm2#0 | ctrl-kill c " +
			"| settle | create sexcl-c@vm1#0 | settle | delete xnuma-c@vm1#0 | server-restart b | " +
			"settle | create sdax-a@vm2#0 | create sdax-b@vm0#0 | create xdax-a@vm2#0 | settle | delete " +
			"sexcl-c@vm1#0 | ctrl-restart b | create sdax-b@vm0#1 | settle | delete sexcl-a@vm2#0 | " +
			"server-restart a | delete lease@vm1#0 | settle | ctrl-kill b | create xnuma-c@vm1#0 | " +
			"delete xnuma-c@vm1#0 | settle | create sro-a@vm2#0 | delete xdax-a@vm2#0 | settle | create " +
			"sexcl-c@vm1#0 | ctrl-start a | create sdax-a@vm2#1 | settle"},
	{"F4: two claims wait for the slices published again (refused)", 234, 19,
		"ctrl-restart c | create xdax-a@vm1#0 | create lnuma@vm0#0 | settle | ctrl-restart a | " +
			"ctrl-kill a | ctrl-restart c | settle | create sro-a@vm1#0 | ctrl-kill b | driver-kill vm2 " +
			"| settle | delete sro-a@vm1#0 | ctrl-restart c | ctrl-start b | settle | create " +
			"sdax-a@vm1#0 | ctrl-start a | create sexcl-a@vm2#0 | settle"},
	{"F4: two creates while the slices are unknown (refused)", 216, 3,
		"ctrl-restart a | create xdax-a@vm2#0 | create xnuma-a@vm1#0 | settle"},
	{"F5: ctrl-kill: the attach of a stalled contender in flight", 352, 0,
		"create lnuma@vm0#0 | create sexcl-a@vm2#0 | create ldax@vm1#0 | settle | ctrl-kill a | " +
			"create sdax-c@vm2#0 | ctrl-kill b | settle | create sdax-c@vm1#0 | create sdax-c@vm0#0 | " +
			"delete sdax-c@vm1#0 | settle | create sdax-c@vm1#0 | ctrl-start a | ctrl-kill c | settle"},
	{"F5: ctrl-kill: the attach of a claim deleted before it was bound", 477, 0,
		"ctrl-restart b | create lsteer@vm2#0 | ctrl-restart a | settle | create sdax-b@vm0#1 | " +
			"delete sdax-b@vm0#1 | ctrl-kill b | settle"},
	{"F5: ctrl-kill: an orphan detached by the start's reconcile", 4208, 0,
		"server-restart b | create xnuma-a@vm1#0 | create sdax-c@any#0 | settle | ctrl-kill a | " +
			"create sro-c@vm2#0 | create lease@vm2#0 | settle | create sro-c@vm0#0 | ctrl-kill b | " +
			"settle | delete sro-c@vm2#0 | ctrl-restart c | ctrl-kill c | settle | create xdax-a@vm1#0 " +
			"| create ldax@vm2#0 | crash sdax-c@any#0 | settle | create sdax-b@vm0#1 | create " +
			"sdax-a@vm1#0 | create sdax-c@vm2#0 | settle | create sro-a@vm1#0 | delete sro-a@vm1#0 | " +
			"settle | delete sdax-b@vm0#1 | ctrl-start c | ctrl-kill c | settle"},
	{"F7: ctrl-start prepares an \"any\" pod on a stack of a stalled pod (refused)", 1371, 26,
		"ctrl-kill c | create sro-b@vm0#0 | create sro-c@vm2#0 | settle | ctrl-kill b | create " +
			"lnuma@vm2#0 | ctrl-kill a | settle | create lsteer@vm2#0 | create plain@vm2#0 | create " +
			"xnuma-a@vm1#0 | settle | create ldax@vm2#0 | ctrl-start b | create xdax-c@any#0 | settle | " +
			"create xnuma-c@vm1#0 | delete sro-c@vm2#0 | delete xdax-c@any#0 | settle | ctrl-kill b | " +
			"server-restart a | create ldax@vm0#0 | settle | create sdax-c@any#0 | ctrl-start c | " +
			"delete ldax@vm2#0 | settle"},
	{"F8: the claim of a pod gone at the last settle not deallocated yet (refused)", 6047, 42,
		"create xdax-a@vm2#0 | create ldax@vm2#0 | create sdax-c@vm1#0 | settle | create " +
			"sdax-c@any#0 | create plain@vm0#0 | create xnuma-c@vm1#0 | settle | create sdax-c@vm0#0 | " +
			"create sro-c@vm2#0 | ctrl-kill c | settle | ctrl-kill b | delete ldax@vm2#0 | ctrl-kill a " +
			"| settle | create sdax-a@vm1#0 | create sdax-b@vm0#0 | kubelet-restart vm1 | settle | " +
			"create ldax@vm2#0 | delete sdax-c@any#0 | driver-kill vm2 | settle | crash xdax-a@vm2#0 | " +
			"create lnuma@vm2#0 | create lnuma@vm2#1 | settle | create sdax-c@any#0 | create " +
			"sro-a@vm2#0 | delete sro-a@vm2#0 | settle | delete sdax-c@vm1#0 | delete sdax-c@vm0#0 | " +
			"create xdax-a@vm1#0 | settle | create sdax-c@vm0#0 | delete sdax-c@any#0 | delete " +
			"xnuma-c@vm1#0 | settle | create xnuma-c@vm1#0 | create xdax-c@vm2#0 | delete xdax-a@vm2#0 " +
			"| settle"},
	{"F9: promotion after an unbound delete of the same device in the window", 18363, 0,
		"ctrl-kill b | ctrl-kill c | create sdax-a@vm2#1 | settle | delete sdax-a@vm2#1 | create " +
			"sdax-c@vm0#0 | delete sdax-c@vm0#0 | settle | kubelet-restart vm0 | create xnuma-c@vm1#0 | " +
			"create sdax-a@vm2#1 | settle | delete xnuma-c@vm1#0 | create xdax-c@vm2#0 | " +
			"kubelet-restart vm0 | settle | create sdax-b@vm0#0 | kubelet-restart vm0 | create " +
			"xnuma-a@vm1#0 | settle | create xnuma-b@vm0#0 | create sdax-c@vm0#0 | ctrl-kill a | settle " +
			"| server-restart c | create sro-a@vm1#0 | delete xnuma-a@vm1#0 | settle | delete " +
			"sdax-c@vm0#0 | kubelet-restart vm2 | delete xnuma-b@vm0#0 | settle | ctrl-start c | create " +
			"sro-a@vm2#0 | delete sro-a@vm1#0 | settle | create sexcl-a@vm2#0 | ctrl-restart c | delete " +
			"xdax-c@vm2#0 | settle | ctrl-start b | ctrl-restart c | create sro-c@vm0#0 | settle | " +
			"delete sro-a@vm2#0 | delete sdax-a@vm2#1 | create sexcl-c@vm1#0 | settle"},
	{"F9: promotion after an unbound delete (sexcl after shares)", 10164, 0,
		"create plain@vm0#0 | create xdax-a@vm2#0 | delete xdax-a@vm2#0 | settle | create " +
			"sdax-a@vm2#0 | create xdax-b@vm0#0 | create sro-b@vm0#0 | settle | create xnuma-b@vm0#0 | " +
			"create sdax-c@vm2#0 | settle | server-restart c | ctrl-kill c | ctrl-kill b | settle | " +
			"delete sdax-a@vm2#0 | server-restart b | settle | delete xdax-b@vm0#0 | server-restart b | " +
			"server-restart b | settle | create sro-a@vm2#0 | delete sro-b@vm0#0 | create ldax@vm2#0 | " +
			"settle | ctrl-kill a | create lsteer@vm2#0 | create sexcl-c@vm1#0 | settle | create " +
			"sdax-a@vm2#0 | server-restart c | delete sdax-a@vm2#0 | settle | delete sexcl-c@vm1#0 | " +
			"create sdax-b@vm0#0 | server-restart a | settle | kubelet-restart vm0 | ctrl-start a | " +
			"delete sdax-b@vm0#0 | settle | create sdax-c@vm0#0 | settle | delete sdax-c@vm0#0 | create " +
			"sexcl-c@vm1#0 | delete sdax-c@vm2#0 | settle"},
	{"F9: a later fit of a device held since the last settle", 5870, 0,
		"create sdax-a@vm2#1 | create xnuma-b@vm0#0 | create ldax@vm1#0 | settle | ctrl-kill b | " +
			"create lease@vm2#0 | create xdax-b@vm0#0 | settle | ctrl-restart a | delete xdax-b@vm0#0 | " +
			"create xnuma-a@vm1#0 | settle | kubelet-restart vm2 | server-restart c | ctrl-kill a | " +
			"settle | delete xnuma-a@vm1#0 | create sdax-c@any#0 | create sdax-a@vm2#0 | settle | " +
			"ctrl-start b | delete xnuma-b@vm0#0 | ctrl-kill c | settle | create sro-c@vm0#0 | delete " +
			"ldax@vm1#0 | delete sro-c@vm0#0 | settle | delete sdax-c@any#0 | ctrl-start a | create " +
			"sexcl-c@vm1#0 | settle"},
	{"F10: a contender stalled with other region events on its stack (refused)", 35043, 41,
		"create sexcl-c@vm1#0 | create sdax-a@vm2#0 | delete sexcl-c@vm1#0 | settle | ctrl-kill b | " +
			"create lease@vm0#0 | ctrl-restart a | settle | kubelet-restart vm2 | create lnuma@vm0#1 | " +
			"driver-kill vm2 | settle | create xnuma-a@vm1#0 | create xdax-a@vm2#0 | create " +
			"sexcl-b@vm0#0 | settle | crash xnuma-a@vm1#0 | create sdax-c@any#0 | delete sdax-a@vm2#0 | " +
			"settle | delete xnuma-a@vm1#0 | ctrl-restart c | delete lnuma@vm0#1 | settle | create " +
			"sro-a@vm2#0 | create sdax-a@vm2#0 | settle | create xdax-a@vm1#0 | kubelet-restart vm1 | " +
			"delete sdax-c@any#0 | settle | ctrl-start b | create sro-b@vm0#0 | settle | create " +
			"xdax-c@vm2#0 | delete xdax-c@vm2#0 | create ldax@vm1#0 | settle | create sro-c@vm2#0 | " +
			"driver-restart vm1 | create xdax-c@vm2#0 | settle"},
	{"F11: a stalled \"any\" pod and a prepare on a host stack (refused)", 90818, 32,
		"create sdax-a@vm2#1 | ctrl-restart c | ctrl-restart b | settle | ctrl-kill b | create " +
			"xnuma-a@vm1#0 | settle | create lnuma@vm1#0 | create plain@vm0#0 | delete xnuma-a@vm1#0 | " +
			"settle | ctrl-start b | ctrl-kill c | create sdax-c@vm1#0 | settle | delete sdax-c@vm1#0 | " +
			"create sdax-c@vm0#0 | create xdax-c@vm2#0 | settle | create lnuma@vm0#1 | create " +
			"xdax-c@any#0 | delete sdax-a@vm2#1 | settle | delete sdax-c@vm0#0 | delete xdax-c@vm2#0 | " +
			"create xdax-a@vm2#0 | settle | server-restart c | ctrl-start c | create xnuma-a@vm2#0 | " +
			"settle | create sdax-c@vm0#0 | driver-kill vm1 | create lease@vm1#0 | settle"},
	{"M5: ctrl-start after the slices were absent: published again (L4)", 860, 0,
		"create xnuma-a@vm1#0 | ctrl-restart c | ctrl-kill c | settle | ctrl-start c | create " +
			"sdax-c@vm0#0 | server-restart c | settle"},
	{"reference: an attach that conflicts with a wanted attachment on another host (AttachFailed, scheduled again)", 9745, 0,
		"create sdax-a@vm1#0 | ctrl-kill c | create lnuma@vm2#0 | settle | delete sdax-a@vm1#0 | " +
			"create sexcl-b@vm0#0 | kubelet-restart vm1 | settle | create lsteer@vm1#0 | ctrl-kill b | " +
			"create sexcl-a@vm2#0 | settle | delete sexcl-b@vm0#0 | create plain@vm0#0 | create " +
			"xnuma-a@vm2#0 | settle | create sro-a@vm1#0 | ctrl-start c | containerd-restart vm2 | " +
			"settle | create xnuma-c@vm1#0 | settle | create sdax-c@vm1#0 | create lsteer@vm2#0 | " +
			"ctrl-restart a | settle | ctrl-kill a | create ldax@vm0#0 | ctrl-kill c | settle | delete " +
			"xnuma-a@vm2#0 | ctrl-start c | delete sexcl-a@vm2#0 | settle | ctrl-start a | ctrl-kill c " +
			"| create sro-a@vm2#0"},
	{"F13: an unblocking pool pod not bound yet (Attached, PreBind not polled again) taken as bound", 700750, 0,
		"kubelet-restart vm2 | create sexcl-b@vm0#0 | server-restart a | settle | create " +
			"sro-a@vm2#0 | ctrl-kill a | create sdax-b@vm0#1 | settle | ctrl-restart c | ctrl-start a | " +
			"create xnuma-a@vm2#0 | settle | delete sexcl-b@vm0#0 | delete sro-a@vm2#0 | delete " +
			"xnuma-a@vm2#0 | settle | kubelet-restart vm2 | ctrl-kill c | ctrl-restart b | settle | " +
			"server-restart c | ctrl-restart a | create sro-b@vm0#0 | settle | create xdax-c@vm2#0 | " +
			"create sdax-a@vm2#0 | create sexcl-c@vm1#0 | settle | delete sro-b@vm0#0 | create " +
			"xnuma-a@vm1#0 | create sro-c@vm2#0 | settle | delete xdax-c@vm2#0 | create sro-a@vm2#0 | " +
			"delete sdax-b@vm0#1 | settle | delete sro-a@vm2#0 | delete sro-c@vm2#0 | create " +
			"xdax-b@vm0#0 | settle | ctrl-kill a | ctrl-kill b | ctrl-start c | settle | create " +
			"xdax-a@vm1#0 | delete sexcl-c@vm1#0 | create sexcl-b@vm0#0 | settle | create lnuma@vm1#0 | " +
			"create ldax@vm1#1 | kubelet-restart vm0 | settle | delete sexcl-b@vm0#0 | create " +
			"lnuma@vm0#0 | driver-restart vm1 | settle | ctrl-restart c | create xnuma-c@vm1#0 | create " +
			"sro-b@vm0#0 | settle | delete xnuma-c@vm1#0 | delete xnuma-a@vm1#0 | server-restart a | " +
			"settle | ctrl-start a | ctrl-start b | create sexcl-b@vm0#0 | settle | ctrl-restart b | " +
			"ctrl-restart a | ctrl-restart c | settle | create xnuma-a@vm1#0 | ctrl-kill c | delete " +
			"xdax-a@vm1#0 | settle | create sdax-c@vm2#0 | create xdax-a@vm2#0 | ctrl-start c | settle " +
			"| ctrl-restart b | create ldax@vm2#0 | delete sdax-a@vm2#0 | settle | create plain@vm2#0 | " +
			"kubelet-restart vm1 | containerd-restart vm0 | settle | ctrl-kill c | delete xdax-b@vm0#0 " +
			"| create sro-c@vm2#0 | settle | delete xdax-a@vm2#0 | ctrl-kill b | ctrl-start c | settle " +
			"| ctrl-start b | create xdax-c@vm2#0 | delete sro-c@vm2#0 | settle | create sro-a@vm2#0 | " +
			"delete ldax@vm2#0 | ctrl-kill c | settle | create sexcl-a@vm2#0 | settle | delete " +
			"sro-a@vm2#0 | create plain@vm1#0 | create lnuma@vm2#0 | settle"},
}

func TestRefPoolRegressions(t *testing.T) {
	for _, r := range refRegressions {
		steps := strings.Split(r.steps, " | ")
		f := refScript(t, r.seed, steps...)
		if r.refused > 0 {
			if f == nil || !strings.HasPrefix(f.msg, "not enabled") || len(f.steps) != r.refused {
				t.Errorf("%s: want step %d %q refused, got %v", r.why, r.refused, steps[r.refused-1], f)
				continue
			}
			f = refScript(t, r.seed, steps[:r.refused-1]...)
		}
		if f != nil {
			t.Errorf("%s:\n%s", r.why, f)
		}
	}
}

// d8Steps are the actions of the D8 replay (plan-13-gofmbt/06-runs.txt;
// recorded/d8-steps.txt) without the initial settle.
func d8Steps(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("recorded/d8-steps.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines, _ := readSteps(string(data))
	var out []string
	for _, l := range lines[1:] {
		out = append(out, l.Action)
	}
	return out
}

// --stall-window against the reference on the D8 sequence: the default
// (6m: stalled contenders settled in both states) with the scheduler of
// the cluster before the bug-08 fix, a short window (30 s: settles wait
// for the promotion) with the fixed one; the short window with the old
// scheduler fails (the settle that waits for the promotion times out).
func TestRefPoolStallWindow(t *testing.T) {
	steps := d8Steps(t)
	for seed := int64(1); seed <= 20; seed++ {
		if f := refScriptWindow(t, seed, 0, steps...); f != nil {
			t.Fatalf("default window:\n%s", f)
		}
		if f := refScriptWindow(t, seed, 30*time.Second, steps...); f != nil {
			t.Fatalf("30 s, fixed scheduler:\n%s", f)
		}
	}
	refUnfixedScheduler = true
	defer func() { refUnfixedScheduler = false }()
	failed := 0
	for seed := int64(1); seed <= 20; seed++ {
		if f := refScriptWindow(t, seed, 30*time.Second, steps...); f != nil {
			if !strings.Contains(f.msg, "still not allocated") {
				t.Fatalf("30 s, old scheduler: %s", f.msg)
			}
			failed++
		}
	}
	if failed == 0 {
		t.Fatalf("30 s with the old scheduler never failed")
	}
}

// A stalled contender (the scheduler holds the device of a claim deleted
// before it was bound) seen not allocated and unschedulable when its
// pool's slices are gone (ctrl-restart, then ctrl-kill) is Unsched, like
// the claims that wait for the slices: a short --stall-window does not
// fail it (fuzz, fullp seed 20031, pmem seeds 9442, 9445, 9472 with
// --stall-window 30s); allocated before the slices went it waits for
// the attach (seed 328).
func TestRefPoolStalledWithoutSlices(t *testing.T) {
	script := []string{"create sdax-c@any#0", "create pfsc-c@vm2#0", "pwipe c c-pmem1", "delete pfsc-c@vm2#0", "settle",
		"ctrl-restart c", "create pfsc-c@vm1#0", "ctrl-kill c", "settle"}
	if f := refScriptIn(t, "fullp", 20031, 30*time.Second, script...); f != nil {
		t.Fatalf("%s", f)
	}
	s := steps(t, revState(t, "fullp", true, script[:len(script)-1]...), "settle")
	wantPhase(t, s, "pfsc-c@vm1#0", Stalled)
	var absent *State
	for _, a := range alts(s) {
		if a.Ctrl[PoolC].Slices == SlicesAbsent {
			absent = a
		}
	}
	if absent == nil {
		t.Fatalf("no world without the slices:\n%s", dumpAlts(s))
	}
	truth := absent.clone()
	truth.Slots[truth.cfg.slotIndex("pfsc-c@vm1#0")].Phase = Unsched
	v, adopted := checkState(s, observation(t, truth), "")
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted, "pfsc-c@vm1#0", Unsched)
	if f := refScript(t, 328, "create xnuma-a@vm2#0", "create sdax-c@vm1#0", "delete xnuma-a@vm2#0", "settle",
		"create xdax-a@vm1#0", "ctrl-restart a", "ctrl-kill a", "settle"); f != nil {
		t.Fatalf("%s", f)
	}
}

// The simulator's truth makes no namespace that the reference never let
// a writer prepare: pwr-c@vm2#0 created while pool c has no slices,
// deleted unallocated, in a window with ctrl-start c (fuzz, pmem seed
// 9442; seed 9762 alike).
func TestRefPoolTruthNamespace(t *testing.T) {
	script := []string{"driver-kill-at vm0 ns", "kubelet-restart vm2", "server-restart c", "settle",
		"driver-kill vm0", "create pbro-c@vm0#0", "delete pbro-c@vm0#0", "settle",
		"ctrl-restart c", "ctrl-kill c", "create pwr-c@vm2#0", "settle",
		"driver-kill-at vm0 ns", "driver-kill-at vm2 ns", "kubelet-restart vm0", "settle",
		"delete pwr-c@vm2#0", "create pfsd-c@vm2#0", "ctrl-start c", "settle"}
	if f := refScriptIn(t, "pmem", 9442, 0, script...); f != nil {
		t.Fatalf("%s", f)
	}
}

// A18 (fuzz pmem seed 10091): an allocated claim keeps its allocation
// when its pool's slices go (the scheduler deallocates only on its own
// failures and timeouts). A stalled pfsc-c@vm1#0 promoted before
// ctrl-restart deleted the slices, then ctrl-kill: allocated, waiting
// for the attach (adopted); after ctrl-start c and ctrl-kill c, the
// world without the slices has it as with them (attached before the
// kill or not: either), never Unsched.
func TestRefPoolAllocatedWithoutSlices(t *testing.T) {
	s := revState(t, "pmem", true, "create pfsc-c@vm2#0", "delete pfsc-c@vm2#0", "settle", "create pfsc-c@vm1#0")
	wantPhase(t, s, "pfsc-c@vm1#0", Stalled)
	s = steps(t, s, "ctrl-restart c", "ctrl-kill c", "settle")
	var absent *State
	for _, a := range alts(s) {
		if a.Ctrl[PoolC].Slices == SlicesAbsent {
			absent = a
		}
	}
	if absent == nil {
		t.Fatalf("no world without the slices:\n%s", dumpAlts(s))
	}
	truth := absent.clone()
	truth.Slots[truth.cfg.slotIndex("pfsc-c@vm1#0")].Phase = Attaching
	v, adopted := checkState(s, observation(t, truth), "")
	wantVerdict(t, v, VOK, "ok")
	wantPhase(t, adopted, "pfsc-c@vm1#0", Attaching)
	if adopted.Ctrl[PoolC].Slices != SlicesAbsent {
		t.Fatalf("adopted slices %v", adopted.Ctrl[PoolC].Slices)
	}
	r := steps(t, adopted, "ctrl-start c", "ctrl-kill c", "settle")
	found := false
	for _, a := range alts(r) {
		if a.Ctrl[PoolC].Slices != SlicesAbsent {
			continue
		}
		found = true
		if ph := slotOf(t, a, "pfsc-c@vm1#0").Phase; ph != Either {
			t.Fatalf("without the slices: %s, want either (attached before the kill or not)", ph)
		}
	}
	if !found {
		t.Fatalf("no world without the slices:\n%s", dumpAlts(r))
	}
	// the fuzz's sequence against the reference
	script := []string{"driver-kill-at vm2 ns", "create sdax-c@vm0#0", "settle",
		"ctrl-restart c", "ctrl-restart c", "create xnuma-c@vm1#0", "settle",
		"create pfsd-c@vm1#0", "kubelet-restart vm1", "settle",
		"delete pfsd-c@vm1#0", "delete sdax-c@vm0#0", "settle",
		"driver-kill-at vm1 mount", "create pfsd-c@vm1#0", "settle",
		"ctrl-kill c", "settle",
		"delete xnuma-c@vm1#0", "ctrl-start c", "delete pfsd-c@vm1#0", "settle",
		"create pfsc-c@vm2#0", "delete pfsc-c@vm2#0", "ctrl-restart c", "settle",
		"create pfsc-c@vm1#0", "ctrl-restart c", "ctrl-kill c", "settle",
		"ctrl-start c", "ctrl-kill c", "create pfsd-c@vm1#0", "settle"}
	for _, w := range []time.Duration{0, 30 * time.Second} {
		if f := refScriptIn(t, "pmem", 10091, w, script...); f != nil {
			t.Fatalf("--stall-window %s:\n%s", w, f)
		}
	}
}
