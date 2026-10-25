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
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a log buffer that the test may read while the run logs.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func testOpts(t *testing.T, profile string, steps, depth int, planAhead bool) runOpts {
	t.Helper()
	cfg := defaultConfig()
	cfg.Online = true
	if err := cfg.loadProfile(profile); err != nil {
		t.Fatal(err)
	}
	cov, _ := parseCoverage("C1,C2,C3,C4")
	return runOpts{
		cfg: cfg, cov: cov, depth: depth, seed: 1, randomness: 1, maxSteps: steps,
		settleTimeout: 180 * time.Second, planAhead: planAhead, outDir: t.TempDir(), header: "test",
	}
}

// runSim runs the on-line loop against a simulated SUT over pipes.
func runSim(t *testing.T, o runOpts, sm *sim) (error, string) {
	t.Helper()
	goIn, simOut := io.Pipe()
	simIn, goOut := io.Pipe()
	logs := &syncBuffer{}
	r, err := newOnlineRun(o, goIn, goOut, logs)
	if err != nil {
		t.Fatal(err)
	}
	simDone := make(chan error, 1)
	go func() {
		err := sm.serve(simIn, simOut)
		simOut.Close()
		_, _ = io.Copy(io.Discard, simIn)
		simDone <- err
	}()
	runErr := r.run()
	goOut.Close()
	if err := <-simDone; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("sim: %v\nlog:\n%s", err, logs.String())
	}
	return runErr, logs.String()
}

func stepsOf(t *testing.T, dir string) []string {
	t.Helper()
	acts, err := readActions(filepath.Join(dir, "mbt-steps.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return acts
}

func TestOnlineSmall(t *testing.T) {
	o := testOpts(t, "small", 80, 2, true)
	sm := newSim(o.cfg, 7)
	sm.transient = 1
	err, logs := runSim(t, o, sm)
	if err != nil || sm.sawEnd == "" {
		t.Fatalf("run: %v, sim end %q fail %q\n%s", err, sm.sawEnd, sm.sawFail, logs)
	}
	acts := stepsOf(t, o.outDir)
	if len(acts) < 80 || acts[0] != "settle" || acts[len(acts)-1] != "settle" {
		t.Fatalf("steps %d: %v", len(acts), acts)
	}
	if !strings.Contains(logs, "plan: reused") {
		t.Fatalf("no plan was reused:\n%s", logs)
	}
	// the teardown leaves nothing
	for i := range sm.truth.Slots {
		if sm.truth.Slots[i].Phase != Absent {
			t.Fatalf("teardown left %s", sm.truth.slot(i).Name)
		}
	}
	// replay: the same steps against the same SUT
	r := testOpts(t, "small", 0, 2, true)
	r.replay = acts
	sm2 := newSim(r.cfg, 7)
	sm2.transient = 1
	err, logs = runSim(t, r, sm2)
	if err != nil || sm2.sawEnd == "" {
		t.Fatalf("replay: %v %q\n%s", err, sm2.sawFail, logs)
	}
	if got := stepsOf(t, r.outDir); strings.Join(got, "\n") != strings.Join(acts, "\n") {
		t.Fatalf("replay steps differ:\n%v\n%v", got, acts)
	}
}

func TestOnlineLockStepFull(t *testing.T) {
	o := testOpts(t, "full", 50, 2, false)
	sm := newSim(o.cfg, 3)
	sm.transient = 2
	err, logs := runSim(t, o, sm)
	if err != nil || sm.sawEnd == "" {
		t.Fatalf("run: %v, sim fail %q\n%s", err, sm.sawFail, logs)
	}
	if strings.Contains(logs, "plan: reused") {
		t.Fatalf("lock-step reused a plan")
	}
}

func TestOnlineDeterministic(t *testing.T) {
	var runs [2][]string
	for k := range runs {
		o := testOpts(t, "tiny", 60, 2, true)
		sm := newSim(o.cfg, 5)
		if err, logs := runSim(t, o, sm); err != nil {
			t.Fatalf("run %d: %v\n%s", k, err, logs)
		}
		runs[k] = stepsOf(t, o.outDir)
	}
	if strings.Join(runs[0], "\n") != strings.Join(runs[1], "\n") {
		t.Fatalf("same seed, different steps:\n%v\n%v", runs[0], runs[1])
	}
}

func TestOnlineDeviationFails(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(sm *sim)
		timeout bool
		msg     string
	}{
		{"restart", func(sm *sim) {
			sm.deviate = func(step int, o *Observation) {
				for j := range o.Pods {
					if o.Pods[j].Phase == "Running" && step > 10 {
						o.Pods[j].Restarts += 5
						return
					}
				}
			}
		}, false, "restarts, the model crashed it"},
		{"read", func(sm *sim) {
			sm.deviateDone = func(step int, a Act, d *DoneObs) {
				if a.Verb == VRead {
					x := "garbage"
					d.Text = &x
					sm.truth = sm.truth.clone()
					if sl := sm.truth.slot(int(a.Slot)); sl.Kind == KLDax {
						sm.truth.setSlotData(int(a.Slot), Token{})
					}
				}
			}
		}, false, `read "garbage"`},
		{"timeout", func(sm *sim) {
			sm.deviate = func(step int, o *Observation) {
				if step > 5 {
					o.Others = []string{"intruder"}
				}
			}
		}, true, "settle timeout after"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := testOpts(t, "small", 120, 2, true)
			if c.timeout {
				clock := time.Now()
				var mu sync.Mutex
				o.now = func() time.Time {
					mu.Lock()
					defer mu.Unlock()
					clock = clock.Add(time.Second)
					return clock
				}
			}
			sm := newSim(o.cfg, 2)
			c.setup(sm)
			err, logs := runSim(t, o, sm)
			if !errors.Is(err, errFailed) || !strings.Contains(sm.sawFail, c.msg) {
				t.Fatalf("run: %v, sim saw fail %q, want %q\n%s", err, sm.sawFail, c.msg, logs)
			}
			data, err := os.ReadFile(filepath.Join(o.outDir, "mbt-fail.txt"))
			if err != nil || !strings.Contains(string(data), "Differences:") || !strings.Contains(string(data), "Prediction:") {
				t.Fatalf("mbt-fail.txt: %v\n%s", err, data)
			}
			if acts := stepsOf(t, o.outDir); len(acts) != sm.failStep {
				t.Fatalf("mbt-steps.txt has %d steps, failed at %d", len(acts), sm.failStep)
			}
		})
	}
}

func TestOnlineProtocolErrors(t *testing.T) {
	o := testOpts(t, "tiny", 5, 1, false)
	in := strings.NewReader("observe 1 not-json\n")
	var out bytes.Buffer
	r, err := newOnlineRun(o, in, &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.run(); !errors.Is(err, errFailed) || !strings.Contains(out.String(), "fail 1 invalid observation") {
		t.Fatalf("run %v out %q", err, out.String())
	}
	in = strings.NewReader("done 1 0 {}\n")
	out.Reset()
	r, _ = newOnlineRun(testOpts(t, "tiny", 5, 1, false), in, &out, io.Discard)
	if err := r.run(); !errors.Is(err, errFailed) || !strings.Contains(out.String(), "protocol: want \"observe 1 JSON\"") {
		t.Fatalf("run %v out %q", err, out.String())
	}
	// replay of a step that the model does not allow
	o = testOpts(t, "tiny", 0, 1, false)
	o.replay = []string{"settle", "crash plain@vm0#0"}
	sm := newSim(o.cfg, 1)
	if err, _ := runSim(t, o, sm); !errors.Is(err, errFailed) || !strings.Contains(sm.sawFail, "replay diverged at step 2") {
		t.Fatalf("run %v fail %q", err, sm.sawFail)
	}
}
