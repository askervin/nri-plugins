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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func genOpts(t *testing.T, profile string, steps int, seed int64) runOpts {
	t.Helper()
	cfg := defaultConfig()
	cfg.Online = false
	if err := cfg.loadProfile(profile); err != nil {
		t.Fatal(err)
	}
	cov, _ := parseCoverage("C1,C2,C3,C4")
	return runOpts{cfg: cfg, cov: cov, depth: 2, seed: seed, randomness: 1, maxSteps: steps, header: "test"}
}

func generateScript(t *testing.T, o runOpts, from []stepLine) string {
	t.Helper()
	var b bytes.Buffer
	if err := generate(o, from, &b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestGenerateDeterministic(t *testing.T) {
	a := generateScript(t, genOpts(t, "small", 60, 11), nil)
	b := generateScript(t, genOpts(t, "small", 60, 11), nil)
	if a != b {
		t.Fatalf("same seed, different scripts")
	}
	if c := generateScript(t, genOpts(t, "small", 60, 12), nil); c == a {
		t.Fatalf("another seed, the same script")
	}
}

// runScript executes a generated script on a simulated SUT as
// code.var.sh does (A14: every step has an expectation): every one must
// hold, without adoption.
func runScript(t *testing.T, cfg *Config, script string, seed int64) {
	t.Helper()
	g, err := parseGenScript(script)
	if err != nil {
		t.Fatal(err)
	}
	last := g.Expects[len(g.Steps)]
	if last == nil || !last.Final {
		t.Fatalf("the last settle is not the final teardown expectation")
	}
	sm := newSim(cfg, seed)
	for i, line := range g.Steps {
		n := i + 1
		a, err := parseAct(cfg, line)
		if err != nil {
			t.Fatalf("step %d: %v", n, err)
		}
		e := g.Expects[n]
		if e == nil {
			t.Fatalf("step %d %s: no expectation (A14)", n, line)
		}
		if _, err := e.state(); err != nil {
			t.Fatalf("step %d: %v", n, err)
		}
		d := sm.do(n, a)
		if a.Verb == VSettle {
			js, _ := json.Marshal(sm.observe(n, 1))
			obs, _, err := parseObservedFile(js)
			if err != nil {
				t.Fatal(err)
			}
			if v := checkSettle(e, obs); v.Status != VOK {
				t.Fatalf("step %d settle: %s\n%s", n, v.Msg, strings.Join(v.Diffs, "\n"))
			}
			continue
		}
		if v := checkDone(e, d); v.Status != VOK {
			t.Fatalf("step %d %s: %s", n, line, v.Msg)
		}
	}
}

// TestGenerateAgainstSim executes generated scripts on the simulated SUT.
func TestGenerateAgainstSim(t *testing.T) {
	for _, tc := range []struct {
		profile string
		seed    int64
		steps   int
	}{{"small", 1, 150}, {"full", 2, 80}, {"tiny", 3, 150}} {
		t.Run(fmt.Sprintf("%s-%d", tc.profile, tc.seed), func(t *testing.T) {
			o := genOpts(t, tc.profile, tc.steps, tc.seed)
			script := generateScript(t, o, nil)
			g, err := parseGenScript(script)
			if err != nil {
				t.Fatal(err)
			}
			if len(g.Steps) < tc.steps || g.Steps[0] != "settle" || g.Steps[len(g.Steps)-1] != "settle" {
				t.Fatalf("%d steps", len(g.Steps))
			}
			runScript(t, o.cfg, script, tc.seed)
		})
	}
}

// TestGenerateFrom: --from of an on-line run follows what the run
// adopted (R5): the script, executed on an SUT that behaves as the run's
// did, passes every expectation.
func TestGenerateFrom(t *testing.T) {
	for _, tc := range []struct {
		profile string
		seed    int64
	}{{"small", 4}, {"full", 4}, {"full", 9}} {
		t.Run(fmt.Sprintf("%s-%d", tc.profile, tc.seed), func(t *testing.T) {
			o := testOpts(t, tc.profile, 60, 1, false)
			sm := newSim(o.cfg, tc.seed)
			if err, logs := runSim(t, o, sm); err != nil {
				t.Fatalf("%v\n%s", err, logs)
			}
			data, err := os.ReadFile(filepath.Join(o.outDir, "mbt-steps.txt"))
			if err != nil {
				t.Fatal(err)
			}
			lines, _ := readSteps(string(data))
			if !strings.Contains(string(data), "#adopt ") {
				t.Fatalf("no adoption records:\n%s", data)
			}
			adopted := 0
			for _, l := range lines {
				if l.Adopt != "" {
					adopted++
				}
			}
			if tc.profile == "full" && adopted == 0 {
				t.Fatalf("nothing adopted: the test does not test --from")
			}
			t.Logf("%d steps, %d with adoption items", len(lines), adopted)
			g := genOpts(t, tc.profile, 0, 1)
			g.cfg.Online = true
			if err := g.cfg.loadProfile(tc.profile); err != nil {
				t.Fatal(err)
			}
			script := generateScript(t, g, lines)
			gs, _ := parseGenScript(script)
			var acts []string
			for _, l := range lines {
				acts = append(acts, l.Action)
			}
			if strings.Join(gs.Steps, "\n") != strings.Join(acts, "\n") {
				t.Fatalf("--from changed the steps")
			}
			runScript(t, g.cfg, script, tc.seed)
			// without the records it stops at the first open choice,
			// or follows the issue order where nothing is open
			var b bytes.Buffer
			if err := generate(g, stepLines(acts), &b); err != nil && !strings.Contains(err.Error(), "has no adoption record") {
				t.Fatal(err)
			}
		})
	}
}

func TestCheckCommand(t *testing.T) {
	cfg := testConfig(t, "small", false)
	s := steps(t, newState(cfg), "create lnuma@vm0#0", "create sdax-c@vm0#0", "settle")
	dir := t.TempDir()
	write := func(name string, v any) string {
		p := filepath.Join(dir, name)
		var data []byte
		switch x := v.(type) {
		case string:
			data = []byte(x)
		default:
			data, _ = json.Marshal(x)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	exp := write("exp.json", s.expect(3, "settle"))
	sm := newSim(cfg, 1)
	sm.truth = sm.resolve(s)
	good := sm.observe(3, 1)
	okFile := write("ok.json", good)
	bad := sm.observe(3, 2)
	for j := range bad.Pods {
		bad.Pods[j].Ready = false
	}
	waitFile := write("wait.json", bad)
	worse := sm.observe(3, 3)
	worse.Pods[0].Restarts = 3
	failFile := write("fail.json", worse)
	lineFile := write("line.txt", "observe 3 "+string(mustJSON(t, good)))
	cases := []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"--step", "3", "--expect", exp, "--observed", okFile}, exitOK, "ok"},
		{[]string{"--step", "3", "--expect", exp, "--observed", lineFile}, exitOK, "ok"},
		{[]string{"--step", "3", "--expect", exp, "--observed", waitFile, "--since", fmt.Sprint(time.Now().Unix())}, exitWait, "wait pod"},
		{[]string{"--step", "3", "--expect", exp, "--observed", waitFile, "--elapsed", "200"}, exitFail, "fail settle timeout after 200s: pod"},
		{[]string{"--step", "3", "--expect", exp, "--observed", failFile}, exitFail, "fail pod"},
		{[]string{"--step", "4", "--expect", exp, "--observed", okFile}, exitFail, "fail check: the expectation is of step 3"},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if code := runCheck(c.args, &out, &errb); code != c.code || !strings.HasPrefix(out.String(), c.out) {
			t.Fatalf("check %v: exit %d %q, want %d %q (stderr %s)", c.args, code, out.String(), c.code, c.out, errb.String())
		}
	}
	// a done observation
	a := mustAct(t, cfg, "read sdax-c@vm0#0")
	dexp := write("dexp.json", expectDone(s, s.next(a), a, 4))
	var out bytes.Buffer
	if code := runCheck([]string{"--expect", dexp, "--observed", write("done.txt", `done 4 0 {"text":"anything"}`)}, &out, &bytes.Buffer{}); code != exitOK {
		t.Fatalf("done check: %d %s", code, out.String())
	}
	out.Reset()
	if code := runCheck([]string{"--expect", dexp, "--observed", write("done2.txt", `{"status":1}`)}, &out, &bytes.Buffer{}); code != exitFail {
		t.Fatalf("done check: %d %s", code, out.String())
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return js
}

func TestMainCommands(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"generate", "--profile", "tiny", "--steps", "10", "--seed", "3", "--depth", "1"}, nil, &out, &errb); code != 0 {
		t.Fatalf("generate: %d %s", code, errb.String())
	}
	if _, err := parseGenScript(out.String()); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"bogus"}, {"generate", "--profile", "nope", "--steps", "3"}, {"generate", "--steps", "3", "--avoid", "frob"},
		{"generate", "--steps", "3", "--coverage", "C9"}, {"generate"}} {
		if code := run(args, nil, &bytes.Buffer{}, &bytes.Buffer{}); code == 0 {
			t.Fatalf("%v: exit 0", args)
		}
	}
}

func TestExperimentQuick(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runExperiment([]string{"--profile", "tiny", "--exp", "all", "--steps", "30", "--max-depth", "2", "--seed", "3",
		"--mixes", "C1x3,C2x2,C3;all", "--uncovered"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	for _, want := range []string{"branching profile=tiny", "plantime profile=tiny coverage=C1x3,C2x2,C3 depth=2", "growth profile=tiny coverage=C1,C2,C3,C4", "uncovered:"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("no %q in\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "ORACLE DISAGREES") {
		t.Fatalf("the oracle disagrees with the simulated SUT:\n%s", out.String())
	}
}

func TestCoverageParse(t *testing.T) {
	for in, want := range map[string]string{"C1,C2": "C1,C2", "c1x3, C2X2,C3": "C1x3,C2x2,C3", "all": "C1,C2,C3,C4", "C4x1": "C4"} {
		c, err := parseCoverage(in)
		if err != nil || c.String() != want {
			t.Fatalf("%q: %v %v, want %s", in, c, err, want)
		}
	}
	for _, bad := range []string{"", "C5", "C1x0", "C1xx", "C2x101"} {
		if _, err := parseCoverage(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
