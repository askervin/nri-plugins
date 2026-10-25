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

// Off-line experiments (prototype P4 of plan-13-gofmbt/03-plan.txt):
// branching, planning time per depth, coverage growth per criterion mix.
// Every run drives the simulated SUT and checks every step with the
// oracle, so an experiment is also a soak test of the model, the oracle
// and their agreement on what the observations look like.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/pprof"
	"sort"
	"strings"
	"time"
)

// metrics counts the strings of the four criteria along a run,
// independent of what guides the planner.
type metrics struct {
	sets       [4]map[string]bool
	lastFormat string
	lastInc    [4]int // the last step that increased each criterion
	total      int    // C1: number of actions of the model
}

func newMetrics(total int) *metrics {
	m := &metrics{total: total}
	for i := range m.sets {
		m.sets[i] = map[string]bool{}
	}
	return m
}

func (m *metrics) add(step int, cfg *Config, from *State, a Act, to *State) {
	addAll := func(c int, xs ...string) {
		for _, x := range xs {
			if !m.sets[c][x] {
				m.sets[c][x] = true
				m.lastInc[c] = step
			}
		}
	}
	addAll(0, a.name(cfg))
	addAll(1, faultContext(from, a)...)
	f, args := a.format(cfg)
	if len(args) > 0 {
		f = "[" + f + "]"
	}
	addAll(2, f)
	if m.lastFormat != "" {
		addAll(2, m.lastFormat+"\x00"+f)
	}
	m.lastFormat = f
	if step == 1 {
		addAll(3, from.abstract()...)
	}
	addAll(3, to.abstract()...)
}

func (m *metrics) counts() [4]int {
	return [4]int{len(m.sets[0]), len(m.sets[1]), len(m.sets[2]), len(m.sets[3])}
}

// expResult is one experiment run.
type expResult struct {
	steps     int
	branching []int
	planTimes []time.Duration
	depths    []int
	paths     []int
	growth    [][4]int // after each step
	m         *metrics
	random    int
	resets    int
	failures  []string
	allActs   []string
	verbs     map[Verb]int
}

// uncovered returns the actions that the run did not take.
func (r *expResult) uncovered() []string {
	var out []string
	for _, n := range r.allActs {
		if !r.m.sets[0][n] {
			out = append(out, n)
		}
	}
	return out
}

// expRun drives the model through the simulated SUT for some steps.
func expRun(o runOpts, steps int, budget planBudget) (*expResult, error) {
	mm := newMbtModel(o.cfg)
	pl, err := newPlanner(mm, o.cov, o.depth, o.seed, o.randomness)
	if err != nil {
		return nil, err
	}
	s := newSim(o.cfg, o.seed+1)
	st := newState(o.cfg)
	res := &expResult{m: newMetrics(len(mm.acts)), verbs: map[Verb]int{}}
	for _, a := range mm.acts {
		res.allActs = append(res.allActs, a.name(o.cfg))
	}
	settle := Act{Verb: VSettle, Slot: -1, VM: VMAny, Pool: noPool}
	for n := 1; n <= steps; n++ {
		a := settle
		if n > 1 {
			res.branching = append(res.branching, len(mm.enabledActs(st)))
			b := budget
			if !b.Deadline.IsZero() {
				b.Deadline = time.Now().Add(o.planTime)
			}
			var info planInfo
			a, info = pl.plan(st, b)
			res.planTimes = append(res.planTimes, info.Elapsed)
			res.depths = append(res.depths, info.Depth)
			res.paths = append(res.paths, info.Paths)
			if info.Random {
				res.random++
			}
			if info.Reset {
				res.resets++
			}
		}
		next := st.apply(a)
		after := next
		res.verbs[a.Verb]++
		if a.Verb == VSettle {
			s.do(n, a)
			v, adopted := checkState(next, s.observe(n, 1), "")
			if v.Status != VOK {
				res.failures = append(res.failures, fmt.Sprintf("step %d %s: %s", n, a.name(o.cfg), v.Msg))
				return res, nil
			}
			after = adopted
		} else {
			d := s.do(n, a)
			if v := checkDone(expectDone(st, next, a, n), d); v.Status != VOK {
				res.failures = append(res.failures, fmt.Sprintf("step %d %s: %s", n, a.name(o.cfg), v.Msg))
				return res, nil
			}
			after = adoptDone(next, a, d)
		}
		pl.mark(st, a, after)
		res.m.add(n, o.cfg, st, a, after)
		res.growth = append(res.growth, res.m.counts())
		st = after
		res.steps = n
	}
	return res, nil
}

func stats(xs []int) (mean float64, med, max int) {
	if len(xs) == 0 {
		return 0, 0, 0
	}
	s := append([]int(nil), xs...)
	sort.Ints(s)
	sum := 0
	for _, x := range s {
		sum += x
	}
	return float64(sum) / float64(len(s)), s[len(s)/2], s[len(s)-1]
}

func durStats(ds []time.Duration) (mean, med, max time.Duration) {
	if len(ds) == 0 {
		return
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	var sum time.Duration
	for _, d := range s {
		sum += d
	}
	return sum / time.Duration(len(s)), s[len(s)/2], s[len(s)-1]
}

func runExperiment(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("experiment", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c commonFlags
	c.register(fs, false)
	exp := fs.String("exp", "all", "branching, plantime, growth or all")
	maxDepth := fs.Int("max-depth", 4, "plantime: deepest depth")
	planTime := fs.Duration("plan-time", 60*time.Second, "time budget of one plan")
	mixes := fs.String("mixes", "C1;C1,C2;C1,C3;C1,C2,C3;C1,C2,C3,C4", "growth: coverage mixes, ';' separated")
	online := fs.Bool("online", true, "with the any slots of the profile")
	showUncovered := fs.Bool("uncovered", false, "growth: list the actions not taken")
	cpuProfile := fs.String("cpuprofile", "", "write a CPU profile to this file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintf(stderr, "mbt-cxl: %v\n", err)
			return 2
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintf(stderr, "mbt-cxl: %v\n", err)
			return 2
		}
		defer pprof.StopCPUProfile()
	}
	o, err := c.options(*online, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "mbt-cxl: %v\n", err)
		return 2
	}
	o.planTime = *planTime
	o.header = strings.Replace(o.header, "--plan-time 0s", "--plan-time "+planTime.String(), 1)
	steps := c.steps
	if steps <= 0 {
		steps = 200
	}
	budget := planBudget{MaxPaths: o.maxPaths}
	if o.planTime > 0 {
		budget.Deadline = time.Now() // set per plan
	}
	fmt.Fprintf(stdout, "# mbt-cxl experiment: gofmbt %s, %s\n", gofmbtFlavor, o.header)
	if *exp == "branching" || *exp == "all" {
		oo := o
		oo.depth = 1
		r, err := expRun(oo, steps, budget)
		if err != nil {
			fmt.Fprintf(stderr, "mbt-cxl: %v\n", err)
			return 1
		}
		mean, med, max := stats(r.branching)
		fmt.Fprintf(stdout, "branching profile=%s actions=%d steps=%d enabled: mean %.1f median %d max %d\n",
			o.cfg.Profile, r.m.total, r.steps, mean, med, max)
		reportFailures(stdout, r)
	}
	if *exp == "plantime" || *exp == "all" {
		for d := 1; d <= *maxDepth; d++ {
			oo := o
			oo.depth = d
			n := steps
			if d >= 3 && n > 30 {
				n = 30
			}
			if d >= 4 && n > 8 {
				n = 8
			}
			r, err := expRun(oo, n, budget)
			if err != nil {
				fmt.Fprintf(stderr, "mbt-cxl: %v\n", err)
				return 1
			}
			mean, med, max := durStats(r.planTimes)
			_, _, maxPaths := stats(r.paths)
			pm, _, _ := stats(r.paths)
			dm, _, _ := stats(r.depths)
			fmt.Fprintf(stdout, "plantime profile=%s coverage=%s depth=%d steps=%d: mean %s median %s max %s, paths mean %.0f max %d, depth completed mean %.2f, random %d\n",
				o.cfg.Profile, o.cov, d, r.steps, mean.Round(time.Microsecond), med.Round(time.Microsecond), max.Round(time.Microsecond), pm, maxPaths, dm, r.random)
			reportFailures(stdout, r)
		}
	}
	if *exp == "growth" || *exp == "all" {
		for _, mix := range strings.Split(*mixes, ";") {
			cov, err := parseCoverage(mix)
			if err != nil {
				fmt.Fprintf(stderr, "mbt-cxl: %v\n", err)
				return 2
			}
			oo := o
			oo.cov = cov
			r, err := expRun(oo, steps, budget)
			if err != nil {
				fmt.Fprintf(stdout, "growth profile=%s coverage=%s: %v\n", o.cfg.Profile, cov, err)
				continue
			}
			var marks []string
			for _, at := range []int{10, 25, 50, 100, 200, 400, 800, 1600} {
				if at <= len(r.growth) {
					g := r.growth[at-1]
					marks = append(marks, fmt.Sprintf("@%d C1=%d C2=%d C3=%d C4=%d", at, g[0], g[1], g[2], g[3]))
				}
			}
			mean, _, max := durStats(r.planTimes)
			fmt.Fprintf(stdout, "growth profile=%s coverage=%s depth=%d steps=%d: %s; C1 %d/%d actions, last new C1 at step %d, C2 at %d; resets %d random %d; plan mean %s max %s\n",
				o.cfg.Profile, cov, o.depth, r.steps, strings.Join(marks, "; "), len(r.m.sets[0]), r.m.total, r.m.lastInc[0], r.m.lastInc[1],
				r.resets, r.random, mean.Round(time.Microsecond), max.Round(time.Microsecond))
			var vc []string
			for _, v := range []Verb{VCrash, VWrite, VRead, VLeaseGet, VLeasePut, VSettle} {
				vc = append(vc, fmt.Sprintf("%s=%d", v, r.verbs[v]))
			}
			faults := 0
			for v, n := range r.verbs {
				if v.fault() {
					faults += n
				}
			}
			ctx := map[string]int{}
			for x := range r.m.sets[1] {
				for _, w := range []string{"lease-numa", "lease-dax", "blocked", "unblocking", "hole", "steer-on", "steer-off"} {
					if strings.Contains(x, w) {
						ctx[w]++
					}
				}
			}
			var cs []string
			for _, w := range []string{"lease-numa", "lease-dax", "blocked", "unblocking", "hole", "steer-on", "steer-off"} {
				cs = append(cs, fmt.Sprintf("%s=%d", w, ctx[w]))
			}
			fmt.Fprintf(stdout, "  verbs %s faults=%d; C2 contexts %s\n", strings.Join(vc, " "), faults, strings.Join(cs, " "))
			if *showUncovered {
				fmt.Fprintf(stdout, "  uncovered: %s\n", strings.Join(r.uncovered(), ", "))
			}
			reportFailures(stdout, r)
		}
	}
	return 0
}

func reportFailures(w io.Writer, r *expResult) {
	for _, f := range r.failures {
		fmt.Fprintf(w, "  ORACLE DISAGREES WITH THE SIMULATED SUT: %s\n", f)
	}
}
