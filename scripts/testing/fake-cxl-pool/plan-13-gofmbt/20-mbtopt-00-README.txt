plan-13 / 20-mbtopt: immutable states, de-duplication and the cost of
the search
====================================================================
Started 2026-10-27 (orchestrator). Branch 5jg-cxl at fa00607e1 (plan-13
committed, documents only after it). gofmbt: local branch 5jo-mbt-cxl
at 951575f of ~/github.com/askervin/gofmbt. Host: 256 CPUs, go 1.26.3.
  P  scripts/testing/fake-cxl-pool/plan-13-gofmbt/ (these files)
  T  test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/
     test90-gofmbt-reliability
  M  T/model (Go module github.com/containers/nri-plugins/test/e2e/
     mbt-cxl, binary mbt-cxl)
  G  ~/github.com/askervin/gofmbt/gofmbt (package gofmbt)

Task (user, 2026-10-27)
-----------------------
Study whether gofmbt States should be immutable once created (the
suspicion: anything else brings complexity and hard-to-comprehend
hacks), and whether de-duplication of states, which 02-design.txt
mentioned, belongs to the modeler rather than to the test generator
(the modeler is free to cache states and transitions; memory against
CPU, the balance depends on what is modeled). Depending on the
outcomes, plan how the test90 model and possibly gofmbt should change
to become simpler and/or faster. Ideas on the table: State and Action
interfaces with super-fast Marshal/Unmarshal to and from short
(possibly fixed-length) byte arrays, bits used sparingly, so that the
model can de-duplicate states efficiently and gofmbt's cover.go gets
faster; the encodings need not recover the full State/Action, indexes
into a table of human-readable names would do. Study performance and
memory effects, keeping in mind that the best path of a given length
is exponential anyway: optimizations without a significant effect on
search depth or time, which make modeling harder, are not to be done.
Use Opus agents (medium/high thinking) to implement model and gofmbt
changes and measure them; document findings, alternative designs and
their benefits in 20-mbtopt-* files; summarize; leave the best option
in test90 and, where it belongs, in gofmbt. gofmbt must stay a
minimal test generator with nothing dra-driver-cxl specific. Finally,
run long tests from the new test90 model with Opus/medium agents and
debug new bugs with Opus/xhigh agents.

Files
-----
  20-mbtopt-00-README.txt       this file, status log
  20-mbtopt-01-findings.txt     how states are treated today, the
                                baseline cost and profile, the
                                de-duplication potential, memory
  20-mbtopt-02-design.txt       the alternatives and their benefits,
                                provisional decisions
  20-mbtopt-03-plan.txt         streams, measurement protocol,
                                acceptance criteria
  20-mbtopt-04-status-MODEL.txt stream MODEL (canonical states,
                                cached transitions and coverage
                                strings in M)
  20-mbtopt-04-status-GOFMBT.txt stream GOFMBT (immutability contract,
                                simplification, measurements in G)
  20-mbtopt-04-status-DEBUG.txt stream DEBUG (the model error M8 of
                                the baseline simulated run)
  20-mbtopt-05-results.txt      the measurements side by side, the
                                decisions, what was left in test90
                                and in gofmbt
  20-mbtopt-06-runs.txt         long runs of the new model: simulated
                                SUT and the cluster

Status
------
2026-10-27 10:30 baseline measured by the orchestrator (01-findings):
  depth 3 on the full profile 541 ms mean / 2.36 s max per plan on
  this host, 57% of the time in the model's transitions, 34% in
  coverage strings; a depth-3 tree has 3-5x more nodes than distinct
  states; 50-60 MB RSS. The baseline simulated run (seed 1, default
  mix, depth 3) stops at step 330 on an oracle/simulator disagreement
  (M8, stream DEBUG). Design and plan written; streams MODEL, GOFMBT
  and DEBUG started in parallel in worktrees (/tmp/mbtopt/wt-A,
  /tmp/mbtopt/gofmbt-B branch 5jo-mbt-immutable, /tmp/mbtopt/wt-C).
2026-10-27 11:35 DEBUG done (20-mbtopt-04-status-DEBUG.txt): M8 was
  the simulated SUT's error (its scheduler hold of a device never
  ended, so a contender behind a decoder hole was promoted to Running
  where a real kernel refuses the region); the fix exposed three model
  errors it had hidden (M9a-c: data of a stalled numa contender
  unknown; no window where a contender stalled only by the hold races
  with a release of its device on the same stack; a handover prepare
  added by ctrl-start keeps its order) -> amendment A21 proposed; 3
  commits on 5jg-cxl-mbtopt-C (/tmp/mbtopt/wt-C), also experiment
  --steps-out/--from for 0.05 s replays of a failing run; depth 2
  soak of 95 seeds x 1000 steps: 0 disagreements (75 of 95 before).
  Open O1: experiment runs are not reproducible beyond the first
  scheduler hold (~step 260 for seed 1) because the oracle reads the
  wall clock; the @100/@200 marks of seed 1 are the safe acceptance
  numbers. Waiting for MODEL and GOFMBT before integrating.
2026-10-27 12:20 GOFMBT done (20-mbtopt-04-status-GOFMBT.txt): branch
  5jo-mbt-immutable (/tmp/mbtopt/gofmbt-B, 3 commits, fast-forward of
  5jo-mbt-cxl, API identical): states immutable by contract (A1),
  the per-call String() memo machinery removed (cover.go 746 -> 651
  lines, stateStrs/sameState/covCtx fields gone), Walkable says the
  caller owns StepsFrom's slice, doc.go section on caching and
  de-duplication as the model's; TestCachingWalkable replaces the
  mutation test. Results identical (property/reference tests,
  player example, test06-fuzz output); test90 plan times unchanged
  within noise (gofmbt is <2% of its profile). The toy with an
  unmemoized Fprintf String() is 56-68% slower with
  CoverStateActions (one String() per walked step instead of per
  parent); with a memoized toy state 0-7% faster. A2 (library memo)
  not adopted; C2 short keys rejected (0-5% in the toy, the map is
  ~6% of the model's plan); C3 weights rejected (~3% left after
  precomputed strings). Waiting for MODEL.
2026-10-27 13:40 MODEL done (20-mbtopt-04-status-MODEL.txt): canonical
  key + intern table + per-plan transition and coverage-string caches
  (canon.go), -31% at depth 3 and -40..45% in growth runs, -12% at
  depth 4 (cache bounded at 150k states), RSS 40 MB -> ~0.72 GB
  (SetMemoryLimit 768 MiB unless GOMEMLIMIT); short coverage keys
  0-2% (reverted); weight copies cost ~17% per path (no gofmbt
  weight feature). Found that the experiment protocol itself was not
  reproducible (the oracle's wall clock): --step-time D gives it a
  virtual clock. Also a 51-line patch for outcomesCut (struct map
  keys instead of strings, -11..16% per path).
  INTEGRATION (orchestrator): branch 5jg-cxl-mbtopt-A (/tmp/mbtopt/
  wt-A) = MODEL's 3 commits + DEBUG's 3 (conflicts in experiment.go
  and online.go resolved: both clocks kept, --step-time wins over the
  wall clock, a replayed #now record over both) + the outcomesCut
  patch + a --plan-states flag (default 150000, 0 = no cache) for the
  memory/time sweep. gofmbt 5jo-mbt-cxl fast-forwarded to 0ccea8c
  (GOFMBT's branch). Integrated binary, protocol with --step-time 1s,
  concurrent with the stage-0 binary: depth 3 313 ms mean / 1.35 s
  max (stage 0: 561 / 2.40), depth 4 4.07 s / 8.74 s (5.91 / 12.8),
  growth seed 1 279 ms (631 concurrently), seed 2 347 ms; @100/@200
  coverage identical; RSS 0.70-0.76 GB. The cache-bound sweep
  (--plan-states 0, 20k, 50k, 150k, 600k) is running for 05-results.
2026-10-27 15:10 Integration done, results written (20-mbtopt-05-
  results.txt). Sweep of the plan cache on one binary: no cache d3
  405 ms / 1.80 s at 60 MB; 150k states 286 / 1.22 at 751 MB; depth 4
  -6% only; under GOMEMLIMIT=384MiB the cache is slower than none.
  Decision: --plan-states 0 by default (the memory-free improvements
  give -27% d3 against the baseline; the cache is the opt-in knob),
  test90 defaults otherwise unchanged. Main checkout's model = branch
  5jg-cxl-mbtopt-A (6ae5abbd7, 9 commits), uncommitted on 5jg-cxl;
  gofmbt 5jo-mbt-cxl = 0ccea8c. Streams RUNS-SIM (long simulated
  runs, 20-mbtopt-06-runs-SIM.txt) and RUNS-CLUSTER (L10: 2 h test90
  on the cluster, seed 10, 20-mbtopt-06-runs-CLUSTER.txt) started.
2026-10-27 16:10 RUNS-SIM done (20-mbtopt-06-runs-SIM.txt): 57 runs of
  the final binary, all PASS, no oracle/simulator disagreement; the
  cache (--plan-states 150000) halves the plan and wall time of 3000-
  step runs at ~730 MB and produces byte-identical steps files. Depth
  4 without the cache hits the 60 s experiment --plan-time once per
  seed (not reproducible across planner speeds). L10 on the cluster
  still running.
2026-10-27 17:00 L10 PASS (20-mbtopt-06-runs-CLUSTER.txt): 2 h, seed 10,
  2755 steps, clean teardown, no oracle difference, no panic;
  planning 0.48 s/plan (L8/L9 0.66-0.75), bash waited 4.75 min
  (9.9-10.5). DONE. Also written (user's follow-up): a skill on
  applying gofmbt elsewhere, ~/github.com/askervin/gofmbt/skills/
  model-based-testing/SKILL.md (committed on 5jo-mbt-cxl, 484 lines;
  doc.go points to it; symlinked as .claude/skills/gofmbt-model-based-
  testing of this checkout).
