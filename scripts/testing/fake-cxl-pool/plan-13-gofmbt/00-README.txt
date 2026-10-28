plan-13-gofmbt: model-based reliability testing of the CXL DRA driver
=====================================================================
Started 2026-10-24 (orchestrator). Branch 5jg-cxl at ed0370b24 (plan-12
committed). Task: ../5jo-task-apply-mbt.txt.

Task (user, 2026-10-24)
-----------------------
Apply model-based testing with gofmbt (~/github.com/askervin/gofmbt) to
the CXL DRA driver and the pool controllers: a model of the allocations
(claims and leases; local and pool; numa, dax, block, fs; read-only and
read-write; exclusive and shared; whole device and slice; fenced or
not; steered or not; ...) and of the faults the driver must survive
(pod exit and delete, container crash and restart, pool controller
crash and restart, driver crash and restart, ...), from which gofmbt
generates long tests that run in the three-node e2e cluster with the
three pools of test19-many-pools, with many pods created and destroyed.
Study how to integrate gofmbt into a new e2e test
n4-cxl-shared-2/test90-gofmbt-reliability: a generated code.gen.sh, or
code.var.sh building and running the model and executing steps on-line
while the generator already plans the next one. Prototype integration
options, model variants and verification; run real trials; extend
gofmbt where it makes integration much easier; document findings,
designs, plan, implementation, and every driver bug found (fix the easy
ones).

Files
-----
  00-README.txt            this file
  01-findings-gofmbt.txt   the library: API, generation, cost, limits
  01-findings-e2e.txt      the e2e framework and helpers for actions
                           and checks, faults available, durations
  01-findings-driver.txt   the allocation matrix, state and recovery,
                           error scenarios, invariants
  02-design.txt            integration options, model options,
                           verification options, decisions
  03-plan.txt              prototypes and streams
  04-status-*.txt          stream status files
  05-review*.txt           reviews
  06-runs.txt              trial runs in the e2e cluster
  07-results.txt           the prototypes measured, the answer to
                           the integration question
  bug-NN-*.txt             one file per bug found
  08-analysis-*.txt        analysis of a run failure (L2)
  09-status.txt            final status

Status
------
2026-10-24: research started (gofmbt read and measured by the
  orchestrator; e2e helpers and the driver by two agents); gofmbt
  extension (exported coverage, incremental search, budget, Do fix)
  started on the local gofmbt branch 5jo-mbt-cxl.
2026-10-24: findings done (01-findings-e2e.txt, 01-findings-driver.txt;
  precedent found: test06-fuzz of topology-aware already generates its
  script off-line with gofmbt). Design 02-design.txt (decisions D1-D7:
  on-line coproc with planning ahead as the main mode, off-line
  code.gen.sh and replay as modes of the same program; slot model with
  asynchronous create/delete and settle; model as oracle over one JSON
  observation per settle), plan 03-plan.txt, contract 04-contract.txt.
  Streams MODEL (Go, off-line) and EXEC (bash, owns the cluster)
  started in parallel with GOFMBT.
2026-10-24: GOFMBT done (04-status-GOFMBT.txt: 7 commits on the local
  branch, depth 3 ~7x faster, budgeted search); its review started.
  EXEC done (04-status-EXEC.txt): executor, observer, setup, new fault
  helpers; stub run PASS; the first model runs (off-line and on-line)
  stopped on real findings: E1 containerd restart loses NRI for good
  (bug-01, fix being made: exit on close like the other plugins),
  S1/S2 CXL decoders stay committed after an out-of-order region
  teardown, an exclusive pool device cannot be attached again (bug-02,
  being investigated), M1 an oracle error (contract amendments A1-A7).
2026-10-24: gofmbt reviewed (05-review-GOFMBT.txt: no bug; test06-fuzz
  output identical, 7x faster; F1-F3 risks fixed, branch at 8283135).
  bug-01 fixed in the driver (exit on NRI loss, unit tests with the
  real stub), seen working in the cluster. bug-02 root-caused: a Linux
  decoder-stack limit (a region destroyed below the top blocks every
  new region of that port until the regions above are gone); the model
  predicts it (amendments A9, A10); pool-vm-reset checks committed
  decoders; memctl names the hole in its error. bug-03: stale sysfs of
  freed decoders (cosmetic, kernel). Image 571d3f262db0 with the fixes.
2026-10-24: MODEL done (04-status-MODEL.txt). Trials (06-runs.txt): P1
  off-line PASS (47 steps); X1 replay confirmed bug-04 (a steered
  container stays throttled after a driver crash; FIXED, verified in
  V14); P2 on-line lock-step stopped on an exec transient after a
  kubelet restart (executor retry added); P3 on-line with planning
  ahead, full profile: 121 steps, every plan reused, then bug-05 (a
  numa lease lost when its requester restarts; V14 showed a second
  case: a fence update of a container that is not running yet is lost;
  fix in progress). bug-01 verified in V14. Review of MODEL+EXEC
  (05-review.txt, R1-R14) -> amendments A11-A17, fixes in both streams
  (EXEC done). EXEC found S3 = bug-06 (the node's ResourceSlice gone
  20-30 s after a kubelet restart; being looked at).
2026-10-24..26: long runs L1-L9 (06-runs.txt); bugs 07-10 found and
  fixed (bug-08 is Kubernetes'), model errors M3-M7 fixed, an
  independent pool reference fuzzed off-line. L8 (2663 steps) and L9
  (2946 steps, final image 392e3abf548d) PASS 2 h each. DONE: final
  status 09-status.txt, results 07-results.txt.
2026-10-27: gofmbt's extensions merged into its main (bc12d42); test90's
  model/go.mod requires it, code.var.sh builds with GOWORK=off, the
  stock build is gone (04-status-MODEL.txt 19). L10 (257 steps, 10
  min) PASS on that build.
2026-10-27: bug-08 fixed in kube-scheduler (10-scheduler-requeue-
  fix.txt; kubernetes branch 5jr-dra-requeue, commit 4de1561b97c),
  deployed on vm2, verified A/B; model flag --stall-window (A28).
  Persistent devices researched (11-findings-persistent.txt), adopted
  as A22-A27; executor and model work started.
