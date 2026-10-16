plan-6-cxl-driver-in-nri-plugins: move the CXL DRA driver to nri-plugins?
=========================================================================
Written 2026-10-16. Task: ../5jg-task-cxl-driver-to-nri-plugins.md.

Question
--------
kubelet-cxl-plugin (intel-resource-drivers-for-kubernetes,
cmd/kubelet-cxl-plugin) is two DRA drivers (cxl.generic, cxl-pool.generic),
an NRI plugin and a lease broker in one process. Is it sensible to move it
into nri-plugins, and in which shape: a resource policy on pkg/resmgr
(nri-resource-policy-cxl), a DRA driver of its own (nri-dra-driver-cxl),
or something else?

Answer in one screen
--------------------
- Yes, move it. It already lives on nri-plugins: four N packages do its
  hardware and cgroup work, every e2e test and the reference pool
  controller are in N, and the price today is a fork pseudo-version per
  change and constants duplicated across modules. It is the only NRI user
  in D, and the reason D moved to Kubernetes 1.37. Nothing is released, so
  names and packaging can still change for free.
- The problem that matters most cannot be solved where the driver is now:
  on a node that also runs topology-aware or balloons, cpuset.mems (and
  memory.high, thread memory policies) has two writers, the policy and
  the driver's steering and lending. Only the repository that owns both
  sides can give a container one owner of those fields.
- Not as nri-resource-policy-cxl alone: one policy per node would make CXL
  and CPU management mutually exclusive. CXL memory is a resource class of
  a node, not a node-wide policy.
- Not only as nri-dra-driver-cxl: that fixes where the code lives, not the
  two owners of cpuset.mems.
- Target (option C): the CXL code becomes an engine that resmgr hosts next
  to any policy. resmgr owns the NRI connection, the kubelet plugins and
  cpuset.mems, composed from the policy's nodes, the engine's steering
  (which restricts as well as adds) and its leases; the engine owns the
  CXL devices, claims and leases, and runs its blocking operations without
  the resmgr lock (persisted intent, hardware work, then a short commit;
  lock order resmgr -> engine only). nri-resource-policy-cxl remains as
  packaging: resmgr + a policy that manages no CPUs + the engine.
- Path (option D): stage 1 moves the driver as a standalone binary
  nri-dra-driver-cxl (behaviour unchanged, the six e2e tests green, D
  without CXL code); stage 2 turns it into an engine with a host interface
  and one memory composition path (already lifts "a steered container
  cannot take a numa lease"); stage 3 lets resmgr host the engine
  (multi-driver DRA, two-phase claims, components, composition in the
  cache, CXL nodes excluded before discovery, hand-off, credentials);
  stage 4 images, helm (hostPID for the broker), and the fate of the
  standalone host.
- Open design risks of stage 3, written down in 02 C and 03 section 4:
  the exact memory composition formula, memory.high and thread policy
  rules next to nri-memory-qos and mpolset, crash-safe claim phases, and
  the hand-off from the standalone host. 05-review-1.txt lists what an
  independent review found and how the plan answers it.

Reading order
-------------
  00-README.txt           this file
  01-findings.txt         facts with file:line: the driver (F1-F9), its ties
                          to N (F10-F16) and to D (F17-F21), testing
                          (F22-F27), resmgr's NRI and DRA layers (F28-F40),
                          ownership conflicts on a node (F41-F47), build and
                          deployment (F48-F53), and what resmgr lacks to
                          host the driver (G1-G15)
  02-options.txt          options Z (stay), A (resmgr policy), B1/B2
                          (standalone), C (resmgr component), D (B1 then
                          C), E (split the halves); criteria K1-K10 and a
                          comparison table; where the driver's own events
                          go in each option
  03-recommendation.txt   why D, and stages 1-4 with what moves where, what
                          changes, e2e, and when each stage is done; risks
  04-open-questions.txt   Q1-Q10: maintainer consent, driver names, binary
                          names, the standalone host, history, cxl tools,
                          docs, file headers, D after the move, config
  05-review-1.txt         an independent review against the sources, and
                          what it changed

Paths used in all files
-----------------------
  D = ~/github.com/intel/intel-resource-drivers-for-kubernetes
  N = ~/github.com/containers/nri-plugins
  P = N/scripts/testing/fake-cxl-pool
  E = N/test/e2e/memory.test-suite/memory-policy

Background read for this study: plan-2-dra/00-overview.md (D20-D25: why
the pool controller is in N and memctl moved to N), plan-4-cxl-live-
attach-local/08-analysis-mixed-modes.txt, plan-5-api-consistency/
{00-README,02-design,04-open-questions}.txt, D/doc/cxl/*.md, P/README.md,
E/dra.source.sh and E/n4-cxl-shared-2/test10-test15.
