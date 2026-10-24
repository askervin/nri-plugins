plan-12-steering-config: one configuration for CXL memory claims
================================================================
Written 2026-10-23 (orchestrator). Branch 5jg-cxl at ed99fcc44 plus the
uncommitted plan-11 change. Study and plan only: nothing implemented,
nothing committed.

Task (user, 2026-10-23)
-----------------------
Memory-policy steering is only one of the memory settings that users of
the CXL DRA driver may need; an opaque kind of its own for it does not
age well, and it may already keep a pool claim from carrying both a
device configuration and a memory policy. Study the configurability of
claims as a whole and suggest a generic configuration where steering is
one aspect. Steering must be very easy to switch off for a container
(HPC, big databases manage memory themselves; steering hurts them). Other
future options differ in nature: adjusting a container's memory limit,
onlining more of a CXL memory device than claimed, lifting the driver's
cpuset.mems fencing for special containers. Overview, findings, design
options with recommendations, initial plan. No compatibility to keep:
large refactorings are welcome; user-friendliness matters.

The answer in one screen
------------------------
- The hunch is right: the pool driver accepts only DeviceConfig, and
  pool numa memory is not steered at all, so a pool claim cannot carry
  a memory policy (01-findings P1). Further problems: a kind per aspect
  (P2), implicit scopes (P3), containers attributed whole claims instead
  of the requests they use (P4, a real bug), class configs replaced
  instead of merged (P5), no "do not steer" (P6), no admin-only
  settings (P10), separate node vocabulary (P11).
- Decided (02-design "Decisions", contract 04-contract.txt): one kind
  MemoryConfig, apiVersion cxl.nri.io/v1alpha1 for the node driver, the
  pool driver and pool controllers, with three sections by owner:
  pool (the pool controller: pool.opaque.<controller key>, an object the
  controller defines; the reference controller takes slot, numaNode),
  device (the kubelet plugin of the device: mode, readOnly, access,
  path) resolved per allocation result, container (the NRI plugin:
  steering; fencing from the driver configuration only) combined over
  the results a container uses.
- Layers merge field by field: DeviceClass entries, then claim entries;
  node defaults (driver configuration defaults.container, which takes
  over plan-11's containerMemory) apply per container. Classes become
  presets (Helm value deviceClassConfig for the shipped classes).
- Precise attribution: one CDI marker per allocation result, so memory
  and settings reach exactly the containers that use the request.
- Steering is opt-in: default policy none; one line opts in
  (container: {steering: {policy: auto}}), per claim, class or node.
  An unsteered container with numa claims is managed like a container
  without claims (plan-11): its claimed nodes in cpuset.mems, no memory
  policy, no memory.high; it can take numa leases.
- Pool devices behave like local ones, the same steering defaults
  included (pool numa memory steered on opt-in).

Files
-----
  00-README.txt   this file
  01-findings.txt the configuration surfaces today, problems P1-P13,
                  Kubernetes facts, blast radius
  02-design.txt   requirements, options A-M with recommendations,
                  reserved future aspects, decisions Q1-Q5
  03-plan.txt     implementation plan: streams API, DRV, CTRL, DOC, E2E,
                  HW, order, review points, verification
  04-contract.txt the normative contract of MemoryConfig v1alpha1:
                  owners, schema, resolution, markers, container
                  management, pool controller contract, defaults,
                  package API, state, leases, logs, errors, chart
  05-*            stream status files and reviews
  06-runs-*.txt   e2e and hw runs
  09-status.txt   final status

Status
------
2026-10-23: study and plan written; waiting for Q1-Q5.
2026-10-23: user answered (02-design "Decisions"): sections by owner
  pool/device/container with pool.opaque for controllers; pool devices
  like local ones; steering opt-in (default none, one line to opt in);
  admin-only: room only; one apiVersion. Pulled-in commit c55476444
  analyzed (01-findings C6: node-level memdev settings, no effect on the
  schema). Contract 04-contract.txt and plan 03-plan.txt written; phase 1
  (API, with DOC, E2E and HW edits in parallel) started.
2026-10-23: API done and reviewed (05-review-API.txt; deviations accepted
  as contract section 14); DOC and HW phase 1 done; phase 2 (DRV, CTRL)
  started; E2E phase 1 still running.
2026-10-23: DRV and CTRL done and reviewed (05-review.txt). E2E phase 1
  (and 1b: test11/12/13/16/18) done. Image
  nri-dra-driver-cxl-image-21d87b11ec23.tar (v0.15.0-38-gc55476444-dirty)
  and fake-cxl-pool binaries built. Phase 3 started: e2e runs, hw runs on
  cwf, DOC rechecks texts. Found in c55476444 (not plan-12): memdev
  serial matching misses serials written with a leading zero
  (TestMemdevSettings fails on HEAD; 05-review.txt N1).
2026-10-23: DONE. e2e: all 11 tests PASS on the final image
  nri-dra-driver-cxl-image-a68667412e60.tar after three fixes found by
  test14 (05-review.txt F1-F3, all older than plan-12: the address probe's
  open of a fresh dax device; cpuset.mems of a steered container never
  written when its plan added no node; the default minStep made two-type
  plans unsteerable). hw on cwf: no new failure (finding B as before,
  finding C no longer fails), run twice, the last on the final image.
  Unit tests, vet, gofmt clean (TestMemdevSettings fails on HEAD, commit
  c55476444). Nothing committed. Details: 09-status.txt.
