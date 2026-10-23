plan-11-manage-all-containers: keep containers off CXL nodes they did not claim
==============================================================================
Written 2026-10-22 (orchestrator). Branch 5jg-cxl at ed99fcc44 plus the
uncommitted plan-8/plan-10 files. Nothing committed by this plan.
Paths: N = ~/github.com/containers/nri-plugins, D = N/cmd/plugins/
dra-driver-cxl, E = N/test/e2e/memory.test-suite/dra-driver-cxl, H =
N/test/hw/dra-driver-cxl-local, R = ~/github.com/askervin/nri-plugins/
test/hw/dra-driver-cxl-local (hw report and results, read only).

Task (user, 2026-10-22)
-----------------------
The hw report (R/REPORT.md, finding A): containers without claims have
the CXL node that the driver creates in their cpuset.mems and can use
it. The driver gets an option for how it manages the memory of all
containers by default: soft (memory policy), hard (allowed mems, may
OOM-kill) or none; later maybe per kind of container (with/without
claims, QoS class). First requirement only: with hard management (could
be the default), when the driver has created a CXL NUMA node, no
container that has not claimed memory on it has it in cpuset.mems.
Different from steering, which is for containers with claims. Research
in this directory, pick e2e tests that check it (the running containers
of the control plane are such containers), make the e2e tests pass,
extend the hw tests, run them with TARGET=root@cwf.

The answer in one screen
------------------------
- Option: driver configuration containerMemory.default: allowed-mems
  (default, hard), mempolicy (reserved, refused as not implemented),
  none (the old behavior; needed next to a resource policy that sets
  cpuset.mems, NRI refuses two owners). An object, so per-container
  values can be added later.
- Fenced nodes F: the NUMA nodes on which the driver onlines CXL memory
  (local numa slices, pool numa devices, also of leases); seeded from
  the prepared claims at start, only grows. Region devices of the BIOS
  are not fenced. While F is empty nothing is touched.
- A fenced container (every container that cgmpolmgr does not steer)
  gets cpuset.mems = (its own nodes - F) + its pool numa claim nodes +
  its lent nodes. New containers: a CreateContainer adjustment, only
  when it changes something. Running and created ones: a fence pass of
  NRI UpdateContainers, run before the memory of a new node goes online
  (inside Prepare), so no container ever sees the node; after a restart
  first when the lease broker has re-applied its lends. Lending uses
  the same formula. Steered containers stay cgmpolmgr's.
- Checks: a helper lists every container of a node and its effective
  mems; e2e test10, test12, test14 (also over a driver restart), test15
  use it, with the kube-system containers as the containers without
  claims; hw test1, test2, test3 the same on cwf.

Files
-----
  00-README.txt     this file; status at the end when done
  01-findings.txt   what exists, constraints (NRI ownership, deadlock
                    rules, restart and lends, pool claims)
  02-design.txt     decisions D1-D12
  03-plan.txt       streams DRV, DOC, E2E, HW; rules; verification
  04-status-*.txt   status of each stream
  05-review.txt     review of the driver change
  06-runs-*.txt     e2e and hw runs
  09-status.txt     final status

Status
------
2026-10-22: findings, design and plan written. Phase 1 done: DRV (driver,
unit tests), DOC, E2E and HW edits. Review 05-review.txt: two races (V1
concurrent Fence of one node, V2 update racing with container creation)
fixed by DRV. Image nri-dra-driver-cxl-image-d8a0980797d9.tar (tag
v0.15.0-35-ged99fcc44-dirty) built.
Done. e2e: test10-test19 and test01 PASS (06-runs-E2E.txt). hw on cwf:
finding A fixed, only the claiming containers have the CXL node, also
after a driver restart; remaining failures are findings B and C
(06-runs-HW.txt). Unit tests, vet, lint clean. Nothing committed.
Details: 09-status.txt.
