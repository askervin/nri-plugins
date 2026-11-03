plan-14-fs-read-write: any filesystem and read-write mounts in mode fs
======================================================================
Task 5jx (user, 2026-11-02; ../5jx-arbitrary-fs-mount.txt): MemoryConfig
device.mode fs mounts only erofs. Extend it to any filesystem, with
read-write mounts when the user explicitly opts in. Study what read-write
takes, which problems to expect (a filesystem read-write on two hosts
over the same memory; a writer and readers), how to mitigate them,
whether validation or the driver must refuse two read-write pods, whether
pods of one host may share a read-write mount, or mix read-write and
read-only, how the driver tells a dangerous read-write mount (pool or
local device), and allow several read-write hosts where the filesystem
supports it. README, findings, design, plan, then implementation and an
e2e test under test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2
for the crucial filesystem combinations and the refusals that prevent
corruption (crash, restart and reboot are test90's).

Branch 5jg-cxl at 78a3e449f. Shorthands: P7 = plan-7-e2e-cxl-llm-share
(20-erofs-*, 30-dynamic-bind-mount-*), P12 = plan-12-steering-config,
DOC = docs/memory/cxl.

The answer in one screen
------------------------
- Any filesystem: the plugin probes the superblock of known types
  (erofs, squashfs, ext4, xfs, btrfs, gfs2); device.fsType (optional)
  must match, or names a type the plugin does not know, which an admin
  allows on the node. Mounting means the node kernel parses what the
  writer wrote: the types are the admin's (driver configuration fsTypes).
- Read-only mounts must be on a read-only block device. A read-only
  mount on a writable one writes (xfs always, ext4 and xfs when they
  recover a log, probe 1); on a read-only one nothing writes, a dirty
  filesystem is refused, and nobody, root included, can remount it
  read-write.
- One host: one superblock per device, read-write while a claim of the
  node writes; containers get read-write or read-only binds of it, so
  writers and readers of one node share it safely. The new mount API keeps
  the superblock's state apart from the mount attributes, so the
  superblock turns read-write and back while read-only binds stay
  read-only (probe 1).
- Several hosts: a single-host filesystem is read-write on one host only,
  and nobody else may even read it meanwhile (stale caches, half-written
  metadata). Proposed: Kubernetes' ReadWriteOnce, enforced by the pool
  controller with the exclusive per-host attachments that the pool
  server already has (cross-cluster too); claims of other nodes wait. The
  node mounts read-write only when the claim status proves it, so a pool
  controller that does not do this fails writes and corrupts nothing.
- Cluster filesystems (gfs2 lock_dlm) read-write on several hosts, only
  on memory that the pool declares coherent between hosts: without
  hardware coherence one host reads the other's stale cache lines.
- Local devices: persistent local memdevs are added (user decision Q3):
  published by cxl.nri.io with persistent: true, class
  cxl-local-persistent, modes block and fs with the pool's rules on the
  same shared code; single-host by construction unless sharedDevices.

Files
-----
  00-README.txt     this file
  01-findings.txt   the facts: driver, kernel (with probe 1), VMs, prior art
  02-design.txt     requirements, options with recommendations, Q1-Q4
  probe/probe1.sh   the probe of read-only block devices and the mount API
  03-plan.txt       streams, order, checks
  04-contract.txt   the normative contract
  05-status-*.txt   stream status files and reviews
  06-runs-*.txt     e2e runs
  09-status.txt     final status

Decisions (user, 2026-11-02)
---------------------------
Q1 ReadWriteOnce through the pool controller (S3).
Q2 Cluster filesystems (gfs2 lock_dlm on coherent memory): implemented,
   unit tests only (no GFS2 kernel or cluster stack in the e2e).
Q3 Persistent local memdevs in this step.
Q4 Leases with claims: any type, --read-write, --fs-type.

Status
------
2026-11-02: study done: findings (with probe 1 on VM0) and design
  options written; waiting for Q1-Q4.
2026-11-02: decisions Q1-Q4; contract 04 and plan 03 written. For the
  e2e of local persistent memdevs no VM is recreated: a second
  fake-cxl-pool-server without a controller hot-plugs a persistent device
  into VM2 (04 section 9). Streams started: API, E2E (desk), DOC, and
  DRV-POOL, DRV-LOCAL in their study phase.
2026-11-02: DOC phase 1 done (six docs). DRV-LOCAL and DRV-POOL study
  phases done (designs in 05-status-DRV-*.txt, requests answered as
  contract amendments A1-A12). Probe 2 (01 K14-K16): an in-place upgrade
  from a read-only mount works for ext4 and xfs, not btrfs (A7). API core
  done (05-status-API.txt); DRV-POOL and DRV-LOCAL implementing, API on
  the controller (CTRL); E2E desk still running.
2026-11-02: CTRL done (05-status-API.txt). E2E desk done: test20 and
  test21 written, test10/12/14/16/17 and the test90 model updated,
  fs.source.sh (05-status-E2E.txt). Amendments A13-A15 (controller
  singleHost semantics, per-want fallback for a new exclusive attachment,
  companion config and fsType of leases). Waiting for DRV-POOL, DRV-LOCAL
  and the CTRL fix A14.
2026-11-02: CTRL A14 done; DRV-LOCAL done (A16 accepted). Waiting for DRV-POOL and its image.
2026-11-02: DRV-POOL done; image nri-dra-driver-cxl-image-1631d8c97a93.tar
  (v0.15.0-50-g78a3e449f-dirty); unit tests pass twice on the settled
  tree. RUN (Sonnet) runs test20 then test21 (06-runs-E2E.txt); an
  independent Opus review of the driver diff (07-review-DRV.txt) and DOC
  phase 2 (recheck against the code) run meanwhile.
2026-11-02: first e2e runs on image 1631d8c97a93: test20 PASS (12 min,
  first run); test21 FAIL in phase A on a test bug (sorted vs unsorted
  class list; fixed by the orchestrator, line 198), the device was
  published correctly; rerun started. Review 07-review-DRV.txt: B1
  (unexplained superblocks invisible to the safety checks), R1 (BLKROSET on
  a recorded block device of another device), S1-S7; R2 refuted (kubelet
  unprepares before the terminal phase). DRV-POOL fixes B1/R1/S1/S4/S6;
  CTRL S2/S3 after the runs.
2026-11-02: test21 rerun PASS (2m20s, every phase ran). Review fixes done:
  DRV-POOL B1 (node-wide superblocks, A17), R1 (A18), S1, S4, S6;
  DRV-LOCAL A18 wiring; CTRL S2, S3 (A19); DOC phases 2 and 3. Tree:
  gofmt clean, vet ok, go test -race ok for every changed package. Final
  image nri-dra-driver-cxl-image-b86cf8d56946.tar
  (v0.15.0-50-g78a3e449f-dirty). RUN: test20/test21 twice each, then the
  regression list and test90 for 30 minutes.
2026-11-02: DONE. On the final image b86cf8d56946: test20 and test21 PASS
  twice each, the regression list (test16, 12, 10, 13, 14, 15, 17, 18, 11,
  19) PASS, test90 30 min PASS (736 steps). Stray binaries of the agents
  removed. Final status: 09-status.txt. Nothing committed.
2026-11-03: security (user): fsTypes defaults to [erofs] (A20, DRV-LOCAL
  done). A security review (08-review-security.txt) found H-1, the
  lease socket directory writable from containers; the rest of the review
  was cut off. User: make it a read-only mount (A21, DRV-POOL), and give
  the e2e tests explicit fsTypes (E2E).
2026-11-03: security changes A20, A21 done and verified (image b0a0eb6c6c91; 09-status.txt 'Security changes'). Review beyond H-1 open (O8).
