plan-8 20-official: the demo becomes official
=============================================
Task (user, 2026-11-03), in any order:
1. Move the demo from scripts/testing/fake-cxl-pool/plan-8-demo/demo to
   test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/demo01-share-write-read.
2. Bring every current case (local, pool, pool-shared-fs) and every view
   (t2-t6) up to the current driver: claims use MemoryConfig; all status
   shown must be valid. The user's topmost commit 5325df62c makes the
   trace (t5) a pure sequence of lines (scrollable), the other views keep
   painting a whole screen; check and keep it.
3. New case 1: like the others in structure, any filesystem, one writer
   and three readers.
4. New case 2: a wizard: simple options choose a pod or claim among the
   combinations that the driver offers (local and pool devices, exclusive
   and shared, numa, dax, block, fs, the whole device or a slice, any
   device or one by serial, volatile or persistent), generate the YAML of
   the claim and the pod, create them, and delete any or all created
   objects. Both to demonstrate a case and to show what its YAML looks
   like.
Overview, findings, design, plan, implementation status in these
20-official-*.txt files.

Branch 5jg-cxl at 5325df62c (the user committed plan-14 as cfb1af29c,
26940606b). D = the demo directory (old: plan-8-demo/demo, new:
.../n4-cxl-shared-2/demo01-share-write-read), N = nri-plugins.

The answer in one screen
------------------------
- The move: run_tests.sh knows suite/policy/topology/test and runs only
  test* directories of a topology, so demo01-share-write-read is no test
  (suite runs skip it, as they must: setup leaves the demo up) and its
  setup and teardown stay a private suite of links inside it (D/e2e), as
  today, with shorter links. A .gitignore in D keeps run/ and captures/
  out of git and lets testdata/ and bin/tools/ in (a global rule hides
  them today).
- Current cases: checked against the driver as it is now (MemoryConfig,
  per-result CDI markers, fsTypes erofs by default, read-only /run/cxl,
  read-only block devices on reader nodes, new log lines), live: every
  view at the key steps of every case is compared with the ground truth
  (kubectl, cxl list, mountinfo, sysfs, the pool server) taken at the
  same moment.
- New case "pool-fs" (default ext4; xfs, btrfs): the writer formats a
  persistent 512Mi device through a block lease, mounts it read-write
  through an fs lease and writes hello.txt; a reader on the writer's node
  joins at once (one superblock), the readers of the other node wait
  (ReadWriteOnce: AttachFailed Conflict) until the writer leaves, when
  its node turns the filesystem read-only; a reader's write fails.
- New case "wizard": a setup with every kind of device (local sliced on
  both nodes, a local persistent memdev, pool exclusive and shared
  volatile, pool persistent); "demo wizard" asks a few questions (only
  valid choices are offered), shows and saves the claim and pod YAML,
  creates them, lists what it made and deletes one or all; the same as
  command line options for scripts and tests.

Files
-----
  20-official-README.txt    this file
  21-official-findings.txt  the facts
  22-official-design.txt    the design (normative): location, cases, steps,
                            views, wizard
  23-official-plan.txt      streams, order, checks
  24-official-status-<S>.txt per stream
  25-official-runs.txt      live runs and view checks
  29-official-status.txt    final status

Status
------
2026-11-03: study done, design and plan written; stream MOVE started.
2026-11-03: MOVE desk done (24-official-status-MOVE.txt): the demo is in
  D, paths and links fixed, D/.gitignore, MemoryConfig parsing, the
  regexes of the current driver, t5 cleaned up, "demo truth" added,
  selftest passes. RUN (Sonnet) runs local, pool and pool-shared-fs live
  with captures and truth dumps; FSCASE and WIZARD in phase A (new files
  only, the shared-file edits planned).
2026-11-03: run 1 and run 2 of local, pool, pool-shared-fs live: all
  steps pass; MOVE checked every view line against truth dumps (phase 2:
  six defects fixed; phase 3: run 2 all true, three zoom defects fixed,
  "attaching" for pending pool attaches). FSCASE (pool-fs) and WIZARD
  (wizard) phase B done; desk checks of the combined tree green (selftest
  219 renderings, wizard dry run 51 rows). RUN: pool-fs (ext4 x2, xfs,
  btrfs) and wizard (scripted set x2, interactive) live.
2026-11-03: DONE: every case live-verified (local, pool, pool-shared-fs, pool-fs ext4/xfs/btrfs, wizard); final status 29-official-status.txt.
