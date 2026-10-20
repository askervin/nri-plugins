plan-9-local-cxl-sharing: sharing a node-local CXL memory device
=================================================================
Written 2026-10-19, revised 2026-10-20 (Fable, design consultant) after
the user's answers to the open questions (02-options section 4). Branch
5jg-cxl at 7fd7aecda plus the uncommitted plan-7/plan-8 work. Desk work
only: no file outside this directory was changed, no VM was used.
Paths: N = ~/github.com/containers/nri-plugins, D = N/cmd/plugins/dra-driver-cxl,
E = N/test/e2e/memory.test-suite/dra-driver-cxl, P = N/scripts/testing/fake-cxl-pool,
A = N/pkg/cxl/api/api.go, docs = N/docs/memory/cxl.

The question
------------
plan-8 wants one writer and three readers sharing the same CXL memory
device that is local to a node, all through leases (cxl-request), exactly
as test13 does with a shared POOL device. The driver refuses that by
design today (01-findings F1-F3): a local device is sliced, every dax
slice is zeroed for the next tenant, and "--shared --source local" is a
usage error. The orchestrator's sketch was "a local memdev listed in the
driver configuration is published and used like a shared pool device".
The user asked for the big picture first: what sharing means for a local
device, static (claims) and dynamic (leases), fitted to everything that
exists, with the alternatives weighed; then decided the open questions.

The answer in one screen
------------------------
- Sharing bytes is a dax thing. In mode numa every container of the node
  already shares the device's NUMA node (capacity accounting, private
  zero-filled pages); shared CONTENT needs the same bytes mapped by several
  processes, which only a devdax device gives. A shared local device is
  therefore dax only, like a shared pool device (03-design D3).
- The scheduler model is the pool's, simplified: one device,
  allowMultipleAllocations, a count capacity named shares WITHOUT a
  requestPolicy. Verified in the v1.37.1 allocator (01 F31-F34): a claim
  that requests no shares consumes the whole value, which is exclusive
  use and the default; a claim with shares: "1" is one sharer; nobody
  needs to know the value, which is a bound of the model (1M), not a
  limit. The API accepts shares: "0", which would slip past an exclusive
  holder, so both drivers refuse it at Prepare. hosts, validValues and the
  pool controller's -shared-hosts disappear; the pool's claim default
  flips to exclusive (readers add shares: "1"), so claims and cxl-request
  agree: exclusive unless you ask for a share.
- The sketch is the right candidate: a whole memdev listed in the driver
  configuration (sharedDevices, a plain list matched like ignoreDevices)
  is published by cxl.nri.io with the attribute set of a shared pool
  device (shared: true, shares, no memory capacity), selected by the
  DeviceClass cxl-local-shared that plan-5 reserved for it, prepared as
  one devdax device for all its claims, content kept (never zeroed),
  readOnly per claim or lease. Named shared slices, joining an existing
  claim, a third source and "use the pool server" lose on the criteria
  (02-options).
- Leases need small changes in the broker and the API (03 section 6):
  the refusal "local devices are not shareable; share a ResourceClaim
  between pods instead" disappears (test12:631), --shared no longer
  implies the pool, the companion claim gets cxl-local-shared before
  cxl-pool-shared with shares: "1" for a share and no capacity for
  exclusive use, and the serial checks know both sources. The writer
  types "cxl-request request --serial S", the readers "--serial S
  --shared --read-only": the test13 commands, unchanged.
- Life cycle (user: "keep while shared"): the region and its dax device
  are created by the first claim and kept while the device is configured
  shared, also with no claims; destroyed when the device is no longer
  configured shared and idle; the memdev stays enabled. A device switches
  between shared and sliced use by a configuration change and a plugin
  restart; while claims of the old use exist the device is not published
  at all.
- Not now, room kept: persistent local devices (modes block and fs of
  plan-7 on a shared local pmem device), shared slices, zeroing a shared
  device when it becomes idle, a lease joining a pod's claim.

Reading order
-------------
  00-README.txt   this file
  01-findings.txt the facts, with file:line (F1-F36; F31-F36 verify the
                  capacity model and list every "hosts" occurrence)
  02-options.txt  criteria, the six alternatives, why A, the user's
                  decisions on Q1-Q5
  03-design.txt   THE CONTRACT: names, texts, behaviour, docs, the pool
                  side, the rename table
  04-plan.txt     streams S1-S5, sizes, order, tests that change, new
                  tests test17 and test18, risks
The orchestrator of plan-8 fits its 02-shared-local-design.txt and its
demo view T3 to 03 and its stream plan to 04. Implementers read 03
completely, then their section of 04, then the code 01 points at.
