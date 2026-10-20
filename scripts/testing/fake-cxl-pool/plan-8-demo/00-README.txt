plan-8-demo: a live demo of CXL memory sharing, and shared local devices
=========================================================================
Task (user, 2026-10-19): a demo of CXL memory sharing in two use cases,
each with one writer and three readers:
  1. local: all of them use the same CXL memory device that is local to a
     node of the two-node cluster (n4-cxl-shared-2, VM2, has one);
  2. pool:  the device is allocated from the pool dynamically: the writer
     takes it first and keeps it, readers ask meanwhile and wait until the
     writer frees it, then share it.
Shown in up to six terminals (2 columns x 3 rows, each at most 50
characters wide and 10 rows tall) that the audience sees at once: status
of ResourceSlices, ResourceClaims, node drivers, CXL devices of each node,
the pool server, the demo containers, and traces (kernel, scheduler, API
server, dra-driver-cxl). One or more terminals take the presenter's
commands. Steps small and slow enough to follow, with room to stop and
show details.
Plus: a new e2e test that follows the local script closely (writer and
three readers on one node, all with dynamic allocations, i.e. leases),
run on the n4-cxl-shared-* VMs; fix what turns out broken. Nothing
committed.

Decision (user, 2026-10-19): the driver could not share a local device's
bytes between containers through leases (01-findings F1). Add shared
local devices. Then (user): before implementing, a Fable agent designs
local sharing in the big picture, static (claims) and dynamic (leases),
in ../plan-9-local-cxl-sharing/; 02-shared-local-design.txt is fitted to
it afterwards.

Files
  00-README.txt              this file
  01-findings.txt            what exists, what was missing, constraints
  02-shared-local-design.txt the contract of shared local devices
  03-demo-design.txt         the terminal layout, what each view shows and
                             why, the two scripts step by step, Q&A zooms
  04-plan.txt                streams, ownership, order, checks
  05-status-<S>.txt          one per stream; 09-status.txt orchestrator
  demo/                      the demo itself: README (how to run it),
                             bin/ (views, step runners, setup, teardown),
                             manifests
Paths: N = ~/github.com/containers/nri-plugins, D = N/cmd/plugins/dra-driver-cxl,
E = N/test/e2e/memory.test-suite/dra-driver-cxl, P = N/scripts/testing/fake-cxl-pool.
