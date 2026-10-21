plan-10-many-pools: several CXL memory pools in one cluster
============================================================
Written 2026-10-21 (orchestrator, Fable). Branch 5jg-cxl at 3e8cfe17f plus
the uncommitted plan-8 demo files. Nothing committed by this plan.
Paths: N = ~/github.com/containers/nri-plugins, P = N/scripts/testing/
fake-cxl-pool, D = N/cmd/plugins/dra-driver-cxl, E = N/test/e2e/
memory.test-suite/dra-driver-cxl, L = N/test/e2e/lib, docs = N/docs/memory/cxl.

Task (user, 2026-10-21, 5jk-task-many-pools-in-a-cluster.txt)
--------------------------------------------------------------
In a real data centre there is a CXL memory pool appliance per rack, for
some eight servers each; a cluster spans racks and therefore pools. Model
that in the e2e setup: a third VM, n4-cxl-shared-0 (VM0), joins the cluster
as a second worker and is cabled to a second fake-cxl-pool-server instance
(pool B), while VM1 and VM2 stay on the first instance (pool A). Then a new
test, test19-many-pools, runs pods that get CXL memory from devices of
different pools on different servers, and shows that a pod is scheduled to
a node that can reach a pool with a free device for its claim.
Research item: can one server be attached to several pools at once (several
CXL ports to several appliances)? If feasible and useful, test19 also runs
a third pool server (pool C) cabled to every VM, so that pods on all
nodes can share data, and one pod on one node claims devices from two
pools. Before the tests, fake-cxl-pool must support several servers:
a simple way to configure which VMs are connected to which pool, and the
pool controller must publish each pool's devices only for the nodes that
pool can reach, so that the scheduler puts a pod where its claim can be
satisfied. Minimal additional complexity; fit the existing design.

The answer in one screen
------------------------
- One pool appliance = one fake-cxl-pool-server process = one pool
  controller = one DRA pool (spec.pool.name) of the one driver
  cxl-pool.nri.io. Nothing merges pools: that is the real-world shape
  (docs pool.md: "a pool controller, one per pool").
- Connectivity is configuration of the server, and it exists already:
  discovery.names lists the VMs a server is cabled to. New: a server
  "name" (its appliance identity; the controller takes it as the DRA pool
  name unless -pool-name overrides), discovery.control to make every host
  of a server use HMP, and slot patterns (which CXL ports of the servers a
  pool is cabled to). Serial bases per server keep serials unique.
- The controller publishes a nodeSelector (kubernetes.io/hostname In
  [nodes whose VMs the server reaches]) instead of allNodes, so the
  scheduler never picks a node that cannot reach the pool, and it confines
  itself to its own pool (resourceslice Options.ReconcilePoolWithName);
  without that, two controllers of one driver delete each other's slices
  (01-findings F4). Node plugin and lease broker need no change: they key
  by serial and match claim status entries by (driver, pool, device).
- Two pool servers on one VM is the only hard part of pool C: a QMP socket
  takes one client, and pool A holds qmp.sock of VM1 and VM2. Pool C uses
  HMP (monitor.sock, a connection per command, polled events) and the
  slots of the second host bridge, which is what "cabled to the other CXL
  port" means in the emulation. No VM or framework change for it.
- The cluster becomes three nodes permanently (VM2 control plane, VM1 and
  VM0 workers), made by n4-cxl-shared-2/test00-up as before. Every other
  test keeps working: pool A publishes for VM1 and VM2 only, pods are
  pinned with nodeSelectors already, dra-install follows the node list.
- test19-many-pools: pools A (VM1, VM2, index 0), B (VM0, index 1) and
  C (all, index 2, HMP, host bridge 1). Checks the three slices and their
  node selectors, unpinned pods landing where their device is reachable,
  an unschedulable pod when no node reaches the pool, a pod with two
  claims from two pools (B and C) on VM0, a shared device of C on VM0 and
  VM2 at once, and clean teardown of all three servers.

Status (2026-10-21, end of the task)
------------------------------------
Done and passing: test19-many-pools PASS twice (3 min each) with pools
A (VM1, VM2, QMP, hb0), B (VM0, QMP, hb0), C (all, HMP, hb1); test00-up
(three nodes), test10 and test13 PASS with the new controller. Unit tests,
lint and vet clean. Reviewed (05-review.txt), all findings fixed but one
cosmetic. Nothing committed. Details: 09-status.txt, runs: 06-runs.txt.

Files
-----
  00-README.txt               this file; status at the end when done
  01-findings.txt             what exists, what is missing, constraints
  01-research-multi-pool.txt  public sources: servers with several CXL
                              pools (research agent)
  02-design.txt               the design: configuration, server,
                              controller, e2e framework, test19, docs
  03-plan.txt                 work streams for the agents, rules, done
                              criteria, verification
  04-status-POOL.txt          status of stream POOL (fake-cxl-pool Go,
                              README, pool.md)
  04-status-E2E.txt           status of stream E2E (VM0, framework, test19,
                              e2e.md)
  05-review.txt               code review of both streams
  06-runs.txt                 phase 2 runs: commands, durations, verdicts
  09-status.txt               orchestrator's final status

How to run (after the streams are done)
---------------------------------------
  make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images
  make -C scripts/testing/fake-cxl-pool
  cd test/e2e
  qemu_bin=$HOME/github.com/qemu/qemu/build/qemu-system-x86_64 \
    ./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-0/test00-up
  ./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test00-up
  ./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test19-many-pools
