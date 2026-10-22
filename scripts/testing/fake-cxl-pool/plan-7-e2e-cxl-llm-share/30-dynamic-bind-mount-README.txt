plan-7: erofs through leases, a mount into a running container (3x files)
=========================================================================
Task (user, 2026-10-22): revisit 22-erofs-design.txt section 9, "Later":
cxl-request arguments that correspond to DeviceConfig mode: fs and
access: direct|cached, erofs only. The driver on the node bind-mounts the
read-only filesystem of a persistent pool device dynamically into a
container that asks for it, and unmounts and releases the device once
every reference, static (claims) and dynamic (leases), is gone. Study the
feasibility first (bind-mount life cycle included), then, with no
obstacle, implement it, bring leases on par with claims for mode fs, and
extend test16 so that one node has a static and a dynamic mount of the
same device.

Branch: nri-plugins 5jg-cxl (14-branch-5jg-cxl.txt). Paths: N =
nri-plugins, D = N/cmd/plugins/dra-driver-cxl, A = N/pkg/cxl/api,
C = N/cmd/cxl-request, E = N/test/e2e/memory.test-suite/dra-driver-cxl,
S2 = E/n4-cxl-shared-2.

Result of the study (31): feasible, no obstacle. The mechanism of IN 2.4
and 3.1 (a lease CDI mount of a plugin-owned host directory with
[rbind, ro, rslave]; the driver binds the node mount into it) was proved
on VM2 on 2026-10-22 from a Bidirectional pod like the driver's into a
running pod; the life cycle needs no new reference counting: the
companion claim of a lease is a pool claim that the existing node mount
and region accounting already covers, plus one bind mount per lease
whose unmount (never lazy) is the lease's revoke.

Files
  30-dynamic-bind-mount-README.txt     this file
  31-dynamic-bind-mount-findings.txt   the facts, the probe, the analysis
  32-dynamic-bind-mount-design.txt     the contract: CLI, protocol, texts,
                                       broker, pool driver, life cycle,
                                       restart, docs, test16 and test12
  33-dynamic-bind-mount-plan.txt       streams D and T, order, checks
  34-dynamic-bind-mount-status-<S>.txt one per stream, written by its agent
  35-dynamic-bind-mount-review-<S>.txt reviews
  39-dynamic-bind-mount-status.txt     orchestrator status, final state
Every agent reads, in order: N/.github/skills/*/SKILL.md, this file, 31,
32, 33, then what its stream section names. Earlier plan-7 files that
the design rests on: 22-erofs-design.txt (sections 1, 4, 5, 9, 10),
21-erofs-findings.txt (F10-F12), 11-research-IN-integration.txt (2.4,
3.1), 12-proto-P1-erofs-pmem.txt (section 5).
