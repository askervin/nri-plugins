plan-8-demo: the third story line, pool-shared-fs (the 1x files)
================================================================
Task (user, 2026-10-22): extend the demo with an alternative story line,
"pool-shared-fs" under demo/bin: the writer creates an erofs file system
with hello.txt in it (the message that the pool demo writes to the device
at offset 0), and the readers use cxl-request to mount that file system
dynamically. Consider whether the writer can use cxl-request too to get
the memory device dynamically, or whether that needs too much hacking
and a static claim is better. Readability, clarity and simplicity come
first; the design must fit the existing six views. Then Opus agents
implement and test it. Follow-up (user, same day): if lease mode block
is critical for this, implement it first in cxl-request and the driver;
could the lease claim carry a loop device as a CDI device?

Answers in short (11-fs-demo-findings.txt): the writer can be dynamic
with little hacking once leases have mode block, which is the fd model of
dax leases applied to /dev/pmemK (about 250 lines of driver code with
tests and docs, no new mechanism); a loop device per lease claim as a CDI
device node would also work, with three caveats, and is not needed for a
clean demo; the file system is made with the real mkfs.erofs from a small
image built at setup (python:3-alpine plus erofs-utils); the pool view
reads hello.txt out of the backing file with a 60-line erofs reader.

Files
  10-fs-demo-README.txt      this file
  11-fs-demo-findings.txt    the facts and the two decisions (dynamic
                             writer through lease mode block; mkfs.erofs
                             from a demo image), the loop idea assessed
  12-fs-demo-design.txt      the contract: A. lease mode block (api,
                             cxl-request, broker, pool driver, docs,
                             tests), B. the story line F1-F9 and what each
                             view shows, C. setup, teardown, manifests,
                             tools, image, zooms, samples, README
  13-fs-demo-plan.txt        streams D (driver and e2e texts, VM runs) and
                             DEMO (the demo), order, checks
  14-fs-demo-status-<S>.txt  one per stream, written by its agent
  15-fs-demo-review-<S>.txt  reviews
  19-fs-demo-status.txt      orchestrator status and the final state
Every agent reads, in order: N/.github/skills/*/SKILL.md, 00-README.txt,
03-demo-design.txt, demo/README.txt, this file, 11, 12, 13, then what its
stream section names. Paths: N = nri-plugins, P = N/scripts/testing/
fake-cxl-pool, DEMO = P/plan-8-demo/demo, D = N/cmd/plugins/dra-driver-cxl,
A = N/pkg/cxl/api, C = N/cmd/cxl-request, E = N/test/e2e/memory.test-suite/
dra-driver-cxl, S2 = E/n4-cxl-shared-2. The fs leases that the readers use
are plan-7's 3x-dynamic-bind-mount files (P/plan-7-e2e-cxl-llm-share/
32-dynamic-bind-mount-design.txt is their contract).
