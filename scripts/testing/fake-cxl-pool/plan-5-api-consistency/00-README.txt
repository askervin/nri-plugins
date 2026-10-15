plan-5-api-consistency: one vocabulary for the CXL DRA driver
=============================================================
Written 2026-10-15 (Fable). Task: ../5jf-task-consistency-simplification.txt.

Goal
----
Everything built in plan-2 to plan-4 works (12 e2e tests PASS, see
../plan-4-cxl-live-attach-local/06-status.txt "W5 Status") but its API grew
by accretion: DeviceClasses whose names say different things on the local
and the pool side, two opaque config kinds with the same fields, three
environment variable prefixes for one concept, a cxl-request CLI where the
first word (memory, shared) overlaps with options (--dax, --exclusive), a
flag with an alias, labels under the wrong driver domain. Nothing of this
is released. This plan replaces it with one attribute model (source, type,
shared, mode, readOnly, serial, size) that is spelled the same way in
ResourceSlice attributes, DeviceClasses, opaque configs, the lease
protocol, environment variables, the cxl-request CLI, driver flags, the
fake-cxl-pool tools, the e2e helpers and the documentation, and that
leaves room for the extensions listed in 02-design.txt section H.

Reading order
-------------
  00-README.txt          this file: goal, ground rules, ownership
  01-inventory.txt       the current API surface, file:line, and the
                         inconsistencies found (facts only)
  02-design.txt          the target API for A-H, with reasons, the rename
                         table and user-visible examples. THE CONTRACT.
  03-plan.txt            work streams S1-S4, order, contracts between them,
                         verification, review checklist
  04-open-questions.txt  the few decisions the user should confirm
  05-status-S<n>.txt     written by each stream (one file per stream)

Implementers read 02 completely before touching code, then their own
section of 03. 01 is for checking that nothing was missed.

Ground rules for every Opus agent
---------------------------------
1. Start by reading, in this order:
   /home/akervine/github.com/containers/nri-plugins/.github/skills/coding-style/SKILL.md
   /home/akervine/github.com/containers/nri-plugins/.github/skills/run-e2e-tests/SKILL.md
   then 02-design.txt and your stream in 03-plan.txt.
2. Nothing is committed. Both repositories stay with the changes in their
   working trees. Do not run git commit, git stash, git checkout -- <file>
   or anything that rewrites the trees. The user commits.
3. Edit only the files your stream owns (03-plan.txt, "Ownership"). If a
   change is needed in a file of another stream, write it into your
   05-status-S<n>.txt under "Requests to S<m>" and continue; do not edit it.
4. 02-design.txt is the contract. If it cannot be implemented as written,
   do not improvise a different name or shape: record the problem and your
   proposal in your status file under "Deviations", pick the smallest
   change that keeps the vocabulary of 02, and flag it for the review.
5. No aliases, no compatibility paths, no "accepted for now" old names:
   every old name in the rename table of 02 section 10 disappears from
   code, YAML, scripts, tests and documentation (the plan-*/ directories
   are history and are not edited, except plan-2-dra/10-contract.md).
6. Documentation and comments describe the current state only (coding
   style skill). Plain ASCII.
7. e2e tests are run only by S3, never two at a time, never while another
   agent runs one. Ask (status file) rather than start a VM yourself.
8. The driver repository imports nri-plugins through a replace directive in
   go.mod (github.com/askervin/nri-plugins pseudo-version). S1 changes it to
   the local checkout (replace github.com/containers/nri-plugins =>
   /home/akervine/github.com/containers/nri-plugins) for the duration of
   the work so that the memctl changes of S2 are visible, and records in
   its status file that the user must restore a pushed pseudo-version
   before committing (as in plan-4). vendor/ is gitignored there; cxl.mk
   builds with -mod vendor and dra-build runs "go mod vendor" itself, so
   after changing the replace run "go mod tidy && go mod vendor" once and
   build with plain "go build ./..." or "-mod vendor" alike.
9. Verification before "done": the commands of your stream in 03 section
   "Verification", all green, output summarized in the status file.

Who owns which files (details in 03-plan.txt)
---------------------------------------------
  S1 driver   intel-resource-drivers-for-kubernetes: cmd/kubelet-cxl-plugin,
              cmd/cxl-request, pkg/cxl/**, deployments/cxl/**,
              test/e2e/cxl/dra-demo-cxl.sh, go.mod/go.sum/vendor (replace only)
  S2 pool     nri-plugins: pkg/cxl/memctl/**, scripts/testing/fake-cxl-pool/
              {cmd,pkg,deploy,config.example.yaml,Makefile}
  S3 e2e      nri-plugins: test/e2e/memory.test-suite/memory-policy/
              {dra.source.sh, n4-cxl/**, n4-cxl-shared-1/**, n4-cxl-shared-2/**};
              runs all e2e tests
  S4 docs     intel-resource-drivers-for-kubernetes: doc/cxl/*.md;
              nri-plugins: scripts/testing/fake-cxl-pool/README.md,
              scripts/testing/fake-cxl-pool/plan-2-dra/10-contract.md,
              test/e2e/README.md (only if a DRA/pool sentence needs it)
  review      two review agents after S1+S2 (code) and after S3+S4; they
              edit nothing, they write 06-review-<n>.txt
