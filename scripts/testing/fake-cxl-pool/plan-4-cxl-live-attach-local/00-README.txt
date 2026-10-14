plan-4-cxl-live-attach-local: node-local CXL memory devices, as flexible as
pooled ones
===========================================================================
Written 2026-10-14 (Fable), task 5je-task-cxl-live-attach-local-device.txt.

Goal: a node-local CXL memory device (statically attached to the node) can
be allocated and used like a pooled device today: regions are created and
destroyed on demand, the memory is used as a NUMA node or as dax slices,
many containers get isolated slices of one device, and a running
container can borrow local memory and give it back (cxl-request).

Files
  01-findings.txt      verified facts and the answers to the three questions
                       of the task (partitioning, pool limits, class naming)
  02-design.txt        principles, device model, DRA objects, flows, life
                       cycle, limitations
  03-plan-driver.txt   implementation plan for kubelet-cxl-plugin (two Opus
                       agents, W1a and W1b, with the Go contract between them)
  04-plan-e2e.txt      implementation plan for the e2e tests (Opus agent W2)
  05-review.txt        what the reviewer agents check
  06-status.txt        status and findings appended by every agent

Repositories and ground rules (same as plan-3-cxl-live-attach/04)
- Driver: ~/github.com/intel/intel-resource-drivers-for-kubernetes, branch
  5fC-cxl. HEAD b57b62b, working tree clean at the start of this plan.
  go.mod replaces github.com/containers/nri-plugins with the local checkout:
  run `go mod vendor` before building, after every change in nri-plugins
  pkg/cxl/memctl. Build:
    CGO_ENABLED=0 GOARCH=amd64 go build -mod vendor -o bin/kubelet-cxl-plugin ./cmd/kubelet-cxl-plugin
    CGO_ENABLED=0 GOARCH=amd64 go build -mod vendor -o bin/cxl-request ./cmd/cxl-request
  Tests: go vet -mod vendor ./cmd/... ./pkg/... ; go test -mod vendor -race ./cmd/kubelet-cxl-plugin/... ./cmd/cxl-request/...
  Lint: golangci-lint run ./... (compare with the unchanged commit; add no findings).
- nri-plugins: ~/github.com/containers/nri-plugins, branch 5jQ-cxl, HEAD
  ee6442a22, with uncommitted files (see git status; do not touch them).
  pkg/cxl/memctl is the guest-side library both repositories use. Tests:
  go test -race ./pkg/cxl/... ; make reformat; make golangci-lint (see
  .github/skills/coding-style/SKILL.md).
- Nobody commits. W1a and W1b use unit tests only, never a VM. W2 owns the
  VMs of n4-cxl-shared-1 and n4-cxl-shared-2 (see 04). The VM of n4-cxl is
  not used (01, section 5).
- Skills to follow: .github/skills/coding-style/SKILL.md (code and
  comments, e2e style: no sleeps, wait-until-verified),
  .github/skills/run-e2e-tests/SKILL.md (running tests, never in parallel,
  debugging), .github/skills/build-nri-policy-images/SKILL.md is not needed
  (no nri-plugins images change).
- Reuse before writing: memctl (region create, online, dax driver
  binding), the pool helper's prepare/release/lend code (pool.go), the
  broker (broker.go), cxl-request, dra.source.sh, pool.source.sh,
  cxl.source.sh, lib/k8s.bash. The reviewers check this (05).

Reading order for an implementation agent: 01 (sections 1-3), 02, then the
plan of its own work stream (03 or 04), then the code it extends.
