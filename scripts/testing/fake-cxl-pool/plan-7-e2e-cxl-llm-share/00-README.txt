plan-7-e2e-cxl-llm-share: an LLM shared through pooled CXL memory
=================================================================
Task: ../5jg-task-e2e-cxl-llm-share.txt (2026-10-16). A new e2e test and
demo, n4-cxl-shared-2/test16-cxl-llm-share: one writer puts a small LLM
(GGUF) into a shared pool CXL device; three readers on the two-node
cluster (VM1 n4-cxl-shared-1, VM2 n4-cxl-shared-2) run inference on that
same copy, either
  direct: the inference engine maps the model from the CXL device itself
          (every access goes to CXL memory), or
  cached: the model is read through the page cache, so the first access
          to a page copies it from CXL to local DRAM and later accesses
          stay local (on-demand transfer to the nodes that use it).
Copying the whole model to tmpfs is the fallback for "cached".

Facts at the start (2026-10-16, orchestrator):
- VMs: 8 CPUs, 8 GiB RAM (two NUMA nodes of 4 GiB), 28 GB disk, patched
  qemu, kernel 7.3.0-rc4 (test/e2e/playbook/files/qemu-cxl-kernel.config):
  CXL_PMEM, LIBNVDIMM, BLK_DEV_PMEM, ND_PFN, ND_BTT, NVDIMM_DAX, FS_DAX,
  EXT4, SQUASHFS, BLK_DEV_LOOP, FUSE_FS, OVERLAY_FS on; BLK_DEV_NBD,
  BLK_DEV_UBLK, EROFS off. No famfs in the v7.3 tree (no fs/famfs, no
  famfs in fs/fuse).
- Pool devices (fake-cxl-pool) are volatile cxl-type3 (memory-backend-file,
  share=on); shared devices are devdax-only in the guests; pool slots are
  1G. The driver gives a claim on cxl-pool-shared a /dev/daxX.Y node (CDI,
  "r" for readOnly) and a lease an open fd (cxl-request fd --exec).
  /proc/self/fd/N of a passed dax fd cannot be reopened (device cgroup,
  ../plan-4-multinode/02-implementation-status.txt section 7).
- llama.cpp source: ~/github.com/ggml-org/llama.cpp (25a1d63f4, 2026-06-29);
  its loader opens a path with fopen, finds the size with fseek(SEEK_END),
  reads the GGUF header with fread and maps with
  mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0) (src/llama-mmap.cpp).
  Device dax has no read(), no MAP_PRIVATE and needs 2 MiB aligned
  mappings, so plain llama.cpp cannot open /dev/daxX.Y as a model file.
- Hugging Face is reachable from the host through the proxy.

Research streams (01-research-*.txt, one Opus agent each):
  A  inference engine and model: smallest useful GGUF, llama.cpp loading
     internals, ways to load from a dax device or fd, static build and
     delivery into containers. Host only.
  B  kernel mechanisms for direct and cached access to shared CXL memory:
     CXL pmem regions -> /dev/pmem block device -> filesystem with and
     without -o dax; FUSE over the dax mapping; loop/squashfs; userfaultfd;
     how to prove caching (numa_maps, page cache counters). Owns the VMs
     of n4-cxl-shared-1 and -2 during the research.
  C  integration: how writer and readers get the data through our stack
     (claims, leases, DeviceConfig), what each access path needs from the
     driver, fake-cxl-pool and the e2e framework, resource and time
     budget, and the shape of test16. Reads code and docs only.
Then: 02-findings.txt (synthesis), 03-decisions.txt, 04-plan.txt,
05-status.txt, written by the orchestrator and the implementation agents.

Later files: 10-fs-README.txt (2026-10-17, the follow-up task: a
filesystem on the shared device instead of cxl-llm) and
14-branch-5jg-cxl.txt (2026-10-19: plan-7 moved to branch 5jg-cxl, where
the driver is dra-driver-cxl in nri-plugins and test16 is
test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/
test16-cxl-llm-share; the old paths and names of files 01-13 are mapped
there).
