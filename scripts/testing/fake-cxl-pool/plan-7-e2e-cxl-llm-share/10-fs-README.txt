plan-7 follow-up: a filesystem on shared CXL memory
===================================================
Task: "Follow-up task" in ../5jg-task-e2e-cxl-llm-share.txt (2026-10-17).
Replace the custom engine of test16 (cxl-llm mapping /dev/daxX.Y) with a
filesystem on the shared CXL device: the writer puts the model into it
(write mount, or an image "flashed" into the writable device), readers get a
read-only mount point and run stock llama.cpp on a regular file. Candidates
in order of the task: famfs (fail fast: upstream status), erofs, other
filesystems; direct access (DAX) and a switchable page cache matter. The
driver may change (fsdax, mounts into containers by claims and by
cxl-request). Builds and tools run in the e2e VMs only, never on the host
(no new host dependencies); results are cached on the host like kernels.

Branch (2026-10-19): the work continues on nri-plugins branch 5jg-cxl,
where the driver is dra-driver-cxl in nri-plugins itself (image, helm
chart, e2e suite memory.test-suite/dra-driver-cxl). 14-branch-5jg-cxl.txt
maps every old path and name of these files to the new ones and lists
what a containerized driver changes for the filesystem work.

Facts at the start (2026-10-17, orchestrator, from v7.3 sources at
1b78070aaef6 and research B 01-research-B-kernel-access.txt):
- erofs mounts only a block device (dax=always needs a bdev with a
  dax_device, that is a pmem/fsdax namespace) or, with
  EROFS_FS_BACKED_BY_FILE, a regular file with read_folio
  (fs/erofs/super.c erofs_fc_get_tree l.799-830, device table l.147-170).
  A char /dev/daxX.Y is neither: no erofs on today's volatile devdax.
  CONFIG_EROFS_FS is off in qemu-cxl-kernel.config.
- fsdax (ext4/xfs/erofs -o dax) exists only on nvdimm pmem namespaces.
  Our pool devices are volatile cxl-type3, so "fsdax" means a persistent
  pool device kind (qemu persistent-memdev + a shared LSA file; research B
  section 3 measured it end to end in both VMs, ext4 dax and non-dax).
- famfs: drivers/dax/fsdev.c (fsdev_dax, Micron, "for the upcoming
  fuse/famfs") is in v7.1+, the FUSE half (GET_FMAP) is not in v7.3.
- The guest kernel 7.3.0-rc4 was built from the source copy
  /home/akervine/.claude/jobs/5b6674cf/tmp/ws3/linux-src (no git). VMs have
  no ~/linux. Kernel RPM tarballs are cached in ~/.cache/nri-plugins/e2e
  under the name test/e2e/playbook/custom-kernel.yaml computes.
- The two VMs are one two-node cluster (VM2 control plane, VM1 worker),
  Ready, 26 GB disk free, ~4-6 GiB RAM free each (03-decisions D11).

Streams (Opus, medium effort; each writes only its own files):
  FA  famfs: upstream status and fail-fast verdict, what it takes on
      v7.3-rc4 (patches, libfuse, userspace), how it shares one devdax
      between hosts and containers. Desk only. 11-research-FA-famfs.txt
  FS  filesystems and mechanisms besides famfs: erofs details (mkfs,
      alignment, dax, writer flow), ext4/xfs/squashfs/others on fsdax,
      any upstream way to a DAX-capable bdev from volatile CXL, userspace
      block devices over devdax. Desk only. 11-research-FS-filesystems.txt
  IN  integration: driver (DeviceConfig, CDI mounts, node mounts and
      their life cycle), cxl-request (a mount into a running container),
      fake-cxl-pool persistent kind, the stock llama.cpp reader, the new
      shape of test16. Desk only. 11-research-IN-integration.txt
  P1  prototype in the VMs (owns both VMs): an experimental kernel built
      in a VM with EROFS (and options FS may want), erofs and ext4 on a
      shared CXL pmem device hotplugged by hand: writer flashes an image,
      readers in both VMs mount dax=always and dax=never, containers bind
      mount it, stock llama.cpp answers. 12-proto-P1-erofs-pmem.txt
  P2  prototype famfs in the VMs after P1 (FA's recipe): kernel with
      fuse/for-next, famfs userspace built in a VM, two hosts, three
      pods, daemon death. 12-proto-P2-famfs.txt
Then (orchestrator): 13-fs-findings.txt (done), 14-branch-5jg-cxl.txt
(done). Decision (user, 2026-10-19): erofs first; its findings, design,
plan and status are the 2x-erofs files, starting at 20-erofs-README.txt.
Scratch space: /home/akervine/.claude/jobs/plan7-fs/<stream>/.
