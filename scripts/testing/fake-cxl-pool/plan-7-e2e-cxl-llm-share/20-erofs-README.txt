plan-7: erofs on shared CXL persistent memory (the 2x-erofs files)
=================================================================
Task (user, 2026-10-19): "Let's start with erofs. Make all necessary
changes to our custom CXL kernel configuration and update test16
accordingly." The filesystem decision of 13-fs-findings / 10-fs-README is
made: erofs on a shared CXL persistent memory device (fsdax namespace),
with direct (dax=always) and page-cached (dax=never) readers. famfs is
not pursued now (11-FA, 12-P2 stay as the record).

Branch: nri-plugins 5jg-cxl (14-branch-5jg-cxl.txt). Everything lives in
nri-plugins: the kernel config, fake-cxl-pool, the driver dra-driver-cxl
(image, chart) and the e2e suite memory.test-suite/dra-driver-cxl.

Scope of this step
- Kernel: CONFIG_EROFS_FS=y in test/e2e/playbook/files/qemu-cxl-kernel.config,
  its RPM tarball built inside a VM and cached on the host, both VMs on it.
- fake-cxl-pool: a persistent device kind (data file + shared LSA file,
  cxl-type3 persistent-memdev= lsa=), published with attribute persistent.
- Driver: pool devices with persistent memory get modes block (the
  writer gets the block device of the fsdax namespace) and fs (readers get
  a read-only erofs mount, access direct or cached); a DeviceClass for
  them; the chart propagates the driver's mounts to the host; the image
  gets ndctl.
- test16-cxl-llm-share: the writer flashes an erofs image of the model
  into the device; readers run stock llama.cpp (the upstream server
  image) on the mounted file, direct and cached, on both nodes; cxl-llm
  and its host build are deleted.
Not in this step (designed in 22 section 9, later): erofs through
cxl-request leases (a mount into a running container), ext4/famfs
fsType, a write mount.

Files
  20-erofs-README.txt        this file
  21-erofs-findings.txt      the facts the design rests on, with sources
  22-erofs-design.txt        the contract: API, texts, driver behaviour,
                             memctl, fake-cxl-pool, chart, image, kernel,
                             test16
  23-erofs-plan.txt          streams K, P, D, T, ownership, order, checks
  24-erofs-status-<S>.txt    one per stream
  25-erofs-review-<S>.txt    reviews
  29-erofs-status.txt        orchestrator status and the final state
Every agent reads, in order: N/.github/skills/*/SKILL.md, this file, 21,
22, 23, then what its stream section names.
