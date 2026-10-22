# Hardware tests of local CXL memory with nri-dra-driver-cxl

Scripts that validate the local CXL memory allocations of
`nri-dra-driver-cxl` (driver `cxl.nri.io`) on a real single-node
Kubernetes cluster with a CXL memory expander, and the
[report](REPORT.md) of their first run on real hardware.

The scripts run on a workstation and drive the node over ssh
(`TARGET`, "root@hostname"): `kubectl`, `cxl`, `daxctl` and `helm` run
on the node. The node needs a cluster (kubeadm, containerd with NRI and
CDI, cgroup v2, Kubernetes 1.37), `helm`, `cxl`/`daxctl`, `python3`, and a
CXL memdev with RAM capacity.

| file | |
|:--|:--|
| `lib.sh` | helpers: ssh/kubectl, claims and pods (`claim_yaml`, `pod_yaml`), checks |
| `deploy.sh` | import the image, prepare the node, install/reconfigure the Helm chart (`sliced` or `shared`) |
| `run-all.sh` | deploy and run all tests, logs in `results/` |
| `test1-sliced-numa.sh` | slices in mode `numa`: several containers, one NUMA node, `Mems_allowed`, placement, release |
| `test2-sliced-dax.sh` | slices in mode `dax`: one claim shared by a writer and readers, read-only slice, zeroing, `numa` and `dax` slices on one memdev |
| `test3-local-leases.sh` | `cxl-request` leases of local memory in modes `numa` and `dax` |
| `test4-shared-swmr.sh` | the memdev in `sharedDevices`: single writer, many read-only readers, a read-only shared lease, exclusive claims, persistence |
| `test5-memory-integrity.sh` | every page of the memdev, and isolation of slices at 128 GiB distance |
| `alloc-touch.py`, `dax-pattern.py`, `dax-scan.py` | tools that the test pods run (with `numa-touch.py` and `pool-dax-rw.py` of the e2e tests) |
| `results/` | logs of the last run |

## Running

```bash
# build the image (repository root)
make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images

cd test/hw/dra-driver-cxl-local
# first time: prepare the node (udev override, destroy a BIOS region on the memdev)
./run-all.sh --image ../../../build/images/nri-dra-driver-cxl-image-<id>.tar --prepare-node
# later: the deployed image, one test
./run-all.sh test2-sliced-dax.sh
```

`--prepare-node` installs `/etc/udev/rules.d/40-redhat.rules` without the
memory hotplug section of the system rule (RHEL, CentOS Stream and Fedora
online hot-added memory with it), and offlines and destroys a CXL region
that the BIOS created on the memdev: the driver manages only memdevs
without foreign regions. A reboot brings the BIOS region back; run with
`--prepare-node` again then.

Environment: `TARGET` (ssh destination), `CXL_SERIAL` (memdev, default the
first one), `NS` (namespace of the test pods, default `cxl-hw`),
`TOOLS_IMAGE` (default `docker.io/library/python:3-alpine`).

The test containers run their workloads as children of their main process
(`prun`): the driver sets the memory policy of a steered container on the
processes that exist when it steers, and their descendants inherit it;
processes of `kubectl exec` do not.
