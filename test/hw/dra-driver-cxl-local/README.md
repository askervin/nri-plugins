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
| `lib.sh` | helpers: ssh/kubectl, claims and pods (`claim_yaml`, `pod_yaml`), checks (`check_fenced`) |
| `deploy.sh` | import the image, prepare the node, install/reconfigure the Helm chart (`sliced` or `shared`) |
| `run-all.sh` | deploy and run all tests, logs in `results/` |
| `test1-sliced-numa.sh` | slices in mode `numa`: several containers, one NUMA node, `Mems_allowed`, other containers fenced off the node, placement of steered containers (opt-in) and of a container that is not steered, release, a driver restart |
| `test2-sliced-dax.sh` | slices in mode `dax`: one claim shared by a writer and readers, read-only slice, zeroing, `numa` and `dax` slices on one memdev, `dax` pods fenced off the `numa` node |
| `test3-local-leases.sh` | `cxl-request` leases of local memory in modes `numa` and `dax`, other containers fenced off the leased node |
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
`TOOLS_IMAGE` (default `docker.io/library/python:3-alpine`),
`CONTAINER_FENCING` (`deploy.sh`, `run-all.sh`: `defaults.container.fencing`
of the driver configuration, `allowed-mems` or `none`; `mempolicy` is
refused as not implemented; unset leaves it out, the driver's default
`allowed-mems` applies).

## Claims

`claim_yaml` writes claims of one request `mem` on the memdev. Its options
`mode=MODE`, `readonly` and `steering=POLICY` give the claim one opaque
config of kind `MemoryConfig` (`apiVersion: cxl.nri.io/v1alpha1`):

```yaml
config:
- opaque:
    driver: cxl.nri.io
    parameters:
      apiVersion: cxl.nri.io/v1alpha1
      kind: MemoryConfig
      device: {mode: dax, readOnly: true}       # mode=dax readonly
      container: {steering: {policy: auto}}     # steering=auto
```

Steering is opt-in: a container with a `numa` claim without
`container.steering.policy` (the default `none`) is not steered. It gets
the claimed node in its `cpuset.mems` next to its own nodes, no memory
policy and no `memory.high`; its default allocations stay on DRAM. In
test1, `numa-a` and `numa-b` opt in with `steering=auto` (their default
allocations land on the CXL node) and `numa-u` does not. The `numa` claims
of test2 and the leases of test3 are not steered.

## Fencing

With `defaults.container.fencing: allowed-mems`, no container has a CXL NUMA
node of the driver in its `cpuset.mems.effective` (`Mems_allowed`) unless
it claimed memory on it. `check_fenced N POD...` checks that on every
running container of the node (`crictl ps`; pod sandboxes are not
containers): containers `main` of the PODs in `NS` have node N, all others,
the kube-system containers included, do not. It retries for 30 s and
prints the table of `node_mems` (container, `cpuset.mems`, effective).
test1, test2 and test3 use it; with `CONTAINER_FENCING=none` those checks,
and the checks that `plain` cannot use the node, fail.

## Workloads

The test containers run their workloads as children of their main process
(`prun`): the driver sets the memory policy of a steered container on the
processes that exist when it steers, and their descendants inherit it;
processes of `kubectl exec` do not.
