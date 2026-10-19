# CXL DRA driver

CAUTION: experimental, do not use on production clusters. Interfaces may
change.

## About the driver

A DRA driver publishes ResourceSlices, the scheduler allocates the
resources, and the driver's kubelet plugin ensures that the allocated
devices are prepared and available for Pods.

One process, `nri-dra-driver-cxl`, runs two DRA drivers on every node:

- `cxl.nri.io` publishes the memory of the node in a ResourceSlice of the
  node: CXL memory devices (memdevs) whose regions the plugin creates on
  demand, CXL regions that exist already, the DRAM nodes, and the `lease`
  device that lets running containers request memory. It also steers the
  memory of containers to the NUMA nodes of their claims.
- `cxl-pool.nri.io` prepares the devices of a CXL memory pool. A pool
  controller (cluster level, specific to the pool product) publishes the
  pool devices and attaches them to the node that the scheduler picked;
  the node plugin makes the hotplugged memory usable for the pod.

The same process is an NRI plugin (`dra-driver-cxl`, index 30): it steers
the memory of containers and lends memory to running containers.

## Supported Kubernetes versions

Kubernetes v1.37 or later. The driver uses the `DRANodeAllocatableResources`
feature gate, when it is on, to account claimed memory against the node's
allocatable memory. See [Requirements](usage.md#requirements).

## Vocabulary

The same words name the same thing in device attributes, DeviceClasses,
opaque configurations, environment variables, the `cxl-request` CLI and
its protocol.

| word | values | meaning |
|:-----|:-------|:--------|
| `source` | `local`, `pool` | who provides the memory: `local` a device attached to the node, managed by `cxl.nri.io`; `pool` a device of a memory pool, attached by a pool controller, prepared by `cxl-pool.nri.io` |
| `type` | `memdev`, `region`, `dram`, `lease` | what a published device is: `memdev` a CXL memory device whose region the plugin creates when a claim needs it; `region` a region that existed before the plugin, online as a NUMA node; `dram` the DRAM nodes of the system; `lease` the device whose claim lets a container request memory while it runs |
| `shared` | `true`, `false` | `true`: several hosts may map the same bytes at a time (a pool device with a `hosts` capacity); such memory is never onlined as RAM. `false`: one host at a time |
| `persistent` | `true`, `false` | `true`: a pool device of persistent memory, whose data and namespace labels outlive the claims; it is used in modes `block` and `fs` only |
| `mode` | `numa`, `dax`, `block`, `fs` | how a container gets the memory: `numa` as system RAM of a NUMA node; `dax` as a devdax device of its own (claims) or an open file descriptor (leases); `block` as the block device of the fsdax namespace of a persistent pool device; `fs` as a read-only erofs filesystem on it, mounted at a path of the container. Default `numa`; shared volatile memory is `dax` only; `block` and `fs` are for claims of persistent pool devices only |
| `readOnly` | `true`, `false` | `dax`, `block`: the device node (claims) or the file descriptor (leases) allows reads only; `fs` is always read-only |
| `access` | `direct`, `cached` | mode `fs`: `direct` maps the file pages to the memory of the device (DAX), `cached` reads them into the page cache of the node |
| `serial` | `0x` and lower-case hex | `/sys/bus/cxl/devices/memN/serial`, the identity of a memdev in both drivers; upper-case hex without `0x` in environment variable names |
| `size` | bytes, or a quantity such as `512Mi` | attribute `size` and `CXL_<KEY>_SIZE` are bytes; requests and the `--size` of `cxl-request` take a quantity, "at least this much" |
| `hosts` | integer | capacity of a shared pool device: how many nodes may have it attached at a time. A claim consumes 1 by default; all of them is exclusive use |
| lease | 8 hex digits | one request of a running container for memory, served through the lease socket; its memory comes from a companion claim |

## DeviceClasses

The Helm chart installs seven DeviceClasses,
[`templates/deviceclasses.yaml`](blob:/deployment/helm/dra-driver-cxl/templates/deviceclasses.yaml).
They select device kinds only; `mode`, `readOnly`, `access` and `path`
are set with a `DeviceConfig` (see
[Opaque configurations](usage.md#opaque-configurations)).

| class | gets |
|:------|:-----|
| `cxl-local` | a slice of a local memdev: RAM of its NUMA node (default) or a devdax device (`mode: dax`) |
| `cxl-pool` | a whole exclusive pool device of volatile memory: a new NUMA node (default) or a devdax device (`mode: dax`) |
| `cxl-pool-shared` | a shared pool device of volatile memory as devdax; one of its `hosts` by default, all of them (exclusive) with `capacity.requests.hosts` |
| `cxl-pool-persistent` | a pool device of persistent memory, shared or not: its block device (`mode: block`, the writer) or a read-only erofs filesystem on it (`mode: fs`, the readers) |
| `cxl-region` | capacity of a pre-created CXL NUMA node; the container is steered to it |
| `cxl-dram` | DRAM capacity for steering |
| `cxl-lease` | the lease socket and `cxl-request` in the container |

## Documentation

- [How to deploy and use the CXL DRA driver](usage.md): requirements,
  build and deploy, devices, classes, configurations, environment
  variables, example claims, flags
- [Local CXL memory devices: regions and slices on demand](local.md)
- [CXL memory pools: the cxl-pool.nri.io driver and the pool controller contract](pool.md)
- [Leases: memory for running containers, the cxl-request CLI and its protocol](leases.md)
- [Trying the CXL DRA driver in e2e VMs](e2e.md): a developer guide with
  copy-paste examples on qemu VMs and a fake CXL memory pool
- [Helm chart of the driver](../../deployment/helm/dra-driver-cxl.md)

```{toctree}
:maxdepth: 1
:hidden:

usage.md
local.md
pool.md
leases.md
e2e.md
```
