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
  device that lets running containers request memory.
- `cxl-pool.nri.io` prepares the devices of a CXL memory pool. A pool
  controller (cluster level, specific to the pool product) publishes the
  pool devices and attaches them to the node that the scheduler picked;
  the node plugin makes the hotplugged memory usable for the pod.

The same process is an NRI plugin (`dra-driver-cxl`, index 30): it keeps
containers off the CXL memory they did not claim, steers the memory of
the containers that opt in to steering to the NUMA nodes of their claims,
and lends memory to running containers.

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
| `shared` | `true`, `false` | `true`: the same bytes may be mapped by several claims at a time: a pool device attached to several hosts, or a local device that the node's configuration declares shared (both with a `shares` capacity); such memory is never onlined as RAM. `false`: the bytes belong to one claim at a time (a slice of a local memdev, an exclusive pool device) |
| `persistent` | `true`, `false` | `true`: a device of persistent memory (a pool device or a local memdev), whose data and namespace labels outlive the claims; it is used in modes `block` and `fs` only |
| `coherent` | `true`, `false` | `true`: the hardware keeps the memory of a device coherent between the hosts that use it at a time (an attribute of pool devices and claim status data; for a local memdev the `memdevSettings` of the configuration file, which is not published as an attribute); only then a cluster filesystem is read-write on several hosts |
| `mode` | `numa`, `dax`, `block`, `fs` | how a container gets the memory: `numa` as system RAM of a NUMA node; `dax` as a devdax device of its own (claims) or an open file descriptor (leases); `block` as the block device of the fsdax namespace of a persistent device; `fs` as a filesystem on it, read-only or read-write, mounted at a path of the container. Default `numa`; shared volatile memory is `dax` only; `block` and `fs` are for persistent devices only, through claims and leases (`block`: an open file descriptor of the block device for a running container; `fs`: mounted at `/run/cxl/fs/<name>` of a running container) |
| `readOnly` | `true`, `false` | `dax`, `block`: the device node (claims) or the file descriptor (leases) allows reads only; `fs`: read-only unless `readOnly: false` (`--read-write` of a lease), the opt-in to write |
| `access` | `direct`, `cached` | mode `fs`: `direct` maps the file pages to the memory of the device (DAX), `cached` reads them into the page cache of the node; default `direct` for the filesystems with DAX (erofs, ext4, xfs) |
| `fsType` | `erofs`, `squashfs`, `ext4`, `xfs`, `btrfs`, `gfs2`, ... | mode `fs`: the type of the filesystem, detected by the plugin or declared; its class says who may write it: read-only (erofs, squashfs), single-host (read-write on one host at a time: ReadWriteOnce), cluster (gfs2 with `lock_dlm`, read-write on several hosts of coherent memory). A node mounts erofs only, unless its `fsTypes` lists more: every other type trusts the raw writers of the devices |
| `serial` | `0x` and lower-case hex | `/sys/bus/cxl/devices/memN/serial`, the identity of a memdev in both drivers: unique within a pool, and on a node, but the local memdevs of different nodes may have the same serial; upper-case hex without `0x` in environment variable names |
| `size` | bytes, or a quantity such as `512Mi` | attribute `size` and `CXL_<KEY>_SIZE` are bytes; requests and the `--size` of `cxl-request` take a quantity, "at least this much" |
| `shares` | integer | capacity of a shared device. A claim that requests none has the device exclusively; a claim that requests `shares: "1"` shares it. The value (1M for local devices and the reference pool) is the most claims that may hold the device at a time; a pool whose devices have a head limit publishes its heads |
| lease | 8 hex digits | one request of a running container for memory, served through the lease socket; its memory comes from a companion claim |

## DeviceClasses

The Helm chart installs nine DeviceClasses,
[`templates/deviceclasses.yaml`](blob:/deployment/helm/dra-driver-cxl/templates/deviceclasses.yaml).
They select device kinds; `mode`, `readOnly`, `access`, `fsType` and `path`, and
steering, are set with a `MemoryConfig` of the claim, or of the class as
a preset (Helm value `deviceClassConfig`), see
[Opaque configurations](usage.md#opaque-configurations).

| class | gets |
|:------|:-----|
| `cxl-local` | a slice of a local memdev: RAM of its NUMA node (default) or a devdax device (`mode: dax`) |
| `cxl-local-shared` | a shared local device as devdax: exclusively (no capacity request), or one share with `capacity.requests.shares: "1"` |
| `cxl-local-persistent` | a local memdev of persistent memory: its block device (`mode: block`: the writer exclusively, or a reader with `shares: "1"` and `readOnly: true`) or a filesystem on it (`mode: fs`, read-only or read-write, `shares: "1"` each) |
| `cxl-pool` | a whole exclusive pool device of volatile memory: a new NUMA node (default) or a devdax device (`mode: dax`) |
| `cxl-pool-shared` | a shared pool device of volatile memory as devdax: exclusively (no capacity request), or one share with `capacity.requests.shares: "1"` |
| `cxl-pool-persistent` | a pool device of persistent memory, shared or not: its block device (`mode: block`: the writer exclusively, or a reader of a shared device with `shares: "1"` and `readOnly: true`) or a filesystem on it (`mode: fs`, `shares: "1"` each on a shared device: readers on any number of nodes, or readers and writers of one node) |
| `cxl-region` | capacity of a pre-created CXL NUMA node, for steering |
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
- [Design of the driver](design.md): its objects, how a claim becomes
  memory, how a restart recovers, and its files on the node
- [States of the driver's records](states.md): every state field and its
  transitions, generated from the code
- [Helm chart of the driver](../../deployment/helm/dra-driver-cxl.md)

```{toctree}
:maxdepth: 1
:hidden:

usage.md
local.md
pool.md
leases.md
e2e.md
design.md
states.md
```
