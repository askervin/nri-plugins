# How to deploy and use the CXL DRA driver

CAUTION: experimental. Interfaces may change.

`nri-dra-driver-cxl` runs two DRA drivers on every node: `cxl.nri.io` for
the memory of the node (local CXL memory devices, CXL regions, DRAM, the
lease device) and `cxl-pool.nri.io` for the devices of a CXL memory pool.
The words used below (`source`, `type`, `shared`, `persistent`, `mode`,
`readOnly`, `access`, `serial`, `size`, `shares`) are defined in the
[Vocabulary](index.md#vocabulary).

- [Requirements](#requirements)
- [Build and deploy](#build-and-deploy)
- [Devices of cxl.nri.io](#devices-of-cxlnriio)
- [DeviceClasses](#deviceclasses)
- [Opaque configurations](#opaque-configurations)
- [Steering](#steering)
- [Containers without claims](#containers-without-claims)
- [Environment variables](#environment-variables)
- [What the memory contains](#what-the-memory-contains)
- [Example claims](#example-claims)
- [nri-dra-driver-cxl flags](#nri-dra-driver-cxl-flags)
- [Configuration file](#configuration-file)
- [Files on the node](#files-on-the-node)

Local memory devices are described in [local.md](local.md), pool devices
and the pool controller contract in [pool.md](pool.md), memory for running
containers in [leases.md](leases.md). [e2e.md](e2e.md) shows how to try
all of it in the e2e test VMs.

## Requirements

- Kubernetes v1.37 or later, see [Feature gates](#feature-gates).
- A container runtime with CDI support (containerd 1.7 or newer with CDI
  enabled, CRI-O 1.23 or newer) and with NRI enabled: the driver keeps
  containers off the CXL memory they did not claim, steers them, and lends
  memory to them through NRI.
- cgroup v2.
- Kernel with CXL regions (`CONFIG_CXL_REGION`), `CONFIG_DEV_DAX`,
  `CONFIG_DEV_DAX_KMEM`, `CONFIG_MEMORY_HOTREMOVE`, and `CONFIG_FS_DAX` for
  mode `dax` (without it every devdax `mmap` fails).
- For pool devices of persistent memory (modes `block` and `fs`):
  `CONFIG_CXL_PMEM`, `CONFIG_LIBNVDIMM`, `CONFIG_BLK_DEV_PMEM`,
  `CONFIG_ND_PFN` and `CONFIG_FS_DAX`; for mode `fs` also
  `CONFIG_EROFS_FS`, and `CONFIG_BLK_DEV_LOOP` for `access: cached`.
- The `cxl` (ndctl) tool for local memdevs and pool devices, `daxctl` for
  pool devices, `ndctl` for pool devices of persistent memory
  ([local.md](local.md#node-requirements),
  [pool.md](pool.md#node-requirements)). The container image of the driver
  includes them; a host process needs them installed on the node.
- `/sys/devices/system/memory/auto_online_blocks` set to `offline`: the
  plugin onlines the memory of `numa` slices and pool devices itself, and
  the kernel must never online shared devices as RAM.
- No udev rule that onlines hot-added memory. `40-redhat.rules` of RHEL,
  CentOS Stream and Fedora does (`ATTR{state}="online_movable"` for
  `SUBSYSTEM=="memory"`, `ACTION=="add"`), whatever `auto_online_blocks`
  says, and races the plugin when it creates a region. Override it with
  a copy without its "Memory hotadd request" section:

  ```bash
  sed '/^# Memory hotadd request/,/^LABEL="memory_hotplug_end"/d' \
      /usr/lib/udev/rules.d/40-redhat.rules > /etc/udev/rules.d/40-redhat.rules
  udevadm control --reload
  ```

### Feature gates

The driver uses these Kubernetes features:

| feature gate | used for | default in v1.37 |
|:-------------|:---------|:-----------------|
| `DRADeviceBindingConditions` | pool devices: the scheduler waits until the pool controller has attached the device | on |
| `DRAResourceClaimDeviceStatus` | pool devices: the pool controller writes the device serial into the claim status | on |
| `DRAConsumableCapacity` | many claims share one device: slices of a local memdev, regions, DRAM, `shares` of a shared device | on |
| `DRAPrioritizedList` | `firstAvailable` requests, for instance local memory first, then pool memory | on |
| `DRANodeAllocatableResources` | claimed memory is accounted against the node's allocatable memory | off |

Without `DRANodeAllocatableResources` the API server drops
`nodeAllocatableResources` from the ResourceSlices of the driver, and
claimed memory is not accounted against the node's allocatable memory;
everything else works. Turn a gate on in the API server, the scheduler
and the kubelet of every node, for instance with kubeadm:

```yaml
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
apiServer:
  extraArgs:
  - name: feature-gates
    value: DRANodeAllocatableResources=true
scheduler:
  extraArgs:
  - name: feature-gates
    value: DRANodeAllocatableResources=true
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
featureGates:
  DRANodeAllocatableResources: true
```

```bash
kubeadm init --config kubeadm-config.yaml
```

The e2e VMs get the same with `k8s_feature_gates=DRANodeAllocatableResources=true`
when they are created ([e2e.md](e2e.md)).

## Build and deploy

### Build the image

From the root of the repository:

```bash
make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images
```

builds the image `nri-dra-driver-cxl:<version>` from
[`cmd/plugins/dra-driver-cxl/Dockerfile`](blob:/cmd/plugins/dra-driver-cxl/Dockerfile)
and saves it as `build/images/nri-dra-driver-cxl-image-<id>.tar`.
`IMAGE_REPO` and `IMAGE_VERSION` set the repository and the tag
(`make IMAGE_REPO=registry.example.com/cxl IMAGE_VERSION=dev ...` gives
`registry.example.com/cxl/nri-dra-driver-cxl:dev`), and `docker push`
publishes it. The image is based on `gcr.io/distroless/static`, like the
images of the other plugins of this repository, and contains:

| path | |
|:-----|:-|
| `/bin/nri-dra-driver-cxl` | the driver, the entrypoint of the image |
| `/bin/cxl-request` | the static lease CLI; the plugin copies it to the host at start (`--lease-cli-source`), from where it mounts it into the containers of lease claims |
| `/usr/bin/cxl`, `/usr/bin/daxctl`, `/usr/bin/ndctl` | the tools of ndctl v85, with their shared libraries and the dynamic loader |
| `/licenses/` | the licenses of the driver, `cxl-request` and ndctl |

### Deploy with Helm

The chart [`deployment/helm/dra-driver-cxl`](tree:/deployment/helm/dra-driver-cxl)
deploys the driver as a DaemonSet (see
[its documentation](../../deployment/helm/dra-driver-cxl.md)):

```bash
helm install -n kube-system cxl deployment/helm/dra-driver-cxl \
    --set image.name=registry.example.com/cxl/nri-dra-driver-cxl \
    --set image.tag=dev
```

creates the DaemonSet `nri-dra-driver-cxl` with its ServiceAccount, the
ClusterRole and ClusterRoleBinding of the driver, a
ValidatingAdmissionPolicy that lets the driver's ServiceAccount change only
the ResourceSlices of its own node, a ConfigMap with the
[configuration file](#configuration-file), and the eight
[DeviceClasses](#deviceclasses). The pod of the DaemonSet is privileged,
runs in the host PID namespace (the lease broker maps the process ids of
its callers to containers), and mounts `/var/lib/kubelet/plugins`,
`/var/lib/kubelet/plugins_registry`, `/etc/cdi`, `/var/run/cdi`,
`/var/run/nri`, `/sys`, `/dev` and `/lib/modules` (read-only) of the host
at the same paths. `/var/lib/kubelet/plugins` has `mountPropagation:
Bidirectional`: the filesystems that the pool driver mounts there for mode
`fs` reach the host, where the container runtime binds them into
containers. Its image has the `cxl`, `daxctl` and `ndctl` tools. So every
feature works in the DaemonSet: local memdevs, pool devices, steering and
leases.

The main values of the chart:

| value | default | |
|:------|:--------|:-|
| `image.name` | `ghcr.io/containers/nri-plugins/nri-dra-driver-cxl` | |
| `image.tag` | the chart's appVersion | |
| `image.pullPolicy` | `Always` | `Never` for an image that was imported into the nodes |
| `resources.cpu`, `resources.memory` | `10m`, `128Mi` | requests of the plugin container |
| `nri.plugin.index` | `30` | `--nri-idx` |
| `nri.runtime.patchConfig` | `false` | `true`: an init container enables NRI in the configuration of containerd or CRI-O |
| `pool.driverName` | `cxl-pool.nri.io` | `--pool-driver-name`; empty disables the pool driver |
| `pool.prepareTimeout` | `30s` | `--pool-prepare-timeout` |
| `leases.enabled` | `true` | `--leases` |
| `leases.wait` | `120s` | `--lease-wait` |
| `leases.companionImage` | `registry.k8s.io/pause:3.10` | `--lease-companion-image` |
| `config` | `{}` | the [configuration file](#configuration-file) (`-f`) |
| `deviceClassConfig` | `{}` | class name: a `MemoryConfig` body for the class, see [Presets in DeviceClasses](#presets-in-deviceclasses) |
| `logLevel` | `4` | `-v` |
| `extraEnv` | | more environment variables of the plugin container, name: value |
| `tolerations`, `affinity`, `nodeSelector` | | where the DaemonSet runs |
| `podPriorityClassNodeCritical` | `true` | priority class `system-node-critical` |

For example, a configuration that leaves one device alone and shares
another one, and the DaemonSet only on the nodes that have CXL memory:

```bash
cat > cxl-values.yaml <<'EOF'
config:
  ignoreDevices: ["0xc100e2e0"]
  sharedDevices: ["0xc100e2e2"]
nodeSelector:
  example.com/cxl: "true"
EOF
helm install -n kube-system cxl deployment/helm/dra-driver-cxl -f cxl-values.yaml
```

The chart passes `--lease-cli /var/lib/kubelet/plugins/cxl.nri.io/cxl-request`
and `--lease-cli-source /bin/cxl-request`: the plugin copies the static
`cxl-request` of its image to the host, where the containers of lease
claims get it mounted. The logs of the plugin on a node:

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=nri-dra-driver-cxl \
    --field-selector spec.nodeName=NODE
```

`helm uninstall -n kube-system cxl` removes the driver and its
DeviceClasses. Delete the pods with claims of the driver first: kubelet
needs the running plugin to unprepare their claims, and pool devices are
detached only after that.

### As a host process

The driver can run on the node as a host process instead, for example as a
systemd unit. It then needs the `cxl`, `daxctl` and `ndctl` tools on the node and a
kubeconfig with the rights of the ClusterRole of the chart. Build both
static binaries into `build/bin`:

```bash
make PLUGINS=nri-dra-driver-cxl BINARIES=cxl-request build-plugins-static build-binaries-static
```

and run the plugin on the node:

```bash
kubectl apply -f deployment/helm/dra-driver-cxl/templates/deviceclasses.yaml
install -m 755 build/bin/nri-dra-driver-cxl build/bin/cxl-request /usr/local/bin/
echo '{}' > /etc/nri-dra-driver-cxl.yaml
systemd-run --unit nri-dra-driver-cxl -p Restart=on-failure -p RestartSec=5s \
    -E KUBECONFIG=/etc/kubernetes/nri-dra-driver-cxl.conf \
    /usr/local/bin/nri-dra-driver-cxl --node-name "$(hostname)" -f /etc/nri-dra-driver-cxl.yaml
```

The plugin exits with status 1 when the container runtime closes its NRI
connection (when containerd or CRI-O restarts, for example), and connects
again only when it is restarted: the DaemonSet restarts its container, a
host process needs `Restart=on-failure` (or `always`). `RestartSec` gives
the runtime time to bring its NRI socket back: a plugin that cannot reach
it at start runs on without NRI.

`templates/deviceclasses.yaml` is plain YAML: applied as it is, the
classes carry no configuration. Classes with the presets of a
`deviceClassConfig` come from the chart:
`helm template x deployment/helm/dra-driver-cxl -f values.yaml --show-only templates/deviceclasses.yaml | kubectl apply -f -`.

`cxl-request` must be a static binary: it runs in the containers of lease
claims. `--lease-cli` defaults to `/usr/local/bin/cxl-request`; with
`--lease-cli-source PATH` the plugin copies `PATH` there at start, as the
chart does. Never run a host process and the DaemonSet on the same node.

## Devices of cxl.nri.io

The plugin publishes one ResourceSlice per node (pool name = node name)
under the driver `cxl.nri.io`:

```yaml
- name: memdev-c100e2e1              # "memdev-" + serial in lower-case hex
  attributes:
    type:            {string: memdev}
    source:          {string: local}
    serial:          {string: "0xc100e2e1"}
    shared:          {bool: false}
    size:            {int: 1073741824}          # RAM capacity of the memdev
    nodeAffinity:    {int: 0}                   # CPU NUMA node; absent if unknown
    memoryBlockSize: {int: 134217728}           # every slice is a multiple of it
  capacity:
    memory: {value: 1Gi, requestPolicy: {default: 1Gi, validRange: {min: 128Mi, step: 128Mi}}}
  allowMultipleAllocations: true
  nodeAllocatableResources: {memory: {mapping: {capacityKey: memory, capacityMultiplier: "1"}}}
- name: memdev-c100e2e2              # a shared local device (sharedDevices)
  attributes:
    type:            {string: memdev}
    source:          {string: local}
    serial:          {string: "0xc100e2e2"}
    shared:          {bool: true}
    size:            {int: 1073741824}
    nodeAffinity:    {int: 0}
  capacity:
    shares: {value: 1M}                         # no requestPolicy
  allowMultipleAllocations: true
- name: region0-node2                # region0, online as NUMA node 2
  attributes:
    type:            {string: region}
    source:          {string: local}
    node:            {int: 2}
    size:            {int: 2147483648}
    nodeAffinity:    {int: 0}                   # if all memdevs of the region agree
  capacity: {memory: {value: 2Gi}}
  allowMultipleAllocations: true
  nodeAllocatableResources: {memory: {mapping: {capacityKey: memory, capacityMultiplier: "1"}}}
- name: dram
  attributes:
    type:            {string: dram}
    source:          {string: local}
    nodes:           {string: "0-1"}            # cpuset syntax
    size:            {int: 16777216000}
  capacity: {memory: {value: 16000Mi}}
  allowMultipleAllocations: true
  nodeAllocatableResources: {memory: {mapping: {capacityKey: memory, capacityMultiplier: "1"}}}
- name: lease
  attributes:
    type:            {string: lease}
  allowMultipleAllocations: true
```

| attribute | devices | value |
|:----------|:--------|:------|
| `type` | all | `memdev`, `region`, `dram` or `lease` |
| `source` | `memdev`, `region`, `dram` | `local` (pool devices have `pool`) |
| `size` | `memdev`, `region`, `dram` | bytes: the RAM capacity of a memdev, the size of a region, the DRAM of the nodes |
| `serial` | `memdev` | `0x` and lower-case hex |
| `shared` | `memdev` | `false`: every claim gets a slice of its own; `true`: a shared local device, whose claims map the same bytes |
| `node` | `region` | the NUMA node of the region |
| `nodes` | `dram` | the DRAM NUMA nodes, cpuset syntax |
| `nodeAffinity` | `memdev`, `region` | the CPU NUMA node of the device; absent if unknown (for a region: unless all its memdevs agree) |
| `memoryBlockSize` | `memdev`, not shared | the memory block size of the node in bytes |

- `memdev-<serial hex>`, type `memdev`: a CXL memory device without a
  region; every claim gets a slice of it, created when the claim is
  prepared ([local.md](local.md)). A device listed in `sharedDevices` of
  the [configuration file](#configuration-file) has `shared: true` and a
  `shares` capacity instead: every claim maps the whole device as devdax
  ([local.md](local.md#shared-local-devices)).
- `<region>-node<N>`, type `region`: a region that exists already
  (created by the BIOS or an admin) and is online as NUMA node N; claims
  consume its capacity, and their containers that opt in to steering are
  steered to N.
- `dram`, type `dram`: one device for all DRAM nodes, for steering;
  absent with `ignoreDRAMNodes`.
- `lease`, type `lease`: the device of lease claims
  ([leases.md](leases.md)); absent with `--leases=false`.

Every memory device has `allowMultipleAllocations` and `capacity.memory`
(`capacity.shares` for a shared device), so that many claims share it;
with `DRANodeAllocatableResources`, `nodeAllocatableResources` maps the
claimed memory to the node's allocatable memory. Pool devices are published by the pool controller
under `cxl-pool.nri.io` with the same memdev attributes (`type`, `source`,
`serial`, `shared`, `size`) and `persistent`, see
[pool.md](pool.md#what-the-pool-controller-publishes).

Write selectors that test `type` first. Every device has `type`, every
memory device has `source` and `size`; the other attributes exist on some
devices only, and a selector that reads an attribute a device does not
have fails the allocation of the claim. The shipped classes guarantee the
attributes their devices have, so selectors in claims on them may use
those.

## DeviceClasses

[`templates/deviceclasses.yaml`](blob:/deployment/helm/dra-driver-cxl/templates/deviceclasses.yaml)
of the Helm chart:

| class | selects | gets |
|:------|:--------|:-----|
| `cxl-local` | `cxl.nri.io`, `type == "memdev"`, `shared == false` | a slice of a local memdev: RAM of its NUMA node (mode `numa`, default) or a devdax device (`device.mode: dax`) |
| `cxl-local-shared` | `cxl.nri.io`, `type == "memdev"`, `shared == true` | a shared local device as devdax: exclusively (no capacity request), or one share with `capacity.requests.shares: "1"` |
| `cxl-pool` | `cxl-pool.nri.io`, `type == "memdev"`, `shared == false`, `persistent == false` | a whole exclusive pool device: a new NUMA node (default) or a devdax device (`device.mode: dax`) |
| `cxl-pool-shared` | `cxl-pool.nri.io`, `type == "memdev"`, `shared == true`, `persistent == false` | a shared pool device as devdax: exclusively (no capacity request), or one share with `capacity.requests.shares: "1"` |
| `cxl-pool-persistent` | `cxl-pool.nri.io`, `type == "memdev"`, `persistent == true` | a pool device of persistent memory, shared or not: the block device of its fsdax namespace (`device.mode: block`) or a read-only erofs filesystem on it (`device.mode: fs`); a shared device exclusively without a capacity request, one share with `capacity.requests.shares: "1"` |
| `cxl-region` | `cxl.nri.io`, `type == "region"` | capacity of a pre-created CXL NUMA node, CXL memory for [steering](#steering) |
| `cxl-dram` | `cxl.nri.io`, `type == "dram"` | DRAM capacity for steering |
| `cxl-lease` | `cxl.nri.io`, `type == "lease"` | the lease socket and `cxl-request` |

For example:

```yaml
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata: {name: cxl-pool}
spec:
  selectors:
  - cel: {expression: 'device.driver == "cxl-pool.nri.io" && device.attributes["cxl-pool.nri.io"].type == "memdev" && device.attributes["cxl-pool.nri.io"].shared == false && device.attributes["cxl-pool.nri.io"].persistent == false'}
```

The classes carry no configuration unless the Helm value
`deviceClassConfig` gives them one: how a device is prepared and how the
containers that use it are managed is a [MemoryConfig](#opaque-configurations)
of the claim, and a `MemoryConfig` of a class is a preset that the claims
of the class change field by field ([Presets in DeviceClasses](#presets-in-deviceclasses)).
Memory from either source, local first, is a `firstAvailable` request
with a subrequest per class ([example 9](#example-claims)).

## Opaque configurations

Both drivers take one kind of opaque configuration, `MemoryConfig`, with
one apiVersion, `cxl.nri.io/v1alpha1`, in claims and in DeviceClasses.
The `driver` of the entry selects the driver that reads it; the
parameters are the same for local and pool devices:

```yaml
config:
- opaque:
    driver: cxl-pool.nri.io            # or cxl.nri.io
    parameters:
      apiVersion: cxl.nri.io/v1alpha1  # for both drivers
      kind: MemoryConfig
      device:                          # how the device of a result is prepared
        mode: numa
      container:                       # how a container that uses the result is managed
        steering: {policy: auto}
      pool:                            # cxl-pool.nri.io only: for the pool controller
        opaque:
          fake-cxl-pool: {numaNode: 1}
```

Every section and every field is optional.

### Sections and owners

Each section has one owner, which reads only its section:

| section | owner (applies it) | when | errors appear as |
|:--------|:-------------------|:-----|:-----------------|
| `pool` | the pool controller of the device (cluster level, one per pool) | after the allocation, before binding (attach) | claim condition `cxl-pool.nri.io/AttachFailed`, reason `InvalidConfig`; the scheduler allocates the claim again until the binding timeout |
| `device` | the kubelet plugin of the device's driver in nri-dra-driver-cxl (`cxl.nri.io` or `cxl-pool.nri.io`) | NodePrepareResources, per allocation result | Prepare error (pod events): kubelet retries, the pod does not start |
| `container` | the NRI plugin of nri-dra-driver-cxl | CreateContainer of a container that uses the result; it also passes over other containers (fencing, lending) | invalid values: Prepare error; results of a container that disagree: CreateContainer error, the container is not created |

The node driver checks the structure of `pool` (no unknown fields next to
`opaque`), never the contents of a controller's object.

### MemoryConfig fields

Where a field may be set: *class* is an entry of a DeviceClass, *claim*
an entry of a claim, *node* the `defaults.container` of the
[configuration file](#configuration-file).

| field | section | owner | values | default | where it may be set | |
|:------|:--------|:------|:-------|:--------|:--------------------|:-|
| `device.mode` | `device` | kubelet plugin | `numa`, `dax`; `block`, `fs` (`cxl-pool.nri.io`) | `numa`; `dax` for shared devices; none for persistent devices | class, claim | `numa`: the memory is online as system RAM of a NUMA node. `dax`: the container gets a devdax device `/dev/daxX.Y` of its own to `mmap`. Shared devices of volatile memory are `dax` only. `block`, `fs`: pool devices of persistent memory only, which have no other modes, see [Persistent memory](#persistent-memory). |
| `device.readOnly` | `device` | kubelet plugin | `false`, `true` | `false` | class, claim | `dax`, `block`: the container's device node has CDI permissions `r`, so its device cgroup allows opening it for reading only. `fs`: required, the filesystem is mounted read-only. |
| `device.access` | `device` | kubelet plugin | `direct`, `cached` | `direct` | class, claim | `fs` only: `direct` maps the file pages to the memory of the device (DAX), `cached` reads them into the page cache of the node. |
| `device.path` | `device` | kubelet plugin | an absolute path | `/run/cxl-fs/<KEY>` | class, claim | `fs` only: the directory of the filesystem in the container; not `/`, not in `/dev`, `/proc`, `/sys`, `/run/cxl` or `/var/run/cxl`. |
| `container.steering.policy` | `container` | NRI plugin | `none`, `auto`, `first-dram`, `first-cxl`, `start-interleaved`, `end-interleaved`, `waypoints` | `none` | class, claim, node | how the allocations of the container are spread over the DRAM and CXL memory of its results, see [Steering](#steering); `none`: not steered |
| `container.steering.waypoints` | `container` | NRI plugin | list of `{targetUsages: [{memoryType: DRAM or CXL, usage: <quantity>}]}` | | class, claim, node | policy `waypoints` only, which needs them: the target usage per memory type at each waypoint; a type that is not listed keeps its usage of the previous waypoint; usages never decrease |
| `container.steering.minStep` | `container` | NRI plugin | quantity | the smallest change of the usage of a node between two waypoints, at most `maxStep` | class, claim, node | not with policy `none`: the smallest amount of new allocations after which the route is re-evaluated |
| `container.steering.maxStep` | `container` | NRI plugin | quantity | the total quota | class, claim, node | not with policy `none`: the largest amount of new allocations after which the route is re-evaluated |
| `container.fencing` | `container` | NRI plugin | `allowed-mems`, `mempolicy` (not implemented), `none` | `allowed-mems` | node only | whether the containers are kept off the CXL nodes of the driver that they did not claim, see [Containers without claims](#containers-without-claims) |
| `pool.opaque.<key>` | `pool` | the pool controllers with controller key `<key>` | an object that the controller defines | | class, claim; not in entries of `cxl.nri.io` | settings of one implementation of a pool controller; the reference controller (key `fake-cxl-pool`) takes `slot` and `numaNode`, see [Configuration of a pool controller](pool.md#configuration-of-a-pool-controller) |

The `device` fields per device:

- Local memdev (`cxl-local`): `mode` `numa` (default) or `dax`;
  `readOnly` needs `dax`; `access` and `path` are refused.
- Shared local device (`cxl-local-shared`): `dax`, the default and only
  mode; `readOnly` is allowed.
- Regions and DRAM (`cxl-region`, `cxl-dram`): `numa` only; `mode: numa`
  is allowed and nothing else. In a claim that has such requests next to
  `dax` memdev requests, list the memdev requests in the `requests` of
  the entry.
- Lease device (`cxl-lease`): no `device` field.
- Pool devices: `numa` (exclusive devices, their default) or `dax`;
  shared devices of volatile memory `dax` only; devices of persistent
  memory `block` or `fs` only, and `fs` needs `readOnly: true`
  ([pool.md](pool.md#options-of-pool-devices)).

| device | `device` | the container gets |
|:-------|:---------|:-------------------|
| local memdev (`cxl-local`) | none | a slice online as RAM of the memdev's NUMA node |
| local memdev | `mode: dax` | a devdax slice of its own |
| shared local device (`cxl-local-shared`), `capacity.requests.shares: "1"` | none | the device as devdax, shared with the other claims of the device |
| shared local device, no capacity request | none | the device as devdax, no other claim has it meanwhile |
| exclusive pool device (`cxl-pool`) | none | the device online as a new NUMA node |
| exclusive pool device | `mode: dax` | the device as devdax |
| shared pool device (`cxl-pool-shared`), `capacity.requests.shares: "1"` | none | the device as devdax, shared with the other claims of the device |
| shared pool device, no capacity request | none | the device as devdax, no other claim has it meanwhile |
| any of the `dax` rows | `readOnly: true` | the same, the device node read-only |
| persistent pool device (`cxl-pool-persistent`), exclusively (no capacity request) | `mode: block` | the block device of its fsdax namespace, writable; the namespace is created if there is none |
| persistent pool device | `mode: block`, `readOnly: true` | the block device, read-only |
| persistent pool device | `mode: fs`, `readOnly: true` | the erofs filesystem on it at `path`, `access: direct` (default) or `cached` |

Read-only is enforced by the kernel for every process of the container,
whatever its capabilities, except in privileged containers (their device
cgroup allows everything). It is a property of the claim, not of the
device: another claim of the same device may write, and the readers see
it.

### Merge order

A driver resolves the configuration of every allocation result of a
claim:

1. The entries of the result's driver apply that have no `requests`,
   that list the result's request, or, for a subrequest `r/s` of a
   `firstAvailable` request, that list `r`. An entry that lists `r/s`
   applies to that alternative only.
2. The entries of the DeviceClass come first (`FromClass`), then the
   entries of the claim (`FromClaim`), each in the order of its list.
3. Each entry is decoded alone, strictly and case-sensitively: an
   unknown or duplicate field, another kind or another apiVersion fails
   the Prepare, naming the entry
   (`MemoryConfig: FromClaim config 1: json: unknown field "x"`). Every
   entry of the driver is checked so, also one for another request.
4. The parameters merge in that order as a JSON merge patch (RFC 7386):
   objects merge field by field, scalars and lists (`waypoints`) replace,
   and `null` removes a field, which returns it to its default (`null`
   never counts as setting a field).
5. The result is decoded and validated again, and the driver checks it
   against the device (type, shared, persistent, exclusive).

So a class with `device: {mode: dax}` and a claim with
`device: {readOnly: true}` give a read-only dax slice, and a claim with
`device: {mode: null}` gives a numa slice of the same class. The node
defaults are no part of a result: they apply per container.

### Container settings

A container uses the results of the requests it references: all results
of a claim that it lists without a `request`, and only the result of the
request that `resources.claims[].request` names (kubelet gives it only
that result's CDI device, see [Environment variables](#environment-variables)).
Only those results count for the container: their memory for its
steering and its `cpuset.mems`, and their `container` sections. A
container that uses the `dax` request of a claim is neither steered by
nor given the node of the `numa` request of the same claim, which
another container uses.

The settings of a container:

1. A `container` field that the resolved configurations of several of its
   results set must have the same value in all of them (lists and
   objects compared as JSON, quantities by value); a field that only some
   of them set is taken from those. A conflict fails CreateContainer, and
   the container is not created:
   `container ns/pod/ctr: container.steering.policy: claim ns/a request r says first-cxl, claim ns/b request s says none`
2. The `defaults.container` of the driver configuration, overlaid by
   these fields, is effective. The `waypoints`, `minStep` and `maxStep`
   of the defaults apply only when the results set no policy or the
   policy of the defaults: a claim with `policy: none` on a node whose
   default is `{policy: first-dram, maxStep: 1Gi}` is not steered, and
   does not get the `maxStep`. A container without results gets the
   defaults.
3. The effective steering takes `waypoints`, `minStep` and `maxStep` only
   with a policy other than `none`, and policy `waypoints` needs
   `waypoints` (from any of its results or the defaults); else
   CreateContainer fails, naming where the settings came from
   ([Configuration errors](#configuration-errors)).

The `container` sections of different requests of one claim may differ:
they reach different containers. The settings of a shared claim reach
every container that uses its request.

### Examples of configurations

Steering on for the containers of a claim, one line (the same with
`driver: cxl-pool.nri.io` for pool memory):

```yaml
config:
- opaque: {driver: cxl.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, container: {steering: {policy: auto}}}}
```

A read-only dax slice:

```yaml
config:
- opaque: {driver: cxl.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {mode: dax, readOnly: true}}}
```

Two requests for two containers: `app` uses `numa`, steered DRAM first in
1Gi steps; `cache` uses `dax`, and gets neither the node nor steering:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata: {name: app-memory}
spec:
  devices:
    requests:
    - {name: dram, exactly: {deviceClassName: cxl-dram,  capacity: {requests: {memory: 4Gi}}}}
    - {name: numa, exactly: {deviceClassName: cxl-local, capacity: {requests: {memory: 4Gi}}}}
    - {name: dax,  exactly: {deviceClassName: cxl-local, capacity: {requests: {memory: 1Gi}}}}
    config:
    - requests: [dram, numa]
      opaque: {driver: cxl.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, container: {steering: {policy: first-dram, maxStep: 1Gi}}}}
    - requests: [dax]
      opaque: {driver: cxl.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {mode: dax}}}
---
apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  resourceClaims:
  - {name: mem, resourceClaimName: app-memory}
  containers:
  - name: app
    image: docker.io/library/python:3-alpine
    command: ["sleep", "infinity"]
    resources: {claims: [{name: mem, request: dram}, {name: mem, request: numa}]}
  - name: cache
    image: docker.io/library/python:3-alpine
    command: ["sleep", "infinity"]
    resources: {claims: [{name: mem, request: dax}]}
```

Settings for the pool controller (`cxl-pool.nri.io` only): the reference
controller attaches the device to a slot near NUMA node 1 of the host
([pool.md](pool.md#configuration-of-a-pool-controller)):

```yaml
config:
- opaque: {driver: cxl-pool.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, pool: {opaque: {fake-cxl-pool: {numaNode: 1}}}}}
```

### Presets in DeviceClasses

A DeviceClass may carry `MemoryConfig` entries of its driver; they are the
first layer of the [merge](#merge-order), so a claim of the class changes
single fields of them. A class for dax slices of local memdevs:

```yaml
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata: {name: cxl-local-dax}
spec:
  selectors:
  - cel: {expression: 'device.driver == "cxl.nri.io" && device.attributes["cxl.nri.io"].type == "memdev" && device.attributes["cxl.nri.io"].shared == false'}
  config:
  - opaque:
      driver: cxl.nri.io
      parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {mode: dax}}
```

The Helm value `deviceClassConfig` gives the shipped classes such an
entry: class name to a `MemoryConfig` body (`device`, `container`, and
`pool` for the classes of `cxl-pool.nri.io`), which the chart renders
into the class's `spec.config` with the class's driver, the apiVersion
and the kind. Steering on for every container with memory of `cxl-local`
or `cxl-pool`, unless its claim says
`container: {steering: {policy: none}}`:

```yaml
deviceClassConfig:
  cxl-local:
    container: {steering: {policy: auto}}
  cxl-pool:
    container: {steering: {policy: auto}}
```

Steering on for every container of a node is
`defaults.container.steering: {policy: auto}` in the
[configuration file](#configuration-file); there it applies to the
containers whose results do not set a policy.

### Configuration errors

Errors of the `device` and `container` sections fail the Prepare of the
claim (kubelet retries, the pod does not start), before any device is
touched; conflicts between the results of a container fail its
CreateContainer ([Container settings](#container-settings)); errors of
`pool.opaque.<key>` are the pool controller's
([pool.md](pool.md#configuration-of-a-pool-controller)). The errors of a
configuration start with `MemoryConfig: ` and the path of the field. The
Prepare error of `cxl.nri.io` puts `claim NS/NAME: ` before an error of
an entry, and `claim NS/NAME: request R: ` before an error of the
configuration of a result; that of `cxl-pool.nri.io` puts
`cxl-pool.nri.io: preparing claim NS/NAME: ` and `request R: ` or
`device D serial 0xS: ` before them. The CreateContainer error starts with
`container NS/POD/CTR: `.

Decoding is strict and case-sensitive: a field `Mode` is unknown, and so
are a field written twice and the names of fields that are not
implemented. `null` removes a value and never counts as setting a field.
Every entry of the driver is checked, also one for another request of the
claim. Of every entry (`SRC` `FromClass` or `FromClaim`, `I` the index of
the entry among the entries of its source, from 0):

- `unknown kind "..." (MemoryConfig)` (an entry without a kind gives
  `unknown kind ""`)
- `MemoryConfig: apiVersion "...", expected "cxl.nri.io/v1alpha1"`
- `MemoryConfig: SRC config I: json: unknown field "F"`, F the dotted path
  of the field (`x`, `device.online`, `container.steering.memoryUseOrder`)
- `MemoryConfig: SRC config I: json: duplicate field "F"`
- `MemoryConfig: SRC config I: json: cannot unmarshal ...` (a value of
  the wrong type)
- `MemoryConfig: container.fencing: set by the driver configuration only (defaults.container.fencing)`
- `MemoryConfig: pool: only for devices of cxl-pool.nri.io` (in an entry
  of `cxl.nri.io`)
- `MemoryConfig: claim NS/NAME has no allocation`

Of the `container` section of a result:

- `MemoryConfig: container.steering.policy: invalid policy "..." (none, auto, first-dram, first-cxl, start-interleaved, end-interleaved or waypoints)`
- `MemoryConfig: container.steering.minStep: invalid quantity "..."`,
  `... (must be positive)` (also `maxStep`)
- `MemoryConfig: container.steering.waypoints[I].targetUsages: empty`
- `MemoryConfig: container.steering.waypoints[I].targetUsages[J].memoryType: invalid memory type "..." (DRAM or CXL)`,
  `...: DRAM twice in the waypoint` (or `CXL`)
- `MemoryConfig: container.steering.waypoints[I].targetUsages[J].usage: missing`,
  `...: invalid quantity "..."`, `...: invalid quantity "..." (must not be negative)`
- `MemoryConfig: container.steering.waypoints[I]: DRAM usage X is less than Y of waypoint I-1` (or `CXL`)
- `MemoryConfig: container.steering.waypoints needs a policy other than none`
  (also `minStep`, `maxStep`)
- `MemoryConfig: container.steering.waypoints needs policy waypoints`
- `MemoryConfig: container.steering.minStep X exceeds maxStep Y`

Of the `pool` section:

- `MemoryConfig: pool.opaque: empty controller key`
- `MemoryConfig: pool.opaque.KEY: not a JSON object`

Of the effective settings of a container, at CreateContainer: the
conflict of [Container settings](#container-settings), and the texts of
the `container` section and
`MemoryConfig: container.steering.policy waypoints needs waypoints`, each
followed by the fields involved and where they came from:

```
container ns/pod/ctr: MemoryConfig: container.steering.maxStep needs a policy other than none (policy none (default), maxStep 1Gi from claim ns/a request r)
container ns/pod/ctr: MemoryConfig: container.steering.minStep 2Gi exceeds maxStep 1Gi (minStep 2Gi from claim ns/a request r, maxStep 1Gi (node default))
```

Of the `device` section, `cxl.nri.io`, in this order:

- `MemoryConfig: device.mode: invalid mode "..." (numa or dax)`
- `MemoryConfig: device.readOnly needs mode dax`
- `MemoryConfig: device: a shared device is used as dax only`
- `MemoryConfig: device.access needs mode fs`
- `MemoryConfig: device.path needs mode fs`
- `MemoryConfig: device: a region is used as numa only`,
  `MemoryConfig: device: a dram is used as numa only`
- `MemoryConfig: device: the lease device has no device settings`

Of the `device` section, `cxl-pool.nri.io`, first those of the section
alone:

- `MemoryConfig: device.mode: invalid mode "..." (numa, dax, block or fs)`
- `MemoryConfig: device.access needs mode fs`
- `MemoryConfig: device.path needs mode fs`
- `MemoryConfig: device.access: invalid access "..." (direct or cached)`
- `MemoryConfig: device.path: invalid path "..." (an absolute path outside /dev, /proc, /sys, /run/cxl and /var/run/cxl)`
- `MemoryConfig: device.readOnly: mode fs is read-only: set readOnly: true (write the device with mode block)`
- `MemoryConfig: device.readOnly needs mode dax, block or fs`

then those that need the claim status data of the device (`persistent`,
`shared`, `exclusive`, [pool.md](pool.md#what-the-pool-controller-writes)):

- `MemoryConfig: device.mode block needs a persistent device` (or `fs`)
- `MemoryConfig: device: a persistent device needs mode block or fs` (no
  mode, `numa` or `dax` on a persistent device)
- `MemoryConfig: device.mode block: a shared device is writable only exclusively (no shares request)`
- `MemoryConfig: device: a shared device is used as dax only`
- `MemoryConfig: device.readOnly needs mode dax, block or fs` (readOnly
  without a mode on an exclusive volatile device, which is `numa` by
  default)

and of both drivers, for an allocation of a shared device whose
`consumedCapacity` has less than one share (a claim with `shares: "0"`):
`device 0x<serial>: consumed shares "<q>" is less than 1: request shares: 1 (a share) or no shares (exclusive)`
(`<q>` the consumed quantity, `""` when there is none).

### Persistent memory

A pool device of persistent memory (attribute `persistent: true`, class
`cxl-pool-persistent`) holds data that outlives the claims: an erofs
image that a writer stores once and readers on many nodes use in place.
The pool driver creates a pmem region on the device; its nvdimm region
has the namespaces of the labels of the device.

- `mode: block` gives the container the block device `/dev/pmemK` of the
  fsdax namespace (map `mem`) of the region: a CDI device node of type
  `b`, permissions `r` when `readOnly`. A writable block claim on a region
  without such a namespace creates it (`ndctl create-namespace -f -r
  regionK -m fsdax -M mem`), which writes the labels of the device; a
  shared device is writable only by a claim that has it exclusively,
  without a `shares` request. A read-only
  claim never creates a namespace. `CXL_<KEY>_PATH` is the device node,
  `CXL_<KEY>_SIZE` the size of the namespace.
- `mode: fs` gives the container a read-only erofs filesystem of the
  fsdax namespace at `path`, and no device node. The node plugin mounts it
  once per device and access on the node, at
  `/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/<serial hex>-<access>`
  (`c1ae0001-direct`), and every claim of the node gets a read-only bind
  mount of it (CDI mount, options `bind,ro,nosuid,nodev`). `access:
  direct` mounts `/dev/pmemK` with `dax=always`: mappings of the files
  are the memory of the device, no page cache. `access: cached` mounts a
  read-only direct-I/O loop device over `/dev/pmemK` with `dax=never`: the
  files are read into the page cache of the node once. Both accesses of
  one device coexist on a node. A reader never creates or changes a
  namespace or labels.
- Claims of one device on a node may mix `block` and `fs` and both
  accesses; a volatile preparation of the serial is refused.
- Unprepare of the last claim of an access on the node unmounts it
  (never detaching it); a mount that is busy fails the Unprepare, kubelet
  retries. Unprepare of the last claim of the device on the node waits
  until nothing holds `/dev/pmemK`, up to 10 s for all devices of the
  claim together (no mount, no loop device, no
  container that still has the bind mount) before it releases the region;
  else it fails and kubelet retries. Releasing the region touches neither
  labels nor data.
- After a restart of the plugin, the node mounts of prepared claims that
  are missing are mounted again, when the fsdax namespace of the device
  still has the block device that Prepare recorded (else the plugin logs
  it and mounts nothing); mounts in the directory of node mounts that no
  prepared claim uses are unmounted.

Errors of the Prepare after the configuration checks above:

- `device 0x<serial>: memN has no persistent memory`: the status data
  says `persistent`, the memdev has no persistent capacity.
- `device 0x<serial>: no fsdax namespace in regionK: has a writer written the device?`:
  mode `fs` or a read-only `block` claim on a region without an fsdax
  namespace with map `mem`.
- `device 0x<serial>: /dev/pmemK has no erofs filesystem: <mount error>`
- `device 0x<serial>: erofs on /dev/pmemK was mounted without DAX`:
  `access: direct`, and the mount did not get `dax=always` (another mount
  of `/dev/pmemK` on the node, outside the plugin, has its superblock);
  the plugin unmounts it again. The same when the node mount of the
  device and `access: direct` exists without `dax=always`; then it is
  left alone.
- `device 0x<serial>: <node mount> is a <type> mount of <source>, not of /dev/pmemK`
  (`access: direct`), `..., not of a loop device over /dev/pmemK`
  (`access: cached`): something else is mounted at the node mount; the
  plugin neither uses nor unmounts it.

When a Prepare fails after the region was created, the plugin releases
the region again only when nothing holds `/dev/pmemK` (as Unprepare
does, below); else it leaves the region and logs it.

Errors of the Unprepare: `device 0x<serial>: unmounting <mount>: device or
resource busy` and `device 0x<serial>: /dev/pmemK is still in use`.

The erofs image for `access: direct` must keep each file in one plain,
2 MiB-aligned extent. Without `-Enoinline_data` the tail of a file is
inline in its inode, and the kernel silently uses the page cache for the
whole file although the mount says `dax=always`. Build it with exactly

```bash
mkfs.erofs -b4096 --dsunit=512 -Enoinline_data IMAGE DIR
```

(erofs-utils 1.8.6 or newer), and write it into the block device of a
writer, for example with `dd if=IMAGE of=$CXL_<KEY>_PATH bs=2M oflag=direct
conv=fsync`. The image must fit `CXL_<KEY>_SIZE`.
[pool-persistent-erofs.yaml](blob:/deployment/samples/dra-driver-cxl/pool-persistent-erofs.yaml)
has a writer and two readers.

## Steering

Steering is opt-in: a container is steered when its effective
`container.steering.policy` ([Container settings](#container-settings)) is
not `none` and its results have memory in mode `numa`. The default is
`none`. A claim opts in with one line
(`container: {steering: {policy: auto}}`,
[Examples of configurations](#examples-of-configurations)), a DeviceClass
for all its claims ([Presets in DeviceClasses](#presets-in-deviceclasses)),
a node for all its containers (`defaults.container.steering` of the
[configuration file](#configuration-file)).

The NRI plugin of `nri-dra-driver-cxl` finds the results of a container
by their markers (`CXL_CLAIM_<uid>_<n>`), takes the consumed capacity of
every `dram` device as the DRAM quota, and of every `region` device,
`numa` memdev slice and pool device in mode `numa` (its size) as the CXL
quota: pool memory is steered like local memory. The policy:

| policy | |
|:-------|:-|
| `none` | not steered (default) |
| `auto` | by the memory types of the results: `first-cxl` with only CXL memory, `first-dram` with only DRAM, `start-interleaved` with both |
| `first-dram` | the DRAM quota first, then CXL |
| `first-cxl` | the CXL quota first, then DRAM |
| `start-interleaved` | DRAM and CXL interleaved until the smaller quota is used, then the rest of the other |
| `end-interleaved` | the excess of the larger quota first, then interleaved |
| `waypoints` | along `waypoints` |

The steering adds the nodes to the container's `cpuset.mems` as the plan
reaches them (memory is never migrated), sets the memory policy of the
container's threads, and throttles each step with `memory.high`. When
none of the nodes in `cpuset.mems` has normal (non-movable) memory, as
for a container with only CXL memory whose nodes are onlined movable,
the nearest node with normal memory (`/sys/devices/system/node/has_normal_memory`,
by node distance) is added too: unmovable user allocations, such as pipe
buffers, obey `cpuset.mems` but cannot use movable memory, and would fail
with ENOMEM (`runc` fails to start the container: `write exec fifo:
cannot allocate memory`). The memory policy keeps the allocations of the
container on the CXL node.

Steering is not for every workload. It narrows `cpuset.mems` to the
nodes of the plan, sets the memory policy of the threads that exist when
it starts (processes that are not descendants of them, such as those of
`kubectl exec`, keep theirs), and holds the cgroup at `memory.high` at
every step until the plan moves on. Workloads that place their memory
themselves, such as HPC applications and databases, are better left
unsteered. A steered container cannot take a `numa` lease
([leases.md](leases.md#limitations)). A restart of the plugin, graceful
or killed, also the one after a restart of the runtime, does not restart
the steering of running containers, nor steers those created while it was
down: the restarted plugin manages them like containers that are not
steered (below), and they keep their memory policies. It sets the
`memory.high` of the containers that the steering of the stopped plugin
throttled to `max`, as the end of a steering does, also when the
configuration no longer steers them (the plugin keeps them in
`steeredContainers.json`), and leaves the `memory.high` of the others
alone. A container whose steering fails to start (`failed to start
memory steering`) is managed like a container that is not steered too.

A container that is not steered (policy `none`, or no `numa` memory) is
managed like a [container without claims](#containers-without-claims):
with `defaults.container.fencing` `allowed-mems` (the default) its
`cpuset.mems` are its own nodes without the CXL nodes of the driver,
plus the nodes of its `numa` results (memdev slices, regions, pool
devices) and of its `numa` leases; its memory policy and `memory.high`
are left alone. The kernel allocates its memory from the nodes of its
CPUs first, and the workload binds memory to the CXL node itself with the
node number of `CXL_<KEY>_NODE`, for example with `numactl --membind` or
`mbind`. It may take `numa` leases. Its `dram` and `region` results
reserve capacity only. With `fencing` `none` its `cpuset.mems` are left
as they are.

A container has one policy: results that set different ones fail its
CreateContainer ([Container settings](#container-settings)); the plugin
logs the error too (`NRI CreateContainer: <error>`). It logs the
management of every container at verbosity 3, `memory steered`, `fenced`
or `none`, with the effective policy and fencing and where they came
from (`from <origin>`, `(node default)`, `(default)`):

```
NRI CreateContainer: ctr=<ctr>: memory steered (steering auto from claim ns/a request r, fencing allowed-mems (default))
NRI CreateContainer: ctr=<ctr>: memory fenced (steering none (default), fencing allowed-mems (default))
NRI CreateContainer: ctr=<ctr>: memory none (steering none (default), fencing none (node default))
```

and, for a container with results,

```
NRI CreateContainer: ctr=<ctr>: steering policy auto: no numa memory to steer
NRI CreateContainer: ctr=<ctr>: dram and region memory is not steered: the claims reserve capacity only
```

After a restart the plugin computes the management of the running
containers again from their markers and the prepared claims, and steers
none of them (`NRI Synchronize: ctr=<ctr> id=<id>: steering not
restarted, memory fenced; memory.high <bytes> removed (max)` for one that
was steered); a container whose settings no longer combine is taken as
steered (never fenced, never lent to) with the warning `NRI Synchronize:
ctr=<ctr>: <error>; taken as steered`.

Memory for running containers (leases) in mode `numa` is lent through
`cpuset.mems` ([leases.md](leases.md#limitations)).

## Containers without claims

The NUMA nodes on which the plugin onlines CXL memory are kept away from
the containers that have not claimed memory there. These nodes are the
nodes of `numa` slices of local memdevs and of pool devices in mode
`numa`, also of the companion claims of leases. The nodes of `region`
devices (regions that the plugin did not create) and DRAM nodes are not
among them: they are system RAM from boot, used by host processes and
running containers.

A container has such a node only through

- a `numa` result on it: a steered container gets it from the steering
  ([Steering](#steering)), any other container in its `cpuset.mems`
  next to its other nodes;
- a lease in mode `numa`: the node is lent ([leases.md](leases.md#flow)).

Every container that is not steered gets `cpuset.mems` = its own nodes
without these CXL nodes, plus the nodes of its `numa` results and leases.
Its own nodes are the `cpuset.mems` of its spec (set by the kubelet
memory manager or an earlier NRI plugin), or all nodes with memory
(`/sys/devices/system/node/has_memory`) when the spec has none. A new
container gets it when it is created; the running and created containers
are updated before the memory of a new node goes online, so no running
container sees the node. containerd applies an update of a container
that it has not marked started to its spec only: a container that is
being started when a node is kept away runs with the node until it has
started, when the plugin checks its cgroup and updates it. After a
restart the plugin updates the running containers when NRI has
synchronized and the lease broker has lent the memory of Ready `numa`
leases again. A node stays kept away when its last claim is released,
until the plugin restarts.

`defaults.container.fencing` of the [configuration file](#configuration-file)
selects this, for every container of the node; claims and DeviceClasses
cannot set it:

| value | |
|:------|:-|
| `allowed-mems` | (default, also when `defaults`, `container` or `fencing` is missing) a container that has not claimed memory on a CXL node of the driver does not have that node in its `cpuset.mems` (`Mems_allowed`). It cannot allocate there even with `mbind` or `set_mempolicy`, and a container out of other memory is OOM-killed rather than spilling to CXL memory. |
| `mempolicy` | through the memory policy of the container's threads; not implemented: the configuration is refused with `defaults.container.fencing: mempolicy is not implemented yet` |
| `none` | containers are left as they are: one without its own `cpuset.mems` inherits every node with memory, CXL nodes too |

Any other value is refused with `defaults.container.fencing: invalid
value "X" (allowed-mems, mempolicy or none)`, and the plugin does not
start. Steering and leases work with every value. At start the plugin
logs the node defaults:

```
defaults.container.fencing: allowed-mems: containers get the CXL nodes of the driver only by claims and leases
defaults.container.fencing: none: containers are not kept off the CXL nodes of the driver
defaults.container.steering.policy: none: containers are steered only when their claims opt in
defaults.container.steering.policy: auto: containers with numa claims are steered unless their claims say none
```

(the last one with the policy of the node default), and
`NRI fence: fencing CXL node N (fenced nodes ...)` when it starts keeping
a node away.

While no node is kept away (no CXL memory onlined by the plugin since
its start, and none of its prepared claims), no container is changed.
Without NRI (the socket cannot be reached) containers are not changed
either.

Not covered:

- Pod sandboxes (the `pause` containers): NRI cannot update their
  `cpuset.mems`. The pause process allocates nothing after its start.
- Processes outside containers (kubelet, the container runtime, systemd
  services) keep every node.

An NRI resource policy that sets `cpuset.mems` of containers
(nri-resource-policy balloons or topology-aware) needs
`defaults.container.fencing` `none` and no steering: NRI refuses a
container whose `cpuset.mems` two plugins set, and the container is not
created.

## Environment variables

Every memory device of a claim, and the memory of a lease, gives a
container the same set of variables:

| variable | value | present for |
|:---------|:------|:------------|
| `CXL_<KEY>_SERIAL` | `0x<hex>` | memdevs (local and pool) |
| `CXL_<KEY>_SHARED` | `0` or `1` | memdevs: `1` for a shared device, also when the claim or lease uses it exclusively |
| `CXL_<KEY>_MODE` | `numa`, `dax`, `block` or `fs` | every memory device |
| `CXL_<KEY>_SIZE` | bytes | every memory device: what the claim or lease got (the slice of a local memdev, the whole pool device, the consumed capacity of a region or DRAM; of modes `block` and `fs` the size of the fsdax namespace) |
| `CXL_<KEY>_NODE` | NUMA node | mode `numa`: memdev slices, pool devices, regions |
| `CXL_<KEY>_NODES` | cpuset syntax | `dram` |
| `CXL_<KEY>_DAX` | `/dev/daxX.Y` | mode `dax`: the device node of a claim; of a lease, the host path (informational: the container has no such node) |
| `CXL_<KEY>_FD` | file descriptor number | leases of modes `dax` and `block`, the command of `cxl-request request --exec` and `cxl-request fd --exec`: instead of `DAX` (`dax`) or `PATH` (`block`) |
| `CXL_<KEY>_PATH` | path | mode `block`: the block device node `/dev/pmemK` of a claim; of a lease, the host path (informational: the container has no such node); mode `fs`: the directory of the filesystem in the container (`path` of a claim, `/run/cxl/fs/<name>` of a lease) |
| `CXL_<KEY>_ACCESS` | `direct` or `cached` | mode `fs` |
| `CXL_<KEY>_READONLY` | `0` or `1` | modes `dax` and `block`; `1` in mode `fs` |

`<KEY>`:

- memdev: the serial in upper-case hex without `0x` (`C100E2E1`);
- region: `REGION<n>` from the region name (`REGION0`);
- DRAM: `DRAM`.

The second and later devices with the same key in one claim (two slices
of one memdev, two requests on one region) get `_2`, `_3`, ... appended:
`C100E2E1_2`, `REGION0_2`. The count runs over the allocation results of
the claim, whatever requests a container references.

Programs find what they got by scanning `CXL_*_MODE`.

The variables and device nodes come from CDI devices, one per allocation
result of a claim: `nri.io/cxl=claim-<uid>-<n>` (spec file `cxl-claims`)
and `nri.io/cxl-pool=claim-<uid>-<n>` (spec file `cxl-pool`), n being the
index of the result in the claim's allocation (so the n of one driver may
have gaps). Each has the marker, the variables and the device node (or,
in mode `fs`, the bind mount) of its own result only. kubelet gives a
container the CDI devices of the requests it references
(`resources.claims[].request`), all of them without a request: a
container that references only the read-only request of a claim gets only
that request's device node and variables, and only that result's memory
and settings count for it ([Container settings](#container-settings)).

Other variables:

| variable | |
|:---------|:-|
| `CXL_CLAIM_<uid>_<n>=1` | the marker of allocation result n of a claim (the claim uid with `_` for `-`), in the CDI device of the result, both drivers; internal: the NRI plugin finds the results that a container uses by it |
| `CXL_LEASE_SOCKET=/run/cxl/cxl.sock` | containers of claims on `cxl-lease` |
| `CXL_LEASE=<id>` | the output of `cxl-request env` and the commands of `cxl-request ... --exec` |

The lease variables are described in [leases.md](leases.md). Two claims
of the same memdev in one container set the same names; the container sees
one value of each.

## What the memory contains

- Mode `numa`, any source: the memory is system RAM; the kernel gives a
  process only zeroed pages.
- Local `dax` slices: the plugin writes zeros to the whole slice before
  the claim gets it, so a claim never reads what an earlier claim left
  there.
- Exclusive pool devices in mode `dax`: the content is kept. Nothing
  clears the device between claims, so a claim, maybe on another node,
  reads what the previous one wrote.
- Shared local devices: the same bytes for every claim and lease of the
  device on the node, zeroed only when the plugin creates its region: a
  claim reads what the last writer left, also after the device was idle,
  until the node reboots
  ([local.md](local.md#shared-local-devices)).
- Shared pool devices: the same bytes for every host that has the device
  attached, as long as the pool keeps the device.
- Pool devices of persistent memory: the data and the namespace labels
  stay in the device as long as the pool keeps it, also while no host has
  it attached; releasing a claim changes neither. A new device is all
  zeros, without labels: the first writable `block` claim creates the
  fsdax namespace, readers find it in the labels. Readers see what the
  last writer wrote; erofs never writes the device.

## Example claims

[`deployment/samples/dra-driver-cxl`](tree:/deployment/samples/dra-driver-cxl)
has a complete claim and pod for each case. The pods of claims 1-10 and
13-15 use their claim as `mem` the same way:

```yaml
apiVersion: v1
kind: Pod
metadata: {name: consumer}
spec:
  resourceClaims:
  - {name: mem, resourceClaimName: <claim>}       # or resourceClaimTemplateName
  containers:
  - name: app
    image: docker.io/library/python:3-alpine
    command: ["sh", "-c", "env | grep ^CXL_ | sort; sleep infinity"]
    resources: {claims: [{name: mem}]}
```

The claims show `spec.devices` and the environment the container sees,
with the local memdev `0xc100e2e1`, the shared local device `0xc100e2e2`
(listed in `sharedDevices`), the exclusive pool device `0xc1ee0001` and
the shared pool device `0xc1ae0001`.

1. 128Mi of local CXL memory as RAM; the container is not steered, it has
   the node in its `cpuset.mems`
   ([local-numa.yaml](blob:/deployment/samples/dra-driver-cxl/local-numa.yaml)):

   ```yaml
   requests: [{name: mem, exactly: {deviceClassName: cxl-local, capacity: {requests: {memory: 128Mi}}}}]
   ```

   ```
   CXL_C100E2E1_MODE=numa
   CXL_C100E2E1_NODE=2
   CXL_C100E2E1_SERIAL=0xc100e2e1
   CXL_C100E2E1_SHARED=0
   CXL_C100E2E1_SIZE=134217728
   CXL_CLAIM_<uid>_0=1
   ```

2. A 64Mi read-only dax slice of a local memdev; with 128 MiB memory
   blocks the slice is 128Mi
   ([local-dax-readonly.yaml](blob:/deployment/samples/dra-driver-cxl/local-dax-readonly.yaml)):

   ```yaml
   requests: [{name: mem, exactly: {deviceClassName: cxl-local, capacity: {requests: {memory: 64Mi}}}}]
   config:
   - opaque: {driver: cxl.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {mode: dax, readOnly: true}}}
   ```

   ```
   CXL_C100E2E1_DAX=/dev/dax0.1
   CXL_C100E2E1_MODE=dax
   CXL_C100E2E1_READONLY=1
   CXL_C100E2E1_SERIAL=0xc100e2e1
   CXL_C100E2E1_SHARED=0
   CXL_C100E2E1_SIZE=134217728
   CXL_CLAIM_<uid>_0=1
   ```

   One ResourceClaim (not a template) that several pods reference gives
   all of them the same slice
   ([local-dax-shared-claim.yaml](blob:/deployment/samples/dra-driver-cxl/local-dax-shared-claim.yaml)).

3. A specific local device: add to the request

   ```yaml
   selectors: [{cel: {expression: 'device.attributes["cxl.nri.io"].serial == "0xc100e2e1"'}}]
   ```

4. 512Mi of pool memory as RAM: a whole exclusive device of at least
   512Mi; not steered, like claim 1
   ([pool-numa.yaml](blob:/deployment/samples/dra-driver-cxl/pool-numa.yaml)):

   ```yaml
   requests: [{name: mem, exactly: {deviceClassName: cxl-pool, capacity: {requests: {memory: 512Mi}}}}]
   ```

   ```
   CXL_C1EE0001_MODE=numa
   CXL_C1EE0001_NODE=3
   CXL_C1EE0001_SERIAL=0xc1ee0001
   CXL_C1EE0001_SHARED=0
   CXL_C1EE0001_SIZE=536870912
   CXL_CLAIM_<uid>_0=1
   ```

5. An exclusive pool device as dax: claim 4 plus
   ([pool-dax.yaml](blob:/deployment/samples/dra-driver-cxl/pool-dax.yaml))

   ```yaml
   config:
   - opaque: {driver: cxl-pool.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {mode: dax}}}
   ```

   ```
   CXL_C1EE0001_DAX=/dev/dax0.0
   CXL_C1EE0001_MODE=dax
   CXL_C1EE0001_READONLY=0
   ...
   ```

6. The shared pool device `0xc1ae0001` exclusively (the writer of
   single-writer sharing): no capacity request
   ([pool-shared-writer-readers.yaml](blob:/deployment/samples/dra-driver-cxl/pool-shared-writer-readers.yaml)
   has the writer of 6 and the readers of 8):

   ```yaml
   requests: [{name: mem, exactly: {deviceClassName: cxl-pool-shared, selectors: [{cel: {expression: 'device.attributes["cxl-pool.nri.io"].serial == "0xc1ae0001"'}}]}}]
   ```

   ```
   CXL_C1AE0001_DAX=/dev/dax0.0
   CXL_C1AE0001_MODE=dax
   CXL_C1AE0001_READONLY=0
   CXL_C1AE0001_SERIAL=0xc1ae0001
   CXL_C1AE0001_SHARED=1
   CXL_C1AE0001_SIZE=268435456
   CXL_CLAIM_<uid>_0=1
   ```

7. One share of the same device: claim 6 plus, in `exactly`,

   ```yaml
   capacity: {requests: {shares: "1"}}
   ```

8. One share, read-only (a reader): claim 7 plus

   ```yaml
   config:
   - opaque: {driver: cxl-pool.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {readOnly: true}}}
   ```

   ```
   CXL_C1AE0001_READONLY=1
   ...
   ```

   A reader that asks while the writer has the device waits (its pod stays
   pending) until the writer's claim is deallocated: the writer's pod has
   finished or is deleted.

9. 256Mi as dax, local if a local memdev has room, else pool
   ([local-then-pool-dax.yaml](blob:/deployment/samples/dra-driver-cxl/local-then-pool-dax.yaml)):

   ```yaml
   requests:
   - name: mem
     firstAvailable:
     - {name: local, deviceClassName: cxl-local, capacity: {requests: {memory: 256Mi}}}
     - {name: pool,  deviceClassName: cxl-pool,  capacity: {requests: {memory: 256Mi}}}
   config:
   - opaque: {driver: cxl.nri.io,      parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {mode: dax}}}
   - opaque: {driver: cxl-pool.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {mode: dax}}}
   ```

   The two entries differ in `driver` only.

10. Steering, opted in: DRAM first, then a pre-created CXL node
    ([region-dram-policy.yaml](blob:/deployment/samples/dra-driver-cxl/region-dram-policy.yaml)):

    ```yaml
    requests:
    - {name: dram, exactly: {deviceClassName: cxl-dram,   capacity: {requests: {memory: 64Mi}}}}
    - {name: cxl,  exactly: {deviceClassName: cxl-region, capacity: {requests: {memory: 64Mi}}}}
    config:
    - opaque: {driver: cxl.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, container: {steering: {policy: first-dram}}}}
    ```

    ```
    CXL_CLAIM_<uid>_0=1
    CXL_CLAIM_<uid>_1=1
    CXL_DRAM_MODE=numa
    CXL_DRAM_NODES=0-1
    CXL_DRAM_SIZE=67108864
    CXL_REGION0_MODE=numa
    CXL_REGION0_NODE=2
    CXL_REGION0_SIZE=67108864
    ```

11. A pod that may request memory while it runs; a template, so that the
    claim follows the pod
    ([lease.yaml](blob:/deployment/samples/dra-driver-cxl/lease.yaml),
    [leases.md](leases.md)):

    ```yaml
    apiVersion: resource.k8s.io/v1
    kind: ResourceClaimTemplate
    metadata: {name: cxl-lease}
    spec: {spec: {devices: {requests: [{name: lease, exactly: {deviceClassName: cxl-lease}}]}}}
    ```

    The container gets `CXL_LEASE_SOCKET=/run/cxl/cxl.sock`,
    `/usr/local/bin/cxl-request` and the claim marker.

12. A writer of a persistent pool device and its readers
    ([pool-persistent-erofs.yaml](blob:/deployment/samples/dra-driver-cxl/pool-persistent-erofs.yaml)).
    The writer claims the device exclusively (no capacity request), in
    mode `block`:

    ```yaml
    requests: [{name: mem, exactly: {deviceClassName: cxl-pool-persistent}}]
    config:
    - opaque: {driver: cxl-pool.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {mode: block}}}
    ```

    ```
    CXL_C1AE0001_MODE=block
    CXL_C1AE0001_PATH=/dev/pmem1
    CXL_C1AE0001_READONLY=0
    CXL_C1AE0001_SERIAL=0xc1ae0001
    CXL_C1AE0001_SHARED=1
    CXL_C1AE0001_SIZE=534773760
    CXL_CLAIM_<uid>_0=1
    ```

    A reader, after the writer is done, with one share in mode `fs`:

    ```yaml
    requests: [{name: mem, exactly: {deviceClassName: cxl-pool-persistent, capacity: {requests: {shares: "1"}}}}]
    config:
    - opaque: {driver: cxl-pool.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {mode: fs, readOnly: true, path: /models}}}
    ```

    ```
    CXL_C1AE0001_ACCESS=direct
    CXL_C1AE0001_MODE=fs
    CXL_C1AE0001_PATH=/models
    CXL_C1AE0001_READONLY=1
    ...
    ```

13. The shared local device `0xc100e2e2` exclusively (the writer): no
    capacity request
    ([local-shared-writer-readers.yaml](blob:/deployment/samples/dra-driver-cxl/local-shared-writer-readers.yaml)
    has the writer of 13 and the readers of 15,
    [local.md](local.md#shared-local-devices)):

    ```yaml
    requests: [{name: mem, exactly: {deviceClassName: cxl-local-shared, selectors: [{cel: {expression: 'device.attributes["cxl.nri.io"].serial == "0xc100e2e2"'}}]}}]
    ```

    ```
    CXL_C100E2E2_DAX=/dev/dax0.0
    CXL_C100E2E2_MODE=dax
    CXL_C100E2E2_READONLY=0
    CXL_C100E2E2_SERIAL=0xc100e2e2
    CXL_C100E2E2_SHARED=1
    CXL_C100E2E2_SIZE=1073741824
    CXL_CLAIM_<uid>_0=1
    ```

14. One share of the same device: claim 13 plus, in `exactly`,

    ```yaml
    capacity: {requests: {shares: "1"}}
    ```

15. One share, read-only (a reader): claim 14 plus

    ```yaml
    config:
    - opaque: {driver: cxl.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryConfig, device: {readOnly: true}}}
    ```

    ```
    CXL_C100E2E2_READONLY=1
    ...
    ```

    As with a shared pool device, a reader that asks while the writer has
    the device waits until the writer's claim is deallocated.

## nri-dra-driver-cxl flags

Every flag with an environment variable takes its default from the
variable when it is set. Both `-flag` and `--flag` work.

| flag | environment | default | |
|:-----|:------------|:--------|:-|
| `--node-name` | `NODE_NAME` | (required) | the node the plugin runs on |
| `--kubeconfig` | `KUBECONFIG` | (empty: in-cluster config) | |
| `--kube-api-qps` | `KUBE_API_QPS` | `5` | queries per second of the Kubernetes API client |
| `--kube-api-burst` | `KUBE_API_BURST` | `10` | burst of the Kubernetes API client |
| `--cdi-root` | `CDI_ROOT` | `/etc/cdi` | where the CDI spec files are written |
| `--sysfs` | `SYSFS_ROOT` | (empty: the host's `/sys`) | sysfs mount point, for testing |
| `--config-str`, `-c` | `CONFIG_STR` | (empty) | the [configuration](#configuration-file) as a JSON or YAML string |
| `--config-file`, `-f` | | | the configuration file, JSON or YAML; not together with `-c` |
| `--nri-name` | `NRI_PLUGIN_NAME` | `dra-driver-cxl` | NRI plugin name |
| `--nri-idx` | `NRI_PLUGIN_IDX` | `30` | NRI plugin index (place in the plugin chain, higher is later) |
| `--nri-socket` | `NRI_SOCKET` | (empty: the runtime's default) | NRI socket path |
| `--pool-driver-name` | `POOL_DRIVER_NAME` | `cxl-pool.nri.io` | DRA driver name of the pool driver; empty disables it |
| `--pool-prepare-timeout` | `POOL_PREPARE_TIMEOUT` | `30s` | how long the pool driver waits for a hotplugged memdev |
| `--leases` | `LEASES` | `true` | lend memory to running containers: publish the `lease` device, serve lease sockets, create companions (needs NRI) |
| `--lease-cli` | `LEASE_CLI` | `/usr/local/bin/cxl-request` | host path of the static `cxl-request`, mounted into the containers of lease claims |
| `--lease-cli-source` | `LEASE_CLI_SOURCE` | (empty) | at start, before any CDI spec is written, copy this file to `--lease-cli` (mode 0755, replaced atomically); the chart copies the `/bin/cxl-request` of the image to the host this way |
| `--lease-wait` | `LEASE_WAIT` | `120s` | how long a lease request waits for Ready when it does not say |
| `--lease-companion-image` | `LEASE_COMPANION_IMAGE` | `registry.k8s.io/pause:3.10` | image of the companion pods of leases |

`-v` and the other logging flags of klog are accepted too;
`nri-dra-driver-cxl -help` lists them all. The plugin stops on SIGTERM and
SIGINT, and exits with status 1 when the runtime closes the NRI connection,
to be restarted ([As a host process](#as-a-host-process)).

Without NRI (the socket cannot be reached) the plugin runs on: claims are
prepared, containers are not steered and not kept off the CXL nodes of
the plugin, and lease requests fail with
`lending unavailable: NRI not connected`.

## Configuration file

`-f FILE` (or `-c STRING`; the `config` value of the Helm chart), JSON or
YAML; unknown keys are refused. All keys are optional:

```yaml
ignoreDevices: ["mem0", "0xc100e2e0"]
sharedDevices: ["0xc100e2e2"]
manageMemdevs: true
memdevSettings:
- device: "0xc1ffe2ef"
  usableSize: 128Gi
verifyAddressing: true
udevStableDuration: 200ms
defaults:
  container:
    steering: {policy: none}    # none (default) | auto | first-dram | ...
    fencing: allowed-mems       # allowed-mems (default) | mempolicy | none
```

| key | type | default | |
|:----|:-----|:--------|:-|
| `ignoreDevices` | list of strings | | CXL memory devices to leave alone: device name (`mem0`, `cxl/mem0`), `major:minor` (`251:0`), or serial in decimal or `0x` hex |
| `sharedDevices` | list of strings | | local CXL memory devices to publish as shared devices, matched as `ignoreDevices`: claims and leases of such a device map the whole device as devdax ([local.md](local.md#shared-local-devices)) |
| `ignoreRegions` | list of strings | | CXL regions to leave alone (`region0`) |
| `ignoreNodes` | list of integers | | NUMA nodes to leave alone |
| `ignoreNewMemoryDevices` | bool | `false` | ignore memdevs that are hotplugged after the start |
| `ignoreNewRegions` | bool | `false` | ignore regions that are created after the start |
| `ignoreNewNodes` | bool | `false` | ignore NUMA nodes that appear after the start |
| `ignoreDRAMNodes` | bool | `false` | publish no `dram` device |
| `udevStableDuration` | duration | `200ms` | quiet period after the last udev event before the devices are scanned again |
| `manageMemdevs` | bool | `true` | publish the local memdevs that have no region and create their regions for claims |
| `memdevSettings` | list | | settings of individual local memdevs: `device` (name `mem0` or serial in decimal or `0x` hex) and `usableSize` (quantity): only the first `usableSize` bytes of the memdev are published and mapped by its regions ([local.md](local.md#broken-and-aliased-memory)) |
| `verifyAddressing` | bool | `true` | run an address line test on every new region of a local memdev, and use only the distinct bytes of a memdev whose memory aliases ([local.md](local.md#broken-and-aliased-memory)) |
| `defaults.container.steering` | object | `{policy: none}` | the steering of every container of the node whose results do not set it, the fields of `container.steering` ([MemoryConfig fields](#memoryconfig-fields), [Steering](#steering)); `{policy: auto}` steers every container with `numa` memory |
| `defaults.container.fencing` | string | `allowed-mems` | how the plugin manages the memory of containers on the CXL nodes it onlines: `allowed-mems`, `mempolicy` (not implemented) or `none` ([Containers without claims](#containers-without-claims)) |
| `testability` | object | | fake devices for testing without CXL hardware: `fakeRegionDevices`, `fakeUdevFifo` |

`defaults` has the `container` section of a
[MemoryConfig](#memoryconfig-fields) only: the node defaults of the
settings of containers, which their results override field by field
([Container settings](#container-settings)). It is decoded strictly and
case-sensitively, and an error stops the plugin:

- `defaults: json: unknown field "F"` (`device`, `pool`,
  `container.Fencing`, ...)
- `defaults.container.fencing: invalid value "X" (allowed-mems, mempolicy or none)`,
  `defaults.container.fencing: mempolicy is not implemented yet`
- the texts of the `container` section
  ([Configuration errors](#configuration-errors)) with `defaults.` instead
  of `MemoryConfig: `, as for an effective steering:
  `defaults.container.steering.policy: invalid policy "X" (...)`,
  `defaults.container.steering.maxStep needs a policy other than none`,
  `defaults.container.steering.policy waypoints needs waypoints`

[local.md](local.md#what-the-plugin-publishes) describes
`manageMemdevs`. The configuration is read at start: a change of
`sharedDevices`, or of any other key, takes effect when the plugin
restarts.

## Files on the node

| file | |
|:-----|:-|
| `/var/lib/kubelet/plugins/cxl.nri.io/preparedClaims.json` | prepared claims of `cxl.nri.io` (kubelet plugin helper) |
| `/var/lib/kubelet/plugins/cxl.nri.io/preparedClaimsInfo.json` | devices of every prepared claim of `cxl.nri.io`, with the request and the resolved `container` settings of each result, and its lend |
| `/var/lib/kubelet/plugins/cxl.nri.io/localDevices.json` | regions and slices of local memdevs, and the claims of shared local devices |
| `/var/lib/kubelet/plugins/cxl.nri.io/poolSerials.json` | the serials of pool devices and of local memdevs that the plugin has seen, and the pools it has listed: a pool device is never published as a local memdev while its controller's ResourceSlices are absent; edit it only while the plugin is stopped ([local.md](local.md#what-the-plugin-publishes)) |
| `/var/lib/kubelet/plugins/cxl.nri.io/steeredContainers.json` | the containers that the steering of the plugin throttles, with their cgroups: a restarted plugin removes their `memory.high` ([Steering](#steering)) |
| `/var/lib/kubelet/plugins/cxl.nri.io/leases.json` | the lease table |
| `/var/lib/kubelet/plugins/cxl.nri.io/leases/<claim uid>/cxl.sock` | the lease socket of a lease claim |
| `/var/lib/kubelet/plugins/cxl.nri.io/cxl-request` | the lease CLI that the plugin of the Helm chart copies from its image (`--lease-cli-source`) |
| `/var/lib/kubelet/plugins/cxl-pool.nri.io/preparedPoolClaims.json` | prepared claims of `cxl-pool.nri.io` |
| `/var/lib/kubelet/plugins/cxl-pool.nri.io/preparingPoolClaims.json` | claims of `cxl-pool.nri.io` whose Prepare has touched a device and not finished: after a plugin restart their Unprepare releases the device ([pool.md](pool.md#ordering-and-failure-semantics)) |
| `/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/<serial hex>-<access>` | the node mount of the erofs of a persistent pool device for mode `fs` |
| `<cdi root>/cxl-claims.yaml` | CDI kind `nri.io/cxl`: a device `claim-<uid>-<n>` per allocation result n of a prepared `cxl.nri.io` claim, with the marker, the result's variables and its dax device node |
| `<cdi root>/cxl-leases.yaml` | CDI kind `nri.io/cxl`: a device `lease-<uid>` per lease claim |
| `<cdi root>/cxl-pool.yaml` | CDI kind `nri.io/cxl-pool`: a device `claim-<uid>-<n>` per allocation result n of a prepared pool claim, likewise |

The regions and slices of local memdevs are described in
[local.md](local.md#what-prepare-does), the lease table and sockets in
[leases.md](leases.md#life-cycle), the prepared pool claims in
[pool.md](pool.md#what-the-node-plugin-does). Companion claims of leases
get no CDI device ([leases.md](leases.md#companion-objects)).

At start the plugin deletes every CDI spec of the kinds `nri.io/cxl` and
`nri.io/cxl-pool` and writes the three files again from the prepared
claims.
