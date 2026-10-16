# How to deploy and use the CXL DRA driver

CAUTION: experimental. Interfaces may change.

`nri-dra-driver-cxl` runs two DRA drivers on every node: `cxl.nri.io` for
the memory of the node (local CXL memory devices, CXL regions, DRAM, the
lease device) and `cxl-pool.nri.io` for the devices of a CXL memory pool.
The words used below (`source`, `type`, `shared`, `mode`, `readOnly`,
`serial`, `size`, `hosts`) are defined in the
[Vocabulary](index.md#vocabulary).

- [Requirements](#requirements)
- [Build and deploy](#build-and-deploy)
- [Devices of cxl.nri.io](#devices-of-cxlnriio)
- [DeviceClasses](#deviceclasses)
- [Opaque configurations](#opaque-configurations)
- [Steering](#steering)
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
  enabled, CRI-O 1.23 or newer) and with NRI enabled: the driver steers
  containers and lends memory to them through NRI.
- cgroup v2.
- Kernel with CXL regions (`CONFIG_CXL_REGION`), `CONFIG_DEV_DAX`,
  `CONFIG_DEV_DAX_KMEM`, `CONFIG_MEMORY_HOTREMOVE`, and `CONFIG_FS_DAX` for
  mode `dax` (without it every devdax `mmap` fails).
- The `cxl` (ndctl) tool for local memdevs and pool devices, `daxctl` for
  pool devices ([local.md](local.md#node-requirements),
  [pool.md](pool.md#node-requirements)). The container image of the driver
  includes both; a host process needs them installed on the node.
- `/sys/devices/system/memory/auto_online_blocks` set to `offline`: the
  plugin onlines the memory of `numa` slices and pool devices itself, and
  the kernel must never online shared devices as RAM.

### Feature gates

The driver uses these Kubernetes features:

| feature gate | used for | default in v1.37 |
|:-------------|:---------|:-----------------|
| `DRADeviceBindingConditions` | pool devices: the scheduler waits until the pool controller has attached the device | on |
| `DRAResourceClaimDeviceStatus` | pool devices: the pool controller writes the device serial into the claim status | on |
| `DRAConsumableCapacity` | many claims share one device: slices of a local memdev, regions, DRAM, `hosts` of a shared pool device | on |
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
| `/usr/bin/cxl`, `/usr/bin/daxctl` | the tools of ndctl v85, with their shared libraries and the dynamic loader |
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
[configuration file](#configuration-file), and the six
[DeviceClasses](#deviceclasses). The pod of the DaemonSet is privileged,
runs in the host PID namespace (the lease broker maps the process ids of
its callers to containers), and mounts `/var/lib/kubelet/plugins`,
`/var/lib/kubelet/plugins_registry`, `/etc/cdi`, `/var/run/cdi`,
`/var/run/nri`, `/sys`, `/dev` and `/lib/modules` (read-only) of the host
at the same paths. Its image has the `cxl` and `daxctl` tools. So every
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
| `logLevel` | `4` | `-v` |
| `extraEnv` | | more environment variables of the plugin container, name: value |
| `tolerations`, `affinity`, `nodeSelector` | | where the DaemonSet runs |
| `podPriorityClassNodeCritical` | `true` | priority class `system-node-critical` |

For example, a configuration that leaves one device alone, and the
DaemonSet only on the nodes that have CXL memory:

```bash
cat > cxl-values.yaml <<'EOF'
config:
  ignoreDevices: ["0xc100e2e0"]
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
systemd unit. It then needs the `cxl` and `daxctl` tools on the node and a
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
systemd-run --unit nri-dra-driver-cxl -E KUBECONFIG=/etc/kubernetes/nri-dra-driver-cxl.conf \
    /usr/local/bin/nri-dra-driver-cxl --node-name "$(hostname)" -f /etc/nri-dra-driver-cxl.yaml
```

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
| `shared` | `memdev` | `false`: `cxl.nri.io` publishes no device that several hosts share |
| `node` | `region` | the NUMA node of the region |
| `nodes` | `dram` | the DRAM NUMA nodes, cpuset syntax |
| `nodeAffinity` | `memdev`, `region` | the CPU NUMA node of the device; absent if unknown (for a region: unless all its memdevs agree) |
| `memoryBlockSize` | `memdev` | the memory block size of the node in bytes |

- `memdev-<serial hex>`, type `memdev`: a CXL memory device without a
  region; every claim gets a slice of it, created when the claim is
  prepared ([local.md](local.md)).
- `<region>-node<N>`, type `region`: a region that exists already
  (created by the BIOS or an admin) and is online as NUMA node N; claims
  consume its capacity and their containers are steered to N.
- `dram`, type `dram`: one device for all DRAM nodes, for steering;
  absent with `ignoreDRAMNodes`.
- `lease`, type `lease`: the device of lease claims
  ([leases.md](leases.md)); absent with `--leases=false`.

Every memory device has `capacity.memory` and `allowMultipleAllocations`,
so that many claims share it; with `DRANodeAllocatableResources`,
`nodeAllocatableResources` maps the claimed memory to the node's
allocatable memory. Pool devices are published by the pool controller
under `cxl-pool.nri.io` with the same memdev attributes (`type`, `source`,
`serial`, `shared`, `size`), see
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
| `cxl-local` | `cxl.nri.io`, `type == "memdev"` | a slice of a local memdev: RAM of its NUMA node (mode `numa`, default) or a devdax device (`DeviceConfig` `mode: dax`) |
| `cxl-pool` | `cxl-pool.nri.io`, `type == "memdev"`, `shared == false` | a whole exclusive pool device: a new NUMA node (default) or a devdax device (`mode: dax`) |
| `cxl-pool-shared` | `cxl-pool.nri.io`, `type == "memdev"`, `shared == true` | a shared pool device as devdax; one of its `hosts` by default, all of them (exclusive) with `capacity.requests.hosts` |
| `cxl-region` | `cxl.nri.io`, `type == "region"` | capacity of a pre-created CXL NUMA node; the container is steered to it |
| `cxl-dram` | `cxl.nri.io`, `type == "dram"` | DRAM capacity for steering |
| `cxl-lease` | `cxl.nri.io`, `type == "lease"` | the lease socket and `cxl-request` |

For example:

```yaml
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata: {name: cxl-pool}
spec:
  selectors:
  - cel: {expression: 'device.driver == "cxl-pool.nri.io" && device.attributes["cxl-pool.nri.io"].type == "memdev" && device.attributes["cxl-pool.nri.io"].shared == false'}
```

The classes carry no configuration: how a device is used (`mode`,
`readOnly`) is a `DeviceConfig` of the claim. Memory from either source,
local first, is a `firstAvailable` request with a subrequest per class
([example 9](#example-claims)).

## Opaque configurations

### DeviceConfig

Both drivers take the same configuration for the devices of a request:

```yaml
config:
- opaque:
    driver: cxl.nri.io                 # or cxl-pool.nri.io
    parameters:
      apiVersion: cxl.nri.io/v1alpha1  # <driver>/v1alpha1
      kind: DeviceConfig
      mode: dax
      readOnly: true
```

| field | values | default | |
|:------|:-------|:--------|:-|
| `mode` | `numa`, `dax` | `numa`; `dax` for shared devices | `numa`: the memory is online as system RAM of a NUMA node. `dax`: the container gets a devdax device `/dev/daxX.Y` of its own to `mmap`. Shared devices are `dax` only. |
| `readOnly` | `false`, `true` | `false` | `dax` only: the container's device node has CDI permissions `r`, so its device cgroup allows opening it for reading only. |

- `apiVersion` is the driver name followed by `/v1alpha1`; `driver` and
  `apiVersion` change together.
- Unknown fields are refused, and so is another apiVersion. An opaque
  configuration of the driver with a kind it does not know fails the
  Prepare before any device is touched:
  `unknown kind "..." (DeviceConfig or MemoryPolicyConfig)` for
  `cxl.nri.io`, `unknown kind "..." (DeviceConfig)` for `cxl-pool.nri.io`
  (a configuration without a kind gives `unknown kind ""`).
- Regions and DRAM (`cxl-region`, `cxl-dram`) are used as `numa` only: a
  `DeviceConfig` for them may say `mode: numa` and nothing else. In a
  claim that has such requests next to `dax` memdev requests, list the
  memdev requests in the `requests` of the `DeviceConfig`.
- A configuration comes from the DeviceClass or from the claim; the
  claim's comes later and replaces the class's. It applies to the requests
  it lists (a request `r` also covers its subrequests `r/s`) or, without
  `requests`, to all requests of its driver.
- Errors fail the Prepare of the claim (kubelet retries, the pod does not
  start); the error of the Prepare contains:
  - `DeviceConfig: invalid mode "..." (numa or dax)`
  - `DeviceConfig: mode numa: a shared device is used as dax only`
  - `DeviceConfig: readOnly needs mode dax`
  - `DeviceConfig: mode dax: a region is used as numa only`,
    `DeviceConfig: mode dax: a dram is used as numa only`
  - `DeviceConfig: apiVersion "...", expected "<driver>/v1alpha1"`
  - `DeviceConfig: invalid FromClaim config: json: unknown field "..."`
    (`FromClass` for a config of the DeviceClass)

| device | DeviceConfig | the container gets |
|:-------|:-------------|:-------------------|
| local memdev (`cxl-local`) | none | a slice online as RAM of the memdev's NUMA node |
| local memdev | `mode: dax` | a devdax slice of its own |
| exclusive pool device (`cxl-pool`) | none | the device online as a new NUMA node |
| exclusive pool device | `mode: dax` | the device as devdax |
| shared pool device (`cxl-pool-shared`) | none | the device as devdax, shared with the other claims of the device |
| shared pool device, `capacity.requests.hosts` = all | none | the device as devdax, no other claim has it meanwhile |
| any of the `dax` rows | `readOnly: true` | the same, the device node read-only |

Read-only is enforced by the kernel for every process of the container,
whatever its capabilities, except in privileged containers (their device
cgroup allows everything). It is a property of the claim, not of the
device: another claim of the same device may write, and the readers see
it.

### MemoryPolicyConfig

`cxl.nri.io` only: how the memory of a container is spread over the DRAM
and CXL nodes of its claims while it allocates ([Steering](#steering)).

```yaml
config:
- opaque:
    driver: cxl.nri.io
    parameters:
      apiVersion: cxl.nri.io/v1alpha1
      kind: MemoryPolicyConfig
      memoryUseOrder: first-dram
```

| field | values | |
|:------|:-------|:-|
| `memoryUseOrder` | `first-dram`, `first-cxl`, `start-interleaved`, `end-interleaved`, `waypoints` | `first-dram`: the DRAM quota first, then CXL; `first-cxl` the other way round; `start-interleaved`: DRAM and CXL interleaved until the smaller quota is used, then the rest of the other; `end-interleaved`: the excess of the larger quota first, then interleaved; `waypoints`: along `memoryUseWaypoints` |
| `memoryUseWaypoints` | list of `{targetUsages: [{memoryType: DRAM or CXL, usage: <quantity>}]}` | target usage per memory type at each waypoint; a type that is not listed keeps its usage of the previous waypoint; usages never decrease |
| `minStep` | quantity | the smallest amount of new allocations after which the route is re-evaluated; default `maxStep` |
| `maxStep` | quantity | the largest amount of new allocations after which the route is re-evaluated; default the total quota |

A `MemoryPolicyConfig` belongs to a claim, not to a request: it applies to
the containers that reference the claim, whatever its `requests` say, and
one container may have only one claim with a policy. It may come from the
DeviceClass or from the claim; the later one replaces the earlier.
Unknown fields, another apiVersion and an invalid policy fail the Prepare
of the claim with `MemoryPolicyConfig: ...`; an unknown kind with
`unknown kind "..." (DeviceConfig or MemoryPolicyConfig)`.

## Steering

A container that references `cxl.nri.io` claims in mode `numa` when it is
created is steered: the NRI plugin of `nri-dra-driver-cxl` finds the
claims by their marker (`CXL_CLAIM_<uid>`), takes the consumed capacity of
every `dram` device as the DRAM quota and of every `region` device and
`numa` memdev slice as the CXL quota, and steers the container's
allocations along the claim's `MemoryPolicyConfig`. Without one, a
container with only DRAM or only CXL uses that one (`first-dram`,
`first-cxl`), and one with both interleaves them (`start-interleaved`).
The steering adds the nodes to the container's `cpuset.mems` as the plan
reaches them (memory is never migrated), sets the memory policy of the
container's threads, and throttles each step with `memory.high`.

Pool devices in mode `numa` are not steered: the container gets the node
number in `CXL_<KEY>_NODE` and binds its memory to it itself, for example
with `numactl --membind` or `mbind`. The pool driver does not change
`cpuset.mems`, so other containers whose cpusets allow every node may
allocate from the node too.

Memory for running containers (leases) in mode `numa` is lent through
`cpuset.mems` instead; a steered container cannot take such a lease
([leases.md](leases.md#limitations)).

## Environment variables

Every memory device of a claim, and the memory of a lease, gives a
container the same set of variables:

| variable | value | present for |
|:---------|:------|:------------|
| `CXL_<KEY>_SERIAL` | `0x<hex>` | memdevs (local and pool) |
| `CXL_<KEY>_SHARED` | `0` or `1` | memdevs: `1` for a shared device, also when the claim or lease uses it exclusively |
| `CXL_<KEY>_MODE` | `numa` or `dax` | every memory device |
| `CXL_<KEY>_SIZE` | bytes | every memory device: what the claim or lease got (the slice of a local memdev, the whole pool device, the consumed capacity of a region or DRAM) |
| `CXL_<KEY>_NODE` | NUMA node | mode `numa`: memdev slices, pool devices, regions |
| `CXL_<KEY>_NODES` | cpuset syntax | `dram` |
| `CXL_<KEY>_DAX` | `/dev/daxX.Y` | mode `dax`: the device node of a claim; of a lease, the host path (informational: the container has no such node) |
| `CXL_<KEY>_FD` | file descriptor number | mode `dax`, the command of `cxl-request request --exec` and `cxl-request fd --exec`, instead of `DAX` |
| `CXL_<KEY>_READONLY` | `0` or `1` | mode `dax` |

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
have gaps). Each has the claim marker and the variables and device node
of its own result only. kubelet gives a container the CDI devices of the
requests it references (`resources.claims[].request`), all of them
without a request: a container that references only the read-only request
of a claim gets only that request's device node and variables.

Other variables:

| variable | |
|:---------|:-|
| `CXL_CLAIM_<uid>=1` | the claim marker (the claim uid with `_` for `-`), in every CDI device of both drivers, internal: the NRI plugin finds the claims of a container by it; pool claims have no steering information and are not steered |
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
- Shared pool devices: the same bytes for every host that has the device
  attached, as long as the pool keeps the device.

## Example claims

[`deployment/samples/dra-driver-cxl`](tree:/deployment/samples/dra-driver-cxl)
has a complete claim and pod for each case. The pods of claims 1-10 use
their claim as `mem` the same way:

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
with the local memdev `0xc100e2e1`, the exclusive pool device
`0xc1ee0001` and the shared pool device `0xc1ae0001`.

1. 128Mi of local CXL memory as RAM
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
   CXL_CLAIM_<uid>=1
   ```

2. A 64Mi read-only dax slice of a local memdev; with 128 MiB memory
   blocks the slice is 128Mi
   ([local-dax-readonly.yaml](blob:/deployment/samples/dra-driver-cxl/local-dax-readonly.yaml)):

   ```yaml
   requests: [{name: mem, exactly: {deviceClassName: cxl-local, capacity: {requests: {memory: 64Mi}}}}]
   config:
   - opaque: {driver: cxl.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: DeviceConfig, mode: dax, readOnly: true}}
   ```

   ```
   CXL_C100E2E1_DAX=/dev/dax0.1
   CXL_C100E2E1_MODE=dax
   CXL_C100E2E1_READONLY=1
   CXL_C100E2E1_SERIAL=0xc100e2e1
   CXL_C100E2E1_SHARED=0
   CXL_C100E2E1_SIZE=134217728
   CXL_CLAIM_<uid>=1
   ```

   One ResourceClaim (not a template) that several pods reference gives
   all of them the same slice
   ([local-dax-shared-claim.yaml](blob:/deployment/samples/dra-driver-cxl/local-dax-shared-claim.yaml)).

3. A specific local device: add to the request

   ```yaml
   selectors: [{cel: {expression: 'device.attributes["cxl.nri.io"].serial == "0xc100e2e1"'}}]
   ```

4. 512Mi of pool memory as RAM: a whole exclusive device of at least 512Mi
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
   CXL_CLAIM_<uid>=1
   ```

5. An exclusive pool device as dax: claim 4 plus
   ([pool-dax.yaml](blob:/deployment/samples/dra-driver-cxl/pool-dax.yaml))

   ```yaml
   config:
   - opaque: {driver: cxl-pool.nri.io, parameters: {apiVersion: cxl-pool.nri.io/v1alpha1, kind: DeviceConfig, mode: dax}}
   ```

   ```
   CXL_C1EE0001_DAX=/dev/dax0.0
   CXL_C1EE0001_MODE=dax
   CXL_C1EE0001_READONLY=0
   ...
   ```

6. The shared device `0xc1ae0001`, one of its hosts
   ([pool-shared-writer-readers.yaml](blob:/deployment/samples/dra-driver-cxl/pool-shared-writer-readers.yaml)
   has the writer of 7 and the readers of 8):

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
   CXL_CLAIM_<uid>=1
   ```

7. The same device exclusively (the writer of single-writer sharing):
   claim 6 plus, in `exactly`,

   ```yaml
   capacity: {requests: {hosts: "4"}}
   ```

8. The same device read-only (a reader): claim 6 plus

   ```yaml
   config:
   - opaque: {driver: cxl-pool.nri.io, parameters: {apiVersion: cxl-pool.nri.io/v1alpha1, kind: DeviceConfig, readOnly: true}}
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
   - opaque: {driver: cxl.nri.io,      parameters: {apiVersion: cxl.nri.io/v1alpha1,      kind: DeviceConfig, mode: dax}}
   - opaque: {driver: cxl-pool.nri.io, parameters: {apiVersion: cxl-pool.nri.io/v1alpha1, kind: DeviceConfig, mode: dax}}
   ```

10. Steering to a pre-created CXL node after DRAM
    ([region-dram-policy.yaml](blob:/deployment/samples/dra-driver-cxl/region-dram-policy.yaml)):

    ```yaml
    requests:
    - {name: dram, exactly: {deviceClassName: cxl-dram,   capacity: {requests: {memory: 64Mi}}}}
    - {name: cxl,  exactly: {deviceClassName: cxl-region, capacity: {requests: {memory: 64Mi}}}}
    config:
    - opaque: {driver: cxl.nri.io, parameters: {apiVersion: cxl.nri.io/v1alpha1, kind: MemoryPolicyConfig, memoryUseOrder: first-dram}}
    ```

    ```
    CXL_CLAIM_<uid>=1
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
SIGINT.

Without NRI (the socket cannot be reached) the plugin runs on: claims are
prepared, containers are not steered, and lease requests fail with
`lending unavailable: NRI not connected`.

## Configuration file

`-f FILE` (or `-c STRING`; the `config` value of the Helm chart), JSON or
YAML; unknown keys are refused. All keys are optional:

```yaml
ignoreDevices: ["mem0", "0xc100e2e0"]
manageMemdevs: true
udevStableDuration: 200ms
```

| key | type | default | |
|:----|:-----|:--------|:-|
| `ignoreDevices` | list of strings | | CXL memory devices to leave alone: device name (`mem0`, `cxl/mem0`), `major:minor` (`251:0`), or serial in decimal or `0x` hex |
| `ignoreRegions` | list of strings | | CXL regions to leave alone (`region0`) |
| `ignoreNodes` | list of integers | | NUMA nodes to leave alone |
| `ignoreNewMemoryDevices` | bool | `false` | ignore memdevs that are hotplugged after the start |
| `ignoreNewRegions` | bool | `false` | ignore regions that are created after the start |
| `ignoreNewNodes` | bool | `false` | ignore NUMA nodes that appear after the start |
| `ignoreDRAMNodes` | bool | `false` | publish no `dram` device |
| `udevStableDuration` | duration | `200ms` | quiet period after the last udev event before the devices are scanned again |
| `manageMemdevs` | bool | `true` | publish the local memdevs that have no region and create their regions for claims |
| `testability` | object | | fake devices for testing without CXL hardware: `fakeRegionDevices`, `fakeUdevFifo` |

[local.md](local.md#what-the-plugin-publishes) describes `manageMemdevs`.

## Files on the node

| file | |
|:-----|:-|
| `/var/lib/kubelet/plugins/cxl.nri.io/preparedClaims.json` | prepared claims of `cxl.nri.io` (kubelet plugin helper) |
| `/var/lib/kubelet/plugins/cxl.nri.io/preparedClaimsInfo.json` | devices, memory policy and lend of every prepared claim of `cxl.nri.io` |
| `/var/lib/kubelet/plugins/cxl.nri.io/localDevices.json` | regions and slices of local memdevs |
| `/var/lib/kubelet/plugins/cxl.nri.io/leases.json` | the lease table |
| `/var/lib/kubelet/plugins/cxl.nri.io/leases/<claim uid>/cxl.sock` | the lease socket of a lease claim |
| `/var/lib/kubelet/plugins/cxl.nri.io/cxl-request` | the lease CLI that the plugin of the Helm chart copies from its image (`--lease-cli-source`) |
| `/var/lib/kubelet/plugins/cxl-pool.nri.io/preparedPoolClaims.json` | prepared claims of `cxl-pool.nri.io` |
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
