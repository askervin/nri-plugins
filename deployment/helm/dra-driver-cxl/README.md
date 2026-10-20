# CXL DRA Driver

This chart deploys the dra-driver-cxl Node Resource Interface (NRI) plugin.
The plugin is a Dynamic Resource Allocation (DRA) driver for CXL memory: it
publishes the CXL memory devices, regions and DRAM of every node as DRA
devices (driver `cxl.nri.io`), prepares claims of CXL memory pool devices
(driver `cxl-pool.nri.io`), steers the memory of containers to their claimed
memory, and lends memory to running containers (leases).

CAUTION: experimental. Interfaces may change.

How to use the driver, its DeviceClasses, configurations and leases are
described in the
[CXL memory documentation](https://github.com/containers/nri-plugins/blob/main/docs/memory/cxl/usage.md).

## Prerequisites

- Kubernetes 1.37+, with the DRA feature gates listed in the CXL memory
  documentation.
- Helm 3.0.0+
- Container runtime with CDI and NRI enabled:
  - containerD:
    - At least [containerd 1.7.0](https://github.com/containerd/containerd/releases/tag/v1.7.0)
      release version to use the NRI feature.
    - Enable NRI feature by following
      [these](https://github.com/containerd/containerd/blob/main/docs/NRI.md#enabling-nri-support-in-containerd)
      detailed instructions, or set `nri.runtime.patchConfig` (see below).
  - CRI-O
    - At least [v1.26.0](https://github.com/cri-o/cri-o/releases/tag/v1.26.0)
      release version.
    - Enable NRI feature by following
      [these](https://github.com/cri-o/cri-o/blob/main/docs/crio.conf.5.md#crionri-table)
      detailed instructions, or set `nri.runtime.patchConfig` (see below).
- cgroup v2 and a kernel with CXL regions (`CONFIG_CXL_REGION`),
  `CONFIG_DEV_DAX`, `CONFIG_DEV_DAX_KMEM`, `CONFIG_MEMORY_HOTREMOVE` and
  `CONFIG_FS_DAX`; for pool devices of persistent memory also
  `CONFIG_CXL_PMEM`, `CONFIG_LIBNVDIMM`, `CONFIG_BLK_DEV_PMEM`,
  `CONFIG_ND_PFN`, `CONFIG_EROFS_FS` and `CONFIG_BLK_DEV_LOOP`.
- `/sys/devices/system/memory/auto_online_blocks` set to `offline`.

The image contains the `cxl`, `daxctl` and `ndctl` tools of ndctl and the
static `cxl-request` command line tool of leases. The pod runs privileged
in the host PID namespace, and mounts from the host `/sys`, `/dev`,
`/lib/modules` (read-only), the NRI socket directory `/var/run/nri`, the
CDI directories `/etc/cdi` and `/var/run/cdi`, and the kubelet directories
`/var/lib/kubelet/plugins` and `/var/lib/kubelet/plugins_registry`. At start
the driver copies `cxl-request` to
`/var/lib/kubelet/plugins/cxl.nri.io/cxl-request` on the host, from where
lease claims mount it into containers. `/var/lib/kubelet/plugins` is
mounted with `mountPropagation: Bidirectional`: the erofs filesystems
that the pool driver mounts under
`/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts` for claims in mode `fs`
must reach the host, where the container runtime binds them into
containers (kubelet makes `/var/lib/kubelet` a shared mount, and
Bidirectional needs a privileged container).

## Installing the Chart

Path to the chart: `nri-dra-driver-cxl`.

```sh
helm repo add nri-plugins https://containers.github.io/nri-plugins
helm install my-dra-driver-cxl nri-plugins/nri-dra-driver-cxl --namespace kube-system
```

The command above deploys the driver on the Kubernetes cluster within the
`kube-system` namespace with default configuration. Besides the DaemonSet
the chart installs the DeviceClasses `cxl-local`, `cxl-local-shared`,
`cxl-pool`, `cxl-pool-shared`, `cxl-pool-persistent`, `cxl-region`,
`cxl-dram` and `cxl-lease`, a ClusterRole
and a ValidatingAdmissionPolicy that lets the driver modify only the
ResourceSlices of its own node. To customize the available parameters as
described in the [Configuration options](#configuration-options) below, you
have two options: you can use the `--set` flag or create a custom
values.yaml file and provide it using the `-f` flag. For example:

```sh
# Install the driver with custom values specified in a custom values.yaml file
cat <<EOF > myPath/values.yaml
config:
  ignoreDevices: ["mem0"]
  # local devices shared by the claims of class cxl-local-shared
  sharedDevices: ["0xc100e2e1"]

leases:
  enabled: false

tolerations:
- key: "node-role.kubernetes.io/control-plane"
  operator: "Exists"
  effect: "NoSchedule"
EOF

helm install my-dra-driver-cxl nri-plugins/nri-dra-driver-cxl --namespace kube-system -f myPath/values.yaml
```

## Uninstalling the Chart

To uninstall the driver run the following command:

```sh
helm delete my-dra-driver-cxl --namespace kube-system
```

Delete the pods that use CXL claims before uninstalling the driver, so that
it can unprepare their claims.

## Configuration options

The tables below present an overview of the parameters available for users to
customize with their own values, along with the default values.

| Name                     | Default                                                                                                                       | Description                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `image.name`             | [ghcr.io/containers/nri-plugins/nri-dra-driver-cxl](https://ghcr.io/containers/nri-plugins/nri-dra-driver-cxl)                | container image name                                 |
| `image.tag`              | unstable                                                                                                                      | container image tag                                  |
| `image.pullPolicy`       | Always                                                                                                                        | image pull policy                                    |
| `resources.cpu`          | 10m                                                                                                                           | cpu resources for the Pod                            |
| `resources.memory`       | 128Mi                                                                                                                         | memory quota for the Pod                             |
| `nri.runtime.config.pluginRegistrationTimeout` | ""                                                                                                      | set NRI plugin registration timeout in NRI config of containerd or CRI-O |
| `nri.runtime.config.pluginRequestTimeout`      | ""                                                                                                      | set NRI plugin request timeout in NRI config of containerd or CRI-O |
| `nri.runtime.patchConfig` | false                                                                                                                        | patch NRI configuration in containerd or CRI-O       |
| `nri.plugin.index`       | 30                                                                                                                            | NRI plugin index (`--nri-idx`)                       |
| `pool.driverName`        | cxl-pool.nri.io                                                                                                               | DRA driver name of the CXL memory pool driver, "" disables it (`--pool-driver-name`) |
| `pool.prepareTimeout`    | 30s                                                                                                                           | how long the pool driver waits for a hotplugged CXL memory device (`--pool-prepare-timeout`) |
| `leases.enabled`         | true                                                                                                                          | lend memory to running containers (`--leases`)       |
| `leases.wait`            | 120s                                                                                                                          | how long a lease request waits for Ready when it does not say (`--lease-wait`) |
| `leases.companionImage`  | registry.k8s.io/pause:3.10                                                                                                    | image of the companion pods of leases (`--lease-companion-image`) |
| `config`                 | {}                                                                                                                            | driver configuration file (`-f`)                     |
| `logLevel`               | 4                                                                                                                             | log verbosity (`-v`)                                 |
| `extraEnv`               | {}                                                                                                                            | extra environment variables of the driver, name: value |
| `initContainerImage.name` | [ghcr.io/containers/nri-plugins/nri-config-manager](https://ghcr.io/containers/nri-plugins/nri-config-manager)               | init container image name                            |
| `initContainerImage.tag` | unstable                                                                                                                      | init container image tag                             |
| `initContainerImage.pullPolicy` | Always                                                                                                                 | init container image pull policy                     |
| `tolerations`            | []                                                                                                                            | specify taint toleration key, operator and effect    |
| `affinity`               | {}                                                                                                                            | specify node affinity                                |
| `nodeSelector`           | {}                                                                                                                            | specify node selector labels                         |
| `podPriorityClassNodeCritical` | true                                                                                                                    | enable [marking Pod as node critical](https://kubernetes.io/docs/tasks/administer-cluster/guaranteed-scheduling-critical-addon-pods/#marking-pod-as-critical) |
