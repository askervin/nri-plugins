# Trying the CXL DRA driver in e2e VMs

This guide runs the CXL DRA driver in the qemu VMs of the e2e tests of
this repository, with emulated CXL memory devices and a fake CXL memory
pool, and shows with copy-paste examples how pods use local, pooled and
shared CXL memory. It is for developers of the driver; it assumes the e2e
framework works on the host (see the `test/e2e` directory and its
`run_tests.sh`).

- [The setup](#the-setup)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Create the VMs](#create-the-vms)
- [Run the driver tests](#run-the-driver-tests)
- [Deploy by hand](#deploy-by-hand)
- [Example a: local CXL memory as RAM](#example-a-local-cxl-memory-as-ram)
- [Example b: a local dax slice](#example-b-a-local-dax-slice)
- [Example c: a pool device as RAM](#example-c-a-pool-device-as-ram)
- [Example d: a shared pool device in two clusters](#example-d-a-shared-pool-device-in-two-clusters)
- [Example e: leasing memory in a running container](#example-e-leasing-memory-in-a-running-container)
- [Example f: a shared file, one writer, three readers](#example-f-a-shared-file-one-writer-three-readers)
- [Clean up](#clean-up)
- [Troubleshooting](#troubleshooting)

## The setup

Two VMs of the e2e topologies `n4-cxl-shared-1` (VM1) and
`n4-cxl-shared-2` (VM2), Fedora with containerd, each a single-node
Kubernetes cluster. The VM name is also the host name and the node name:
`n4-cxl-shared-1-fedora-43-containerd` and
`n4-cxl-shared-2-fedora-43-containerd` (other distros and runtimes change
the suffix; adjust the names below then).

```
 host
 +-------------------------------------------------------------------+
 | fake-cxl-pool-server 127.0.0.1:9909                               |
 |   pool devices: backing files /tmp/fake-cxl-pool/<device>.raw    |
 |   hotplugs and hot-removes cxl-type3 devices over QMP             |
 |                                                                   |
 |  qemu: VM1 n4-cxl-shared-1          qemu: VM2 n4-cxl-shared-2     |
 |  +---------------------------+      +---------------------------+ |
 |  | Kubernetes node           |      | Kubernetes node           | |
 |  | nri-dra-driver-cxl        |      | nri-dra-driver-cxl        | |
 |  |   (DaemonSet, helm)       |      |   (DaemonSet, helm)       | |
 |  | fake-cxl-pool-controller  |      | fake-cxl-pool-controller  | |
 |  |   -> 192.168.76.2:9909    |      |   -> 192.168.76.2:9909    | |
 |  +---------------------------+      +---------------------------+ |
 +-------------------------------------------------------------------+
```

Each VM has two NUMA nodes of DRAM (0 and 1, 4G each), a memory block
size of 128 MiB, and two CXL host bridges with a CXL switch of four ports each.
The ports hold:

- empty *pool slots*, where fake-cxl-pool-server hotplugs the devices of
  the pool (`shared0`, serial `0xc1ae0001`, and `pooled0`, serial
  `0xc1ee0001`, below);
- a *local* device `cxl_memdev1`, serial `0xc100e2e1`: 1G in VM2, 256M in
  VM1. It is not present at boot; fake-cxl-pool-server knows it as the
  device `<VM name>.memdev1` of scope `local`, which only its own VM can
  attach. Attached, it is what `cxl.nri.io` publishes as
  `memdev-c100e2e1`;
- a statically shared, file-backed device (serial `0xc1ae0000`) that the
  test `test01-shared-cxl` uses without Kubernetes.

The VMs reach the host at `192.168.76.2` (the slirp gateway), so
fake-cxl-pool-controller in a VM talks to fake-cxl-pool-server on the
host. The VMs of `n4-cxl-shared-1` and `n4-cxl-shared-2` also have a VM
network of their own (`cxl-pool`), over which the e2e framework can make
one cluster of the two (`vm-k8s-reinit` in `test/e2e/lib/k8s.bash`).

A device of the pool is attached to the VM where the scheduler puts its
claim, by the pool controller of the cluster. Several clusters may use
the same fake-cxl-pool-server: shared devices are attached to nodes of
both clusters, an exclusive attachment keeps out every other host.

## Prerequisites

- What the e2e tests need on the host: qemu, vagrant, ansible, docker,
  go, python3, curl (see `test/e2e`).
- A qemu that can hot-remove CXL memory devices. Stock qemu plugs a
  device into a running VM, but cannot complete its removal from a CXL
  switch port: the device stays in qemu as a zombie until the VM
  restarts, and its port and backing file cannot be used again. A pool
  needs detach and attach again: build a qemu whose `cxl-downstream`
  ports have a power controller (QOM property `power_controller_present`)
  and whose `cxl-type3` device unmaps its memory backend on unplug, and
  give it with `qemu_bin` when the VMs are created
  ([Create the VMs](#create-the-vms)). The e2e framework records it in
  the VM (`QEMU_BIN` in the `env` file of the VM's output directory), so
  later runs use it too. `test00-up` prints the qemu binary of the VM.
- The CXL guest kernel. The topologies install a vanilla kernel built
  with
  [`test/e2e/playbook/files/qemu-cxl-kernel.config`](blob:/test/e2e/playbook/files/qemu-cxl-kernel.config)
  (CXL regions, devdax, kmem, memory hot-remove, `CONFIG_FS_DAX` for
  devdax `mmap`, DMI for the VM's uuid). The configuration was made on
  7.3.0-rc4; the VMs of the examples below run 7.3.0-rc7 with it.
  Without a cached build the e2e framework clones and builds the kernel
  inside the VM, which takes long.
  [`scripts/testing/fake-cxl-pool/proto/build-kernel-rpms.sh`](blob:/scripts/testing/fake-cxl-pool/proto/build-kernel-rpms.sh)
  builds the Fedora RPMs on the host in a Fedora container (podman) and
  stores them in the e2e kernel cache, where provisioning finds them:

  ```bash
  git clone --depth 1 --branch v7.3-rc4 \
      https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git ~/linux-7.3-rc4
  LINUX_SRC=~/linux-7.3-rc4 WORK=~/cxl-kernel-build \
      scripts/testing/fake-cxl-pool/proto/build-kernel-rpms.sh
  ```

  The script writes the effective configuration back to
  `qemu-cxl-kernel.config`: with the version of its header line the file
  does not change; with another version review the changes (`git diff`),
  they make a kernel tarball of another name. It prints the name of the tarball in the cache
  (`~/.cache/nri-plugins/e2e/kernel.getsource_vanilla.config_<sha256>.rpms.tar`).
  `test00-up` fails with a pointer to this script if the VM runs another
  kernel.

## Build

In the root of the repository, the image of the driver (as for the other
plugins, see [Build the image](usage.md#build-the-image)) and the
fake-cxl-pool binaries (static, copied into the VMs as they are):

```bash
make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images
make -C scripts/testing/fake-cxl-pool
ls build/images/nri-dra-driver-cxl-image-*.tar scripts/testing/fake-cxl-pool/bin/
```

The e2e framework takes the newest `build/images/nri-dra-driver-cxl-image-*.tar`.
Rebuild the image after every change of the driver.

## Create the VMs

`test00-up` of each topology creates its VM (or starts it), installs the
CXL kernel and the `cxl` and `daxctl` tools in it, and checks the qemu
devices and the kernel:

```bash
cd test/e2e
qemu_bin=/path/to/patched/qemu-system-x86_64 \
    ./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-1/test00-up
qemu_bin=/path/to/patched/qemu-system-x86_64 \
    ./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test00-up
```

Kubernetes is the latest release (`k8s_release`), v1.37 or later is
needed. The VMs are created with the default feature gates of that
release: `DRANodeAllocatableResources` is off, so the API server drops
`nodeAllocatableResources` from the ResourceSlices (see
[Feature gates](usage.md#feature-gates)). To try it, create the VMs with
`k8s_feature_gates=DRANodeAllocatableResources=true` in the environment
of `run_tests.sh`.

Log in to a VM with the ssh configuration of its output directory, as
user `vagrant`, who has `kubectl` and `helm` and may `sudo`:

```bash
ssh -F test/e2e/n4-cxl-shared-2-fedora-43-containerd/.ssh-config node
```

## Run the driver tests

The tests of the driver are in
[`test/e2e/memory.test-suite/dra-driver-cxl`](tree:/test/e2e/memory.test-suite/dra-driver-cxl).
They install the driver with helm from `deployment/helm/dra-driver-cxl`
and the image of `make images`, run fake-cxl-pool-server on the host and
fake-cxl-pool-controller in the VMs, and clean up after themselves. Run
them one at a time, from `test/e2e`:

```bash
cd test/e2e
./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test10-dra-pooling
```

or all of them in order:

```bash
./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-2
```

| test | |
|:-----|:-|
| `test00-up` | create and check the VM (of each topology) |
| `test01-shared-cxl` | CXL memory shared by the two VMs through fake-cxl-pool, without Kubernetes |
| `test10-dra-pooling` | pool devices for pods: exclusive devices as NUMA node and as dax device |
| `test11-dra-sharing` | a shared device in the two single-node clusters at once |
| `test12-dra-live-attach` | leases of pool memory for running containers |
| `test13-dra-shared-one-writer-many-readers` | single-writer sharing on the two nodes of one cluster |
| `test14-dra-local-memdev` | slices of a local memdev, `numa` and `dax` |
| `test15-dra-local-live-attach` | leases of local memory for running containers |

The tests need the port 9909 of the host for their own
fake-cxl-pool-server: stop the server of [Deploy by hand](#deploy-by-hand)
first. They remove a driver that is installed as below (release `test`)
and the pool controller before they install their own. The output of a
test, with the log of the driver, is in
`test/e2e/n4-cxl-shared-2-fedora-43-containerd/memory.test-suite/dra-driver-cxl/<test>/`.

## Deploy by hand

The examples below run on the driver installed by hand. Run the commands
of this section on the host, in the root of the repository, in one shell:
they define variables and functions that the later host commands use.

```bash
N=$PWD
P=$N/scripts/testing/fake-cxl-pool
VM1=$N/test/e2e/n4-cxl-shared-1-fedora-43-containerd
VM2=$N/test/e2e/n4-cxl-shared-2-fedora-43-containerd
IMAGE_TAR=$(ls -1t "$N"/build/images/nri-dra-driver-cxl-image-*.tar | head -n 1)
IMAGE_ID=${IMAGE_TAR##*-image-}; IMAGE_ID=${IMAGE_ID%.tar}

# Run a command line in the VM of the output directory $1.
vm() { local vmdir=$1; shift; ssh -F "$vmdir/.ssh-config" node "$@"; }

# Import the image into the VM as localhost/dra-driver-cxl:testing, the
# way the e2e framework does.
cxl-image-put() {
    scp -F "$1/.ssh-config" "$IMAGE_TAR" node:dra-driver-cxl.tar &&
    vm "$1" "sudo ctr -n k8s.io images import dra-driver-cxl.tar &&
        sudo ctr -n k8s.io images tag --force \$(sudo ctr -n k8s.io images ls | awk '/sha256:$IMAGE_ID/ {print \$1; exit}') localhost/dra-driver-cxl:testing &&
        rm dra-driver-cxl.tar"
}

# Copy the helm chart to ~/helm/dra-driver-cxl in the VM.
cxl-chart-put() {
    tar -C "$N/deployment/helm" -cf - dra-driver-cxl |
        vm "$1" 'rm -rf helm/dra-driver-cxl && mkdir -p helm && tar -C helm -xf -'
}

# Install fake-cxl-pool-client and fake-cxl-pool-controller in the VM, and
# run the controller as a transient systemd unit.
cxl-controller-start() {
    scp -F "$1/.ssh-config" "$P/bin/fake-cxl-pool-client" "$P/bin/fake-cxl-pool-controller" node: &&
    vm "$1" 'sudo install -m 755 fake-cxl-pool-client fake-cxl-pool-controller /usr/local/bin/ &&
        rm fake-cxl-pool-client fake-cxl-pool-controller &&
        { sudo systemctl stop fake-cxl-pool-controller; sudo systemctl reset-failed fake-cxl-pool-controller; } 2>/dev/null;
        sudo systemd-run --unit fake-cxl-pool-controller -E KUBECONFIG=/root/.kube/config \
            /usr/local/bin/fake-cxl-pool-controller -server http://192.168.76.2:9909 -v'
}

# Install the driver with helm (release test in kube-system), replacing an
# earlier release, and wait until its pods run on every node.
cxl-helm-install() {
    vm "$1" 'helm uninstall -n kube-system test --wait 2>/dev/null;
        helm install -n kube-system test ./helm/dra-driver-cxl \
            --set image.name=localhost/dra-driver-cxl --set image.tag=testing --set image.pullPolicy=Never &&
        kubectl rollout status -n kube-system ds/nri-dra-driver-cxl --timeout=180s'
}

# Pull the images of the examples and of the companion pods of leases.
cxl-images-pull() {
    vm "$1" 'for i in docker.io/library/python:3-alpine registry.k8s.io/pause:3.10; do sudo crictl pull $i 2>&1 | grep -v level=warning; done'
}

# fake-cxl-pool-client on the host.
pool() { "$P/bin/fake-cxl-pool-client" --server http://127.0.0.1:9909 "$@"; }
```

Start fake-cxl-pool-server on the host with two pool devices: `shared0`
(256Mi, shared) and `pooled0` (512Mi, exclusive). It discovers the qemu
processes of the two VMs and connects to their QMP sockets:

```bash
cat > "$N/build/fake-cxl-pool-demo.yaml" <<EOF
listen: 127.0.0.1:9909
pools:
  - name: default
    dir: /tmp/fake-cxl-pool
    capacity: 8Gi
    sharable: true
devices:
  - name: shared0
    size: 256Mi
    shared: true
    pool: default
    serial: 0xc1ae0001
  - name: pooled0
    size: 512Mi
    shared: false
    pool: default
    serial: 0xc1ee0001
discovery:
  qemu: true
  interval: 10s
  names: ["$(basename "$VM1")", "$(basename "$VM2")"]
  localDevices: true
detachTimeout: 15s
EOF
"$P/bin/fake-cxl-pool-server" -config "$N/build/fake-cxl-pool-demo.yaml" -state - -v \
    > "$N/build/fake-cxl-pool-demo.log" 2>&1 &
POOL_SERVER_PID=$!
until curl -sf http://127.0.0.1:9909/api/v1/status >/dev/null; do sleep 1; done
pool hosts
pool devices
```

```
NAME                                  STATE    CONTROL  PID     QEMU                              UUID                                  FREE-SLOTS  ATTACHMENTS  LOCAL-DEVICES
n4-cxl-shared-1-fedora-43-containerd  running  qmp      40020   11.0.50 v11.0.0-2960-g1238677442  b6a78455-edb1-558d-8cf1-01a259f76e97  6/8         0            2
n4-cxl-shared-2-fedora-43-containerd  running  qmp      331593  11.0.50 v11.0.0-2960-g1238677442  1b6d55a2-ae4a-52f8-bbba-2e3f9adca1b1  6/8         0            2
NAME                                          SERIAL      SIZE   SHARED  SCOPE                                                                            STATE  ATTACHED-TO  OWNER
n4-cxl-shared-1-fedora-43-containerd.memdev1  0xc100e2e1  256Mi  false   local:n4-cxl-shared-1-fedora-43-containerd                                       free   -            -
n4-cxl-shared-2-fedora-43-containerd.memdev1  0xc100e2e1  1Gi    false   local:n4-cxl-shared-2-fedora-43-containerd                                       free   -            -
pooled0                                       0xc1ee0001  512Mi  false   pool                                                                             free   -            -
shared0                                       0xc1ae0001  256Mi  true    pool                                                                             free   -            -
static-shared0                                0xc1ae0000  256Mi  true    local:n4-cxl-shared-1-fedora-43-containerd,n4-cxl-shared-2-fedora-43-containerd  free   -            -
```

`pool devices` lists `shared0` and `pooled0` (scope `pool`) and the local
devices of the VMs (scope `local:<VM name>`), among them
`n4-cxl-shared-2-fedora-43-containerd.memdev1`.

Deploy the driver and the pool controller in the cluster of VM2:

```bash
cxl-image-put "$VM2"
cxl-chart-put "$VM2"
cxl-controller-start "$VM2"
cxl-helm-install "$VM2"
cxl-images-pull "$VM2"
```

Example d uses the cluster of VM1 too: deploy the same there with `"$VM1"`.

Then log in to VM2 (`vm "$VM2"`, or
`ssh -F test/e2e/n4-cxl-shared-2-fedora-43-containerd/.ssh-config node`)
and look at what the driver publishes:

```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=nri-dra-driver-cxl -o wide
kubectl get deviceclasses
kubectl get resourceslices -o custom-columns='DRIVER:.spec.driver,NODE:.spec.nodeName,POOL:.spec.pool.name,DEVICES:.spec.devices[*].name'
cat /sys/devices/system/memory/auto_online_blocks
```

```
NAME                       READY   STATUS    RESTARTS   AGE   IP            NODE                                   NOMINATED NODE   READINESS GATES
nri-dra-driver-cxl-hjfmp   1/1     Running   0          11s   10.217.0.27   n4-cxl-shared-2-fedora-43-containerd   <none>           <none>
NAME              AGE
cxl-dram          12s
cxl-lease         12s
cxl-local         12s
cxl-pool          12s
cxl-pool-shared   12s
cxl-region        12s
DRIVER            NODE                                   POOL                                   DEVICES
cxl-pool.nri.io   <none>                                 fake-cxl-pool                          pooled0,shared0
cxl.nri.io        n4-cxl-shared-2-fedora-43-containerd   n4-cxl-shared-2-fedora-43-containerd   lease,dram
offline
```

The node publishes `dram` and `lease`; `memdev-c100e2e1` appears when the
local device is attached (example a). The pool controller publishes the
two pool devices for every node. `auto_online_blocks` is `offline` (the
kernel configuration of the VMs): the driver onlines memory itself.

The examples run `kubectl` in VM2 (and in VM1 for example d) as user
`vagrant`, in the namespace `default`, and delete what they create.

## Example a: local CXL memory as RAM

256Mi of the local CXL memory device of VM2 as system RAM: the driver
creates a region on the device, onlines a slice of it as movable memory
of the device's NUMA node, and steers the container to that node. In VM2,
attach the local device (nothing happens if it is attached already) and
wait until the driver publishes it:

```bash
fake-cxl-pool-client attach "$(hostname).memdev1" --self
until kubectl get resourceslices -o yaml | grep -q 'name: memdev-c100e2e1'; do sleep 1; done
sudo cxl list -M
```

Claim 256Mi of it with the DeviceClass `cxl-local` and print what the
container gets:

```bash
kubectl apply -f - <<'EOF'
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: local-numa
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-local
        capacity:
          requests:
            memory: 256Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: local-numa
spec:
  terminationGracePeriodSeconds: 2
  resourceClaims:
  - name: mem
    resourceClaimName: local-numa
  containers:
  - name: app
    image: docker.io/library/python:3-alpine
    command:
    - sh
    - -c
    - |
      env | grep ^CXL_ | sort
      node=$(env | sed -n 's/^CXL_.*_NODE=//p')
      echo "cpuset.mems: $(cat /sys/fs/cgroup/cpuset.mems.effective)"
      grep MemTotal /sys/devices/system/node/node$node/meminfo
      sleep infinity
    resources:
      claims:
      - name: mem
EOF
kubectl wait --for=condition=Ready pod/local-numa --timeout=120s
kubectl logs local-numa
```

```
CXL_C100E2E1_MODE=numa
CXL_C100E2E1_NODE=2
CXL_C100E2E1_SERIAL=0xc100e2e1
CXL_C100E2E1_SHARED=0
CXL_C100E2E1_SIZE=268435456
CXL_CLAIM_<uid>=1
cpuset.mems: 0-2
Node 2 MemTotal:         262144 kB
```

`CXL_C100E2E1_NODE` is the NUMA node of the slice; the container is in
its `cpuset.mems`. On the node, the region, its two memory blocks online
and the state of the driver:

```bash
sudo cxl list -R
grep MemTotal /sys/devices/system/node/node2/meminfo
sudo cat /var/lib/kubelet/plugins/cxl.nri.io/localDevices.json; echo
kubectl logs -n kube-system ds/nri-dra-driver-cxl | grep 'local: memdev'
```

Delete the pod and the claim: the driver offlines and deletes the slice
and, as it was the last one, destroys the region. The node disappears.

```bash
kubectl delete pod/local-numa resourceclaim/local-numa
sudo cxl list -R
```

## Example b: a local dax slice

A devdax slice of the same local device: claim 64Mi with a `DeviceConfig`
`mode: dax`. The slice is rounded up to a whole memory block (128Mi), and
the driver zeroes it before the container gets it. The container gets the
device node `/dev/daxX.Y`, maps it, writes and reads. In VM2:

```bash
fake-cxl-pool-client attach "$(hostname).memdev1" --self
until kubectl get resourceslices -o yaml | grep -q 'name: memdev-c100e2e1'; do sleep 1; done
kubectl apply -f - <<'EOF'
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: local-dax
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-local
        capacity:
          requests:
            memory: 64Mi
    config:
    - opaque:
        driver: cxl.nri.io
        parameters:
          apiVersion: cxl.nri.io/v1alpha1
          kind: DeviceConfig
          mode: dax
---
apiVersion: v1
kind: Pod
metadata:
  name: local-dax
spec:
  terminationGracePeriodSeconds: 2
  resourceClaims:
  - name: mem
    resourceClaimName: local-dax
  containers:
  - name: app
    image: docker.io/library/python:3-alpine
    command:
    - python3
    - -u
    - -c
    - |
      import mmap, os, time
      key = [k[:-len("DAX")] for k in os.environ if k.startswith("CXL_") and k.endswith("_DAX")][0]
      dax, size = os.environ[key + "DAX"], int(os.environ[key + "SIZE"])
      print("device", dax, "size", size, "read-only", os.environ[key + "READONLY"])
      # devdax: MAP_SHARED, a length that is a multiple of the device
      # alignment (2 MiB): map the whole slice
      m = mmap.mmap(os.open(dax, os.O_RDWR), size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
      mib = 1 << 20
      print("zeroed:", all(not m[i:i + mib].strip(b"\0") for i in range(0, size, mib)))
      msg = b"hello from local-dax\0"
      m[0:len(msg)] = msg
      print("read back:", bytes(m[0:4096]).split(b"\0", 1)[0].decode())
      time.sleep(1e9)
    resources:
      claims:
      - name: mem
EOF
kubectl wait --for=condition=Ready pod/local-dax --timeout=120s
until kubectl logs local-dax | grep -q '^read back:'; do sleep 1; done
kubectl logs local-dax
```

```
device /dev/dax0.0 size 134217728 read-only 0
zeroed: True
read back: hello from local-dax
```

On the node the slice is a dax device of the device's devdax region,
bound to `device_dax`, and adds nothing to any NUMA node:

```bash
sudo daxctl list
```

Several pods that reference the same ResourceClaim share its slice; a
`DeviceConfig` with `readOnly: true` gives a device node that the
container may open for reading only
([local-dax-shared-claim.yaml](blob:/deployment/samples/dra-driver-cxl/local-dax-shared-claim.yaml),
[local-dax-readonly.yaml](blob:/deployment/samples/dra-driver-cxl/local-dax-readonly.yaml)).
Clean up:

```bash
kubectl delete pod/local-dax resourceclaim/local-dax
```

## Example c: a pool device as RAM

512Mi of exclusive pool memory as RAM: the scheduler allocates `pooled0`
and waits for its binding condition, the pool controller attaches it to
the node through fake-cxl-pool-server and sets
`cxl-pool.nri.io/Attached`, and the driver onlines the hotplugged device
as a new NUMA node. The container is not steered: it gets the node number
and binds its memory there itself (`numactl --membind`, `mbind`). In VM2:

```bash
kubectl apply -f - <<'EOF'
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: pool-numa
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool
        capacity:
          requests:
            memory: 512Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: pool-numa
spec:
  terminationGracePeriodSeconds: 2
  resourceClaims:
  - name: mem
    resourceClaimName: pool-numa
  containers:
  - name: app
    image: docker.io/library/python:3-alpine
    command:
    - sh
    - -c
    - |
      env | grep ^CXL_ | sort
      node=$(env | sed -n 's/^CXL_.*_NODE=//p')
      grep MemTotal /sys/devices/system/node/node$node/meminfo
      sleep infinity
    resources:
      claims:
      - name: mem
EOF
kubectl wait --for=condition=Ready pod/pool-numa --timeout=180s
kubectl logs pool-numa
kubectl get resourceclaim pool-numa -o jsonpath='{.status.devices[0].conditions[0].type}={.status.devices[0].conditions[0].status} {.status.devices[0].data}{"\n"}'
```

```
CXL_C1EE0001_MODE=numa
CXL_C1EE0001_NODE=2
CXL_C1EE0001_SERIAL=0xc1ee0001
CXL_C1EE0001_SHARED=0
CXL_C1EE0001_SIZE=536870912
CXL_CLAIM_<uid>=1
Node 2 MemTotal:         524288 kB
cxl-pool.nri.io/Attached=True {"attachment":"pooled0@n4-cxl-shared-2-fedora-43-containerd","host":"n4-cxl-shared-2-fedora-43-containerd","hostUUID":"1b6d55a2-ae4a-52f8-bbba-2e3f9adca1b1","qemuDeviceId":"fcp_pooled0.hp2","serial":"0xc1ee0001","shared":false,"size":536870912}
```

The pool slot of `pooled0` is under the first host bridge, as the local
device of examples a and b: all regions under one CXL host bridge share
its NUMA node, here node 2.

On the host, the attachments (`pooled0`, and the local device if it is
still attached from examples a and b):

```bash
pool attachments
```

```
ID                                                                                 SLOT                NUMA  QEMU-DEVICE                                           QEMU-OBJECT                                               SERIAL      STATE     ERROR
n4-cxl-shared-2-fedora-43-containerd.memdev1@n4-cxl-shared-2-fedora-43-containerd  cxlsw_ds3_usrp0hb0  0     fcp_n4-cxl-shared-2-fedora-43-containerd.memdev1.hp1  beram_cxl_memdev1__bus_cxlsw_ds3_usrp0hb0__sn_0xc100e2e1  0xc100e2e1  attached  -
pooled0@n4-cxl-shared-2-fedora-43-containerd                                       cxlsw_ds0_usrp0hb0  0     fcp_pooled0.hp2                                       fcp_pooled0.hp2                                           0xc1ee0001  attached  -
```

Delete the pod and the claim. The driver offlines the memory, destroys
the region and disables the memory device; then the claim is deallocated
and the controller detaches the device (a few seconds). `cxl list -M`
shows only the local device then, if it is attached:

```bash
kubectl delete pod/pool-numa resourceclaim/pool-numa
sudo cxl list -M
```

Never force-delete a pod that uses pool memory
([pool.md](pool.md#ordering-and-failure-semantics)).

## Example d: a shared pool device in two clusters

`shared0` attached to the single-node clusters of VM1 and VM2 at the same
time, each with a claim of its own on `cxl-pool-shared` (one of the
device's four `hosts`): a writer in cluster 2 and a reader in cluster 1
see the same bytes. Both clusters need the driver and a pool controller:
on the host, deploy them to VM1 as to VM2 in
[Deploy by hand](#deploy-by-hand):

```bash
cxl-image-put "$VM1"
cxl-chart-put "$VM1"
cxl-controller-start "$VM1"
cxl-helm-install "$VM1"
cxl-images-pull "$VM1"
```

The claim, the same in both clusters:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: shared-memory
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool-shared
        selectors:
        - cel:
            expression: 'device.attributes["cxl-pool.nri.io"].serial == "0xc1ae0001"'
```

In VM2, the claim and a writer that writes a new message every two
seconds:

```bash
kubectl apply -f - <<'EOF'
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: shared-memory
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool-shared
        selectors:
        - cel:
            expression: 'device.attributes["cxl-pool.nri.io"].serial == "0xc1ae0001"'
---
apiVersion: v1
kind: Pod
metadata:
  name: shared-writer
spec:
  terminationGracePeriodSeconds: 2
  resourceClaims:
  - name: mem
    resourceClaimName: shared-memory
  containers:
  - name: writer
    image: docker.io/library/python:3-alpine
    env:
    - name: NODE_NAME
      valueFrom:
        fieldRef:
          fieldPath: spec.nodeName
    command:
    - python3
    - -u
    - -c
    - |
      import mmap, os, time
      key = [k[:-len("DAX")] for k in os.environ if k.startswith("CXL_") and k.endswith("_DAX")][0]
      dax, size = os.environ[key + "DAX"], int(os.environ[key + "SIZE"])
      m = mmap.mmap(os.open(dax, os.O_RDWR), size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
      n = 0
      while True:
          n += 1
          msg = "message %d from %s" % (n, os.environ["NODE_NAME"])
          m[0:len(msg) + 1] = msg.encode() + b"\0"
          print("wrote:", msg)
          time.sleep(2)
    resources:
      claims:
      - name: mem
EOF
kubectl wait --for=condition=Ready pod/shared-writer --timeout=180s
kubectl logs shared-writer
```

In VM1 (`vm "$VM1"` on the host), the same claim and a reader:

```bash
kubectl apply -f - <<'EOF'
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: shared-memory
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool-shared
        selectors:
        - cel:
            expression: 'device.attributes["cxl-pool.nri.io"].serial == "0xc1ae0001"'
---
apiVersion: v1
kind: Pod
metadata:
  name: shared-reader
spec:
  terminationGracePeriodSeconds: 2
  resourceClaims:
  - name: mem
    resourceClaimName: shared-memory
  containers:
  - name: reader
    image: docker.io/library/python:3-alpine
    command:
    - python3
    - -u
    - -c
    - |
      import mmap, os, time
      key = [k[:-len("DAX")] for k in os.environ if k.startswith("CXL_") and k.endswith("_DAX")][0]
      dax, size = os.environ[key + "DAX"], int(os.environ[key + "SIZE"])
      m = mmap.mmap(os.open(dax, os.O_RDONLY), size, mmap.MAP_SHARED, mmap.PROT_READ)
      while True:
          print("read:", bytes(m[0:4096]).split(b"\0", 1)[0].decode(errors="replace"))
          time.sleep(2)
    resources:
      claims:
      - name: mem
EOF
kubectl wait --for=condition=Ready pod/shared-reader --timeout=180s
kubectl exec shared-reader -- sh -c 'env | grep ^CXL_ | sort'
until [ "$(kubectl logs shared-reader | grep -c '^read:')" -ge 3 ]; do sleep 1; done
kubectl logs --tail 3 shared-reader
```

```
CXL_C1AE0001_DAX=/dev/dax0.0
CXL_C1AE0001_MODE=dax
CXL_C1AE0001_READONLY=0
CXL_C1AE0001_SERIAL=0xc1ae0001
CXL_C1AE0001_SHARED=1
CXL_C1AE0001_SIZE=268435456
CXL_CLAIM_<uid>=1
read: message 4 from n4-cxl-shared-2-fedora-43-containerd
read: message 5 from n4-cxl-shared-2-fedora-43-containerd
read: message 6 from n4-cxl-shared-2-fedora-43-containerd
```

The reader in cluster 1 reads what the writer in cluster 2 writes, with
no network in between: the memory is the backing file of `shared0` on the
host (with real hardware, the memory of the device behind the CXL
switch). On the host, the device is attached to both VMs:

```bash
pool attachments --device shared0
```

```
ID                                            SLOT                NUMA  QEMU-DEVICE      QEMU-OBJECT      SERIAL      STATE     ERROR
shared0@n4-cxl-shared-1-fedora-43-containerd  cxlsw_ds0_usrp0hb0  0     fcp_shared0.hp1  fcp_shared0.hp1  0xc1ae0001  attached  -
shared0@n4-cxl-shared-2-fedora-43-containerd  cxlsw_ds0_usrp0hb0  0     fcp_shared0.hp3  fcp_shared0.hp3  0xc1ae0001  attached  -
```

Clean up in both VMs (cluster 2: `shared-writer`, cluster 1:
`shared-reader`):

```bash
kubectl delete pod/shared-writer resourceclaim/shared-memory    # in VM2
kubectl delete pod/shared-reader resourceclaim/shared-memory    # in VM1
```

In one cluster of two nodes ([example f](#example-f-a-shared-file-one-writer-three-readers))
the same is one ResourceClaimTemplate and two pods with a `nodeSelector`
each: one claim covers one node.

## Example e: leasing memory in a running container

A pod with a claim on the lease device (`cxl-lease`) gets the lease socket
and `cxl-request`, with which the running container asks for more memory
([leases.md](leases.md)). In VM2, attach the local device (local memory
first, then pool memory) and create the pod:

```bash
fake-cxl-pool-client attach "$(hostname).memdev1" --self
kubectl apply -f - <<'EOF'
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: cxl-lease
spec:
  spec:
    devices:
      requests:
      - name: lease
        exactly:
          deviceClassName: cxl-lease
---
apiVersion: v1
kind: Pod
metadata:
  name: borrower
spec:
  terminationGracePeriodSeconds: 2
  resourceClaims:
  - name: lease
    resourceClaimTemplateName: cxl-lease
  containers:
  - name: app
    image: docker.io/library/python:3-alpine
    command: ["sleep", "infinity"]
    resources:
      claims:
      - name: lease
EOF
kubectl wait --for=condition=Ready pod/borrower --timeout=120s
kubectl exec borrower -- sh -c 'echo $CXL_LEASE_SOCKET; ls -l /usr/local/bin/cxl-request; cat /sys/fs/cgroup/cpuset.mems.effective'
```

```
/run/cxl/cxl.sock
-rwxr-xr-x    1 root     root       3918324 Oct 16 12:23 /usr/local/bin/cxl-request
0-1
```

Lease 128Mi of local memory as RAM: the driver creates a companion claim
and pod for the lease, prepares a `numa` slice of the local device for
it, and adds its NUMA node to the `cpuset.mems` of the container:

```bash
kubectl exec borrower -- cxl-request request --source local --size 128Mi
kubectl exec borrower -- cat /sys/fs/cgroup/cpuset.mems.effective
kubectl get pods,resourceclaims -l cxl.nri.io/lease
```

```
{"lease":"1b7d6551","state":"Ready","source":"local","mode":"numa","shared":false,"readOnly":false,"size":134217728,"serial":"0xc100e2e1","node":2,"env":{"CXL_C100E2E1_MODE":"numa","CXL_C100E2E1_NODE":"2","CXL_C100E2E1_SERIAL":"0xc100e2e1","CXL_C100E2E1_SHARED":"0","CXL_C100E2E1_SIZE":"134217728"}}
0-2
NAME                     READY   STATUS              RESTARTS   AGE
pod/cxl-lease-1b7d6551   0/1     ContainerCreating   0          0s

NAME                                               STATE                AGE
resourceclaim.resource.k8s.io/cxl-lease-1b7d6551   allocated,reserved   0s
```

The lease is Ready as soon as the companion claim is prepared and the
node is lent; the pause container of the companion pod may still be
starting.

Lease the exclusive pool device as a dax device and run a command with
it: the driver passes an open file descriptor of the device over the
socket, and `cxl-request` gives it to the command as fd 3. The container
has no device node for it.

```bash
kubectl exec borrower -- cxl-request request --source pool --size 256Mi --mode dax \
    --exec sh -c 'env | grep ^CXL_ | sort; readlink /proc/self/fd/3'
kubectl exec borrower -- cxl-request list
```

```
CXL_C1EE0001_FD=3
CXL_C1EE0001_MODE=dax
CXL_C1EE0001_READONLY=0
CXL_C1EE0001_SERIAL=0xc1ee0001
CXL_C1EE0001_SHARED=0
CXL_C1EE0001_SIZE=536870912
CXL_CLAIM_<uid>=1
CXL_LEASE=ca0ba3b1
CXL_LEASE_SOCKET=/run/cxl/cxl.sock
/dev/dax2.0
{"shared":false,"readOnly":false,"leases":[{"lease":"1b7d6551","state":"Ready","source":"local","mode":"numa",...},{"lease":"ca0ba3b1","state":"Ready","source":"pool","mode":"dax","shared":false,"readOnly":false,"size":536870912,"serial":"0xc1ee0001","dax":"/dev/dax2.0","env":{...}}]}
```

`CXL_CLAIM_<uid>` is the marker of the pod's own lease claim. The whole
512Mi device `pooled0` serves the 256Mi request.

Give the memory back; the node leaves `cpuset.mems`, the companions go,
and the pool device is detached:

```bash
kubectl exec borrower -- cxl-request release --all
kubectl exec borrower -- cat /sys/fs/cgroup/cpuset.mems.effective
kubectl delete pod/borrower resourceclaimtemplate/cxl-lease
```

```
{"shared":false,"readOnly":false,"leases":[{"lease":"1b7d6551","state":"Released","shared":false,"readOnly":false},{"lease":"ca0ba3b1","state":"Released","shared":false,"readOnly":false}]}
0-1
pod "borrower" deleted from default namespace
resourceclaimtemplate.resource.k8s.io "cxl-lease" deleted from default namespace
```

Deleting a pod releases its leases too.

## Example f: a shared file, one writer, three readers

Single-writer data sharing of a file: a writer pod gets `shared0` for
itself, stores a file in it and exits; then three reader pods on two
nodes get the same device read-only at the same time, open the file in
place and print it.

A devdax device `/dev/daxX.Y` is a character device that supports only
`mmap`: no `read` or `write`, and it is no block device. So `mkfs.ext4`
cannot format it and the kernel cannot mount it. File systems that live
in shared memory and are mounted by several hosts at once (famfs, for
example) exist, but they are outside this driver. What works with plain
`mmap` is a file system image that programs read in place: here an
uncompressed tar archive. The writer writes the archive with Python's
`tarfile` straight into its mapping of the device. Each reader maps the
device read-only, opens the archive in the mapping
(`tarfile.open(fileobj=<mmap object>)`, which reads the headers from the
mapping: this is the "mount"), finds the data offset of the file
(`TarInfo.offset_data`) and prints the file's bytes from a `memoryview` of
the mapping: no copy into a file, no page cache, the bytes that the
writer stored. The archive does not change while the readers hold the
device: their device nodes allow reads only, and a new exclusive claim
of a writer waits until the readers' claims are deallocated. Devdax
needs `MAP_SHARED` and a mapping length that is a multiple of the device
alignment (2 MiB); the tool maps the whole device, 256 MiB.

The pods run on the two nodes of one cluster: VM2 the control plane, VM1
a worker. `test13-dra-shared-one-writer-many-readers` makes that cluster
of the two VMs (with `vm-k8s-reinit` of the e2e framework) and keeps it
after a successful run with `k8s_restore=no`. The test rebuilds the
clusters of both VMs and needs the port of fake-cxl-pool-server: remove
first what the examples left (the driver and the pool controller in both
VMs, the local device of VM2), stop the server of this guide, then run
the test (about five minutes) and start the server again. On the host:

```bash
vm "$VM2" 'helm uninstall -n kube-system test --wait; sudo systemctl stop fake-cxl-pool-controller;
    sudo fake-cxl-pool-client guest release 0xc100e2e1; fake-cxl-pool-client detach "$(hostname).memdev1" --self'
vm "$VM1" 'helm uninstall -n kube-system test --wait; sudo systemctl stop fake-cxl-pool-controller'
kill $POOL_SERVER_PID
(cd test/e2e && k8s_restore=no ./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test13-dra-shared-one-writer-many-readers)
"$P/bin/fake-cxl-pool-server" -config "$N/build/fake-cxl-pool-demo.yaml" -state - -v \
    > "$N/build/fake-cxl-pool-demo.log" 2>&1 &
POOL_SERVER_PID=$!
until curl -sf http://127.0.0.1:9909/api/v1/status >/dev/null; do sleep 1; done
```

The test removes its driver and controller when it ends. Install the
image on both nodes, and the chart and the pool controller on the control
plane, which installs the DaemonSet on both nodes:

```bash
cxl-image-put "$VM1"
cxl-images-pull "$VM1"
cxl-image-put "$VM2"
cxl-images-pull "$VM2"
cxl-chart-put "$VM2"
cxl-controller-start "$VM2"
cxl-helm-install "$VM2"
```

In VM2, check the cluster: two nodes, a driver pod on each, one pool
ResourceSlice:

```bash
kubectl get nodes
kubectl get pods -n kube-system -l app.kubernetes.io/name=nri-dra-driver-cxl -o wide
kubectl get resourceslices -o custom-columns='DRIVER:.spec.driver,NODE:.spec.nodeName,DEVICES:.spec.devices[*].name'
```

```
NAME                                   STATUS   ROLES           AGE     VERSION
n4-cxl-shared-1-fedora-43-containerd   Ready    <none>          3m48s   v1.37.1
n4-cxl-shared-2-fedora-43-containerd   Ready    control-plane   4m      v1.37.1
NAME                       READY   STATUS    RESTARTS   AGE   IP            NODE                                   NOMINATED NODE   READINESS GATES
nri-dra-driver-cxl-9zpkk   1/1     Running   0          6s    10.217.1.9    n4-cxl-shared-1-fedora-43-containerd   <none>           <none>
nri-dra-driver-cxl-sms8v   1/1     Running   0          6s    10.217.0.10   n4-cxl-shared-2-fedora-43-containerd   <none>           <none>
DRIVER            NODE                                   DEVICES
cxl-pool.nri.io   <none>                                 pooled0,shared0
cxl.nri.io        n4-cxl-shared-1-fedora-43-containerd   dram,lease
cxl.nri.io        n4-cxl-shared-2-fedora-43-containerd   dram,lease
```

The tool, in a ConfigMap that the pods mount at `/tools`:

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: cxl-tar
data:
  cxl-tar.py: |
    """A tar archive in the memory of a devdax device: a file system image
    that lives in shared CXL memory and is read in place.

    Usage:
      cxl-tar.py write PATH TEXT   write an archive with the file PATH
      cxl-tar.py read PATH         list the archive, print the file PATH
                                   from the mapping, keep the mapping

    The device is the one of the CXL_<KEY>_DAX variable of the claim.
    """
    import errno
    import io
    import mmap
    import os
    import signal
    import sys
    import tarfile
    import time


    def device():
        """Return the path, size and read-only flag of the dax device of the claim."""
        keys = [k[:-len("DAX")] for k in os.environ if k.startswith("CXL_") and k.endswith("_DAX")]
        if len(keys) != 1:
            sys.exit("expected one CXL_<KEY>_DAX variable, found %d" % len(keys))
        key = keys[0]
        return os.environ[key + "DAX"], int(os.environ[key + "SIZE"]), os.environ[key + "READONLY"]


    def write(dax, size, path, text):
        # devdax: MAP_SHARED, and a length that is a multiple of the device
        # alignment (2 MiB). Map the whole device.
        m = mmap.mmap(os.open(dax, os.O_RDWR), size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        data = text.encode()
        now = time.time()
        # The archive is written straight into the mapping: the mmap object
        # is the file object of tarfile.
        with tarfile.open(fileobj=m, mode="w:", format=tarfile.USTAR_FORMAT) as tar:
            if os.path.dirname(path):
                d = tarfile.TarInfo(os.path.dirname(path))
                d.type, d.mode, d.mtime = tarfile.DIRTYPE, 0o755, now
                tar.addfile(d)
            f = tarfile.TarInfo(path)
            f.size, f.mode, f.mtime = len(data), 0o644, now
            tar.addfile(f, io.BytesIO(data))
        print("wrote %s (%d bytes) in a tar archive of %d bytes at the start of %s" % (path, len(data), m.tell(), dax))


    def read(dax, size, ro, path):
        m = mmap.mmap(os.open(dax, os.O_RDONLY), size, mmap.MAP_SHARED, mmap.PROT_READ)
        # "Mount": tarfile reads the headers from the mapping, in place.
        tar = tarfile.open(fileobj=m, mode="r:")
        print("archive in %s (%d bytes, read-only %s):" % (dax, size, ro))
        for ti in tar.getmembers():
            print("  %s %6d %s" % ("d" if ti.isdir() else "-", ti.size, ti.name))
        ti = tar.getmember(path)
        print("%s, %d bytes at offset %d of %s:" % (path, ti.size, ti.offset_data, dax), flush=True)
        # The bytes of the file straight from the shared mapping: a view of
        # the memory, not a copy.
        with memoryview(m) as mem:
            sys.stdout.buffer.write(mem[ti.offset_data:ti.offset_data + ti.size])
        print(flush=True)
        try:
            os.close(os.open(dax, os.O_RDWR))
            print("open for writing: allowed")
        except OSError as e:
            print("open for writing refused:", errno.errorcode.get(e.errno, e.errno))
        print("holding the mapping", flush=True)
        return m


    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    dax, size, ro = device()
    if len(sys.argv) == 4 and sys.argv[1] == "write":
        write(dax, size, sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "read":
        m = read(dax, size, ro, sys.argv[2])
        while True:
            time.sleep(3600)
    else:
        sys.exit(__doc__)
EOF
```

The writer, on VM1: its claim requests all four `hosts` of `shared0`, so
that the scheduler allocates the device to no other claim and the pool
controller attaches it exclusively, until the claim is deallocated:

```bash
kubectl apply -f - <<'EOF'
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: fs-writer
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool-shared
        selectors:
        - cel:
            expression: 'device.attributes["cxl-pool.nri.io"].serial == "0xc1ae0001"'
        capacity:
          requests:
            hosts: "4"
---
apiVersion: v1
kind: Pod
metadata:
  name: fs-writer
spec:
  nodeSelector:
    kubernetes.io/hostname: n4-cxl-shared-1-fedora-43-containerd
  restartPolicy: Never
  resourceClaims:
  - name: mem
    resourceClaimName: fs-writer
  volumes:
  - name: tools
    configMap:
      name: cxl-tar
  containers:
  - name: writer
    image: docker.io/library/python:3-alpine
    env:
    - name: NODE_NAME
      valueFrom:
        fieldRef:
          fieldPath: spec.nodeName
    command:
    - sh
    - -c
    - python3 -u /tools/cxl-tar.py write notes/hello.txt "Hello from $NODE_NAME, written at $(date)."
    volumeMounts:
    - name: tools
      mountPath: /tools
    resources:
      claims:
      - name: mem
EOF
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/fs-writer --timeout=180s
kubectl logs fs-writer
```

```
wrote notes/hello.txt (89 bytes) in a tar archive of 10240 bytes at the start of /dev/dax0.0
```

When the writer's pod has finished, its claim is reserved for no pod
any more: Kubernetes deallocates it (`kubectl get resourceclaim fs-writer`
shows the state `pending`), the driver has released the device, and the
pool controller detaches it from VM1. Readers created while the writer
runs stay pending until then (test13 shows it with leases). Delete the
writer's pod and claim:

```bash
kubectl delete pod/fs-writer resourceclaim/fs-writer
```

The readers: a ResourceClaimTemplate, so that each reader gets a claim of
its own (one host of the device each) with a `DeviceConfig`
`readOnly: true`, and three pods, two on VM2 and one on VM1:

```bash
kubectl apply -f - <<'EOF'
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: fs-reader
spec:
  spec:
    devices:
      requests:
      - name: mem
        exactly:
          deviceClassName: cxl-pool-shared
          selectors:
          - cel:
              expression: 'device.attributes["cxl-pool.nri.io"].serial == "0xc1ae0001"'
      config:
      - opaque:
          driver: cxl-pool.nri.io
          parameters:
            apiVersion: cxl-pool.nri.io/v1alpha1
            kind: DeviceConfig
            readOnly: true
EOF
for r in reader-1:n4-cxl-shared-2-fedora-43-containerd \
         reader-2:n4-cxl-shared-2-fedora-43-containerd \
         reader-3:n4-cxl-shared-1-fedora-43-containerd; do
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${r%%:*}
spec:
  nodeSelector:
    kubernetes.io/hostname: ${r#*:}
  terminationGracePeriodSeconds: 2
  resourceClaims:
  - name: mem
    resourceClaimTemplateName: fs-reader
  volumes:
  - name: tools
    configMap:
      name: cxl-tar
  containers:
  - name: reader
    image: docker.io/library/python:3-alpine
    command: ["python3", "-u", "/tools/cxl-tar.py", "read", "notes/hello.txt"]
    volumeMounts:
    - name: tools
      mountPath: /tools
    resources:
      claims:
      - name: mem
EOF
done
kubectl wait --for=condition=Ready pod/reader-1 pod/reader-2 pod/reader-3 --timeout=180s
for r in reader-1 reader-2 reader-3; do
    until kubectl logs $r | grep -q '^holding the mapping'; do sleep 1; done
done
kubectl get pods -o wide
for r in reader-1 reader-2 reader-3; do echo "=== $r"; kubectl logs $r; done
```

```
NAME       READY   STATUS    RESTARTS   AGE   IP            NODE                                   NOMINATED NODE   READINESS GATES
reader-1   1/1     Running   0          12s   10.217.0.13   n4-cxl-shared-2-fedora-43-containerd   <none>           <none>
reader-2   1/1     Running   0          12s   10.217.0.14   n4-cxl-shared-2-fedora-43-containerd   <none>           <none>
reader-3   1/1     Running   0          12s   10.217.1.13   n4-cxl-shared-1-fedora-43-containerd   <none>           <none>
=== reader-1
archive in /dev/dax0.0 (268435456 bytes, read-only 1):
  d      0 notes
  -     89 notes/hello.txt
notes/hello.txt, 89 bytes at offset 1024 of /dev/dax0.0:
Hello from n4-cxl-shared-1-fedora-43-containerd, written at Fri Oct 16 12:42:47 UTC 2026.
open for writing refused: EPERM
holding the mapping
=== reader-2
archive in /dev/dax0.0 (268435456 bytes, read-only 1):
  d      0 notes
  -     89 notes/hello.txt
notes/hello.txt, 89 bytes at offset 1024 of /dev/dax0.0:
Hello from n4-cxl-shared-1-fedora-43-containerd, written at Fri Oct 16 12:42:47 UTC 2026.
open for writing refused: EPERM
holding the mapping
=== reader-3
archive in /dev/dax0.0 (268435456 bytes, read-only 1):
  d      0 notes
  -     89 notes/hello.txt
notes/hello.txt, 89 bytes at offset 1024 of /dev/dax0.0:
Hello from n4-cxl-shared-1-fedora-43-containerd, written at Fri Oct 16 12:42:47 UTC 2026.
open for writing refused: EPERM
holding the mapping
```

All three readers hold a read-only mapping of the same memory at the
same time, on both nodes: `reader-1` and `reader-2` share the device's
region on VM2, `reader-3` has its own on VM1. Their device nodes have
the CDI permissions `r`: the device cgroup refuses to open them for
writing (`EPERM`), whatever the capabilities of the container. On the
host, the device is attached to both VMs, not exclusively:

```bash
pool attachments --device shared0
```

```
ID                                            SLOT                NUMA  QEMU-DEVICE      QEMU-OBJECT      SERIAL      STATE     ERROR
shared0@n4-cxl-shared-1-fedora-43-containerd  cxlsw_ds0_usrp0hb0  0     fcp_shared0.hp2  fcp_shared0.hp2  0xc1ae0001  attached  -
shared0@n4-cxl-shared-2-fedora-43-containerd  cxlsw_ds0_usrp0hb0  0     fcp_shared0.hp1  fcp_shared0.hp1  0xc1ae0001  attached  -
```

Clean up in VM2; the controller detaches the device from both nodes:

```bash
kubectl delete pod/reader-1 pod/reader-2 pod/reader-3 resourceclaimtemplate/fs-reader configmap/cxl-tar
```

The same works across the two single-node clusters: run the writer in one
cluster and readers in both, each cluster with the driver and a pool
controller (as in example d). fake-cxl-pool-server keeps the writer's
exclusive attachment from every other host, so readers of the other
cluster wait (their claims fail to attach and are allocated again) until
the writer's claim is deallocated.

After example f the two VMs are one cluster; [Clean up](#clean-up) makes
two single-node clusters of them again.

## Clean up

Delete the pods with claims first: kubelet needs the running driver to
unprepare their claims, and pool devices are detached only after that.
Then, in each VM where you deployed (after example f: VM2):

```bash
helm uninstall -n kube-system test --wait
sudo systemctl stop fake-cxl-pool-controller
```

If the local device of VM2 is attached (examples a, b and e), release and
detach it in VM2 (the driver leaves the memdev enabled when it destroys
its last region):

```bash
sudo fake-cxl-pool-client guest release 0xc100e2e1
fake-cxl-pool-client detach "$(hostname).memdev1" --self
```

On the host, check that nothing is attached any more, and stop the
server:

```bash
pool attachments
kill $POOL_SERVER_PID
```

After example f, make two single-node clusters of the VMs again with a
test that does it first, `test11-dra-sharing` (it needs the port of the
server, and removes what it installs when it ends):

```bash
(cd test/e2e && ./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test11-dra-sharing)
```

## Troubleshooting

- The log of the driver: `kubectl logs -n kube-system ds/nri-dra-driver-cxl`
  (one node), or the pod of the node:
  `kubectl logs -n kube-system $(kubectl get pods -n kube-system -l app.kubernetes.io/name=nri-dra-driver-cxl --field-selector spec.nodeName=NODE -o name)`.
  The chart logs at verbosity 4 (`logLevel`).
- The pool controller: `sudo journalctl -u fake-cxl-pool-controller` in
  the VM. The server: `build/fake-cxl-pool-demo.log` on the host.
- A pod that stays `Pending` or `ContainerCreating`:
  `kubectl describe pod NAME` (scheduling, `BindingConditionsPending`,
  errors of NodePrepareResources) and `kubectl describe resourceclaim NAME`
  (allocation, the `cxl-pool.nri.io/Attached` or `AttachFailed`
  condition).
- CXL devices in a VM: `sudo cxl list -M -R`, `sudo daxctl list`,
  `cat /sys/devices/system/node/online`. The driver's state is in
  `/var/lib/kubelet/plugins/cxl.nri.io/` and
  `/var/lib/kubelet/plugins/cxl-pool.nri.io/`
  ([Files on the node](usage.md#files-on-the-node)), its CDI specs in
  `/etc/cdi/cxl-*.yaml`.
- A device that stays in a VM after a force-deleted pod, or a zombie
  device of a stock qemu: the e2e framework restarts the VM to get rid of
  it; `test00-up` of the topology does it too.
- `run_tests.sh` fails with `port 9909 is busy`: stop the
  fake-cxl-pool-server of this guide.
