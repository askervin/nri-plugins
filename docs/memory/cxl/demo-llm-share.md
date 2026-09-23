# The CXL demo: one language model, shared from a memory pool

CAUTION: experimental. The demo runs on emulated hardware only: qemu VMs
and a fake memory pool.

This guide repeats the demo on your own machine, from an empty Linux host
to the results. It needs this repository and no CXL hardware.

- [What the demo shows](#what-the-demo-shows)
- [What runs where](#what-runs-where)
- [What the host needs](#what-the-host-needs)
- [Get the code](#get-the-code)
- [Build the QEMU fork](#build-the-qemu-fork)
- [The guest kernel](#the-guest-kernel)
- [Kubernetes, and the Kubernetes fork](#kubernetes-and-the-kubernetes-fork)
- [Build the images](#build-the-images)
- [Create the three VMs](#create-the-three-vms)
- [Get the model](#get-the-model)
- [Run the demo](#run-the-demo)
- [The latency variant](#the-latency-variant)
- [Look inside](#look-inside)
- [Read the results](#read-the-results)
- [Tear down](#tear-down)
- [Troubleshooting](#troubleshooting)
- [What was not verified](#what-was-not-verified)

Terms:

- A *memory pool* is memory that several hosts share over CXL. A *pool
  device* is a slice of it that the pool hands to one host or to several.
- *Direct access* (DAX) means a program reads the bytes of a file straight
  from the memory device, with no copy in the page cache of the operating
  system.
- *TTFT* is the time from sending a question to the first token of the
  answer. *TPOT* is the time per output token after the first; the decode
  speed in tokens per second is its inverse.

## What the demo shows

Hosts that run the same language model each keep a copy of it in memory.
With a CXL memory pool they can read one copy. The demo does this in a
Kubernetes cluster of three VMs:

1. A *writer* pod on VM1 downloads the model (a GGUF file, the model
   Qwen3.5-2B in 4-bit form). It puts the file into a read-only file system
   (erofs) on a pool device called `llm0`. Then it lets the device go.
2. One *reader* pod on each of the three VMs gets a read-only share of
   `llm0`. Each reader runs `llama-server` of the llama.cpp project, which
   maps the model file from the device.
3. A *client* pod asks every reader the kind of question that an AI agent
   asks: a short system prompt, a question about the weather in Helsinki,
   and one tool, `get_weather`, that the model may call. The model answers
   with a call of the tool. The client measures TTFT and TPOT, first for
   each reader alone and then for all three readers at once.
4. The readers are replaced by readers that use *cached access*: each VM
   reads the model into its own page cache. The client measures again.

The demo answers three questions (numbered 2.1 to 2.3 in its task):

- **2.1: Is the model in the host memory only once?** With direct access it
  is: all three VMs map the same pages of one file on the host.
- **2.2: What changes if the pool memory is slow, like real CXL memory?**
  On a host with two sockets, the demo can put the VMs on socket 0 and the
  memory of the device on socket 1, and slow socket 1 down. This is the
  *far* setup of the [latency variant](#the-latency-variant). A *local*
  setup puts the device on socket 0 too, as a baseline to compare with.
- **2.3: Does a page cache in each VM make inference faster, and what does
  it cost?** The cached readers show it.

The steps of the demo are called M1 to M15:

| step | what happens |
|:-----|:-------------|
| M1 | the writer pod starts on VM1; it has no CXL memory yet |
| M2 | the writer asks for `llm0` as a block device; the pool attaches `llm0` to VM1 |
| M3 | the writer downloads the model, checks its sha256, makes the erofs and writes it into the device |
| M4 | the writer releases the device; `llm0` is detached from VM1 |
| M5 | a reader starts on each VM with a read-only share of `llm0`, direct access; the client pod starts on VM2 |
| M6 | the client asks each reader once; the model calls the tool |
| M7 | benchmark, each reader alone |
| M8 | benchmark, all readers at once |
| M9 | host and VM memory: the model is in host memory once |
| M10 | the readers start again with cached access |
| M11 to M13 | ask and benchmark again |
| M14 | host and VM memory: a copy of the model in each VM |
| M15 | everything goes away |

With `DEMO_LLM_ACCESS=cached` the two accesses swap places.

## What runs where

The demo is made to look like a real cluster with a pool. Everything
except the pool "hardware" runs in containers:

| part | where it runs |
|:-----|:--------------|
| pool server, `fake-cxl-pool-server`: it plays the part of the pool hardware | a process on the host |
| the three VMs | qemu processes on the host |
| Kubernetes | in the VMs: VM2 is the control plane, VM0 and VM1 are workers |
| CXL DRA driver (DRA is Kubernetes Dynamic Resource Allocation), `nri-dra-driver-cxl` | a DaemonSet pod on every node |
| pool controller, `fake-cxl-pool-controller` | a Deployment pod, namespace `fake-cxl-pool` |
| writer, readers, client | pods, namespace `cxl-demo` |
| model download and erofs build | inside the writer pod |
| model mirror (only if you ask for one) | a Python web server on the host: it stands for a model registry outside the cluster |
| latency setup, and looking at host memory | the host: these are about the "hardware" |

The device `llm0` is a file on the host (`llm0.raw`) on a tmpfs, that is,
in host memory. When a VM attaches the device, its qemu maps that file.
All VMs map the same file. This is why one copy is enough. The file
system, the driver and the pods do not know that the "hardware" is fake.

How the driver and the pool work is in [pool.md](pool.md),
[leases.md](leases.md) and [e2e.md](e2e.md). The presenter's guide of the
demo (how to run it on a stage, with the six terminals) is
[`README.txt`](blob:/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/demo01-share-write-read/README.txt)
in the demo directory.

## What the host needs

The demo ran on two servers with two sockets each: an Intel Xeon 6
(Granite Rapids) server with sub-NUMA clustering (SNC2: two NUMA nodes per
socket; Ubuntu 24.04, kernel 6.8), called "the Xeon 6 server" below, and
another x86 server with several NUMA nodes per socket (openSUSE
Tumbleweed), called "the second server". Both have 256 hardware threads
and 250 GiB of memory. Smaller hosts were not tried; the sizes below are
estimates from what the VMs use.

| need | version or size | how to check |
|:-----|:----------------|:-------------|
| a 64-bit x86 Linux host with a CPU that supports KVM | | `lscpu` has a `Virtualization:` line, and `test -r /dev/kvm -a -w /dev/kvm && echo ok` prints ok |
| memory | 32 GiB or more (estimate: three VMs of 8 GiB each, plus 1.2 GiB for the model, plus the page cache of the host) | `free -g` |
| hardware threads | 24 or more (estimate: three VMs of 8 vCPUs; a reader uses 6 threads; fewer threads make the "all at once" numbers worse) | `nproc` |
| disk | 100 GiB or more free (estimate: 30 GB of sparse disk per VM, the downloaded images, the kernel cache) | `df -h ~ .` |
| vagrant | 2.4.9 (tested) | `vagrant --version` |
| vagrant plugins | `vagrant-qemu` (0.3.12 and 0.8.0 tested), `vagrant-proxyconf` (2.0.10), `dotenv` (3.2.0) | `vagrant plugin list`; install with `vagrant plugin install vagrant-qemu vagrant-proxyconf dotenv` |
| ansible | `ansible-core` 2.20.6 and 2.21.5 tested, with the `ansible.posix` collection (the playbooks use `synchronize`) | `ansible --version`, `ansible-galaxy collection list ansible.posix` |
| docker | 29.x (29.1.3 and 29.3.0 tested), usable without sudo; it builds the driver, controller and demo images | `docker info > /dev/null && echo ok` |
| go | 1.26 or newer (`go.mod` says 1.26.0; 1.27.3 tested); it builds the pool binaries | `go version` |
| python | 3.12 and 3.13 tested; the demo scripts and the model mirror use it | `python3 --version` |
| other tools | `git`, `make`, `rsync`, `curl`, `ssh`, `scp`, and `qemu-img` (vagrant-qemu calls it from PATH) | `command -v git make rsync curl ssh scp qemu-img` |
| to build qemu | the build dependencies of your distribution's qemu package: a C compiler, `ninja`, Python 3 and the development packages of glib and libslirp are enough (`configure` brings its own `meson`; pixman was not found and not needed) | see [Build the QEMU fork](#build-the-qemu-fork) |

The model is downloaded from huggingface.co. The VMs pull the llama.cpp
image from ghcr.io, the Kubernetes images from registry.k8s.io, and the
Kubernetes, containerd and helm packages and releases from pkgs.k8s.io
and github.com. If your network needs a proxy, set `http_proxy`,
`https_proxy` and `no_proxy` in the shell that runs the e2e framework
(`run_tests.sh` passes `https_proxy` on to the VMs), and the proxy of
docker in `~/.docker/config.json`. Where huggingface.co is not reachable,
see [Get the model](#get-the-model).

### What the caches save

A host without the caches below spends much more time on the first VMs.

- `~/.cache/nri-plugins/e2e` (834 MB): the Fedora 43 box (796 MB), the
  containerd and helm tarballs (36 MB and 20 MB), the kernel packages
  (21 MB, see [The guest kernel](#the-guest-kernel)) and the names of the
  latest releases. Without the box the framework downloads it from
  dl.fedoraproject.org. Without the kernel packages the first VM builds
  the kernel, which is by far the longest step of the guide.
- `~/.vagrant.d/boxes` (762 MB): vagrant's copy of the box, made from the
  file in the cache. A host without it adds the box once.
- docker's layers and the Go module cache: a cold host pulls the base
  images and downloads the modules before the driver image builds.

The demo asks for **passwordless sudo** (`sudo -n true` works) for one
thing: to mount a tmpfs for the memory of the pool device, with 2 MiB
pages spread over the memory nodes of the host. Without it, setup warns
and uses `/dev/shm`, which works but has 4 KiB pages, placed where the
writer ran, unless `/dev/shm` is mounted with `huge=`. (Also,
systemd-logind removes your files from `/dev/shm` when your last login
session ends.) The latency variant needs passwordless sudo for much more.

A quick check of the scripts that needs no VM at all: `demo selftest`
(see [Run the demo](#run-the-demo) for the `demo` command) renders every
view from recorded samples and checks that it fits a terminal of 50 x 10.
It also runs the host-side scripts (`pool-tmpfs.sh`, `latency.sh`) against
stubs of `sudo`, `mount` and `taskset` and a fake `/sys`, without root.

## Get the code

Use this repository at the branch or commit that carries this guide, in a
fresh clone if you like:

```bash
git clone <URL of the repository> -b <the branch with this guide> ~/nri-plugins
```

All paths below are relative to its root, called `N`. The VMs are created
in `$N/test/e2e`, inside this clone. Set up the `demo` command once in
every shell that you use for the demo:

```bash
cd /path/to/nri-plugins          # the root of your checkout
export N=$PWD
export D01=$N/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/demo01-share-write-read
demo() { "$D01"/bin/demo "$@"; }
```

`demo` is the entry point of the presenter's demo, and `D01` is its
directory. The demo keeps its state in `$D01/run` (ignored by git).

## Build the QEMU fork

Stock qemu cannot hot-remove a CXL memory device: the device stays in
qemu as a zombie until the VM restarts, and its slot and backing file
cannot be used again. A pool must detach and attach again, many times.
The demo needs a qemu with two fixes (branch `5jL-fix-cxl-hot-remove` of
github.com/askervin/qemu, two commits on top of the upstream master of
September 2026, version 11.1.50):

- the `cxl-downstream` port has a power controller (the QOM property
  `power_controller_present`), and the `cxl-type3` device unmaps its
  memory backend when it is unplugged, so that a device can leave and
  come back;
- the CXL device DVSEC (a block of PCIe configuration registers) is reset
  with the device, so that a guest that reboots can use its CXL devices
  again.

The setup of the demo checks for the first fix and stops without it.

**If you have a qemu with the fixes already**, check it with the two
commands at the end of this section and use it as `qemu_bin`; there is no
need to build. A build of this branch (QEMU
`11.1.50 (v11.1.0-1741-gff076b1e6c-dirty)`) passed both commands on the
second server, and its VMs ran it (`readlink /proc/<qemu pid>/exe`).
Otherwise build qemu on the host. Install the build dependencies first with
your distribution: `sudo dnf builddep qemu` on Fedora, or `sudo apt-get
build-dep qemu` on Ubuntu. On Ubuntu 24.04 the source repositories are off
and `apt-get build-dep` stops with `E: You must put some 'deb-src' URIs in
your sources.list`. Turn them on first:

```bash
sudo sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
sudo apt-get update
sudo apt-get build-dep qemu
```

(Tried in a clean `ubuntu:24.04` container, where the build below then
worked. The Xeon 6 server had the packages already and was not changed.)

On openSUSE Tumbleweed the source repository is off too. Turn it on and
install the dependencies of the qemu package:

```bash
sudo zypper modifyrepo --enable repo-source
sudo zypper source-install -d qemu
```

(Tried in a clean `opensuse/tumbleweed` container only as far as the
dependencies: `zypper source-install -d qemu` installed `meson` and `ninja`
among others. A bare container has no `git` and no `make`; install them
with `zypper install git make`. The build below was **not tried on
openSUSE**: the second server used the build it had.) Then build:

```bash
git clone https://github.com/askervin/qemu.git ~/qemu
cd ~/qemu
git checkout 5jL-fix-cxl-hot-remove
mkdir build && cd build
../configure --target-list=x86_64-softmmu
make -j"$(nproc)"
```

`configure` fetches some git submodules, so it needs network access. The
binary is `~/qemu/build/qemu-system-x86_64`. It runs from the build
directory; no `make install` is needed. Check it:

```bash
~/qemu/build/qemu-system-x86_64 --version
~/qemu/build/qemu-system-x86_64 -device cxl-downstream,help | grep power_controller_present
```

The second command must print a line like
`power_controller_present=<bool> - on/off (default: on)`. Stock qemu
prints nothing. The first prints `QEMU emulator version 11.1.50` and no
commit id, because a fresh clone has no tags.

The clone is about 400 MB, and the build compiles about 2500 files, which
takes longer on a host with fewer threads. The Xeon 6 server built it with
`x86_64-softmmu` only and the check printed the line above. (An older build
of this branch used the default `--target-list`.)

Tell the e2e framework about the binary with `qemu_bin`, when you create
the VMs ([Create the three VMs](#create-the-three-vms)). The framework
records it as `QEMU_BIN` in the file `env` of the output directory of each
VM, and later runs use it too. `qemu_bin` is read only when the VM is
created; to change the qemu of an existing VM, edit `QEMU_BIN` in its
`env` and restart the VM (halt it, wait until `vagrant status` says
`stopped`, then `vagrant up --no-provision`; see [Tear down](#tear-down)).

## The guest kernel

The VMs run a Linux kernel built from
[`test/e2e/playbook/files/qemu-cxl-kernel.config`](blob:/test/e2e/playbook/files/qemu-cxl-kernel.config).
It has CXL regions, devdax, `CONFIG_FS_DAX` (without it a program cannot
map a file of a DAX file system), erofs and the other file systems of the
driver. The topologies ask for the kernel `vanilla`, which means the
current master of Linus Torvalds' tree. The configuration was made on
7.3.0-rc4. The VMs of the demo ran 7.3.0-rc7 and 7.4.0-rc2.

You do not need to build the kernel by hand. The e2e framework looks for
built kernel packages in its cache on the host:

```text
~/.cache/nri-plugins/e2e/kernel.getsource_vanilla.config_<sha256 of the config>.rpms.tar
```

The hash in the name is the sha256 of the config file with its trailing
white space cut off, so `sha256sum` of the file gives another value. This
prints the one that the framework uses:

```bash
python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1]).read().rstrip().encode()).hexdigest())' \
    "$N/test/e2e/playbook/files/qemu-cxl-kernel.config"
```

At the commit of this guide it prints
`b71a627c295f783edd6fceb77b40d2611ed96951f850fbb7e4098b94d9f5306a`.

- If the tarball is there, `test00-up` copies it to the VM and installs
  it. The kernel is the one that the tarball holds, whatever its date: the
  tarball of the Xeon 6 server held `7.4.0-rc2-gb3dfbde62cf1`, that of the
  second server `7.3.0-rc4`, and all three VMs of each server ran that.
  The cache of the second server had four more kernel tarballs with other
  hashes in their names; those are for other configurations, and
  `test00-up` did not use them.
- If it is not, the first VM that needs it clones the kernel, builds the
  RPMs inside the VM (`make binrpm-pkg`), and the framework copies the
  tarball back to the cache. This takes much longer, and you get the master
  of that day, which may differ from the kernel above: **not tried**. The
  next VMs find the tarball in the cache.

A faster way, for a host that has `podman`, is the script
`scripts/testing/fake-cxl-pool/proto/build-kernel-rpms.sh`. It builds the
RPMs in a Fedora container and puts the tarball in the cache. **The script
is not on this branch.** It is on the branch `5jg-cxl` of
github.com/askervin/nri-plugins (older text in [e2e.md](e2e.md) still
points at it). It needs a clone of the kernel source in `LINUX_SRC` and a
work directory in `WORK`; set both, because its defaults are paths of the
author's machine. It also rewrites `qemu-cxl-kernel.config` with the
effective configuration. **Not verified:** the script was not run for this
guide.

## Kubernetes, and the Kubernetes fork

The e2e framework installs Kubernetes in the VMs from the official
packages (`k8s_release`, default the latest release; v1.37 or later is
needed). The demo was run with these releases, and you should pin them:

```bash
export k8s_release=1.37.2 helm_release=4.3.1 containerd_release=2.4.2
```

Without the pins the framework looks up the latest releases on github.com
and keeps the answer in its cache for 3 days; a lookup can stall when the
network is slow. It also refuses to run against a VM
that was created with other versions, unless you set
`e2e_vm_versions=ignore` (see the [e2e README](blob:/test/e2e/README.md)).
Every command of this guide that runs `run_tests.sh` needs the same pins:
the three `test00-up` runs, and also `demo setup`, `demo llm-share --auto`
and `demo teardown`. Set them in every shell that you use for the demo.

### Do you need the Kubernetes fork?

For this demo: probably not. The fork is github.com/askervin/kubernetes,
branch `5jr-dra-requeue`. It is Kubernetes v1.37.2 plus two commits that
change one place only, the DRA plugin of **kube-scheduler**
(`pkg/scheduler/framework/plugins/dynamicresources`). The kubelet,
kubeadm and the API server are not changed by it.

What the two fixes do, and what you see without them:

- *Requeue after Unreserve.* The scheduler keeps a device "in flight"
  between choosing it for a pod and writing the choice into the claim. If
  the pod that holds the device fails, or its claim is deleted while the
  pod waits for the device to attach, the scheduler does not tell the
  other pods that wait for the same device. Without the fix such a pod
  stays `Pending` until the scheduler's periodic flush of unschedulable
  pods, 5 minutes later. With the fix it starts at once.
- *Count consumed capacity once.* While a pod waits for a device to
  attach, the capacity that its claim uses was counted twice. A device
  that allows several claims (it has capacity to share) then looks fuller
  than it is, for up to the binding timeout, and other pods are refused
  with "cannot allocate all claims".

The demo ran without the fork: two complete setups with four `--auto`
runs on a host with upstream Kubernetes 1.37.2 (the Xeon 6 server),
all steps passed. It also ran on the second server, whose control plane
(VM2) ran a custom kube-scheduler image with the two fixes,
`localhost/kube-scheduler:v1.37.1-dra-requeue.3`. So the demo works with
both. The fork matters when pods that want the same
pool device are deleted and created again quickly, as the driver's own e2e
tests do.

Where the facts are thin:

- The demo was not run on one host with and without the fork, so "not
  needed" comes from the runs that passed, not from a comparison.
- Installing the fork is not documented in the repository, and the e2e
  framework has no option for it. What the second server's VM2 had is a
  scheduler image in the container runtime and a changed `image:` line in
  `/etc/kubernetes/manifests/kube-scheduler.yaml`. The way to get there
  is: build `kube-scheduler` and its image from the fork with the
  Kubernetes build system (`make`, see the Kubernetes docs), copy the
  image tarball into VM2, import it with `sudo ctr -n k8s.io images
  import`, and edit the `image:` line (the kubelet restarts the
  scheduler). **Not verified:** these steps were reconstructed from the
  state of the VMs, not run for this guide.

## Build the images

Two things are built on the host before the demo: the pool binaries, and
the image of the driver. In the root of the repository:

```bash
make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images
make -C scripts/testing/fake-cxl-pool
ls build/images/nri-dra-driver-cxl-image-*.tar
ls scripts/testing/fake-cxl-pool/bin/
```

- The first command builds the image of the driver (`nri-dra-driver-cxl`)
  with docker and saves it in `build/images/`. `demo setup` stops with a
  message if there is no such tarball, and uses the newest one. Build the
  image again after every change of the driver.
- The second command builds `fake-cxl-pool-server`, `fake-cxl-pool-client`,
  `fake-cxl-pool-controller`, the tool `cxl-numa-place` and the load
  program `cxl-load` (static binaries, in
  `scripts/testing/fake-cxl-pool/bin/`).

The other images are built by `demo setup`, so you do not have to:

- the **controller image**, `localhost/fake-cxl-pool-controller:testing`:
  the static controller binary in an otherwise empty image, built from
  [`scripts/testing/fake-cxl-pool/Dockerfile`](blob:/scripts/testing/fake-cxl-pool/Dockerfile)
  (to build it by hand: `make -C scripts/testing/fake-cxl-pool image`).
  Setup imports it into every VM; there is no registry;
- the **demo tools image**, `localhost/cxl-demo-tools` (Python on Alpine
  with `erofs-utils`, built from the `image/Dockerfile` of the demo
  directory), which the writer and the client use. Setup imports it into
  every VM;
- the **llama.cpp image**, `ghcr.io/ggml-org/llama.cpp:server-b11681`,
  which the VMs pull themselves (about 300 MB each).

## Create the three VMs

Create the VMs with the `test00-up` test of each topology, in this order:
VM1, VM0, and then VM2, whose `test00-up` also builds the three-node
cluster. Give the patched qemu with `qemu_bin`, an absolute path:

```bash
cd "$N/test/e2e"
export k8s_release=1.37.2 helm_release=4.3.1 containerd_release=2.4.2
export qemu_bin=$HOME/qemu/build/qemu-system-x86_64   # or the path of the qemu you have
./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-1/test00-up
./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-0/test00-up
./run_tests.sh memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test00-up
```

Each run creates a VM in `test/e2e/n4-cxl-shared-<n>-fedora-43-containerd`
(Fedora 43, containerd), downloads the Fedora image and the packages,
installs the kernel, and checks the CXL devices of the VM. Do not pass
`-o` to `run_tests.sh`: it moves the output directory of the VM, and the
framework then creates a new, single-node VM there. Run one `run_tests.sh`
at a time ([What the caches save](#what-the-caches-save) tells what makes a
run long). Lines like `Status code: 503 for https://mirrors...` or `Curl error (28): Timeout`
come from dnf trying a mirror in the VM; they are harmless when the run
ends with `Test verdict: PASS`. The VMs' memory is 8 GiB each, and
`vagrant global-status` lists them with the directory of each. The framework
lets the qemu of each VM use transparent huge pages whatever the host's
setting is, so that the guest RAM and the pool memory can be in 2 MiB pages
(`grep THP_enabled /proc/<qemu pid>/status` says 1).

When it works, VM2 has this cluster (check it from the host):

```bash
ssh -F n4-cxl-shared-2-fedora-43-containerd/.ssh-config node kubectl get nodes -o wide
```

You see the three nodes `Ready`: `n4-cxl-shared-0-fedora-43-containerd`,
`-1-` and `-2-` (the last one is the control plane). The VMs keep running
until you stop them; the demo uses them as they are. Details of the
VMs and the cluster are in [Create the VMs](e2e.md#create-the-vms) of
the e2e guide.

## Get the model

The default model is Qwen3.5-2B, quantized to 4 bits (`Q4_K_M`), from the
unsloth repository on Hugging Face. It is a small model with native
tool calling, under the Apache-2.0 licence. The setup pins each model by
the commit of its repository and checks its sha256.

| `DEMO_LLM_MODEL` | file | size | device `llm0` |
|:-----------------|:-----|:-----|:--------------|
| `qwen3.5-2b` (default) | `Qwen3.5-2B-Q4_K_M.gguf` | 1221 MiB | 1536Mi |
| `qwen3.5-0.8b` | `Qwen3.5-0.8B-Q4_K_M.gguf` | 508 MiB | 768Mi |
| `qwen3-0.6b` | `Qwen3-0.6B-Q4_K_M.gguf` | 378 MiB | 512Mi |

Use the smaller models for a quick rehearsal or a slower host. In a VM of
8 vCPUs, with 6 threads, the 0.8B decodes about twice as fast as the 2B and
the 0.6B about three and a half times as fast.

**Where huggingface.co works:** do nothing. The writer pod downloads the
file when you run step M3 (it uses the proxy settings of VM2).

**Where it does not work** (for example behind a proxy that intercepts
TLS; the Xeon 6 server was one): download the file on any machine
that can reach Hugging Face, check it, and put it in a directory of the
host. Then give the directory to `demo setup`:

```bash
mkdir -p ~/llm-models && cd ~/llm-models
curl -LO https://huggingface.co/unsloth/Qwen3.5-2B-GGUF/resolve/f6d5376be1edb4d416d56da11e5397a961aca8ae/Qwen3.5-2B-Q4_K_M.gguf
echo "aaf42c8b7c3cab2bf3d69c355048d4a0ee9973d48f16c731c0520ee914699223  Qwen3.5-2B-Q4_K_M.gguf" | sha256sum -c
export DEMO_LLM_MODEL_DIR=$HOME/llm-models
```

If the machine that can reach Hugging Face is not the host, download and
check the file there, and copy it to the host with `scp`:

```bash
ssh HOST mkdir -p llm-models
scp Qwen3.5-2B-Q4_K_M.gguf HOST:llm-models/
ssh HOST 'cd llm-models && echo "aaf42c8b7c3cab2bf3d69c355048d4a0ee9973d48f16c731c0520ee914699223  Qwen3.5-2B-Q4_K_M.gguf" | sha256sum -c'
```

`sha256sum -c` must print `OK`. Copy only the model that you will use. On
the host, `export DEMO_LLM_MODEL_DIR=$HOME/llm-models` as above.

With `DEMO_LLM_MODEL_DIR` setup checks the sha256, starts a small web
server for the directory on the host (port 9920, which the VMs reach at
`http://192.168.76.2:9920`) and tells the writer to download from it.
Teardown stops it. The file name must be exactly the one in the table.
The URLs, commits and sha256 sums of the other two models are in the table
`LLM_MODELS` at the top of
[`test90-demo-setup/code.var.sh`](blob:/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/demo01-share-write-read/e2e/demo.test-suite/dra-driver-cxl/n4-cxl-shared-2/test90-demo-setup/code.var.sh).
A directory on the host is also useful for rehearsals, because the
download is then local.

You can also use your own mirror: `DEMO_LLM_MODEL_URL=<url>` makes the
writer download from that URL (the sha256 must still match). It takes
precedence over `DEMO_LLM_MODEL_DIR`. For a URL outside the host, setup
gives the writer the proxy settings of VM2.

## Run the demo

Check first that no other test runs and nothing uses the ports 9909 (the
pool server) and 9920 (the model mirror): `pgrep -x run_tests.sh` prints
nothing, and `ss -ltn` does not show those ports. One demo at a time.

Set the release pins ([Kubernetes](#kubernetes-and-the-kubernetes-fork))
and, if you staged the model, `DEMO_LLM_MODEL_DIR` in this shell too:
`demo setup`, `demo llm-share --auto` and `demo teardown` run `run_tests.sh`.

### Set up

```bash
demo setup llm-share
```

Setup is a test of the e2e framework (`test90-demo-setup`), run through
`run_tests.sh`. Its log is `run/test90-demo-setup.log` in the demo
directory. It does this:

- mounts a tmpfs for the pool memory at `/tmp/fake-cxl-pool-llm`: 2 MiB
  pages where possible (`huge=within_size`), spread evenly over all the
  memory nodes of the host (`mpol=interleave:<nodes>`, see
  [The pool directory](#the-pool-directory) below); the local and far
  setups of the latency variant mount their own;
- starts `fake-cxl-pool-server` on the host with the device `llm0`
  (persistent, shared, cabled to all three VMs);
- builds the controller and demo images, imports them and the driver
  image into the VMs, pulls the llama.cpp image into the VMs;
- installs the driver on every node with helm and starts the pool
  controller as a Deployment;
- starts the model mirror if you gave `DEMO_LLM_MODEL_DIR`, creates the
  ConfigMaps with the demo tools and the model description, labels the
  nodes `cxl-demo/node=vm0|vm1|vm2`, and starts the trace collectors.

The first setup on freshly created VMs is the longest: it builds the
controller and demo images, and the three VMs pull the llama.cpp image.

The output of a setup or a teardown ends with lines that look like errors
and are not: `curl: (7) Failed to connect to localhost port 8891` (the test
asks a coverage port that is not there), `no coverage data to dump`, `No
coverage data found under ...`, and a few ansible `DEPRECATION WARNING`
lines. What counts is `Test verdict: PASS`.

When setup is done it prints the six terminal commands of the presenter's
layout and leaves everything up until `demo teardown`. `run/state.env` says
what runs.

The options are environment variables of `demo setup`:

| variable | default | meaning |
|:---------|:--------|:--------|
| `DEMO_LLM_MODEL` | `qwen3.5-2b` | `qwen3.5-2b`, `qwen3.5-0.8b` or `qwen3-0.6b` |
| `DEMO_LLM_MODEL_DIR` | not set | a host directory with the model file: setup serves it to the writer ([Get the model](#get-the-model)) |
| `DEMO_LLM_MODEL_URL` | the Hugging Face URL | where the writer downloads the model from; wins over `DEMO_LLM_MODEL_DIR` |
| `DEMO_LLM_ACCESS` | `direct` | the access of the first readers, `direct` or `cached`; the steps switch to the other one at M10 |
| `DEMO_LLM_LATENCY` | `off` | the [latency setup](#the-three-setups): `off`, `local` or `far` (`on` is the old name of `far`) |
| `DEMO_LLM_LATENCY_LOAD` | `off` | with `DEMO_LLM_LATENCY=far`: `700` or `1000` adds background memory traffic on socket 1 that raises the latency to the device; 1000 loads the memory more than 700 ([background traffic](#background-traffic-a-busier-device)) |
| `DEMO_LLM_REPEAT` | `3` | how many requests per reader the benchmarks send; you can also set it when you run a step |
| `DEMO_POOL_DIR` | `/tmp/fake-cxl-pool-llm` | the pool directory: setup mounts a tmpfs there; it must be empty or missing ([the pool directory](#the-pool-directory)) |

### The pool directory

The pool directory is where the pool server creates the files that are the
memory of its devices, so the pages of its tmpfs are the memory of `llm0`.
Setup mounts the tmpfs with these options:

- `huge=within_size`: 2 MiB pages where the file is large enough;
- `mpol=interleave:<nodes>`: the pages are spread round robin over the
  NUMA nodes of the host that have memory and CPUs (the nodes in both
  `/sys/devices/system/node/has_memory` and `has_cpu`, like `1-2,5-6`). A
  node with memory and no CPUs, like the memory of a CXL device or HBM, is
  left out. On a host with one such node there is no policy.

The spread matters. With no policy a page is allocated on the node of the
CPU that first writes it, which is where the writer's vCPU happened to run.
On the second server that put all of `llm0.raw` on one node in two runs and
on two or three nodes in two others, and three direct readers at once
decoded about 1.8 times as slowly with the file on one node, and about 1.4
times with it on two or three nodes, as with it spread evenly over the four
nodes. So the latency-off baseline would depend on where a thread happened
to run.
With the spread it does not. It is neutral: about half of the file is on
the other socket. The local setup of the latency variant spreads the pool
directory over the nodes of socket 0 instead, and the far setup binds it to
the nodes of socket 1.

Two things to know. mount(8) splits the options at their commas and gives
each to the kernel on its own, so `mpol=interleave:1-2,5-6` fails with
"tmpfs: Unknown parameter '5-6'". The scripts therefore run `mount` with
`LIBMOUNT_FORCE_MOUNT2=always`, which makes it pass all the options in one
string. With 2 MiB pages the spread is best effort: a huge page goes to the
next node of the list if its node has no free 2 MiB block then, so check
the nodes after the model is written (step M9), as in
[Host memory: where the model is](#host-memory-where-the-model-is). The
saved results record the policy (`pool.mpol` in the JSON files).

### Step by step

Run the steps in a terminal, one after another:

```bash
demo llm-share
```

Each step shows its caption and the real command, and waits for a key:
Enter runs it, `s` skips it, `z` opens a zoom (a detail view, for example
`pool` or `driver vm1`), `q` stops. After the command the step shows a
short result (one to four lines) and the time it took. The command is never
hidden. The commands run as root in VM2 in `/root/demo`, with a
kubeconfig whose default namespace is `cxl-demo`. The steps that look at
the host (M9 and M14) run on the host.

You can run one step, the steps from one on, or a range of steps:

```bash
demo llm-share 7        # only M7
demo llm-share 7-       # M7 to the end
demo llm-share 2-5      # M2 to M5
DEMO_LLM_REPEAT=5 demo llm-share 7
```

The selection is `N`, `N-` or `N-M`, and `--auto` or `--no-color` can
come with it. The script refuses any other argument (`2..5`, say) and
a step that does not exist, and says why; it runs nothing then. A step that you
stop in the middle (by closing the terminal, say) leaves its work half
done; run `demo llm-share N` for that step again, or `demo reset llm-share`
and start over.

The full output of every step is in `run/steps.log` (`demo zoom last`
shows the last one). To start the script again from step 1 in the same
setup, run `demo reset llm-share`: it deletes the demo pods and their
claims. The presenter's guide has the six-terminal screen: run
`demo commands` to print the commands for the terminals T1 to T6 (`demo
view t2` to `demo view t6` are the live views), and
[`README.txt`](blob:/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/demo01-share-write-read/README.txt)
describes what each view shows.

### All at once, with `--auto`

```bash
demo llm-share --auto
```

All steps, with a pause between them (`DEMO_AUTO_PAUSE`, default 2
seconds, and the script adds 1). The timings of each run are appended to
`run/timings.txt`. You can run `--auto` again in the same setup (the writer
fetches and writes the model again). The second run of a setup gave similar
numbers; with latency off, where the VMs are not pinned, some cells
differed by up to about 40% between the two runs.

### The matrix of measurements

One setup runs both accesses (direct and cached) and both modes (alone and
all at once) with the latency setup that you chose. The latency setup is
chosen at setup and cannot change while the demo is set up, so the full
table takes one setup for each:

```bash
DEMO_LLM_LATENCY=off   demo setup llm-share; demo llm-share --auto; demo teardown
DEMO_LLM_LATENCY=local demo setup llm-share; demo llm-share --auto; demo teardown
DEMO_LLM_LATENCY=far   demo setup llm-share; demo llm-share --auto; demo teardown
demo llm results
```

The last command prints one table of all the results, each run labelled
with its latency setup (`off`, `local`, `far`, or `far+700` with the
background load). They stay in `run/llm-results/` over teardown. [The three
setups](#the-three-setups) say which runs can be compared.

## The latency variant

Real CXL memory is slower than the DRAM next to the CPU. The VMs of the
demo read the pool memory at the speed of host memory. The latency variant
makes the reads slower, towards the latency of real CXL memory, which is
higher than that of the DRAM of the other socket. On the Xeon 6 server
`mlc` measures three to five times the latency to the DRAM of the other
socket as to the DRAM of the same socket. A *NUMA node* is a group of CPUs
and the memory next to them; a socket has one or more of them.

### The three setups

`DEMO_LLM_LATENCY` chooses where the VMs run and where the memory of the
device `llm0` is:

| setup | the VMs | the memory of `llm0` | slowdown |
|:------|:--------|:---------------------|:---------|
| `off` (the default) | not pinned: any CPU of the host, memory wherever the host put it | spread evenly over all the memory nodes of the host (`mpol=interleave`); on a two-socket host about half of it is on the other socket | none |
| `local` | pinned to the CPUs of socket 0, their own memory moved to the nodes of socket 0 | spread evenly over the memory nodes of socket 0 (`mpol=interleave`) | none |
| `far` | the same as `local` | on the memory nodes of socket 1 only (`mpol=bind`) | the uncore and IO dies of socket 1 capped, where the host has the controls; with `DEMO_LLM_LATENCY_LOAD` also background traffic |

"Near" is socket 0 and "far" is socket 1. `on` is the old name of `far`
and still works. In `local` and `far` the host also turns off what moves
pages by itself (automatic NUMA balancing, KSM, memory demotion), so that a
page stays where the setup put it. `off` changes nothing on the host.

Which runs to compare:

- **`local` is the best placement the host has for the model.** The memory
  of the device is on the socket of the VMs, spread over the nodes of that
  socket, and nothing slows it down. Compare direct and cached access
  *within* `local` to see what is left of the gap between them when the
  memory distance is as small as it gets.
- **`local` against `far`** differ for the VMs in one thing: where the
  device memory is, and the slowdown that goes with it. The pinning, the
  tunables and the placement of the VMs' own memory are the same. This is
  the cost of the distance to the device.
- **`off` is not a local setup.** The VMs are not pinned and the device is
  spread over all the nodes, so on a two-socket host about half of the
  model is on the other socket and the numbers depend on where the host
  puts the VMs. `off` against `local` shows the effect of pinning and
  placement; `off` against `far` mixes that with the distance. Use `off`
  to see the demo as the e2e framework leaves the host.
- **Servers do not compare.** Compare the setups of one server.

The `far` setup needs a host with **two sockets**. It does this:

- the VMs run on socket 0, with their own memory on socket 0;
- the memory of the device `llm0` is on socket 1;
- socket 1 is slowed down, where the host has the controls;
- no page moves between the sockets by itself.

Then a VM crosses the socket boundary when, and only when, it reads the
device. The `local` setup needs socket 0 only. Start either with
`DEMO_LLM_LATENCY=far demo setup llm-share` or
`DEMO_LLM_LATENCY=local demo setup llm-share`.

### What it changes on the host

The work is done by the script `bin/latency.sh` of the demo directory.
`demo latency on [far|local]|off|status` runs it, and `demo setup` runs
`on` with your setup for you (`demo latency on` alone is `far`). In the
setup, `on` runs after the VMs are reset and before the pool server makes
the device files. It changes these things, and saves each old value in
`run/latency.state` first. The table is the `far` setup; the `local` setup
does the same except the last three rows: its pool directory is a tmpfs
mounted with `mpol=interleave:<nodes of socket 0>` and `huge=within_size`,
and it caps no frequency and starts no load:

| what | to |
|:-----|:---|
| automatic NUMA balancing (`kernel.numa_balancing`) | 0 |
| KSM (the kernel's page merging) | `run` 2: unmerge and stop (only if it ran or had merged pages) |
| memory demotion (`demotion_enabled`) | `false` |
| every thread of each demo VM's qemu | pinned (`taskset`) to the CPUs of socket 0 |
| the memory of each demo VM's qemu | moved (`migratepages`) to the NUMA nodes of socket 0 |
| the pool directory | a tmpfs mounted with `mpol=bind:<nodes of socket 1>` and `huge=within_size`: the pages of the device are born on socket 1 (with latency off they are interleaved over all nodes, see [the pool directory](#the-pool-directory)) |
| the maximum frequency of the uncore and IO dies of socket 1 (the "uncore" is the part of the CPU outside the cores: memory controllers, caches, links) | capped to their minimum (`/sys/devices/system/cpu/intel_uncore_frequency/uncore*/max_freq_khz`) |
| the background load (only with `DEMO_LLM_LATENCY_LOAD`; see [below](#background-traffic-a-busier-device)) | started in the background, after the caps |

It also measures the idle latency from a CPU of socket 0 to a node of
socket 0 and to a node of socket 1 with `mlc`, before and after (in the
`local` setup too, where the two readings only show that nothing changed),
and lists the other VMs on the host. It never touches VMs that are not part
of the demo; stop big ones yourself, because they add noise.

What it needs: for `far` **two sockets**, each with NUMA nodes that have
both CPUs and memory (for `local` socket 0 only); **passwordless sudo**;
`taskset`, `migratepages` (the `numactl` package), `findmnt`, `mountpoint`
and `flock`. Optional: Intel
MLC (`mlc`, for the latency numbers) and Intel PCM
([github.com/intel/pcm](https://github.com/intel/pcm), only `pcm-tpmi`, to
label the dies as compute or IO). Put the directory of each in your `PATH`
before you run `demo`, or set `MLC` and `PCM_TPMI` to their paths.
`latency.sh` finds them in your `PATH`, not in the `PATH` that `sudo` gives
it, and runs them under `sudo` by the path it found. Both variables and
`PATH` reach `latency.sh` when you set them for `demo setup`: the setup
runs `latency.sh` with `host-command`, which is `bash -c` in the
environment of the e2e run, and `run_tests.sh` does not clear that
environment.

### Hosts without the frequency controls

The frequency controls are the `intel_uncore_frequency` files in sysfs. The
Xeon 6 server (kernel 6.8) has them. The second server has none. Without
them `latency.sh` prints

```text
uncore/IO-die frequency controls are not available on this host
```

and goes on. Everything else is done: the VMs are on socket 0 and the
device memory is on socket 1, so the VMs still cross the socket link when
they read the device. Only the extra slowdown is missing. (The second
server printed this line, found its near and far nodes, pinned the three
qemus to the CPUs of socket 0, mounted the pool tmpfs with `mpol=bind:` and
the far nodes, and printed `mlc not found ... no latency measurement
before`. Teardown restored the CPU affinities and `kernel.numa_balancing`.)
If `mlc` is missing, it says so and skips the latency numbers. If `pcm-tpmi` is
missing, the dies are labeled `unknown`, and the frequencies of all
domains of socket 1 are still capped.

The domains say which package they are of (`package_id`), and only the CPUs
say which CPUs and memory a package has (`physical_package_id`). `latency.sh`
caps the domains of package 1 only if the packages of the domains are the
packages of the CPUs. Otherwise it caps nothing, says so, and `on` fails
and restores what it changed: it cannot tell which domains are the far
socket's, and capping the near socket's would slow the VMs instead of the
device. On success it prints the nodes and CPUs of the package that it
capped.

On a host with one socket, or one where socket 0 or socket 1 has no node
with CPUs and memory, `latency.sh on` stops with the reason, for example
"this host has one package (socket)", and `DEMO_LLM_LATENCY=far` makes the
setup fail. Run the demo without it there; `DEMO_LLM_LATENCY=local` works
on a host with one socket (it stops only if socket 0 has no node with CPUs
and memory), but then there is nothing to compare it with.

### Restoring

`demo teardown` runs `latency.sh off` at the end, and so does a failed
setup. `off` stops the background load if there is one, writes back every
saved value: NUMA balancing, KSM, demotion, the CPU affinity of every
thread, the frequency caps, and it unmounts the tmpfs. An `on` that fails,
or that gets SIGINT (Ctrl-C), SIGTERM or SIGHUP, does the same for what it
had changed so far, and exits with 1. The one thing it does not save is
the hardware prefetchers that `mlc` switches off while it measures and back
on at its end (see [Background
traffic](#background-traffic-a-busier-device)). With `rdmsr` (the
`msr-tools` package and the `msr` kernel module) `latency.sh` reads their
register (MSR 0x1a4) before and after `mlc`, shows it in `status`, and warns
if a killed `mlc` left it changed; without `rdmsr` it cannot tell. You can
look at it and run it yourself:

```bash
demo latency status
demo latency off
```

`status` shows the topology, the settings, the VMs and their memory, the
placement of the device files, the uncore frequencies, and the `mlc`
numbers. Three things stay by nature after `off`: the memory of the VMs
stays on the nodes it was moved to (automatic NUMA balancing moves it again
over time), KSM starts to merge again from zero, and qemu keeps the removed
device file mapped (see [Tear down](#tear-down)).

### What the caps did on the Xeon 6 server

The caps slowed socket 1 itself (a read from a CPU of socket 1 to its own
memory took about 20% longer), but they did not reach the latency of real
CXL memory. `mlc --idle_latency` from CPU 0 to the memory of the first NUMA
node of socket 1 rose by about 5%, and the whole socket 0 to socket 1 part
of the latency matrix by 5 to 10%. That is well below what the demo aims at.
The IO dies of that server already idle at their minimum frequency, so
there is little left to cap.

### Background traffic: a busier device

The caps alone raise the latency to the far memory only a little. Real CXL
memory is often slower than that, most of all when other hosts use the same
link or device.
The knob `DEMO_LLM_LATENCY_LOAD` emulates that: it keeps the memory of
socket 1 busy, so that a read from socket 0 waits in a queue. It is **off
by default**, and it needs `DEMO_LLM_LATENCY=far`.

There are two levels, `700` and `1000`; the names are labels. The table
gives the idle latency that `mlc` measures from CPU 0 (socket 0) to the
memory of socket 1 while the load runs, relative to the value with the caps
only:

| level | what the load does | latency to socket 1 |
|:------|:-------------------|:--------------------|
| none | nothing (the caps only) | 1.0 |
| `700` | every CPU of socket 1 writes to a buffer of its own, and waits 120 microseconds after each block | 1.4 |
| `1000` | the same, with no waiting | 2.1 |

Start it with the setup:

```bash
DEMO_LLM_LATENCY=far DEMO_LLM_LATENCY_LOAD=700 demo setup llm-share
```

`demo latency levels` lists the levels. A level that does not exist, or the
knob without `DEMO_LLM_LATENCY=far` (with `local` or `off`), stops the
setup before it changes anything.

**On another host the levels mean something else.** They were calibrated
on the Xeon 6 server. The load needs the CPUs of the far socket (it pins
its threads to them) and the far memory, and it writes as fast as that
host allows with the pause of the level. The second server (no `mlc`, so
the latency was not measured) had `cxl-load` writing at about a quarter of
the rate of the Xeon 6 server with the level 700. The direct readers were
far slower than with the far setup and no load (about 3.7 times as slow
alone and 2.8 times at once), and the cached readers did not change when
alone. Everything worked and the teardown stopped the load (`latency:
stopped the background load of level 700`). To approach a given latency on
your host, calibrate the level with `mlc` and `LATENCY_LOAD_ARGS` (below).

How it works:

- `latency.sh on` starts the program `cxl-load` (from
  `scripts/testing/fake-cxl-pool`, built with the other binaries) in the
  background, after the frequency caps. It runs one thread on each CPU of
  socket 1 (128 on the Xeon 6 server). Each thread writes, block after
  block, over its own buffer of 64 MiB. The buffer is bound to the memory of
  socket 1 and every page of it is touched before the load starts. The wait
  after each block sets the bandwidth.
- The load runs in a session of its own, at the lowest priority, so that
  other work on the CPUs of socket 1 goes first. The VMs are on socket 0, so
  the load takes no CPU from them. It takes 8 GiB of the memory of socket 1,
  and `cxl-load` refuses to take more than half of the free memory of the
  nodes.
- The process is saved in `run/latency.state`. `latency.sh off` and
  `demo teardown` stop it. `demo latency status` shows the level and the
  last line of bandwidth that it printed (`run/cxl-load.log` has them all).
  The result files of the benchmarks carry the level in their latency column
  (`far+700`).
- Why writes? A CPU that writes a line first reads it, to own it, and later
  writes it back. So writes at the full rate make about twice that in memory
  traffic: the memory channels of socket 1 are full. Reads from the CPUs of
  socket 1 did much less: reads at 40 to 80% of that rate raised the
  latency by at most 16%.

The curve on the Xeon 6 server (`mlc --idle_latency`, CPU 0 to the first
node of socket 1, `mlc` as `latency.sh` runs it, the caps on, 128 writing
threads). The written rate is relative to the highest rate that the server
took, the latency to the value with no load:

| wait after each block | written | latency |
|:----------------------|:--------|:--------|
| no load | 0 | 1.00 |
| 800 microseconds | 0.23 | 0.92 |
| 400 microseconds | 0.41 | 0.99 |
| 200 microseconds | 0.65 | 1.18 |
| 150 microseconds | 0.77 | 1.31 |
| 120 microseconds (level 700) | 0.86 | 1.39 |
| 90 microseconds | 0.95 | 1.53 |
| 60 microseconds | 1.00 | 1.82 |
| none (level 1000) | 0.99 | 2.10 |

The latency stays near its idle value while the memory has room, then it
rises fast when the channels fill up. Repeated runs of one level agree
within 1%, and the readings before and after a long benchmark were the
same.

What to know:

- It is a busy memory, not a longer path. The queue is in the memory
  controllers of socket 1, and the readers see it as a larger latency. It
  makes the reads slow like a busy CXL device does, but it does not model
  the CXL protocol.
- The levels mean what the table says on the server of the calibration: an
  Intel Xeon 6 with two sockets, 128 CPUs per socket, sub-NUMA clustering
  (SNC2) and the caps on. On another host, read the line `mlc idle latency
  after` that
  `latency.sh on` prints, and change the load with `LATENCY_LOAD_ARGS`
  (more arguments for `cxl-load`; the last one wins): `-pause 200us` for
  less load, `-threads 32` for fewer threads. `cxl-load -h` lists all its
  options.
- `mlc` as `latency.sh` runs it switches the prefetchers of all CPUs off
  while it runs (the register MSR 0x1a4) and writes them back. A load of
  reads slows down when that happens; the load of writes does not, which is
  another reason for writes. With `mlc --idle_latency -e -r`, which leaves
  the prefetchers on, the same load reads 10 to 30% lower and not always the
  same. Compare numbers of the same kind.
- The idle latency before the load depends on how warm the uncore of socket
  1 is: `latency.sh on` measured about 20% less right after a busy period
  than after a quiet one. The line "before" in the output shows which.
- The decode speed falls with the direct access, because the readers wait
  for the busy memory (see [Read the results](#read-the-results)).
  The cached access does not change: its copy is in the memory of the VM,
  on socket 0.

## Look inside

### Log in to the VMs

Each VM has an ssh configuration in its output directory. The user is
`vagrant`, who may `sudo`. VM2 also has `kubectl` and `helm`, with
cluster-admin rights:

```bash
cd "$N/test/e2e"
ssh -F n4-cxl-shared-2-fedora-43-containerd/.ssh-config node     # VM2, control plane
ssh -F n4-cxl-shared-1-fedora-43-containerd/.ssh-config node     # VM1
ssh -F n4-cxl-shared-0-fedora-43-containerd/.ssh-config node     # VM0
```

Add a command to run it at once, for example
`ssh -F n4-cxl-shared-2-fedora-43-containerd/.ssh-config node kubectl -n cxl-demo get pods -o wide`.

### Look at the cluster with kubectl

In VM2:

```bash
kubectl -n cxl-demo get pods -o wide              # writer, readers, client, and where they run
kubectl -n cxl-demo get resourceclaims            # the claims of the pods and their leases
kubectl get resourceslices                        # the devices that the driver and the controller publish
kubectl -n kube-system get pods -l app.kubernetes.io/name=nri-dra-driver-cxl -o wide
kubectl -n fake-cxl-pool get pods                 # the pool controller
kubectl -n fake-cxl-pool logs -l app.kubernetes.io/name=fake-cxl-pool-controller --tail=20
kubectl -n cxl-demo logs reader-1 --tail=20       # llama-server: model load, one line per request
kubectl -n cxl-demo describe pod reader-1         # why a pod is not Running
```

The log of the driver on a node is the log of the driver pod of that node
(`kubectl -n kube-system logs <pod>`); `demo zoom driver vm1` prints the
last lines of it from the host. More zooms (`demo zoom help` lists all):
`slice` (the ResourceSlice entry of a device), `claim writer` (the claim
behind the writer's lease), `pool` (the pool server's devices and
attachments), `cdi NODE`, `kernel NODE` (the kernel's CXL and DAX lines),
`cxl NODE` (`cxl list` of the node), `mounts NODE` and `last` (the full
output of the last step). NODE is `vm0`, `vm1` or `vm2`. The zooms `claim`,
`pod` and `env` are for pods with leases: in this case that is the writer.

### The live views

The presenter's screen has six terminals of 50 x 10 characters. `demo
commands` prints the command for each. In short: T1 the steps, `demo view
t2` the pods and leases, `t3` the scheduler's devices and claims, `t4` the
nodes (which process maps which file of the file system on each node),
`t5` a trace with one line per event, `t6` the pool server and the model
in the device. `demo capture LABEL` writes each view once to a text file.

### Trigger one inference by hand

Ask one reader the demo's question with the demo's own client. In VM2:

```bash
kubectl -n cxl-demo exec client -- /demo/llm ask reader-1
```

It prints one line, for example
`reader-1: get_weather {"city":"Helsinki","unit":"celsius"} (TTFT N s, 40 tokens)`:
the reader, its answer (cut at 60 characters), the time to the first token
and the number of tokens. Without a reader name it asks all three, one after
another. To run the benchmarks by hand:

```bash
kubectl -n cxl-demo exec client -- /demo/llm bench single --repeat 3
kubectl -n cxl-demo exec client -- /demo/llm bench simultaneous --repeat 3
```

You can also send your own question straight to the server of a reader,
from a shell in any VM, on the IP of the pod:

```bash
ip=$(kubectl -n cxl-demo get pod reader-1 -o jsonpath='{.status.podIP}')
curl -s --noproxy '*' "http://$ip:8080/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -d '{"messages": [{"role": "user", "content": "Say hello in five words."}], "max_tokens": 32}'
```

This is the same server and the same kind of request that the client
sends (the client adds a system prompt, the tool, streaming and a fixed
seed). The command ran from VM2 and the answer was `Hello there, how's your day going?`. The llama.cpp
image has `curl`, so `kubectl -n cxl-demo exec reader-0 -- curl -s
localhost:8080/v1/chat/completions ...` works as well (`.../health` answers
`{"status":"ok"}`), as the presenter's guide says.

### Host memory: where the model is

On the host, `demo llm mem LABEL` prints where the model is in memory and
saves it to `run/llm-mem-LABEL.json`. The steps M9 and M14 run it. You can
run it any time while readers run:

```bash
demo llm mem direct
demo llm mem cached --since direct       # also the changes since the snapshot "direct"
```

The lines to look at: how much of `llm0.raw` is in host memory (once), what
each VM's qemu maps (`Rss`, and `Pss`, which splits shared pages among
the qemus that map them), how much of it is in 2 MiB pages, on which NUMA
nodes, and, from inside each VM, how much page cache the reader is charged
for.

The tool `cxl-numa-place` shows on which NUMA nodes of the host the pages of
a file are. The device file is in the pool directory:

```bash
"$N"/scripts/testing/fake-cxl-pool/bin/cxl-numa-place where /tmp/fake-cxl-pool-llm/llm0.raw
```

It prints the size, the resident size and the share of the resident pages
on each node. With latency off and the default pool directory, it shows the
file spread over the memory nodes, about the same share on each (the
[pool directory](#the-pool-directory) is interleaved); with the far setup,
only the far nodes, and with the local setup only the nodes of socket 0.
(With `move --nodes N file` it can move the pages; this needs root and is
not part of the demo.) To see the mapping of one qemu you need its process
id. This finds the qemu of VM1 the way the e2e framework does,
and shows its mapping of the device file:

```bash
dir=$(realpath "$N/test/e2e/n4-cxl-shared-1-fedora-43-containerd")
for pid in $(pgrep qemu-system); do
    grep -qaF "$dir/.vagrant/machines/" /proc/$pid/cmdline || continue
    echo "VM1 qemu: pid $pid"
    awk '/^[0-9a-f]+-[0-9a-f]+ /{m=($NF ~ /llm0.raw/)} m && /^(Rss|Pss|ShmemPmdMapped):/' /proc/$pid/smaps
    grep llm0.raw /proc/$pid/numa_maps     # N<node>=<pages> are the pages per NUMA node
    grep THP_enabled /proc/$pid/status     # 1: this qemu may use huge pages
done
```

`Rss` is the same for the three qemus and `Pss` is a third of it: the
three VMs map the same pages. `ShmemPmdMapped` equal to `Rss` means 2 MiB
pages everywhere. If `THP_enabled` is 0 there are no huge pages; see
[Troubleshooting](#troubleshooting). The pool memory itself:

```bash
findmnt -T /tmp/fake-cxl-pool-llm        # the tmpfs and its options (huge=, mpol=)
grep -E '^Shmem:|ShmemHugePages' /proc/meminfo
```

### The pool server

The server is a host process. Its state and its log:

```bash
"$N"/scripts/testing/fake-cxl-pool/bin/fake-cxl-pool-client --server http://127.0.0.1:9909 devices llm0
demo zoom pool                           # the same through the demo
sed -n 's/^POOL_SERVER_LOG=//p' "$D01"/run/state.env
```

The last command prints the path of the server log.

### Inside the VMs: page cache and mounts

```bash
kubectl -n cxl-demo exec reader-0 -- /demo/llm-mem reader-0       # one line of KEY=VALUE
demo zoom mounts vm0                                              # the pmem mounts, loop devices, read-only flags
```

The last section of `demo zoom mounts` (the lease binds) says `find: ...
lease-fs: No such file or directory` here, because the node has no lease
binds. Ignore it.

`llm-mem` prints the VM's `MemAvailable` and `Cached` (the page cache),
the page cache charged to the reader's cgroup (`cgFileKb`: 0 with direct
access, the size of the model with cached access), and the mapping of the
gguf file by `llama-server` (`ggufRssKb`). In a VM, `findmnt -t erofs`
shows the mount: with direct access it has `dax=always`, with cached access
`dax=never` on a loop device.

### mlc and the frequencies (latency variant, Intel host)

`mlc` measures the idle latency. Run it as root, by its path (`sudo` may not
have it in its `PATH`); CPU 0 to the memory of a NUMA node of socket 1 (`N`
here; `numactl -H` shows which nodes are on which socket):

```bash
sudo "$(command -v mlc)" --idle_latency -c0 -jN
sudo "$(command -v mlc)" --latency_matrix
```

The frequencies of the uncore dies, and the caps (`max_freq_khz`), are in
sysfs; `demo latency status` lists them, or read them yourself:

```bash
sudo bash -c 'for d in /sys/devices/system/cpu/intel_uncore_frequency/uncore*; do
    echo "$(basename $d) package $(cat $d/package_id) max $(cat $d/max_freq_khz) now $(cat $d/current_freq_khz) kHz"; done'
```

With a build of Intel PCM, `sudo env PATH=/path/to/pcm/build/bin:$PATH bash
/path/to/pcm/scripts/ufs-die-stat.sh` prints the uncore frequency per die
and says which dies are compute and which are IO. While the demo runs with
the far setup, the four domains of socket 1 read their minimum frequency, and
the domains of socket 0 follow the load.

## Read the results

Each benchmark (steps M7, M8, M12, M13) prints a line per reader, for
example:

```text
reader-0 TTFT <ms> (<min>-<max>) TPOT <ms> <tok/s> tok/s
```

This is the median, and the range of the samples in brackets. TTFT is the
time from sending the request to the first streamed piece of the answer.
TPOT is the server's time per predicted token for an answer with a tool
call (the tool-call parser streams the answer in few pieces, so the
client cannot time single tokens), and the client's own
(last piece minus first piece) / (tokens - 1) for a plain text answer.
The answer here is a tool call of about 40 tokens.

`demo llm results` merges all the saved benchmarks of `run/llm-results/`
into one table:

```text
model       latency  huge         2M    access  mode    reader    TTFT ms  prompt ms  TPOT ms  tok/s  failed
qwen3.5-2b  off      within_size  100%  direct  single  reader-0  ...      ...        ...      ...    0
...
```

`latency` is the latency setup of that run: `off`, `local`, `far`, or
`far+700` for the far setup with the background load 700 (a result that an
older version saved as `on` shows as `far`). `huge` is the `huge=`
option of the pool tmpfs and `2M` is the share of `llm0` that the qemus map
in 2 MiB pages. Every saved result also has the output of `demo latency
status` of that moment, in the JSON file.

### The results of the four setups

The Xeon 6 server, Qwen3.5-2B, three readers, one setup and two `--auto`
runs for each of the setups `off`, `local`, `far` and `far` with the load
700. No request failed, and `llm0` was in 2 MiB pages for 100% in every
run. Every cell is relative to the baseline, direct access alone in the
`local` setup (1.0): the mean over the medians of the three readers in the
two runs, with the lowest and the highest of those medians in brackets.
Lower is faster.

| latency | access | mode | TTFT | TPOT |
|:--------|:-------|:-----|:-----|:-----|
| off | direct | alone | 1.22 (1.08 - 1.32) | 1.73 (1.68 - 1.79) |
| off | direct | all at once | 1.27 (1.14 - 1.39) | 1.86 (1.84 - 1.88) |
| off | cached | alone | 1.15 (0.98 - 1.27) | 1.51 (1.32 - 1.69) |
| off | cached | all at once | 1.29 (1.04 - 1.44) | 1.38 (1.12 - 1.63) |
| local | direct | alone | 1.00 (0.97 - 1.04) | 1.00 (0.92 - 1.09) |
| local | direct | all at once | 0.95 (0.90 - 1.00) | 0.94 (0.90 - 1.01) |
| local | cached | alone | 0.98 (0.92 - 1.06) | 1.07 (0.99 - 1.17) |
| local | cached | all at once | 0.87 (0.81 - 0.95) | 0.95 (0.90 - 0.99) |
| far | direct | alone | 1.34 (1.28 - 1.38) | 2.03 (1.96 - 2.12) |
| far | direct | all at once | 1.22 (1.21 - 1.23) | 1.99 (1.91 - 2.06) |
| far | cached | alone | 1.00 (0.93 - 1.05) | 1.05 (0.98 - 1.13) |
| far | cached | all at once | 0.93 (0.84 - 0.98) | 0.95 (0.94 - 0.96) |
| far, load 700 | direct | alone | 1.78 (1.74 - 1.80) | 3.61 (3.57 - 3.70) |
| far, load 700 | direct | all at once | 1.50 (1.47 - 1.52) | 3.26 (3.25 - 3.27) |
| far, load 700 | cached | alone | 0.94 (0.87 - 1.04) | 0.98 (0.86 - 1.03) |
| far, load 700 | cached | all at once | 0.89 (0.82 - 0.96) | 0.96 (0.91 - 0.98) |

The same data as the TPOT of direct access divided by the TPOT of cached
access (1.0: no gap):

| latency | alone | all at once |
|:--------|:------|:------------|
| off | 1.15 | 1.35 |
| local | 0.93 | 1.00 |
| far | 1.94 | 2.10 |
| far, load 700 | 3.70 | 3.41 |

### How close direct gets to cached

In the `local` setup direct access gets all the way: it is neither slower
nor faster than cached access beyond the spread between runs. The ratio
was 0.93 alone and 1.00 at once; a repetition of the `local` setup gave
1.01 and 0.96. TTFT agrees too. The gap in the other setups is therefore
about where the memory is, not about how the reader gets at it:

- In `far` the direct readers are about twice as slow and with the load
  3.3 to 3.6 times, and the cached readers do not move: their copy is in
  the RAM of the VM, on socket 0.
- In `off` both accesses are 1.4 to 1.9 times slower than in `local`. The
  VMs are not pinned, and about half of the model is on the other socket
  for the direct readers.

Why nothing is left in `local`, from the memory facts of the runs:

- Direct: the guest maps the file of the device with 2 MiB page table
  entries (the VM's `FilePmdMapped` is the size of the gguf), and the host
  backs the device with 2 MiB tmpfs pages, 50% on each of the two nodes of
  socket 0.
- Cached: the loop device reads the file once into the page cache of the
  guest, and `llama-server` maps those pages with 4 KiB entries
  (`FilePmdMapped` is 0). The copy is in guest RAM, which the setup moved
  to the nodes of socket 0 and which the host backs largely with 2 MiB
  pages.
- Both read the DRAM of socket 0 through huge pages of the host. The page
  size differs at the guest level only, and it costs little: the CPUs'
  page-walk counters show a walk active in about 5% of the cycles with
  direct access and 5 to 6% with cached access (3 to 4% in the steps with
  all three readers). A decode step streams the whole model, and streaming
  hides most translation misses.
- What is left is outside the speed: the cached copy costs RAM in every VM
  and a read of the file through the loop device when the readers start,
  see [What 2.3 shows](#what-23-shows-the-cost-of-a-page-cache).

Half of the device's pages in `local` are on the other sub-NUMA node of
the socket, with a latency about 25% higher than the node of the CPU; it
did not show. A host without sub-NUMA clustering has one node per socket.

### What the other runs showed

The numbers differ between hosts and between runs, so compare the setups
of one host. Earlier runs, also with other hosts and the load level 1000,
showed this:

- On the Xeon 6 server, with no background traffic, the 2B model kept a
  usable decode speed in every setup, and three readers at once were not
  slower than one alone (the server has cores for all of them). On the
  second server the direct readers were about 2.2 times slower at once with
  the file on one node, 1.3 times with the pool directory spread over its
  four nodes, and 1.4 times in a later run, so your host may differ. With
  the far setup and no frequency caps the same server needed 2.5 times as
  long at once: the three readers wanted the one model from the two far nodes
  through the socket link.
- With the background traffic the direct access is slow: about 1.7 times as
  slow as with the caps only at level 700, and 1.9 times at level 1000. The
  level 1000 is only about 10% slower than the level 700, although its
  latency is half as large again. The cached access does not change,
  because it reads its own copy in the memory of the VM. The two direct
  readers at once are a little faster than one alone with the load, the
  other way round than on the second server. The smaller models were not
  run with the load.
- With latency off the readers differ (reader-1 was faster in both runs).
  Nothing is pinned, so the numbers depend on how the host places the VMs;
  the exact cause was not found. This is the host as the e2e framework
  leaves it, not a tuned host.
- With the far setup the readers agree much better (the direct readers
  within 5% of each other), because all three VMs are on the same CPUs of
  socket 0. So "off" and "far" differ in pinning and in memory placement,
  not only in the speed of the far memory; the `local` setup separates the
  two.
- The numbers are from one model and a few runs. Use them to see the
  direction, not as a benchmark.

The memory facts were the same in every run: 1228 MiB of `llm0.raw` in host
memory once, in 2 MiB pages, `Pss` 409 MiB for each qemu, page cache
charged to the readers 0 MiB with direct access and 1222 MiB each with
cached access. On the second server `llm0.raw` was spread 25% on each of
its four nodes with latency off (306-308 MiB each), and with the far setup it
was on the two far nodes (1222 and 6 MiB).

### What 2.1 shows: one copy in host memory

After step M9 (direct access), on the Xeon 6 server:

- the device file `llm0.raw` is 1536 MiB, of which 1228 MiB are in host
  memory, **once**, in 2 MiB pages;
- each of the three qemus maps all 1228 MiB (`Rss` 1228 MiB), but `Pss` is
  409 MiB, a third: the pages are the same. The three `Pss` values add up
  to the one copy;
- the page cache charged to the readers is 0 MiB, and the `Cached` of the
  VMs did not grow: `llama-server` maps the file from the device, and each
  reader maps about 1211 MiB of the gguf.

So the model is in host memory once, however many VMs read it, and in no
page cache.

### What 2.3 shows: the cost of a page cache

After step M14 (cached access), since M9:

- every reader is charged 1222 MiB of page cache, and the `Cached` of
  every VM grew by about the same: 3 x 1222 = 3666 MiB of guest memory;
- the device file stays in host memory too (the VMs read it once, through
  a loop device). In total the model costs 1228 + 3 x 1222 = 4894 MiB
  with cached access, against 1228 MiB with direct access;
- the host sees the cost in the private memory of the qemus (`RssAnon`),
  but only where the guest touched memory that the host had not backed
  yet: +1.2 GiB on a fresh VM, almost nothing on a VM that has run a
  while;
- the cache is reclaimable: `MemAvailable` stayed near 7 GiB of 8 GiB, and
  the pages reclaimed (`pgsteal`) rose by about 16 to 19 MiB on VM2 only. The
  model did not push other cached data out in these runs;
- speed: with the far setup, cached access is about twice as fast as direct
  access, because the VM reads the copy from its own near memory instead
  of from the far socket. With latency off there is no clear difference.

## Tear down

```bash
demo teardown
```

It deletes the pods, unconfigures and detaches the device, checks that no file system, bind mount or loop device over the
device is left in the VMs (if one is, it stops with a WARNING and tells you
the manual cleanup; run it again after that), uninstalls the driver and
the controller, stops the pool server and the model mirror, removes the
device files, labels and tools, runs `latency.sh off`, and unmounts the pool
tmpfs. The VMs stay up, clean, and the images stay in them. The results in
`run/llm-results/` stay.

**qemu keeps the last detached device mapped.** After a device is detached,
qemu keeps its memory backend mapped until the next change of memory in that
VM, or until the VM restarts. The mapping shows as `/llm0.raw (deleted)` in
`/proc/<qemu pid>/maps`. On a tmpfs the pages of that file stay allocated
as long as any qemu maps them: about 1.2 GiB for the 2B model, counted once
because all the qemus map the same pages. So teardown unmounts the tmpfs
lazily and says

```text
tmpfs unmounted lazily, processes ... still map removed files of it
```

The memory comes back when a later device is attached to that VM (the next
demo does it at steps M2 and M5), or when you restart the VMs. To restart a VM, run
`vagrant halt` in its output directory, **wait until `vagrant status` says
`stopped`**, and then run `vagrant up --no-provision`; do the workers first,
then VM2, and wait until the nodes are `Ready` again:

```bash
cd "$N/test/e2e/n4-cxl-shared-0-fedora-43-containerd"
vagrant halt
until vagrant status | grep -q 'stopped (qemu)'; do sleep 2; done
vagrant up --no-provision
```

`vagrant halt` returns before the qemu has exited. If you run `vagrant up`
at once, vagrant still sees a running VM, does nothing ("Machine not
provisioned because `--no-provision` is specified") and the VM is then
stopped when the qemu exits: this happened on the second server with
`vagrant halt; vagrant up --no-provision` (all three VMs ended `stopped`).
On the Xeon 6 server the `Shmem` line of `/proc/meminfo` went from 1271 MB
to 14 MB when the last of the three qemus had gone (not before: the three
share the pages); on the second server it fell by the 1.2 GB of the model.
After the restart the three qemus had `THP_enabled: 1` again.

To remove the VMs altogether, run `vagrant destroy -f` in the output
directory of each and delete the directories. `destroy` returns before the
qemu has exited, which took a while for VM2 on the second server: wait
until `pgrep -f <the directory of the VM>` finds
nothing before you create the VM again. Keep `~/.cache/nri-plugins/e2e` and
`~/.vagrant.d/boxes`: they save the downloads and the kernel build of the next
set of VMs ([What the caches save](#what-the-caches-save)).

## Troubleshooting

- **`demo setup` says there is no image of the driver:** build it
  ([Build the images](#build-the-images)).
- **`run_tests.sh runs already`:** another e2e run is going. The VMs serve
  one run at a time. Wait, or find it with `pgrep -a run_tests.sh`.
- **Port 9909 or 9920 is busy:** an earlier pool server or model mirror
  runs: `ss -ltnp | grep -E ':(9909|9920) '`. Run `demo teardown`.
- **`apt-get build-dep qemu` says "You must put some 'deb-src' URIs":** turn
  the source repositories on ([Build the QEMU fork](#build-the-qemu-fork)).
- **`demo llm-share` says "cannot understand ...":** the selection of steps
  is `N`, `N-` or `N-M` (one of them), for example `2-5`. The same message
  comes for a typo in a flag.
- **Setup says "docker is needed":** install or start docker on the host.
- **A demo is set up already:** `demo teardown` first. A failed setup
  cleans up after itself; if it did not, `demo teardown` and, if the
  latency variant was on, `demo latency off` finish the job.
- **Setup: cluster is not in shape ("run ...n4-cxl-shared-2/test00-up
  first"):** the three VMs are not one cluster. Run the three `test00-up`
  tests in the order of [Create the three VMs](#create-the-three-vms).
- **Setup fails with "cannot hot-remove CXL memory devices" and
  `power_controller_present`:** the VM runs stock qemu. Create it again
  with `qemu_bin` (`vagrant destroy` in its output directory, remove the
  directory, run `test00-up`), or edit `QEMU_BIN` in its `env` file and
  restart it ([Build the QEMU fork](#build-the-qemu-fork)).
- **"The VM ... was provisioned with other versions":** pin the same
  releases as when you created the VMs, or set `e2e_vm_versions=ignore`.
- **M3 cannot download the model, "SSL certificate problem" or a TLS
  error:** Hugging Face is not reachable through your proxy. Use
  `DEMO_LLM_MODEL_DIR` ([Get the model](#get-the-model)).
- **"DEMO_LLM_MODEL_DIR ... has no ... with sha256 ...":** the file in the
  directory is not the pinned one. Download it again from the URL of the
  pinned commit.
- **A reader stays `Pending`:** `kubectl -n cxl-demo describe pod reader-N`
  gives the scheduler's reason, and `kubectl -n cxl-demo describe
  resourceclaim` the state of its claim. "0/3 nodes are available" means
  that no node matches the pod's claim: check that the node labels exist
  (`kubectl get nodes --show-labels`, look for `cxl-demo/node`) and that
  `demo zoom pool` shows `llm0` and no exclusive attachment (the writer
  must have released it: step M4).
- **A reader is `Running` but not `Ready` for a long time:** `llama-server`
  is loading the model. With cached access this takes a while with the 2B
  model (it reads the file through the loop device). `kubectl -n cxl-demo
  logs reader-N` shows it.
- **Inference is much slower than in the runs above:** the host has too few free
  hardware threads for three VMs of 8 vCPUs, or a big process shares the
  host. A reader runs with 6 threads, the limit of its pod.
- **The `2M` column says 0%:** the qemu of a VM runs with transparent huge
  pages disabled, and the pool memory and the VM memory then use 4 KiB
  pages. It is not an error, but the numbers are not comparable with 2 MiB
  pages. Check with `grep THP_enabled /proc/<qemu pid>/status` (0: off).
  Vagrant's Ruby turns the pages off for itself when the host's setting is
  `always` (`cat /sys/kernel/mm/transparent_hugepage/enabled`), and the
  qemu it starts inherits that. The e2e framework allows them again in the
  `Vagrantfile` of every VM when it runs `test00-up`, so VMs made or
  prepared with this repository start their qemu with `THP_enabled: 1`.
  A qemu that started before that keeps 0 until it restarts: run `test00-up`
  of the VM (it patches the `Vagrantfile`), then restart it (halt, wait for
  `stopped`, `vagrant up --no-provision`; see [Tear down](#tear-down)).
- **Teardown stops with a WARNING about a mount or loop device:** a process
  in a VM still uses the device. Follow the steps it prints; `demo zoom
  mounts vm1` shows the mounts. Run `demo teardown` again.
- **`latency.sh on` refuses:** the message says why. Typical reasons: one
  socket only; `sudo -n true` fails; the pool directory is not empty or is
  a mount point (the demo is set up: tear it down first); the latency is on
  already (`demo latency off`).
- **Memory stays used on the host after teardown:** see the end of
  [Tear down](#tear-down) (qemu keeps the removed device file mapped).
- **A VM has CXL devices left, or the cluster is broken after a failed
  teardown:** run `test00-up` of that VM again; it restarts a VM that has
  CXL devices. Restarting VM2 makes the API server unavailable for a while.
- **A view says "stale":** its ssh or kubectl call failed or took over 4
  seconds; it retries every second. If it stays stale, stop it with Ctrl-C
  and start it again.
- **More:** the section "When something hangs or goes wrong" of the
  presenter's guide
  ([`README.txt`](blob:/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/demo01-share-write-read/README.txt)),
  and the troubleshooting section of [e2e.md](e2e.md#troubleshooting).

## What was not verified

The guide was written from the scripts and from the logs of earlier runs.
Then the steps from "What the host needs" to "Tear down" were followed once as
written on the Xeon 6 server, from VMs created from scratch (the QEMU
build, the images, the three VMs, the model, the demo with latency off and
with the far setup and the load 700, the teardown, the restart of the VMs), and
once on the second server with openSUSE (the same, with the QEMU build that
the host had, the model copied with `cp`, the demo step by step in two
ranges `1-3` and `4-6`, `--auto` with latency off, with the far setup and with
the far setup and the load 700, and the restart of the VMs). Both servers had
their caches. These parts were not run:

- where to get this repository: the guide says "the branch or commit that
  carries this guide" because the branch is not published yet, so the
  clone URL and branch are not given (the clone in the test was made from a
  checkout on the same host);
- a host without the caches: only the download of the box was tried; the
  in-VM kernel build was not, and docker's layers and the Go modules were
  warm; and `build-kernel-rpms.sh` (on another branch);
- hosts other than Ubuntu 24.04 and openSUSE Tumbleweed (the Ubuntu steps
  for the qemu build dependencies were tried in a clean container, not on a
  clean host; the openSUSE step only as far as the dependencies, in a clean
  container, and the qemu build itself on openSUSE not at all), and
  `vagrant plugin install` (the plugins were there already);
- installing the Kubernetes fork into VM2; whether the demo needs it was
  concluded from runs that passed without it, not from a comparison;
- the keys `z` and `q` of the step-by-step mode, and the live views T2 to
  T6 (Enter and `s` were tried, and a step stopped in the middle);
- the host sizes (memory, threads, disk): estimates, and the demo was run
  on hosts with 256 hardware threads only;
- `MLC` and `PCM_TPMI` set to a path (the tools were found in PATH);
  building `mlc`/`pcm`;
- the latency variant on hosts other than the two servers (the frequency
  controls were "not available" on the second server, and `mlc` was not
  installed there, so its latency was not measured), and the `local` setup
  on a host with one socket;
- the restart of a VM with the wait for `stopped` on more than one VM (the
  second server tried it on VM0 only; the version without the wait failed
  for all three);
- the background traffic (`DEMO_LLM_LATENCY_LOAD`) on a host other than the
  Xeon 6 server, with the smaller models, and the `mlc` numbers while one
  benchmark step runs (the probes ran during several steps, not one);
- the results are from a few runs of one model per host: a trend, not a
  benchmark.
