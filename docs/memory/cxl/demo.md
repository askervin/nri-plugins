# The CXL demo

CAUTION: experimental. The demo runs on emulated hardware only: qemu VMs
and a fake memory pool.

The demo shows CXL memory sharing live, in the cluster of the e2e suite.
A container asks for CXL memory while it runs, and the scheduler gives
it a share of a device only when the rules allow. The node maps the
device into the container, every sharer sees the same bytes, and readers
cannot write. It needs this repository and no CXL hardware. This page tells how
to prepare a host, how to run each story of the demo in front of an
audience, and how to read the results of its language model story.

- [The stories](#the-stories)
- [What runs where](#what-runs-where)
- [Preparation](#preparation)
- [The presenter's screen](#the-presenters-screen)
- [Setup and teardown](#setup-and-teardown)
- [local and pool](#local-and-pool)
- [pool-shared-fs](#pool-shared-fs)
- [pool-fs](#pool-fs)
- [The wizard](#the-wizard)
- [llm-share](#llm-share)
- [The latency variant](#the-latency-variant)
- [Look inside](#look-inside)
- [Read the results](#read-the-results)
- [Troubleshooting](#troubleshooting)
- [The demo directory](#the-demo-directory)

## The stories

Five scripts tell the story, each with one writer and readers, and a
wizard shows the rest:

| story | what it shows |
|:------|:--------------|
| `local` | four pods on VM2 share VM2's own CXL memory device (`sharedMemdevs`): a writer that has it alone, then three read-only readers |
| `pool` | the same with the shared pool device `shared0`: the writer on VM1, readers on VM2 and VM1; the device is hot-plugged into the nodes as needed |
| `pool-shared-fs` | `shared0` persistent: the writer puts an erofs with `hello.txt` on it as a block device, the readers get the filesystem mounted into their running containers |
| `pool-fs` | the persistent `fs0`: the writer makes an ext4 (or xfs, btrfs) and mounts it read-write; the reader of its node shares it at once, the readers of the other node wait until the writer leaves (ReadWriteOnce) |
| `wizard` | every kind of device that the driver offers, any claim or lease of it that the driver accepts, its YAML, created and deleted |
| `llm-share` | a language model on the persistent pool device `llm0` for all three VMs: a writer stores an erofs of it, one llama.cpp server per VM serves it, a client measures the time to the first token and per token, alone and all at once |

`llm-share` answers three questions:

- Is the model in the host memory only once? With direct access (DAX) it
  is: all three VMs map the same pages of one file on the host.
- What changes when the pool memory is slower, like real CXL memory? On
  a host with two sockets the [latency variant](#the-latency-variant)
  puts the VMs on socket 0 and the device on socket 1.
- Does a page cache in each VM make inference faster, and what does it
  cost? The readers with cached access show it.

## What runs where

Everything except the pool "hardware" runs in containers, as in a
cluster with a pool appliance:

| part | where it runs |
|:-----|:--------------|
| the pool server, `fake-cxl-pool-server`: the pool hardware | a process on the host |
| the three VMs | qemu processes on the host |
| Kubernetes | in the VMs: VM2 is the control plane, VM0 and VM1 are workers |
| `nri-dra-driver-cxl` | a DaemonSet pod on every node |
| the pool controller, `fake-cxl-pool-controller` | a Deployment pod, namespace `fake-cxl-pool` |
| writers, readers, the client | pods, namespace `cxl-demo` |
| the model mirror (only if you ask for one) | a Python web server on the host, standing for a model registry outside the cluster |
| the latency setup, the views of host memory | the host |

A pool device is a file on the host, which every qemu that attaches the
device maps (`share=on`): all VMs map the same file. The filesystem, the
driver and the pods do not know that the hardware is fake. The pool of
the scripts is cabled to VM1 and VM2; that of `llm-share` to all three
VMs.

## Preparation

### The host

The demo ran on two-socket x86 servers with several NUMA nodes per
socket. The sizes below are estimates from what the VMs use; smaller
hosts were not tried.

| need | |
|:-----|:-|
| a 64-bit x86 Linux host with KVM | `test -r /dev/kvm -a -w /dev/kvm && echo ok` |
| memory | 32 GiB or more: three VMs of 8 GiB, the model, the page cache of the host |
| hardware threads | 24 or more: three VMs of 8 vCPUs; a reader uses 6 threads, and fewer threads make the "all at once" runs worse |
| disk | 100 GiB free: the sparse disks of the VMs, the images, the kernel cache |
| tools | what the e2e suite needs ([e2e.md](e2e.md#requirements)): vagrant with the plugins `vagrant-qemu`, `vagrant-proxyconf` and `dotenv`, ansible with `ansible.posix`, docker usable without sudo, go, python3, git, make, rsync, curl, ssh, `qemu-img` |
| sudo without a password | to mount the tmpfs of the pool memory (setup falls back to `/dev/shm` without it), and for the latency variant |

The qemu, the guest kernel and the three VMs are those of the e2e suite:
[e2e.md](e2e.md#the-e2e-setup) tells their requirements and how to
create them. Pin the releases of the VMs in every shell that runs the
e2e framework, for the three `test00-up` runs and for `demo setup`,
`demo llm-share --auto` and `demo teardown`:

```bash
export k8s_release=1.37.2 helm_release=4.3.1 containerd_release=2.4.2
```

A VM that was created with other versions is refused unless
`e2e_vm_versions=ignore` is set. The model comes from huggingface.co,
the llama.cpp image from ghcr.io; with a proxy, set `http_proxy`,
`https_proxy` and `no_proxy` for the e2e framework and the proxy of
docker in `~/.docker/config.json`. Keep `~/.cache/nri-plugins/e2e` and
`~/.vagrant.d/boxes`: they save the downloads and the kernel build.

### Images and the demo command

```bash
make PLUGINS=nri-dra-driver-cxl OTHER_IMAGE_TARGETS= BINARIES= images
make -C scripts/testing/fake-cxl-pool
```

The first builds the image of the driver, which `demo setup` imports into
the VMs (the newest one); the second the pool binaries, `cxl-numa-place`
and the load program `cxl-load`. Setup builds the rest itself: the image
of the pool controller, the demo image `localhost/cxl-demo-tools`
(Python on Alpine with erofs-utils, e2fsprogs, xfsprogs and btrfs-progs,
from the `image/Dockerfile` of the demo directory), and the VMs pull the
llama.cpp image.

The demo directory is
[`test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/demo01-share-write-read`](tree:/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/demo01-share-write-read),
and `bin/demo` in it is the entry point:

```bash
export N=/path/to/nri-plugins
export D01=$N/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/demo01-share-write-read
demo() { "$D01"/bin/demo "$@"; }
demo selftest
```

`demo selftest` needs no VM. It renders every view from recorded samples
and checks that it fits a terminal of 50 x 10, and runs the wizard's
checks. It also runs the host scripts (`pool-tmpfs.sh`, `latency.sh`) against stubs
of `sudo`, `mount` and `taskset` and a fake `/sys`.

### The model

`llm-share` uses Qwen3.5-2B in 4-bit form (`Q4_K_M`) from the unsloth
repository on Hugging Face by default: a small model with native tool
calling, under the Apache-2.0 licence. Setup pins each model by the
commit of its repository and checks its sha256:

| `DEMO_LLM_MODEL` | file | size | `llm0` |
|:-----------------|:-----|:-----|:-------|
| `qwen3.5-2b` (default) | `Qwen3.5-2B-Q4_K_M.gguf` | 1221 MiB | 1536Mi |
| `qwen3.5-0.8b` | `Qwen3.5-0.8B-Q4_K_M.gguf` | 508 MiB | 768Mi |
| `qwen3-0.6b` | `Qwen3-0.6B-Q4_K_M.gguf` | 378 MiB | 512Mi |

Where the VMs reach huggingface.co, the writer downloads the model at
step M3. Where they do not (behind a proxy that intercepts TLS, for
instance), download the file on any machine, check it, and give its
directory to setup:

```bash
mkdir -p ~/llm-models && cd ~/llm-models
curl -LO https://huggingface.co/unsloth/Qwen3.5-2B-GGUF/resolve/f6d5376be1edb4d416d56da11e5397a961aca8ae/Qwen3.5-2B-Q4_K_M.gguf
echo "aaf42c8b7c3cab2bf3d69c355048d4a0ee9973d48f16c731c0520ee914699223  Qwen3.5-2B-Q4_K_M.gguf" | sha256sum -c
export DEMO_LLM_MODEL_DIR=$HOME/llm-models
```

Setup then serves the directory to the writer from the host (port 9920,
`http://192.168.76.2:9920` for the VMs). The URLs, commits and sums of
the other models are in `LLM_MODELS` of
[`test98-demo-setup/code.var.sh`](blob:/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test98-demo-setup/code.var.sh).
`DEMO_LLM_MODEL_URL` points the writer at a mirror of your own.

## The presenter's screen

Six terminals of 50 columns x 10 rows, in two columns of three:

```
  +---------- T1 ----------+  +---------- T2 ----------+
  | PRESENTER: the steps   |  | PODS & LEASES          |
  +---------- T3 ----------+  +---------- T4 ----------+
  | SCHEDULER: devices and |  | NODES: CXL in the      |
  | claims                 |  | kernel of each node    |
  +---------- T5 ----------+  +---------- T6 ----------+
  | TRACE: one line per    |  | MEMORY (local), POOL   |
  | event                  |  | server (pool)          |
  +------------------------+  +------------------------+
```

T1 runs the story (`demo local`, `demo pool`, ..., `demo llm-share`), T2
to T6 run
`demo view t2` to `demo view t6`; `demo commands` prints them all. The
views refresh once a second, show the clock in their title, and say
"stale" when a refresh fails (the last good picture stays). T5 scrolls:
one line per event, and one line for a teardown or a new setup. Colors:
green Ready or allocated, yellow waiting, red refused; `--no-color` (or
`NO_COLOR=1`) turns them off. Read the right column from the application
down to the memory (T2, T4, T6), the left one from the action down to
why (T1, T3, T5). On a small screen use T1 to T4 and zoom the rest.

Each step of T1 shows its caption and the real command, which runs in
VM2 in `/root/demo` with the demo namespace `cxl-demo`:

| key | |
|:----|:-|
| Enter | run the step |
| `s` | skip it |
| `z` | zoom: a detail view, for example `claim reader-a` ([Look inside](#look-inside)) |
| `q` | stop |

After the command the step shows a one to four line result and the time
it took; the command is never hidden, and the full output is in
`run/steps.log` (`demo zoom last`). `demo local 6` runs step 6 alone,
`demo local 6-` from step 6 on, `demo local 2-5` a range. `--auto` runs
all steps with a pause between them (`DEMO_AUTO_PAUSE`), for a
rehearsal, and appends the timings of the steps to `run/timings.txt`.

## Setup and teardown

```bash
demo setup local      # or pool, pool-shared-fs, pool-fs [ext4|xfs|btrfs], wizard, llm-share
demo teardown
demo reset local      # deletes the demo pods and their leases: start from step 1 again
```

One demo at a time: to switch, tear down and set up the next. Setup is
the test `test98-demo-setup` of the suite (which a run of the suite
skips), run through `run_tests.sh`; it refuses to start while another
`run_tests.sh` runs. Its log is `run/test98-demo-setup.log`, and
`run/state.env` says what runs. It

- checks the shape of the cluster;
- starts `fake-cxl-pool-server` on the host with the devices of the
  story (`local`: VM2's local device; `pool`: `shared0`;
  `pool-shared-fs`: `shared0` persistent and empty; `pool-fs`: `fs0`
  persistent and empty; `wizard`: the devices of [the wizard](#the-wizard);
  `llm-share`: `llm0` on a tmpfs of its own);
- installs the driver on every node with helm: for `local` with VM2's
  device in `sharedMemdevs`, for `pool-fs` with
  `fsTypes: [erofs, <type>]`, for `wizard` with
  `fsTypes: [erofs, ext4, xfs, btrfs]`;
- installs the pool controller as a Deployment, its image built with
  docker and imported into every node;
- imports the demo image where the story needs it, creates the ConfigMap
  `demo-tools` (`/demo/write`, `/demo/read`, `/demo/hold`, `/demo/mkfs`,
  `/demo/fswrite`, ... in the pods), copies the manifests to `/root/demo`
  in VM2, labels the nodes `cxl-demo/node=vm0|vm1|vm2`, and starts the
  trace.

For `pool-fs` and the wizard setup prints the trust note of
[persistent.md](persistent.md#filesystems): a node that mounts ext4,
xfs or btrfs trusts every party that can write the device raw. A failed
setup cleans up after itself. The output ends with lines that look like
errors and are not (`curl: (7) Failed to connect to localhost port
8891`, `no coverage data ...`): what counts is `Test verdict: PASS`.

Teardown unconfigures VM2's shared device first, then removes the rest,
and checks that no VM has CXL memory devices left. Before it detaches a
pool device it checks that no filesystem mount, lease bind or loop
device over pmem is left in the VMs. If one is, it stops with a WARNING
and the manual cleanup, and `demo teardown` again goes on from there. It
removes the files of the persistent devices. qemu keeps the backing file
of a detached device mapped until the next memory change of the VM or
its restart. On a tmpfs that memory stays allocated, so teardown
unmounts the pool tmpfs lazily
(`tmpfs unmounted lazily, processes ... still map removed files of it`).
To get the memory back, restart the VMs: `vagrant halt` in the output
directory of each, wait until `vagrant status` says `stopped`, then
`vagrant up --no-provision`; the workers first, then VM2.

## local and pool

`local` has nine steps, L1 to L9, with S the serial of VM2's device
(`0xc100e2e1`):

| step | command | point at |
|:-----|:--------|:---------|
| L1 a writer starts on VM2 | `kubectl apply -f local/writer.yaml` | T2 the writer Running, no lease; T3 the device `1Gi shared`, no claims; T6 the bytes there |
| L2 the writer asks for the whole device | `kubectl exec writer -- cxl-request request --serial S --mode dax` | T2 `dax rw excl`; T3 `exclusive: writer rw`; T4 region0, dax0.0 on `device_dax`; T5 the lease, its allocation, the region, the zeroing once, Ready; T6 zeros |
| L3 the writer writes a line | `kubectl exec writer -- /demo/write "Hello ..."` | T6 the line; T4 `mapped: writer rw` while it writes |
| L4 three readers start | `kubectl apply -f local/readers.yaml` | T2 reader-a to reader-c Running |
| L5 the readers ask for a read-only share | `cxl-request request --serial S --share --read-only --wait 0s` in each | T2 three `waiting`; T3 `waiting: reader-a reader-b reader-c`; T5 `cannot allocate`. Pause: the writer has the device alone, nothing moves |
| L6 the writer releases the device | `kubectl exec writer -- cxl-request release --all` | T3 `shared: reader-a ro, ...`; T2 three `dax ro share`; T4 dax0.0 stays; T6 the line stays |
| L7 each reader reads the line and keeps it mapped | `/demo/read`, `/demo/hold` in each | T1 `3 readers read at 0: ...`; T4 `mapped: reader-a ro, ...`, the kernel's own record |
| L8 a reader tries to write | `kubectl exec reader-a -- /demo/write "overwrite"` | T1 `refused: read-only (EACCES)`: the fd of a read-only lease allows no writable mapping, whatever the privileges of the container |
| L9 everything goes away | `kubectl delete -f local/` | T3 no claims; T4 region0 and dax0.0 stay; T6 the bytes stay: the next writer finds them |

Say at L2: the lease became a claim (its companion), the scheduler
allocated it like any claim, and the node made the device. A shared
local memdev keeps its region and bytes while it is configured shared,
so a run before a teardown finds the line of the last one.

`pool` has the same nine steps with the `pool/` manifests and
`S = 0xc1ae0001` (`shared0`, 256Mi): the writer on VM1, reader-a and
reader-b on VM2, reader-c on VM1. T6 is the pool server: the device,
where it is attached, and its bytes as the backing file on the host
holds them. What is new:

- L2: the device is hot-plugged into VM1 (T6 `attached: vm1 single-host`,
  T4 mem0 with its region on VM1), and the lease is Ready after the
  attach: the scheduler waits for it.
- L3: T6 shows the line from the host's side: the bytes are in the pool.
- L6: `shared0` stays on VM1, now shared, and is attached to VM2 too; the
  readers whose node does not have it yet show `attaching`. T5 has the
  release of the writer's memdev on VM1 and its bind again for reader-c.
- L9: the drivers release the device (`disabled, no region` in T4), then
  the pool detaches it from both nodes; the bytes stay in the pool.

## pool-shared-fs

The pool story once more, with a filesystem instead of bytes at offset
0. The writer gets `shared0` as a block device (an fd of `/dev/pmem0`,
no device node), makes an erofs with `hello.txt` and writes it into the
device. The readers find it mounted at `/run/cxl/fs/hello` in their
running containers. `S = 0xc1ae0001`, the writer on VM1, reader-a and
reader-b on VM2, reader-c on VM1. The steps are F1 to F9:

| step | command | point at |
|:-----|:--------|:---------|
| F1 a writer starts on VM1 | `kubectl apply -f pool-shared-fs/writer.yaml` | T3 `shared0 @pool 256Mi shared persistent`; T6 `no file system (zeros)` |
| F2 the writer asks for a block device | `cxl-request request --serial S --mode block` | T1 `block /dev/pmem0`; T4 the pmem region and `pmem0 ... (block rw)`; T5 the attach, the region and namespace, Ready |
| F3 the writer makes an erofs with hello.txt | `/demo/mkfs "Hello ..."` | T4 `pmem0 ... erofs`; T6 `erofs: hello.txt` and its text, read from the backing file on the host |
| F4 three readers start | `kubectl apply -f pool-shared-fs/readers.yaml` | |
| F5 the readers ask for the filesystem | `cxl-request request --serial S --share --read-only --mode fs --name hello --wait 0s` in each | T2 three `waiting`: the writer has the device alone. Zoom `claim reader-a`: class `cxl-pool-persistent`, shares `1`, mode `fs`, read-only |
| F6 the writer releases the device | `cxl-request release --all` | T2 three `fs ro share`; T4 on both nodes `erofs (block ro)` and the readers that have it mounted (dax); T5 the node mounts and the binds |
| F7 each reader reads hello.txt | `cat /run/cxl/fs/hello/hello.txt` in each | T1 `3 readers read: ...` |
| F8 a reader tries to write | `sh -c 'echo overwrite > /run/cxl/fs/hello/hello.txt'` | T1 `Read-only file system` |
| F9 everything goes away | `kubectl delete -f pool-shared-fs/` | T4 no CXL memory; T6 the erofs stays in the pool for the next reader |

Say at F3: `mkfs.erofs` writes a file in the container, and the tool
copies it through the fd: `/proc/self/fd/3` cannot be opened again, and
`/run/cxl` of the container is read-only. The block device starts 2 MiB
into the device, after the pfn info block of the namespace
(`demo zoom fs` says where). Say at F6: each node mounted the erofs once
with `dax=always`, so the pages of `hello.txt` are the memory of the
device, and bound it into the running containers. A reader that still
has a file of the mount open keeps its lease releasing at F9 (T5
`unmount busy, retry`) until the file is closed.

## pool-fs

Any filesystem, read-write: the writer formats `fs0` (512Mi) with ext4
(`demo setup pool-fs xfs` or `btrfs` for the others) through a block
lease, then mounts it read-write through an `fs` lease and writes
`hello.txt`. A reader on the writer's node shares its superblock at once;
the readers of the other node wait while the writer writes: a
single-host filesystem written on one host and read on another corrupts
or misleads. When the writer leaves, its node makes the filesystem
read-only, and the other node mounts it. `S = 0xc1ae0001`, the nodes as
in pool-shared-fs, and the filesystem at `/run/cxl/fs/data`. T2 labels the writer's lease `fs rw (vm1 only)`: it
is one share of `fs0`, and the pool attaches `fs0` to VM1 alone while it
writes.

| step | command | point at |
|:-----|:--------|:---------|
| R1 a writer starts on VM1 | `kubectl apply -f pool-fs/writer.yaml` | T6 `no file system (zeros)` |
| R2 the writer asks for a block device | `cxl-request request --serial S --mode block` | as F2 |
| R3 the writer makes an empty ext4 | `/demo/mkfs --type ext4` | T4 `pmem0 ... ext4 (block rw)`; T6 `ext4 "demo" ..., clean`, read from the backing file |
| R4 the writer mounts it read-write instead | `cxl-request release --all && cxl-request request --serial S --share --mode fs --read-only=false --name data` | T1 `attached to vm1 only (ReadWriteOnce)`; T4 `node mount ext4 rw (dax)`; T5 the single-host attach; T6 `needs recovery`: the journal is in use while a node has it read-write |
| R5 the writer writes hello.txt | `/demo/fswrite "Hello ..."` | T1 the line |
| R6 three readers start | `kubectl apply -f pool-fs/readers.yaml` | |
| R7 the readers ask to read | `cxl-request request --serial S --share --mode fs --name data --wait 0s` in each | T1 reader-c Ready on VM1 next to the writer, reader-a and reader-b `waiting: Conflict`; T4 one superblock on VM1, reader-c's bind read-only. Pause: nothing reaches VM2 while VM1 writes |
| R8 the writer adds a line; VM1's reader sees it at once | `/demo/fswrite --append "..."`, then `cat` in reader-c | T1 the new line: one node, one superblock |
| R9 the writer is done | `cxl-request release --all` | T1 `vm1: ext4 read-only, pmem0 read-only`, the readers of VM2 Ready; T4 both nodes `ext4 (block ro)`; T6 `clean` |
| R10 each reader reads hello.txt; a write fails | `cat` in each, then `echo x >> ...` | T1 the same two lines in all three, `Read-only file system` |
| R11 everything goes away | `kubectl delete -f pool-fs/` | T6 the ext4 stays for the next run |

Say at R3: `mkfs.ext4` makes an image file of the block device's size in
the container, and the tool writes all of it through the fd of the
lease. Say at R9: the writer's release synced the ext4 and made it
read-only on VM1, block device too, before the controller let another
host in; VM2 reads what VM1 wrote. With xfs it goes the same; btrfs has
no DAX, so its access is cached, through a loop device.

## The wizard

`demo wizard` asks a few questions that choose a pod and its claim, or a
lease, among the combinations that the driver accepts, shows the YAML,
creates it in the demo namespace and deletes it again. Each question
lists its choices numbered, the default marked `*`, and the choices that
the driver refuses with the reason. Then it shows the request in words,
the warnings (the pod will wait, and why), the same as a command line,
and "Enter create, y the YAML, q quit". `demo setup wizard` makes every kind
of device:

- the local memdevs of VM2 (1Gi) and VM1 (256Mi), both with the serial
  `0xc100e2e1`, so that a claim of that serial gets the memdev of its
  pod's node;
- `lp0` (`0xc100f5e1`), a persistent local memdev of VM2, through a
  second pool server without a controller;
- in pool A: `pooled0` (unshared), `shared0` (shared) and `fs0`
  (persistent, `0xc1ae0002`).

Setup formats `fs0` and `lp0` with an ext4 holding `hello.txt`, so that
`fs` claims find something. Without questions:

```bash
demo wizard new [OPTIONS] [--dry-run]   # --dry-run prints the YAML
demo wizard list
demo wizard yaml NAME
demo wizard delete NAME...|--all
```

The options follow the questions (`demo wizard new --help`): `--kind
claim|lease`, `--source local|pool|any`, `--memory
volatile|persistent`, `--share[=false]`, `--mode numa|dax|block|fs`,
`--size whole|SIZE`, `--serial any|SERIAL`, `--read-only[=false]`,
`--fs-type`, `--access`, `--path`, `--steering`, `--node vm1|vm2|any`,
`--command idle|env|read|write TEXT|mkfs TYPE` and `--name`. The rules are
the driver's. A choice that the devices cannot satisfy now is taken with
a warning, and the pod waits: that is how waiting is shown. A walk:

```bash
demo wizard new --name w1 --source local --mode numa --size 256Mi --node vm2
demo wizard new --name w12 --source pool --mode dax --serial 0xc1ae0001 --node vm1 --command write "Hello"
demo wizard new --name w13 --kind lease --source pool --share --read-only --serial 0xc1ae0001 --node vm2 --command read
                         # waits: w12 has shared0 alone
demo wizard delete w12   # w13 Ready, its pod's log reads "Hello"
demo wizard new --name w18 --source pool --memory persistent --share --mode fs --read-only=false --serial 0xc1ae0002 --node vm1
demo wizard delete --all
```

Delete an object only after `demo wizard new` has printed that its
command ended: a `mkfs` stopped half way leaves no filesystem.
`bin/wizard-rules.sh` runs every accepted combination on the cluster and
every refused one against the wizard (`--dry-run` at the desk), and
`demo wizard check` runs the wizard's checks.

## llm-share

One copy of a language model in pooled memory for every VM. The writer
on VM1 fetches the GGUF file of the model, makes an erofs of it in its
container (`mkfs.erofs -b4096 --dsunit=512 -Enoinline_data`: one plain,
2 MiB-aligned extent, the condition of DAX) and writes it into `llm0`
through its block lease. Then a reader starts on each VM: stock
llama.cpp, `llama-server -nr` with the model at `/models` from a
read-only `fs` claim of `llm0`, with as many threads as its CPU limit.
A client pod on VM2 asks them the way an agent asks its model, with a
system prompt, a question and one tool, `get_weather`. The question is
"What is the weather like in Helsinki right now, and should I take an
umbrella?", and the model answers with a call of the tool.

- Direct access: each node mounts the erofs with DAX, so `llama-server`
  maps the gguf from the device. Every qemu maps the same backing file,
  so the model is in host memory once, whatever the number of VMs, and
  in no page cache of a VM.
- Cached access: each node mounts the erofs through a read-only loop
  device, so the model is read once into the page cache of each VM, and
  `llama-server` maps that copy.

| step | what happens |
|:-----|:-------------|
| M1 | the writer starts on VM1 |
| M2 | the writer asks for `llm0` as a block device; the pool attaches it to VM1 |
| M3 | the writer fetches the model, checks its sha256, makes the erofs and writes it into the device |
| M4 | the writer releases the device; `llm0` detaches from VM1 |
| M5 | a reader starts on each VM with a read-only share of `llm0`, the first access; the client starts on VM2 |
| M6 | the client asks each reader once; the model calls the tool |
| M7 | benchmark, each reader alone |
| M8 | benchmark, all readers at once |
| M9 | (host) the model is in host memory once: every qemu maps the same pages |
| M10 | the readers start again with the other access |
| M11 to M13 | ask and benchmark again |
| M14 | (host) the memory again, against M9: with cached access a copy of the model in each VM |
| M15 | everything goes away |

The options are environment variables of `demo setup llm-share`:

| variable | default | |
|:---------|:--------|:-|
| `DEMO_LLM_MODEL` | `qwen3.5-2b` | `qwen3.5-2b`, `qwen3.5-0.8b` or `qwen3-0.6b` |
| `DEMO_LLM_MODEL_DIR` | | a host directory with the model file, served to the writer ([The model](#the-model)) |
| `DEMO_LLM_MODEL_URL` | the Hugging Face URL | where the writer fetches the model; wins over `DEMO_LLM_MODEL_DIR` |
| `DEMO_LLM_ACCESS` | `direct` | the first access, `direct` or `cached`; M10 switches to the other one |
| `DEMO_LLM_LATENCY` | `off` | the [latency setup](#the-latency-variant): `off`, `local` or `far` |
| `DEMO_LLM_LATENCY_LOAD` | `off` | with `far`: the level of the background load, `700` or `1000` |
| `DEMO_LLM_REPEAT` | `3` | the requests per reader of a benchmark; also at step time: `DEMO_LLM_REPEAT=5 demo llm-share 7` |
| `DEMO_POOL_DIR` | `/tmp/fake-cxl-pool-llm` | the pool directory, empty or missing |

The pool directory is where the pool server creates the files that are
the memory of its devices. Setup mounts a tmpfs there with
`huge=within_size`, which gives 2 MiB pages where the file is large
enough. It adds `mpol=interleave:<nodes>` over the NUMA nodes of the
host that have both memory and CPUs, which leaves out the memory of a
CXL device or HBM; a host with one such node gets no policy. Without the
policy a page lands on the node of the CPU that first writes it, where
the writer's vCPU happened to run, and the readers all wait on that
node. In one run three direct readers
at once decoded about 1.8 times as slowly with the file on one node as
with it spread over the four nodes of a two-socket host. A node list has
a comma, which mount(8) splits options at, so the mount runs with
`LIBMOUNT_FORCE_MOUNT2=always`. With huge pages the spread is best
effort: a 2 MiB page can fall to the next node of the list
(`demo llm mem` shows the nodes). Without sudo setup uses
`/dev/shm/fake-cxl-pool-llm` (4 KiB pages, no policy).

The framework lets the qemu of each VM use transparent huge pages
whatever the host's setting (`grep THP_enabled /proc/<qemu pid>/status`
says 1), so that the guest RAM and the pool memory can be in 2 MiB pages.

One setup runs both accesses and both modes at the latency setup that it
was set up with, so the whole table takes one setup for each:

```bash
DEMO_LLM_LATENCY=off   demo setup llm-share; demo llm-share --auto; demo teardown
DEMO_LLM_LATENCY=local demo setup llm-share; demo llm-share --auto; demo teardown
DEMO_LLM_LATENCY=far   demo setup llm-share; demo llm-share --auto; demo teardown
demo llm results
```

`run/llm-results/` keeps the benchmarks over teardown, and
`demo llm results` prints them as one table.

## The latency variant

Real CXL memory is slower than the DRAM next to the CPU, and the VMs of
the demo read the pool memory at the speed of host memory. On a host
with two sockets the latency variant puts the device on the other
socket, and can keep that socket's memory busy. `DEMO_LLM_LATENCY`
chooses the setup:

| setup | the VMs | the memory of `llm0` |
|:------|:--------|:---------------------|
| `off` (default) | not pinned | spread over all memory nodes of the host: on two sockets about half of it is on the other socket |
| `local` | pinned to the CPUs of socket 0, their memory moved to its nodes | spread over the nodes of socket 0 |
| `far` | as `local` | on the nodes of socket 1 only, with the background load of `DEMO_LLM_LATENCY_LOAD` if set |

Which runs to compare:

- `local` is the best placement that the host has for the model. Direct
  against cached access within `local` shows what is left of the gap
  between them when the memory distance is as small as it gets.
- `local` against `far` differ in one thing for the VMs: where the device
  memory is. This is the cost of the distance to the device.
- `off` is the host as the e2e framework leaves it, not a local setup:
  `off` against `local` shows the effect of pinning and placement.
- Compare the setups of one host only.

`bin/latency.sh` does the work; `demo setup` runs `latency.sh on` with
the setup after the VMs are reset and before the pool server makes the
device files, and teardown, or a failed setup, runs `latency.sh off`.
`demo latency on [far|local]|off|status|levels` runs it by hand; it
refuses `on` while the demo is set up. It saves every value before it
changes it, in `run/latency.state`:

| what | to |
|:-----|:---|
| automatic NUMA balancing (`kernel.numa_balancing`) | 0 |
| KSM | `run` 2: unmerge and stop |
| memory demotion | off |
| every thread of each demo VM's qemu | pinned to the CPUs of socket 0 |
| the memory of each demo VM's qemu | moved to the nodes of socket 0 |
| the pool directory | a tmpfs with `huge=within_size` and `mpol=bind:<nodes of socket 1>` (`far`) or `mpol=interleave:<nodes of socket 0>` (`local`) |
| the background load (`far` with `DEMO_LLM_LATENCY_LOAD`) | started after the rest |

`off` stops the load and writes every saved value back; an `on` that
fails or gets SIGINT, SIGTERM or SIGHUP does the same for what it had
changed. The memory of the VMs stays where it was moved, and KSM starts
again from zero. It needs two sockets for `far` (socket 0 only for
`local`), each with NUMA nodes that have both CPUs and memory, sudo
without a password, `taskset`, `migratepages` (numactl), `findmnt`,
`mountpoint` and `flock`. On a host with one socket `latency.sh on far`
stops with the reason. VMs that are not part of the demo are never
touched; stop big ones, because they add noise.

The background load keeps the memory of socket 1 busy, so that a read
from socket 0 waits in the queues of its memory controllers, like a read
of a busy CXL link or device. `cxl-load` runs one thread on each CPU of
socket 1, at the lowest priority; each writes, block after block, over a
buffer of its own that is bound to the memory of socket 1. Writes, not
reads: a CPU that writes a line first reads it to own it, and later
writes it back, so the memory channels fill up. The levels:

| level | what each thread does |
|:------|:----------------------|
| `700` | writes a block and waits after each one |
| `1000` | writes as fast as it can |

The levels were set on a two-socket server with sub-NUMA clustering;
on another host they load the memory by what it takes, and
`LATENCY_LOAD_ARGS` gives `cxl-load` other arguments (`cxl-load -h`). It
is a busy memory, not a longer path: it makes reads slow as a busy CXL
device does, without the CXL protocol. `demo latency status` shows the
topology, the settings, the VMs and their memory, the placement of the
device files and the load.

## Look inside

Zooms answer questions; in T1 press `z`, or run `demo zoom WHAT` in any
terminal (`demo zoom help` lists them):

| zoom | |
|:-----|:-|
| `slice [DEVICE]` | the ResourceSlice entry of a device |
| `claim POD` | the companion claim of the lease of POD: request, allocation, configuration |
| `pod POD` | why the lease of POD waits (the scheduler's message) |
| `env POD` | the `CXL_*` variables of the leases of POD |
| `cdi NODE`, `driver NODE [N]`, `kernel NODE`, `cxl NODE` | the CDI specs, the driver's log, the kernel's CXL lines, `cxl list` of the node |
| `pool` | the pool server's devices and attachments |
| `fs` | the filesystem in the pool device's backing file |
| `mounts NODE` | the mounts of the pmem block devices, their read-only flags, loop devices and lease binds |
| `bytes [OFFSET]` | a hex dump of the device |
| `last` | the full output of the last step |

`demo capture LABEL` writes each view once to `captures/`.
`demo truth LABEL` writes the ground truth of the moment to check the
views against: kubectl objects, `cxl list`, dax and pmem devices,
mounts, the mappings and fds of the pod processes, the pool server and
its backing file.

In VM2, the cluster:

```bash
kubectl -n cxl-demo get pods -o wide
kubectl -n cxl-demo get resourceclaims
kubectl get resourceslices
kubectl -n fake-cxl-pool logs -l app.kubernetes.io/name=fake-cxl-pool-controller --tail=20
kubectl -n cxl-demo logs reader-1 --tail=20       # llama-server: the model load, one line per request
```

One inference by hand, with the demo's client or straight to a server:

```bash
kubectl -n cxl-demo exec client -- /demo/llm ask reader-1
ip=$(kubectl -n cxl-demo get pod reader-1 -o jsonpath='{.status.podIP}')
curl -s --noproxy '*' "http://$ip:8080/v1/chat/completions" -H 'Content-Type: application/json' \
    -d '{"messages": [{"role": "user", "content": "Say hello in five words."}], "max_tokens": 32}'
```

On the host, `demo llm mem LABEL` prints where the model is in memory
and saves it to `run/llm-mem-LABEL.json`; M9 and M14 run it. It tells
how much of `llm0.raw` is in host memory, how much of it in 2 MiB pages
and on which NUMA nodes. It tells what each qemu maps (`Rss`, and `Pss`,
which splits shared pages among the qemus that map them), and how much
page cache each reader is charged for in its VM. `cxl-numa-place where /tmp/fake-cxl-pool-llm/llm0.raw`
shows the nodes of the pages of the file, and
`kubectl -n cxl-demo exec reader-0 -- /demo/llm-mem reader-0` the memory
of a reader in one line.

## Read the results

Each benchmark (M7, M8, M12, M13) prints a line per reader:

```text
reader-0 TTFT <ms> (<min>-<max>) TPOT <ms> <tok/s> tok/s
```

the median and the range of the samples. TTFT is the time from sending
the request to the first streamed piece of the answer. TPOT is the time
per predicted token after the first. For an answer with a tool call it
is the server's, because the parser of tool calls streams the answer in
a few pieces. Else it is the client's: (last piece minus first piece) /
(tokens - 1). The answer
is a tool call of a few dozen tokens. `demo llm results` merges the
saved benchmarks into one table with the model, the latency setup
(`off`, `local`, `far` or `far+700`), the `huge=` option of the pool
tmpfs, the share of `llm0` in 2 MiB pages, the access and the mode.

### Four setups on one host

A two-socket x86 server with sub-NUMA clustering, Qwen3.5-2B, three
readers, two `--auto` runs of each setup, `llm0` in 2 MiB pages in every
run, no failed request. Each cell is relative to direct access alone in
the `local` setup (1.0): the mean over the medians of the three readers
in the two runs, with the lowest and highest median in brackets. Lower
is faster.

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

The TPOT of direct access divided by that of cached access (1.0: no
gap):

| latency | alone | all at once |
|:--------|:------|:------------|
| off | 1.15 | 1.35 |
| local | 0.93 | 1.00 |
| far | 1.94 | 2.10 |
| far, load 700 | 3.70 | 3.41 |

In `local` direct access gets all the way: it is neither slower nor
faster than cached access beyond the spread between runs. The gap in the
other setups is about where the memory is, not about how the reader gets
at it. In `far` the direct readers are about twice as slow, and with the
load more than three times, while the cached readers do not move: their
copy is in the RAM of the VM, on socket 0. In `off` both accesses are
slower than in `local`: the VMs are not pinned, and about half of the
model is on the other socket. In `local` both accesses read the DRAM of
socket 0 through huge pages of the host. The page size differs inside
the guest only: 2 MiB entries for the DAX mapping, 4 KiB for the page
cache. A decode step streams the whole model, which hides most
translation misses. The numbers are from one model and a few runs: use
them for the direction, not as a benchmark.

### One copy, and what a page cache costs

After M9, with direct access, the device file is in host memory once,
in 2 MiB pages: each of the three qemus maps all of it (`Rss`), and its
`Pss` is a third of that. The page cache charged to the readers is 0,
and the page cache of the VMs did not grow: `llama-server` maps the file
from the device.

After M14, with cached access, every reader is charged the size of the
model in page cache, and the page cache of each VM grew by as much. The
model costs four times its size, one copy on the host and one in each
VM, against once with direct access. The host sees the copies in the
private memory of the qemus only where the guest touched memory that
the host had not backed yet. A fresh VM grows by the copy, a VM that has
run a while hardly at all. The cache is reclaimable, and it did not push
other cached data out in these runs.

## Troubleshooting

- A view says "stale": its ssh or kubectl call failed or took too long;
  it retries every second. If it stays stale, stop it with Ctrl-C and
  start it again, and check
  `ssh -F $N/test/e2e/n4-cxl-shared-2-fedora-43-containerd/.ssh-config node true`.
- T3 says `drivers: vm2 restarting`: the driver pod restarts; wait. The
  trace of that node stops at a restart.
- A step does not finish: every command has a timeout, and so has every
  check of a result. Ctrl-C in T1 stops the runner; `demo zoom last`
  shows what the command printed, and `demo local N` runs the step again.
- Start over in front of the audience: `demo reset local`, then
  `demo local`.
- Readers stay waiting after L6, F6 or R9: `demo zoom pod reader-a` (the
  scheduler's reason), `demo zoom driver vm2`. In pool-fs the writer's
  release may not have finished: `demo zoom mounts vm1` shows the
  superblock still read-write while a file of the writer is open.
- A lease stays releasing and T5 says `unmount busy, retry`: a process of
  the reader has a file of the mount open; it ends with the pod.
- pool-fs: R3 says `mkfs.xfs failed` or R4 does not mount: the kernel of
  the VMs lacks a feature of the image's mkfs (`demo zoom kernel vm1`).
- A pod of the wizard stays Pending: the warning of `demo wizard new`
  said why; `demo zoom pod wN`, `demo zoom claim wN`, `kubectl logs wN`.
- `demo setup` says there is no image of the driver: build it. It says
  `run_tests.sh runs already`: another e2e run is going. A port 9909 or
  9920 is busy: an earlier pool server or model mirror runs; `demo
  teardown`.
- Setup fails with `cannot hot-remove CXL memory devices`: the VM runs
  a qemu without the hot-remove ([e2e.md](e2e.md#requirements)).
- "The VM ... was provisioned with other versions": pin the releases of
  the creation, or set `e2e_vm_versions=ignore`.
- M3 cannot download the model (`SSL certificate problem`): use
  `DEMO_LLM_MODEL_DIR`. "DEMO_LLM_MODEL_DIR ... has no ... with
  sha256": the file is not the pinned one.
- A reader of llm-share stays Pending with "0/3 nodes are available":
  check the node labels (`cxl-demo/node`) and that `demo zoom pool`
  shows `llm0` with no single-host attachment (the writer released it at
  M4). A reader Running but not Ready loads the model; with cached
  access that takes a while.
- The `2M` column says 0%: the qemu of a VM runs with transparent huge
  pages off (`THP_enabled: 0`), and the numbers are not comparable. Run
  `test00-up` of the VM, which allows them in its Vagrantfile, and
  restart it.
- `latency.sh on` refuses: the message says why (one socket, sudo, a
  pool directory that is not empty, the latency on already).
- A VM has CXL devices left, or the cluster is broken after a failed
  teardown: run `test00-up` of that VM; it restarts a VM that has CXL
  devices. Restarting VM2 makes the API server unavailable for a while.
- Anything else: `demo teardown` and `demo setup` again; a teardown that
  failed can run again.

## The demo directory

| path | |
|:-----|:-|
| `bin/demo` | the entry point |
| `bin/views.py`, `bin/probe.py` | the views T2 to T6, and what they run in the VMs |
| `bin/steps.py`, `bin/zoom.py`, `bin/truth.py` | the step runner, the zooms, the ground truth |
| `bin/wizard.py`, `bin/wizard_views.py`, `bin/wizard_check.py`, `bin/wizard-rules.sh` | the wizard, its views, its checks, its scripted rules |
| `bin/llm.py`, `bin/tools/` | llm-share on the host; the tools in the pods (the ConfigMap `demo-tools`) |
| `bin/latency.sh`, `bin/pool-tmpfs.sh` | the latency variant, the pool tmpfs |
| `bin/selftest.py`, `bin/selftest-shell.sh`, `testdata/` | the selftest and its samples |
| `image/Dockerfile` | the demo image |
| `manifests/` | the pods and claim templates of the stories |
| `run/` | the state, logs, timings and results of the current demo (not in git) |
| `captures/` | `demo capture` and `demo truth` (not in git) |

The setup and teardown are the tests
[`test98-demo-setup`](tree:/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test98-demo-setup)
and
[`test99-demo-teardown`](tree:/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test99-demo-teardown).
