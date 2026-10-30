# Leases: memory for running containers

CAUTION: prototype. Interfaces may change.

A pod's claims are fixed when it is created, so a running container cannot
get more memory through its own claims. It can *lease* memory instead: the
node plugin allocates a device for a *companion pod* and lends it to the
container, as a NUMA node added to the container's `cpuset.mems` (mode
`numa`), as an open file descriptor of a devdax device (mode `dax`) or, for
a pool device of persistent memory, as an open file descriptor of the block
device of its fsdax namespace (mode `block`) or as its read-only erofs
filesystem mounted into the running container (mode `fs`). The memory is a
slice of a local memdev or a shared local device (`cxl.nri.io`,
[local.md](local.md)) or a pool device (`cxl-pool.nri.io`,
[pool.md](pool.md)), local first unless the request names a source; modes
`block` and `fs` are pool only.

- [Opting in](#opting-in)
- [Flow](#flow)
- [cxl-request](#cxl-request)
- [Protocol](#protocol)
- [Companion objects](#companion-objects)
- [Life cycle](#life-cycle)
- [Limitations](#limitations)

## Opting in

nri-dra-driver-cxl (`--leases`, environment `LEASES`, Helm value
`leases.enabled`, on by default) publishes the device `lease` in the
node's `cxl.nri.io` ResourceSlice: attribute `type: lease`, no capacity,
`allowMultipleAllocations: true`, so any number of pods can claim it. The
DeviceClass `cxl-lease` of
[`templates/deviceclasses.yaml`](blob:/deployment/helm/dra-driver-cxl/templates/deviceclasses.yaml)
selects it. A pod that may lease memory claims it through a template, so
that the claim follows the pod
([lease.yaml](blob:/deployment/samples/dra-driver-cxl/lease.yaml)):

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata: {name: cxl-lease}
spec: {spec: {devices: {requests: [{name: lease, exactly: {deviceClassName: cxl-lease}}]}}}
---
apiVersion: v1
kind: Pod
metadata: {name: borrower}
spec:
  resourceClaims:
  - {name: lease, resourceClaimTemplateName: cxl-lease}
  containers:
  - name: app
    image: docker.io/library/python:3-alpine
    command: ["sleep", "infinity"]
    resources: {claims: [{name: lease}]}
```

Leases need NRI (the plugin lends nodes through NRI and maps callers to
containers) and the host PID namespace. The DaemonSet of the Helm chart
has both, and so has a host process ([usage.md](usage.md#build-and-deploy)).
Leasing local memory needs no pool driver; with `--pool-driver-name ""` a
pool lease fails with `pool driver disabled (--pool-driver-name)`.

NodePrepare of a claim on `lease` creates
`/var/lib/kubelet/plugins/cxl.nri.io/leases/<claim uid>/cxl.sock` (mode
0666; the directory 0755, labelled `container_file_t` when SELinux is
enabled), the empty mount point `fs` in that directory and the directory
`/var/lib/kubelet/plugins/cxl.nri.io/lease-fs/<claim uid>` (0755, labelled
the same way), and returns for the allocation result of the lease device
its CDI device `nri.io/cxl=claim-<claim uid>-<n>` (spec file `cxl-claims`,
only the marker `CXL_CLAIM_<uid>_<n>=1`) and the CDI device `nri.io/cxl=lease-<claim uid>`
(spec file `cxl-leases`):

- bind mount (rbind, rw) of the socket directory at `/run/cxl`,
- bind mount (rbind, ro, rslave) of the `lease-fs` directory at
  `/run/cxl/fs`: the filesystems of `fs` leases appear below it in the
  running containers,
- bind mount (ro) of the static CLI (`--lease-cli`, default
  `/usr/local/bin/cxl-request` on the host; the Helm chart uses
  `/var/lib/kubelet/plugins/cxl.nri.io/cxl-request`, copied from the image
  with `--lease-cli-source`) at `/usr/local/bin/cxl-request`; it is left
  out, with a warning, if the file does not exist,
- env `CXL_LEASE_SOCKET=/run/cxl/cxl.sock`.

Only containers that list the claim in `resources.claims` get them. The
directory, not the socket, is mounted, so a restarted plugin can create a
new socket in it that the running containers see.

`/run/cxl/fs` is a slave of the host's mount: a mount that the plugin
makes in `lease-fs/<claim uid>` later appears in every running container
of the claim, with the flags it was made with, and its unmount takes it
away there. The directory is separate from the socket directory and
read-only in the containers: only the plugin writes it, so a container
cannot replace a mount point by a symlink and make the privileged plugin
mount over a host path. The `lease-fs` directories are under
`/var/lib/kubelet/plugins`, which the DaemonSet of the Helm chart mounts
with `mountPropagation: Bidirectional`; nothing else is needed.

## Flow

```
container: cxl-request request --size 512Mi
  -> plugin: authenticate the caller, store lease L                 (Creating)
  -> create ResourceClaim cxl-lease-L, then Pod cxl-lease-L          (Pending)
  -> the scheduler allocates a slice of a local memdev or, if none has
     room, a pool device (the pool controller attaches it, the binding
     condition releases the bind)
  -> kubelet prepares cxl-lease-L: a slice or a region, online movable,
     NUMA node N; the label cxl.nri.io/lease=L names the lease        (Lending)
  -> NRI UpdateContainers: cpuset.mems of THAT container = its own nodes
     without the CXL nodes of the driver + N
  -> response {"lease":"L","state":"Ready","node":N,...}              (Ready)
container: cxl-request release --lease L
  -> revoke (cpuset.mems shrinks, the kernel migrates the pages back)
  -> delete Pod and ResourceClaim cxl-lease-L                        (Releasing)
  -> kubelet unprepares (offline, delete the slice or destroy the region;
     a pool device is disabled, deallocated and detached)
  -> lease dropped                                                    (Released)
```

A lease in mode `dax` is the same, but nothing is lent through cgroups:
the plugin opens `/dev/daxX.Y` (O_RDWR, or O_RDONLY for a read-only
lease) and passes the open file descriptor to the container over the
socket (SCM_RIGHTS). The container needs no device node and no device
cgroup rule; the device cgroup is checked only at open().
`cxl-request request --exec CMD` (and `cxl-request fd --exec CMD`) runs
CMD with the fd as fd 3. A local `dax` lease gets a devdax slice of a
local memdev of its own or a shared local device, a pool one a whole
exclusive device or a shared device.

A read-only lease's fd allows mappings for reading only: a writable
mapping (`mmap` with `PROT_WRITE`, or `mprotect` to it) fails with EACCES,
a store into the mapping raises SIGSEGV, and reopening the fd through
`/proc/self/fd` is refused by the device cgroup, whatever the
capabilities of the container.

A shared device of volatile memory, local or pool, is `dax` only, a
pool device of persistent memory `block` or `fs` only. `--shared` takes one
share of it; a request that names a shared device by `--serial` without
`--shared` takes the whole device (the writer of single-writer sharing).
A local memdev that is not configured shared is never shared through a
lease; several pods share its slice by referencing one ResourceClaim
([local.md](local.md#claims)).

A local lease waits for no attach and no binding condition: it is Ready a
few seconds after the request. A `numa` lease reports node N and the
slice or device size (`"node"`, `"size"`); a local slice grows N while
the lease is Ready.

A lease in mode `block` is the fd model of `dax` leases applied to the
block device of a pool device of persistent memory (attribute
`persistent: true`, [usage.md](usage.md#persistent-memory)): no device
node in the container, no mount:

```
container: cxl-request request --serial 0xc1af0001 --mode block
  -> companion claim cxl-lease-L of class cxl-pool-persistent, MemoryConfig device {mode: block, readOnly}
  -> kubelet prepares cxl-lease-L as a claim of mode block: pmem region, the fsdax namespace
     (created only by an exclusive writable one, the writer of a fresh device)  (Lending)
  -> the plugin opens /dev/pmemK (O_RDWR, or O_RDONLY for a read-only lease)
  -> response {"lease":"L","state":"Ready","mode":"block","block":"/dev/pmemK",...} with the fd  (Ready)
container: cxl-request fd --lease L --exec CMD                       # the fd again
container: cxl-request release --lease L                             # close the fd first
```

Without `--shared` the lease takes the whole device, exclusively, and may
write it (the writer); `--shared --read-only` takes one share, read-only
(a reader); a share is never writable. The fd can be read, written
(`write`, `pwrite`) and fsynced; it cannot be given to a tool that wants a
path: reopening it through `/proc/self/fd` is refused by the device cgroup,
as for `dax` fds. `CXL_<KEY>_SIZE` is the size of the fsdax namespace.

A lease in mode `fs` gives the container the erofs filesystem of a pool
device of persistent memory (attribute `persistent: true`,
[usage.md](usage.md#persistent-memory)), read-only, no fd and no device
node:

```
container: cxl-request request --serial 0xc1ae0001 --shared --read-only --mode fs [--access cached] [--name models]
  -> companion claim cxl-lease-L of class cxl-pool-persistent, MemoryConfig device {mode: fs, readOnly: true, access}
  -> kubelet prepares cxl-lease-L: pmem region, the node mount
     /var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/<serial hex>-<access> (as for a claim of mode fs),
     then a bind of it at lease-fs/<claim uid>/<name>                 (Lending)
  -> the bind appears at /run/cxl/fs/<name> in the running containers of the lease claim
  -> response {"lease":"L","state":"Ready","mode":"fs","access":"direct","path":"/run/cxl/fs/<name>",...}  (Ready)
container: cxl-request release --lease L
  -> delete Pod and ResourceClaim cxl-lease-L                        (Releasing)
  -> kubelet unprepares: unmount the bind (it fails while files of it are open or mapped,
     kubelet retries), then the node mount if no claim of the node uses it, then the region
  -> lease dropped                                                    (Released)
```

`<name>` is `--name`, by default the lease id. The bind is a plain bind of
the node mount: it is read-only, `nosuid` and `nodev` like the node mount,
in the containers too. `access: direct` maps the file pages to the memory
of the device, `access: cached` reads them into the page cache of the
node; a lease and the claims of a device on a node share one node mount
per access. `CXL_<KEY>_PATH` is `/run/cxl/fs/<name>`.

## cxl-request

`cxl-request` is a static binary (in the image of the driver, see
[usage.md](usage.md#build-the-image)) that talks to `$CXL_LEASE_SOCKET`.
The first word is the operation; every other input is `--opt` or
`--opt ARG` (`--opt=ARG` too); `--exec` ends the options, the rest of the
line is the command.

```
cxl-request request [--source local|pool] [--mode numa|dax|fs|block] [--shared] [--read-only]
                    [--access direct|cached] [--name NAME]
                    [--size SIZE] [--serial SERIAL] [--wait DURATION] [--request-id ID]
                    [--exec CMD [ARG...]]
cxl-request release (--lease ID | --all) [--wait DURATION]
cxl-request list
cxl-request fd  --lease ID [--wait DURATION] --exec CMD [ARG...]
cxl-request env --lease ID [--wait DURATION] [--exec CMD [ARG...]]
cxl-request help
```

| operation | |
|:----------|:-|
| `request` | create a lease, wait until it is Ready, print the response; with `--exec` run CMD with the lease's environment (and its fd for `dax` and `block`, its mount for `fs`) |
| `release` | release a lease of the pod, or all of them, and wait until Released |
| `list` | print the leases of the pod |
| `fd` | get the fd of a Ready `dax` or `block` lease again and run CMD with it, for example after CMD restarted |
| `env` | print the lease's environment as `KEY=VALUE` lines, or run CMD with it |

| option | values, default | |
|:-------|:----------------|:-|
| `--source` | `local`, `pool`; omitted: local first, then pool | which devices |
| `--mode` | `numa`, `dax`, `fs`, `block`; omitted: `numa`, or `dax` for a shared device | how the memory is given: a NUMA node, a devdax fd, the read-only filesystem of a pool device of persistent memory at `/run/cxl/fs/NAME`, or an fd of the block device of a pool device of persistent memory (`fs` and `block` are never a default) |
| `--shared` | default off | one share of a shared device (default: the whole device, exclusive) |
| `--read-only` | default off | `dax`, `block`: the fd allows reads only; `fs` needs it, and `block` with `--shared` |
| `--access` | `direct`, `cached`; default `direct` | `fs`: `direct` maps the file pages to the memory of the device, `cached` reads them into the page cache of the node |
| `--name` | 1 to 255 letters, digits, `.`, `_`, `-`, not `.` or `..`; default the lease id | `fs`: the mount point `/run/cxl/fs/NAME`, unique among the leases of the lease claim |
| `--size` | quantity, for example `512Mi` | at least this much: a capacity request on exclusive devices, a size selector on shared devices |
| `--serial` | `0x` hex or decimal | this device |
| `--wait` | Go duration; omitted: the plugin's `--lease-wait` (`120s`); `0s`: do not wait | `request`, `fd`, `env`: until Ready; `release`: until Released |
| `--request-id` | string | the same id from the same container returns the same lease: repeat the whole command after a lost connection |
| `--lease` | 8 hex digits | the lease of `release`, `fd` and `env` |
| `--all` | | `release`: every lease of the pod |
| `--exec` | CMD ARG... | run CMD with the lease's environment, and the fd of a `dax` or `block` lease as fd 3 |

The defaults are the safe ones: exclusive, read-write, `numa`, local
first, then pool.
A request needs `--size`, `--serial` or `--shared`.

`cxl-request` refuses these command lines with exit code 2 before
anything is sent, checked in this order; the plugin checks requests from
other clients the same way and answers `{"error": ...}`:

| case | message |
|:-----|:--------|
| `--source` other than `local`, `pool` | `invalid source "..." (local or pool)` |
| `--mode` other than `numa`, `dax`, `fs`, `block` | `invalid mode "..." (numa, dax, fs or block)` |
| `--access` other than `direct`, `cached` | `invalid access "..." (direct or cached)` |
| `--shared` with `--mode numa` | `shared memory is never onlined as RAM: use mode dax` |
| `--access` without `--mode fs` | `access needs mode fs` |
| `--name` without `--mode fs` | `name needs mode fs` |
| `--name` not 1 to 255 bytes of letters, digits, `.`, `_` and `-`, or `.` or `..` | `invalid name "..." (letters, digits, ".", "_" and "-", not "." or "..")` |
| `--mode fs` without `--read-only` | `mode fs needs readOnly` |
| `--mode block` with `--shared` without `--read-only` (a share of a device is read-only; the whole device, without `--shared`, may be written) | `mode block with shared needs readOnly` |
| `--read-only` without `--mode dax`, `--mode fs`, `--mode block` or `--shared` | `readOnly needs mode dax, fs or block` |
| `--mode fs` or `--mode block` with `--source local` | `mode fs needs source pool`, `mode block needs source pool` |
| `request` without `--shared`, `--serial` and `--size` | `size or serial is required` |
| `--serial` not a number | `invalid serial "..."` |
| `--exec` with `release` or `list` | `--exec is for request, fd and env` |
| `fd` without `--exec` | `fd needs --exec` |
| `fd` or `env` without `--lease` | `fd needs --lease ID`, `env needs --lease ID` |
| `release` with neither or both of `--lease` and `--all` | `release takes --lease ID or --all` |
| `--wait` not a duration, or negative | `invalid wait "..."` |

The plugin refuses further requests that only it can judge:

| case | message |
|:-----|:--------|
| `--size` not a positive quantity | `invalid size "..."` |
| `--shared` with the serial of a device that is not shared (an exclusive pool device, a local memdev that is not configured shared) | `device 0x...: not shareable` |
| `--source local` with the serial of a pool device | `device 0x...: not a local device` |
| `--source pool` with the serial of a local device | `device 0x...: not a pool device` |
| the serial of a local device of another node | `device 0x...: a local device of node <X>, not of this node` |
| `--mode fs` or `--mode block` with the serial of a device of volatile memory | `device 0x...: mode fs needs a persistent device`, `device 0x...: mode block needs a persistent device` |
| the serial of a pool device of persistent memory without `--mode block` or `--mode fs` | `device 0x...: a persistent device needs mode block or fs` |
| `--mode numa` with the serial of a shared device | `shared memory is never onlined as RAM: use mode dax` |
| `--source pool`, `--mode fs` or `--mode block` while the pool driver is disabled (a `--shared` request without `--source` is served by shared local devices then) | `pool driver disabled (--pool-driver-name)` |
| `--mode fs` in a container of a lease claim that a driver without mode `fs` prepared (its containers have no `/run/cxl/fs`) | `lease claim <ns>/<name> has no filesystem directory (prepared by an older driver): recreate the pod` |
| `--mode fs` with the `--name` (or default name) of another lease of the lease claim, in any state | `name "..." is in use by lease <id>` |
| any request while NRI is not connected | `lending unavailable: NRI not connected` |
| `fd` on a lease in mode `numa` or `fs` | `lease <id> is not a dax or block lease; use env` |

A serial that names a shared device of volatile memory makes the mode
`dax` when `--mode` is omitted; the CLI cannot know that, so
`--read-only` needs `--shared`, `--mode dax`, `--mode fs` or `--mode block`
with it. A persistent device is never `block` or `fs` by default: name the
mode. The plugin's refusals are a JSON line with
`error` on stdout (on stderr for `env` and with `--exec`) and exit code 1,
3 for `fd` on a `numa` or `fs` lease.

Unknown operations and options, an option of another operation, and an
option without its value are usage errors too. `help` (or `-h`,
`--help`) prints the usage.

Output: `request`, `release` and `list` print the plugin's JSON response
line. `env` prints the variables of the lease
([usage.md](usage.md#environment-variables), with `CXL_<KEY>_DAX` for
`dax`, `CXL_<KEY>_PATH` for `block`) and `CXL_LEASE=<id>` as `KEY=VALUE`
lines, sorted, so that `eval "$(cxl-request env --lease ID)"` works.
Without `--exec` the fd of a `dax` or `block` lease is not kept.

With `--exec`, CMD runs once the lease is Ready, with the environment of
`cxl-request` plus the variables of the lease and `CXL_LEASE=<id>`. For
`request --exec` and `fd --exec` of a `dax` lease, the fd is fd 3 of CMD
and `CXL_<KEY>_FD=3` takes the place of `CXL_<KEY>_DAX`; `env --exec`
passes no fd and keeps `CXL_<KEY>_DAX`. The same for a `block` lease, with
`CXL_<KEY>_PATH` in the place of `CXL_<KEY>_DAX`: without the fd (`env`,
`env --exec`) `CXL_<KEY>_PATH` is the host path `/dev/pmemK` of the block
device, informational, as `CXL_<KEY>_DAX` is; the container has no such
node. A `numa` lease has no fd: CMD
gets `CXL_<KEY>_NODE` and the rest. An `fs` lease has no fd either: CMD
gets `CXL_<KEY>_PATH=/run/cxl/fs/<name>`, `CXL_<KEY>_ACCESS`,
`CXL_<KEY>_READONLY=1`, `CXL_<KEY>_MODE=fs`, `CXL_<KEY>_SIZE` (the size
of the fsdax namespace), `CXL_<KEY>_SERIAL`, `CXL_<KEY>_SHARED` and
`CXL_LEASE`; the filesystem is mounted at the path when CMD starts. CMD's exit code is passed through
(128+signal when it is killed by a signal), and SIGTERM, SIGINT, SIGHUP
and SIGQUIT to `cxl-request` are forwarded to CMD.

Exit codes: 0 ok; 1 error (no socket, connection, invalid response, an
error from the plugin, CMD could not start); 2 usage; 3 the lease is
Failed, not Ready within `--wait` (`request`, `fd`, `env`; with
`--exec` CMD is not started), not Released within `--wait` (`release`),
or `fd` on a lease that is neither `dax` nor `block`. Without `--exec`,
`request --wait 0s` exits with 0 whatever the state of the lease, unless
it is Failed. With `--exec` it exits with 3 unless the lease is Ready at
once. Without
`$CXL_LEASE_SOCKET`, `cxl-request` exits with 1 and
`CXL_LEASE_SOCKET is not set (the pod needs a claim on DeviceClass cxl-lease)`.

Examples, with the local memdev `0xc100e2e1`, the shared local device
`0xc100e2e2`, the exclusive pool device `0xc1ee0001`, the shared pool
device `0xc1ae0001` and the shared pool device of persistent memory
`0xc1af0001` with an erofs that has `model.gguf`:

```
cxl-request request --size 512Mi
  -> {"lease":"1a2b3c4d","state":"Ready","source":"local","mode":"numa","shared":false,"readOnly":false,
      "size":536870912,"serial":"0xc100e2e1","node":2,"env":{"CXL_C100E2E1_MODE":"numa",...}}
cxl-request request --source pool --size 512Mi --mode dax --exec python3 app.py
  -> app.py sees CXL_C1EE0001_FD=3 CXL_C1EE0001_MODE=dax CXL_C1EE0001_SIZE=536870912
     CXL_C1EE0001_SERIAL=0xc1ee0001 CXL_C1EE0001_SHARED=0 CXL_C1EE0001_READONLY=0 CXL_LEASE=1a2b3c4d
cxl-request request --source local --size 64Mi --mode dax --read-only --exec prog
cxl-request request --serial 0xc1ae0001                       # the shared device, exclusively (writer)
cxl-request request --serial 0xc1ae0001 --shared --read-only --exec prog   # a reader
cxl-request request --serial 0xc100e2e2                       # the shared local device, exclusively
cxl-request request --serial 0xc100e2e2 --shared --read-only  # one read-only share of it
cxl-request request --shared --size 256Mi                     # one share of any shared device of 256Mi or more, local first, then pool
cxl-request request --source local --shared --size 64Mi       # one share of a shared local device
cxl-request request --size 1Gi --wait 0s --request-id r1      # asynchronous: Pending
cxl-request request --serial 0xc1af0001 --shared --read-only --mode fs \
    --exec sh -c 'exec llama-server -m "$CXL_C1AF0001_PATH/model.gguf"'   # direct: /run/cxl/fs/<lease id>
  -> {"lease":"1a2b3c4e","state":"Ready","source":"pool","mode":"fs","shared":true,"readOnly":true,"access":"direct",
      "path":"/run/cxl/fs/1a2b3c4e","size":534773760,"serial":"0xc1af0001","env":{"CXL_C1AF0001_PATH":"/run/cxl/fs/1a2b3c4e",...}}
cxl-request request --serial 0xc1af0001 --shared --read-only --mode fs --access cached --name models \
    --exec llama-server -m /run/cxl/fs/models/model.gguf         # cached, at a fixed path
cxl-request request --serial 0xc1af0001 --mode block \
    --exec sh -c 'cat /tmp/model.erofs >&3'                   # the writer: an erofs image into the device
  -> {"lease":"1a2b3c4f","state":"Ready","source":"pool","mode":"block","shared":false,"readOnly":false,
      "size":534773760,"serial":"0xc1af0001","block":"/dev/pmem0","env":{"CXL_C1AF0001_PATH":"/dev/pmem0",...}}
cxl-request fd --lease 1a2b3c4f --exec sh -c 'cat /tmp/model.erofs >&3'   # the same through the fd again
cxl-request request --serial 0xc1af0001 --shared --read-only --mode block --exec prog   # a reader of the block device
cxl-request env --lease 1a2b3c4d                              # KEY=VALUE lines (DAX, not FD)
cxl-request fd --lease 1a2b3c4d --wait 60s --exec prog        # the fd again after a restart of prog
cxl-request env --lease 1a2b3c4d --exec numactl --membind=2 prog   # a numa lease: CXL_C100E2E1_NODE=2
cxl-request list
cxl-request release --lease 1a2b3c4d
cxl-request release --all
```

## Protocol

`SOCK_STREAM` unix socket, one JSON object per line in each direction; a
connection may carry several requests. The fields of a request mirror the
options of `cxl-request`; all are optional except `op`. Requests are
decoded strictly: an unknown field is answered with
`invalid request: json: unknown field "..."`, an unknown `op` with
`unknown op "..." (request, release, list, fd or env)`.

| field | values |
|:------|:-------|
| `op` | `request`, `release`, `list`, `fd`, `env` |
| `source` | `local`, `pool`; omitted: local first, then pool |
| `mode` | `numa`, `dax`, `fs`, `block` |
| `shared` | bool |
| `readOnly` | bool |
| `access` | `direct`, `cached`; mode `fs` only |
| `name` | the mount point in `/run/cxl/fs`; mode `fs` only |
| `size` | quantity string |
| `serial` | string, `0x` hex or decimal |
| `wait` | Go duration string |
| `requestId` | string |
| `lease` | lease id |
| `all` | bool |

For example:

| request | |
|:--------|:-|
| `{"op":"request","size":"512Mi","wait":"120s","requestId":"r1"}` | 512Mi, local first, then pool, lent as a NUMA node |
| `{"op":"request","source":"pool","size":"512Mi","mode":"dax","readOnly":true}` | an exclusive pool device as dax, read-only fd passed |
| `{"op":"request","source":"local","size":"64Mi","mode":"dax"}` | a dax slice of a local memdev, fd passed |
| `{"op":"request","source":"local","size":"64Mi","serial":"0xc100e2e1"}` | memory of the device with the serial |
| `{"op":"request","serial":"0xc1ae0001","shared":true}` | one share of a shared device, fd passed |
| `{"op":"request","serial":"0xc1ae0001"}` | the shared device, nobody else meanwhile, fd passed |
| `{"op":"request","serial":"0xc1af0001","shared":true,"readOnly":true,"mode":"fs","access":"cached","name":"models"}` | one share of a persistent device, its filesystem at `/run/cxl/fs/models`, page-cached |
| `{"op":"request","serial":"0xc1af0001","mode":"block"}` | a persistent device whole, the fd of its block device passed, read-write |
| `{"op":"release","lease":"1a2b3c4d","wait":"120s"}` | release one lease of the pod |
| `{"op":"release","all":true}` | release all leases of the pod |
| `{"op":"list"}` | leases of the pod |
| `{"op":"fd","lease":"1a2b3c4d"}` | send the fd of a Ready dax or block lease again |
| `{"op":"env","lease":"1a2b3c4d"}` | the lease with its environment |

Response (`shared` and `readOnly` are always present, the other fields
only when they have a value):

| field | |
|:------|:-|
| `lease` | id, 8 hex digits |
| `state` | `Creating`, `Pending`, `Lending`, `Ready`, `Releasing`, `Failed`, `Released` (in responses only: the lease is gone) |
| `source` | `local` or `pool`: the requested one, the allocated one once Ready; omitted while undecided |
| `mode` | `numa`, `dax`, `fs` or `block`, effective |
| `shared` | bool, effective: `false` for a lease that uses a shared device exclusively |
| `readOnly` | bool |
| `access` | `direct` or `cached`, mode `fs` |
| `path` | the directory of the filesystem in the container, `/run/cxl/fs/<name>`, mode `fs` once Ready |
| `size` | bytes: once Ready the size of the slice or the device (a pool device may be larger than requested; modes `fs` and `block`: the size of the fsdax namespace), the requested size before |
| `serial` | `0x` hex, once known |
| `node` | NUMA node, mode `numa` once Ready |
| `dax` | `/dev/daxX.Y`, mode `dax` once Ready; informational, the container has no such device node |
| `block` | `/dev/pmemK`, mode `block` once Ready; informational, the container has no such device node |
| `env` | once Ready: the variables a claim of this memory would inject, with `DAX` for `dax` leases and `PATH` the host path of the block device for `block` leases |
| `error` | message |
| `leases` | list of responses, for `list` and `release` with `all` |

The variables of `env` are those of
[Environment variables](usage.md#environment-variables). The response of a
Ready `dax` or `block` lease to `request` and `fd` carries the fd of its
device as SCM_RIGHTS on the same write. A device that cannot be opened is
answered with `opening <device>: <error>` instead, and the lease is kept.

- `wait` blocks until Ready or Failed (`release`: until Released). At the
  timeout of a `request` the lease is released and reported Failed
  `timeout: not Ready after <wait>`; `fd` and `env` report the state at
  their timeout and keep the lease. `"wait":"0s"` returns the current
  state at once and keeps the lease.
- `requestId`: a repeated request with the same id from the same
  container returns the same lease (a retry after a lost connection).
- A release waits up to `wait` for the companion objects to disappear and
  answers Released, or Releasing if they are still going.
- `fd` serves the container that requested the lease only; `env`,
  `list` and `release` serve every container of the pod.
- Errors: the validation messages of [cxl-request](#cxl-request),
  `not a container of the claim's pod`, `no such lease` (`release`),
  `no such lease of this container` (`fd`, `env`), and the errors of the
  lend. A lend that fails (for example the container is steered,
  see [Limitations](#limitations), or not running) makes the lease Failed
  with that message, and it is released.

Caller authentication: the socket identifies the lease claim, and the
claim's `reservedFor` the pod. SO_PEERCRED gives the caller's pid; the
NRI plugin maps it through `/proc/<pid>/cgroup` to a container. The
container's pod must be a pod of the claim. A lease is bound to that pod
and container: memory is lent to the calling container only; any
container of the same pod with the socket may list and release it.

## Companion objects

The companion objects of lease `<id>` live in the requester's namespace:

- ResourceClaim `cxl-lease-<id>` with one request `lease`:
  - a `--serial` that a ResourceSlice of `cxl.nri.io` or of the pool
    driver has: `exactly` with the source and class of that device,
    with or without `--source`;
  - else one source: `exactly` with the class of the source;
  - else `firstAvailable: [{name: local, ...}, {name: pool, ...}]`,
    without `pool` when the pool driver is disabled; a single source left
    is an `exactly` request.

  The class is `cxl-local` for a local slice, `cxl-local-shared` for a
  shared local device, `cxl-pool` for an exclusive pool device and
  `cxl-pool-shared` for a shared one; a shared lease (`--shared`) asks the
  shared classes only. A lease in mode `block` or `fs` asks the pool only,
  class `cxl-pool-persistent` (shared or not). The selectors are
  `device.attributes["<driver>"].serial == "0x<hex>"` when a serial is
  given and `device.attributes["<driver>"].size >= <bytes>` on a shared
  class when a size is given. The capacity request is `memory: <size>` on
  a slice or an exclusive pool device, `shares: "1"` for a share
  (`--shared`), and none when a shared device is taken whole
  (exclusively). For example:

  | request | `spec.devices.requests` of the companion claim |
  |:--------|:-----------------------------------------------|
  | `--serial S`, S a shared local device (the writer) | `exactly`: `cxl-local-shared`, serial selector, no capacity |
  | `--serial S --shared --read-only`, S a shared local device (a reader) | `exactly`: `cxl-local-shared`, serial selector, `shares: "1"`, `readOnly: true` |
  | `--serial S`, S a shared pool device | `exactly`: `cxl-pool-shared`, serial selector, no capacity |
  | `--serial S --size N`, S an exclusive local or pool device | `exactly`: `cxl-local` or `cxl-pool`, serial selector, `memory: N` |
  | `--serial S --shared`, S in no ResourceSlice | `firstAvailable`: `cxl-local-shared`, then `cxl-pool-shared`, serial selector and `shares: "1"` each |
  | `--shared --size 64Mi` | `firstAvailable`: `cxl-local-shared`, then `cxl-pool-shared`, `size >= 67108864` and `shares: "1"` each |
  | `--source local --shared --size 64Mi` | `exactly`: `cxl-local-shared`, `size >= 67108864`, `shares: "1"` |
  | `--size 512Mi` | `firstAvailable`: `cxl-local`, then `cxl-pool`, `memory: 512Mi` each |
  | `--serial S --shared --read-only --mode fs`, S a shared persistent pool device | `exactly`: `cxl-pool-persistent`, serial selector, `shares: "1"` |
  | `--serial S --read-only --mode fs`, S a shared persistent pool device | `exactly`: `cxl-pool-persistent`, serial selector, no capacity |
  | `--shared --read-only --mode fs --size 256Mi` | `exactly`: `cxl-pool-persistent`, `size >= 268435456`, `shares: "1"` |
  | `--serial S --mode block`, S a shared persistent pool device (the writer) | `exactly`: `cxl-pool-persistent`, serial selector, no capacity: the whole device |
  | `--serial S --shared --read-only --mode block`, S a shared persistent pool device (a reader) | `exactly`: `cxl-pool-persistent`, serial selector, `shares: "1"` |

  Every source
  driver gets a `MemoryConfig` (apiVersion `cxl.nri.io/v1alpha1`) whose
  `device` section has the effective `mode` and `readOnly`, and for mode
  `fs` the `access` (no `path`: the companion pod gets no mount;
  `{mode: block, readOnly}` for mode `block`), so that the claim shows
  what was asked; in a `firstAvailable` request
  each applies to its subrequest (`requests: [lease/local]`,
  `[lease/pool]`). The claim has no `container` section: the settings
  of the borrower come from its own claims, the lease claim included,
  and the node defaults ([usage.md](usage.md#container-settings)). The
  claim has an ownerReference to the requester pod (controller: true).
- Pod `cxl-lease-<id>`: ownerReference to the requester pod, required
  node affinity `metadata.name In [<node>]`, `tolerations: [{operator: Exists}]`,
  restartPolicy Always, `automountServiceAccountToken: false`,
  `enableServiceLinks: false`, `terminationGracePeriodSeconds: 1`, one
  container `pause` (`--lease-companion-image`,
  default `registry.k8s.io/pause:3.10`) with requests = limits cpu 100m,
  memory 16Mi (Guaranteed; runc init needs about 9 MiB, and with 1m CPU
  the pause container takes about 12 s to start), no `resources.claims`,
  and `spec.resourceClaims: [{name: lease, resourceClaimName: cxl-lease-<id>}]`.
  kubelet prepares a pod's claims even if no container references them.
  Both drivers return no CDI device for a companion claim, so nothing of
  its memory reaches the pause container, which is not steered either.
- Both carry the labels `cxl.nri.io/lease=<id>`,
  `cxl.nri.io/requester-uid=<pod uid>`, `cxl.nri.io/node=<node>` and
  the annotation `cxl.nri.io/requester=<ns>/<pod>/<container>`.

A claim with the label `cxl.nri.io/lease` is a companion claim. Before
it touches a device, the driver that prepares it checks that the lease is
in the lease table and is being created (or Lending or Ready, for a
prepare again after a restart), that the claim's name is
`cxl-lease-<id>` and its namespace the requester pod's, and that the
claim has an ownerReference to the requester pod. A claim that carries
the label and fails a check fails its Prepare with
`claim <ns>/<name>: not the companion of lease <id>` (kubelet retries; a
pod that references such a claim never starts); the companion of a lease
that is Releasing or Failed fails with `lease <id> is <state>`. With
`--leases=false` every companion claim fails with
`lease <id>: lending to running containers is disabled (--leases=false)`.
So a tenant can create a claim with the label only in its own namespace,
and cannot make it the companion of a lease it did not request.

## Life cycle

- The lease table `leases.json` in the `cxl.nri.io` plugin data
  directory is written before any object is created. The driver that
  prepared the companion claim stores the lend with it
  (`preparedPoolClaims.json` of the pool driver, `preparedClaimsInfo.json`
  of `cxl.nri.io`), so it can revoke after a restart. A lease table that
  cannot be decoded (strictly) is logged, and the plugin starts with an
  empty one.
- Requester container stops: if the pod is being deleted, finished, gone
  or has restartPolicy Never, its leases are released. Otherwise they
  are kept, and the restarted container is created with the nodes of its
  `numa` leases in its `cpuset.mems` (in the CreateContainer adjustment
  when it is fenced; containerd would apply an update before the start
  to the container's spec only), and they are checked against its cgroup
  when it has started (a dax or block fd is gone with the process: get it
  again with `cxl-request fd --lease ID --exec ...`).
- Requester pod deleted: the companion pods are garbage collected
  (ownerReference); NodeUnprepare of the lease claim starts the release of
  all leases of the pod, waits until their nodes are revoked and the
  deletion of their companions is requested, and fails with "still
  releasing N leases, retry" (kubelet retries) if that takes longer than
  5 s. It does not wait for the companions to be gone: kubelet unprepares
  the companion claim of a local lease through the same driver
  (`cxl.nri.io`), one call at a time. A lease stays Releasing until its
  companion pod and claim are gone, also across a plugin restart.
- Companion pod deleted or evicted behind the plugin's back: the driver
  of the device revokes before it releases the device; the lease becomes
  Failed and is dropped by the reconcile.
- Reconcile, at start (after NRI synchronized) and every 60 s: restarts
  interrupted releases, releases leases left in Creating, leases whose
  companion pod is gone or finished and leases whose requester will not
  come back, applies the `numa` lends of Ready leases again (this is how a
  plugin restart restores them, and a lend that the container's cgroup
  lacks is updated again), and deletes the pods and claims labelled
  `cxl.nri.io/node=<node>` and `cxl.nri.io/lease` that are named
  `cxl-lease-<value of the lease label>` and have no lease in the table.
- Plugin restart: the sockets of the lease claims are created again in
  the mounted directories, leases continue.
- Node reboot: the lease table records the boot id of the kernel
  (`/proc/sys/kernel/random/boot_id`). A lease does not survive a reboot
  (the fds of `dax` and `block` leases went with their processes, the
  binds of `fs` leases are unmounted, the memory of `numa` leases is
  gone), so at start the plugin drops the leases of another boot: the
  requester containers, which restart too, have no leases and ask again;
  the first reconcile deletes the companions, whose claims the drivers
  then unprepare (their device is released, nothing was lent in the new
  boot). The lease claims stay; kubelet prepares them again. A table
  without a boot id (of an older plugin) is taken as one of this boot.
- Mode `fs`: the bind `lease-fs/<claim uid>/<name>` is the lend of the
  device, made by the pool driver when it prepares the companion claim and
  recorded with it (`preparedPoolClaims.json`); its unmount when the
  companion claim is unprepared is the revoke. The unmount is never lazy:
  while the borrower has files of the filesystem open or mapped (a
  running `llama-server` maps its model), it fails with `device or
  resource busy`, the Unprepare fails
  (`cxl-pool.nri.io: unpreparing claim <ns>/cxl-lease-<id>: lease <id>: unmounting <bind>: device or resource busy`),
  kubelet retries it, the companion stays Terminating and the lease
  Releasing; `cxl-request release --wait ...` exits with 3. Close the files
  (stop CMD) before releasing, or let the pod end: its containers take
  their mounts with them. The node mount is unmounted and the region
  released only after the bind is gone, when no claim of the node uses
  them, so the device is released only when every claim and lease of the
  node has let go of it.
- Mode `block`: nothing is bound or lent; the plugin opens the block
  device for each response that carries the fd and closes its copy. A
  plain open fd is no holder that the pool driver sees (it checks
  mounts, loop devices and exclusive opens), so the release does not wait
  for it: the region is released under a container that still holds the
  fd, and I/O through it fails from then on (ENXIO, EIO). No DAX mapping
  is involved, so this cannot crash the node. Close the fd before
  releasing.
- Directories: when the lease claim is unprepared, the socket is
  removed, then `lease-fs/<claim uid>`, then `leases/<claim uid>` with
  whatever a container wrote into its `/run/cxl`. While a bind is still
  in `lease-fs/<claim uid>`, both directories stay (removing the mount
  point of `/run/cxl/fs` would detach the bind lazily in a container that
  is still there) and are removed when the last lease of the claim is
  dropped, and by the reconcile and the start of the plugin, which remove
  the directories of lease claims that are gone. Under `lease-fs` only
  empty directories without a mount are removed, never recursively. When
  the lease table could not be decoded at start, no directory is removed
  until a start with a table that decodes.
- Plugin restart with `fs` leases: binds and node mounts are kernel
  mounts and outlive the plugin. At start the pool driver binds again a
  bind of a prepared companion claim that is missing (when its node mount
  is there or could be mounted again), and unmounts the mounts under
  `lease-fs` that belong to no prepared companion claim (left by a crash
  between the bind and the write of its state), so that they do not hold
  the device.
- Stale binds: a bind that belongs to no prepared companion claim and
  cannot be unmounted (busy) when a Prepare fails or at start is
  unmounted at the next Unprepare (or failed Prepare) of any pool claim on
  the node; once it is gone, the region of its device is released if no
  claim of the node has the device and nothing holds `/dev/pmemK` within
  10 s. The node plugin never detaches a mount, and releases a region
  only when nothing holds its block device: a bind left mounted keeps the
  device, never crashes the node.

## Limitations

- Leases have every mode of claims: `numa`, `dax`, `block` and `fs`.
  Block leases pass an fd: there is no device node in the container, and
  a path in the container is not available (a tool that writes to a path,
  such as `mkfs.erofs`, writes a file that is then copied through the fd).
  Mode `fs` is read-only erofs only.
- The filesystem of an `fs` lease is visible in every container of the
  lease claim that has `/run/cxl/fs` (every container that lists the
  claim), not only in the requesting one.
- A container created before its lease claim was prepared by a driver
  with mode `fs` has no `/run/cxl/fs` and cannot get an `fs` lease
  (`lease claim ... has no filesystem directory ...`): recreate the pod.
- User-namespaced pods are untested with `fs` leases.

- Memory limits: lent memory counts against the container's `memory.max`
  and the pod cgroup. Without a raise the extra node adds locality, not
  room. Use requester pods without a memory limit, or raise it with
  `pods/resize`. Node allocatable never includes pool memory.
- cpuset.mems has one owner: the lend goes through NRI UpdateContainers,
  as does keeping the CXL nodes of the driver away from every container
  that is not steered ([usage.md](usage.md#containers-without-claims)).
  The other containers of the borrower's pod, and every other container,
  do not get the lent node (with `defaults.container.fencing` `none` a
  container without its own cpuset.mems inherits it).
  A node is lent per lease: memory devices under one CXL host bridge share
  a NUMA node, and when two leases of a container hold the same node, it
  stays in the container's cpuset.mems until the last of them is released.
  A steered container (one whose settings opt in to steering and whose
  claims have memory in mode `numa`: memory steered by cgmpolmgr,
  [usage.md](usage.md#steering)) cannot take a `numa` lease: the lend is
  refused with "lend node N to <container>: container is memory-steered
  (container.steering.policy of its claims or the node defaults); lending
  is not supported together with steering yet", and the lease becomes
  Failed. A container that is not steered
  may, also with `numa` claims of its own: the lent node joins the nodes
  of its claims in its cpuset.mems. `dax` leases lend no node and are
  not affected.
  Both components would own the container's cpuset.mems, and cgmpolmgr
  writes cgroupfs directly, which the next NRI update reverts.
  nri-resource-policy or the kubelet memory manager would conflict the
  same way; next to an NRI resource policy that sets cpuset.mems
  `defaults.container.fencing` must be `none`. A movable node is never the
  only node in cpuset.mems.
- Release is cooperative. Releasing a `dax` lease while the device is
  still mapped makes the holder get SIGBUS at its next access; munmap
  first. Releasing a `block` lease while its fd is open makes I/O through
  the fd fail; close it first. An `fs` lease is not released while its
  files are open or mapped (the data stays usable meanwhile). A passed fd cannot be revoked short of release, and can be
  duplicated or passed on inside the pod. A `numa` release blocks
  (kubelet retries, the companion stays Terminating) while the pages
  cannot move.
- Latency: about 5-7 s per pool request (the scheduler's binding
  condition poll), about 8 s for a release. A local lease takes a few
  seconds. An `fs` lease adds the pmem region and the mounts, as a claim
  of mode `fs` does; its release waits for the borrower to close the
  files. A `block` lease adds the pmem region and, for the writer of a
  fresh device, the fsdax namespace.
- RBAC: the plugin creates and deletes pods and resourceclaims in every
  namespace (the ClusterRole of the Helm chart,
  [`deployment/helm/dra-driver-cxl/templates`](tree:/deployment/helm/dra-driver-cxl/templates));
  companions count against the tenant's ResourceQuota. No admission
  policy limits what the plugin's account may create to companions on its
  own node.
- The plugin must run in the host pid namespace with the NRI socket (the
  DaemonSet of the Helm chart has `hostPID` and mounts `/var/run/nri`; a
  host process has both anyway). SELinux labels of the socket are set
  best effort and unverified.
- Leases follow the pod object: a finished but undeleted pod keeps its
  leases until its lease claim is unprepared.
- Do not force-delete a companion pod while it holds a device (the force
  deletion hazard of [pool.md](pool.md#ordering-and-failure-semantics)).
