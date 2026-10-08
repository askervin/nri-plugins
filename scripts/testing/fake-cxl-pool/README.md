# fake-cxl-pool

A fake CXL memory pooling and sharing appliance for testing on one host:

- `fake-cxl-pool-server` runs on the host. It owns memory devices (backing
  files in pool directories) and hotplugs/hot-removes them as `cxl-type3`
  devices into running qemu VMs over their QMP or HMP monitor sockets, without
  restarting the VMs.
- `fake-cxl-pool-client` (CLI) and `pkg/client` (Go library) talk to the
  server's REST API. In a VM, the client also prepares hotplugged memory for
  use and releases it before detach (`guest` commands).
- `fake-cxl-pool-controller` connects a Kubernetes cluster to the server:
  it publishes the pool devices for DRA (driver `cxl-pool.generic`) and
  attaches and detaches them as the scheduler allocates and frees claims
  (see [fake-cxl-pool-controller](#fake-cxl-pool-controller)).

A device may be *exclusive* (attached to one VM, used as system RAM there) or
*shared* (the same backing file attached to several VMs, same serial in
every VM, used as devdax).

## Build and test

```
make -C scripts/testing/fake-cxl-pool          # bin/fake-cxl-pool-{server,client,controller}
make -C scripts/testing/fake-cxl-pool test     # unit tests (go test -race)
make -C scripts/testing/fake-cxl-pool lint     # go vet + gofmt
```

The client and the controller are built static for amd64
(`CGO_ENABLED=0 GOARCH=amd64`), so they can be copied into the e2e VMs as is:

```
scp -F test/e2e/<vm>/.ssh-config scripts/testing/fake-cxl-pool/bin/fake-cxl-pool-client vagrant@node:/tmp/
ssh -F test/e2e/<vm>/.ssh-config vagrant@node sudo install /tmp/fake-cxl-pool-client /usr/local/bin/
```

## Running the server

```
bin/fake-cxl-pool-server [-config config.example.yaml] [-listen 127.0.0.1:9909] [-state FILE|-] [-v]
```

Without a config file the server listens on 127.0.0.1:9909, has one pool
`default` in /tmp/fake-cxl-pool (8G), discovers qemu processes every 10s
and keeps its state in /tmp/fake-cxl-pool.state.json. `-v` logs every qemu
command and HTTP request. See [config.example.yaml](config.example.yaml)
for all keys (pools, static devices, static hosts, discovery filters,
detach timeout).

### Serial numbers

The guest finds a device by its serial (`/sys/bus/cxl/devices/memN/serial`),
so serials are unique over all devices of the server. Devices created
without a serial get the next free one above the base of their kind:
`0xc1` = CXL, then `00` = present at boot (the e2e topology's local devices
are `0xc100e2e0+i`), `ae` = shared pool devices (`sharedSerialBase`,
default `0xc1ae0000`: `0xc1ae0001`, ...), `ee` = exclusive pool devices
(`exclusiveSerialBase`, default `0xc1ee0000`: `0xc1ee0001`, ...). The kind
is decided when the serial is assigned; a later `PATCH shared` keeps it.

VMs with slirp networking (the e2e VMs) reach the host loopback at
192.168.76.2, which is the client's default server:
`http://192.168.76.2:9909`. Override with `--server URL` or
`$FAKE_CXL_POOL_SERVER`. On the host use `http://127.0.0.1:9909`.

### Discovery of qemu VMs

The server scans `/proc/*/cmdline` for `qemu-system-*`:

- host name = `<name>` of `.vagrant/machines/<name>/` in a `-drive` path
  (== VM hostname), else `-name guest=<name>`; uuid from `-uuid`.
- monitor sockets from `-qmp unix:...`, `-monitor unix:...` and
  `-chardev socket,path=...` + `-mon chardev=...,mode=control|readline`.
  Relative paths are resolved against the vagrant project directory (the
  e2e output dir): qemu `-daemonize` chdirs to `/`, so `/proc/PID/cwd` is
  useless. Socket paths close to the 108 byte `sun_path` limit are
  connected through `/proc/self/fd/N/<name>` of their directory.
- QMP is preferred (`qmp.sock`); `qmp-e2e.sock` is never used, it is the
  test framework's (`vm-qmp`). A QMP socket serves one client at a time; the
  server keeps one persistent QMP connection per VM, so it never misses a
  `DEVICE_DELETED` event. HMP (`monitor.sock`) is used only when there is no
  QMP socket, with a new connection per command like `vm-monitor` does.
- pre-declared backends `beram_<memdev>__bus_<bus>__sn_<serial>` and
  `befile_...` (test/e2e/lib/topology2qemuopts.py) become *local* devices of
  that VM (`scope: local`): attach plugs them into their own bus with their
  own serial and never object-adds or object-deletes them. A `befile_`
  backend whose file is declared in several VMs is one shared device bound to
  all of them (`localHosts`); if its file is a configured pool device, the
  pool device is bound to the VM.
- a host bridge's NUMA node and fixed memory window size come from qemu
  (`qom-get /machine cxl-fmw`) or from the command line.
- `hotRemoveCapable: false` means stock qemu: it cannot complete hot-removal
  from a `cxl-downstream` port (no power controller); the device stays in
  qemu as a zombie, its slot and backend can never be reused until the VM
  restarts. Use the patched qemu (`qemu_bin=...` in test/e2e) for
  detach/re-attach.

Devices that someone else plugged (for instance `vm-cxl-hotplug`) and that
use a known backend are *adopted* as attachments (`adopted: true`).

## Client CLI

```
fake-cxl-pool-client [--server URL] [-o table|json] COMMAND
  status | pools [NAME] | hosts [NAME] | whoami | rescan
  devices [NAME] [--shared] [--free] [--host H]
  create --size 256M [--shared] [--name N] [--pool P] [--serial 0x..] [--label k=v]
  delete NAME [--force]
  attach DEVICE (--self | --host HOST) [--slot BUS] [--numa N] [--owner O] [--no-wait] [--force]
  detach DEVICE (--self | --host HOST) [--timeout 15s] [--no-wait] [--owner O] [--force]
  attachments [--self | --host H] [--device D]
  allocate DEVICE --owner O [--note TEXT] ; release DEVICE [--owner O] [--force]
  events
  guest wait DEVICE [--timeout 30s]          # prints memN when the serial shows up
  guest memdev DEVICE
  guest region create DEVICE --mode devdax|ram [--decoder decoderX.Y]
  guest online DEVICE [--movable]
  guest info DEVICE
  guest release DEVICE
```

`--host` takes a host name or uuid. `--self` resolves the VM the client
runs in from its hostname and system uuid (`/sys/class/dmi/id/product_uuid`,
else `/etc/machine-id`; uuids are compared without dashes). `guest`
commands take a device name (the serial is looked up from the server) or a
serial (`0xc1ee0001`, no server needed) and must run as root. Exit codes: 0
ok, 1 error, 2 usage, 3 conflict or timeout (the device is still held).

### Sharing a device between two VMs (devdax)

```
# anywhere (host or VM):
fake-cxl-pool-client create --size 256M --shared --name shared0
fake-cxl-pool-client attach shared0 --host vm-a
fake-cxl-pool-client attach shared0 --host vm-b
# in each VM:
sudo fake-cxl-pool-client guest wait shared0
sudo fake-cxl-pool-client guest region create shared0 --mode devdax   # -> /dev/daxN.M
#   apps: open /dev/daxN.M, mmap MAP_SHARED (length multiple of 2M)
# done, in each VM:
sudo fake-cxl-pool-client guest release shared0
fake-cxl-pool-client detach shared0 --self
```

Never online a shared device as system RAM in more than one VM: both
kernels would use the same memory (silent corruption). devdax mmap needs a
guest kernel with `CONFIG_FS_DAX=y`.

### Pooling an exclusive device (system RAM)

```
fake-cxl-pool-client attach pooled0 --self
sudo fake-cxl-pool-client guest wait pooled0
sudo fake-cxl-pool-client guest region create pooled0 --mode ram
sudo fake-cxl-pool-client guest online pooled0 --movable   # a new NUMA node
...
sudo fake-cxl-pool-client guest release pooled0            # offline, destroy region, disable memdev
fake-cxl-pool-client detach pooled0 --self
```

Release in the guest **before** detach. `device_del` makes the guest remove
the PCI device after about 5 s whatever its state. If its memory was still
online, qemu can never finalize the device: no `DEVICE_DELETED`, and the
backend stays mapped into that guest until the VM restarts. The server then
reports the attachment `failed` (exit code 3 / HTTP 409), keeps it listed,
and keeps an exclusive device in state `error`, so that it is not given to
another VM. `detach --force` forgets a failed attachment. A timed-out
attachment clears itself if qemu deletes the device later.

## fake-cxl-pool-controller

The cluster side of the DRA driver `cxl-pool.generic`. The node side is the
`cxl-pool.generic` helper of kubelet-cxl-plugin in
intel-resource-drivers-for-kubernetes; the contract between the two is
[plan-2-dra/10-contract.md](plan-2-dra/10-contract.md), shipped as
doc/cxl/POOL.md in the driver repository. The controller:

- publishes the pool devices of the server (`GET /devices?scope=pool`) as one
  cluster-scoped ResourceSlice (`allNodes`) of pool `fake-cxl-pool`.
  Exclusive devices have `capacity.memory`, shared devices
  `allowMultipleAllocations` and `capacity.hosts` (how many nodes may attach
  them); all have `bindsToNode` and the binding conditions
  `cxl-pool.generic/Attached` / `cxl-pool.generic/AttachFailed`. Device
  names become DNS labels; devices in state `error` are not published. The
  slice is updated when the device list changes (server events, or every
  sync interval) and deleted when the controller stops (it has no owner,
  nothing else garbage collects it).
- attaches a device when the scheduler allocates it to a claim: node =
  `allocation.nodeSelector` (`metadata.name`), host = the server host whose
  uuid is the Node's `status.nodeInfo.systemUUID` (lower case, dashes
  ignored), else the host whose name is the node name. Then it writes
  `cxl-pool.generic/Attached=True` and the device data (serial, shared, size,
  host, attachment) into `claim.status.devices[]`, which releases the
  scheduler's binding wait and tells the node plugin which memdev to wait
  for. A node that is not a pool host, a 409 or another error gives
  `AttachFailed=True` (reason `NoHost`, `Conflict`, `Timeout`,
  `AttachError`), and the scheduler allocates again.
- detaches a device when no allocated claim wants it on that node any more.
  The node plugin has released it in NodeUnprepare by then; if the guest
  still holds it, the attachment stays `detaching` (or `failed`) and the
  controller only logs it.

The attachment owner is `k8s:resourceclaim/<claim uid>` (`-owner-prefix`).
The controller is stateless: it only touches attachments with its owner
prefix on hosts that are Nodes of its cluster, never adopted ones or those
made with the CLI, so a restart just re-confirms existing attachments.
Each cluster runs one controller; several clusters (for instance the
single-node clusters of n4-cxl-shared-1 and -2) may share one server, and
then share its devices, including shared devices attached to nodes of
different clusters.

```
fake-cxl-pool-controller [-server http://192.168.76.2:9909] [-kubeconfig FILE]
    [-driver-name cxl-pool.generic] [-pool-name fake-cxl-pool]
    [-sync-interval 10s] [-attach-timeout 60s] [-detach-timeout 60s]
    [-shared-hosts 4] [-owner-prefix k8s:] [-v]
```

`-server` defaults to `$FAKE_CXL_POOL_SERVER`, `-kubeconfig` to
`$KUBECONFIG`, else the in-cluster config. In the e2e VMs:

```
systemd-run --unit fake-cxl-pool-controller /usr/local/bin/fake-cxl-pool-controller -kubeconfig /root/.kube/config -v
```

[deploy/fake-cxl-pool-controller.yaml](deploy/fake-cxl-pool-controller.yaml)
runs it as a Deployment with a ServiceAccount and the RBAC it needs
(`resourceclaims/driver` `arbitrary-node:update` for `cxl-pool.generic`,
`resourceclaims/status`, `resourceslices`, nodes, events).

## REST API

Base URL `http://HOST:9909/api/v1`, JSON, errors as
`{"error": "...", "code": "NotFound|Conflict|InvalidArgument|Unavailable|Internal"}`.
The authoritative spec is plan/20-rest-api.md (also lists the deviations of
this implementation); routes are in [pkg/api/routes.go](pkg/api/routes.go):

```
GET    /status
GET    /pools                     GET /pools/{name}
GET    /hosts                     GET /hosts/{name|uuid}     POST /hosts/rescan
GET    /hosts/resolve?hostname=H&uuid=U
GET    /devices?shared=&state=&host=&pool=&scope=
POST   /devices                   GET|PATCH|DELETE /devices/{name}[?force=true]
PUT    /devices/{name}/allocation DELETE /devices/{name}/allocation[?owner=&force=]
POST   /devices/{name}/attachments                       {"host": ..., "slot", "numaNode", "owner", "wait", "timeout", "force"}
GET    /devices/{name}/attachments[/{host}]
DELETE /devices/{name}/attachments/{host}?wait=&timeout=&owner=&force=
GET    /attachments?host=&device=  GET /attachments/{device@host}
GET    /events                    (text/event-stream)
```

Attach: 201 attached, 200 already attached, 202 attaching (`wait: false`),
409 sharing/ownership/slot/capacity conflicts, 503 qemu errors. An
attachment records the `owner` of the attach request that created it
(fake-cxl-pool-controller filters its own attachments by it). Detach: 200
detached, 202 detaching (`wait=false`), 409 the guest did not release the
device in time (attachment `failed`).

## Layout

```
cmd/fake-cxl-pool-server   server main
cmd/fake-cxl-pool-client   CLI
cmd/fake-cxl-pool-controller  DRA pool controller (cxl-pool.generic) main
pkg/api                    JSON types, routes, errors, size/serial units
pkg/client                 Go client library
pkg/controller             DRA pool controller: ResourceSlice publisher, attach/detach reconciler
pkg/server                 config, state machine, persistence, HTTP handlers
pkg/qemu                   Monitor interface: QMP (persistent, events, QOM tree), HMP
                           (text protocol, info qtree parser), discovery, fake monitor
pkg/pool                   pools, backing files, serials
pkg/cxl/memctl in nri-plugins  guest side: sysfs + cxl/daxctl
deploy/                    Kubernetes manifests (controller Deployment + RBAC)
plan/                      design and findings of the workstreams
plan-2-dra/                DRA driver extension, controller, e2e: specs and findings
proto/                     qemu prototyping scripts (WS3)
```
