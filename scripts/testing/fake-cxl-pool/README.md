# fake-cxl-pool

A fake CXL memory pooling and sharing appliance for testing on one host:

- `fake-cxl-pool-server` runs on the host. It owns memory devices (backing
  files in pool directories) and hotplugs/hot-removes them as `cxl-type3`
  devices into running qemu VMs over their QMP or HMP monitor sockets, without
  restarting the VMs.
- `fake-cxl-pool-client` (CLI) and `pkg/client` (Go library) talk to the
  server's REST API. In a VM, the client also prepares hotplugged memory for
  use and releases it before detach (`guest` commands).

A device may be *exclusive* (attached to one VM, used as system RAM there) or
*shared* (the same backing file attached to several VMs, same serial in
every VM, used as devdax).

## Build and test

```
make -C scripts/testing/fake-cxl-pool          # bin/fake-cxl-pool-server, bin/fake-cxl-pool-client
make -C scripts/testing/fake-cxl-pool test     # unit tests (go test -race)
make -C scripts/testing/fake-cxl-pool lint     # go vet + gofmt
```

The client is built static for amd64 (`CGO_ENABLED=0 GOARCH=amd64`), so it
can be copied into the e2e VMs as is:

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
serial (`0xc1f00001`, no server needed) and must run as root. Exit codes: 0
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
409 sharing/ownership/slot/capacity conflicts, 503 qemu errors. Detach: 200
detached, 202 detaching (`wait=false`), 409 the guest did not release the
device in time (attachment `failed`).

## Layout

```
cmd/fake-cxl-pool-server   server main
cmd/fake-cxl-pool-client   CLI
pkg/api                    JSON types, routes, errors, size/serial units
pkg/client                 Go client library
pkg/server                 config, state machine, persistence, HTTP handlers
pkg/qemu                   Monitor interface: QMP (persistent, events, QOM tree), HMP
                           (text protocol, info qtree parser), discovery, fake monitor
pkg/pool                   pools, backing files, serials
pkg/guest                  guest side: sysfs + cxl/daxctl
plan/                      design and findings of the workstreams
proto/                     qemu prototyping scripts (WS3)
```
