# fake-cxl-pool REST API v1

Status: v1 spec written 2026-10-02 (Fable); host uuid added after the KEP-5007/CoHDI research. Implementation: WS5 (50-server-client.md).

Design inputs: UnifabriX Maxview API (memory_resources, viewports with
shared/persist, attach/detach to port+HDM, allocate/free, GET/POST/PATCH/DELETE,
/api/v1), CoHDI Composable Resource API (machines, resources, attach/detach to a
node), Kubernetes DRA (devices with attributes and capacity, claims, binding
conditions). Simplifications: our "HDM" is a qemu CXL slot (cxl-downstream or
cxl-rp bus without a device); our "viewport" is a device = one backing file.

Base URL: http://HOST:9909/api/v1 . JSON request/response bodies. Errors:
`{"error": "...", "code": "NotFound|Conflict|InvalidArgument|Unavailable|Internal"}`
with matching HTTP status (404/409/400/503/500).

## Resources

### Server status
- `GET /api/v1/status` -> `{"version": "...", "qemu": {...}, "hosts": N, "devices": N, "attachments": N, "uptime": "..."}`

### Pools (memory resources: where device backing files live)
- `GET /api/v1/pools` -> `[Pool]`
- `GET /api/v1/pools/{name}` -> `Pool`
```
Pool {
  name: string            # e.g. "default"
  dir: string             # host directory of backing files
  capacity: int64         # bytes, max sum of device sizes created in this pool
  used: int64             # bytes, sum of device sizes
  free: int64
  sharable: bool          # whether shared devices may be created here (Maxview: sharable memory resource)
}
```

### Hosts (consumers: qemu VMs)
- `GET /api/v1/hosts` -> `[Host]`
- `GET /api/v1/hosts/{name}` -> `Host`
- `POST /api/v1/hosts/rescan` -> rediscover qemu processes (202 with `[Host]`)
- `GET /api/v1/hosts/resolve?hostname=X&uuid=U` -> `Host` (404 if unknown). Used by clients for "--self": uuid (SMBIOS system UUID, /sys/class/dmi/id/product_uuid) matches first, then hostname == name or its first label.
- Wherever a request names a host (AttachRequest.host, .../attachments/{host}, ?host=) either Host.name or Host.uuid is accepted.
```
Host {
  name: string            # VM name == guest hostname, e.g. n4-cxl-shared-1-fedora-43-containerd
  uuid: string            # SMBIOS system UUID from qemu "-uuid" ("" if not set); kubelet reports it as node.status.nodeInfo.systemUUID
  pid: int                # qemu pid, 0 if not running
  state: "running"|"stopped"|"unreachable"
  control: "qmp"|"hmp"    # which monitor the server uses
  qmp: string             # socket path (may be empty)
  hmp: string
  qemuVersion: string
  source: "config"|"discovered"
  hostBridges: [ { id: "cxlhb0", numaNode: 0, fmwSize: int64, attachedBytes: int64 } ]
  slots: [ Slot ]
  attachments: [ Attachment ]   # devices currently attached to this host
  localDevices: [string]        # names of devices that are local to this host (pre-declared beram_* backends)
}
Slot {
  bus: string             # qemu bus id to pass as cxl-type3 bus=, e.g. cxlsw_ds0_usrp0hb0 or cxlrp0hb0
  kind: "downstream"|"rootport"
  hostBridge: string      # cxlhb0
  numaNode: int
  device: string          # qemu device id occupying it, "" if free
  attachment: string      # attachment id, "" if free / not managed by the server
}
```

### Devices (pool memory devices = backing files / ram objects)
- `GET /api/v1/devices` -> `[Device]` ; filters `?shared=true|false&state=free|attached&host=NAME`
- `POST /api/v1/devices` body `DeviceCreate` -> 201 `Device` (dynamic creation, Maxview "viewport new + allocate")
- `GET /api/v1/devices/{name}` -> `Device`
- `PATCH /api/v1/devices/{name}` body `{shared?: bool, labels?: {..}}` -> `Device` (only when not attached)
- `DELETE /api/v1/devices/{name}` -> 204 (409 if attached; `?force=true` detaches first)
```
Device {
  name: string            # unique, DNS-label-like
  serial: string          # "0xc1f00001", guest-visible; identical in every VM it is attached to
  size: int64             # bytes
  shared: bool            # may be attached to several hosts at once
  backend: "file"|"ram"   # file: memory-backend-file,share=on,mem-path=...; ram: memory-backend-ram (host-local only)
  path: string            # backing file (backend=file)
  pool: string            # pool name ("" for host-local ram devices)
  scope: "pool"|"local"   # local devices exist only inside one qemu (beram_* objects of today's VMs)
  localHost: string       # for scope=local
  state: "free"|"attached"|"attaching"|"detaching"|"error"
  allocation: Allocation|null
  attachments: [Attachment]
  labels: {string: string}
  created: time
}
DeviceCreate {
  name?: string           # generated if omitted ("devN")
  size: string|int64      # "256M", "1G" or bytes
  shared?: bool           # default false
  pool?: string           # default "default"
  serial?: string         # default: next free from the server's range
  labels?: {..}
}
```

### Allocation (reservation, for DRA controllers; optional)
Allocation records that a logical owner (e.g. a Kubernetes ResourceClaim UID)
holds the device. Attach/detach of an allocated device require the same owner
(`owner` field in AttachRequest) unless `force=true`.
- `PUT /api/v1/devices/{name}/allocation` body `{"owner": "k8s:resourceclaim/<uid>", "note": "..."}` -> `Allocation` (409 if owned by someone else)
- `DELETE /api/v1/devices/{name}/allocation` -> 204
```
Allocation { owner: string, note: string, since: time }
```

### Attachments (device <-> host hotplug state)
- `GET /api/v1/attachments` -> `[Attachment]` ; filters `?host=NAME&device=NAME`
- `POST /api/v1/devices/{name}/attachments` body `AttachRequest` -> 201 `Attachment` (state attached) or 202 (`wait=false`, state attaching)
- `GET /api/v1/devices/{name}/attachments/{host}` -> `Attachment`
- `DELETE /api/v1/devices/{name}/attachments/{host}?wait=true|false&timeout=30s` -> 200 `Attachment` (state detached) / 202 (detaching) / 409 when the guest has not released the device within timeout (state stays "detaching"; the server keeps waiting for DEVICE_DELETED in background and finalizes later)
- `GET /api/v1/attachments/{id}` -> `Attachment`
```
AttachRequest {
  host: string            # target VM name (required)
  slot?: string           # qemu bus id, default: first free slot (prefer numaNode if given)
  numaNode?: int          # prefer slots under a host bridge with this NUMA node
  owner?: string          # must match device.allocation.owner if allocated
  wait?: bool             # default true: return when qemu accepted device_add
  timeout?: string        # default "30s"
}
Attachment {
  id: string              # "<device>@<host>"
  device: string
  host: string
  serial: string
  slot: Slot
  qemuDeviceId: string    # id= of the cxl-type3 (unique per hotplug: <device>.hpN)
  qemuObjectId: string    # memory backend object id
  state: "attaching"|"attached"|"detaching"|"detached"|"failed"
  error: string
  created, updated: time
}
```

Semantics:
- A non-shared device has at most one attachment; a second POST -> 409 Conflict.
- A shared device may have one attachment per host (same serial everywhere).
- Attach is idempotent per (device, host): POST on an existing attached
  attachment returns 200 with it.
- Attach steps (server): pick slot -> object-add backend (file: share=on,
  mem-path=path,size=size; local ram: already exists) -> device_add
  cxl-type3,bus=slot,volatile-memdev=obj,id=qemuDeviceId,sn=serial -> attached.
  On device_add failure: object-del, state failed, 503 with qemu error text.
- Detach steps: device_del qemuDeviceId -> wait DEVICE_DELETED (QMP) or poll
  "info qtree" (HMP) until the device is gone -> object-del backend (pool
  devices only) -> detached, attachment removed. The guest must have released
  the device (offline memory, destroy region, disable memdev) or the event
  never arrives: that is reported as 409 after timeout.

### Events
- `GET /api/v1/events` -> text/event-stream of `{type: "attachment.updated"|"device.updated"|"host.updated", object: ...}` (nice to have, phase 2)

## Client CLI (fake-cxl-pool-client)

```
fake-cxl-pool-client [--server URL] [-o json|table] <command>
  status
  hosts [NAME]
  whoami                           # resolve this VM (hostname) to a Host
  devices [NAME] [--shared] [--free]
  create --size 256M [--shared] [--name N] [--pool P] [--serial 0x..]
  delete NAME [--force]
  attach DEVICE (--self | --host HOST) [--slot BUS] [--numa N] [--owner O] [--no-wait]
  detach DEVICE (--self | --host HOST) [--timeout 30s] [--no-wait]
  attachments [--host H] [--device D]
  allocate DEVICE --owner O ; release DEVICE
  guest wait DEVICE [--timeout 30s]      # wait until /sys/bus/cxl/devices/mem*/serial == device serial appears in this VM
  guest memdev DEVICE                    # print memN name of the device in this VM
  guest region create DEVICE --mode devdax|ram [--decoder decoderX.Y]  # cxl create-region ... ; devdax: ensure dax device bound to device_dax
  guest online DEVICE [--movable]        # online all memory blocks of the region (mode ram)
  guest release DEVICE                   # offline blocks, destroy region, disable memdev: makes detach possible
```
URL default: $FAKE_CXL_POOL_SERVER, else http://192.168.76.2:9909 .
Exit codes: 0 ok, 1 error, 2 usage, 3 conflict/timeout (device still held by guest).

## Server configuration (YAML)

```yaml
listen: 127.0.0.1:9909
serialBase: 0xc1f00000          # serials for devices created without one
pools:
  - name: default
    dir: /tmp/fake-cxl-pool      # created if missing; backing files <name>.raw
    capacity: 8G
    sharable: true
devices:                          # static inventory, created at startup if missing
  - name: shared0
    size: 256M
    shared: true
    pool: default                 # file: /tmp/fake-cxl-pool/shared0.raw
    serial: 0xc1f0ee00
  - name: pooled0
    size: 512M
    file: /tmp/fake-cxl-pool/pooled0.raw   # explicit path allowed
hosts:                            # static hosts; discovery adds more
  - name: n4-cxl-shared-1-fedora-43-containerd
    uuid: 6ba7b810-9dad-11d1-80b4-00c04fd430c8   # optional, else from -uuid
    qmp: /home/akervine/.../n4-cxl-shared-1-fedora-43-containerd/qmp.sock
    hmp: /home/akervine/.../n4-cxl-shared-1-fedora-43-containerd/monitor.sock
discovery:
  qemu: true                      # scan /proc/*/cmdline for qemu-system-*; name from .vagrant/machines/<name>/, sockets from -qmp/-monitor/-chardev+-mon (relative to /proc/PID/cwd)
  interval: 10s
  localDevices: true              # expose pre-declared beram_cxl_memdev* backends as scope=local devices
detachTimeout: 30s
```

## Deviations (implementation, WS5 agent C, 2026-10-02)

Additions are backwards compatible; changes of behaviour are marked CHANGED.

Types
- Host: `hotRemoveCapable: bool` (coordinator request: false = stock qemu,
  `qom-get <cxl-downstream> power_controller_present` not found), `error`
  (last monitor error, omitted if none). `uuid` as in the spec; uuids match
  case-insensitively and without dashes (so /etc/machine-id and kubelet's
  systemUUID format match the qemu -uuid).
- HostBridge.fmwSize comes from `qom-get /machine cxl-fmw` (cmdline fallback);
  attachedBytes includes failed (leaked) attachments.
- Slot: `reservedFor` = the local device whose pre-declared backend names
  this bus (`..._bus_<slot>_...`). Such slots are used for other devices only
  when nothing else is free. CLI FREE-SLOTS counts slots that are free and
  not reserved.
- Device: `static` (from the config file), `localHosts` (a befile_ backend
  pre-declared in several VMs is ONE shared local device bound to all of
  them; `localHost` is the first). Local device names: `<host>.memdevN` for
  `beram_cxl_memdevN__...`, file basename for `befile_...` (or the pool device
  with the same file, which then gets a binding to that VM).
- Attachment: `adopted: true` for cxl-type3 devices someone else plugged
  (e.g. vm-cxl-hotplug) that use a known backend; found from the device tree.
- CHANGED: `qemuObjectId` = `fcp_<device>.hp<N>` (same string as the device
  id) instead of `fcp_<device>`: unique per attachment, because stock qemu
  can never object-del a backend that was mapped once, and a later attach of
  the same device to the same VM would collide with the leftover object.
- Error body: optional `object` = the current Attachment for 409/503 of
  attach/detach (e.g. state "failed" after a detach timeout).
- Status: `qemu: {discovery: bool, versions: {host: version}}`, `started`, `stateFile`.

Semantics
- CHANGED (coordinator, from WS3 Q6): detach waits `timeout` (default 15s,
  config detachTimeout) for qemu to delete the device (QMP DEVICE_DELETED on
  the persistent connection, or device gone from QOM/qtree). On timeout the
  attachment becomes `failed` with error "guest did not release the device
  ...", the response is 409 with the attachment, device_del is never sent
  again (a repeated DELETE is 409; `?force=true` forgets the record). A
  failed attachment of an exclusive device puts the device in state `error`
  (not attachable anywhere); for a shared device only that attachment is
  affected (device `error` only if it has no other attachment). It is cleared
  when the qemu pid goes away, or automatically if qemu deletes the device
  later (background check every 2s). If the device is gone from qemu but
  `info mtree` still shows `cxl-direct-mapping-alias-N @<backend>`, the guest
  kept the memory: the attachment stays `failed` with error "leaked: ...".
  With `wait=false` the same applies after `timeout` in the background.
- Attach rejects with 409 when the sum of device sizes under a host bridge
  would exceed its fixed memory window; device sizes must be multiples of
  256M (400 on POST /devices, config error).
- DELETE /devices/{name} of a config or local device: 409 (only API-created
  devices can be deleted; their backing file is removed).
- PATCH labels replace all labels.
- `?host=` on GET /devices: devices attached to OR local to the host.
- Attach/detach of an allocated device: `owner` (body / `?owner=`) must
  match unless `force` (AttachRequest.force, `?force=true`).
  DELETE .../allocation accepts `?owner=` (checked if given) and `?force=`.
- Hosts restored from the state file that discovery does not find at the
  first scan are forgotten; hosts that stop while the server runs stay as
  `stopped` (attachments dropped).

Extra routes / parameters
- GET /devices/{name}/attachments; GET /devices?pool=&scope=;
  GET /hosts[/{name}]?cached=true (skip the live device tree query).

Config
- `stateFile` (default `<first pool dir>.state.json`, "-" = none),
  `discovery.names` (path.Match patterns of VM names), `hosts[].control`
  (qmp|hmp, force the protocol), `detachTimeout` default 15s. Sockets named
  `qmp-e2e.sock` are never used (test framework's vm-qmp). Relative socket
  paths resolve against the vagrant project dir, not /proc/PID/cwd (qemu
  -daemonize chdirs to /).

CLI
- Extra: `pools [NAME]`, `rescan`, `events`, `guest info DEVICE`,
  `create --label k=v`, `attach --timeout --force`, `detach --owner --force`,
  `release --owner --force`, `attachments --self`, global `-v`.
- `--self` sends hostname and uuid (/sys/class/dmi/id/product_uuid, else
  /etc/machine-id). `guest` commands accept a serial (0x...) instead of a
  device name (then no server is needed).
- After the code review (51): config devices take `shared`/labels from the
  config on every start (PATCH of a config device lasts until restart);
  DELETE /devices/{name} of an allocated device needs `?force=true` (409);
  a pool device may not have the serial of a local device of the host it is
  attached to (409 on create and attach); a slot reserved for a local device
  is chosen only if no unreserved slot is free, before the NUMA preference;
  an interleaved fixed memory window counts size/targets per host bridge; a
  detach that cannot check the backend mapping returns 202 and completes in
  the background.
