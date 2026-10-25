#!/usr/bin/env python3
"""Observations of test90-gofmbt-reliability (plan-13, 04-contract.txt 6).

Usage:
  mbt-observe.py vm [--ns NS] [--cluster --nodes ID=NODE,... --units P=UNIT,...
                     [--pools P=POOL,...]
                     [--inspected UID:RESTARTS,...]]
      In a VM, as root (mbt.source.sh installs it as /usr/local/bin/
      mbt-observe.py): print one JSON line {"vm": OBS} where OBS is the
      per-VM observation of contract 6.3: boot id, CXL memdevs, regions
      and their dax devices, the CXL ports with committed decoders
      (amendment A10), NUMA nodes, the state files of the driver,
      the device names of the CDI specs, and the cpuset.mems,
      cpuset.mems.effective and memory.high of every running container of
      namespace NS (default cxl-pool-demo).
      With --cluster (on the control plane) also "cluster": the parts of
      the settle observation (contract 6.1) that kubectl and systemd give:
      "pods" (one per mbt.slot pod, with its newest Warning event, A10),
      "companions", "others", "drivers",
      "controllers" and "inspect", the environment (and the leases of
      lease pods) of the Running and Ready slot pods whose UID:RESTARTS is
      not in --inspected (entries UID:RESTARTS[:SLOT]). ID are the VM ids
      of the model (vm2, vm1, vm0),
      NODE their Kubernetes node names; P are pool ids (a, b, c), UNIT the
      systemd units of their controllers.
  mbt-observe.py assemble --step N --poll K --nodes ID=NODE,...
                          --vm ID=FILE... --attachments P=FILE...
                          [--inspected-in FILE] [--inspected-out FILE]
                          [--summary FILE]
      On the host: merge the outputs of "vm" (FILE: what the VM printed)
      and the attachment lists of the pool servers (FILE: the JSON of
      GET /api/v1/attachments) into the settle observation of contract
      6.1, printed as one JSON line. --inspected-in has the
      UID:RESTARTS:SLOT entries inspected before (one per line),
      --inspected-out gets those of the pods that still exist plus the
      ones inspected now.
      --summary gets lines for the shell: "driver ID POD RESTARTS READY".

Python 3 standard library only. Every part is read in its own try: a part
that cannot be read is null, and the reason is in the "errors" list of the
object that has the part.

Where the data comes from:
  memdevs       /sys/bus/cxl/devices/memN: serial, ram/size + pmem/size,
                enabled = the memdev has a driver
  regions       /sys/bus/cxl/devices/regionN: size, mode (the kernel's: ram
                or pmem), the serials of the memdevs of its targets
                (targetI -> decoderE.D -> endpointE -> uport memN), node =
                target_node of its dax devices; dax = the dax devices of
                its dax region with a size (the zero-size seed device is
                left out): size, driver (kmem, device_dax or null), online
                = bytes of its memory blocks that are online
  ports         /sys/bus/cxl/devices/portN and endpointN with
                decoders_committed > 0: kind (hostbridge: a port right
                under rootR; switch: a port below one; endpoint), hb (the
                host bridge it is under: hbK for the root decoder
                decoderR.K whose target_list names the dport that is the
                host bridge's uport; the topologies of test90 have
                cxl-fmw.K -> cxlhbK), the decoders 0..N-1 (N =
                decoders_committed: committed, or pinned below a
                committed one, plan-13 bug-02) with region ("" for none),
                start and size
  nodes         /sys/devices/system/node/nodeN/meminfo MemTotal
  state         /var/lib/kubelet/plugins/cxl.nri.io/{preparedClaims,
                preparedClaimsInfo,localDevices,leases}.json and
                /var/lib/kubelet/plugins/cxl-pool.nri.io/
                preparedPoolClaims.json (a missing file is null)
  cdi           /etc/cdi/* and /var/run/cdi/*: file -> device names
  containers    crictl ps (running containers of NS) and crictl inspect:
                the cgroup v2 directory of each container is that of its
                init process (/proc/PID/cgroup). mems is cpuset.mems, or,
                when that file is empty (the cgroup sets no nodes and
                has its parent's), cpuset.mems.effective with
                mems_inherited true: never "" (amendment A11). A field
                that cannot be read is null, with an error. Left out:
                containers that are not running (crictl ps lists
                running ones; one that exits between the listing and
                the reading is dropped). assemble lists in "missing"
                every container that the pod status says runs and that
                is not here (A11)
  driverLog     the running nri-dra-driver-cxl container of the node
                (crictl): its id, pod, attempt, start, the log lines of
                its log file (status.logPath) that match "panic|fatal
                error|SIGSEGV" (count, the first 5), lendsRestored (its
                log has "NRI fence: lends restored": NRI and lending are
                up, A15) and sockets (both dra.sock files exist); the
                file is read incrementally, the position is kept in
                /run/mbt-observe (A13)
  pods[].events one "kubectl get events -n NS --field-selector
                type=Warning" per observation: the Warning events of the
                pod (by uid), newest first, at most 5: reason, message
                (at most 4000 bytes: a longer one keeps its first 1900
                and last 2000 bytes around " [...] ", so that the end,
                where the driver's reason is, stays), count,
                lastTimestamp; "event" is the first of them, null if
                none (A10, A12)
  slices        one "kubectl get resourceslices": per VM the devices of
                its cxl.nri.io slices: name, serial, shared, type (A13);
  poolSlices    from the same call, per pool id (--pools ID=POOL, default
                ID=pool-ID) its cxl-pool.nri.io slices: name, device
                names, nodes (VM ids of the nodeSelector), [] for none
                (A18)
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import threading
import time

CXL = "/sys/bus/cxl/devices"
DAX = "/sys/bus/dax/devices"
NODES = "/sys/devices/system/node"
MEMORY = "/sys/devices/system/memory"
LOCAL_DIR = "/var/lib/kubelet/plugins/cxl.nri.io"
POOL_DIR = "/var/lib/kubelet/plugins/cxl-pool.nri.io"
CDI_DIRS = ["/etc/cdi", "/var/run/cdi"]
SLOT_LABEL = "mbt.slot"
LEASE_LABEL = "cxl.nri.io/lease"
REQUESTER_LABEL = "cxl.nri.io/requester-uid"
DRIVER_LABEL = "app.kubernetes.io/name=nri-dra-driver-cxl"
DRIVER_CONTAINER = "nri-dra-driver-cxl"
POOL_DRIVER = "cxl-pool.nri.io"
MAIN = "main"
CXL_REQUEST = "/usr/local/bin/cxl-request"
EXEC_TIMEOUT = 30


def natkey(path):
    """Sort key of a path: its digits as numbers (mem2 before mem10)."""
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", path)]


def read(path):
    with open(path) as f:
        return f.read().strip()


def serial_text(value):
    """0x<lower-case hex> of a serial: a number, or hex text with or
    without 0x (sysfs, serialHex)."""
    if isinstance(value, int):
        return "0x%x" % value
    text = str(value).strip().lower()
    try:
        return "0x%x" % int(text, 16)
    except ValueError:
        return text


def run(args, timeout=30):
    env = dict(os.environ)
    if "CONTAINER_RUNTIME_ENDPOINT" not in env:
        for sock in ("/run/containerd/containerd.sock", "/run/crio/crio.sock"):
            if os.path.exists(sock):
                env["CONTAINER_RUNTIME_ENDPOINT"] = "unix://" + sock
                break
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)


def part(errors, name, fn, *args):
    """Return fn(*args), or None with an error in errors."""
    try:
        return fn(*args)
    except Exception as e:  # every part on its own
        errors.append("%s: %s: %s" % (name, type(e).__name__, e))
        return None


###
### The VM (contract 6.3)
###

def block_size():
    return int(read(MEMORY + "/block_size_bytes"), 16)


def endpoint_memdevs():
    """Endpoint id -> memdev name (endpointE/uport is the memdev)."""
    out = {}
    for p in glob.glob(CXL + "/endpoint[0-9]*"):
        try:
            out[os.path.basename(p)[len("endpoint"):]] = os.path.basename(os.readlink(p + "/uport"))
        except OSError:
            continue
    return out


def memdevs(errors):
    out = []
    for p in sorted(glob.glob(CXL + "/mem[0-9]*"), key=natkey):
        name = os.path.basename(p)
        try:
            serial = serial_text(read(p + "/serial"))
        except OSError as e:
            errors.append("memdev %s: serial: %s" % (name, e))
            serial = None
        size = 0
        for kind in ("ram", "pmem"):
            try:
                size += int(read("%s/%s/size" % (p, kind)), 0)
            except (OSError, ValueError):
                pass
        out.append({"name": name, "serial": serial, "size": size,
                    "enabled": os.path.exists(p + "/driver")})
    return out


def online_bytes(dax, bs):
    """Bytes of the memory blocks of dax device dax (daxX.Y) that are online."""
    base = DAX + "/" + dax
    ranges = []
    for m in sorted(glob.glob(base + "/mapping[0-9]*"), key=natkey):
        try:
            ranges.append((int(read(m + "/start"), 0), int(read(m + "/end"), 0)))
        except (OSError, ValueError):
            continue
    if not ranges:
        start = int(read(base + "/resource"), 0)
        size = int(read(base + "/size"), 0)
        if size <= 0:
            return 0
        ranges = [(start, start + size - 1)]
    online = 0
    for start, end in ranges:
        for b in range(start // bs, end // bs + 1):
            try:
                if read("%s/memory%d/state" % (MEMORY, b)) == "online":
                    online += bs
            except OSError:
                continue
    return online


def dax_devices(region_path, bs, errors):
    out = []
    for dr in sorted(glob.glob(region_path + "/dax_region[0-9]*"), key=natkey):
        for d in sorted(glob.glob(dr + "/dax[0-9]*.[0-9]*"), key=natkey):
            name = os.path.basename(d)
            try:
                size = int(read(d + "/size"), 0)
            except (OSError, ValueError) as e:
                errors.append("dax %s: size: %s" % (name, e))
                continue
            if size == 0:
                continue  # the seed device of the dax region
            entry = {"name": name, "size": size, "driver": None, "node": None, "online": None}
            try:
                entry["driver"] = os.path.basename(os.readlink(d + "/driver"))
            except OSError:
                pass
            try:
                entry["node"] = int(read(d + "/target_node"))
            except (OSError, ValueError):
                pass
            try:
                entry["online"] = online_bytes(name, bs) if bs else None
            except (OSError, ValueError) as e:
                errors.append("dax %s: online: %s" % (name, e))
            out.append(entry)
    return out


def regions(errors):
    eps = endpoint_memdevs()
    serials = {}
    for p in glob.glob(CXL + "/mem[0-9]*"):
        try:
            serials[os.path.basename(p)] = serial_text(read(p + "/serial"))
        except OSError:
            continue
    try:
        bs = block_size()
    except (OSError, ValueError) as e:
        errors.append("block size: %s" % e)
        bs = 0
    out = []
    for p in sorted(glob.glob(CXL + "/region[0-9]*"), key=natkey):
        name = os.path.basename(p)
        r = {"name": name, "serials": [], "mode": None, "size": None, "node": None, "dax": []}
        try:
            r["size"] = int(read(p + "/size"), 0)
        except (OSError, ValueError) as e:
            errors.append("region %s: size: %s" % (name, e))
        try:
            r["mode"] = read(p + "/mode")
        except OSError:
            pass
        targets = sorted(glob.glob(p + "/target[0-9]*"), key=natkey)
        for t in targets:
            try:
                dec = read(t)
            except OSError:
                continue
            m = re.fullmatch(r"decoder(\d+)\.\d+", dec)
            mem = eps.get(m.group(1)) if m else None
            if mem:
                r["serials"].append(serials.get(mem, mem))
        r["dax"] = dax_devices(p, bs, errors)
        nodes = sorted(set(d["node"] for d in r["dax"] if d["node"] is not None))
        if nodes:
            r["node"] = nodes[0]
            if len(nodes) > 1:
                errors.append("region %s: dax devices on nodes %s" % (name, nodes))
        out.append(r)
    return out


def port_number(name):
    m = re.search(r"(\d+)$", name)
    return m.group(1) if m else ""


def host_bridges():
    """The real path of a host bridge's uport -> hbK: the host bridge that
    root decoder decoderR.K targets (target_list: ids of dports of rootR,
    dportID links to the host bridge)."""
    out = {}
    for root in glob.glob(CXL + "/root[0-9]*"):
        rid = port_number(root)
        for rd in glob.glob("%s/decoder%s.[0-9]*" % (root, rid)):
            k = rd.rsplit(".", 1)[1]
            try:
                targets = [t.strip() for t in read(rd + "/target_list").split(",") if t.strip()]
            except OSError:
                continue
            for t in targets:
                dport = "%s/dport%s" % (root, t)
                if os.path.exists(dport):
                    out[os.path.realpath(dport)] = "hb" + k
    return out


def ports(errors):
    """CXL ports and endpoints with committed decoders (amendment A10)."""
    hbs = host_bridges()
    out = []
    paths = glob.glob(CXL + "/port[0-9]*") + glob.glob(CXL + "/endpoint[0-9]*")
    for p in sorted(paths, key=natkey):
        name = os.path.basename(p)
        try:
            committed = int(read(p + "/decoders_committed"))
        except (OSError, ValueError) as e:
            errors.append("port %s: decoders_committed: %s" % (name, e))
            continue
        if committed <= 0:
            continue
        real = os.path.realpath(p).split("/")
        roots = [i for i, c in enumerate(real) if re.fullmatch(r"root\d+", c)]
        chain = real[roots[-1] + 1:] if roots else [name]
        if name.startswith("endpoint"):
            kind = "endpoint"
        elif len(chain) == 1:
            kind = "hostbridge"
        else:
            kind = "switch"
        hb = None
        if roots and len(chain) >= 1:
            hbport = "/".join(real[:roots[-1] + 2])
            try:
                hb = hbs.get(os.path.realpath(hbport + "/uport"))
            except OSError:
                pass
        entry = {"port": name, "kind": kind, "hb": hb, "committed": committed, "decoders": []}
        num = port_number(name)
        for i in range(committed):
            d = "%s/decoder%s.%d" % (p, num, i)
            dec = {"name": os.path.basename(d), "region": None, "start": None, "size": None}
            try:
                dec["region"] = read(d + "/region")
            except OSError:
                dec["region"] = ""
            try:
                dec["start"] = int(read(d + "/start"), 0)
                dec["size"] = int(read(d + "/size"), 0)
            except (OSError, ValueError) as e:
                errors.append("port %s: %s: %s" % (name, dec["name"], e))
            entry["decoders"].append(dec)
        out.append(entry)
    return out


def numa_nodes():
    out = {}
    for p in sorted(glob.glob(NODES + "/node[0-9]*"), key=natkey):
        n = os.path.basename(p)[len("node"):]
        with open(p + "/meminfo") as f:
            for line in f:
                w = line.split()
                if len(w) >= 4 and w[2] == "MemTotal:":
                    out[n] = {"memtotal": int(w[3]) * 1024}
                    break
    return out


def json_file(path):
    """The JSON of path, None if it does not exist. The driver writes
    preparedClaims.json in place: retry a torn read."""
    last = None
    for _ in range(4):
        try:
            with open(path) as f:
                text = f.read()
        except FileNotFoundError:
            return None
        try:
            return json.loads(text)
        except ValueError as e:
            last = e
            time.sleep(0.05)
    raise ValueError("%s: %s" % (path, last))


def keys(obj):
    return None if obj is None else sorted((obj or {}).keys())


def local_devices(obj):
    if obj is None:
        return None
    out = {"bootID": obj.get("bootID"), "devices": []}
    for d in obj.get("devices") or []:
        serial = d.get("serial")
        if serial is None and d.get("serialHex"):
            serial = int(str(d["serialHex"]), 16)
        out["devices"].append({
            "serial": serial_text(serial) if serial is not None else None,
            "memdev": d.get("memdev"),
            "region": d.get("region") or "",
            "node": d.get("node"),
            "shared": bool(d.get("shared")),
            "dax": d.get("dax") or "",
            "claims": d.get("claims") or {},
        })
    return out


def state(errors):
    out = {"prepared": None, "info": None, "pool": None, "localDevices": None, "leases": None}
    files = [
        ("prepared", LOCAL_DIR + "/preparedClaims.json", keys),
        ("info", LOCAL_DIR + "/preparedClaimsInfo.json", keys),
        ("pool", POOL_DIR + "/preparedPoolClaims.json", keys),
        ("localDevices", LOCAL_DIR + "/localDevices.json", local_devices),
        ("leases", LOCAL_DIR + "/leases.json", lambda o: o),
    ]
    for key, path, fn in files:
        try:
            out[key] = fn(json_file(path))
        except Exception as e:
            errors.append("state %s: %s" % (key, e))
    return out


def unquote(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def cdi_names(path):
    """The device names of the CDI spec file path (YAML or JSON)."""
    with open(path) as f:
        text = f.read()
    if path.endswith(".json"):
        return [d.get("name") for d in json.loads(text).get("devices") or []]
    names, in_devices, item = [], False, None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and not s.startswith("-"):
            in_devices, item = s.split(":", 1)[0] == "devices", None
            continue
        if not in_devices:
            continue
        if s.startswith("- ") or s == "-":
            if item is None:
                item = indent
            if indent == item:
                s = s[1:].strip()
                if s.startswith("name:"):
                    names.append(unquote(s[len("name:"):]))
                continue
        if item is not None and indent == item + 2 and s.startswith("name:"):
            names.append(unquote(s[len("name:"):]))
    return names


def cdi(errors):
    out = {}
    for d in CDI_DIRS:
        for path in sorted(glob.glob(d + "/*")):
            if not os.path.isfile(path):
                continue
            try:
                out[path] = cdi_names(path)
            except Exception as e:
                errors.append("cdi %s: %s" % (path, e))
                out[path] = None
    return out


def json_objects(text):
    """The JSON values of text: one value, a list, or concatenated values."""
    dec, out, text = json.JSONDecoder(), [], text.strip()
    while text:
        obj, end = dec.raw_decode(text)
        out.extend(obj if isinstance(obj, list) else [obj])
        text = text[end:].strip()
    return out


def crictl_inspect(ids):
    if not ids:
        return []
    r = run(["crictl", "inspect", "-o", "json"] + ids)
    if r.returncode == 0:
        return json_objects(r.stdout)
    # A container went away after the listing: the others one by one.
    out = []
    for i in ids:
        r = run(["crictl", "inspect", "-o", "json", i])
        if r.returncode == 0:
            out.extend(json_objects(r.stdout))
    return out


def containers(ns, errors):
    r = run(["crictl", "ps", "-o", "json", "--namespace", "^%s$" % re.escape(ns)])
    if r.returncode != 0:
        raise RuntimeError("crictl ps: %s" % r.stderr.strip()[-300:])
    listed = json.loads(r.stdout or "{}").get("containers") or []
    out = []
    for c in crictl_inspect([c["id"] for c in listed]):
        st = c.get("status") or {}
        if st.get("state") != "CONTAINER_RUNNING":
            continue
        lb = st.get("labels") or {}
        md = st.get("metadata") or {}
        entry = {
            "ns": lb.get("io.kubernetes.pod.namespace"),
            "pod": lb.get("io.kubernetes.pod.name"),
            "uid": lb.get("io.kubernetes.pod.uid"),
            "name": lb.get("io.kubernetes.container.name") or md.get("name"),
            "id": st.get("id"),
            "attempt": md.get("attempt"),
            "mems": None, "mems_effective": None, "mems_inherited": None, "memory_high": None,
        }
        pid = (c.get("info") or {}).get("pid") or 0
        try:
            with open("/proc/%d/cgroup" % pid) as f:
                cg = "/sys/fs/cgroup" + [l[3:].strip() for l in f if l.startswith("0::")][0]
            mems = read(cg + "/cpuset.mems")
            eff = read(cg + "/cpuset.mems.effective")
            entry["memory_high"] = read(cg + "/memory.high") or None
            if not eff:
                # Never empty for a live cgroup: unreadable.
                raise OSError("empty cpuset.mems.effective in %s" % cg)
            entry["mems_effective"] = eff
            entry["mems"] = mems or eff
            entry["mems_inherited"] = not mems
            if entry["memory_high"] is None:
                errors.append("container %s/%s/%s: empty memory.high" % (entry["ns"], entry["pod"], entry["name"]))
        except (OSError, IndexError) as e:
            if pid and os.path.exists("/proc/%d" % pid):
                errors.append("container %s/%s/%s: cgroup: %s" % (entry["ns"], entry["pod"], entry["name"], e))
            else:
                continue  # it exited meanwhile
        out.append(entry)
    return sorted(out, key=lambda e: (e["pod"] or "", e["name"] or ""))


DRIVER_STATE_DIR = "/run/mbt-observe"
PANIC = re.compile(r"panic|fatal error|SIGSEGV")
LENDS_RESTORED = "NRI fence: lends restored"


def driver_log(errors):
    """The running driver container of the node and what its log says
    (amendment A13, A15)."""
    out = {"container": None, "pod": None, "attempt": None, "started": None, "panics": 0, "errors": [],
           "lendsRestored": False, "sockets": all(os.path.exists("/var/lib/kubelet/plugins/%s/dra.sock" % d)
                                                   for d in ("cxl.nri.io", "cxl-pool.nri.io"))}
    r = run(["crictl", "ps", "-q", "--state", "running", "--namespace", "^kube-system$",
             "--name", "^%s$" % DRIVER_CONTAINER])
    if r.returncode != 0:
        raise RuntimeError("crictl ps: %s" % r.stderr.strip()[-300:])
    ids = r.stdout.split()
    if not ids:
        return out
    if len(ids) > 1:
        errors.append("driverLog: %d running driver containers: %s" % (len(ids), " ".join(i[:13] for i in ids)))
    info = crictl_inspect(ids[:1])
    if not info:
        return out  # it exited meanwhile
    st = info[0].get("status") or {}
    cid = st.get("id") or ids[0]
    out.update(container=cid, pod=(st.get("labels") or {}).get("io.kubernetes.pod.name"),
               attempt=(st.get("metadata") or {}).get("attempt"), started=st.get("startedAt"))
    path = st.get("logPath")
    if not path:
        raise RuntimeError("no logPath of container %s" % cid)
    os.makedirs(DRIVER_STATE_DIR, exist_ok=True)
    statefile = os.path.join(DRIVER_STATE_DIR, "driverlog-%s.json" % cid)
    saved = {"offset": 0, "panics": 0, "errors": [], "lendsRestored": False}
    try:
        with open(statefile) as f:
            saved.update(json.load(f))
    except (OSError, ValueError):
        pass
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size < saved["offset"]:
            saved["offset"] = 0  # rotated: the new file from its start
        f.seek(saved["offset"])
        data = f.read()
    # Only whole lines: a line that is being written is read next time.
    end = data.rfind(b"\n") + 1
    for raw in data[:end].splitlines():
        line = raw.decode(errors="replace")
        # CRI log format: TIME STREAM P|F CONTENT
        content = line.split(" ", 3)[3] if line.count(" ") >= 3 else line
        if not saved["lendsRestored"] and LENDS_RESTORED in content:
            saved["lendsRestored"] = True
        if PANIC.search(content):
            saved["panics"] += 1
            if len(saved["errors"]) < 5:
                saved["errors"].append(content[:300])
    saved["offset"] += end
    try:
        with open(statefile + ".tmp", "w") as f:
            json.dump(saved, f)
        os.replace(statefile + ".tmp", statefile)
    except OSError as e:
        errors.append("driverLog: %s: %s" % (statefile, e))
    out.update(panics=saved["panics"], errors=saved["errors"], lendsRestored=saved["lendsRestored"])
    return out


def vm_observation(ns):
    errors = []
    obs = {}
    obs["bootID"] = part(errors, "bootID", read, "/proc/sys/kernel/random/boot_id")
    obs["memdevs"] = part(errors, "memdevs", memdevs, errors)
    obs["regions"] = part(errors, "regions", regions, errors)
    obs["ports"] = part(errors, "ports", ports, errors)
    obs["nodes"] = part(errors, "nodes", numa_nodes)
    obs["state"] = part(errors, "state", state, errors)
    obs["cdi"] = part(errors, "cdi", cdi, errors)
    obs["containers"] = part(errors, "containers", containers, ns, errors)
    obs["driverLog"] = part(errors, "driverLog", driver_log, errors)
    obs["errors"] = errors
    return obs


###
### The cluster (contract 6.1, the parts of kubectl and systemd)
###

def id_map(text):
    """"k=v,k=v" -> {k: v}."""
    out = {}
    for kv in (text or "").split(","):
        k, sep, v = kv.partition("=")
        if sep:
            out[k.strip()] = v.strip()
    return out


def slot_of_label(label):
    """mbt.slot label KIND_VM_I -> slot KIND@VM#I."""
    parts = (label or "").split("_")
    if len(parts) != 3:
        return label
    return "%s@%s#%s" % tuple(parts)


def condition(obj, ctype):
    for c in (obj.get("status") or {}).get("conditions") or []:
        if c.get("type") == ctype:
            return c
    return None


def container_status(pod, name):
    for cs in (pod.get("status") or {}).get("containerStatuses") or []:
        if cs.get("name") == name:
            return cs
    return None


def claim_part(pod, claims):
    spec_claims = (pod.get("spec") or {}).get("resourceClaims") or []
    if not spec_claims:
        return None
    cname = spec_claims[0].get("name")
    name = spec_claims[0].get("resourceClaimName")
    for s in (pod.get("status") or {}).get("resourceClaimStatuses") or []:
        if s.get("name") == cname and s.get("resourceClaimName"):
            name = s["resourceClaimName"]
    claim = claims.get(name) if name else None
    if claim is None:
        return {"name": name, "uid": None, "allocated": False, "devices": [], "attached": None}
    st = claim.get("status") or {}
    alloc = st.get("allocation")
    results = ((alloc or {}).get("devices") or {}).get("results") or []
    devices = [{"driver": r.get("driver"), "pool": r.get("pool"), "device": r.get("device")} for r in results]
    attached = None
    pool_results = [r for r in results if r.get("driver") == POOL_DRIVER]
    if pool_results:
        attached = True
        for r in pool_results:
            ok = False
            for d in st.get("devices") or []:
                if (d.get("driver"), d.get("pool"), d.get("device")) != (r.get("driver"), r.get("pool"), r.get("device")):
                    continue
                for c in d.get("conditions") or []:
                    if c.get("type") == POOL_DRIVER + "/Attached" and c.get("status") == "True":
                        ok = True
            attached = attached and ok
    return {"name": name, "uid": (claim.get("metadata") or {}).get("uid"),
            "allocated": alloc is not None, "devices": devices, "attached": attached,
            "deleting": bool((claim.get("metadata") or {}).get("deletionTimestamp"))}


def event_time(e):
    """The time of event e as a sortable string (RFC 3339, UTC)."""
    t = (e.get("series") or {}).get("lastObservedTime") or e.get("lastTimestamp") \
        or e.get("eventTime") or (e.get("metadata") or {}).get("creationTimestamp") or ""
    # 2026-10-24T08:10:51Z and 2026-10-24T08:10:51.123456Z sort alike.
    t = t.replace("Z", "")
    if not t:
        return ""
    head, _, frac = t.partition(".")
    return head + "." + (frac + "000000")[:6]


MAX_EVENTS = 5
MAX_MESSAGE = 4000


def short_message(text):
    """text in at most MAX_MESSAGE bytes (UTF-8): a longer one keeps its
    start and its end, where the driver puts the reason of a failure."""
    b = (text or "").encode()
    if len(b) <= MAX_MESSAGE:
        return text or ""
    return (b[:1900].decode(errors="ignore") + " [...] " + b[-2000:].decode(errors="ignore"))


def warning_events(items):
    """Pod uid -> its Warning events, newest first, at most MAX_EVENTS:
    reason, message, count, lastTimestamp."""
    by_uid = {}
    for e in items:
        io = e.get("involvedObject") or {}
        if io.get("kind") != "Pod" or not io.get("uid"):
            continue
        last = (e.get("series") or {}).get("lastObservedTime") or e.get("lastTimestamp") or e.get("eventTime") \
            or (e.get("metadata") or {}).get("creationTimestamp")
        by_uid.setdefault(io["uid"], []).append((event_time(e), {
            "reason": e.get("reason"), "message": short_message(e.get("message")),
            "count": (e.get("series") or {}).get("count") or e.get("count") or 1, "lastTimestamp": last}))
    return {uid: [ev for _, ev in sorted(evs, key=lambda x: x[0], reverse=True)[:MAX_EVENTS]]
            for uid, evs in by_uid.items()}


def container_states(pod):
    """The containers of the pod status: name, id (without the runtime
    prefix), state (running, waiting, terminated), restarts."""
    out = []
    for cs in (pod.get("status") or {}).get("containerStatuses") or []:
        state = next(iter((cs.get("state") or {}).keys()), None)
        out.append({"name": cs.get("name"), "id": (cs.get("containerID") or "").split("://")[-1] or None,
                    "state": state, "restarts": cs.get("restartCount") or 0})
    return out


def slices_part(items, vm_of):
    """VM -> the devices of its cxl.nri.io ResourceSlices: name, serial,
    shared, type."""
    def attr(dev, name):
        attrs = dev.get("attributes") or {}
        a = attrs.get(name)
        if a is None:
            a = next((v for k, v in attrs.items() if k.endswith("/" + name)), None)
        return next(iter(a.values()), None) if isinstance(a, dict) and a else None
    out = {}
    for sl in items:
        spec = sl.get("spec") or {}
        if spec.get("driver") != "cxl.nri.io" or not spec.get("nodeName"):
            continue
        vm = vm_of.get(spec["nodeName"], spec["nodeName"])
        for d in spec.get("devices") or []:
            out.setdefault(vm, []).append({"name": d.get("name"), "serial": attr(d, "serial"),
                                           "shared": bool(attr(d, "shared")), "type": attr(d, "type")})
    for vm in out:
        out[vm].sort(key=lambda d: d["name"] or "")
    return out


def pool_slices_part(items, vm_of, pools):
    """Pool id -> the cxl-pool.nri.io ResourceSlices of its pool: name,
    devices (names), nodes (VM ids of the nodeSelector; every VM for
    allNodes), [] for a pool without slices (amendment A18). pools maps
    pool ids to DRA pool names; a slice of another pool is keyed by its
    pool name."""
    id_of = {name: pid for pid, name in pools.items()}
    out = {pid: [] for pid in pools}
    for sl in items:
        spec = sl.get("spec") or {}
        if spec.get("driver") != POOL_DRIVER:
            continue
        name = (spec.get("pool") or {}).get("name")
        nodes = set()
        if spec.get("allNodes"):
            nodes.update(vm_of.values())
        if spec.get("nodeName"):
            nodes.add(vm_of.get(spec["nodeName"], spec["nodeName"]))
        for term in (spec.get("nodeSelector") or {}).get("nodeSelectorTerms") or []:
            for e in term.get("matchExpressions") or []:
                if e.get("key") == "kubernetes.io/hostname" and e.get("operator") == "In":
                    nodes.update(vm_of.get(v, v) for v in e.get("values") or [])
        out.setdefault(id_of.get(name, name), []).append({
            "name": (sl.get("metadata") or {}).get("name"),
            "devices": sorted(d.get("name") for d in spec.get("devices") or []),
            "nodes": sorted(nodes)})
    for pid in out:
        out[pid].sort(key=lambda x: x["name"] or "")
    return out


def pod_part(pod, claims, vm_of, events=None):
    md = pod.get("metadata") or {}
    st = pod.get("status") or {}
    cs = container_status(pod, MAIN) or {}
    ready = condition(pod, "Ready")
    sched = condition(pod, "PodScheduled")
    m = re.search(r"-g(\d+)$", md.get("name") or "")
    node = (pod.get("spec") or {}).get("nodeName")
    waiting = ((cs.get("state") or {}).get("waiting") or {}).get("reason")
    last = ((cs.get("lastState") or {}).get("terminated") or {}).get("exitCode")
    return {
        "slot": slot_of_label((md.get("labels") or {}).get(SLOT_LABEL)),
        "name": md.get("name"),
        "uid": md.get("uid"),
        "gen": int(m.group(1)) if m else None,
        "node": vm_of.get(node, node) if node else None,
        "phase": st.get("phase"),
        "ready": bool(ready and ready.get("status") == "True"),
        "deleting": bool(md.get("deletionTimestamp")),
        "restarts": cs.get("restartCount") or 0,
        "waiting": waiting,
        "lastExit": last,
        "unschedulable": bool(sched and sched.get("status") == "False" and sched.get("reason") == "Unschedulable"),
        "claim": claim_part(pod, claims),
        "events": (events or {}).get(md.get("uid")) or [],
        "event": next(iter((events or {}).get(md.get("uid")) or []), None),
        "containers": container_states(pod),
    }


def driver_part(pods, vm_of):
    by_vm = {}
    for p in pods:
        md = p.get("metadata") or {}
        node = (p.get("spec") or {}).get("nodeName")
        vm = vm_of.get(node, node)
        cs = container_status(p, DRIVER_CONTAINER) or {}
        ready = condition(p, "Ready")
        entry = {"pod": md.get("name"), "ready": bool(ready and ready.get("status") == "True"),
                 "restarts": cs.get("restartCount") or 0, "phase": (p.get("status") or {}).get("phase"),
                 "deleting": bool(md.get("deletionTimestamp")), "count": 1}
        old = by_vm.get(vm)
        if old is None:
            by_vm[vm] = entry
            continue
        # The pod of the node, not a terminating one of an earlier restart.
        count = old["count"] + 1
        if (old["deleting"], not old["ready"]) > (entry["deleting"], not entry["ready"]):
            by_vm[vm] = entry
        by_vm[vm]["count"] = count
    return by_vm


def cxl_leases(text):
    text = text.strip()
    try:
        j = json.loads(text) if text else []
        if isinstance(j, dict):
            j = j.get("leases", [j] if "lease" in j else [])
        return j or []
    except ValueError:
        return [json.loads(l) for l in text.splitlines() if l.strip().startswith("{")]


def inspect_pod(ns, pod, kind, out, errors, lock):
    name = pod["name"]
    r = run(["kubectl", "exec", "-n", ns, name, "-c", MAIN, "--", "env"], timeout=EXEC_TIMEOUT)
    if r.returncode != 0:
        with lock:
            errors.append("inspect %s: env: exit %d: %s" % (name, r.returncode, r.stderr.strip()[-200:]))
        return
    env = {}
    for line in r.stdout.splitlines():
        k, sep, v = line.partition("=")
        if sep and k.startswith("CXL_"):
            env[k] = v
    leases = None
    if kind == "lease":
        r = run(["kubectl", "exec", "-n", ns, name, "-c", MAIN, "--", CXL_REQUEST, "list"], timeout=EXEC_TIMEOUT)
        if r.returncode != 0:
            with lock:
                errors.append("inspect %s: cxl-request list: exit %d: %s" % (name, r.returncode, (r.stdout + r.stderr).strip()[-200:]))
            return
        try:
            leases = cxl_leases(r.stdout)
        except ValueError as e:
            with lock:
                errors.append("inspect %s: cxl-request list: %s" % (name, e))
            return
    with lock:
        out[pod["slot"]] = {"uid": pod["uid"], "restarts": pod["restarts"], "env": env, "leases": leases}


def cluster_observation(ns, nodes, units, inspected, pools=None):
    errors = []
    vm_of = {node: vm for vm, node in nodes.items()}
    results = {}

    def get(key, args):
        try:
            r = run(args, timeout=60)
            if r.returncode != 0:
                raise RuntimeError("%s: exit %d: %s" % (" ".join(args[:4]), r.returncode, r.stderr.strip()[-300:]))
            results[key] = r.stdout
        except Exception as e:
            errors.append("%s: %s" % (key, e))

    unit_names = [units[p] for p in sorted(units)]
    jobs = [
        ("ns", ["kubectl", "get", "pods,resourceclaims", "-n", ns, "-o", "json"]),
        ("drivers", ["kubectl", "get", "pods", "-n", "kube-system", "-l", DRIVER_LABEL, "-o", "json"]),
        ("events", ["kubectl", "get", "events", "-n", ns, "--field-selector", "type=Warning", "-o", "json"]),
        ("slices", ["kubectl", "get", "resourceslices", "-o", "json"]),
    ]
    threads = [threading.Thread(target=get, args=job) for job in jobs]
    for t in threads:
        t.start()
    # systemctl is-active exits non-zero when a unit is not active: not an error.
    try:
        r = run(["systemctl", "is-active"] + unit_names, timeout=30)
        states = r.stdout.split()
        if len(states) != len(unit_names):
            raise RuntimeError("systemctl is-active printed %r" % r.stdout)
        controllers = {p: states[i] for i, p in enumerate(sorted(units))}
    except Exception as e:
        errors.append("controllers: %s" % e)
        controllers = None
    for t in threads:
        t.join()

    out = {"pods": None, "companions": None, "others": None, "drivers": None,
           "controllers": controllers, "inspect": None, "slices": None, "poolSlices": None}
    if "slices" in results:
        try:
            items = json.loads(results["slices"]).get("items") or []
            out["slices"] = slices_part(items, vm_of)
            out["poolSlices"] = pool_slices_part(items, vm_of, pools or {p: "pool-" + p for p in units})
        except Exception as e:
            errors.append("slices: %s: %s" % (type(e).__name__, e))
    events = None
    if "events" in results:
        try:
            events = warning_events(json.loads(results["events"]).get("items") or [])
        except Exception as e:
            errors.append("events: %s: %s" % (type(e).__name__, e))
    if "ns" in results:
        try:
            items = json.loads(results["ns"]).get("items") or []
            pods = [i for i in items if i.get("kind") == "Pod"]
            claims = {(i.get("metadata") or {}).get("name"): i for i in items if i.get("kind") == "ResourceClaim"}
            slot_pods, companions, others = [], [], []
            for p in pods:
                labels = (p.get("metadata") or {}).get("labels") or {}
                if SLOT_LABEL in labels:
                    slot_pods.append(pod_part(p, claims, vm_of, events))
                elif LEASE_LABEL in labels:
                    companions.append(p)
                else:
                    others.append((p.get("metadata") or {}).get("name"))
            by_uid = {sp["uid"]: sp["slot"] for sp in slot_pods}
            comp = []
            for p in companions:
                md = p.get("metadata") or {}
                labels = md.get("labels") or {}
                node = (p.get("spec") or {}).get("nodeName")
                ready = condition(p, "Ready")
                comp.append({"name": md.get("name"), "node": vm_of.get(node, node) if node else None,
                             "uid": md.get("uid"), "containers": container_states(p),
                             "phase": (p.get("status") or {}).get("phase"),
                             "ready": bool(ready and ready.get("status") == "True"),
                             "deleting": bool(md.get("deletionTimestamp")),
                             "lease": labels.get(LEASE_LABEL),
                             "requester": by_uid.get(labels.get(REQUESTER_LABEL))})
            out["pods"] = sorted(slot_pods, key=lambda sp: (sp["slot"] or "", sp["name"] or ""))
            out["companions"] = sorted(comp, key=lambda c: c["name"] or "")
            out["others"] = sorted(n for n in others if n)
        except Exception as e:
            errors.append("pods: %s: %s" % (type(e).__name__, e))
    if "drivers" in results:
        try:
            out["drivers"] = driver_part(json.loads(results["drivers"]).get("items") or [], vm_of)
        except Exception as e:
            errors.append("drivers: %s: %s" % (type(e).__name__, e))
    if out["pods"] is not None:
        inspect, lock, threads = {}, threading.Lock(), []
        for sp in out["pods"]:
            if sp["phase"] != "Running" or not sp["ready"] or sp["deleting"]:
                continue
            if "%s:%s" % (sp["uid"], sp["restarts"]) in inspected:
                continue
            kind = (sp["slot"] or "").split("@")[0]
            t = threading.Thread(target=inspect_pod, args=(ns, sp, kind, inspect, errors, lock))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        out["inspect"] = inspect
    out["errors"] = errors
    return out


def cmd_vm(args):
    out = {}
    threads = []
    if args.cluster:
        def cluster():
            out["cluster"] = cluster_observation(args.ns, id_map(args.nodes), id_map(args.units),
                                                 set(":".join(i.split(":")[:2]) for i in (args.inspected or "").split(",") if i),
                                                 id_map(args.pools) or None)
        threads.append(threading.Thread(target=cluster))
        threads[-1].start()
    out["vm"] = vm_observation(args.ns)
    for t in threads:
        t.join()
    print(json.dumps(out, sort_keys=True, separators=(",", ":")))


###
### The host: the settle observation (contract 6.1)
###

def load_first_json(path):
    with open(path) as f:
        text = f.read()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise ValueError("no JSON line in %s: %r" % (path, text[-300:]))


def attachments(path, vm_of):
    with open(path) as f:
        text = f.read().strip()
    if not text:
        raise ValueError("no answer")
    j = json.loads(text) or []
    out = []
    for a in j:
        host = a.get("host")
        out.append({"device": a.get("device"), "host": vm_of.get(host, host), "serial": a.get("serial"),
                    "state": a.get("state"), "exclusive": bool(a.get("exclusive")),
                    "adopted": bool(a.get("adopted")), "owner": a.get("owner") or ""})
    return sorted(out, key=lambda a: (a["device"] or "", a["host"] or ""))


def mark_missing(obs, errors):
    """A11: per VM "missing", the containers that the status of a pod
    (slot pod or companion) on the VM says run and that the VM's
    "containers" lacks, or has without its cpuset."""
    pods = [("pod", p) for p in obs.get("pods") or []] + [("companion", c) for c in obs.get("companions") or []]
    for vm, v in (obs.get("vms") or {}).items():
        if v is None:
            continue
        missing = []
        if v.get("containers") is None:
            v["missing"] = None
            continue
        seen = {c.get("id"): c for c in v["containers"]}
        for kind, p in pods:
            if p.get("node") != vm:
                continue
            for c in p.get("containers") or []:
                if c.get("state") != "running" or not c.get("id"):
                    continue
                got = seen.get(c["id"])
                if got is None:
                    why = "the pod status says it runs, crictl does not list it"
                elif not got.get("mems_effective"):
                    why = "its cpuset cannot be read"
                else:
                    continue
                missing.append({"pod": p.get("name"), "kind": kind, "container": c.get("name"), "id": c["id"],
                                "reason": why})
        v["missing"] = missing


def cmd_assemble(args):
    errors = []
    vm_of = {node: vm for vm, node in id_map(args.nodes).items()}
    obs = {"step": args.step, "poll": args.poll, "pods": None, "companions": None, "others": None,
           "attachments": {}, "drivers": None, "controllers": None, "vms": {}, "inspect": None, "slices": None,
           "poolSlices": None}
    for spec in args.vm or []:
        vm, _, path = spec.partition("=")
        try:
            j = load_first_json(path)
        except Exception as e:
            errors.append("%s: %s" % (vm, e))
            obs["vms"][vm] = None
            continue
        obs["vms"][vm] = j.get("vm")
        if "cluster" in j:
            c = j["cluster"] or {}
            for key in ("pods", "companions", "others", "drivers", "controllers", "inspect", "slices", "poolSlices"):
                obs[key] = c.get(key)
            errors.extend("cluster: %s" % e for e in c.get("errors") or [])
    for spec in args.attachments or []:
        pool, _, path = spec.partition("=")
        try:
            obs["attachments"][pool] = attachments(path, vm_of)
        except Exception as e:
            errors.append("attachments %s: %s" % (pool, e))
            obs["attachments"][pool] = None
    mark_missing(obs, errors)
    obs["errors"] = errors
    if args.inspected_out:
        before = []
        if args.inspected_in and os.path.exists(args.inspected_in):
            with open(args.inspected_in) as f:
                before = [l.strip() for l in f if l.strip()]
        if obs["pods"] is None:
            keep = before
        else:
            uids = set(p["uid"] for p in obs["pods"])
            keep = [e for e in before if e.split(":")[0] in uids]
            keep += ["%s:%s:%s" % (i["uid"], i["restarts"], slot) for slot, i in (obs["inspect"] or {}).items()]
        with open(args.inspected_out, "w") as f:
            f.write("".join(e + "\n" for e in sorted(set(keep))))
    if args.summary:
        with open(args.summary, "w") as f:
            for vm, d in sorted((obs["drivers"] or {}).items()):
                f.write("driver %s %s %s %s\n" % (vm, d.get("pod"), d.get("restarts"), "ready" if d.get("ready") else "unready"))
    print(json.dumps(obs, sort_keys=True, separators=(",", ":")))


def main():
    ap = argparse.ArgumentParser(description="observations of test90-gofmbt-reliability")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("vm")
    v.add_argument("--ns", default="cxl-pool-demo")
    v.add_argument("--cluster", action="store_true")
    v.add_argument("--nodes", default="")
    v.add_argument("--units", default="")
    v.add_argument("--pools", default="")
    v.add_argument("--inspected", default="")
    a = sub.add_parser("assemble")
    a.add_argument("--step", type=int, required=True)
    a.add_argument("--poll", type=int, required=True)
    a.add_argument("--nodes", default="")
    a.add_argument("--vm", action="append")
    a.add_argument("--attachments", action="append")
    a.add_argument("--inspected-in")
    a.add_argument("--inspected-out")
    a.add_argument("--summary")
    args = ap.parse_args()
    if args.cmd == "vm":
        cmd_vm(args)
    else:
        cmd_assemble(args)


if __name__ == "__main__":
    main()
