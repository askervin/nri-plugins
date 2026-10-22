#!/usr/bin/env python3
"""The live views of the demo, one per terminal of 50 x 10.

Usage:
  views.py VIEW [local|pool|pool-shared-fs] [--color|--no-color] [--once] [--interval S]
  views.py VIEW --sample DIR [--now EPOCH] [--until EPOCH]

VIEW is t2 (pods and leases), t3 (scheduler: devices and claims), t4
(nodes: CXL in the kernel), t5 (trace), t6 (memory; the pool server in the
pool demos). The case defaults to DEMO_CASE of the state of demo setup.
A view refreshes once a second: a title with a clock and at most 9 lines,
cut to 50 columns. A failed refresh keeps the last rendering and marks
the title "stale". --once prints one rendering without color (captures).
--sample renders the files of a test data directory instead: state.env,
vm2.json and vm1.json (probe.py output), pool.json, trace/.
"""
import json
import os
import re
import sys
import threading
import time

import common as c

CASES = ("local", "pool", "pool-shared-fs")


def pool_case(state):
    """Return True if the case of STATE is a pool demo (pool, pool-shared-fs)."""
    return (state.get("DEMO_CASE") or "").startswith("pool")


###
### T2 PODS & LEASES
###

def pod_state(p):
    if c.deleting(p):
        return "Exiting"
    phase = (p.get("status") or {}).get("phase") or "?"
    return {"Succeeded": "Done"}.get(phase, phase)[:7]


def demo_pods(pods_doc):
    """Return the pods of the demo without the companion pods of leases, writer first."""
    pods = [p for p in c.items(pods_doc, "Pod") if not c.lease_id(p)]
    return sorted(pods, key=lambda p: (c.meta(p).get("name") != "writer", c.meta(p).get("name")))


def leases_of(claims, pod):
    uid = c.meta(pod).get("uid")
    name = c.meta(pod).get("name")
    out = [cl for cl in claims if c.lease_id(cl) and
           (c.requester(cl) == name or c.labels(cl).get(c.REQUESTER_UID_LABEL) == uid)]
    return sorted(out, key=lambda cl: c.meta(cl).get("creationTimestamp") or "")


def render_t2(data, state, now=None, stale=False):
    k8s = (data.get("vm2") or {}).get("k8s") or {}
    lines = [c.title("PODS & LEASES", stale, now), "POD       NODE STATE   LEASE    MEMORY"]
    claims = c.items(k8s.get("claims"), "ResourceClaim")
    rows = []
    for p in demo_pods(k8s.get("pods")):
        name = c.meta(p).get("name")
        node = c.short_node((p.get("spec") or {}).get("nodeName"), state)
        head = "%-9s %-4s %-7s " % (name[:9], node[:4], pod_state(p))
        leases = leases_of(claims, p)
        if not leases:
            rows.append(head + "%-8s %s" % ("-", "-"))
        for i, cl in enumerate(leases):
            prefix = head if i == 0 else " " * len(head)
            rows.append(prefix + "%-8s %s" % (c.lease_id(cl)[:8], c.lease_memory(cl)))
    if not rows:
        rows = ["no demo pods yet"]
    return lines + c.fit(rows, c.CONTENT_ROWS - 1)


###
### T3 SCHEDULER
###

def driver_status(drivers_doc, state, case):
    nodes = [state.get("VM2_NODE"), state.get("VM1_NODE")]
    words = []
    pods = c.items(drivers_doc, "Pod")
    for n in [n for n in nodes if n]:
        mine = [p for p in pods if (p.get("spec") or {}).get("nodeName") == n]
        if not mine:
            st = "down"
        else:
            p = mine[-1]
            cs = (p.get("status") or {}).get("containerStatuses") or []
            if c.deleting(p):
                st = "restarting"
            elif (p.get("status") or {}).get("phase") == "Running" and cs and all(x.get("ready") for x in cs):
                st = "ok"
            else:
                st = "restarting" if any(x.get("restartCount") for x in cs) else "starting"
        words.append("%s %s" % (c.short_node(n, state), st))
    return "drivers: " + "  ".join(words) if words else "drivers: ?"


def shared_devices(slices_doc, serial=None):
    """Return [(driver, pool, where, device)] of the shared devices, of SERIAL only if given."""
    out = []
    for drv, pool, where, d in c.slice_devices(slices_doc):
        if c.device_attr(d, "shared") is not True:
            continue
        if serial and (c.int_any(c.device_attr(d, "serial")) != c.int_any(serial)):
            continue
        out.append((drv, pool, where, d))
    return out


def device_holders(entry, claims):
    """Return (exclusive, shared, waiting) holder words of a shared device ENTRY."""
    drv, pool, _, d = entry
    serial = (c.device_attr(d, "serial") or "").lower()
    excl, shared, waiting = [], [], []
    for cl in claims:
        res = [r for r in c.results(cl) if (r.get("driver"), r.get("pool"), r.get("device")) == (drv, pool, d.get("name"))]
        if res:
            ex, ro = c.holding(cl, res[0], d)
            word = "%s %s%s" % (c.holder_name(cl), "ro" if ro else "rw", " releasing" if c.deleting(cl) else "")
            (excl if ex else shared).append(word)
        elif not c.allocation(cl) and not c.deleting(cl) and serial and serial in c.claim_serials(cl):
            waiting.append(c.holder_name(cl))
    return sorted(excl), sorted(shared), sorted(waiting)


def render_t3(data, state, now=None, stale=False):
    k8s = (data.get("vm2") or {}).get("k8s") or {}
    case = state.get("DEMO_CASE", "local")
    lines = [c.title("SCHEDULER: DEVICES AND CLAIMS", stale, now)]
    status = driver_status(k8s.get("drivers"), state, case)
    pool_slices = [s for s in c.items(k8s.get("slices"))
                   if (s.get("spec") or {}).get("driver") == "cxl-pool.nri.io"
                   and not (s.get("spec") or {}).get("nodeName")]
    if pool_case(state):
        status += "  pool %s" % ("ok" if pool_slices else "down")
    rows = [status]
    claims = c.items(k8s.get("claims"), "ResourceClaim")
    devices = shared_devices(k8s.get("slices"), state.get("SERIAL")) or shared_devices(k8s.get("slices"))
    matched = set()
    for entry in devices:
        drv, pool, where, d = entry
        at = "@" + (c.short_node(where, state) if where else "pool")
        rows.append("%s %s %s shared%s" % (d.get("name"), at, c.k8s_size(c.device_attr(d, "size")),
                                           " persistent" if c.device_attr(d, "persistent") is True else ""))
        excl, shared, waiting = device_holders(entry, claims)
        for w in excl:
            rows.append("  exclusive: " + w)
        if shared:
            rows += c.wrap_list("  shared: ", shared, indent=4)
        if waiting:
            rows += c.wrap_list("  waiting: ", waiting, indent=4, sep="")
        if not (excl or shared or waiting):
            rows.append("  no claims")
        serial = (c.device_attr(d, "serial") or "").lower()
        matched.update(id(cl) for cl in claims if serial in c.claim_serials(cl))
    if not devices:
        rows.append("no shared device published (yet)")
    other = [c.holder_name(cl) for cl in claims if c.lease_id(cl) and not c.allocation(cl)
             and not c.deleting(cl) and id(cl) not in matched]
    if other:
        rows += c.wrap_list("waiting (any device): ", other, indent=2, sep="")
    return lines + c.fit(rows)


###
### T4 NODES
###

def pod_names(pods_doc):
    """Return pod uid -> name; companions of leases are named after their requester."""
    out = {}
    for p in c.items(pods_doc, "Pod"):
        uid = c.meta(p).get("uid")
        if uid:
            out[uid] = c.requester(p) or c.meta(p).get("name")
    return out


def lease_claim_pods(k8s):
    """Return lease claim uid -> pod name: the claim's name in the pods' status.resourceClaimStatuses."""
    by_name = {}
    for p in c.items(k8s.get("pods"), "Pod"):
        for st in (p.get("status") or {}).get("resourceClaimStatuses") or []:
            if st.get("resourceClaimName"):
                by_name[st["resourceClaimName"]] = c.meta(p).get("name")
    out = {}
    for cl in c.items(k8s.get("claims"), "ResourceClaim"):
        uid, name = c.meta(cl).get("uid"), c.meta(cl).get("name")
        if uid and name in by_name:
            out[uid] = by_name[name]
    return out


def pmem_lines(region, node, names, claim_pods):
    """Return the lines of the fsdax namespaces of a pmem REGION: block device, file system, openers, mounts."""
    out = []
    for n in region.get("namespaces") or []:
        block = n.get("block")
        if not block:
            out.append("    %s %s %s, no block device" % (n.get("name"), c.kernel_size(n.get("size")), n.get("mode")))
            continue
        fs = {"erofs": "erofs", "none": "no file system"}.get(n.get("fs"), "file system ?")
        out.append("    %s %s %s" % (block, c.kernel_size(n.get("size")), fs))
        who = {}
        for o in node.get("openers") or []:
            if o.get("block") == block:
                name = names.get(o.get("podUID")) or "pid %s" % o.get("pid")
                if who.get(name) != "rw":
                    who[name] = o.get("perms") or "ro"
        if who:
            out += c.wrap_list("    open: ", ["%s %s" % (k, v) for k, v in sorted(who.items())], indent=6)
        mounts = [m for m in node.get("mounts") or [] if m.get("block") == block]
        groups = {}
        for m in mounts:
            if m.get("kind") == "lease":
                how = "cached" if m.get("loop") else ("dax" if m.get("dax") else "no dax")
                groups.setdefault(how, []).append(claim_pods.get(m.get("claimUID")) or (m.get("claimUID") or "?")[:8])
        if groups:
            words = []
            for how in sorted(groups):
                words += sorted(set(groups[how])) + ["(%s)%s" % (how, "," if how != sorted(groups)[-1] else "")]
            out += c.wrap_list("    mounted: ", words, indent=6, sep="")
        elif any(m.get("kind") == "node" for m in mounts):
            out.append("    mounted: node mount, no lease")
        elif n.get("fs") == "erofs":
            out.append("    mounted: -")
    if not region.get("namespaces"):
        out.append("    no namespace yet")
    return out


def node_lines(label, node, names, claim_pods=None):
    if node is None:
        return ["%s unreachable" % label]
    devs = node.get("memdevs") or []
    if not devs:
        return ["%s no CXL memory" % label]
    out = []
    regions = node.get("regions") or []
    mappers = node.get("mappers") or []
    for i, d in enumerate(devs):
        pre = label if i == 0 else " " * len(label)
        serial = d.get("serial", "0x?")[2:]
        mine = [r for r in regions if d["name"] in (r.get("memdevs") or [])]
        if not mine:
            out.append("%s %s %s %s  no region" % (pre, d["name"], serial, c.kernel_size(d.get("size"))))
            continue
        for j, r in enumerate(mine):
            head = "%s %s %s %s" % (pre, d["name"], serial, c.kernel_size(d.get("size"))) if j == 0 else " " * (len(label) + 1)
            if r.get("mode") == "pmem":
                out.append("%s  %s pmem %s" % (head, r["name"], c.kernel_size(r.get("size"))))
                out += pmem_lines(r, node, names, claim_pods or {})
                continue
            out.append("%s  %s %s" % (head, r["name"], c.kernel_size(r.get("size"))))
            dax_names = []
            for x in r.get("dax") or []:
                drv = x.get("driver") or "no driver"
                if drv == "kmem" and x.get("targetNode") is not None:
                    drv = "kmem node %s" % x["targetNode"]
                out.append("    %s %s %s" % (x["name"], c.kernel_size(x.get("size")), drv))
                dax_names.append(x["name"])
            if not r.get("dax"):
                out.append("    no dax device (mode %s)" % r.get("mode"))
            who = {}
            for m in mappers:
                if m.get("dax") in dax_names:
                    n = names.get(m.get("podUID")) or "pid %s" % m.get("pid")
                    rw = "rw" if "w" in (m.get("perms") or "") else "ro"
                    if who.get(n) != "rw":
                        who[n] = rw
            words = ["%s %s" % (n, rw) for n, rw in sorted(who.items())]
            out += c.wrap_list("    mapped: ", words or ["-"], indent=6)
    return out


def render_t4(data, state, now=None, stale=False):
    vm2 = data.get("vm2") or {}
    vm1 = data.get("vm1") or {}
    k8s = vm2.get("k8s") or {}
    names = pod_names(k8s.get("pods"))
    claim_pods = lease_claim_pods(k8s)
    lines = [c.title("NODES: CXL IN THE KERNEL", stale, now)]
    order = [("vm2", vm2), ("vm1", vm1)]
    if pool_case(state):
        order.reverse()
    rows = []
    for label, d in order:
        rows += node_lines(label, d.get("node") if d else None, names, claim_pods)
    return lines + c.fit(rows)


###
### T6 MEMORY (local) and POOL (pool)
###

def text_at(hexdata):
    data = bytes.fromhex(hexdata or "")
    s = data.split(b"\0", 1)[0]
    if not s:
        return "(zeros)" if data and not any(data) else "(empty)"
    return '"%s"' % "".join(chr(b) if 32 <= b < 127 else "." for b in s)


def hex_line(hexdata, offset=0):
    data = bytes.fromhex(hexdata or "")[offset:offset + 16]
    groups = [data[i:i + 4].hex() for i in range(0, len(data), 4)]
    return "%04x: %s" % (offset, " ".join(groups))


def render_t6_local(data, state, now=None, stale=False):
    vm2 = data.get("vm2") or {}
    b = vm2.get("bytes") or {}
    serial = state.get("SERIAL", "")
    where = b.get("dax") or (serial[2:] if serial.startswith("0x") else serial)
    lines = [c.title("MEMORY: %s on vm2" % where, stale, now)]
    rows = []
    if b.get("hex"):
        rows.append("at 0: " + text_at(b["hex"]))
        rows.append(hex_line(b["hex"]))
    elif b.get("error") == "no dax device":
        rows.append("%s %s: no region, no dax device yet" % (b.get("memdev", "memdev"), serial))
        rows.append("the first claim creates them")
    else:
        rows.append("cannot read: %s" % (b.get("error") or "no data"))
    k8s = vm2.get("k8s") or {}
    devs = shared_devices(k8s.get("slices"), serial)
    if devs:
        excl, shared, waiting = device_holders(devs[0], c.items(k8s.get("claims"), "ResourceClaim"))
        if excl:
            rows.append("used by: %s (exclusive)" % ", ".join(excl))
        elif shared:
            rows += c.wrap_list("shared by: ", shared, indent=4)
        else:
            rows.append("used by: nobody (the bytes stay)")
        if waiting:
            rows += c.wrap_list("waiting: ", waiting, indent=4, sep="")
    return lines + c.fit(rows)


def render_t6_pool(data, state, now=None, stale=False):
    pool = data.get("pool") or {}
    dev = pool.get("device") or {}
    lines = [c.title("POOL: fake-cxl-pool-server", stale, now)]
    rows = []
    if not dev:
        rows.append("no device %s: %s" % (state.get("POOL_DEVICE", "?"), pool.get("error", "?")))
        return lines + rows
    rows.append("%s %s %s%s  %s" % (dev.get("name"), c.k8s_size(dev.get("size")),
                                    "shared" if dev.get("shared") else "exclusive",
                                    " persistent" if dev.get("persistent") else "", dev.get("state")))
    atts = dev.get("attachments") or []
    words = []
    for a in sorted(atts, key=lambda a: a.get("host") or ""):
        w = c.short_node(a.get("host"), state)
        if a.get("state") != "attached":
            w += " " + (a.get("state") or "?")
        words.append(w)
    excl = any(a.get("exclusive") for a in atts)
    if words:
        rows += c.wrap_list("  attached: ", words + (["exclusive"] if excl else []), indent=4,
                            sep="," if not excl else "")
    else:
        rows.append("  attached: nowhere")
    if dev.get("allocation"):
        rows.append("  owner: " + c.short_text(dev["allocation"].get("owner") or "?", state))
    if pool.get("fileError"):
        rows.append("backing file: " + pool["fileError"])
    elif state.get("DEMO_CASE") == "pool-shared-fs":
        rows += fs_lines(pool.get("fs"))
    elif pool.get("hex"):
        rows.append("at 0: " + text_at(pool["hex"]))
        rows.append(hex_line(pool["hex"]))
    rows.append("file " + (dev.get("path") or "?"))
    return lines + c.fit(rows)


def fs_lines(fs):
    """Return the lines of the file system FS (common.erofs_files) of the pool device."""
    if not fs:
        return ["file system: no data"]
    if fs.get("type") == "zeros":
        return ["no file system (zeros)"]
    if fs.get("type") != "erofs":
        return ["no file system"]
    files = fs.get("files") or []
    if not files:
        return ["erofs (not readable: %s)" % fs["error"] if fs.get("error") else "erofs: no files"]
    rows = []
    for i, f in enumerate(files):
        if f.get("type") == "dir":
            what = f["name"] + "/"
        else:
            what = "%s %s bytes" % (f["name"], f["size"] if f.get("size") is not None else "?")
        rows.append(("erofs: " if i == 0 else "       ") + what)
    first = next((f for f in files if f.get("type") == "file"), None)
    if first:
        text = first.get("text")
        rows.append("  " + (text if text in (None, "(not readable)") else '"%s"' % text))
    return rows


def render_t6(data, state, now=None, stale=False):
    if pool_case(state):
        return render_t6_pool(data, state, now, stale)
    return render_t6_local(data, state, now, stale)


###
### T5 TRACE
###

KLOG = re.compile(r"^([IWEF])\d{4} [\d:.]+\s+\d+ [^\]]+\] (.*)$")
LEASE_MARK = "\x01%s\x02"
LEASE_RE = re.compile("\x01([0-9a-f]{8})\x02")
# Driver errors that tell nothing: the apiserver drops fields of the
# ResourceSlices on every publish (dra.source.sh, dra-trace-summary).
DRIVER_NOISE = r"some fields were dropped by the apiserver"


class Trace:
    """Reads the streams of dra-trace-start and translates them to one line per event."""

    def __init__(self, trace_dir, state):
        self.dir = trace_dir
        self.state = state
        self.ns = state.get("NS", "")
        self.offsets = {}
        self.events = []        # (t, tag, text)
        self.who = {}           # lease id -> requester pod
        self.uid_claim = {}     # claim uid prefix -> claim name
        self.claims = {}        # claim name -> (allocated, deleting)
        self.busy = set()       # lease ids whose busy unmount is shown

    def lease_who(self, name):
        """Return a marker of the requester of a companion claim or pod cxl-lease-ID, else NAME.

        The marker is resolved when the line is shown: the driver names the
        requester of a lease, but its log may come after the scheduler's.
        """
        m = re.fullmatch(r"cxl-lease-([0-9a-f]{8})", name or "")
        if m:
            return LEASE_MARK % m.group(1)
        return name

    def text(self, text):
        """Return TEXT with the requesters of the lease markers."""
        return re.sub(LEASE_RE, lambda m: self.who.get(m.group(1), "lease " + m.group(1)), text)

    def node_label(self, tag):
        vm = tag.split(".")[0]
        return "vm2" if vm == "vm" else vm

    def short(self, text):
        return c.short_text(text, self.state)

    def emit(self, t, tag, text):
        self.events.append([t, tag, self.short(text)])

    def poll(self, until=None):
        """Read what the streams added, translate it; return True if anything changed."""
        if not self.dir or not os.path.isdir(self.dir):
            return False
        rows = []
        for f in sorted(os.listdir(self.dir)):
            if not f.endswith(".log"):
                continue
            p = os.path.join(self.dir, f)
            try:
                with open(p, "rb") as fh:
                    fh.seek(self.offsets.get(f, 0))
                    data = fh.read()
            except OSError:
                continue
            end = data.rfind(b"\n") + 1
            self.offsets[f] = self.offsets.get(f, 0) + end
            for raw in data[:end].decode(errors="replace").splitlines():
                parts = raw.split(" ", 2)
                if len(parts) < 3:
                    continue
                try:
                    t = float(parts[0])
                except ValueError:
                    continue
                if until is not None and t > until:
                    continue
                rows.append((t, parts[1], parts[2]))
        rows.sort(key=lambda r: r[0])
        before = len(self.events)
        for t, tag, text in rows:
            kind = tag.split(".")[-1]
            fn = getattr(self, "on_" + kind, None)
            if fn:
                fn(t, tag, text)
        return len(self.events) != before

    def on_events(self, t, tag, text):
        cols = re.split(r"\s{2,}|\t", text.strip(), maxsplit=4)
        if len(cols) < 4 or cols[0] != self.ns:
            return
        kind, name, reason = cols[1], cols[2], cols[3]
        msg = cols[4] if len(cols) > 4 else ""
        who = self.lease_who(name)
        node = re.search(r" to (\S+)$", msg)
        if kind == "Pod" and reason == "FailedScheduling":
            why = "cannot allocate" if "cannot allocate all claims" in msg else msg
            self.emit(t, "sched", "%s waits: %s" % (who, why))
        elif kind == "Pod" and reason == "Scheduled":
            what = "lease scheduled" if who != name else "scheduled"
            self.emit(t, "sched", "%s: %s on %s" % (who, what, node.group(1) if node else "?"))
        elif kind == "Pod" and reason == "BindingConditionsPending":
            self.emit(t, "sched", "%s: waits for the attach" % who)
        elif kind == "ResourceClaim" and reason == "AttachFailed":
            self.emit(t, "ctrl", "%s: AttachFailed %s" % (who, msg))
        elif reason.startswith("Failed") or reason in ("Unschedulable",):
            self.emit(t, "kube", "%s: %s %s" % (who, reason, msg))

    def on_claims(self, t, tag, text):
        m = re.match(r"(\S+) claim (\S+)/(\S+) uid=(\S+) allocated=(\S+) node=(\S+) reservedFor=\S+ status=\S+( deleting)?", text)
        if not m or m.group(2) != self.ns:
            return
        event, name, uid, alloc, node, dele = m.group(1), m.group(3), m.group(4), m.group(5), m.group(6), bool(m.group(7))
        self.uid_claim[uid[:8]] = name
        if alloc.endswith("/lease") or (alloc == "-" and not name.startswith("cxl-lease-")):
            return   # the lease claims of the demo pods (device "lease"), before their allocation
        who = self.lease_who(name)
        was = self.claims.get(name)
        if event == "DELETED":
            self.claims.pop(name, None)
            self.emit(t, "api", "%s: claim deleted" % who)
            return
        self.claims[name] = (alloc, dele)
        if was is None and event == "ADDED":
            self.emit(t, "api", "%s: claim created" % who)
        if alloc != "-" and (was is None or was[0] == "-"):
            self.emit(t, "api", "%s: allocated %s" % (who, alloc.split("/")[-1]))
        if dele and (was is None or not was[1]):
            self.emit(t, "api", "%s: claim deleting" % who)

    def on_driver(self, t, tag, text):
        m = KLOG.match(text)
        if not m:
            return
        level, msg = m.group(1), m.group(2)
        node = self.node_label(tag)
        lm = re.match(r"lease broker: lease ([0-9a-f]{8}): (.*)$", msg)
        if lm:
            lid, rest = lm.group(1), lm.group(2)
            rq = re.match(r"\S+?/([^/\s]+)/\S+ requests .*mode (\w+), shared (\w+), .*read-only (\w+)[,)]", rest)
            if rq:
                self.who[lid] = rq.group(1)
                self.emit(t, "drv", "%s %s asks %s %s %s" % (
                    node, rq.group(1), rq.group(2), "ro" if rq.group(4) == "true" else "rw",
                    "share" if rq.group(3) == "true" else "excl"))
                return
            who = LEASE_MARK % lid
            if rest.startswith("Ready"):
                self.emit(t, "drv", "%s %s: lease Ready%s" % (node, who, self.ready_what(rest)))
            elif rest.startswith("releasing"):
                why = re.match(r"releasing \(([^,]*)", rest)
                why = (why.group(1) if why else "?").replace("requester ", "")
                if why.startswith("released by"):
                    self.emit(t, "drv", "%s %s: lease releasing" % (node, who))
                else:
                    self.emit(t, "drv", "%s %s releasing: %s" % (node, who, why))
            elif rest.startswith("released"):
                self.emit(t, "drv", "%s %s: lease released" % (node, who))
            elif level in "EF" or rest.startswith("failed") or "Failed" in rest:
                self.emit(t, "drv", "%s %s: ERROR %s" % (node, who, rest))
            return
        pp = re.search(r'claim \S+?/(\S+): prepared \S+ \(.*mode (\w+), read-only (\w+)\) as \S+ \S+ namespace \S+ block (\S+) access "([^"]*)"', msg)
        if pp:
            ro = "ro" if pp.group(3) == "true" else "rw"
            # An fs device is read-only always: its access fits the 35 columns instead.
            what = "erofs " + pp.group(5) if pp.group(2) == "fs" else "%s %s" % (os.path.basename(pp.group(4)), ro)
            self.emit(t, "drv", "%s %s: prepared %s" % (node, self.lease_who(pp.group(1)), what))
            return
        if self.on_lease_mount(t, node, msg):
            return
        pm = re.search(r"claim \S+?/(\S+): prepared (\S+) \(.*read-only (\w+)\) as \S+ \S+ dax (\S+)", msg)
        if pm:
            self.emit(t, "drv", "%s %s: prepared %s %s" % (
                node, self.lease_who(pm.group(1)), pm.group(4), "ro" if pm.group(3) == "true" else "rw"))
            return
        um = re.search(r"unprepared claim \S+?/(\S+)", msg)
        if um:
            self.emit(t, "drv", "%s %s: unprepared" % (node, self.lease_who(um.group(1))))
            return
        lo = re.match(r"local: memdev (\S+) \(serial (\S+)\): claim (\S+) request \S+: shared (\S+) size \d+ read-only (\w+) (.*)$", msg)
        if lo:
            claim = self.uid_claim.get(lo.group(3)[:8], lo.group(3)[:8])
            self.emit(t, "drv", "%s %s: %s %s %s" % (
                node, self.lease_who(claim), lo.group(4), "ro" if lo.group(5) == "true" else "rw",
                "excl" if "exclusive" in lo.group(6) else "share"))
            return
        # The other lines of a shared local device (05-status-DRV section 5).
        sm = re.match(r"local: memdev \S+ \(serial \S+\): (.*)$", msg)
        if sm:
            rest = sm.group(1)
            cr = re.match(r"created (region\d+) \(devdax, dax (\S+?),", rest)
            rl = re.match(r"claim (\S+): released shared (\S+), claims left \[(.*)\]", rest)
            if cr:
                self.emit(t, "drv", "%s created %s %s" % (node, cr.group(1), cr.group(2)))
            elif rl:
                claim = self.uid_claim.get(rl.group(1)[:8], rl.group(1)[:8])
                left = len(rl.group(3).split())
                self.emit(t, "drv", "%s %s: released %s, %d left" % (node, self.lease_who(claim), rl.group(2), left))
            elif rest.startswith("zeroed new shared"):
                self.emit(t, "drv", "%s zeroed new %s (once)" % (node, rest.split()[3]))
            elif rest.startswith("keeping") and "idle" in rest:
                self.emit(t, "drv", "%s idle: keeping the region" % node)
            elif re.match(r"released region\d+", rest):
                self.emit(t, "drv", "%s %s" % (node, rest.split(" in ")[0]))
            elif rest.startswith("not configured shared"):
                self.emit(t, "drv", "%s %s" % (node, rest))
            return
        if level in "EF" and not re.search(DRIVER_NOISE, msg):
            self.emit(t, "drv", "%s ERROR %s" % (node, msg))

    def ready_what(self, rest):
        """Return what a Ready line of the lease broker names: " block pmem0", " fs hello", " dax0.0"."""
        block = re.search(r'block "([^"]+)"', rest)
        path = re.search(r'path "([^"]+)"', rest)
        dax = re.search(r'dax "([^"]+)"', rest)
        if block:
            return " block " + os.path.basename(block.group(1))
        if path:
            return " fs " + os.path.basename(path.group(1))
        return " " + os.path.basename(dax.group(1)) if dax else ""

    def on_lease_mount(self, t, node, msg):
        """Emit the bind, unbind and busy unmount lines of fs leases in MSG; return True if MSG was one."""
        bm = re.search(r": lease ([0-9a-f]{8}): bound \S+ at (\S+?)( again)?$", msg)
        um = re.search(r": lease ([0-9a-f]{8}): unbound (\S+)$", msg)
        busy = re.search(r"unpreparing claim \S+: lease ([0-9a-f]{8}): unmounting \S+: .*busy", msg)
        if bm:
            self.emit(t, "drv", "%s %s: mounted %s%s" % (node, LEASE_MARK % bm.group(1), os.path.basename(bm.group(2)),
                                                       " again" if bm.group(3) else ""))
        elif um:
            self.busy.discard(um.group(1))
            self.emit(t, "drv", "%s %s: unmounted %s" % (node, LEASE_MARK % um.group(1), os.path.basename(um.group(2))))
        elif busy:
            # kubelet retries the Unprepare: one line until the unmount succeeds.
            if busy.group(1) not in self.busy:
                self.busy.add(busy.group(1))
                self.emit(t, "drv", "%s %s: unmount busy, retry" % (node, LEASE_MARK % busy.group(1)))
        return bool(bm or um or busy)

    def on_kubelet(self, t, tag, text):
        self.on_lease_mount(t, self.node_label(tag), text)

    def on_udev(self, t, tag, text):
        m = re.match(r"KERNEL\[[\d.]+\]\s+(add|remove|bind|unbind)\s+(\S+) \((cxl|dax|block)\)", text)
        if not m:
            return
        name = os.path.basename(m.group(2))
        # pmemN of the cxl subsystem is the memdev's nvdimm, of block the block device.
        if not re.fullmatch(r"mem\d+|region\d+|dax\d+\.\d+", name) and not (m.group(3) == "block" and re.fullmatch(r"pmem\d+", name)):
            return
        if m.group(1) in ("bind", "unbind"):
            return
        node = self.node_label(tag)
        head = "%s %s" % (node, m.group(1))
        last = self.events[-1] if self.events else None
        # One line for what one action did: "vm1 add mem0 region0 dax0.0".
        if last and last[1] == "kern" and last[2].startswith(head + " ") and t - last[0] < 2:
            if name not in last[2].split():
                last[2] += " " + name
            return
        self.emit(t, "kern", "%s %s" % (head, name))

    def on_server(self, t, tag, text):
        m = re.search(r"attachment (\S+)@(\S+): (attached|detached|failed|exclusive \w+)", text)
        if not m:
            return
        dev, host, what = m.group(1), m.group(2), m.group(3)
        if what == "attached":
            self.emit(t, "pool", "%s attached to %s" % (dev, host))
        elif what == "detached":
            self.emit(t, "pool", "%s detached from %s" % (dev, host))
        elif what == "failed":
            self.emit(t, "pool", "%s on %s: attachment failed" % (dev, host))
        else:
            self.emit(t, "pool", "%s on %s: %s" % (dev, host, what))

    def on_controller(self, t, tag, text):
        text = re.sub(r"^fake-cxl-pool-controller: \S+ \S+ ", "", text)
        m = re.match(r"(attached|detached) (\S+) (to|from) (\S+)(.*?)(?: for \S+?/(\S+))?$", text)
        if m:
            excl = " excl" if "exclusive true" in (m.group(5) or "") else ""
            who = self.lease_who(m.group(6)) + ": " if m.group(6) else ""
            self.emit(t, "ctrl", "%s%s %s %s %s%s" % (who, m.group(1)[:-2] if m.group(1) == "attached" else "detach",
                                                      m.group(2), m.group(3), m.group(4), excl))
        elif re.search(r"(?i)\berror\b|failed", text):
            self.emit(t, "ctrl", "ERROR " + text)


def render_t5(trace, state, now=None, stale=False):
    lines = [c.title("TRACE", stale, now)]
    rows = ["%s %-5s %s" % (time.strftime("%H:%M:%S", time.localtime(t)), tag, trace.text(text))
            for t, tag, text in trace.events[-c.CONTENT_ROWS:]] if trace else []
    if not rows:
        rows = ["no events yet"]
    return lines + rows


###
### Collecting, painting
###

def collect(view, state):
    """Return the data of VIEW from the VMs, the pool server or the host."""
    ns = state.get("NS", "default")
    vm2, vm1 = state.get("VM2_DIR"), state.get("VM1_DIR")
    if view == "t2":
        return {"vm2": need(c.run_probe(vm2, ["--k8s", "pods,claims", "--ns", ns]), "pods", "claims")}
    if view == "t3":
        return {"vm2": need(c.run_probe(vm2, ["--k8s", "claims,slices,drivers", "--ns", ns]), "claims", "slices", "drivers")}
    if view == "t4":
        out, errs = {}, []

        def get(key, vmdir, args):
            try:
                out[key] = c.run_probe(vmdir, args)
            except RuntimeError as e:
                errs.append("%s: %s" % (key, e))
        ts = [threading.Thread(target=get, args=("vm2", vm2, ["--node", "--k8s", "pods,claims", "--ns", ns])),
              threading.Thread(target=get, args=("vm1", vm1, ["--node"]))]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        out["partial"] = errs
        if len(errs) == 2:
            raise RuntimeError("; ".join(errs))
        return out
    if view == "t6" and pool_case(state):
        dev = state.get("POOL_DEVICE", "shared0")
        out = {"device": c.http_json("%s/api/v1/devices/%s" % (state["POOL_URL"], dev))}
        try:
            with open(out["device"].get("path") or "", "rb") as f:
                if state.get("DEMO_CASE") == "pool-shared-fs":
                    # The erofs is on the block device: after the pfn info block.
                    out["fsOffset"], data = c.read_fsdax(f, 1 << 20)
                    out["fs"] = c.erofs_files(data)
                else:
                    out["hex"] = f.read(256).hex()
        except OSError as e:
            out["fileError"] = e.strerror or str(e)
        return {"pool": out}
    if view == "t6":
        return {"vm2": need(c.run_probe(vm2, ["--bytes", state.get("SERIAL", "0"), "--k8s", "claims,slices", "--ns", ns]),
                            "claims", "slices")}
    raise ValueError(view)


def need(probe, *kinds):
    missing = [k for k in kinds if k not in (probe.get("k8s") or {})]
    if missing:
        raise RuntimeError((probe.get("errors") or ["no %s" % ",".join(missing)])[0])
    return probe


TITLES = {"t2": "PODS & LEASES", "t3": "SCHEDULER: DEVICES AND CLAIMS", "t4": "NODES: CXL IN THE KERNEL",
          "t5": "TRACE", "t6": "MEMORY"}
RENDER = {"t2": render_t2, "t3": render_t3, "t4": render_t4, "t5": render_t5, "t6": render_t6}


def paint(lines, color):
    out = ["\033[H"]
    for i, line in enumerate(lines[:c.ROWS]):
        line = c.cut(line)
        if color:
            line = (c.BOLD + line + c.RESET) if i == 0 else c.colorize(line)
        out.append(line + "\033[K" + ("\n" if i < len(lines) - 1 else ""))
    out.append("\033[J")
    sys.stdout.write("".join(out))
    sys.stdout.flush()


def loop(view, case, color, interval, once):
    last, trace, trace_dir = None, None, None
    if not once:
        sys.stdout.write("\033[2J\033[?25l")
    try:
        while True:
            start = time.time()
            state = c.load_state()
            if state is None:
                lines = [c.title(TITLES[view]), "demo not set up: demo setup " + "|".join(CASES)]
                last, trace = None, None
            else:
                if case:
                    state["DEMO_CASE"] = case
                stale = False
                if view == "t5":
                    if trace is None or trace_dir != state.get("TRACE_DIR"):
                        trace_dir = state.get("TRACE_DIR")
                        trace = Trace(trace_dir, state)
                    trace.poll()
                    lines = render_t5(trace, state)
                else:
                    err = ""
                    try:
                        data = collect(view, state)
                        last = data
                        stale = bool(data.get("partial"))
                    except Exception as e:   # keep the last good rendering
                        stale = True
                        data = last
                        err = str(e)
                    if data is None:
                        lines = [c.title(TITLES[view], True), "no data yet: " + err]
                    else:
                        lines = RENDER[view](data, state, None, stale)
            if once:
                print("\n".join(c.cut(l) for l in lines))
                return
            paint(lines, color)
            time.sleep(max(0.1, interval - (time.time() - start)))
    except KeyboardInterrupt:
        pass
    finally:
        if not once:
            sys.stdout.write("\033[?25h\n")


def sample(view, sdir, now, until):
    """Render VIEW from the test data in SDIR, at the clock NOW."""
    state = c.load_state(os.path.join(sdir, "state.env")) or {}
    if view == "t5":
        tr = Trace(os.path.join(sdir, "trace"), state)
        tr.poll(until)
        return render_t5(tr, state, now)
    data = {}
    for key in ("vm2", "vm1", "pool"):
        p = os.path.join(sdir, key + ".json")
        if os.path.exists(p):
            with open(p) as f:
                data[key] = json.load(f)
    stale = os.path.exists(os.path.join(sdir, "stale"))
    return RENDER[view](data, state, now, stale)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help") or args[0] not in RENDER:
        sys.exit(__doc__)
    view = args[0]
    opt = {}
    rest = []
    i = 1
    while i < len(args):
        if args[i] in ("--sample", "--now", "--until", "--interval") and i + 1 < len(args):
            opt[args[i]] = args[i + 1]
            i += 2
        else:
            rest.append(args[i])
            i += 1
    if "--sample" in opt:
        now = float(opt.get("--now", time.time()))
        until = float(opt["--until"]) if "--until" in opt else None
        print("\n".join(c.cut(l) for l in sample(view, opt["--sample"], now, until)))
        return
    case = next((a for a in rest if a in CASES), None)
    loop(view, case, c.use_color(rest) and "--once" not in rest, float(opt.get("--interval", 1)), "--once" in rest)


if __name__ == "__main__":
    main()
