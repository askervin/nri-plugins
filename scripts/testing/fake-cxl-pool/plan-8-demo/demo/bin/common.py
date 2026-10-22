"""Shared helpers of the demo tools: state, ssh to the VMs, Kubernetes
objects of the demo, formatting for 50 x 10 terminals.

Standard library only. The VMs are reached with
"ssh -F <vm dir>/.ssh-config node"; the .ssh-config of the e2e VMs has
ControlMaster auto, so repeated calls reuse one connection.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

BIN_DIR = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR = os.path.dirname(BIN_DIR)
STATE_DIR = os.environ.get("DEMO_STATE_DIR", os.path.join(DEMO_DIR, "run"))
STATE_FILE = os.path.join(STATE_DIR, "state.env")
PROBE = os.path.join(BIN_DIR, "probe.py")

terminal_size = shutil.get_terminal_size()
WIDTH = terminal_size.columns
ROWS = terminal_size.lines
CONTENT_ROWS = ROWS - 1

LEASE_LABEL = "cxl.nri.io/lease"
REQUESTER_ANNOTATION = "cxl.nri.io/requester"
REQUESTER_UID_LABEL = "cxl.nri.io/requester-uid"
SHARES_KEYS = ("shares", "hosts")   # "hosts": drivers before plan-9


def load_state(path=STATE_FILE):
    """Return the KEY=VALUE pairs of the state file of demo setup, or None."""
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return None
    state = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        state[key.strip()] = value
    return state


def ssh_base(vmdir):
    """Return the ssh command line to the VM of the e2e output dir VMDIR."""
    return ["ssh", "-F", os.path.join(vmdir, ".ssh-config"),
            "-o", "ConnectTimeout=3", "-o", "BatchMode=yes", "node"]


def run_vm(vmdir, script, timeout=60):
    """Return (exit status, output) of the bash SCRIPT run as root in the VM."""
    try:
        p = subprocess.run(ssh_base(vmdir) + ["sudo", "bash", "-l"], input=script.encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return 124, (e.output or b"").decode(errors="replace") + "\n(timeout after %ds)" % timeout
    return p.returncode, p.stdout.decode(errors="replace")


def run_probe(vmdir, args, timeout=4.0):
    """Return the JSON that probe.py ARGS prints as root in the VM.

    The probe goes over stdin: nothing is installed in the VM. Raise
    RuntimeError on failure or timeout.
    """
    with open(PROBE, "rb") as f:
        code = f.read()
    try:
        p = subprocess.run(ssh_base(vmdir) + ["sudo", "python3", "-"] + list(args), input=code,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError("timeout")
    if p.returncode != 0:
        err = p.stderr.decode(errors="replace").strip().splitlines()
        raise RuntimeError(err[-1] if err else "ssh exit %d" % p.returncode)
    try:
        return json.loads(p.stdout.decode(errors="replace"))
    except ValueError as e:
        raise RuntimeError("bad probe output: %s" % e)


def http_json(url, timeout=3.0):
    """Return the JSON document at URL (the pool server)."""
    import urllib.request
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


###
### Names
###

def short_node(name, state):
    """Return vm1/vm2 for the node names of the demo, else NAME cut to 8."""
    if not name:
        return "-"
    for key, short in (("VM1_NODE", "vm1"), ("VM2_NODE", "vm2")):
        if state and state.get(key) == name:
            return short
    m = re.match(r"n4-cxl-shared-(\d)", name)
    if m:
        return "vm" + m.group(1)
    return name[:8]


def short_text(text, state):
    """Return TEXT with node names replaced by vm1/vm2 and the namespace cut."""
    for key, short in (("VM1_NODE", "vm1"), ("VM2_NODE", "vm2")):
        if state and state.get(key):
            text = text.replace(state[key], short)
    text = re.sub(r"n4-cxl-shared-(\d)-[a-z0-9.-]*?-(containerd|crio)", r"vm\1", text)
    ns = (state or {}).get("NS")
    if ns:
        text = text.replace(ns + "/", "")
    return text


###
### Quantities and sizes
###

_SUFFIX = {"": 1, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18, "m": 1e-3,
           "Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50, "Ei": 1 << 60}


def quantity(q):
    """Return the value of a Kubernetes quantity string or number, None if unparsable."""
    if q is None:
        return None
    if isinstance(q, (int, float)):
        return float(q)
    m = re.fullmatch(r"\s*([+-]?[0-9.]+(?:[eE][+-]?[0-9]+)?)\s*([kMGTPEm]i?|)\s*", str(q))
    if not m or m.group(2) not in _SUFFIX:
        return None
    try:
        return float(m.group(1)) * _SUFFIX[m.group(2)]
    except ValueError:
        return None


def k8s_size(n):
    """Return bytes N as 256Mi, 1Gi, ... (binary units)."""
    if n is None:
        return "?"
    n = int(n)
    for unit, shift in (("Ti", 40), ("Gi", 30), ("Mi", 20), ("Ki", 10)):
        if n >= 1 << shift and n % (1 << shift) == 0:
            return "%d%s" % (n >> shift, unit)
    for unit, shift in (("Ti", 40), ("Gi", 30), ("Mi", 20), ("Ki", 10)):
        if n >= 1 << shift:
            return "%.1f%s" % (n / (1 << shift), unit)
    return str(n)


def kernel_size(n):
    """Return bytes N as 1.0G, 256M, ... (as the kernel view prints them)."""
    if n is None:
        return "?"
    n = int(n)
    if n >= 1 << 30:
        return "%.1fG" % (n / (1 << 30))
    if n >= 1 << 20:
        return "%dM" % (n >> 20)
    if n >= 1 << 10:
        return "%dK" % (n >> 10)
    return str(n)


def int_any(s):
    """Return the int of a decimal or 0x hex string, None if it is neither."""
    try:
        return int(str(s).strip(), 0)
    except (TypeError, ValueError):
        return None


###
### Kubernetes objects
###

def items(doc, kind=None):
    """Return the items of a List document, of KIND only if given."""
    if not doc:
        return []
    its = doc.get("items") if "items" in doc else [doc]
    return [i for i in its or [] if kind is None or i.get("kind") == kind]


def meta(o):
    return o.get("metadata") or {}


def labels(o):
    return meta(o).get("labels") or {}


def requester(o):
    """Return the requester pod name of a companion claim or pod, or None."""
    req = (meta(o).get("annotations") or {}).get(REQUESTER_ANNOTATION)
    if req:
        parts = req.split("/")
        if len(parts) >= 2:
            return parts[1]
    return None


def lease_id(o):
    return labels(o).get(LEASE_LABEL)


def deleting(o):
    return bool(meta(o).get("deletionTimestamp"))


def allocation(claim):
    return (claim.get("status") or {}).get("allocation")


def results(claim):
    a = allocation(claim) or {}
    return (a.get("devices") or {}).get("results") or []


def allocated_node(claim):
    a = allocation(claim) or {}
    for term in (a.get("nodeSelector") or {}).get("nodeSelectorTerms") or []:
        for f in term.get("matchFields") or []:
            if f.get("key") == "metadata.name" and f.get("values"):
                return f["values"][0]
    return None


def subrequests(claim):
    """Return the requests of a claim, firstAvailable subrequests flattened.

    Each entry is a dict with name, deviceClassName, selectors, capacity.
    """
    out = []
    for r in ((claim.get("spec") or {}).get("devices") or {}).get("requests") or []:
        if r.get("exactly"):
            e = dict(r["exactly"])
            e["name"] = r.get("name")
            out.append(e)
        for s in r.get("firstAvailable") or []:
            e = dict(s)
            e["name"] = "%s/%s" % (r.get("name"), s.get("name"))
            out.append(e)
    return out


def claim_serials(claim):
    """Return the serials that the CEL selectors of a claim name."""
    found = []
    for r in subrequests(claim):
        for s in r.get("selectors") or []:
            expr = (s.get("cel") or {}).get("expression") or ""
            for m in re.finditer(r"serial\s*==\s*\"(0x[0-9a-fA-F]+)\"", expr):
                if m.group(1).lower() not in found:
                    found.append(m.group(1).lower())
    return found


def claim_configs(claim):
    """Return the opaque DeviceConfig parameters of a claim: [(driver, requests, params)]."""
    a = allocation(claim)
    configs = ((a or {}).get("devices") or {}).get("config")
    if configs is None:
        configs = ((claim.get("spec") or {}).get("devices") or {}).get("config") or []
    out = []
    for c in configs:
        op = c.get("opaque") or {}
        out.append((op.get("driver"), c.get("requests") or [], op.get("parameters") or {}))
    return out


def claim_params(claim, driver=None, request=None):
    """Return the DeviceConfig parameters that apply to a result of DRIVER and REQUEST."""
    best = {}
    for drv, reqs, params in claim_configs(claim):
        if driver and drv and drv != driver:
            continue
        if reqs and request and request not in reqs and request.split("/")[0] not in reqs:
            continue
        best = params
    return best


def shares_request(claim):
    """Return the shares quantity a claim requests, None if it requests none."""
    for r in subrequests(claim):
        reqs = (r.get("capacity") or {}).get("requests") or {}
        for k in SHARES_KEYS:
            if k in reqs:
                return reqs[k]
    return None


def consumed_shares(result):
    cc = result.get("consumedCapacity") or {}
    for k in SHARES_KEYS:
        if k in cc:
            return cc[k]
    return None


def device_attr(dev, name):
    """Return the value of attribute NAME of a ResourceSlice device."""
    attrs = dev.get("attributes") or {}
    a = attrs.get(name)
    if a is None:
        for k, v in attrs.items():
            if k.endswith("/" + name):
                a = v
                break
    if not isinstance(a, dict):
        return None
    for t in ("string", "int", "bool", "version"):
        if t in a:
            return a[t]
    return None


def device_shares(dev):
    cap = dev.get("capacity") or {}
    for k in SHARES_KEYS:
        if k in cap:
            return cap[k].get("value")
    return None


def slice_devices(slices_doc):
    """Return [(driver, pool, where, device)] of the ResourceSlices; WHERE is a node name or None."""
    out = []
    for s in items(slices_doc):
        spec = s.get("spec") or {}
        where = spec.get("nodeName")
        for d in spec.get("devices") or []:
            out.append((spec.get("driver"), (spec.get("pool") or {}).get("name"), where, d))
    return out


def holder_name(claim):
    """Return who holds or wants a claim: the requester pod of a lease, else the reserving pod or the claim."""
    r = requester(claim)
    if r:
        return r
    reserved = (claim.get("status") or {}).get("reservedFor") or []
    if reserved:
        return reserved[0].get("name") or meta(claim).get("name")
    return meta(claim).get("name")


def holding(claim, result, dev):
    """Return (exclusive, read-only) of an allocation RESULT of CLAIM on the shared device DEV."""
    consumed = quantity(consumed_shares(result))
    total = quantity(device_shares(dev)) if dev else None
    if consumed is not None and total is not None:
        exclusive = consumed >= total
    elif consumed is not None:
        exclusive = consumed > 1
    else:
        exclusive = shares_request(claim) is None
    ro = bool(claim_params(claim, result.get("driver"), result.get("request")).get("readOnly"))
    return exclusive, ro


def lease_memory(claim):
    """Return the MEMORY column of a lease: dax rw excl, dax ro share, waiting, releasing."""
    if deleting(claim):
        return "releasing"
    res = results(claim)
    if not res:
        return "waiting"
    r = res[0]
    params = claim_params(claim, r.get("driver"), r.get("request"))
    mode = params.get("mode") or "numa"
    access = "ro" if params.get("readOnly") else "rw"
    consumed = consumed_shares(r)
    if consumed is None and shares_request(claim) is None and not any(
            (s.get("deviceClassName") or "").endswith("-shared") for s in subrequests(claim)):
        return "%s %s" % (mode, access)
    q = quantity(consumed)
    share = (q is not None and q <= 1) or (q is None and shares_request(claim) is not None)
    return "%s %s %s" % (mode, access, "share" if share else "excl")


###
### erofs
###

EROFS_MAGIC = 0xE0F5E1E2
EROFS_SUPER_OFFSET = 1024
EROFS_LAYOUTS = {0: "plain", 1: "compressed", 2: "inline", 3: "compressed", 4: "chunk-based"}
EROFS_TEXT_LEN = 48


PFN_INFO = b"NVDIMM_PFN_INFO\0"
PFN_INFO_OFFSET = 4096


def fsdax_data_offset(head):
    """Return where the block device of an fsdax namespace starts in the device bytes HEAD (from 0), 0 without a pfn info block."""
    import struct
    o = PFN_INFO_OFFSET
    if head[o:o + 16] != PFN_INFO or len(head) < o + 64:
        return 0
    # struct nd_pfn_sb: signature, uuid, parent_uuid, flags, version
    # major and minor, then dataoff (from the start of the namespace).
    return struct.unpack_from("<Q", head, o + 56)[0]


def read_fsdax(f, length):
    """Return (offset, data): LENGTH bytes of the block device of the fsdax namespace at the start of the open device file F."""
    f.seek(0)
    off = fsdax_data_offset(f.read(2 * PFN_INFO_OFFSET))
    f.seek(off)
    return off, f.read(length)


def read_hex(path):
    """Return the bytes of a hex dump file; lines starting with # are comments."""
    with open(path) as f:
        return bytes.fromhex("".join(l for l in f if not l.lstrip().startswith("#")))


def _erofs_inode(data, sb, nid):
    """Return the fields of the inode NID of the erofs image DATA with the superblock SB."""
    import struct
    off = sb["meta_blkaddr"] * sb["blocksize"] + nid * 32
    if off + 32 > len(data):
        raise ValueError("inode %d at %d is beyond the data" % (nid, off))
    fmt, xcount, mode = struct.unpack_from("<HHH", data, off)
    if fmt & 1 == 0:
        size, raw = struct.unpack_from("<I4xI", data, off + 8)
        isize = 32
    else:
        if off + 64 > len(data):
            raise ValueError("inode %d at %d is beyond the data" % (nid, off))
        size, raw = struct.unpack_from("<QI", data, off + 8)
        isize = 64
    xsize = 12 + (xcount - 1) * 4 if xcount else 0
    return {"nid": nid, "offset": off, "extended": bool(fmt & 1), "layout": (fmt >> 1) & 7, "mode": mode,
            "size": size, "rawBlkaddr": raw, "tail": off + isize + xsize}


def _erofs_data(data, sb, ino, limit):
    """Return the first LIMIT bytes of the data of inode INO, ValueError if they cannot be read."""
    bs, size = sb["blocksize"], ino["size"]
    want = min(size, limit)
    if ino["layout"] == 0:
        start = ino["rawBlkaddr"] * bs
        out = data[start:start + want]
    elif ino["layout"] == 2:
        full = size // bs * bs
        head = data[ino["rawBlkaddr"] * bs:ino["rawBlkaddr"] * bs + min(full, want)] if full else b""
        out = head + data[ino["tail"]:ino["tail"] + max(0, want - full)]
    else:
        raise ValueError("data layout %s of inode %d" % (EROFS_LAYOUTS.get(ino["layout"], ino["layout"]), ino["nid"]))
    if len(out) < want:
        raise ValueError("the data of inode %d is beyond the data" % ino["nid"])
    return out


def erofs_files(data):
    """Return what the start DATA of an erofs image holds: type, files, error, super.

    type is "erofs", "zeros" (DATA is all zeros) or "none" (no erofs
    magic); files are the entries of the root directory, each {name, size,
    type, text}: text is the first 48 bytes of a regular file up to its
    first newline, printable ASCII, "(not readable)" if the data does not
    hold them; super has the superblock fields; error says what could not
    be read ("" for nothing).
    """
    import struct
    out = {"type": "none", "files": [], "error": "", "super": {}}
    if not any(data):
        out["type"] = "zeros"
        return out
    sbo = EROFS_SUPER_OFFSET
    if len(data) < sbo + 128 or struct.unpack_from("<I", data, sbo)[0] != EROFS_MAGIC:
        return out
    out["type"] = "erofs"
    compat, bits, _, root2, inos = struct.unpack_from("<IBBHQ", data, sbo + 8)
    blocks, meta, xattr = struct.unpack_from("<III", data, sbo + 36)
    incompat = struct.unpack_from("<I", data, sbo + 80)[0]
    root = struct.unpack_from("<Q", data, sbo + 112)[0] if incompat & 0x80 else root2
    sb = {"magic": "0x%08x" % EROFS_MAGIC, "blocksize": 1 << bits, "blkszbits": bits, "inos": inos,
          "blocks": blocks, "rootNid": root, "metaBlkaddr": meta, "xattrBlkaddr": xattr,
          "featureCompat": "0x%x" % compat, "featureIncompat": "0x%x" % incompat}
    out["super"] = sb
    geom = {"blocksize": sb["blocksize"], "meta_blkaddr": meta}
    try:
        if not 9 <= bits <= 16:
            raise ValueError("block size 2^%d" % bits)
        rootino = _erofs_inode(data, geom, root)
        if rootino["mode"] & 0o170000 != 0o040000:
            raise ValueError("root inode %d is not a directory" % root)
        dirents = _erofs_data(data, geom, rootino, sb["blocksize"])
        if len(dirents) < 12:
            raise ValueError("root directory without entries")
        count = struct.unpack_from("<H", dirents, 8)[0] // 12
        ents = [struct.unpack_from("<QHBx", dirents, 12 * i) for i in range(count)]
        for i, (nid, nameoff, ftype) in enumerate(ents):
            end = ents[i + 1][1] if i + 1 < count else len(dirents)
            name = dirents[nameoff:end].split(b"\0", 1)[0].decode(errors="replace")
            if name in (".", ".."):
                continue
            f = {"name": name, "size": None, "type": {1: "file", 2: "dir", 7: "symlink"}.get(ftype, "other")}
            try:
                ino = _erofs_inode(data, geom, nid)
                f["size"] = ino["size"]
                if ftype == 1:
                    text = _erofs_data(data, geom, ino, EROFS_TEXT_LEN).split(b"\n", 1)[0]
                    f["text"] = "".join(chr(b) if 32 <= b < 127 else "." for b in text)
            except ValueError as e:
                out["error"] = out["error"] or str(e)
                if ftype == 1:
                    f["text"] = "(not readable)"
            out["files"].append(f)
    except (ValueError, struct.error) as e:
        out["error"] = str(e)
    return out


###
### Formatting
###

def cut(line, width=WIDTH):
    """Return LINE as printable ASCII, cut to WIDTH columns."""
    line = "".join(c if 32 <= ord(c) < 127 else "?" for c in line.expandtabs(4))
    return line[:width]


def title(text, stale=False, now=None, width=WIDTH, extra=""):
    """Return the title line: TEXT left, [stale] [EXTRA] HH:MM:SS right."""
    clock = time.strftime("%H:%M:%S", time.localtime(now if now is not None else time.time()))
    right = ("stale " if stale else "") + (extra + " " if extra else "") + clock
    text = text[:max(0, width - len(right) - 1)]
    return text + " " * (width - len(text) - len(right)) + right


def fit(lines, rows=CONTENT_ROWS):
    """Return at most ROWS lines; the last one says how many more there are."""
    if len(lines) <= rows:
        return lines
    keep = lines[:rows - 1]
    return keep + ["... %d more" % (len(lines) - len(keep))]


def wrap_list(prefix, words, indent=None, width=WIDTH, sep=","):
    """Return lines PREFIX w1, w2, ... wrapped at WIDTH, continued at INDENT."""
    ind = " " * (len(prefix) if indent is None else indent)
    lines, cur = [], prefix
    for i, w in enumerate(words):
        piece = w + (sep if i < len(words) - 1 else "")
        fresh = cur in (prefix, ind)
        space = "" if fresh else " "
        if not fresh and len(cur) + len(space) + len(piece) > width:
            lines.append(cur)
            cur, space = ind, ""
        cur += space + piece
    lines.append(cur.rstrip())
    return lines


GREEN, YELLOW, RED, BOLD, RESET = "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[0m"
_COLOR_WORDS = [
    (RED, r"\b(refused|Failed|ERROR|error|restarting|down|EACCES|failed)\b"),
    (YELLOW, r"\b(waiting|waits|Pending|releasing|stale|Exiting|attaching|detaching)\b"),
    (GREEN, r"\b(Ready|Running|ok|allocated|excl|share|exclusive|shared|attached)\b"),
]


def colorize(line):
    """Return LINE with the words of states colored (ANSI)."""
    for code, pattern in _COLOR_WORDS:
        line = re.sub(pattern, lambda m: code + m.group(0) + RESET, line)
    return line


def use_color(argv):
    if "--no-color" in argv or os.environ.get("NO_COLOR"):
        return False
    if "--color" in argv or os.environ.get("DEMO_COLOR") == "1":
        return True
    return sys.stdout.isatty() and os.environ.get("TERM", "dumb") != "dumb"
