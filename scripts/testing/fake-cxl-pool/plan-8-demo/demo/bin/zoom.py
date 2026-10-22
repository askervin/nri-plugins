#!/usr/bin/env python3
"""Zooms for questions: details the views leave out (03-demo-design section 7).

Usage: zoom.py WHAT [ARGS]
  slice [DEVICE]    the ResourceSlice entry: attributes, capacity
  claim POD         the companion claims of POD's leases: request,
                    allocation, config
  pod POD           why the companions of POD's leases wait (PodScheduled)
  env POD           the CXL_* variables of POD's leases
  cdi NODE          the CDI specs of the node's claims and leases
  driver NODE [N]   the last N (30) lines of the driver's log
  kernel NODE       dmesg lines of cxl, dax, memory
  cxl NODE          cxl list -M -R -X (memdevs, regions, dax)
  pool              the pool server's devices and attachments
  fs                the erofs in the pool device's backing file: the
                    superblock and the files of the root directory
  mounts NODE       the node's erofs mounts, loop devices and lease binds
  bytes [OFFSET]    a hex dump of 256 bytes of the demo device from OFFSET
                    (default 0); in pool-shared-fs of its block device
                    (1024 is the erofs superblock)
  last              the full output of the last step
NODE is vm1 or vm2. The output is plain text; "demo zoom" pages it.
"""
import json
import os
import sys

import common as c


def vmdir(state, node):
    key = {"vm1": "VM1_DIR", "vm2": "VM2_DIR"}.get(node)
    if not key:
        sys.exit("NODE is vm1 or vm2, not %r" % node)
    return state[key]


def k8s(state, kinds):
    p = c.run_probe(state["VM2_DIR"], ["--k8s", kinds, "--ns", state["NS"]], timeout=10)
    for e in p.get("errors") or []:
        print("error: " + e)
    return p.get("k8s") or {}


def companions(state, pod, kinds="claims"):
    k = k8s(state, kinds + ",pods")
    objs = [o for o in c.items(k.get("claims")) + c.items(k.get("pods")) if c.lease_id(o) and c.requester(o) == pod]
    if not objs:
        print("%s has no leases" % pod)
    return objs


def show(obj, indent="  "):
    print("\n".join(indent + l for l in json.dumps(obj, indent=1, sort_keys=True).splitlines()))


def zoom_slice(state, args):
    k = k8s(state, "slices")
    for drv, pool, where, d in c.slice_devices(k.get("slices")):
        if args and d.get("name") != args[0]:
            continue
        if not args and c.device_attr(d, "type") == "lease":
            continue
        print("%s  driver %s, pool %s, %s" % (d.get("name"), drv, pool, ("node " + c.short_node(where, state)) if where else "all nodes"))
        for name in sorted(d.get("attributes") or {}):
            print("  %-14s %s" % (name, c.device_attr(d, name)))
        for name, cap in sorted((d.get("capacity") or {}).items()):
            pol = cap.get("requestPolicy")
            print("  capacity %s: %s%s" % (name, cap.get("value"), " policy %s" % json.dumps(pol) if pol else " (no request policy)"))
        if d.get("allowMultipleAllocations"):
            print("  allowMultipleAllocations: true")


def zoom_claim(state, args):
    for cl in companions(state, args[0]):
        if cl.get("kind") != "ResourceClaim":
            continue
        print("claim %s (lease %s)%s" % (c.meta(cl).get("name"), c.lease_id(cl), " deleting" if c.deleting(cl) else ""))
        for r in c.subrequests(cl):
            print("  request %s: class %s" % (r.get("name"), r.get("deviceClassName")))
            for s in r.get("selectors") or []:
                print("    selector " + (s.get("cel") or {}).get("expression", "?"))
            print("    capacity %s" % json.dumps((r.get("capacity") or {}).get("requests") or "none (the whole device)"))
        if not c.allocation(cl):
            print("  allocation: none (waiting)")
        for res in c.results(cl):
            print("  allocated %s/%s on %s" % (res.get("pool"), res.get("device"), c.short_node(c.allocated_node(cl), state)))
            print("    consumed %s" % json.dumps(res.get("consumedCapacity") or {}))
        for drv, reqs, params in c.claim_configs(cl):
            print("  config %s%s: %s" % (drv, " " + ",".join(reqs) if reqs else "", json.dumps(params, sort_keys=True)))


def zoom_pod(state, args):
    for p in companions(state, args[0], "claims"):
        if p.get("kind") != "Pod":
            continue
        st = p.get("status") or {}
        print("companion pod %s: %s on %s" % (c.meta(p).get("name"), st.get("phase"), c.short_node((p.get("spec") or {}).get("nodeName"), state)))
        for cond in st.get("conditions") or []:
            if cond.get("type") == "PodScheduled":
                print("  PodScheduled %s %s" % (cond.get("status"), cond.get("reason") or ""))
                if cond.get("message"):
                    print("  " + c.short_text(cond["message"], state))


def pool_device(state):
    """Return the pool server's JSON of the demo's pool device."""
    return c.http_json("%s/api/v1/devices/%s" % (state["POOL_URL"], state.get("POOL_DEVICE", "shared0")))


def zoom_fs(state):
    if not (state.get("DEMO_CASE") or "").startswith("pool"):
        sys.exit("zoom fs: the file system is in the pool device of pool-shared-fs, not in the %s demo" % state.get("DEMO_CASE"))
    dev = pool_device(state)
    with open(dev["path"], "rb") as f:
        off, data = c.read_fsdax(f, 1 << 20)
    fs = c.erofs_files(data)
    print("%s, the backing file %s on the host; its block device (pmem) starts at %d:" % (dev["name"], dev["path"], off))
    if fs["type"] != "erofs":
        print("no file system%s" % (" (the first MiB is zeros)" if fs["type"] == "zeros" else " (no erofs magic at 1024)"))
        return
    sb = fs["super"]
    print("erofs superblock at 1024: magic %s, block size %d, inodes %d, blocks %d, root nid %d" % (
        sb["magic"], sb["blocksize"], sb["inos"], sb["blocks"], sb["rootNid"]))
    print("  meta_blkaddr %d, xattr_blkaddr %d, feature_compat %s, feature_incompat %s" % (
        sb["metaBlkaddr"], sb["xattrBlkaddr"], sb["featureCompat"], sb["featureIncompat"]))
    print("root directory:")
    for f in fs["files"]:
        size = "" if f.get("size") is None else " %d bytes" % f["size"]
        text = ' "%s"' % f["text"] if f.get("text") and f["text"] != "(not readable)" else (" " + f["text"] if f.get("text") else "")
        print("  %s %s%s%s" % (f["type"], f["name"], size, text))
    if fs["error"]:
        print("not readable: " + fs["error"])


def zoom_mounts(state, node):
    zoom_shell(state, node, "echo '== erofs mounts'; findmnt -t erofs -o TARGET,SOURCE,FSTYPE,OPTIONS || echo none; "
               "echo '== loop devices'; losetup -l; "
               "echo '== lease binds'; find /var/lib/kubelet/plugins/cxl.nri.io/lease-fs -maxdepth 2 2>&1")


def zoom_shell(state, node, script, timeout=30):
    rc, out = c.run_vm(vmdir(state, node), script, timeout)
    print(c.short_text(out.rstrip(), state))


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        sys.exit(__doc__)
    if args[0] == "last":
        try:
            with open(os.path.join(c.STATE_DIR, "steps.log")) as f:
                text = f.read()
        except OSError:
            sys.exit("no steps run yet")
        print(text[text.rfind("=== "):].rstrip())
        return
    state = c.load_state()
    if state is None:
        sys.exit("demo not set up: demo setup local|pool|pool-shared-fs")
    what, rest = args[0], args[1:]
    ns = state["NS"]
    if what == "slice":
        zoom_slice(state, rest)
    elif what == "claim" and rest:
        zoom_claim(state, rest)
    elif what == "pod" and rest:
        zoom_pod(state, rest)
    elif what == "env" and rest:
        zoom_shell(state, "vm2", "kubectl exec -n %s %s -- /demo/env" % (ns, rest[0]))
    elif what == "cdi" and rest:
        zoom_shell(state, rest[0], "for f in /etc/cdi/*cxl* /var/run/cdi/*cxl*; do [ -f \"$f\" ] && { echo \"== $f\"; cat \"$f\"; }; done; ls /etc/cdi/*cxl* /var/run/cdi/*cxl* >/dev/null 2>&1 || echo 'no CDI specs of nri.io/cxl: no claim with a device is prepared on this node'")
    elif what == "driver" and rest:
        n = int(rest[1]) if len(rest) > 1 else 30
        node = state["VM1_NODE" if rest[0] == "vm1" else "VM2_NODE"]
        zoom_shell(state, "vm2", "pod=$(kubectl get pods -n kube-system -l app.kubernetes.io/name=nri-dra-driver-cxl "
                   "--field-selector spec.nodeName=%s -o name | head -n 1); kubectl logs -n kube-system --tail=%d -c nri-dra-driver-cxl $pod "
                   "| grep -vE 'CA file|Watch close|some fields were dropped|Waited before sending request' | tail -n %d "
                   "| sed -E 's/^[IWEF][0-9]{4} [0-9:.]+ +[0-9]+ [^]]+\\] //'" % (node, 4 * n, n))
    elif what == "kernel" and rest:
        zoom_shell(state, rest[0], "dmesg -T | grep -iE 'cxl|dax|memory|region' | grep -vE '(save|restore) config|pci_notify|IRQ mapping|bus mastering' | tail -n 40")
    elif what == "cxl" and rest:
        zoom_shell(state, rest[0], "cxl list -M -R -X -u 2>&1")
    elif what == "pool":
        for kind in ("devices", "attachments"):
            print("== %s" % kind)
            try:
                for o in c.http_json("%s/api/v1/%s" % (state["POOL_URL"], kind)) or []:
                    if kind == "devices":
                        print("%s %s %s %s %s scope %s%s" % (o.get("name"), o.get("serial"), c.k8s_size(o.get("size")),
                                                             "shared" if o.get("shared") else "exclusive", o.get("state"),
                                                             o.get("scope"), "  file " + o["path"] if o.get("path") else ""))
                    else:
                        print("%s %s%s owner %s" % (c.short_text(o.get("id", "?"), state), o.get("state"),
                                                   " exclusive" if o.get("exclusive") else "", o.get("owner") or "-"))
            except OSError as e:
                print("pool server: %s" % e)
    elif what == "fs":
        zoom_fs(state)
    elif what == "mounts" and rest:
        zoom_mounts(state, rest[0])
    elif what == "bytes":
        start = c.int_any(rest[0]) if rest else 0
        if start is None or not 0 <= start <= (2 << 20) - 256:
            sys.exit("bytes [OFFSET]: OFFSET is 0 to %d" % ((2 << 20) - 256))
        if state.get("DEMO_CASE") == "pool-shared-fs":
            dev = pool_device(state)
            with open(dev["path"], "rb") as f:
                off, data = c.read_fsdax(f, start + 256)
            data = data[start:]
            print("%s, the block device in the backing file %s (from %d), from %d:" % (dev["name"], dev["path"], off, start))
        elif state.get("DEMO_CASE") == "pool":
            dev = pool_device(state)
            with open(dev["path"], "rb") as f:
                f.seek(start)
                data = f.read(256)
            print("%s, the backing file %s on the host, from %d:" % (dev["name"], dev["path"], start))
        else:
            b = c.run_probe(state["VM2_DIR"], ["--bytes", state["SERIAL"], "--len", str(start + 256)], timeout=10).get("bytes") or {}
            if not b.get("hex"):
                sys.exit("cannot read: %s" % b.get("error"))
            data = bytes.fromhex(b["hex"])[start:]
            print("/dev/%s (%s, %s) on vm2, from %d:" % (b.get("dax"), b.get("region"), b.get("memdev"), start))
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            print("%04x  %-48s %s" % (start + off, " ".join("%02x" % x for x in chunk),
                                     "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
