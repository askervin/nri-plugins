#!/usr/bin/env python3
"""Desk check of the demo: every rendering fits 50 x 10.

Usage: selftest.py [--write] [--quiet]

- renders the views of every scenario in testdata/ (t2, t3, t4, t6 from
  vm2.json, vm1.json, pool.json; t5 from trace/ at several points of time)
  and checks: at most 10 lines, at most 50 columns, printable ASCII;
- runs probe.py on fake /sys, /proc and /dev trees (a ram region with a
  dax device; a pmem region with an erofs on its block device, a node
  mount, a lease bind and an opener) and renders T4 and T6 from its output;
- reads the real erofs image testdata/hello.erofs.hex with
  common.erofs_files;
- checks the trace lines of trace-fs (block and fs leases, binds, node
  mounts) and the translation of the log lines of the current driver and
  controller, written with their format strings (trace_formats_test);
- checks the trace lines of trace-pool-fs (a writer's exclusive attach, a
  reader's Conflict once however often the scheduler retries, the
  downgrade) and the superblocks of testdata/pool-fs-super.json (fsinfo);
- lays out the presenter terminal (T1) of every step of the four scripts
  with a two-line result and checks that it fits;
- checks a few helpers (quantities, wrapping, lease memory words, the
  claim status of pool-fs, its step checks);
- runs the checks of the wizard (wizard_check.py: its rules, its YAML,
  its question screens, the states of its objects, its scripted set).
The terminal size is 50 x 10 whatever the terminal.
Prints the renderings (testdata/renderings.txt with --write) and exits 1
on the first failed check.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

os.environ["TZ"] = "UTC"
os.environ["COLUMNS"], os.environ["LINES"] = "50", "10"
time.tzset()

import common as c   # noqa: E402
import fsinfo        # noqa: E402
import steps         # noqa: E402
import views         # noqa: E402
import wizard_check  # noqa: E402

TESTDATA = os.path.join(c.DEMO_DIR, "testdata")
NOW = 1792500067.0
failures = []
out = []


def check(name, lines):
    """Check one rendering and add it to the report."""
    problems = []
    if len(lines) > c.ROWS:
        problems.append("%d lines" % len(lines))
    for i, l in enumerate(lines):
        if len(l) > c.WIDTH:
            problems.append("line %d has %d columns" % (i + 1, len(l)))
        if any(not 32 <= ord(ch) < 127 for ch in l):
            problems.append("line %d is not printable ASCII" % (i + 1))
    out.append("+" + "-" * c.WIDTH + "+ " + name + (" FAIL: " + "; ".join(problems) if problems else ""))
    out.extend("|" + l.ljust(c.WIDTH) + "|" for l in lines)
    out.append("+" + "-" * c.WIDTH + "+")
    if problems:
        failures.append("%s: %s" % (name, "; ".join(problems)))


def expect(name, cond, detail=""):
    if not cond:
        failures.append("%s %s" % (name, detail))


def scenarios():
    for d in sorted(os.listdir(TESTDATA)):
        p = os.path.join(TESTDATA, d)
        if os.path.isdir(p) and os.path.exists(os.path.join(p, "state.env")):
            yield d, p


def render_scenarios():
    for name, p in scenarios():
        if os.path.exists(os.path.join(p, "vm2.json")):
            for v in ("t2", "t3", "t4", "t6"):
                check("%s %s" % (name, v), [c.cut(l) for l in views.sample(v, p, NOW, None)])
        tdir = os.path.join(p, "trace")
        if os.path.isdir(tdir):
            stamps = []
            for f in os.listdir(tdir):
                with open(os.path.join(tdir, f)) as fh:
                    for line in fh:
                        try:
                            stamps.append(float(line.split(" ", 1)[0]))
                        except ValueError:
                            pass
            stamps.sort()
            if not stamps:
                continue
            points = [stamps[int(len(stamps) * k / 4)] for k in range(1, 4)] + [stamps[-1]]
            for t in points:
                lines = [c.cut(l) for l in views.sample("t5", p, t, t)]
                check("%s t5 at %s" % (name, time.strftime("%H:%M:%S", time.gmtime(t))), lines)
                expect("%s t5" % name, len(lines) > 1 and lines[1] != "no events yet", "has no events")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def fake_tree(root):
    """Build /sys, /proc and /dev of a node with the local device shared by a writer and a reader."""
    cxl = root + "/sys/bus/cxl/devices"
    write(cxl + "/mem0/serial", "0xc100e2e1\n")
    write(cxl + "/mem0/ram/size", "0x40000000\n")
    write(cxl + "/mem0/numa_node", "0\n")
    os.makedirs(cxl + "/endpoint4", exist_ok=True)
    os.symlink("../../../../devices/pci0000:0c/0000:0c:00.0/mem0", cxl + "/endpoint4/uport")
    os.symlink("../../../../bus/cxl/drivers/cxl_mem", cxl + "/mem0/driver")
    write(cxl + "/region0/mode", "ram\n")
    write(cxl + "/region0/size", "0x40000000\n")
    write(cxl + "/region0/target0", "decoder4.0\n")
    write(cxl + "/region0/dax_region0/dax0.0/size", "1073741824\n")
    write(cxl + "/region0/dax_region0/dax0.0/target_node", "2\n")
    os.makedirs(root + "/sys/bus/dax/devices/dax0.0", exist_ok=True)
    os.symlink("../../../../bus/dax/drivers/device_dax", root + "/sys/bus/dax/devices/dax0.0/driver")
    write(root + "/proc/sys/kernel/hostname", "n4-cxl-shared-2-fedora-43-containerd\n")
    cg = "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod%s.slice/cri-containerd-0123.scope\n"
    for pid, uid, perms in ((100, "0644829a_2838_4cb6_9708_f7ff0d84a9dc", "r--s"),
                            (101, "30c961ce_314b_4317_b08f_af695a53d3f2", "rw-s"),
                            (102, None, "rw-s")):
        write("%s/proc/%d/cgroup" % (root, pid), cg % uid if uid else "0::/system.slice/sshd.service\n")
        write("%s/proc/%d/comm" % (root, pid), "python3\n")
        write("%s/proc/%d/maps" % (root, pid),
              "55d0c0000000-55d0c0001000 r-xp 00000000 fd:00 1 /usr/bin/python3.14\n"
              "7f0000000000-7f0000200000 %s 00000000 00:06 123                        /dev/dax0.0\n" % perms)
    data = b"Hello from the writer, 12:01:12\0"
    write(root + "/dev/dax0.0", "")
    with open(root + "/dev/dax0.0", "wb") as f:
        f.write(data + b"\0" * ((4 << 20) - len(data)))


def probe_test():
    with tempfile.TemporaryDirectory() as root:
        fake_tree(root)
        p = subprocess.run([sys.executable, c.PROBE, "--root", root, "--node", "--bytes", "0xc100e2e1"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        expect("probe exit", p.returncode == 0, p.stderr.decode())
        j = json.loads(p.stdout.decode())
    node, b = j.get("node") or {}, j.get("bytes") or {}
    expect("probe errors", j.get("errors") == [], str(j.get("errors")))
    expect("probe memdevs", [(d["name"], d["serial"], d["size"], d["enabled"]) for d in node.get("memdevs", [])] == [("mem0", "0xc100e2e1", 1 << 30, True)],
           str(node.get("memdevs")))
    r = (node.get("regions") or [{}])[0]
    expect("probe region", r.get("memdevs") == ["mem0"] and [(x["name"], x["driver"]) for x in r.get("dax", [])] == [("dax0.0", "device_dax")], str(r))
    expect("probe mappers", sorted((m["pid"], m["perms"]) for m in node.get("mappers", [])) == [(100, "r--s"), (101, "rw-s")],
           str(node.get("mappers")))
    expect("probe bytes", views.text_at(b.get("hex")) == '"Hello from the writer, 12:01:12"', str(b))
    with open(os.path.join(TESTDATA, "local-L8", "vm2.json")) as f:
        vm2 = json.load(f)
    state = c.load_state(os.path.join(TESTDATA, "local-L8", "state.env"))
    vm2["node"], vm2["bytes"] = node, b
    data = {"vm2": vm2, "vm1": {"node": {"memdevs": [], "regions": [], "mappers": []}}}
    lines = views.render_t4(data, state, NOW)
    check("probe on a fake node, t4", lines)
    expect("probe t4 mapped", any("mapped: reader-a ro, writer rw" in l for l in lines), "\n".join(lines))
    check("probe on a fake node, t6", views.render_t6(data, state, NOW))


def fake_tree_pmem(root):
    """Build /sys, /proc and /dev of a node with the persistent pool device: pmem0 with an erofs, mounted and open."""
    cxl = root + "/sys/bus/cxl/devices"
    write(cxl + "/mem0/serial", "0xc1ae0001\n")
    write(cxl + "/mem0/ram/size", "0x0\n")
    write(cxl + "/mem0/pmem/size", "0x10000000\n")
    os.makedirs(cxl + "/endpoint4", exist_ok=True)
    os.symlink("../../../../devices/pci0000:0c/0000:0c:00.0/mem0", cxl + "/endpoint4/uport")
    os.symlink("../../../../bus/cxl/drivers/cxl_mem", cxl + "/mem0/driver")
    write(cxl + "/region0/mode", "pmem\n")
    write(cxl + "/region0/size", "0x10000000\n")
    write(cxl + "/region0/target0", "decoder4.0\n")
    write(cxl + "/region0/resource", "0x650000000\n")
    nd = root + "/sys/bus/nd/devices"
    write(nd + "/region0/resource", "0x650000000\n")
    write(nd + "/region0/namespace0.0/mode", "memory\n")
    write(nd + "/region0/namespace0.0/size", "%d\n" % (256 << 20))
    write(nd + "/region0/namespace0.0/holder", "pfn0.1\n")
    write(nd + "/region0/namespace0.1/size", "0\n")
    os.makedirs(nd + "/region0/pfn0.1/block/pmem0", exist_ok=True)
    write(nd + "/region1/resource", "0x750000000\n")
    write(nd + "/region1/namespace1.0/size", "%d\n" % (256 << 20))
    write(root + "/sys/block/pmem0/dev", "259:0\n")
    write(root + "/sys/block/pmem0/ro", "0\n")
    write(root + "/sys/block/pmem0/size", "%d\n" % ((254 << 20) // 512))
    write(root + "/proc/sys/kernel/hostname", "n4-cxl-shared-1-fedora-43-containerd\n")
    os.makedirs(root + "/dev", exist_ok=True)
    with open(root + "/dev/pmem0", "wb") as f:
        f.write(c.read_hex(os.path.join(TESTDATA, "hello.erofs.hex")))
    lease_uid = "1ea5e000-0000-4000-8000-0000aabbccdd"
    write(root + "/proc/self/mountinfo",
          "22 1 0:21 / / rw,relatime - xfs /dev/vda1 rw\n"
          "40 22 259:0 / /var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-direct ro,nosuid,nodev,relatime shared:9 - erofs /dev/pmem0 ro,dax=always\n"
          "41 22 259:0 / /var/lib/kubelet/plugins/cxl.nri.io/lease-fs/%s/hello ro,nosuid,nodev,relatime shared:9 - erofs /dev/pmem0 ro,dax=always\n"
          "42 22 7:0 / /var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-cached ro,nosuid,nodev - erofs /dev/loop0 ro\n"
          "43 22 0:50 / /mnt/other ro - erofs /dev/vdb ro\n" % lease_uid)
    write(root + "/sys/block/loop0/loop/backing_file", "/dev/pmem0\n")
    cg = "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod%s.slice/cri-containerd-0123.scope\n"
    for pid, uid, flags in ((200, "30c961ce_314b_4317_b08f_af695a53d3f2", "0100002"),
                            (201, "0644829a_2838_4cb6_9708_f7ff0d84a9dc", "0100000"),
                            (202, None, "0100002")):
        write("%s/proc/%d/cgroup" % (root, pid), cg % uid if uid else "0::/system.slice/sshd.service\n")
        write("%s/proc/%d/comm" % (root, pid), "python3\n")
        write("%s/proc/%d/fdinfo/3" % (root, pid), "pos:\t0\nflags:\t%s\nmnt_id:\t30\n" % flags)
        os.makedirs("%s/proc/%d/fd" % (root, pid), exist_ok=True)
        os.symlink("/dev/pmem0", "%s/proc/%d/fd/3" % (root, pid))
        os.symlink("/dev/null", "%s/proc/%d/fd/0" % (root, pid))
    return lease_uid


def probe_pmem_test():
    with tempfile.TemporaryDirectory() as root:
        lease_uid = fake_tree_pmem(root)
        p = subprocess.run([sys.executable, c.PROBE, "--root", root, "--node"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        expect("probe pmem exit", p.returncode == 0, p.stderr.decode())
        j = json.loads(p.stdout.decode())
    node = j.get("node") or {}
    expect("probe pmem errors", j.get("errors") == [], str(j.get("errors")))
    expect("probe pmem memdev size", [(d["name"], d["size"]) for d in node.get("memdevs", [])] == [("mem0", 256 << 20)], str(node.get("memdevs")))
    r = (node.get("regions") or [{}])[0]
    expect("probe pmem namespaces", [(n["name"], n["mode"], n["size"], n["block"], n["major"], n["minor"], n["fs"], n["ro"])
                                     for n in r.get("namespaces") or []]
           == [("namespace0.0", "fsdax", 254 << 20, "pmem0", 259, 0, "erofs", False)], str(r))
    mounts = sorted((m["kind"], m["loop"], m["dax"], m["fstype"], m["ro"], m.get("claimUID"), m.get("name")) for m in node.get("mounts") or [])
    expect("probe pmem mounts", mounts == [("lease", False, True, "erofs", True, lease_uid, "hello"), ("node", False, True, "erofs", True, None, None),
                                           ("node", True, False, "erofs", True, None, None)],
           str(node.get("mounts")))
    expect("probe pmem openers", sorted((o["pid"], o["block"], o["perms"]) for o in node.get("openers") or []) == [(200, "pmem0", "rw"), (201, "pmem0", "ro")],
           str(node.get("openers")))
    with open(os.path.join(TESTDATA, "pool-shared-fs-F6", "vm2.json")) as f:
        vm2 = json.load(f)
    state = c.load_state(os.path.join(TESTDATA, "pool-shared-fs-F6", "state.env"))
    claims = vm2["k8s"]["claims"]["items"]
    lease_claim = next(cl for cl in claims if cl["metadata"]["name"] == "reader-c-cxl-7hhht")
    lease_claim["metadata"]["uid"] = lease_uid
    data = {"vm2": vm2, "vm1": {"node": node}}
    lines = views.render_t4(data, state, NOW)
    check("probe on a fake pmem node, t4", lines)
    for want in ("vm1 mem0 c1ae0001 256M  region0 pmem 256M", "    pmem0 254M erofs (block rw)", "    open: reader-a ro, writer rw",
                 "    mounted: reader-c (dax)"):
        expect("probe pmem t4", want in lines, "no %r in\n%s" % (want, "\n".join(lines)))


def released_test():
    """Check T4 of memdevs that the drivers released before their detach."""
    lines = views.sample("t4", os.path.join(TESTDATA, "pool-L9-release"), NOW, None)
    expect("released t4", lines[1:] == ["vm1 mem0 c1ae0001 256M  disabled, no region", "vm2 mem0 c1ae0001 256M  disabled, no region"],
           "\n".join(lines))
    lines = views.sample("t6", os.path.join(TESTDATA, "pool-L9-release"), NOW, None)
    expect("released t6", "  attached: vm1, vm2 detaching" in lines, "\n".join(lines))
    long = views.render_t6_pool({"pool": {"device": {"name": "shared0", "size": 1 << 28, "shared": True, "state": "free"},
                                          "hex": ("x" * 80).encode().hex()}}, {}, NOW)
    expect("t6 long text", any(l.startswith('at 0: "xxx') and l.endswith('"...') and len(l) <= c.WIDTH for l in long), "\n".join(long))


def attaching_test():
    """Check T2 and T3 of a pool claim that is allocated but not attached yet."""
    sdir = os.path.join(TESTDATA, "pool-L6-attaching")
    t2 = views.sample("t2", sdir, NOW, None)
    expect("attaching t2", any(l.startswith("reader-a") and l.endswith(" attaching") for l in t2), "\n".join(t2))
    t3 = views.sample("t3", sdir, NOW, None)
    expect("attaching t3", "  attaching: reader-a" in t3 and "  shared: reader-b ro, reader-c ro" in t3, "\n".join(t3))


def t5_sequence_test():
    """Check that the live T5 moves the cursor home once only, through a teardown and a new trace."""
    import io
    fs, local = (c.load_state(os.path.join(TESTDATA, d, "state.env")) for d in ("trace-fs", "trace-local"))
    fs["TRACE_DIR"], local["TRACE_DIR"] = os.path.join(TESTDATA, "trace-fs", "trace"), os.path.join(TESTDATA, "trace-local", "trace")
    seq = [fs, fs, None, None, local, local]
    real_load, real_sleep, real_out = c.load_state, views.time.sleep, sys.stdout

    def sleep(_):
        seq.pop(0)
        if len(seq) == 0:
            raise KeyboardInterrupt
    out = io.StringIO()
    c.load_state, views.time.sleep, sys.stdout = (lambda *a: dict(seq[0]) if seq[0] else None), sleep, out
    try:
        views.loop("t5", None, False, 1, False)
    finally:
        c.load_state, views.time.sleep, sys.stdout = real_load, real_sleep, real_out
    text = out.getvalue()
    expect("t5 home once", text.count("\033[H") == 1 and text.count("\033[2J") == 1, repr(text[:300]))
    expect("t5 no demo once", text.count("no demo (teardown") == 1, repr(text))
    expect("t5 new trace once", text.count("new trace: setup local") == 1, repr(text))
    expect("t5 new events", "vm2 writer asks dax rw excl" in text.split("new trace: setup local")[-1], repr(text[-400:]))


def erofs_test():
    fs = c.erofs_files(c.read_hex(os.path.join(TESTDATA, "hello.erofs.hex")))
    expect("erofs type", fs["type"] == "erofs" and not fs["error"], str(fs))
    expect("erofs files", [(f["name"], f["size"], f["type"], f.get("text")) for f in fs["files"]]
           == [("hello.txt", 32, "file", "Hello from the writer, 12:01:12")], str(fs["files"]))
    expect("erofs super", (fs["super"]["blocksize"], fs["super"]["rootNid"], fs["super"]["inos"]) == (4096, 36, 2), str(fs["super"]))
    expect("erofs zeros", c.erofs_files(bytes(1 << 20))["type"] == "zeros")
    expect("erofs none", c.erofs_files(b"x" * 4096)["type"] == "none")
    cut = c.erofs_files(c.read_hex(os.path.join(TESTDATA, "hello.erofs.hex"))[:4096])
    expect("erofs cut", cut["error"] and cut["files"][0]["text"] == "(not readable)", str(cut))
    lines = views.fs_lines(cut)
    expect("erofs cut lines", lines == ["erofs: hello.txt 32 bytes", "  (not readable)"], str(lines))


def trace_fs_test():
    state = c.load_state(os.path.join(TESTDATA, "trace-fs", "state.env"))
    tr = views.Trace(os.path.join(TESTDATA, "trace-fs", "trace"), state)
    tr.poll()
    texts = [tr.text(text) for _, _, text in tr.events]
    for want in ("vm1 writer asks block rw excl", "vm1 add mem0", "vm1 add region0 pmem0", "vm1 writer: prepared pmem0 rw",
                 "vm1 writer: lease Ready block pmem0", "vm2 reader-a asks fs ro share",
                 "vm2 reader-a: prepared erofs direct", "vm2 reader-a: mounted hello",
                 "vm2 reader-a: lease Ready fs hello", "vm2 reader-a: unmount busy, retry",
                 "vm2 reader-a: unmounted hello", "vm1 remove pmem0 region0",
                 "vm2 pmem0 read-only", "vm2 node mount pmem0 erofs ro", "vm1 node mount pmem0 erofs ro",
                 "vm2 node mount unmounted", "vm1 node mount unmounted", "shared0 on vm1: not exclusive",
                 "reader-c: shared0 on vm1 already", "vm2 reader-a releases: ctr gone", "vm2 released mem0",
                 "shared0 detaching from vm2", "vm1 released mem0", "vm1 bind mem0"):
        expect("trace-fs", want in texts, "no %r" % want)
    expect("trace-fs vm1 kept", "detach shared0 from vm1" not in texts[:texts.index("vm2 reader-a asks fs ro share") + 30],
           "shared0 detached from vm1 at F6")
    expect("trace-fs busy once", sum(1 for t in texts if "unmount busy" in t) == 1, "busy shown more than once")
    # T5: "HH:MM:SS tag   " leaves 35 columns.
    long = [t for t in texts if len(t) > c.WIDTH - 15]
    expect("trace-fs width", not long, "lines cut in T5: %s" % long)


def trace_formats_test():
    """Check the trace lines of log lines written with the format strings of the current driver and controller."""
    state = c.load_state(os.path.join(TESTDATA, "trace-fs", "state.env"))
    vm1, vm2 = state["VM1_NODE"], state["VM2_NODE"]
    mnt = "/var/lib/kubelet/plugins/cxl-pool.nri.io/mounts/c1ae0001-direct"
    lease_fs = "/var/lib/kubelet/plugins/cxl.nri.io/lease-fs/1ea5e000-0000-4000-8000-000000000001/data"
    want = 'claim cxl-demo/cxl-lease-3f2a91c0 device fs0 node %s' % vm1
    driver = [
        # broker.go
        'lease broker: lease 3f2a91c0: cxl-demo/writer/main requests size "" serial "0xc1ae0001" (source "", mode fs, shared false, '
        'shared device true, read-only false, access "", name "data")',
        'lease broker: lease 51aa7b09: cxl-demo/reader-b/main requests size "" serial "0xc1ae0001" (source "", mode dax, shared true, '
        'shared device true, read-only true, access "", name "")',
        'lease broker: lease 3f2a91c0: Ready (source pool, serial 0xc1ae0001, mode fs, read-only false, node -1, dax "", block "", '
        'access "direct", fs "ext4", path "/run/cxl/fs/data", 534773760 bytes)',
        'lease broker: lease 3f2a91c0: releasing (released by main, was Ready)',
        'lease broker: lease 3f2a91c0: released',
        # pool.go
        'cxl-pool.nri.io: claim cxl-demo/cxl-lease-3f2a91c0: prepared fs0 (serial 0xc1ae0001, shared true, mode fs, read-only false) as '
        'mem0 region0 namespace namespace0.0 block /dev/pmem0 access "direct" fs "ext4" mount "%s" loop ""' % mnt,
        'cxl-pool.nri.io: claim cxl-demo/cxl-lease-51aa7b09: prepared shared0 (serial 0xc1ae0001, shared true, mode dax, read-only true) '
        'as mem0 region0 dax dax0.0 node -1',
        'cxl-pool.nri.io: unprepared claim cxl-demo/cxl-lease-3f2a91c0 (c1a10006-0000-4000-8000-000000000000)',
        # persistent.go
        'cxl-pool.nri.io: device 0xc1ae0001: mounted /dev/pmem0 at %s (ext4, rw, dax=always)' % mnt,
        'cxl-pool.nri.io: device 0xc1ae0001: mounted /dev/loop0 at %s (erofs, ro)' % mnt.replace("direct", "cached"),
        'cxl-pool.nri.io: device 0xc1ae0001: remounted %s read-only' % mnt,
        'cxl-pool.nri.io: device 0xc1ae0001: /dev/pmem0 read-write',
        'cxl-pool.nri.io: lease 3f2a91c0: bound %s at %s' % (mnt, lease_fs),
        'cxl-pool.nri.io: claim cxl-demo/cxl-lease-3f2a91c0: lease 3f2a91c0: bound %s at %s again' % (mnt, lease_fs),
        'cxl-pool.nri.io: lease 3f2a91c0: unbound %s' % lease_fs,
        'cxl-pool.nri.io: device 0xc1ae0001: unmounted %s' % mnt,
        # local.go
        'local: memdev mem0 (serial 0xc100e2e1): released region0 in 35ms',
        'local: memdev mem0 (serial 0xc100e2e1): not configured shared any more, releasing its region',
        'local: memdev mem0 (serial 0xc100e2e1): not configured shared any more: keeping region0 for claims [a b], '
        'not publishing the memdev until they are gone',
        'local: memdev mem0 (serial 0xc100e2e1): claim c1a10006-0000-4000-8000-000000000000: released shared dax0.0, claims left [a b]',
        'lease broker: lease 3f2a91c0: releasing (requester container gone, was Ready)',
        'cxl-pool.nri.io: released mem0 (serial 0xc1ae0001)',
    ]
    controller = [
        'attach fs0 to %s for %s: exclusive for a read-write ext4 claim' % (vm1, want),
        'ERROR: Conflict for claim cxl-demo/cxl-lease-51aa7b09 device fs0 node %s: attach fs0 to %s: conflict' % (vm2, vm2),
        'attached fs0 to %s (node %s, slot cxlsw_ds0_usrp0hb0, qemu device fcp_fs0.hp1, owner k8s:resourceclaim/c1a10006, '
        'exclusive true) for cxl-demo/cxl-lease-3f2a91c0' % (vm1, vm1),
        'detached fs0 from %s (node %s, owner k8s:resourceclaim/c1a10006)' % (vm1, vm1),
        'attach fs0 to %s for %s: already attached (attached, owner "k8s:resourceclaim/c1a10006", exclusive false)' % (vm1, want),
    ]
    with tempfile.TemporaryDirectory() as tdir:
        with open(os.path.join(tdir, "vm1.driver.log"), "w") as f:
            for i, m in enumerate(driver):
                f.write("%d.0 vm1.driver I1103 12:00:00.000000  4242 x.go:1] %s\n" % (1000 + i, m))
        with open(os.path.join(tdir, "vm.controller.log"), "w") as f:
            for i, m in enumerate(controller):
                f.write("%d.0 vm.controller fake-cxl-pool-controller: 2026/11/03 12:00:00.000000 %s\n" % (2000 + i, m))
        tr = views.Trace(tdir, state)
        tr.poll()
    texts = [tr.text(text) for _, _, text in tr.events]
    for w in ("vm1 writer asks fs rw excl", "vm1 writer: lease Ready fs data", "vm1 writer: lease releasing",
              "vm1 writer: lease released", "vm1 writer: prepared ext4 rw direct", "vm1 reader-b asks dax ro share", "vm1 reader-b: prepared dax0.0 ro",
              "vm1 writer: unprepared", "vm1 node mount pmem0 ext4 rw", "vm1 node mount loop0 erofs ro",
              "vm1 node mount now read-only", "vm1 pmem0 read-write", "vm1 writer: mounted data", "vm1 writer: mounted data again",
              "vm1 writer: unmounted data", "vm1 node mount unmounted", "vm1 released region0",
              "vm1 unshared: releasing the region", "vm1 unshared: keeping the region", "vm1 c1a10006: released, 2 left",
              "vm1 writer releases: ctr gone", "vm1 released mem0", "writer: fs0 on vm1 already",
              "writer: fs0 excl: rw ext4", "reader-b: fs0 not on vm2: Conflict", "writer: attach fs0 to vm1 excl",
              "detach fs0 from vm1"):
        expect("trace formats", w in texts, "no %r in %s" % (w, texts))
    expect("trace formats count", len(texts) == len(driver) + len(controller), "%d lines of %d: %s" % (
        len(texts), len(driver) + len(controller), texts))
    long = [t for t in texts if len(t) > c.WIDTH - 15]
    expect("trace formats width", not long, "lines cut in T5: %s" % long)


def super_sample(fstype):
    """Return the first fsinfo.READ_LEN bytes of an empty FSTYPE of testdata/pool-fs-super.json."""
    data = bytearray(fsinfo.READ_LEN)
    with open(os.path.join(TESTDATA, "pool-fs-super.json")) as f:
        for off, hexdata in json.load(f)[fstype]:
            raw = bytes.fromhex(hexdata)
            data[off:off + len(raw)] = raw
    return data


def fsinfo_test():
    size = (512 - 2) << 20
    for t in ("ext4", "xfs", "btrfs"):
        sb = fsinfo.fs_super(bytes(super_sample(t)))
        expect("fsinfo %s" % t, (sb["type"], sb["size"], sb["blockSize"], sb["label"], sb["error"]) == (t, size, 4096, "demo", ""), str(sb))
    sb = fsinfo.fs_super(bytes(super_sample("ext4")))
    expect("fsinfo ext4 clean", sb["clean"] and not sb["needsRecovery"] and not sb["errors"], str(sb))
    dirty = super_sample("ext4")
    dirty[1024 + 0x60] |= fsinfo.EXT4_INCOMPAT_RECOVER
    lines = fsinfo.lines(fsinfo.fs_super(bytes(dirty)))
    expect("fsinfo ext4 needs recovery", lines[0] == 'ext4 "demo" 510M, needs recovery', str(lines))
    expect("fsinfo btrfs", fsinfo.lines(fsinfo.fs_super(bytes(super_sample("btrfs"))))[0].startswith('btrfs "demo" 510M, generation '))
    several = super_sample("ext4")
    several[0:512] = super_sample("xfs")[0:512]
    expect("fsinfo several", fsinfo.lines(fsinfo.fs_super(bytes(several))) == ["signatures of ext4, xfs"])
    erofs = c.read_hex(os.path.join(TESTDATA, "hello.erofs.hex"))
    expect("fsinfo erofs", fsinfo.fs_super(erofs + bytes(fsinfo.READ_LEN - len(erofs)))["type"] == "erofs")
    expect("fsinfo zeros", fsinfo.lines(fsinfo.fs_super(bytes(fsinfo.READ_LEN))) == ["no file system (zeros)"])
    expect("fsinfo cut", fsinfo.fs_super(bytes(super_sample("ext4"))[:1100])["error"] == "superblock beyond the data")
    for t in ("ext4", "xfs", "btrfs"):
        expect("fsinfo details %s" % t, all(len(l) < 200 for l in fsinfo.details(fsinfo.fs_super(bytes(super_sample(t))))))


def trace_poolfs_test():
    state = c.load_state(os.path.join(TESTDATA, "trace-pool-fs", "state.env"))
    tr = views.Trace(os.path.join(TESTDATA, "trace-pool-fs", "trace"), state)
    tr.poll()
    texts = [tr.text(text) for _, _, text in tr.events]
    for want in ("vm1 writer asks fs rw share", "writer: fs0 excl: rw filesystem", "vm1 node mount pmem0 ext4 rw",
                 "vm1 writer: prepared ext4 rw direct", "vm1 writer: lease Ready fs data", "vm1 reader-c: lease Ready fs data",
                 "vm1 node mount now read-only", "vm1 pmem0 read-only", "fs0 on vm1: not exclusive",
                 "reader-a waits: claim deallocated",
                 "reader-a: attach fs0 to vm2", "vm2 node mount pmem0 ext4 ro", "vm2 reader-b: lease Ready fs data"):
        expect("trace-pool-fs", want in texts, "no %r" % want)
    for r in ("reader-a", "reader-b"):
        n = sum(1 for t in texts if t == "%s: fs0 not on vm2: Conflict" % r)
        expect("trace-pool-fs %s Conflict once" % r, n == 1, "%d times" % n)
        n = sum(1 for t in texts if t == "%s: allocated fs0" % r)
        expect("trace-pool-fs %s allocated" % r, n == 2, "%d times: the first attempt and the one after the writer" % n)
    bad = [t for t in texts if "ERROR" in t or "AttachFailed" in t or "PreBind" in t]
    expect("trace-pool-fs retries", not bad, "lines of the retries: %s" % bad)
    long = [t for t in texts if len(t) > c.WIDTH - 15]
    expect("trace-pool-fs width", not long, "lines cut in T5: %s" % long)


def sample_k8s(name):
    with open(os.path.join(TESTDATA, name, "vm2.json")) as f:
        return json.load(f)["k8s"]


def poolfs_helper_test():
    state = c.load_state(os.path.join(TESTDATA, "pool-fs-R7", "state.env"))
    for name, want in (("pool-fs-R7", {"writer": "fs rw (vm1 only)", "reader-a": "waiting (Conflict)", "reader-b": "waiting (Conflict)",
                                       "reader-c": "fs ro share"}),
                       ("pool-fs-R9", {"reader-a": "fs ro share", "reader-b": "fs ro share", "reader-c": "fs ro share"})):
        k = sample_k8s(name)
        got = {c.requester(cl): views.fs_lease_memory(cl, k.get("events"), state)
               for cl in c.items(k["claims"], "ResourceClaim") if c.lease_id(cl)}
        expect("fs_lease_memory %s" % name, got == want, str(got))
    # The scheduler's next attempt: allocated again, not attached yet, the last Event AttachFailed Conflict.
    k = sample_k8s("pool-fs-R7")
    retry = next(cl for cl in c.items(k["claims"], "ResourceClaim") if c.requester(cl) == "reader-a")
    retry["status"].pop("devices", None)
    got = views.fs_lease_memory(retry, k.get("events"), state)
    expect("fs_lease_memory retry", got == "waiting (Conflict)", got)
    t3 = views.sample("t3", os.path.join(TESTDATA, "pool-fs-R2"), NOW, None)
    expect("pool-fs R2 t3", "  exclusive: writer rw" in t3, "\n".join(t3))
    k7 = sample_k8s("pool-fs-R7")
    saved = steps.k8s
    try:
        steps.k8s = lambda st, kinds="pods,claims": k7
        join = ('{"lease": "8c1d02e4", "state": "Creating"}\n{"lease": "51aa7b09", "state": "Creating"}\n'
                '{"lease": "e0c4d3f1", "state": "Creating"}\n')
        got = steps.check_join(state, join, 0)
        expect("check_join", got[0] == "reader-c Ready on vm1, next to the writer" and
               got[1].startswith("reader-a reader-b waiting: Conflict ("), str(got))
        fsw = ('{"leases": [{"lease": "3f2a91c0", "state": "Released"}]}\n{"lease": "7b3e5a10", "state": "Ready", "mode": "fs", '
               '"readOnly": false, "shared": true, "access": "direct", "fsType": "ext4", "path": "/run/cxl/fs/data"}\n')
        got = steps.check_fs_writer(state, fsw, 0)
        expect("check_fs_writer", got == ["lease 7b3e5a10 Ready ext4 rw (direct)", "path /run/cxl/fs/data",
                                          "attached to vm1 only (ReadWriteOnce)"], str(got))
    finally:
        steps.k8s = saved
    text, more = "Hello from the writer, 12:01:12", "A second line, 12:02:10"
    got = steps.check_append(state, 'appended to /run/cxl/fs/data/hello.txt: "%s"\n%s\n%s\n' % (more, text, more), 0)
    expect("check_append", got == ['reader-c reads it at once: "%s"' % more], str(got))
    refused = "sh: can't create /run/cxl/fs/data/hello.txt: Read-only file system"
    got = steps.check_read_refused(state, "\n".join([text, more] * 3 + [refused, "command terminated with exit code 1"]), 1)
    expect("check_read_refused", got == ["3 readers read the same 2 lines", refused], str(got))
    got = steps.check_read_refused(state, "\n".join([text, more, text, more, text, refused]), 1)
    expect("check_read_refused different", got[0] == "readers read different texts!", str(got))


def presenter_test():
    for case, serial, fstype in (("local", "0xc100e2e1", ""), ("pool", "0xc1ae0001", ""), ("pool-shared-fs", "0xc1ae0001", ""),
                                 ("pool-fs", "0xc1ae0001", "ext4"), ("pool-fs", "0xc1ae0001", "xfs"),
                                 ("pool-fs", "0xc1ae0001", "btrfs")):
        all_steps = steps.steps(case, serial, fstype or "ext4")
        for n, st in enumerate(all_steps, 1):
            caption = c.wrap_list("", st.caption.split(" "), indent=2, sep="")
            expect("T1 %s %d caption" % (case, n), len(caption) <= 2, st.caption)
            lines = [c.title("PRESENTER %s %s%d/%d" % (case, steps.step_letter(case), n, len(all_steps)), now=NOW)]
            lines += caption + steps.wrap_command(st.command)
            lines += steps.result_lines(["r" * 60, "r" * 60], st.rows) + ["   12.3 s (command 10.1 s); Enter: next "]
            check("T1 %s%s %s%d" % (case, " " + fstype if fstype else "", steps.step_letter(case), n), lines)


def helper_test():
    expect("quantity 1M", c.quantity("1M") == 1e6)
    expect("quantity 256Mi", c.quantity("256Mi") == 256 << 20)
    expect("quantity 1", c.quantity("1") == 1)
    expect("wrap_list", c.wrap_list("x: ", ["a", "b"]) == ["x: a, b"], str(c.wrap_list("x: ", ["a", "b"])))
    long = c.wrap_list("  shared: ", ["reader-%d ro" % i for i in range(8)], indent=4)
    expect("wrap_list width", all(len(l) <= c.WIDTH for l in long) and len(long) > 1, str(long))
    expect("k8s_size", c.k8s_size(1 << 30) == "1Gi" and c.k8s_size(256 << 20) == "256Mi")
    expect("kernel_size", c.kernel_size(1 << 30) == "1.0G" and c.kernel_size(256 << 20) == "256M")
    expect("title", len(c.title("x" * 80, True, NOW)) == c.WIDTH)
    def fs_claim(device, shares, consumed, kind="MemoryConfig"):
        req = {"deviceClassName": "cxl-pool-persistent"}
        if shares:
            req["capacity"] = {"requests": {"shares": shares}}
        params = {"apiVersion": "cxl.nri.io/v1alpha1", "kind": kind, "device": device}
        return {"spec": {"devices": {"requests": [{"name": "lease", "exactly": req}]}},
                "status": {"allocation": {"devices": {
                    "results": [{"request": "lease", "driver": "cxl-pool.nri.io", "device": "fs0", "consumedCapacity": {"shares": consumed}}],
                    "config": [{"source": "FromClaim", "opaque": {"driver": "cxl-pool.nri.io", "parameters": params}}]}},
                    "devices": [{"driver": "cxl-pool.nri.io", "device": "fs0",
                                 "conditions": [{"type": "cxl-pool.nri.io/Attached", "status": "True"}]}]}}
    for cl, want in ((fs_claim({"mode": "fs"}, "1", "1"), "fs ro share"),
                     (fs_claim({"mode": "fs", "readOnly": False}, None, "1M"), "fs rw excl"),
                     (fs_claim({"mode": "block"}, None, "1M"), "block rw excl")):
        expect("lease_memory", c.lease_memory(cl) == want, "%s, not %s" % (c.lease_memory(cl), want))
    pending = fs_claim({"mode": "fs"}, "1", "1")
    pending["status"].pop("devices")
    expect("lease_memory attaching", c.lease_memory(pending) == "attaching", c.lease_memory(pending))
    pending["status"]["devices"] = [{"driver": "cxl-pool.nri.io", "device": "fs0", "conditions": [
        {"type": "cxl-pool.nri.io/AttachFailed", "status": "True", "reason": "Timeout"}]}]
    expect("lease_memory failed", c.lease_memory(pending) == "waiting (Timeout)", c.lease_memory(pending))
    expect("MemoryConfig only", c.claim_params(fs_claim({"mode": "fs"}, "1", "1", kind="DeviceConfig")) == {})
    block = '{"lease": "3f2a91c0", "state": "Ready", "mode": "block", "readOnly": false, "shared": false, "block": "/dev/pmem0"}'
    expect("check_lease block", steps.check_lease({}, block, 0) == ["lease 3f2a91c0 Ready block rw (exclusive)", "block /dev/pmem0"],
           str(steps.check_lease({}, block, 0)))
    fs = ('{"lease": "8c1d02e4", "state": "Ready", "mode": "fs", "readOnly": true, "shared": true, "access": "direct", "fsType": "erofs", '
          '"path": "/run/cxl/fs/hello", "env": {"CXL_C1AE0001_FSTYPE": "erofs"}}')
    expect("check_lease fs", steps.check_lease({}, fs, 0) == ["lease 8c1d02e4 Ready fs ro (share) (direct)", "path /run/cxl/fs/hello"],
           str(steps.check_lease({}, fs, 0)))
    text = "Hello from the writer, 12:01:12"
    for res, want in (
            (['wrote erofs (8192 bytes) with hello.txt: "Hello from the writer, 12:01:12"'],
             ["-> wrote erofs (8192 bytes) with hello.txt:", '   "Hello from the writer, 12:01:12"']),
            (["sh: can't create /run/cxl/fs/hello/hello.txt: Read-only file system"],
             ["-> sh: can't create /run/cxl/fs/hello/hello.txt:", "   Read-only file system"]),
            (['3 readers read: "Hello from the writer, 12:01:12"'], ["-> 3 readers read:", '   "Hello from the writer, 12:01:12"']),
            (['3 readers read at 0: "Hello from the writer, 12:01:12"', "3 hold a read-only mapping"],
             ["-> 3 readers read at 0:", '   "Hello from the writer, 12:01:12"', "-> 3 hold a read-only mapping"]),
            (["lease 3f2a91c0 Ready block rw (exclusive)", "block /dev/pmem0"],
             ["-> lease 3f2a91c0 Ready block rw (exclusive)", "-> block /dev/pmem0"])):
        expect("result_lines", steps.result_lines(res) == want, str(steps.result_lines(res)))
    expect("check_cat", steps.check_cat({}, "\n".join([text] * 3) + "\n", 0) == ['3 readers read: "%s"' % text])
    bad = "%s\ncat: can't open '/run/cxl/fs/hello/hello.txt': No such file or directory\ncommand terminated with exit code 1\n%s\n" % (text, text)
    expect("check_cat different", steps.check_cat({}, bad, 1)[0] == "readers read different texts!", str(steps.check_cat({}, bad, 1)))


def wizard_test():
    """Run the checks of the wizard; its views are rendered with the other scenarios."""
    for test in (wizard_check.yaml_scalar_test, wizard_check.rule_test, wizard_check.question_test,
                 wizard_check.status_test, wizard_check.script_test, wizard_check.state_test,
                 wizard_check.command_test, wizard_check.dax_test):
        test()
    failures.extend("wizard: " + f for f in wizard_check.failures)


def main():
    helper_test()
    render_scenarios()
    probe_test()
    probe_pmem_test()
    erofs_test()
    trace_fs_test()
    trace_formats_test()
    released_test()
    attaching_test()
    t5_sequence_test()
    fsinfo_test()
    trace_poolfs_test()
    poolfs_helper_test()
    presenter_test()
    wizard_test()
    report = "\n".join(out) + "\n"
    if "--write" in sys.argv:
        with open(os.path.join(TESTDATA, "renderings.txt"), "w") as f:
            f.write("# demo selftest: every rendering of testdata/, TZ=UTC (bin/selftest.py --write)\n" + report)
    if "--quiet" not in sys.argv:
        sys.stdout.write(report)
    if failures:
        print("selftest: FAIL")
        for f in failures:
            print("  " + f)
        sys.exit(1)
    print("selftest: ok, %d renderings fit %d x %d" % (sum(1 for l in out if l.startswith("+-") and len(l) > c.WIDTH + 2), c.WIDTH, c.ROWS))


if __name__ == "__main__":
    main()
