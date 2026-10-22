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
- checks the trace lines of trace-fs (block and fs leases, binds);
- lays out the presenter terminal (T1) of every step of the three scripts
  with a two-line result and checks that it fits;
- checks a few helpers (quantities, wrapping, lease memory words).
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
import steps         # noqa: E402
import views         # noqa: E402

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
    expect("probe memdevs", [(d["name"], d["serial"], d["size"]) for d in node.get("memdevs", [])] == [("mem0", "0xc100e2e1", 1 << 30)],
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
    expect("probe pmem namespaces", [(n["name"], n["mode"], n["size"], n["block"], n["major"], n["minor"], n["fs"]) for n in r.get("namespaces") or []]
           == [("namespace0.0", "fsdax", 254 << 20, "pmem0", 259, 0, "erofs")], str(r))
    mounts = sorted((m["kind"], m["loop"], m["dax"], m.get("claimUID"), m.get("name")) for m in node.get("mounts") or [])
    expect("probe pmem mounts", mounts == [("lease", False, True, lease_uid, "hello"), ("node", False, True, None, None), ("node", True, False, None, None)],
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
    for want in ("vm1 mem0 c1ae0001 256M  region0 pmem 256M", "    pmem0 254M erofs", "    open: reader-a ro, writer rw",
                 "    mounted: reader-c (dax)"):
        expect("probe pmem t4", want in lines, "no %r in\n%s" % (want, "\n".join(lines)))


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
                 "vm2 reader-a: unmounted hello", "vm1 remove pmem0 region0"):
        expect("trace-fs", want in texts, "no %r" % want)
    expect("trace-fs busy once", sum(1 for t in texts if "unmount busy" in t) == 1, "busy shown more than once")
    # T5: "HH:MM:SS tag   " leaves 35 columns.
    long = [t for t in texts if len(t) > c.WIDTH - 15]
    expect("trace-fs width", not long, "lines cut in T5: %s" % long)


def presenter_test():
    for case, serial in (("local", "0xc100e2e1"), ("pool", "0xc1ae0001"), ("pool-shared-fs", "0xc1ae0001")):
        all_steps = steps.steps(case, serial)
        for n, st in enumerate(all_steps, 1):
            expect("T1 %s %d caption" % (case, n), len(st.caption) <= c.WIDTH, st.caption)
            lines = [c.title("PRESENTER %s %s%d/%d" % (case, steps.step_letter(case), n, len(all_steps)), now=NOW)]
            lines += c.wrap_list("", st.caption.split(" "), indent=2, sep="") + steps.wrap_command(st.command)
            lines += steps.result_lines(["r" * 60, "r" * 60]) + ["   12.3 s (command 10.1 s); Enter: next "]
            check("T1 %s %s%d" % (case, steps.step_letter(case), n), lines)


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
    block = '{"lease": "3f2a91c0", "state": "Ready", "mode": "block", "readOnly": false, "shared": false, "block": "/dev/pmem0"}'
    expect("check_lease block", steps.check_lease({}, block, 0) == ["lease 3f2a91c0 Ready block rw (exclusive)", "block /dev/pmem0"],
           str(steps.check_lease({}, block, 0)))
    fs = '{"lease": "8c1d02e4", "state": "Ready", "mode": "fs", "readOnly": true, "shared": true, "access": "direct", "path": "/run/cxl/fs/hello"}'
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


def main():
    helper_test()
    render_scenarios()
    probe_test()
    probe_pmem_test()
    erofs_test()
    trace_fs_test()
    presenter_test()
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
