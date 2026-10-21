#!/usr/bin/env python3
"""Desk check of the demo: every rendering fits 50 x 10.

Usage: selftest.py [--write] [--quiet]

- renders the views of every scenario in testdata/ (t2, t3, t4, t6 from
  vm2.json, vm1.json, pool.json; t5 from trace/ at several points of time)
  and checks: at most 10 lines, at most 50 columns, printable ASCII;
- runs probe.py on a fake /sys, /proc and /dev tree and renders T4 and T6
  from its output;
- lays out the presenter terminal (T1) of every step of both scripts with
  a two-line result and checks that it fits;
- checks a few helpers (quantities, wrapping, lease memory words).
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


def presenter_test():
    for case, serial in (("local", "0xc100e2e1"), ("pool", "0xc1ae0001")):
        all_steps = steps.steps(case, serial)
        for n, st in enumerate(all_steps, 1):
            lines = [c.title("PRESENTER %s L%d/%d" % (case, n, len(all_steps)), now=NOW)]
            lines += c.wrap_list("", st.caption.split(" "), indent=2, sep="") + steps.wrap_command(st.command)
            lines += [c.cut("-> " + "r" * 60), c.cut("-> " + "r" * 60), "   12.3 s (command 10.1 s); Enter: next "]
            check("T1 %s L%d" % (case, n), lines)


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


def main():
    helper_test()
    render_scenarios()
    probe_test()
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
