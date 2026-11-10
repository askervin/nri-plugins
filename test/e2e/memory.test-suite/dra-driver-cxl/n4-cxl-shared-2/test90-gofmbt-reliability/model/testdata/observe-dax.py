#!/usr/bin/env python3
"""The reads of the dax devices and the stacks of mbt-observe.py.

Usage: observe-dax.py MBT_OBSERVE MBT_SOURCE

On a sysfs tree in a temporary directory: online_bytes of MBT_OBSERVE
counts the online memory blocks of a dax device of one range, of several
ranges and of none (a kernel before 5.10) as the ranges of its mappingN
give them, and reads no mappingN file of a device of one range or none.
Then arm_stacks writes STACKS_MARKER, the kernel stacks of the threads of
the process and the Python stacks of its threads to stderr, nothing once
cancelled, and the executor MBT_SOURCE (mbt.source.sh) looks for the same
marker. Prints "ok" and exits 0, or prints the failures and exits 1.

Python 3 standard library only.
"""

import importlib.util
import io
import os
import sys
import tempfile
import time

sys.dont_write_bytecode = True

BS = 128 << 20
START = 0x250000000

# the dax devices: their ranges (start block, blocks) in mapping order, and
# whether the kernel has mappingN files
DEVICES = {
    "dax0.0": ([(0, 2)], True),
    "dax0.1": ([(2, 1), (5, 2)], True),
    "dax0.2": ([(3, 2)], False),
}
ONLINE = {0, 2, 3, 6}


def load(path):
    """The module of the observer in path."""
    spec = importlib.util.spec_from_file_location("mbt_observe", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text + "\n")


def sysfs(root):
    """Write the dax devices and memory blocks of DEVICES and ONLINE under
    root; return the online bytes of each device."""
    want = {}
    for name, (ranges, mapped) in DEVICES.items():
        d = os.path.join(root, "dax", name)
        size = 0
        want[name] = 0
        for i, (first, n) in enumerate(ranges):
            start, end = START + first * BS, START + (first + n) * BS - 1
            if mapped:
                write("%s/mapping%d/start" % (d, i), "%#x" % start)
                write("%s/mapping%d/end" % (d, i), "%#x" % end)
            size += n * BS
            want[name] += BS * len(ONLINE & set(range(first, first + n)))
        write(d + "/size", str(size))
        write(d + "/resource", "%#x" % (START + ranges[0][0] * BS))
    for b in range(START // BS, START // BS + 8):
        state = "online" if b - START // BS in ONLINE else "offline"
        write(os.path.join(root, "memory", "memory%d" % b, "state"), state)
    return want


def check_online_bytes(obs, failures):
    with tempfile.TemporaryDirectory() as root:
        want = sysfs(root)
        obs.DAX, obs.MEMORY = os.path.join(root, "dax"), os.path.join(root, "memory")
        plain = obs.read
        for name, (ranges, _) in DEVICES.items():
            seen = []

            def read(path):
                seen.append(path)
                return plain(path)
            obs.read = read
            try:
                got = obs.online_bytes(name, BS)
            finally:
                obs.read = plain
            if got != want[name]:
                failures.append("%s: online %d, expected %d" % (name, got, want[name]))
            mappings = [p for p in seen if "/mapping" in p]
            if len(ranges) == 1 and mappings:
                failures.append("%s of one range: read %s" % (name, mappings))
            if len(ranges) > 1 and len(mappings) != 2 * len(ranges):
                failures.append("%s of %d ranges: read %s" % (name, len(ranges), mappings))


def stderr_of(fn, seconds):
    """What fn() and the next seconds write to stderr."""
    with tempfile.TemporaryFile() as out:
        saved, stderr = os.dup(2), sys.stderr
        os.dup2(out.fileno(), 2)
        sys.stderr = io.TextIOWrapper(os.fdopen(os.dup(2), "wb"), write_through=True)
        try:
            fn()
            time.sleep(seconds)
        finally:
            sys.stderr.close()
            sys.stderr = stderr
            os.dup2(saved, 2)
            os.close(saved)
        out.seek(0)
        return out.read().decode(errors="replace")


def check_stacks(obs, failures):
    text = stderr_of(lambda: obs.arm_stacks(0.1), 1.6)
    lines = text.splitlines()
    if not lines or lines[0] != obs.STACKS_MARKER:
        failures.append("stacks: the first line is not the marker: %r" % text[:200])
    for part in ("== observer pid %d" % os.getpid(), "-- task %d " % os.getpid(), "most recent call first"):
        if part not in text:
            failures.append("stacks: no %r in %r" % (part, text[:2000]))
    text = stderr_of(lambda: obs.arm_stacks(0.1)(), 1.6)
    if text:
        failures.append("stacks after the cancel: %r" % text[:200])


def main():
    obs = load(sys.argv[1])
    failures = []
    check_online_bytes(obs, failures)
    check_stacks(obs, failures)
    with open(sys.argv[2]) as f:
        if 'MBT_OBS_STACKS_MARKER="%s"' % obs.STACKS_MARKER not in f.read():
            failures.append("%s: no MBT_OBS_STACKS_MARKER of %r" % (sys.argv[2], obs.STACKS_MARKER))
    if failures:
        print("\n".join(failures))
        sys.exit(1)
    print("ok")


if __name__ == "__main__":
    main()
