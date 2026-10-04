#!/usr/bin/env python3
"""Read/write patterns through a devdax device (run inside the guest as root).

Usage:
  guest-dax-rw.py write DEV TAG [OFFSET_MB...]   write "TAG@OFFSET" 4K blocks
  guest-dax-rw.py read  DEV [OFFSET_MB...]       print the strings found there
  guest-dax-rw.py bench DEV [MB]                 memcpy MB (default: all-2M) twice
                                                 into the device, report GB/s
  guest-dax-rw.py find SERIAL                    print memdev, region and dax
                                                 device of the memdev with SERIAL
DEV may be a /dev/daxX.Y path or "serial:0x..." (resolved with find).
devdax needs MAP_SHARED and mappings aligned to the device alignment (2M);
the whole device is mapped at once.
"""
import mmap
import os
import sys
import time

MB = 1 << 20
DEFAULT_OFFSETS = [0, 1, 100, 255]


def dev_size(dev):
    name = os.path.basename(dev)
    with open("/sys/bus/dax/devices/%s/size" % name) as f:
        return int(f.read())


def find(serial):
    """(memdev, region, dax device) of the CXL memdev with serial."""
    cxl = "/sys/bus/cxl/devices"
    serial = int(serial, 0)
    mem = next((m for m in os.listdir(cxl) if m.startswith("mem") and
                int(open("%s/%s/serial" % (cxl, m)).read(), 0) == serial), None)
    if mem is None:
        return None, None, None
    for r in sorted(os.listdir(cxl)):
        if not r.startswith("region"):
            continue
        i = 0
        while os.path.exists("%s/%s/target%d" % (cxl, r, i)):
            dec = open("%s/%s/target%d" % (cxl, r, i)).read().strip()
            port = os.path.basename(os.path.dirname(os.path.realpath("%s/%s" % (cxl, dec))))
            uport = os.path.basename(os.path.realpath("%s/%s/uport" % (cxl, port)))
            if uport == mem:
                daxes = [d for d in os.listdir("%s/%s/dax_%s" % (cxl, r, r))
                         if d.startswith("dax") and d != "dax_region"] if os.path.isdir(
                             "%s/%s/dax_%s" % (cxl, r, r)) else []
                return mem, r, (daxes[0] if daxes else None)
            i += 1
    return mem, None, None


def open_map(dev):
    if dev.startswith("serial:"):
        dev = "/dev/" + find(dev[7:])[2]
    size = dev_size(dev)
    fd = os.open(dev, os.O_RDWR)
    m = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    return fd, m, size


def main():
    op, dev = sys.argv[1], sys.argv[2]
    if op == "find":
        print(*find(dev))
        return
    fd, m, size = open_map(dev)
    if op == "write":
        tag = sys.argv[3]
        offs = [int(x) for x in sys.argv[4:]] or DEFAULT_OFFSETS
        for o in offs:
            s = ("%s@%dM " % (tag, o)).encode()
            blk = (s * (4096 // len(s) + 1))[:4096]
            m[o * MB:o * MB + 4096] = blk
            print("wrote %r at %dM" % (s, o))
    elif op == "read":
        offs = [int(x) for x in sys.argv[3:]] or DEFAULT_OFFSETS
        for o in offs:
            b = bytes(m[o * MB:o * MB + 64])
            print("%dM: %r" % (o, b.split(b" ")[0]))
    elif op == "bench":
        n = int(sys.argv[3]) * MB if len(sys.argv) > 3 else size - 2 * MB
        src = bytearray(os.urandom(MB)) * (n // MB)
        for i in range(2):
            t0 = time.perf_counter()
            m[0:n] = src
            t1 = time.perf_counter()
            dst = m[0:n]
            t2 = time.perf_counter()
            print("pass %d: write %d MB in %.3fs = %.2f GB/s, read %.3fs = %.2f GB/s, equal=%s"
                  % (i, n // MB, t1 - t0, n / (t1 - t0) / 1e9, t2 - t1, n / (t2 - t1) / 1e9, dst == src))
    m.close()
    os.close(fd)


if __name__ == "__main__":
    main()
