#!/usr/bin/env python3
"""Write and read strings in CXL memory through a devdax device.

Run in a VM as root. pool.source.sh copies this to the VMs.

Usage:
  pool-dax-rw.py write DEV OFFSET TEXT   write TEXT and a NUL byte at OFFSET
  pool-dax-rw.py read DEV OFFSET         print the NUL-terminated string at OFFSET

DEV is /dev/daxX.Y. OFFSET is in bytes, or with a K, M or G suffix.

The whole device is mapped MAP_SHARED: devdax refuses private mappings and
mappings that are not aligned to the device alignment (2M). The mapping
goes straight to the CXL memory, that is, to the backing file of the memory
device on the host, so every VM that has the same shared device attached
sees a write at once.
"""
import mmap
import os
import sys

MAX_STRING = 4096
UNITS = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}


def parse_offset(s):
    if s and s[-1].upper() in UNITS:
        return int(s[:-1], 0) * UNITS[s[-1].upper()]
    return int(s, 0)


def main():
    if len(sys.argv) < 4 or sys.argv[1] not in ("write", "read") or \
            (sys.argv[1] == "write") != (len(sys.argv) == 5):
        sys.exit(__doc__)
    op, dev, offset = sys.argv[1], sys.argv[2], parse_offset(sys.argv[3])
    with open("/sys/bus/dax/devices/%s/size" % os.path.basename(dev)) as f:
        size = int(f.read())
    if offset < 0 or offset + MAX_STRING > size:
        sys.exit("offset %d out of range, %s has %d bytes" % (offset, dev, size))
    fd = os.open(dev, os.O_RDWR)
    try:
        m = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        if op == "write":
            data = sys.argv[4].encode() + b"\0"
            if len(data) > MAX_STRING:
                sys.exit("text too long, max %d bytes" % (MAX_STRING - 1))
            m[offset:offset + len(data)] = data
        else:
            data = bytes(m[offset:offset + MAX_STRING]).split(b"\0", 1)[0]
            print(data.decode(errors="replace"))
        m.close()
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
