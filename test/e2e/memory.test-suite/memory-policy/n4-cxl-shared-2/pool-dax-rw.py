#!/usr/bin/env python3
"""Write and read strings in CXL memory through a devdax device.

Run in a VM as root. pool.source.sh copies this to the VMs.

Usage:
  pool-dax-rw.py write DEV OFFSET TEXT        write TEXT and a NUL byte at OFFSET
  pool-dax-rw.py read DEV OFFSET              print the NUL-terminated string at OFFSET
  pool-dax-rw.py --fd N write OFFSET TEXT     the same through the open fd N
  pool-dax-rw.py --fd N read OFFSET

DEV is /dev/daxX.Y. OFFSET is in bytes, or with a K, M or G suffix.

With --fd N the device is not opened: N is a file descriptor that the
process inherited, for instance from "cxl-request shared SERIAL --exec"
(fd 3, CXL_LEASE_FD), which received it from kubelet-cxl-plugin over a unix
socket. The container needs no device node for it. The size of the mapping
comes from the sysfs of the device the fd refers to, from CXL_LEASE_SIZE,
or, for a regular file (tests), from its size.

The whole device is mapped MAP_SHARED: devdax refuses private mappings and
mappings that are not aligned to the device alignment (2M). The mapping
goes straight to the CXL memory, that is, to the backing file of the memory
device on the host, so every VM that has the same shared device attached
sees a write at once.
"""
import mmap
import os
import stat
import sys

MAX_STRING = 4096
UNITS = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}


def parse_offset(s):
    if s and s[-1].upper() in UNITS:
        return int(s[:-1], 0) * UNITS[s[-1].upper()]
    return int(s, 0)


def dax_size(name):
    with open("/sys/bus/dax/devices/%s/size" % os.path.basename(name)) as f:
        return int(f.read())


def fd_size(fd):
    st = os.fstat(fd)
    if stat.S_ISREG(st.st_mode):
        return st.st_size
    try:
        return dax_size(os.readlink("/proc/self/fd/%d" % fd))
    except OSError:
        pass
    if os.environ.get("CXL_LEASE_SIZE"):
        return int(os.environ["CXL_LEASE_SIZE"], 0)
    sys.exit("cannot find the size of fd %d: no sysfs entry, no CXL_LEASE_SIZE" % fd)


def main():
    args = sys.argv[1:]
    fd = None
    if args[:1] == ["--fd"]:
        if len(args) < 2:
            sys.exit(__doc__)
        fd, args = int(args[1]), args[2:]
        args = args[:1] + ["fd:%d" % fd] + args[1:]   # the place of DEV
    if len(args) < 3 or args[0] not in ("write", "read") or \
            (args[0] == "write") != (len(args) == 4):
        sys.exit(__doc__)
    op, dev, offset = args[0], args[1], parse_offset(args[2])
    if fd is None:
        size = dax_size(dev)
    else:
        size = fd_size(fd)
    if offset < 0 or offset + MAX_STRING > size:
        sys.exit("offset %d out of range, %s has %d bytes" % (offset, dev, size))
    own = fd is None
    if own:
        fd = os.open(dev, os.O_RDWR)
    try:
        prot = mmap.PROT_READ | (mmap.PROT_WRITE if op == "write" else 0)
        m = mmap.mmap(fd, size, mmap.MAP_SHARED, prot)
        if op == "write":
            data = args[3].encode() + b"\0"
            if len(data) > MAX_STRING:
                sys.exit("text too long, max %d bytes" % (MAX_STRING - 1))
            m[offset:offset + len(data)] = data
        else:
            data = bytes(m[offset:offset + MAX_STRING]).split(b"\0", 1)[0]
            print(data.decode(errors="replace"))
        m.close()
    finally:
        if own:
            os.close(fd)


if __name__ == "__main__":
    main()
