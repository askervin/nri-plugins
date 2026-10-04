#!/usr/bin/env python3
# Usage: guest-dax-hold.py DAXDEV   (in the guest, as root)
# Keep /dev/DAXDEV mmapped and write a counter at offset 0 every second.
# Used for WS3 Q6: what a devdax user sees when the device is hot-removed
# (answer: the process dies with SIGBUS, DEVICE_DELETED still arrives).
import mmap, os, time, sys
dev = sys.argv[1]
size = int(open("/sys/bus/dax/devices/%s/size" % dev).read())
fd = os.open("/dev/" + dev, os.O_RDWR)
m = mmap.mmap(fd, size, mmap.MAP_SHARED)
i = 0
while True:
    try:
        m[0:16] = (b"HOLDER %09d" % i)[:16]
        print("write", i, bytes(m[0:16]), flush=True)
    except Exception as e:
        print("ERR", repr(e), flush=True)
    i += 1
    time.sleep(1)
