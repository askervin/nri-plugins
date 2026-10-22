#!/usr/bin/env python3
"""The demo tools in the containers: the memory of a lease, through its fd.

ConfigMap demo-tools mounts this at /demo with the wrappers write, read,
hold, env and mkfs:
  /demo/write TEXT   write TEXT and a NUL at offset 0 of the lease's memory,
                     keep the mapping DEMO_HOLD seconds (default 3)
  /demo/read         print the NUL-terminated string at offset 0
  /demo/hold         keep a read-only mapping in the background until
                     /demo/hold --stop (or the pod ends)
  /demo/env          the CXL_* variables of every lease of the pod
  /demo/mkfs TEXT    make an erofs with hello.txt (TEXT and a newline) with
                     mkfs.erofs and write it at offset 0 of the block device
                     of a block lease, keep the fd DEMO_HOLD seconds
The lease is the newest dax lease of the container (block lease for mkfs,
cxl-request list); DEMO_LEASE=ID picks one. The fd comes from
"cxl-request fd --lease ID --exec": the container needs no device node. A
read-only lease's fd refuses a writable mapping: write prints "refused:
read-only (EACCES)"; mkfs prints "refused: read-only (EBADF)".
"""
import errno
import json
import mmap
import os
import signal
import subprocess
import sys
import time

FD = 3
MAP_LEN = 2 << 20     # devdax maps in multiples of its 2 MiB alignment
STOP = "/tmp/demo-hold.stop"
HOLD_LOG = "/tmp/demo-hold.log"
FS_DIR = "/tmp/fs"
FS_FILE = "hello.txt"
FS_IMAGE = "/tmp/hello.erofs"
HINTS = {"dax": "no dax lease: cxl-request request ... first",
         "block": "no block lease: cxl-request request --mode block first"}


def leases():
    p = subprocess.run(["cxl-request", "list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        sys.exit("cxl-request list: " + (p.stderr or p.stdout).decode(errors="replace").strip())
    try:
        return json.loads(p.stdout.decode()).get("leases") or []
    except ValueError:
        sys.exit("cxl-request list: unexpected output")


def lease(modes=("dax",)):
    """Return the id of the lease to use: DEMO_LEASE or the newest lease of one of MODES."""
    if os.environ.get("DEMO_LEASE"):
        return os.environ["DEMO_LEASE"]
    found = [l for l in leases() if l.get("mode") in modes and l.get("state") not in ("Failed", "Released", "Releasing")]
    if not found:
        sys.exit(HINTS.get(modes[0], "no %s lease" % modes[0]))
    return found[-1]["lease"]


def with_fd(op, *args, background=False, modes=("dax",)):
    """Run this tool's internal OP with the fd of a lease of MODES as fd 3."""
    cmd = ["cxl-request", "fd", "--lease", lease(modes), "--wait", "120s", "--exec",
           sys.executable, os.path.abspath(__file__), op] + list(args)
    if not background:
        os.execvp(cmd[0], cmd)
    log = open(HOLD_LOG, "w")
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                         start_new_session=True)
    for _ in range(50):
        time.sleep(0.1)
        with open(HOLD_LOG) as f:
            text = f.read()
        if "holding" in text or p.poll() is not None:
            break
    print(text.strip() or "holder started, pid %d" % p.pid)


def mapping(write):
    size = MAP_LEN
    for k, v in os.environ.items():
        if k.startswith("CXL_") and k.endswith("_SIZE") and v.isdigit():
            size = min(size, int(v))
    prot = mmap.PROT_READ | (mmap.PROT_WRITE if write else 0)
    return mmap.mmap(FD, size, mmap.MAP_SHARED, prot)


def text_at(m):
    s = bytes(m[:4096]).split(b"\0", 1)[0]
    return s.decode(errors="replace")


def do_write(text):
    try:
        m = mapping(True)
    except PermissionError as e:
        print("refused: read-only (%s)" % errno.errorcode.get(e.errno, e.errno))
        sys.exit(1)
    data = text.encode() + b"\0"
    m[:len(data)] = data
    print('wrote at 0: "%s"' % text)
    sys.stdout.flush()
    time.sleep(float(os.environ.get("DEMO_HOLD", "3")))
    m.close()


def do_read():
    m = mapping(False)
    print('read at 0: "%s"' % text_at(m))
    m.close()


def do_hold():
    m = mapping(False)
    if os.path.exists(STOP):
        os.unlink(STOP)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print('holding a read-only mapping, pid %d: "%s"' % (os.getpid(), text_at(m)), flush=True)
    while not os.path.exists(STOP):
        time.sleep(0.2)
    m.close()
    print("released the mapping", flush=True)


def do_mkfs(text):
    """Make the erofs image with hello.txt, then write it through the fd of a block lease."""
    os.makedirs(FS_DIR, exist_ok=True)
    with open(os.path.join(FS_DIR, FS_FILE), "w") as f:
        f.write(text + "\n")
    if os.path.exists(FS_IMAGE):
        os.unlink(FS_IMAGE)
    p = subprocess.run(["mkfs.erofs", "-b4096", "-Enoinline_data", FS_IMAGE, FS_DIR],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        sys.stdout.write(p.stdout.decode(errors="replace"))
        sys.exit("mkfs.erofs failed with exit status %d" % p.returncode)
    with_fd("_flash", FS_IMAGE, modes=("block",))


def do_flash(image):
    """Write IMAGE at offset 0 of fd 3, fsync it, and keep the fd DEMO_HOLD seconds."""
    with open(image, "rb") as f:
        data = f.read()
    try:
        done = 0
        while done < len(data):
            done += os.pwrite(FD, data[done:], done)
        os.fsync(FD)
    except OSError as e:
        if e.errno == errno.EBADF:
            print("refused: read-only (EBADF)")
            sys.exit(1)
        raise
    with open(os.path.join(FS_DIR, FS_FILE)) as f:
        text = f.read().rstrip("\n")
    print('wrote erofs (%d bytes) with %s: "%s"' % (len(data), FS_FILE, text))
    sys.stdout.flush()
    time.sleep(float(os.environ.get("DEMO_HOLD", "3")))
    os.close(FD)


def do_env():
    for l in leases():
        print("lease %s %s" % (l.get("lease"), l.get("state")))
        for k, v in sorted((l.get("env") or {}).items()):
            print("  %s=%s" % (k, v))


def main():
    args = sys.argv[1:]
    op = args[0] if args else ""
    if op == "write" and len(args) == 2:
        with_fd("_write", args[1])
    elif op == "read" and len(args) == 1:
        with_fd("_read")
    elif op == "hold" and args[1:] == ["--stop"]:
        open(STOP, "w").close()
        print("asked the holder to release its mapping")
    elif op == "hold" and len(args) == 1:
        with_fd("_hold", background=True)
    elif op == "env":
        do_env()
    elif op == "mkfs" and len(args) == 2:
        do_mkfs(args[1])
    elif op == "_flash" and len(args) == 2:
        do_flash(args[1])
    elif op == "_write":
        do_write(args[1])
    elif op == "_read":
        do_read()
    elif op == "_hold":
        do_hold()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
