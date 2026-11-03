#!/bin/bash
# plan-14 probe 1: read-only block devices, ext4/xfs recovery, the new
# mount API (superblock ro, mount attribute rw), upgrade and downgrade
# with binds. Runs as root in a VM; loop devices over files in /var/tmp
# only, no CXL device, no cluster object.
set -u
W=/var/tmp/fsprobe
cleanup() {
    for m in $(awk '{print $5}' /proc/self/mountinfo | grep "^$W" | sort -r); do umount "$m" 2>/dev/null; done
    for l in $(losetup -j $W/ext4.img -O NAME -n 2>/dev/null) $(losetup -j $W/xfs.img -O NAME -n 2>/dev/null); do losetup -d "$l"; done
    [ -n "${SLAVE:-}" ] && kill "$SLAVE" 2>/dev/null
}
trap cleanup EXIT
rm -rf $W; mkdir -p $W/m $W/m2
cd $W
sha() { sha256sum "$1" | cut -c1-16; }
say() { echo "== $*"; }
klog() { dmesg | tail -n "${1:-3}" | sed 's/^/   dmesg: /'; }

cat > $W/mapi.py <<'EOF'
# the new mount API through syscall(2): python3 mapi.py OP ARGS
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
SYS_open_tree, SYS_move_mount, SYS_fsopen, SYS_fsconfig, SYS_fsmount, SYS_fspick, SYS_mount_setattr = 428, 429, 430, 431, 432, 433, 442
FSCONFIG_SET_FLAG, FSCONFIG_SET_STRING, FSCONFIG_CMD_CREATE, FSCONFIG_CMD_RECONFIGURE = 0, 1, 6, 7
MOUNT_ATTR_RDONLY, MOUNT_ATTR_NOSUID, MOUNT_ATTR_NODEV = 1, 2, 4
MOVE_MOUNT_F_EMPTY_PATH, OPEN_TREE_CLONE, AT_EMPTY_PATH, AT_FDCWD = 4, 1, 0x1000, -100
class mount_attr(ctypes.Structure):
    _fields_ = [("attr_set", ctypes.c_uint64), ("attr_clr", ctypes.c_uint64),
                ("propagation", ctypes.c_uint64), ("userns_fd", ctypes.c_uint64)]
def sc(n, *a):
    r = libc.syscall(n, *a)
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r
def fslog(fd):
    out = []
    while True:
        try:
            out.append(os.read(fd, 512).decode().strip())
        except OSError:
            return out
op = sys.argv[1]
try:
    if op == "mount":            # mount FSTYPE DEV TARGET sbflag(ro|rw) [data...]
        fstype, dev, target, sbflag = sys.argv[2:6]
        fd = sc(SYS_fsopen, fstype.encode(), 0)
        try:
            sc(SYS_fsconfig, fd, FSCONFIG_SET_STRING, b"source", dev.encode(), 0)
            if sbflag == "ro":
                sc(SYS_fsconfig, fd, FSCONFIG_SET_FLAG, b"ro", None, 0)
            for d in sys.argv[6:]:
                k, _, v = d.partition("=")
                if v:
                    sc(SYS_fsconfig, fd, FSCONFIG_SET_STRING, k.encode(), v.encode(), 0)
                else:
                    sc(SYS_fsconfig, fd, FSCONFIG_SET_FLAG, k.encode(), None, 0)
            sc(SYS_fsconfig, fd, FSCONFIG_CMD_CREATE, None, None, 0)
        except OSError as e:
            print("   mount failed:", e, fslog(fd)); sys.exit(1)
        mfd = sc(SYS_fsmount, fd, 0, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)
        sc(SYS_move_mount, mfd, b"", AT_FDCWD, target.encode(), MOVE_MOUNT_F_EMPTY_PATH)
        print("   mounted", fstype, dev, "at", target, "sb", sbflag, "attr nosuid,nodev", fslog(fd))
    elif op == "robind":         # robind SOURCE TARGET
        src, target = sys.argv[2:4]
        t = sc(SYS_open_tree, AT_FDCWD, src.encode(), OPEN_TREE_CLONE)
        ma = mount_attr(MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0, 0, 0)
        sc(SYS_mount_setattr, t, b"", AT_EMPTY_PATH, ctypes.byref(ma), ctypes.sizeof(ma))
        sc(SYS_move_mount, t, b"", AT_FDCWD, target.encode(), MOVE_MOUNT_F_EMPTY_PATH)
        print("   ro bind (clone + setattr + move) of", src, "at", target)
    elif op == "reconf":         # reconf TARGET ro|rw
        target, flag = sys.argv[2:4]
        fd = sc(SYS_fspick, AT_FDCWD, target.encode(), 0)
        sc(SYS_fsconfig, fd, FSCONFIG_SET_FLAG, flag.encode(), None, 0)
        try:
            sc(SYS_fsconfig, fd, FSCONFIG_CMD_RECONFIGURE, None, None, 0)
            print("   reconfigured", target, flag, fslog(fd))
        except OSError as e:
            print("   reconfigure", target, flag, "failed:", e, fslog(fd)); sys.exit(1)
except OSError as e:
    print("   ", op, "failed:", e); sys.exit(1)
EOF
mapi() { python3 $W/mapi.py "$@"; }

truncate -s 256M ext4.img
mkfs.ext4 -q -b 4096 -F ext4.img
L=$(losetup -f --show ext4.img)

say "A1 ext4 clean, mount -o ro on a writable bdev, umount: image changed?"
s0=$(sha ext4.img); mount -o ro $L $W/m; umount $W/m; s1=$(sha ext4.img)
[ "$s0" != "$s1" ] && echo "   changed" || echo "   unchanged"

say "A2 ext4 clean, ro bdev: mount -o ro"
blockdev --setro $L; s0=$(sha ext4.img)
mount -o ro $L $W/m; echo "   mount rc=$?"
mount -o remount,rw $W/m 2>&1 | sed 's/^/   /'; echo "   A3 remount rw on ro bdev rc=${PIPESTATUS[0]}"
mapi reconf $W/m rw; echo "   A3b fspick reconfigure rw on ro bdev rc=$?"
umount $W/m; s1=$(sha ext4.img); [ "$s0" != "$s1" ] && echo "   image changed" || echo "   image unchanged"
mount $L $W/m 2>&1 | sed 's/^/   /'; echo "   A4 mount rw on ro bdev rc=${PIPESTATUS[0]}"
umount $W/m 2>/dev/null

say "A5 ext4 needs_recovery (debugfs), ro bdev: mount -o ro"
blockdev --setrw $L
debugfs -w -R "feature needs_recovery" $L >/dev/null 2>&1
dumpe2fs -h $L 2>/dev/null | grep -i "^Filesystem features" | sed 's/^/   /'
blockdev --setro $L
mount -o ro $L $W/m 2>&1 | sed 's/^/   /'; echo "   rc=${PIPESTATUS[0]}"; klog 3
umount $W/m 2>/dev/null
mapi mount ext4 $L $W/m ro; klog 2
umount $W/m 2>/dev/null
blockdev --setrw $L
debugfs -w -R "feature -needs_recovery" $L >/dev/null 2>&1

say "B mount API: sb ro + mount attr rw under a shared dir, seen from a slave namespace"
mkdir -p $W/sh; mount --bind $W/sh $W/sh; mount --make-shared $W/sh
mkdir -p $W/sh/node $W/sh/ro1 $W/sh/rw1
unshare -m --propagation slave sleep 600 & SLAVE=$!
sleep 1
mapi mount ext4 $L $W/sh/node ro
mapi robind $W/sh/node $W/sh/ro1
mount --bind $W/sh/node $W/sh/rw1
view() { for t in node ro1 rw1; do echo "   $1 $t: $(grep " $W/sh/$t " /proc/$2/mountinfo | awk '{print "mnt=" $6 " sb=" $NF}')"; done; }
view host self; view slave $SLAVE
nsw() { nsenter -t $SLAVE -m sh -c "$1" 2>&1 | sed 's/^/   /'; }
say "B3 writes in the slave while sb ro"
nsw "touch $W/sh/rw1/a && echo rw1 write ok"; nsw "touch $W/sh/ro1/a && echo ro1 write ok"

say "B4 upgrade: fspick + rw + reconfigure"
mapi reconf $W/sh/node rw
view slave $SLAVE
nsw "touch $W/sh/rw1/b && echo rw1 write ok"; nsw "touch $W/sh/ro1/b && echo ro1 write ok"
nsw "mkdir -p /tmp/ctr && mount --bind $W/sh/node /tmp/ctr && mount -o remount,bind,nosuid,nodev /tmp/ctr && touch /tmp/ctr/c && echo cdi-like rw bind write ok; umount /tmp/ctr"
nsw "mkdir -p /tmp/ctr && mount --bind $W/sh/node /tmp/ctr && mount -o remount,bind,ro,nosuid,nodev /tmp/ctr && (touch /tmp/ctr/d && echo cdi-like ro bind write ok); umount /tmp/ctr"

say "B5 downgrade with a file open for write in the slave"
nsenter -t $SLAVE -m sh -c "exec 3>$W/sh/rw1/held; sleep 4" & H=$!
sleep 1
mapi reconf $W/sh/node ro
wait $H
mapi reconf $W/sh/node ro
dumpe2fs -h $L 2>/dev/null | grep -E "^Filesystem features|^Filesystem state" | sed 's/^/   /'
view slave $SLAVE
nsw "ls $W/sh/ro1 | tr '\n' ' '"
umount $W/sh/rw1 $W/sh/ro1 $W/sh/node

say "C two superblocks of one ext4 (two loop devices over the image), both ro"
L2=$(losetup -r -f --show ext4.img)
blockdev --setro $L
mount -o ro $L $W/m && mount -o ro $L2 $W/m2 && echo "   both mounted"; umount $W/m $W/m2 2>/dev/null
blockdev --setrw $L

if command -v mkfs.xfs >/dev/null; then
    say "D xfs"
    truncate -s 512M xfs.img; mkfs.xfs -q -f xfs.img
    X=$(losetup -f --show xfs.img)
    s0=$(sha xfs.img); mount -o ro $X $W/m; umount $W/m; s1=$(sha xfs.img)
    echo "   D1 clean, ro mount on writable bdev: $([ "$s0" != "$s1" ] && echo changed || echo unchanged)"
    blockdev --setro $X; s0=$(sha xfs.img); mount -o ro $X $W/m; umount $W/m; s1=$(sha xfs.img)
    echo "   D2 clean, ro mount on ro bdev: $([ "$s0" != "$s1" ] && echo changed || echo unchanged)"
    X2=$(losetup -r -f --show xfs.img)
    mount -o ro $X $W/m; mount -o ro $X2 $W/m2 2>&1 | sed 's/^/   /'; echo "   D3 second sb without nouuid rc=${PIPESTATUS[0]}"; klog 1
    mount -o ro,nouuid $X2 $W/m2 && echo "   D3 second sb with nouuid ok"; umount $W/m $W/m2 2>/dev/null
    blockdev --setrw $X
    mount $X $W/m && dd if=/dev/zero of=$W/m/f bs=1M count=8 status=none && sync && xfs_io -x -c "shutdown" $W/m; umount $W/m
    blockdev --setro $X
    mount -o ro $X $W/m 2>&1 | sed 's/^/   /'; echo "   D4 dirty log, ro bdev, ro mount rc=${PIPESTATUS[0]}"; klog 3
    umount $W/m 2>/dev/null
    blockdev --setrw $X
    s0=$(sha xfs.img); mount -o ro $X $W/m 2>&1 | sed 's/^/   /'; umount $W/m 2>/dev/null; s1=$(sha xfs.img)
    echo "   D5 dirty log, writable bdev, ro mount: $([ "$s0" != "$s1" ] && echo "image changed (log recovered)" || echo unchanged)"; klog 2
fi
echo "probe done"
