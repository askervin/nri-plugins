#!/bin/bash
# plan-14 probe 2: upgrade of a superblock that was mounted on a read-only
# block device (ext4, xfs, btrfs), a writable loop device made read-only
# by BLKROSET over a read-only backing device, and downgrade back. Runs as
# root in a VM; loop devices over files in /var/tmp only.
set -u
W=/var/tmp/fsprobe2
cleanup() {
    for m in $(awk '{print $5}' /proc/self/mountinfo | grep "^$W" | sort -r); do umount "$m" 2>/dev/null; done
    for f in $W/*.img; do for l in $(losetup -j "$f" -O NAME -n 2>/dev/null); do losetup -d "$l"; done; done
}
trap cleanup EXIT
rm -rf $W; mkdir -p $W/m
cd $W
cp /var/tmp/fsprobe/mapi.py $W/mapi.py 2>/dev/null || { echo "run probe1.sh first (mapi.py)"; exit 1; }
mapi() { python3 $W/mapi.py "$@"; }
say() { echo "== $*"; }
sha() { sha256sum "$1" | cut -c1-16; }
klog() { dmesg | tail -n "${1:-2}" | sed 's/^/   dmesg: /'; }

upgrade() { # FSTYPE MKFS... : mount ro on ro bdev, upgrade, write, downgrade
    local t=$1; shift
    truncate -s 512M $t.img; "$@" $t.img >/dev/null 2>&1 || { echo "   mkfs $t failed"; return; }
    local L; L=$(losetup -f --show $t.img)
    blockdev --setro $L
    local s0; s0=$(sha $t.img)
    mapi mount $t $L $W/m ro || { klog 3; losetup -d $L; return; }
    echo "   sb: $(grep " $W/m " /proc/self/mountinfo | awk '{print "mnt=" $6 " sb=" $NF}')"
    blockdev --setrw $L
    mapi reconf $W/m rw || klog 3
    touch $W/m/written && echo "   write after upgrade ok"
    sync -f $W/m/written
    mapi reconf $W/m ro || klog 3
    blockdev --setro $L
    touch $W/m/x 2>&1 | sed 's/^/   /'
    umount $W/m
    [ "$(sha $t.img)" != "$s0" ] && echo "   image changed (expected: the write)"
    case $t in ext4) dumpe2fs -h $L 2>/dev/null | grep -E "^Filesystem state|^Filesystem features" | sed 's/^/   /';; esac
    mapi mount $t $L $W/m ro >/dev/null && { ls $W/m | tr '\n' ' ' | sed 's/^/   files: /'; echo; umount $W/m; }
    losetup -d $L
}

say "U1 ext4: mounted on a ro bdev, BLKROSET 0, reconfigure rw, write, reconfigure ro, BLKROSET 1"
upgrade ext4 mkfs.ext4 -q -F -b 4096
say "U2 xfs: the same"
upgrade xfs mkfs.xfs -q -f
say "U3 btrfs: the same"
upgrade btrfs mkfs.btrfs -q -f

say "L1 writable loop (backing O_RDWR) over a ro backing device, BLKROSET 1 on both, ro mount, upgrade"
truncate -s 512M back.img; mkfs.ext4 -q -F -b 4096 back.img
B=$(losetup -f --show back.img)
blockdev --setro $B
python3 - "$B" <<'EOF'
import fcntl, os, struct, sys
LOOP_CTL_GET_FREE, LOOP_CONFIGURE = 0x4C82, 0x4C0A
LO_FLAGS_AUTOCLEAR, LO_FLAGS_DIRECT_IO = 4, 16
back = sys.argv[1]
ctl = os.open("/dev/loop-control", os.O_RDWR)
n = fcntl.ioctl(ctl, LOOP_CTL_GET_FREE)
loop = "/dev/loop%d" % n
fd = os.open(back, os.O_RDWR)          # a ro block device opened for writing
lfd = os.open(loop, os.O_RDWR)
# struct loop_config { u32 fd; u32 block_size; struct loop_info64 info; u64 reserved[8]; }
info = bytearray(232)                  # loop_info64
struct.pack_into("=I", info, 52, LO_FLAGS_DIRECT_IO)   # lo_flags (not AUTOCLEAR: kept for the probe)
cfg = struct.pack("=II", fd, 0) + bytes(info) + bytes(64)
fcntl.ioctl(lfd, LOOP_CONFIGURE, cfg)
print("   configured", loop, "over", back, "ro of loop:", open("/sys/block/loop%d/ro" % n).read().strip())
open("/var/tmp/fsprobe2/loopname", "w").write(loop)
EOF
LP=$(cat $W/loopname)
blockdev --setro $LP
mapi mount ext4 $LP $W/m ro && echo "   ro mount on the ro loop ok"
touch $W/m/a 2>&1 | sed 's/^/   /'
blockdev --setrw $LP
mapi reconf $W/m rw; touch $W/m/b 2>&1 | sed 's/^/   /'; sync -f $W/m 2>&1 | sed 's/^/   /'; klog 3
echo "   (expected: the write reaches the loop, the loop's write to the ro backing fails)"
mapi reconf $W/m ro 2>&1; umount $W/m 2>&1 | sed 's/^/   /'
blockdev --setrw $B
mapi mount ext4 $LP $W/m ro >/dev/null && { umount $W/m; }
blockdev --setrw $LP
mapi mount ext4 $LP $W/m rw && touch $W/m/c && sync -f $W/m && echo "   both rw: write ok"; umount $W/m
losetup -d $LP; losetup -d $B
echo "probe done"
