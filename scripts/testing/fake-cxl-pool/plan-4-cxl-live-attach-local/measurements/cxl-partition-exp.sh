#!/bin/bash
# Partitioning experiment on a VM with four hotplugged 256M CXL memdevs.
set -u
BS=$(( 0x$(cat /sys/devices/system/memory/block_size_bytes) ))  # hex in sysfs
echo "block size $BS"
bysn() { for m in /sys/bus/cxl/devices/mem*; do [ "$(cat $m/serial)" = "$1" ] && basename $m; done; }
A=$(bysn 0xc100e2e0); B=$(bysn 0xc100e2e1); C=$(bysn 0xc100e2e2); D=$(bysn 0xc100e2e3)
echo "HB0: A=$A B=$B   HB1: C=$C D=$D"
echo "== decoder counts per component (HDM decoders)"
for p in /sys/bus/cxl/devices/port* /sys/bus/cxl/devices/endpoint*; do echo "$(basename $p): $(ls -d $p/decoder* 2>/dev/null | wc -l) decoders"; done
echo "== 1. region of 128M on $A: expect EINVAL (256M alignment)"
cxl create-region -t ram -d decoder0.0 -m $A -s $((128<<20)) 2>&1 | tail -2; echo "rc=${PIPESTATUS[0]}"
echo "== 2. full 256M region on $A"
cxl create-region -t ram -d decoder0.0 -m $A 2>&1 | grep -v "^{" | tail -3
sleep 1
R0=$(ls -d /sys/bus/cxl/devices/region* | head -1 | xargs basename)
DR0=$(ls -d /sys/bus/cxl/devices/$R0/dax_region* | xargs basename)
echo "region $R0 size=$(cat /sys/bus/cxl/devices/$R0/size) mode=$(cat /sys/bus/cxl/devices/$R0/mode 2>/dev/null) dax_region=$DR0"
echo "dax_region attrs: $(ls /sys/bus/cxl/devices/$R0/$DR0 | tr '\n' ' ')"
echo "available_size=$(cat /sys/bus/cxl/devices/$R0/$DR0/available_size) align=$(cat /sys/bus/cxl/devices/$R0/$DR0/align)"
daxinfo() { for d in /sys/bus/dax/devices/dax*; do echo "  $(basename $d): size=$(cat $d/size) target_node=$(cat $d/target_node) align=$(cat $d/align) resource=$(cat $d/resource 2>/dev/null) driver=$(readlink $d/driver 2>/dev/null | xargs -r basename)"; done; }
daxinfo
echo "== 3. second region on $B (same HB0, same window decoder0.0) and on $C (HB1)"
cxl create-region -t ram -d decoder0.0 -m $B 2>&1 | grep -v "^{" | tail -2
cxl create-region -t ram -d decoder0.1 -m $C 2>&1 | grep -v "^{" | tail -2
sleep 1
for r in /sys/bus/cxl/devices/region*; do echo "$(basename $r): resource=$(cat $r/resource) size=$(cat $r/size) targets=$(cat $r/target0)"; done
daxinfo
echo "== 4. interleave 2-way over $A+$B impossible now (both busy); skip"
echo "== 5. slice $R0 into dax sub-devices"
D0=$(ls /sys/bus/cxl/devices/$R0/$DR0 | grep '^dax' | head -1)
echo "initial device $D0 driver=$(readlink /sys/bus/dax/devices/$D0/driver | xargs basename)"
echo $D0 > /sys/bus/dax/drivers/kmem/unbind 2>&1 && echo "unbound $D0 from kmem"
echo $D0 > /sys/bus/cxl/devices/$R0/$DR0/delete 2>&1 && echo "deleted $D0"
echo "available_size=$(cat /sys/bus/cxl/devices/$R0/$DR0/available_size)"
mk() { # size driver
  local n; n=$(cat /sys/bus/cxl/devices/$R0/$DR0/create) || return 1
  echo $1 > /sys/bus/dax/devices/$n/size || { echo "size failed for $n"; return 1; }
  echo $n > /sys/bus/dax/drivers/$2/new_id 2>/dev/null
  [ "$(readlink /sys/bus/dax/devices/$n/driver 2>/dev/null | xargs -r basename)" = "$2" ] || echo $n > /sys/bus/dax/drivers/$2/bind 2>&1
  echo "$n"
}
S1=$(mk $((64<<20)) device_dax); S2=$(mk $((64<<20)) device_dax); S3=$(mk $((128<<20)) kmem)
echo "created $S1 $S2 $S3; available_size=$(cat /sys/bus/cxl/devices/$R0/$DR0/available_size)"
sleep 1; daxinfo; ls -l /dev/dax* 2>&1
echo "== 6. kmem slice $S3: memory blocks and onlining"
RES=$(( $(cat /sys/bus/dax/devices/$S3/resource) )); SZ=$(( $(cat /sys/bus/dax/devices/$S3/size) ))
echo "$S3 resource=0x$(printf %x $RES) size=$SZ blocks $((RES/BS))..$(((RES+SZ)/BS-1))"
for b in $(seq $((RES/BS)) $(((RES+SZ)/BS-1))); do f=/sys/devices/system/memory/memory$b/state; [ -f $f ] && { echo "memory$b: $(cat $f) -> online_movable"; echo online_movable > $f; echo "  now $(cat $f), node $(ls -d /sys/devices/system/memory/memory$b/node* | xargs -n1 basename)"; } || echo "memory$b: no such block"; done
grep -H MemTotal /sys/devices/system/node/node*/meminfo
echo "== 7. isolation of dax slices: write $S1, read $S1 and $S2"
python3 - "$S1" "$S2" <<'PY'
import mmap, os, sys
def rw(path, data=None):
    fd = os.open(path, os.O_RDWR); m = mmap.mmap(fd, 2<<20, mmap.MAP_SHARED, mmap.PROT_READ|mmap.PROT_WRITE)
    if data: m[0:len(data)] = data
    v = bytes(m[0:8]); m.close(); os.close(fd); return v
a, b = "/dev/"+sys.argv[1], "/dev/"+sys.argv[2]
print(a, "write:", rw(a, b"SLICE-A!"), "read:", rw(a)); print(b, "read:", rw(b))
PY
echo "== 8. teardown: offline, unbind, delete slices, destroy regions"
for b in $(seq $((RES/BS)) $(((RES+SZ)/BS-1))); do echo offline > /sys/devices/system/memory/memory$b/state; done
echo $S3 > /sys/bus/dax/drivers/kmem/unbind; echo $S1 > /sys/bus/dax/drivers/device_dax/unbind; echo $S2 > /sys/bus/dax/drivers/device_dax/unbind
for s in $S1 $S2 $S3; do echo $s > /sys/bus/cxl/devices/$R0/$DR0/delete && echo "deleted $s"; done
echo "available_size=$(cat /sys/bus/cxl/devices/$R0/$DR0/available_size)"
for r in $(ls -d /sys/bus/cxl/devices/region* | xargs -n1 basename); do cxl disable-region $r >/dev/null 2>&1; cxl destroy-region $r >/dev/null 2>&1 && echo "destroyed $r"; done
ls /sys/bus/cxl/devices/ | grep -c region; ls /sys/bus/dax/devices/ 2>/dev/null | wc -l
echo "== 9. dax device minor numbers available: $(cat /proc/devices | grep dax)"
