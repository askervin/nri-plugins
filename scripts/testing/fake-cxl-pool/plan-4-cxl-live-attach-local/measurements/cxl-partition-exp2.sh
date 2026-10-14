#!/bin/bash
set -u
BS=$(( 0x$(cat /sys/devices/system/memory/block_size_bytes) ))  # hex in sysfs
bysn() { for m in /sys/bus/cxl/devices/mem*; do [ "$(cat $m/serial)" = "$1" ] && basename $m; done; }
A=$(bysn 0xc100e2e0); C=$(bysn 0xc100e2e2)
echo "A=$A (HB0) C=$C (HB1); dmesg marker"; echo "EXP2 start" > /dev/kmsg
t0=$EPOCHREALTIME
cxl create-region -t ram -d decoder0.0 -m $A >/dev/null 2>&1 || echo "create-region A failed"
R0=$(ls -d /sys/bus/cxl/devices/region* | head -1 | xargs basename); DR=/sys/bus/cxl/devices/$R0/dax_region0/dax_region
while [ ! -d $DR ]; do sleep 0.1; done
printf "region %s created in %.2f s\n" $R0 $(echo "$EPOCHREALTIME - $t0" | bc)
echo "dax_region attrs: $(ls $DR | tr '\n' ' ')"
echo "id=$(cat $DR/id) region_size=$(cat $DR/region_size) align=$(cat $DR/align) available_size=$(cat $DR/available_size) seed=$(cat $DR/seed) create=$(cat $DR/create)"
daxinfo() { for d in /sys/bus/dax/devices/dax*; do echo "  $(basename $d): size=$(cat $d/size) target_node=$(cat $d/target_node) resource=$(cat $d/resource 2>/dev/null) driver=$(readlink $d/driver 2>/dev/null | xargs -r basename) dev=$(cat $d/dev 2>/dev/null)"; done; }
sleep 1; daxinfo
D0=$(ls /sys/bus/cxl/devices/$R0/dax_region0 | grep '^dax' | head -1)
drv=$(readlink /sys/bus/dax/devices/$D0/driver | xargs -r basename)
[ -n "$drv" ] && echo $D0 > /sys/bus/dax/drivers/$drv/unbind && echo "unbound $D0 from $drv"
echo "== shrink $D0 to 64M devdax (first slice)"
echo $((64<<20)) > /sys/bus/dax/devices/$D0/size && echo "size ok, available_size=$(cat $DR/available_size)"
bindto() { echo $1 > /sys/bus/dax/drivers/$2/new_id 2>/dev/null; [ "$(readlink /sys/bus/dax/devices/$1/driver 2>/dev/null | xargs -r basename)" = "$2" ] || echo $1 > /sys/bus/dax/drivers/$2/bind 2>&1; echo $1 > /sys/bus/dax/drivers/$2/remove_id 2>/dev/null; echo "$1 -> $(readlink /sys/bus/dax/devices/$1/driver | xargs -r basename)"; }
bindto $D0 device_dax
mk() { echo 1 > $DR/create || return 1; local n; n=$(cat $DR/create); echo $1 > /sys/bus/dax/devices/$n/size || echo "size $1 failed for $n"; echo "$n"; }
echo "== slice 2: 128M kmem at offset 64M (misaligned to $BS blocks)"
S2=$(mk $((128<<20))); bindto $S2 kmem; sleep 1
echo "== slice 3: 64M devdax"
S3=$(mk $((64<<20))); bindto $S3 device_dax
echo "available_size=$(cat $DR/available_size)"; daxinfo; ls -l /dev/dax*
echo "== kmem slice $S2 memory blocks"
RES=$(( $(cat /sys/bus/dax/devices/$S2/resource) )); SZ=$(( $(cat /sys/bus/dax/devices/$S2/size) ))
echo "$S2 resource=0x$(printf %x $RES) size=$SZ; blocks spanned $((RES/BS))..$(((RES+SZ-1)/BS))"
for b in $(seq $((RES/BS)) $(((RES+SZ-1)/BS))); do f=/sys/devices/system/memory/memory$b/state; if [ -f $f ]; then echo "memory$b: $(cat $f), valid_zones=$(cat /sys/devices/system/memory/memory$b/valid_zones)"; echo online_movable > $f 2>&1 && echo "  -> $(cat $f) node=$(ls -d /sys/devices/system/memory/memory$b/node* | xargs -n1 basename)"; else echo "memory$b: no block (dropped by kmem alignment)"; fi; done
grep -H MemTotal /sys/devices/system/node/node*/meminfo | sed 's/  */ /g'
echo "== isolation: write $D0, read $D0 and $S3"
python3 - "$D0" "$S3" <<'PY'
import mmap, os, sys
def rw(path, data=None):
    fd = os.open(path, os.O_RDWR); m = mmap.mmap(fd, 2<<20, mmap.MAP_SHARED, mmap.PROT_READ|mmap.PROT_WRITE)
    if data: m[0:len(data)] = data
    v = bytes(m[0:8]); m.close(); os.close(fd); return v
a, b = "/dev/"+sys.argv[1], "/dev/"+sys.argv[2]
print(a, "write:", rw(a, b"SLICE-A!"), "read:", rw(a)); print(b, "read:", rw(b))
PY
echo "== teardown"
t1=$EPOCHREALTIME
for b in $(seq $((RES/BS)) $(((RES+SZ-1)/BS))); do f=/sys/devices/system/memory/memory$b/state; [ -f $f ] && echo offline > $f; done
echo $S2 > /sys/bus/dax/drivers/kmem/unbind; echo $D0 > /sys/bus/dax/drivers/device_dax/unbind; echo $S3 > /sys/bus/dax/drivers/device_dax/unbind
for s in $S2 $S3; do echo 0 > /sys/bus/dax/devices/$s/size; echo $s > $DR/delete && echo "deleted $s"; done
echo 0 > /sys/bus/dax/devices/$D0/size; echo "available_size=$(cat $DR/available_size) (dax0.0 kept with size 0, seed=$(cat $DR/seed))"
cxl disable-region $R0 >/dev/null 2>&1; cxl destroy-region $R0 >/dev/null 2>&1 && printf "destroyed %s, teardown %.2f s\n" $R0 $(echo "$EPOCHREALTIME - $t1" | bc)
ls /sys/bus/cxl/devices/ | grep -c region; ls /sys/bus/dax/devices/ | wc -l
echo "== dmesg since marker"; dmesg | sed -n '/EXP2 start/,$p' | grep -iv "audit" | head -40
