#!/bin/bash
set -u
BS=$(( 0x$(cat /sys/devices/system/memory/block_size_bytes) ))
bysn() { for m in /sys/bus/cxl/devices/mem*; do [ "$(cat $m/serial 2>/dev/null)" = "$1" ] && basename $m; done; }
for i in $(seq 1 50); do M=$(bysn 0xc100e2e1); [ -n "$M" ] && [ -e /sys/bus/cxl/devices/$M/driver ] && break; sleep 0.2; done
cxl create-region -t ram -d decoder0.0 -m $M >/dev/null 2>&1 || cxl enable-memdev $M >/dev/null 2>&1 && cxl create-region -t ram -d decoder0.0 -m $M >/dev/null 2>&1
R=$(ls -d /sys/bus/cxl/devices/region* | head -1 | xargs basename); DR=/sys/bus/cxl/devices/$R/dax_region0/dax_region
for i in $(seq 1 50); do [ -d $DR ] && break; sleep 0.1; done
START=$(( $(cat /sys/bus/cxl/devices/$R/resource) ))
echo "region $R start=$(printf 0x%x $START) dax_region driver: $(readlink /sys/bus/cxl/devices/$R/dax_region0/driver | xargs basename)"
sleep 1
D0=dax$(cat $DR/id).0; drv=$(readlink /sys/bus/dax/devices/$D0/driver | xargs -r basename); [ -n "$drv" ] && echo $D0 > /sys/bus/dax/drivers/$drv/unbind
echo $((64<<20)) > /sys/bus/dax/devices/$D0/size
echo 1 > $DR/create; K=$(cat $DR/create); echo "created $K"
python3 - "$K" $((START + BS)) $((START + 2*BS - 1)) <<'PY'
import os, sys, errno
k, s, e = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
p = f"/sys/bus/dax/devices/{k}/mapping"
for text in (f"0x{s:x}-0x{e:x}", f"{s:x}-{e:x}", f"{s:x}-{e:x}\n"):
    try:
        fd = os.open(p, os.O_WRONLY); n = os.write(fd, text.encode()); os.close(fd)
        print(f"write {text!r}: returned {n}")
    except OSError as ex:
        print(f"write {text!r}: {errno.errorcode.get(ex.errno, ex.errno)} {ex.strerror}")
    print("  size now", open(f"/sys/bus/dax/devices/{k}/size").read().strip(), "mappings", [d for d in os.listdir(f"/sys/bus/dax/devices/{k}") if d.startswith("mapping")])
PY
sz=$(cat /sys/bus/dax/devices/$K/size); echo "$K size=$sz"
if [ "$sz" -gt 0 ]; then
  echo $K > /sys/bus/dax/drivers/kmem/bind 2>&1 || echo $K > /sys/bus/dax/drivers/kmem/new_id; sleep 1
  echo "$K driver=$(readlink /sys/bus/dax/devices/$K/driver | xargs -r basename) mapping0=$(cat /sys/bus/dax/devices/$K/mapping0/start)-$(cat /sys/bus/dax/devices/$K/mapping0/end)"
  B=$(( (START + BS) / BS )); f=/sys/devices/system/memory/memory$B/state; [ -f $f ] && { echo online_movable > $f; echo "memory$B: $(cat $f) node=$(ls -d /sys/devices/system/memory/memory$B/node* | xargs -n1 basename)"; }
  grep -H MemTotal /sys/devices/system/node/node2/meminfo
  echo 1 > $DR/create; D2=$(cat $DR/create); echo $((32<<20)) > /sys/bus/dax/devices/$D2/size; echo $D2 > /sys/bus/dax/drivers/device_dax/bind 2>/dev/null || echo $D2 > /sys/bus/dax/drivers/device_dax/new_id; echo "$D2 driver=$(readlink /sys/bus/dax/devices/$D2/driver | xargs -r basename) at $(printf 0x%x $(( $(cat /sys/bus/dax/devices/$D2/resource) ))) size=$(cat /sys/bus/dax/devices/$D2/size) (expected gap at $(printf 0x%x $((START + (64<<20)))))"
  [ -f $f ] && echo offline > $f; echo $K > /sys/bus/dax/drivers/kmem/unbind; echo 0 > /sys/bus/dax/devices/$K/size; echo $K > $DR/delete
  echo $D2 > /sys/bus/dax/drivers/device_dax/unbind; echo 0 > /sys/bus/dax/devices/$D2/size; echo $D2 > $DR/delete
fi
echo 0 > /sys/bus/dax/devices/$D0/size
cxl disable-region $R >/dev/null 2>&1; cxl destroy-region $R >/dev/null 2>&1 && echo "destroyed $R"
dmesg | tail -5 | grep -i "dax\|kmem" || true
