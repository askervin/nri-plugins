#!/bin/bash
# Usage: launch-vm.sh NAME SSH_PORT [EXTRA_QEMU_ARGS...]
#
# Launch a direct (non-vagrant) qemu VM from an overlay of base.qcow2 with one
# CXL host bridge -> root port -> switch -> 2 empty downstream ports
# (cxlsw_ds0_usrp0hb0, cxlsw_ds1_usrp0hb0), plus a second host bridge with a
# root port and no switch (cxlrp0hb1) for direct root port hotplug.
#
# Environment:
#   WORK   work directory (default: directory of this script)
#   BASE   flattened guest disk (default: $WORK/base.qcow2)
#   QEMU   qemu binary (default: ~/github.com/qemu/qemu/build/qemu-system-x86_64)
#   MEMOPT -m option value (default: 4G)
#   FMW    cxl-fmw size per host bridge (default: 4G)
#   FRESH  if 1, recreate the overlay from BASE
#   KERNEL boot this bzImage with -kernel (default: the guest disk's grub)
#   INITRD initrd for KERNEL (default: $WORK/kernel/initramfs-7.3.0-rc4.img)
#   APPEND kernel command line for KERNEL
#   HBOPT  extra pxb-cxl options, e.g. ",hdm_for_passthrough=on"
#
# Creates $WORK/NAME.{qcow2,qmp,hmp,serial,pid,log}.
set -e
name="$1"; port="$2"; shift 2 || { echo "usage: $0 NAME SSH_PORT [QEMU_ARGS...]" >&2; exit 1; }
WORK="${WORK:-$(cd "$(dirname "$0")" && pwd)}"
BASE="${BASE:-$WORK/base.qcow2}"
QEMU="${QEMU:-$HOME/github.com/qemu/qemu/build/qemu-system-x86_64}"
MEMOPT="${MEMOPT:-4G}"
FMW="${FMW:-4G}"
HBOPT="${HBOPT:-}"
KERNELARGS=()
if [ -n "$KERNEL" ]; then
    INITRD="${INITRD:-$WORK/kernel/initramfs-7.3.0-rc4.img}"
    APPEND="${APPEND:-BOOT_IMAGE=/vmlinuz-7.3.0-rc4 root=UUID=445076f3-fb18-49c5-8cf4-d31b2905a99f ro rootflags=subvol=root no_timer_check console=tty1 console=ttyS0,115200n8}"
    KERNELARGS=(-kernel "$KERNEL" -initrd "$INITRD" -append "$APPEND")
fi

if [ "$FRESH" = 1 ] || [ ! -f "$WORK/$name.qcow2" ]; then
    rm -f "$WORK/$name.qcow2"
    qemu-img create -q -f qcow2 -b "$BASE" -F qcow2 "$WORK/$name.qcow2"
fi
rm -f "$WORK/$name.qmp" "$WORK/$name.hmp" "$WORK/$name.serial"

set -x
"$QEMU" \
    -name "$name" \
    -machine q35,kernel-irqchip=split,cxl=on,accel=kvm \
    -cpu host -smp 4 -m "$MEMOPT" \
    -object memory-backend-ram,id=m0,size=4G \
    -numa node,nodeid=0,memdev=m0,cpus=0-3 \
    -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxlhb0,numa_node=0$HBOPT \
    -device cxl-rp,port=0,bus=cxlhb0,id=cxlrp0hb0,chassis=193,slot=0 \
    -device cxl-upstream,bus=cxlrp0hb0,id=cxlsw_usrp0hb0 \
    -device cxl-downstream,port=1,bus=cxlsw_usrp0hb0,id=cxlsw_ds0_usrp0hb0,chassis=193,slot=1 \
    -device cxl-downstream,port=2,bus=cxlsw_usrp0hb0,id=cxlsw_ds1_usrp0hb0,chassis=193,slot=2 \
    -device pxb-cxl,bus_nr=24,bus=pcie.0,id=cxlhb1,numa_node=0$HBOPT \
    -device cxl-rp,port=0,bus=cxlhb1,id=cxlrp0hb1,chassis=194,slot=0 \
    -M cxl-fmw.0.targets.0=cxlhb0,cxl-fmw.0.size=$FMW,cxl-fmw.1.targets.0=cxlhb1,cxl-fmw.1.size=$FMW \
    -drive if=none,id=disk0,format=qcow2,file="$WORK/$name.qcow2" \
    -device pcie-root-port,id=rp_disk,bus=pcie.0,port=0x9,chassis=5 \
    -device virtio-blk-pci,drive=disk0,bus=rp_disk \
    -device virtio-net-pci,netdev=net0,bus=pcie.0 \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22,net=192.168.76.0/24,dhcpstart=192.168.76.9 \
    -qmp unix:"$WORK/$name.qmp",server,nowait \
    -monitor unix:"$WORK/$name.hmp",server,nowait \
    -display none -vga none \
    -serial file:"$WORK/$name.serial" \
    -D "$WORK/$name.log" \
    -daemonize -pidfile "$WORK/$name.pid" \
    "${KERNELARGS[@]}" \
    "$@"
