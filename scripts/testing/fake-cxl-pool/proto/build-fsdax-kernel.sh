#!/bin/bash
# Usage: build-fsdax-kernel.sh [GUEST_SSH_PORT]
#
# Build the n4-cxl guest kernel (7.3.0-rc4, the tree the e2e playbook left in
# the guest's ~/linux) on the host with CONFIG_FS_DAX=y, which devdax mmap
# needs (without it: "dax_mmap_prepare: fail, vma is not DAX capable").
# Result: $WORK/kernel/bzImage-7.3.0-rc4-fsdax and the guest's initramfs,
# for launch-vm.sh KERNEL=... (qemu -kernel/-initrd/-append). ~1 min.
set -e
port="${1:-52201}"
WORK="${WORK:-$(cd "$(dirname "$0")" && pwd)}"
cd "$WORK"
mkdir -p linux-src kernel/build
[ -f linux-src/Makefile ] || ./vm-ssh.sh "$port" 'cd ~/linux && git archive --format=tar HEAD' | tar -x -C linux-src
./vm-ssh.sh "$port" 'cat /boot/config-$(uname -r)' > kernel/guest.config
./vm-ssh.sh "$port" 'sudo cat /boot/initramfs-$(uname -r).img' > kernel/initramfs-7.3.0-rc4.img
cp kernel/guest.config kernel/build/.config
linux-src/scripts/config --file kernel/build/.config --enable FS_DAX
make -C linux-src O="$WORK/kernel/build" olddefconfig
make -C linux-src O="$WORK/kernel/build" -j"$(nproc)" bzImage
cp kernel/build/arch/x86/boot/bzImage kernel/bzImage-7.3.0-rc4-fsdax
diff <(grep -v '^#' kernel/guest.config | sort) <(grep -v '^#' kernel/build/.config | sort) | grep '^[<>]' || true
