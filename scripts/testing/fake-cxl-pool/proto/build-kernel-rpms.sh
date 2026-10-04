#!/bin/bash
# Usage: build-kernel-rpms.sh
#
# Build Fedora RPMs of the e2e CXL guest kernel on the host, in a Fedora
# container, and put them in the e2e kernel cache. VMs that are provisioned
# with kernel_config=qemu-cxl-kernel.config then install these RPMs instead
# of cloning and building the kernel inside the VM.
#
# 1. Enable $ENABLE options in a copy of the e2e kernel config and run
#    "make olddefconfig" on it with the compiler of the container.
# 2. Build the RPMs like test/e2e/playbook/custom-kernel-fedora.yaml does
#    ("make binrpm-pkg"), with the same build dependencies, plus the ones
#    a container lacks compared to a Fedora cloud VM.
# 3. Write the effective .config back to the e2e kernel config file, so that
#    the file equals the config of the kernel in the RPMs.
# 4. Store the RPMs as the cached kernel tarball of that config. The name of
#    the tarball must be what test/e2e/playbook/custom-kernel.yaml looks for:
#      kernel.getsource_<kernel_getsource>.config_<sha256>.rpms.tar
#    where sha256 is of the config file content as Ansible lookup('file')
#    returns it, that is, without trailing newlines. This is NOT what
#    "sha256sum FILE" prints.
#
# Environment:
#   LINUX_SRC  kernel source tree, mounted read-only. It must be the tree
#              that kernel_getsource gives, here vanilla 7.3.0-rc4. The
#              default is the copy of the guests' ~/linux of WS3.
#   WORK       build output directory (make O=...).
#   ENABLE     config options to enable.
#   CACHE_DIR  e2e cache directory, see test/e2e/lib/vm.bash.
#   IMAGE      container image.
set -e -o pipefail

REPO="$(cd "$(dirname "$0")/../../../.." && pwd)"
CONFIG="$REPO/test/e2e/playbook/files/qemu-cxl-kernel.config"
KERNEL_GETSOURCE=vanilla
LINUX_SRC="${LINUX_SRC:-/home/akervine/.claude/jobs/5b6674cf/tmp/ws3/linux-src}"
WORK="${WORK:-/home/akervine/.claude/jobs/5b6674cf/tmp/ws4/kernel}"
ENABLE="${ENABLE:-FS_DAX FS_DAX_PMD DMI DMIID INPUT INPUT_EVDEV ACPI_BUTTON}"
CACHE_DIR="${CACHE_DIR:-$HOME/.cache/nri-plugins/e2e}"
IMAGE="${IMAGE:-registry.fedoraproject.org/fedora:43}"

# Build dependencies of custom-kernel-fedora.yaml, then rpm-build and the
# tools that a Fedora cloud VM has but a container does not.
DEPS="fedpkg fedora-packager rpmdevtools ncurses-devel pesign grubby make gcc
      flex bison elfutils-devel elfutils-libelf-devel dwarves openssl
      openssl-devel perl
      rpm-build bc diffutils findutils hostname kmod cpio rsync python3 tar xz"

[ -f "$LINUX_SRC/Makefile" ] || { echo "no kernel source tree in $LINUX_SRC" >&2; exit 1; }
rm -rf "$WORK/build"
mkdir -p "$WORK/build"
cp "$CONFIG" "$WORK/build/.config"

podman run --rm --security-opt label=disable \
       -v "$LINUX_SRC:/src:ro" -v "$WORK/build:/build" \
       -e DEPS="$DEPS" -e ENABLE="$ENABLE" \
       "$IMAGE" bash -c '
set -e -o pipefail
dnf install -y $DEPS > /build/dnf.log 2>&1 || { tail -20 /build/dnf.log; exit 1; }
for opt in $ENABLE; do
    /src/scripts/config --file /build/.config --enable "$opt"
done
make -C /src O=/build olddefconfig
for opt in $ENABLE; do
    grep -q "^CONFIG_$opt=y$" /build/.config || { echo "CONFIG_$opt=y did not stick" >&2; exit 1; }
done
cp /build/.config /build/config.olddefconfig
cd /build
make -C /src O=/build -j$(nproc) binrpm-pkg > /build/build.log 2>&1 || { tail -40 /build/build.log; exit 1; }
cmp /build/.config /build/config.olddefconfig
cd /build/rpmbuild/RPMS/x86_64
tar cf /build/kernel-pkgs.tar kernel-*.rpm
tar tvf /build/kernel-pkgs.tar
'

cp "$WORK/build/.config" "$CONFIG"
sha=$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1]).read().rstrip().encode()).hexdigest())' "$CONFIG")
tarball="$CACHE_DIR/kernel.getsource_${KERNEL_GETSOURCE}.config_${sha}.rpms.tar"
cp "$WORK/build/kernel-pkgs.tar" "$tarball"
echo "config:  $CONFIG"
echo "tarball: $tarball"
