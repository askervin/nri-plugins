# Bring up a VM for testing CXL memory that is shared by VMs or pooled with
# fake-cxl-pool (scripts/testing/fake-cxl-pool), and check that it is ready:
# - The CXL kernel and the cxl, daxctl and cxl-dump tools are installed.
#   The kernel has CONFIG_FS_DAX (devdax mmap, the way to share CXL memory)
#   and DMI (the VM sees its UUID in /sys/class/dmi/id/product_uuid).
# - Qemu answers on QMP, and host bridges have HDM decoders
#   (hdm_for_passthrough=on) for more than one region per host bridge.
# - Qemu has the statically shared, file-backed CXL memory device of the
#   topology (cxl_memdev0, serial 0xc1f0ee00) and the local one (cxl_memdev1),
#   both unplugged, and the empty pool slots for hotplugging pool devices.
# - The VM sees no CXL memory devices.
#
# The topologies n4-cxl-shared-1 and n4-cxl-shared-2 are identical, so their
# VMs can share the same CXL memory devices. Hot-removing and hotplugging a
# device again needs a patched qemu. Give it when creating the VM, see
# qemu_bin in .github/skills/run-e2e-tests/SKILL.md, for instance:
#   qemu_bin=$HOME/github.com/qemu/qemu/build/qemu-system-x86_64 \
#     ./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-1/test00-up

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

vm-kernel-pkgs-install
cxl-tools-install
vm-command-q "command -v daxctl >/dev/null" ||
    vm-command "dnf install -y daxctl" ||
        command-error "cannot install daxctl in the VM"

echo "### kernel of the VM"
# The kernel comes from the cached kernel tarball of the kernel config, if
# there is one. Point at it if the kernel is not the expected one.
kernel_tarball=$(python3 -c '
import hashlib, re, sys
getsource, config_file, cache_dir = sys.argv[1:4]
# The name that test/e2e/playbook/custom-kernel.yaml gives the tarball.
sha = hashlib.sha256(open(config_file).read().rstrip().encode()).hexdigest()
print("%s/kernel.getsource_%s.config_%s.rpms.tar" % (cache_dir, re.sub("[^a-zA-Z0-9-]+", "_", getsource), sha))
' "$kernel_getsource" "$nri_resource_policy_src/test/e2e/playbook/files/$kernel_config" "$CACHE_DIR")
kernel_error="the VM does not run the kernel of $kernel_tarball. Build it with scripts/testing/fake-cxl-pool/proto/build-kernel-rpms.sh. If the VM had installed older RPMs of the same name, recreate the VM, or remove ~vagrant/.vm-kernel-pkgs.installed_packages in it and run this test again"
vm-command "uname -r; grep -E '^CONFIG_(FS_DAX|DMIID|INPUT_EVDEV)=' /boot/config-\$(uname -r)"
vm-command-q 'grep -q ^CONFIG_FS_DAX=y /boot/config-$(uname -r)' ||
    error "kernel lacks CONFIG_FS_DAX=y: $kernel_error"
vm_uuid=$(sed -n 's/^VM_UUID=//p' "$OUTPUT_DIR/env")
product_uuid=$(vm-command-q "cat /sys/class/dmi/id/product_uuid")
echo "VM_UUID: $vm_uuid, product_uuid in the VM: $product_uuid"
[ -n "$vm_uuid" ] || error "no VM_UUID in $OUTPUT_DIR/env, VM created without -uuid?"
[ "${product_uuid,,}" == "${vm_uuid,,}" ] ||
    error "product_uuid '$product_uuid' of the VM differs from VM_UUID '$vm_uuid' (kernel without CONFIG_DMIID?): $kernel_error"

echo "### qemu of the VM"
qemu_pid=$(vm-qemu-pid)
[[ "$qemu_pid" =~ ^[0-9]+$ ]] || error "expected one qemu process of $OUTPUT_DIR, found: '$qemu_pid'"
tr '\0' ' ' < /proc/$qemu_pid/cmdline > "$TEST_OUTPUT_DIR/qemu-cmdline.txt"
echo "qemu pid:     $qemu_pid"
echo "qemu binary:  $(readlink /proc/$qemu_pid/exe)"
echo "qemu cmdline: $TEST_OUTPUT_DIR/qemu-cmdline.txt"
[ "$(grep -o 'pxb-cxl,[^ ]*,hdm_for_passthrough=on' "$TEST_OUTPUT_DIR/qemu-cmdline.txt" | wc -l)" = "2" ] ||
    error "expected two pxb-cxl host bridges with hdm_for_passthrough=on, VM created before it was in the topology?"
qmp_version=$(vm-qmp query-version) || error "QMP query-version failed: $qmp_version"
echo "qemu version: $qmp_version"
python3 -c 'import json, sys; v = json.loads(sys.argv[1])["return"]; print("%(major)d.%(minor)d.%(micro)d" % v["qemu"], v["package"])' "$qmp_version" ||
    error "unexpected QMP query-version response: $qmp_version"

echo "### qemu CXL memory devices and slots"
cxl_hw=$(show_sn=1 show_be=1 vm-cxl-hw)
echo "$cxl_hw"
grep -q "^cxl_memdev0 sn=0xc1f0ee00 volatile-memdev=befile_cxl_memdev0__" <<< "$cxl_hw" ||
    error "statically shared, file-backed CXL memory device cxl_memdev0 sn=0xc1f0ee00 not found"
grep -q "^cxl_memdev1 sn=0xc100e2e1 volatile-memdev=beram_cxl_memdev1__" <<< "$cxl_hw" ||
    error "local CXL memory device cxl_memdev1 not found"
if grep -q plugged <<< "$cxl_hw"; then
    error "expected no CXL memory devices plugged in at boot"
fi
# The files of file-backed memory are created by qemu.
for mem_path in $(grep -o 'mem-path=[^, ]*' "$TEST_OUTPUT_DIR/qemu-cmdline.txt" | sed 's/^mem-path=//'); do
    ls -l "$mem_path" || error "qemu memory backend file $mem_path is missing"
done
# Every switch port, 4 + 4, is free: neither pool slots nor declared but not
# present devices have a cxl-type3 device at boot.
qtree=$(vm-monitor "info qtree -b")
[ "$(grep -c 'dev: cxl-downstream' <<< "$qtree")" = "8" ] ||
    error "expected 8 cxl-downstream ports in qemu"
if grep -q 'dev: cxl-type3' <<< "$qtree"; then
    error "expected no cxl-type3 devices in qemu"
fi

echo "### CXL memory devices in the VM"
cxl-dump no-devices
cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
cxl-assert 'len(nodes) == 2'
