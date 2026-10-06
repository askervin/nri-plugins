# Test CXL memory shared by two VMs through fake-cxl-pool
# (scripts/testing/fake-cxl-pool, spec in plan/60-e2e-test.md there).
#
# fake-cxl-pool-server runs on the host. fake-cxl-pool-client runs in this
# VM, VM2 (n4-cxl-shared-2), and attaches one shared pool device, shared0,
# to both VM2 and VM1 (n4-cxl-shared-1), which this test drives over ssh
# from the host. Then:
# - An exclusive device cannot be attached to a second VM.
# - Both VMs map shared0 as a devdax device. What one VM writes, the other
#   reads, and the host finds in the backing file of the device.
# - Both VMs release shared0, and it is detached from both. Released
#   devices are hot-removed for real: hotplugging shared0 to the same slot
#   again works. That needs the patched qemu, see test00-up.
#
# Not tested: detaching a device that the VM has not released. Qemu never
# completes that, the server reports the attachment failed, and the device
# stays in qemu until the VM restarts (see plan/60-e2e-test.md).
#
# Create both VMs first with test00-up of n4-cxl-shared-1 and -2. This test
# starts VM1 if it is not running.

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

VM1="$POOL_VM1_DIR"    # the other VM, driven over ssh from the host
VM2="$OUTPUT_DIR"      # the VM of this test
VM1_NAME="$POOL_VM1_NAME"
VM2_NAME="$POOL_VM2_NAME"
SHARED_SERIAL=0xc1f0ee01  # not 0xc1f0ee00, the static device of the topology
MEM_SIZE=$(( 256 << 20 ))
MiB=$(( 1 << 20 ))

detach-timed() {
    # Usage: detach-timed DEVICE --self|--host HOST
    #
    # Detach DEVICE with the client in VM2 and check that it got detached.
    local start end
    start=$(date +%s.%N)
    pool-client "$VM2" -o json detach "$@" || command-error "cannot detach $*"
    end=$(date +%s.%N)
    pool-assert "$COMMAND_OUTPUT" 'j["state"] == "detached"'
    echo "detach $* took $(printf %.2f "$(echo "$end - $start" | bc)") s"
}

echo "### preconditions: VM1 is up"
pool-host-wait "$VM1" "create VM1 first: ./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-1/test00-up"

echo "### preconditions: patched qemu, hdm_for_passthrough=on, kernel with CONFIG_FS_DAX"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"
pool-vm-require "$VM1" n4-cxl-shared-1

echo "### preconditions: cxl, daxctl and cxl-dump in both VMs"
pool-vm-tools-install "$VM2"
pool-vm-tools-install "$VM1"

echo "### preconditions: no CXL memory devices in either VM"
pool-vm-reset "$VM2"
pool-vm-reset "$VM1"
for vm in "$VM2" "$VM1"; do
    pool-cxl-dump "$vm" no-devices
    cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
done

echo "### preconditions: fake-cxl-pool-server on the host, with the shared device shared0"
pool-server-start "
  - name: shared0
    size: 256M
    shared: true
    pool: default
    serial: $SHARED_SERIAL"
pool-host-client hosts || command-error "cannot list the hosts of the server"
HOSTS_JSON=$(curl -sS --max-time 30 "$POOL_URL/api/v1/hosts") ||
    error "cannot get the hosts of the server"
pool-assert "$HOSTS_JSON" "sorted(h['name'] for h in j) == sorted(['$VM1_NAME', '$VM2_NAME'])"
pool-assert "$HOSTS_JSON" 'all(h["state"] == "running" and h["control"] == "qmp" and not h.get("error") for h in j)'
pool-assert "$HOSTS_JSON" 'all(h["hotRemoveCapable"] for h in j)'
pool-assert "$HOSTS_JSON" 'all(len(h["hostBridges"]) == 2 for h in j)'
pool-assert "$HOSTS_JSON" 'all(h["attachments"] in (None, []) for h in j)'
pool-snapshot start

echo "### preconditions: fake-cxl-pool-client in both VMs, both resolve themselves"
pool-client-install "$VM2" "$VM1"
pool-client "$VM2" -o json whoami || command-error "VM2 cannot resolve itself"
pool-assert "$COMMAND_OUTPUT" "j['name'] == '$VM2_NAME'"
pool-client "$VM1" -o json whoami || command-error "VM1 cannot resolve itself"
pool-assert "$COMMAND_OUTPUT" "j['name'] == '$VM1_NAME'"

echo "### A: shared0 is a free, shared 256M device"
pool-client "$VM2" devices || command-error "cannot list devices"
pool-client "$VM2" -o json devices shared0 || command-error "cannot get device shared0"
pool-assert "$COMMAND_OUTPUT" "j['shared'] and j['state'] == 'free' and j['attachments'] in (None, [])"
pool-assert "$COMMAND_OUTPUT" "j['serial'] == '$SHARED_SERIAL' and j['size'] == $MEM_SIZE"
pool-assert "$COMMAND_OUTPUT" "j['backend'] == 'file' and j['path'] == '$POOL_DIR/shared0.raw'"
SHARED_FILE=$(pool-value "$COMMAND_OUTPUT" 'j["path"]')
ls -l "$SHARED_FILE" || error "backing file $SHARED_FILE of shared0 is missing"

echo "### B: attach shared0 to VM2, it shows up with its serial"
pool-client "$VM2" -o json attach shared0 --self || command-error "cannot attach shared0 to VM2"
pool-assert "$COMMAND_OUTPUT" "j['state'] == 'attached' and j['host'] == '$VM2_NAME' and j['serial'] == '$SHARED_SERIAL'"
SHARED_SLOT=$(pool-value "$COMMAND_OUTPUT" 'j["slot"]["bus"]')
SHARED_QEMU_ID=$(pool-value "$COMMAND_OUTPUT" 'j["qemuDeviceId"]')
echo "shared0 in VM2: slot $SHARED_SLOT, qemu device $SHARED_QEMU_ID"
pool-client "$VM2" guest wait shared0 || command-error "shared0 did not show up in VM2"
VM2_MEM="$COMMAND_OUTPUT"
pool-cxl-wait "$VM2" shared0-attached "by_serial($SHARED_SERIAL) is not None"
cxl-assert "by_serial($SHARED_SERIAL)['Name'] == '$VM2_MEM'"
cxl-assert "by_serial($SHARED_SERIAL)['RamSize'] == $MEM_SIZE"
cxl-assert 'len(memdevs) == 1 and regions == []'
vm-command "cxl list -M -u" || command-error "cxl list failed in VM2"
grep -q "\"serial\":\"$SHARED_SERIAL\"" <<< "${COMMAND_OUTPUT//[[:space:]]/}" ||
    error "cxl list does not show serial $SHARED_SERIAL in VM2"

echo "### C: attach shared0 to VM1 too, the same serial shows up there"
pool-client "$VM2" -o json attach shared0 --host "$VM1_NAME" || command-error "cannot attach shared0 to VM1"
pool-assert "$COMMAND_OUTPUT" "j['state'] == 'attached' and j['host'] == '$VM1_NAME' and j['serial'] == '$SHARED_SERIAL'"
pool-client "$VM1" guest wait shared0 || command-error "shared0 did not show up in VM1"
VM1_MEM="$COMMAND_OUTPUT"
pool-cxl-wait "$VM1" shared0-attached "by_serial($SHARED_SERIAL) is not None"
cxl-assert "by_serial($SHARED_SERIAL)['Name'] == '$VM1_MEM'"
cxl-assert "by_serial($SHARED_SERIAL)['RamSize'] == $MEM_SIZE"
cxl-assert 'len(memdevs) == 1 and regions == []'
pool-client "$VM2" -o json devices shared0 || command-error "cannot get device shared0"
pool-assert "$COMMAND_OUTPUT" "j['state'] == 'attached'"
pool-assert "$COMMAND_OUTPUT" "sorted((a['host'], a['state']) for a in j['attachments']) == sorted([('$VM1_NAME', 'attached'), ('$VM2_NAME', 'attached')])"
pool-client "$VM2" attachments || command-error "cannot list attachments"
pool-snapshot shared0-attached

echo "### D: an exclusive device cannot be attached to two VMs"
# Device sizes are multiples of 256M, the capacity unit of CXL.
pool-client "$VM2" create --size 128M --name excl0 &&
    error "creating a device of 128M should have failed"
[ "$COMMAND_STATUS" == "1" ] && [[ "$COMMAND_OUTPUT" == *InvalidArgument* ]] ||
    command-error "expected exit status 1 and InvalidArgument for a 128M device"
pool-client "$VM2" -o json create --size 256M --name excl0 || command-error "cannot create excl0"
pool-assert "$COMMAND_OUTPUT" "not j['shared'] and j['state'] == 'free' and j['size'] == $MEM_SIZE"
EXCL_SERIAL=$(pool-value "$COMMAND_OUTPUT" 'j["serial"]')
EXCL_FILE=$(pool-value "$COMMAND_OUTPUT" 'j["path"]')
[ -f "$EXCL_FILE" ] || error "backing file $EXCL_FILE of excl0 is missing"
pool-client "$VM2" -o json attach excl0 --self || command-error "cannot attach excl0 to VM2"
pool-assert "$COMMAND_OUTPUT" "j['state'] == 'attached' and j['host'] == '$VM2_NAME'"
pool-client "$VM2" -o json attach excl0 --host "$VM1_NAME" &&
    error "exclusive device excl0 got attached to a second VM"
[ "$COMMAND_STATUS" == "3" ] && [[ "$COMMAND_OUTPUT" == *Conflict* ]] ||
    command-error "expected exit status 3 and Conflict when attaching excl0 to a second VM"
pool-client "$VM2" -o json devices excl0 || command-error "cannot get device excl0"
pool-assert "$COMMAND_OUTPUT" "[a['host'] for a in j['attachments']] == ['$VM2_NAME']"
pool-client "$VM2" guest wait excl0 || command-error "excl0 did not show up in VM2"
pool-client "$VM2" guest release excl0 || command-error "cannot release excl0 in VM2"
detach-timed excl0 --self
pool-cxl-wait "$VM2" excl0-detached "by_serial($EXCL_SERIAL) is None"
pool-client "$VM2" delete excl0 || command-error "cannot delete excl0"
[ ! -e "$EXCL_FILE" ] || error "deleting excl0 left its backing file $EXCL_FILE"
# VM1 never saw excl0.
pool-cxl-dump "$VM1" excl0-deleted
cxl-assert "by_serial($EXCL_SERIAL) is None and len(memdevs) == 1"

echo "### E: shared0 as a devdax device in both VMs"
for vm in "$VM2" "$VM1"; do
    pool-client "$vm" -o json guest region create shared0 --mode devdax ||
        command-error "cannot create a devdax region of shared0 in $(pool-vm-label "$vm")"
    pool-assert "$COMMAND_OUTPUT" 'j["mode"] == "devdax" and j["driver"] == "device_dax" and j["device"].startswith("/dev/dax")'
    dax=$(pool-value "$COMMAND_OUTPUT" 'j["device"]')
    pool-vm-command "$vm" "ls -l $dax && daxctl list -d ${dax#/dev/}" ||
        command-error "devdax device $dax is missing in $(pool-vm-label "$vm")"
    pool-vm-command "$vm" "cat /sys/bus/dax/devices/${dax#/dev/}/size" ||
        command-error "cannot read the size of $dax in $(pool-vm-label "$vm")"
    [ "$COMMAND_OUTPUT" == "$MEM_SIZE" ] ||
        error "devdax device $dax has $COMMAND_OUTPUT bytes, expected $MEM_SIZE"
    pool-cxl-dump "$vm" devdax
    cxl-assert 'len(regions) == 1 and regions[0]["Enabled"]'
    cxl-assert "regions[0]['Size'] == $MEM_SIZE"
    cxl-assert "names(regions[0]['Memories']) == [by_serial($SHARED_SERIAL)['Name']]"
    # Shared memory must never be system RAM.
    cxl-assert 'regions[0]["OnlineSize"] == 0'
    if [ "$vm" == "$VM2" ]; then VM2_DAX="$dax"; else VM1_DAX="$dax"; fi
done
echo "devdax devices: VM2 $VM2_DAX, VM1 $VM1_DAX"

echo "### F: what one VM writes the other reads, and the host finds in the backing file"
TAG="fake-cxl-pool $(date +%Y-%m-%dT%H:%M:%S.%N)"
dax-write() { # VMDIR DAX OFFSET TEXT
    pool-vm-command "$1" "python3 /usr/local/bin/pool-dax-rw.py write $2 $3 '$4'" ||
        command-error "cannot write to $2 in $(pool-vm-label "$1")"
}
dax-expect() { # VMDIR DAX OFFSET TEXT
    pool-vm-command "$1" "python3 /usr/local/bin/pool-dax-rw.py read $2 $3" ||
        command-error "cannot read $2 in $(pool-vm-label "$1")"
    [ "$COMMAND_OUTPUT" == "$4" ] ||
        error "$(pool-vm-label "$1") read '$COMMAND_OUTPUT' at $3 of $2, expected '$4'"
    echo "$(pool-vm-label "$1") read at $3: '$COMMAND_OUTPUT'"
}
dax-write "$VM1" "$VM1_DAX" 0 "$TAG from VM1 at 0M"
dax-write "$VM1" "$VM1_DAX" 128M "$TAG from VM1 at 128M"
dax-expect "$VM2" "$VM2_DAX" 0 "$TAG from VM1 at 0M"
dax-expect "$VM2" "$VM2_DAX" 128M "$TAG from VM1 at 128M"
dax-write "$VM2" "$VM2_DAX" 64M "$TAG from VM2 at 64M"
dax-expect "$VM1" "$VM1_DAX" 64M "$TAG from VM2 at 64M"
dax-expect "$VM1" "$VM1_DAX" 0 "$TAG from VM1 at 0M"
for offset_text in "0:$TAG from VM1 at 0M" "$(( 64 * MiB )):$TAG from VM2 at 64M" "$(( 128 * MiB )):$TAG from VM1 at 128M"; do
    offset="${offset_text%%:*}"
    text="${offset_text#*:}"
    found=$(pool-file-string "$SHARED_FILE" "$offset")
    [ "$found" == "$text" ] ||
        error "host: $SHARED_FILE has '$found' at $offset, expected '$text'"
    echo "host read at $offset of $SHARED_FILE: '$found'"
done
host-command "strings $SHARED_FILE | grep -F '$TAG'" ||
    command-error "the strings are not in the backing file $SHARED_FILE"
[ "$(wc -l <<< "$COMMAND_OUTPUT")" == "3" ] ||
    error "expected 3 strings of this test in $SHARED_FILE"

echo "### G: release shared0 in both VMs, detach it from both"
for vm in "$VM2" "$VM1"; do
    pool-client "$vm" guest release shared0 || command-error "cannot release shared0 in $(pool-vm-label "$vm")"
    pool-cxl-dump "$vm" shared0-released
    cxl-assert "regions == [] and not by_serial($SHARED_SERIAL)['Enabled']"
done
detach-timed shared0 --self
detach-timed shared0 --host "$VM1_NAME"
for vm in "$VM2" "$VM1"; do
    pool-cxl-wait "$vm" shared0-detached "by_serial($SHARED_SERIAL) is None"
    cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
done
pool-client "$VM2" -o json devices shared0 || command-error "cannot get device shared0"
pool-assert "$COMMAND_OUTPUT" "j['state'] == 'free' and j['attachments'] in (None, [])"
pool-vm-monitor "$VM2" "info qtree -b" | grep -q 'dev: cxl-type3' &&
    error "qemu of VM2 still has a CXL memory device"
pool-vm-monitor "$VM1" "info qtree -b" | grep -q 'dev: cxl-type3' &&
    error "qemu of VM1 still has a CXL memory device"

echo "### H: hotplug shared0 to the same slot of VM2 again, and detach it"
pool-client "$VM2" -o json attach shared0 --self --slot "$SHARED_SLOT" || command-error "cannot attach shared0 to VM2 again"
pool-assert "$COMMAND_OUTPUT" "j['state'] == 'attached' and j['slot']['bus'] == '$SHARED_SLOT'"
pool-assert "$COMMAND_OUTPUT" "j['qemuDeviceId'] != '$SHARED_QEMU_ID'"
pool-client "$VM2" guest wait shared0 || command-error "shared0 did not show up in VM2 again"
pool-cxl-wait "$VM2" shared0-reattached "by_serial($SHARED_SERIAL) is not None"
cxl-assert "by_serial($SHARED_SERIAL)['RamSize'] == $MEM_SIZE"
pool-client "$VM2" guest release shared0 || command-error "cannot release shared0 in VM2"
detach-timed shared0 --self
pool-cxl-wait "$VM2" shared0-redetached "by_serial($SHARED_SERIAL) is None"
cxl-assert 'memdevs == [] and regions == []'

echo "### server: nothing attached, every detach completed in qemu"
pool-host-client -o json attachments || command-error "cannot list attachments"
pool-assert "$COMMAND_OUTPUT" 'j in (None, [])'
pool-host-client -o json devices --host "$VM2_NAME" || command-error "cannot list devices"
pool-assert "$COMMAND_OUTPUT" 'all(d["state"] == "free" for d in j)'
pool-snapshot end
deleted=$(grep -c 'event DEVICE_DELETED' "$POOL_SERVER_LOG")
echo "DEVICE_DELETED events in $POOL_SERVER_LOG: $deleted"
[ "$deleted" -ge 4 ] || error "expected 4 DEVICE_DELETED events from qemu, see $POOL_SERVER_LOG"
grep -E 'attachment .*: (attached|detached)' "$POOL_SERVER_LOG"
pool-server-stop
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "fake-cxl-pool-server stopped, state in $TEST_OUTPUT_DIR/fake-cxl-pool.state.json"
