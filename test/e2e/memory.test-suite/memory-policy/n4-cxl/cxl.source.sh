# Helpers for testing pkg/cxl with the cxl-dump tool in the VM.
#
# cxl-dump prints everything pkg/cxl found in the sysfs of the VM. The tests
# drive the CXL hardware of the VM with qemu monitor and the cxl tool, and
# check what pkg/cxl makes of the result.

CXL_DUMP_FILE=""   # cxl-dump output of the last cxl-dump/cxl-wait
CXL_BLOCK_SIZE=""  # memory block size in bytes in the VM

cxl-tools-install() { # script API
    # Usage: cxl-tools-install
    #
    # Install the cxl and numactl tools in the VM if they are missing, and
    # always rebuild and install cxl-dump: it is the tool under test here.
    local host_cxl_dump="$OUTPUT_DIR/cxl-dump"
    local src_dir="${TEST_DIR%%/test/e2e/*}"

    vm-command-q "command -v cxl >/dev/null && command -v numactl >/dev/null" ||
        vm-command "dnf install -y /usr/bin/cxl numactl" ||
            error "cannot install cxl and numactl in the VM"

    GOARCH=amd64 go build -o "$host_cxl_dump" "$src_dir/scripts/cxl-dump/cxl-dump.go" ||
        error "cannot build $src_dir/scripts/cxl-dump/cxl-dump.go"
    vm-put-file "$host_cxl_dump" "/usr/local/bin/cxl-dump"

    CXL_BLOCK_SIZE=$(( 0x$(vm-command-q "cat /sys/devices/system/memory/block_size_bytes") ))
    [ "$CXL_BLOCK_SIZE" -gt 0 ] ||
        error "cannot read memory block size from the VM"
    echo "cxl-tools-install: memory block size $CXL_BLOCK_SIZE bytes"
}

cxl-dump() { # script API
    # Usage: cxl-dump LABEL
    #
    # Run cxl-dump in the VM and store what pkg/cxl found as
    # $TEST_OUTPUT_DIR/cxl-dump.LABEL.json. Store the sysfs and proc files
    # behind it next to the dump, too, so that a failed assertion can be
    # debugged, and so that the files can be used as pkg/cxl unit test data.
    local label="$1"
    [ -n "$label" ] || error "cxl-dump: missing LABEL"

    cxl-dump-json "$label" || error "cxl-dump: running cxl-dump in the VM failed"

    # Sort the sysfs files by the depth of their path, so that the files of a
    # device come before the files of the devices below it.
    vm-command-q "grep -sIr '' /sys/bus/cxl/devices/* | awk '{p=\$0; sub(/:.*/, \"\", p); n=gsub(/\//, \"/\", p); print n \"\t\" \$0}' | sort -k1,1n -k2 | cut -f2-" \
        > "$TEST_OUTPUT_DIR/cxl-sysfs.$label.txt"
    vm-command-q "cat /proc/zoneinfo" > "$TEST_OUTPUT_DIR/zoneinfo.$label.txt"
    vm-command-q "grep -s '' /sys/devices/system/memory/block_size_bytes /sys/devices/system/memory/memory*/state; grep -H MemTotal /sys/devices/system/node/node*/meminfo" \
        > "$TEST_OUTPUT_DIR/memory.$label.txt"

    echo "cxl-dump $label: $(cxl-value 'summary()')"
}

cxl-dump-json() {
    # Usage: cxl-dump-json LABEL
    #
    # Store only the cxl-dump json output. This is the fast part of cxl-dump,
    # the one that cxl-wait repeats.
    local label="$1" json
    json=$(vm-command-q "cxl-dump -o json") || return 1
    CXL_DUMP_FILE="$TEST_OUTPUT_DIR/cxl-dump.$label.json"
    echo "$json" > "$CXL_DUMP_FILE"
}

cxl-wait() { # script API
    # Usage: cxl-wait LABEL EXPRESSION [TIMEOUT]
    #
    # Run cxl-dump in the VM until EXPRESSION, a Python expression on its
    # output, becomes true, TIMEOUT seconds at most (30 by default). Fail the
    # test on timeout. Store the dump as LABEL, both when the wait succeeds and
    # when it times out, and leave it loaded for cxl-assert and cxl-value.
    #
    # Hotplugging, enabling and onlining are all asynchronous, so wait for the
    # state that a test step is expected to reach instead of sleeping.
    local label="$1" expression="$2" tmo="${3:-30}"
    [ -n "$label" ] || error "cxl-wait: missing LABEL"
    [ -n "$expression" ] || error "cxl-wait: missing EXPRESSION"

    retry-until --timeout "$tmo" --message "pkg/cxl: $expression" \
        'cxl-dump-json "$label" && cxl-py assert "$expression" >/dev/null' || {
        cxl-dump "$label"
        error "pkg/cxl did not reach the expected state in ${tmo}s: $expression"
    }
    cxl-dump "$label"
}

cxl-assert() { # script API
    # Usage: cxl-assert EXPRESSION
    #
    # Fail the test unless EXPRESSION, a Python expression on the output of the
    # last cxl-dump or cxl-wait, is true.
    #
    # The dump is available as d, and its device lists as memdevs, regions,
    # endpoints and nodes. See cxl-py for the helper functions.
    local expression="$1"
    cxl-py assert "$expression" ||
        error "pkg/cxl assertion failed: $expression (see $CXL_DUMP_FILE)"
    echo "pkg/cxl ok: $expression"
}

cxl-value() { # script API
    # Usage: cxl-value EXPRESSION
    #
    # Print the value of EXPRESSION, a Python expression on the output of the
    # last cxl-dump or cxl-wait.
    cxl-py eval "$1" || error "pkg/cxl expression failed: $1"
}

cxl-py() {
    # Usage: cxl-py assert|eval EXPRESSION
    #
    # Evaluate EXPRESSION on the last cxl-dump output. In the assert mode exit
    # with a non-zero status unless the value is true, in the eval mode print
    # the value.
    [ -f "$CXL_DUMP_FILE" ] || error "cxl-py: no cxl-dump output, call cxl-dump first"
    python3 -c '
import json, sys

path, mode, expression = sys.argv[1], sys.argv[2], sys.argv[3]

d = json.loads(open(path).read())
memdevs = d.get("MemoryDevices") or []
regions = d.get("RegionDevices") or []
endpoints = d.get("EndpointDevices") or []
nodes = d.get("MemoryNodes") or []

MiB = 1 << 20

def by_name(objs, name):
    """Object called name, None if there is no such object."""
    return next((o for o in objs if o.get("Name") == name), None)

def by_serial(serial):
    """Memory device with the serial number, None if it is not there."""
    return next((m for m in memdevs if m.get("Serial") == serial), None)

def names(objs):
    """Sorted names of the objects."""
    return sorted(o["Name"] for o in objs or [])

def node(node_id):
    """Memory node with the id, None if the node is not online."""
    return next((n for n in nodes if n.get("ID") == node_id), None)

def cpu_nodes():
    """Ids of the NUMA nodes of the CPUs, that is, all but the CXL ones."""
    return sorted(set(n["ID"] for n in nodes) - set(r["Node"] for r in regions))

def region_blocks(name, which, block_size):
    """Memory block indexes of the region: all, the first or the last."""
    r = by_name(regions, name)
    first = r["Resource"] // block_size
    last = (r["Resource"] + r["Size"]) // block_size - 1
    blocks = {
        "all": list(range(first, last + 1)),
        "first": [first],
        "last": [last],
    }[which]
    return " ".join(str(b) for b in blocks)

def summary():
    """One line description of the dump."""
    return "%d memdevs (%s), %d regions (%s), %d endpoints, nodes %s" % (
        len(memdevs),
        ", ".join("%s%s" % (m["Name"], "" if m["Enabled"] else " disabled") for m in memdevs),
        len(regions),
        ", ".join("%s node %d %d/%dM online" %
                  (r["Name"], r["Node"], r["OnlineSize"] // MiB, r["Size"] // MiB)
                  for r in regions),
        len(endpoints),
        ", ".join("%d:%dM" % (n["ID"], n["Size"] // MiB) for n in nodes),
    )

value = eval(expression)
if mode == "eval":
    print(value)
    sys.exit(0)
if not value:
    print("expected true: %s" % expression, file=sys.stderr)
    print("in %s: %s" % (path, summary()), file=sys.stderr)
    sys.exit(1)
' "$CXL_DUMP_FILE" "$1" "$2"
}

cxl-reset() { # script API
    # Usage: cxl-reset
    #
    # Make sure that the VM has no CXL memory devices plugged in, and that
    # hotplugged memory is not onlined without the test asking for it.
    #
    # Restart qemu if there are devices: hot-unplugging a CXL memory device
    # leaves its pci slot occupied and its memory backend in use in qemu
    # (11.1), so the same device cannot be hotplugged again before qemu
    # restarts. vm-reboot restarts qemu, which returns every CXL memory device
    # to its boot time state.
    if vm-cxl-hw | grep -q plugged; then
        echo "cxl-reset: CXL memory devices are plugged in, restarting qemu..."
        timeout=300 vm-reboot
    fi
    vm-cxl-hw | grep -q plugged &&
        error "cxl-reset: failed to unplug all CXL memory devices"
    vm-command "echo offline > /sys/devices/system/memory/auto_online_blocks"
    return 0
}

cxl-qemu-serial() { # script API
    # Usage: cxl-qemu-serial QEMU_MEMDEV
    #
    # Print the serial number of a hotpluggable qemu CXL memory device, for
    # instance 0xc100e2e0 of cxl_memdev0. The serial number is what identifies
    # the device in the VM: the name it gets there depends on the order in
    # which the devices were plugged in.
    local serial
    serial=$(show_sn=1 vm-cxl-hw | awk -v dev="$1" '$1 == dev {print $2}')
    serial=${serial#sn=}
    [ -n "$serial" ] || error "cxl-qemu-serial: no qemu CXL memory device $1"
    echo "$serial"
}

cxl-hotplug() { # script API
    # Usage: cxl-hotplug QEMU_MEMDEV
    #
    # Hotplug a CXL memory device and wait until pkg/cxl sees it in the VM.
    local qemu_memdev="$1" serial
    serial=$(cxl-qemu-serial "$qemu_memdev")
    vm-cxl-hotplug "$qemu_memdev"
    cxl-wait "$qemu_memdev-plugged" "by_serial($serial) is not None"
}

cxl-hotremove() { # script API
    # Usage: cxl-hotremove QEMU_MEMDEV
    #
    # Hotremove a CXL memory device and wait until it is gone from the VM.
    # Disable the device and destroy the regions using it first, otherwise the
    # VM will not release it.
    local qemu_memdev="$1" serial
    serial=$(cxl-qemu-serial "$qemu_memdev")
    vm-cxl-hotremove "$qemu_memdev"
    cxl-wait "$qemu_memdev-removed" "by_serial($serial) is None"
}

cxl-region-blocks() { # script API
    # Usage: cxl-region-blocks REGION [all|first|last]
    #
    # Print the indexes of the memory blocks of a region in the last cxl-dump
    # output.
    cxl-value "region_blocks(\"$1\", \"${2:-all}\", $CXL_BLOCK_SIZE)"
}

cxl-memory-state() { # script API
    # Usage: cxl-memory-state online_movable|offline BLOCK...
    #
    # Online or offline memory blocks. Skip the blocks that are already in the
    # requested state: writing the state a block already has fails.
    local state="$1" block state_file
    shift
    for block in "$@"; do
        state_file="/sys/devices/system/memory/memory$block/state"
        vm-command "grep -qx ${state%_movable} $state_file || echo $state > $state_file" ||
            command-error "cannot set memory block $block $state"
    done
}
