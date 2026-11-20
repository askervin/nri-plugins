# Helpers that read the CXL topology of the VM with the cxl-dump tool.
#
# cxl-dump prints what package kernel (pkg/cxl/kernel) reads from the sysfs
# of the VM: memdevs, regions, dax devices, memory blocks and NUMA nodes
# (kernel.ObserveTopology as JSON). The tests drive the CXL hardware of the
# VM and check the topology that results. Every test of memory.test-suite
# has these helpers.

CXL_DUMP_FILE=""   # cxl-dump output of the last cxl-dump/cxl-wait
CXL_BLOCK_SIZE=""  # memory block size in bytes in the VM

cxl-tools-install() { # script API
    # Usage: cxl-tools-install
    #
    # Install the cxl and numactl tools in the VM if they are missing, and
    # always rebuild and install cxl-dump from the source tree.
    local host_cxl_dump="$OUTPUT_DIR/cxl-dump"
    local src_dir="${TEST_DIR%%/test/e2e/*}"

    vm-command-q "command -v cxl >/dev/null && command -v numactl >/dev/null" ||
        vm-command "dnf install -y /usr/bin/cxl numactl" ||
            error "cannot install cxl and numactl in the VM"

    GOARCH=amd64 go build -o "$host_cxl_dump" "$src_dir/scripts/cxl-dump/cxl-dump.go" ||
        error "cannot build $src_dir/scripts/cxl-dump/cxl-dump.go"
    vm-put-file "$host_cxl_dump" "/usr/local/bin/cxl-dump"

    CXL_BLOCK_SIZE=$(cxl-block-size-parse "$(vm-command-q "cat /sys/devices/system/memory/block_size_bytes")") ||
        error "cannot read memory block size from the VM"
    echo "cxl-tools-install: memory block size $CXL_BLOCK_SIZE bytes"
}

cxl-block-size-parse() { # script API
    # Usage: cxl-block-size-parse TEXT
    #
    # Print the memory block size in bytes that TEXT, the contents of
    # /sys/devices/system/memory/block_size_bytes, gives: hexadecimal with
    # or without 0x ("8000000" is 128 MiB). Return 1 unless TEXT is a
    # positive hexadecimal number.
    local hex="${1//[[:space:]]/}"
    hex="${hex#0x}"
    [[ "$hex" =~ ^[0-9a-fA-F]+$ ]] || return 1
    (( 16#$hex > 0 )) || return 1
    echo $(( 16#$hex ))
}

cxl-dump() { # script API
    # Usage: cxl-dump LABEL
    #
    # Run cxl-dump in the VM and store its output as
    # $TEST_OUTPUT_DIR/cxl-dump.LABEL.json. Store the zone and memory block
    # files of the VM next to the dump, too. They help to debug a failed
    # assertion.
    local label="$1"
    [ -n "$label" ] || error "cxl-dump: missing LABEL"

    cxl-dump-json "$label" || error "cxl-dump: running cxl-dump in the VM failed"

    # Read no file below /sys/bus/cxl/devices here. A recursive read there
    # reaches the mappingN files of dax devices. A read of such a file can
    # deadlock with a dax size write of the driver.
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
    json=$(vm-command-q "cxl-dump") || return 1
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

    retry-until --timeout "$tmo" --message "cxl-dump: $expression" \
        'cxl-dump-json "$label" && cxl-py assert "$expression" >/dev/null' || {
        cxl-dump "$label"
        error "cxl-dump did not show the expected state in ${tmo}s: $expression"
    }
    cxl-dump "$label"
}

cxl-assert() { # script API
    # Usage: cxl-assert EXPRESSION
    #
    # Fail the test unless EXPRESSION, a Python expression on the output of the
    # last cxl-dump or cxl-wait, is true.
    #
    # The dump is available as d, and its lists as memdevs, regions,
    # daxdevs, blocks and nodes, the endpoint ports of the memdevs as
    # endpoints. See cxl-py for the helper functions.
    local expression="$1"
    cxl-py assert "$expression" ||
        error "cxl-dump assertion failed: $expression (see $CXL_DUMP_FILE)"
    echo "cxl-dump ok: $expression"
}

cxl-value() { # script API
    # Usage: cxl-value EXPRESSION
    #
    # Print the value of EXPRESSION, a Python expression on the output of the
    # last cxl-dump or cxl-wait.
    cxl-py eval "$1" || error "cxl-dump expression failed: $1"
}

cxl-py() {
    # Usage: cxl-py assert|eval EXPRESSION
    #
    # Evaluate EXPRESSION on the last cxl-dump output. In the assert mode exit
    # with a non-zero status unless the value is true, in the eval mode print
    # the value. The keys that the dump leaves out when their value is empty
    # or zero have that value here.
    [ -f "$CXL_DUMP_FILE" ] || error "cxl-py: no cxl-dump output, call cxl-dump first"
    python3 -c '
import json, sys

path, mode, expression = sys.argv[1], sys.argv[2], sys.argv[3]

d = json.loads(open(path).read())
memdevs = d.get("memdevs") or []
regions = d.get("regions") or []
daxdevs = d.get("daxDevices") or []
blocks = d.get("blocks") or []
nodes = d.get("numaNodes") or []
block_size = d.get("blockSize") or 0
for m in memdevs:
    for k, v in (("ramSize", 0), ("pmemSize", 0), ("major", 0), ("minor", 0), ("endpoint", ""), ("ports", []), ("regions", [])):
        m.setdefault(k, v)
for r in regions:
    for k, v in (("locked", False), ("targets", []), ("memdevs", []), ("serials", []), ("rootDecoder", ""), ("daxRegion", ""), ("ndRegion", "")):
        r.setdefault(k, v)
for x in daxdevs:
    for k, v in (("driver", ""), ("major", 0), ("minor", 0)):
        x.setdefault(k, v)
for b in blocks:
    b.setdefault("zones", "")
endpoints = [m["endpoint"] for m in memdevs if m["endpoint"]]

MiB = 1 << 20

def by_name(objs, name):
    """Object called name, None if there is no such object."""
    return next((o for o in objs if o.get("name") == name), None)

def by_serial(serial):
    """Memory device with the serial number, None if it is not there."""
    return next((m for m in memdevs if m.get("serial") == serial), None)

def names(objs):
    """Sorted names of the objects."""
    return sorted(o["name"] for o in objs or [])

def node(node_id):
    """NUMA node with the id, None if the node is not online."""
    return next((n for n in nodes if n.get("id") == node_id), None)

def cpu_nodes():
    """Ids of the NUMA nodes of the CPUs, that is, all but the CXL ones."""
    return sorted(set(n["id"] for n in nodes) - set(r["numaNode"] for r in regions))

def enabled(o):
    """True if a memdev has its driver or a region is enabled."""
    return o["state"] in ("BOUND", "READY", "ENABLED")

def size(r):
    """Size of the address range of a region in bytes, 0 without a range."""
    rg = r["range"]
    return rg["end"] - rg["start"] + 1 if rg["end"] else 0

def online_size(r):
    """Bytes of the memory blocks in the address range of a region that are online."""
    rg = r["range"]
    if not rg["end"] or not block_size:
        return 0
    return block_size * sum(1 for b in blocks if b["state"] == "ONLINE" and
                            rg["start"] <= b["index"] * block_size and (b["index"] + 1) * block_size - 1 <= rg["end"])

def summary():
    """One line description of the dump."""
    return "%d memdevs (%s), %d regions (%s), %d endpoints, nodes %s" % (
        len(memdevs),
        ", ".join("%s%s" % (m["name"], "" if enabled(m) else " disabled") for m in memdevs),
        len(regions),
        ", ".join("%s node %d %d/%dM online" %
                  (r["name"], r["numaNode"], online_size(r) // MiB, size(r) // MiB)
                  for r in regions),
        len(endpoints),
        ", ".join("%d:%dM" % (n["id"], n["memTotal"] // MiB) for n in nodes),
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
