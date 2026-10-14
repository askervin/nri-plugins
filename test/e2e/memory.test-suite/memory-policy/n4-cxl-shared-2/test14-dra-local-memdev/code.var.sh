# Node-local CXL memory with Dynamic Resource Allocation: pods share and
# slice a local CXL memory device
#
# test10 and test11 give pods memory of devices that the pool attaches to
# the node on demand. A CXL memory device can also belong to the node
# itself: cabled to it, there from boot. kubelet-cxl-plugin offers such a
# local device whole, as device cxlmem-<serial> of the node's cxl.generic
# ResourceSlice (attributes type cxl-memdev, source local, mode and
# memoryBlockSize; capacity memory in steps of the memory block size of
# the node, any number of claims), and carves a slice of the device for
# every claim that it prepares, a multiple of the block size:
# - DeviceClass cxl-local-memory: the slice becomes movable system memory
#   of the NUMA node of the device. The node grows by the memory blocks
#   of every such claim and shrinks by them when the claim goes. The
#   containers of the claims get the node in their cpuset.mems.
# - DeviceClass cxl-local-dax: the slice is a character device
#   /dev/daxX.Y in the containers of the claim, so containers get isolated
#   pieces of one device. Pods that reference the same ResourceClaim share
#   its slice. Dax slices add nothing to the NUMA node.
# Claims of both classes share one device. The first claim creates a
# region on the device, the last one destroys it. The attribute mode tells
# what the device holds now: none, numa, dax or numa+dax.
#
# The local device here is cxl_memdev1 of the topology (1G, host bridge
# 0): 8 memory blocks of 128M in the VM. It is not present at boot: the
# test attaches it through fake-cxl-pool-server, where it is a device of
# scope "local" of this VM, and detaches it at the end. Claim sizes are
# derived from the block size that the VM reports.
#
# What you will see: the device in the ResourceSlice; NUMA and dax claims
# on it at the same time, the NUMA node appearing with the first NUMA
# claim and growing with the next one by exactly its blocks, while dax
# claims (one rounded up to a block, one shared by two pods) take slices
# next to them, with data isolated between the slices; the node shrinking
# block by block as the NUMA pods go, while the dax pods keep their data;
# the device back in its initial state (no region, memdev enabled, mode
# none); a claim with an invalid config that fails its Prepare; a
# read-only slice; a dax claim without an amount that gets all of the
# device; and the trace summary of what every component did, in order.
#
# Create the VM first with test00-up of n4-cxl-shared-2. The DRA driver
# comes from ~/github.com/intel/intel-resource-drivers-for-kubernetes, or
# CXL_DRA_DRIVER_SRC; it needs deployments/cxl/local/device-classes.yaml.

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

VM2="$OUTPUT_DIR"      # the VM and the cluster of this test
VM2_NAME="$POOL_VM2_NAME"
POOLED0_SERIAL=0xc1ee0001   # 0xc1ee....: exclusive pool devices
MiB=$(( 1 << 20 ))
LOCAL_MEMORY_CLASS=cxl-local-memory   # a slice of the device as system memory of its NUMA node
LOCAL_DAX_CLASS=cxl-local-dax         # a devdax slice of the device per claim
TAG="dra-local-memdev $(date +%Y-%m-%dT%H:%M:%S.%N)"
NODE_LAST=0            # the last MemTotal of the node that node-size saw, in bytes
NODE_TIMES=()          # changes of MemTotal of the node: "LABEL OLD->NEW MiB, seconds since t0"

no-cxl-node() {
    # Usage: no-cxl-node JSON
    #
    # Check that the ResourceSlices in JSON have no cxl-node device of this
    # node: the region of the local device is not published again as
    # node-local CXL memory.
    dra-assert "$1" "not any(attr(d, 'type') == 'cxl-node' for d in devices('$DRA_LOCAL_DRIVER', '$VM2_NAME'))"
}

node-size() {
    # Usage: node-size LABEL BYTES
    #
    # dra-local-node-size on NUMA_NODE. If MemTotal changed, add the time
    # since t0 to NODE_TIMES.
    dra-local-node-size "$VM2" "$1" "$NUMA_NODE" "$2"
    if [ "$2" != "$NODE_LAST" ]; then
        NODE_TIMES+=("$1 $(( NODE_LAST / MiB ))->$(( $2 / MiB ))MiB $(printf %.1f "$(echo "$EPOCHREALTIME - $t0" | bc)")s")
        NODE_LAST=$2
    fi
}

initial-state() {
    # Usage: initial-state LABEL
    #
    # dra-local-initial-state with NUMA_NODE, and no CXL region at all in
    # the VM.
    dra-local-initial-state "$VM2" "$1" "$NUMA_NODE"
    cxl-assert "regions == []"
}

slice-check() {
    # Usage: slice-check POD BYTES [ro]
    #
    # Check the dax slice of the claim of pod POD: the environment of
    # container main names the device, its size BYTES and the serial of the
    # local device (and READONLY=1 with ro, else no READONLY); the device is
    # a character device in the container with the numbers of a dax device
    # of BYTES of the local device, bound to device_dax, in the VM.
    # SLICE_DAX is its path, SLICE_DEV its "major:minor".
    local pod="$1" size="$2" ro="$3" env
    # shellcheck disable=SC2016 # expanded by sh in the container
    dra-exec "$VM2" "$pod" sh -c 'env | grep ^CXL_LOCAL_ | sort' ||
        command-error "cannot read the environment of $pod"
    env="$COMMAND_OUTPUT"
    SLICE_DAX=$(sed -n "s/^CXL_LOCAL_DAX_$DRA_LOCAL_HEX=//p" <<< "$env")
    [[ "$SLICE_DAX" == /dev/dax* ]] || error "$pod has no CXL_LOCAL_DAX_$DRA_LOCAL_HEX=/dev/daxX.Y"
    grep -qx "CXL_LOCAL_SIZE_$DRA_LOCAL_HEX=$size" <<< "$env" ||
        error "$pod has no CXL_LOCAL_SIZE_$DRA_LOCAL_HEX=$size"
    grep -qx "CXL_LOCAL_SERIAL_$DRA_LOCAL_HEX=$DRA_LOCAL_SERIAL" <<< "$env" ||
        error "$pod has no CXL_LOCAL_SERIAL_$DRA_LOCAL_HEX=$DRA_LOCAL_SERIAL"
    if [ "$ro" == ro ]; then
        grep -qx "CXL_LOCAL_READONLY_$DRA_LOCAL_HEX=1" <<< "$env" ||
            error "$pod has no CXL_LOCAL_READONLY_$DRA_LOCAL_HEX=1"
    else
        grep -q "^CXL_LOCAL_READONLY_" <<< "$env" &&
            error "$pod has CXL_LOCAL_READONLY_ without a read-only claim"
    fi
    dra-exec "$VM2" "$pod" python3 -c 'import os, stat, sys; s = os.stat(sys.argv[1]); print("%s %d:%d" % ("c" if stat.S_ISCHR(s.st_mode) else "-", os.major(s.st_rdev), os.minor(s.st_rdev)))' "$SLICE_DAX" ||
        command-error "no $SLICE_DAX in $pod"
    [[ "$COMMAND_OUTPUT" == "c "* ]] || error "$SLICE_DAX is not a character device in $pod"
    SLICE_DEV=${COMMAND_OUTPUT#c }
    dra-memdev-sysfs "$VM2" "$DRA_LOCAL_SERIAL" || error "cannot read the sysfs of the local device"
    dra-assert "$DRA_MEMDEV" "[(d['size'], d['dev'], d['driver']) for d in dax_slices() if d['name'] == '${SLICE_DAX#/dev/}'] == [($size, '$SLICE_DEV', 'device_dax')]"
    echo "$pod: slice $SLICE_DAX ($SLICE_DEV), $size bytes"
}

dax-write() {
    # Usage: dax-write POD DEV TEXT
    #
    # Write TEXT at offset 1M of dax device DEV in pod POD.
    dra-exec "$VM2" "$1" python3 /tools/dax-rw.py write "$2" 1M "$3" ||
        command-error "cannot write to $2 in $1"
}

dax-read() {
    # Usage: dax-read POD DEV EXPECTED
    #
    # Read the string at offset 1M of dax device DEV in pod POD, and fail
    # unless it is EXPECTED.
    dra-exec "$VM2" "$1" python3 /tools/dax-rw.py read "$2" 1M ||
        command-error "cannot read $2 in $1"
    [ "$COMMAND_OUTPUT" == "$3" ] || error "$1 read '$COMMAND_OUTPUT' at 1M of $2, expected '$3'"
}

echo "### preconditions: patched qemu, hdm_for_passthrough=on, kernel with CONFIG_FS_DAX"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"

echo "### preconditions: the VM is a single-node cluster (test13 makes a cluster of two)"
vm-k8s-reinit "$VM2"

echo "### preconditions: cxl, daxctl and cxl-dump in the VM, no CXL memory devices"
pool-vm-tools-install "$VM2"
pool-vm-reset "$VM2"
pool-cxl-dump "$VM2" no-devices
cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
CPU_NODES=$(cxl-value 'len(nodes)')
vm-command "cat /sys/devices/system/node/has_memory" || command-error "cannot read the memory nodes of the VM"
DRAM_NODES="$COMMAND_OUTPUT"
dra-node-size-exact "$VM2"

echo "### preconditions: fake-cxl-pool-server on the host, with one exclusive device"
pool-server-start "
  - name: pooled0
    size: 512M
    shared: false
    pool: default
    serial: $POOLED0_SERIAL"
pool-client-install "$VM2"

echo "### preconditions: the pool controller and the node plugin run in the cluster"
dra-build
[ -f "$DRA_LOCAL_CLASSES" ] ||
    error "the driver in $DRA_DRIVER_SRC has no DeviceClasses of local devices ($DRA_LOCAL_CLASSES)"
dra-install "$VM2"
dra-pull-images "$VM2" "$DRA_TOOLS_IMAGE"
dra-dax-tool-install "$VM2"
dra-trace-start "$VM2"

echo "### A: the local device is a resource of the node"
# Attaching the local device plugs it into its own slot under host bridge
# 0, as if it had been there from boot. The node plugin publishes it whole:
# no region yet, mode none.
dra-local-device "$VM2"
LD="$DRA_LOCAL_LD"             # the device in the ResourceSlices (dra-py)
LREGIONS="$DRA_LOCAL_REGIONS"  # its regions in cxl-dump (cxl-py)
NUMA_NODE=""           # the NUMA node of the device, known when memory of it is online
# Every slice is whole memory blocks of the VM. The claims of the test
# are sized in blocks: numa-a 1, dax-1 half a block (it consumes 1),
# numa-b 2, shared-slice 1, all at the same time.
BS="$DRA_LOCAL_BLOCK_SIZE"
dra-local-blocks-require "$VM2" "$(basename "$TOPOLOGY_DIR")" 5
NUMA_A=$BS
DAX1_REQ=$(( BS / 2 ))
NUMA_B=$(( 2 * BS ))
SHARED=$BS
RO_REQ=$(( BS / 8 ))
BAD_REQ=$(( BS / 4 ))
TOUCH_MIB=$(( BS / 4 / MiB ))
pool-cxl-dump "$VM2" local-attached
cxl-assert "by_serial($DRA_LOCAL_SERIAL) is not None and by_serial($DRA_LOCAL_SERIAL)['Enabled'] and by_serial($DRA_LOCAL_SERIAL)['RamSize'] == $DRA_LOCAL_SIZE"
cxl-assert "regions == []"
MEMDEV=$(cxl-value "by_serial($DRA_LOCAL_SERIAL)['Name']")
AFFINITY=$(cxl-value "by_serial($DRA_LOCAL_SERIAL)['NodeAffinity']")
dra-kubectl "$VM2" "get resourceslices"
dra-json "$VM2" resourceslices
SLICES="$COMMAND_OUTPUT"
dra-assert "$SLICES" "attr($LD, 'type') == 'cxl-memdev' and attr($LD, 'source') == 'local' and attr($LD, 'mode') == 'none'"
dra-assert "$SLICES" "attr($LD, 'serial') == '$DRA_LOCAL_SERIAL' and attr($LD, 'size') == $DRA_LOCAL_SIZE and attr($LD, 'name') == '$MEMDEV'"
# Host bridge 0 is on CPU node 0 (pxb-cxl numa_node=0).
dra-assert "$SLICES" "attr($LD, 'nodeAffinity') == $AFFINITY and $AFFINITY == 0"
# Capacity in steps of the memory block size, the smallest claim one
# block, the whole device for a request without an amount, any number of
# claims.
dra-assert "$SLICES" "attr($LD, 'memoryBlockSize') == $BS"
dra-assert "$SLICES" "quantity(capacity($LD, 'memory')) == $DRA_LOCAL_SIZE"
dra-assert "$SLICES" "quantity((request_policy($LD, 'memory') or {}).get('validRange', {}).get('min', 0)) == $BS and quantity(request_policy($LD, 'memory')['validRange'].get('step', 0)) == $BS"
dra-assert "$SLICES" "quantity(request_policy($LD, 'memory')['default']) == $DRA_LOCAL_SIZE"
dra-assert "$SLICES" "${LD}.get('allowMultipleAllocations') == True"
no-cxl-node "$SLICES"
dra-assert "$SLICES" "len(slices('$DRA_POOL_DRIVER')) == 1 and [d['name'] for d in devices('$DRA_POOL_DRIVER')] == ['pooled0']"
dra-json "$VM2" deviceclasses
dra-assert "$COMMAND_OUTPUT" "{'$LOCAL_MEMORY_CLASS', '$LOCAL_DAX_CLASS'} <= set(names())"
# No memory of the device is online: the VM has only its DRAM nodes.
vm-command "cat /sys/devices/system/node/has_memory" || command-error "cannot read the memory nodes of the VM"
dra-nodes-eq "$COMMAND_OUTPUT" "$DRAM_NODES" || error "memory nodes $COMMAND_OUTPUT before any claim, expected $DRAM_NODES"

echo "### B: NUMA and dax claims share the device, the NUMA node grows with the NUMA claims"
t0=$EPOCHREALTIME
dra-claim-pod "$VM2" numa-a "$LOCAL_MEMORY_CLASS" "$(dra-mi "$NUMA_A")"
dra-pod-wait "$VM2" numa-a Running 120
T_NUMA_A=$(echo "$EPOCHREALTIME - $t0" | bc)
dra-local-claim-check "$VM2" numa-a "$NUMA_A"
# The first claim creates a region on the device. Its slice goes online
# as movable memory of a NUMA node that the VM did not have: the node of
# the CXL window of host bridge 0.
dra-local-slices-wait "$VM2" numa-a "$NUMA_NODE" "numa:$NUMA_A"
NUMA_NODE=$(dra-value "$DRA_MEMDEV" "dax_slices('kmem')[0]['node']")
(( NUMA_NODE >= CPU_NODES )) || error "the NUMA slice is on node $NUMA_NODE, a CPU node"
echo "the local device is NUMA node $NUMA_NODE of the VM"
node-size numa-a "$NUMA_A"
pool-cxl-wait "$VM2" numa-a-region "len($LREGIONS) == 1 and ${LREGIONS}[0]['Node'] == $NUMA_NODE and len(regions) == 1"
dra-local-mode-wait "$VM2" numa-mode numa
no-cxl-node "$COMMAND_OUTPUT"
dra-mems-wait "$VM2" numa-a main "$NUMA_NODE"
# Memory that numa-a allocates on the node is on the node.
dra-touch-start "$VM2" numa-a/main "$TOUCH_MIB" "$NUMA_NODE"
pages=$(dra-touch-log-pages "$DRA_TOUCH_LOG" "$NUMA_NODE")
[ "$pages" -ge $(( (TOUCH_MIB - 4) << 8 )) ] || error "only $pages pages of numa-touch.py in numa-a are on node $NUMA_NODE"
anon=$(dra-container-anon "$VM2" numa-a main "$NUMA_NODE")
echo "memory.numa_stat of numa-a: anon N$NUMA_NODE=$anon"
[ "${anon:-0}" -ge $(( (TOUCH_MIB - 4) * MiB )) ] || error "numa-a has ${anon:-0} bytes anon on node $NUMA_NODE, expected >= $(( TOUCH_MIB - 4 )) MiB"
dra-touch-stop
# A dax claim on the same device while numa-a runs: a slice of its own
# next to the NUMA slice. The scheduler rounds its half block up to a
# block, the step of the capacity, and the slice has that size. It adds
# nothing to the NUMA node.
t0=$EPOCHREALTIME
dra-claim-pod "$VM2" dax-1 "$LOCAL_DAX_CLASS" "$(dra-mi "$DAX1_REQ")"
dra-pod-wait "$VM2" dax-1 Running 120
T_DAX_1=$(echo "$EPOCHREALTIME - $t0" | bc)
dra-local-claim-check "$VM2" dax-1 "$(dra-local-round "$DAX1_REQ")"
slice-check dax-1 "$(dra-local-round "$DAX1_REQ")"
DAX1_DAX="$SLICE_DAX"
DAX1_DEV="$SLICE_DEV"
dra-local-slices-wait "$VM2" numa-a-dax-1 "$NUMA_NODE" "numa:$NUMA_A" "dax:$(dra-local-round "$DAX1_REQ")"
node-size dax-1 "$NUMA_A"
dra-local-mode-wait "$VM2" numa-dax-mode numa+dax
no-cxl-node "$COMMAND_OUTPUT"
# A second NUMA claim: the node grows by its two blocks, both containers
# have the node.
t0=$EPOCHREALTIME
dra-claim-pod "$VM2" numa-b "$LOCAL_MEMORY_CLASS" "$(dra-mi "$NUMA_B")"
dra-pod-wait "$VM2" numa-b Running 120
T_NUMA_B=$(echo "$EPOCHREALTIME - $t0" | bc)
dra-local-claim-check "$VM2" numa-b "$NUMA_B"
dra-local-slices-wait "$VM2" numa-b "$NUMA_NODE" "numa:$NUMA_A" "dax:$(dra-local-round "$DAX1_REQ")" "numa:$NUMA_B"
node-size numa-b $(( NUMA_A + NUMA_B ))
dra-mems-wait "$VM2" numa-a main "$NUMA_NODE"
dra-mems-wait "$VM2" numa-b main "$NUMA_NODE"
# One ResourceClaim referenced by two pods: prepared once, one slice for
# both.
dra-apply "$VM2" <<< "$(dra-claim-yaml claim shared-slice "$LOCAL_DAX_CLASS" "$(dra-mi "$SHARED")")
---
$(dra-claim-pod-yaml dax-s1 claim shared-slice)
---
$(dra-claim-pod-yaml dax-s2 claim shared-slice)"
dra-pod-wait "$VM2" dax-s1 Running 120
dra-pod-wait "$VM2" dax-s2 Running 120
dra-local-claim-check "$VM2" dax-s1 "$SHARED"
dra-assert "$DRA_CLAIM_JSON" "j['metadata']['name'] == 'shared-slice' and sorted(r['name'] for r in j['status']['reservedFor']) == ['dax-s1', 'dax-s2']"
slice-check dax-s1 "$SHARED"
SHARED_DAX="$SLICE_DAX"
SHARED_DEV="$SLICE_DEV"
slice-check dax-s2 "$SHARED"
[ "$SLICE_DAX $SLICE_DEV" == "$SHARED_DAX $SHARED_DEV" ] ||
    error "dax-s2 has $SLICE_DAX ($SLICE_DEV), dax-s1 $SHARED_DAX ($SHARED_DEV): not the same slice"
[ "$SHARED_DEV" != "$DAX1_DEV" ] || error "shared-slice and dax-1 have the same device $SHARED_DEV"
dra-local-slices-wait "$VM2" four-slices "$NUMA_NODE" "numa:$NUMA_A" "dax:$(dra-local-round "$DAX1_REQ")" "numa:$NUMA_B" "dax:$SHARED"
# pkg/cxl finds the node of a region of several slices.
pool-cxl-wait "$VM2" four-slices-node "len($LREGIONS) == 1 and ${LREGIONS}[0]['Node'] == $NUMA_NODE" 10
# The same offset of both dax slices: what one claim writes, only the
# pods of that claim see.
dax-write dax-s1 "$SHARED_DAX" "$TAG: shared-slice"
dax-write dax-1 "$DAX1_DAX" "$TAG: dax-1"
dax-read dax-s2 "$SHARED_DAX" "$TAG: shared-slice"
dax-read dax-1 "$DAX1_DAX" "$TAG: dax-1"
echo "two dax slices, two different strings at 1M: the slices are isolated, the shared slice is shared"
# Four claims, five pods on one device: the scheduler accounted every
# claim once, in whole blocks, and the slices take exactly that of the
# region (dra-local-slices-wait checked available_size).
TOTAL=$(( NUMA_A + $(dra-local-round "$DAX1_REQ") + NUMA_B + SHARED ))
dra-json "$VM2" resourceclaims -n "$DRA_NS"
LOCAL_CLAIMS="[c for c in items if any(r['device'] == '$DRA_LOCAL_DEVICE' for r in results(c))]"
dra-assert "$COMMAND_OUTPUT" "len($LOCAL_CLAIMS) == 4 and sum(consumed(c) for c in $LOCAL_CLAIMS) == $TOTAL"
node-size four-claims $(( NUMA_A + NUMA_B ))
dra-vm-command "$VM2" "daxctl list -R -D 2>/dev/null; ls -l /dev/dax*; numactl -H" || :

echo "### C: the NUMA pods go, the node shrinks by their blocks, the dax slices keep their data"
t0=$EPOCHREALTIME
dra-delete-pod "$VM2" numa-a
node-size numa-a-deleted "$NUMA_B"
dra-local-slices-wait "$VM2" without-numa-a "$NUMA_NODE" "dax:$(dra-local-round "$DAX1_REQ")" "numa:$NUMA_B" "dax:$SHARED"
dra-mems-wait "$VM2" numa-b main "$NUMA_NODE"
dax-read dax-1 "$DAX1_DAX" "$TAG: dax-1"
dax-read dax-s2 "$SHARED_DAX" "$TAG: shared-slice"
dra-json "$VM2" resourceslices
dra-assert "$COMMAND_OUTPUT" "attr($LD, 'mode') == 'numa+dax'"
t0=$EPOCHREALTIME
dra-delete-pod "$VM2" numa-b
node-size numa-b-deleted 0
# The region stays for the dax slices. pkg/cxl finds its node without
# any memory online, from the dax devices.
dra-local-slices-wait "$VM2" without-numa "$NUMA_NODE" "dax:$(dra-local-round "$DAX1_REQ")" "dax:$SHARED"
pool-cxl-wait "$VM2" without-numa-node "len($LREGIONS) == 1 and ${LREGIONS}[0]['Node'] == $NUMA_NODE" 10
dra-local-mode-wait "$VM2" dax-mode dax
no-cxl-node "$COMMAND_OUTPUT"
dax-read dax-1 "$DAX1_DAX" "$TAG: dax-1"
dax-read dax-s2 "$SHARED_DAX" "$TAG: shared-slice"
# The shared slice stays while a pod of its claim runs.
dra-delete-pod "$VM2" dax-s1
dra-wait "$VM2" shared-slice-reserved "resourceclaim -n $DRA_NS shared-slice" \
    "[r['name'] for r in j['status']['reservedFor']] == ['dax-s2']" 60
dra-local-slices-wait "$VM2" with-dax-s2 "$NUMA_NODE" "dax:$(dra-local-round "$DAX1_REQ")" "dax:$SHARED"
dax-read dax-s2 "$SHARED_DAX" "$TAG: shared-slice"
dra-delete-pod "$VM2" dax-1
dra-local-slices-wait "$VM2" without-dax-1 "$NUMA_NODE" "dax:$SHARED"
dax-read dax-s2 "$SHARED_DAX" "$TAG: shared-slice"
t0=$EPOCHREALTIME
dra-delete-pod "$VM2" dax-s2
dra-delete "$VM2" resourceclaim shared-slice --wait=true --timeout=60s
# The last slice destroys the region.
initial-state released
T_RELEASE=$(echo "$EPOCHREALTIME - $t0" | bc)

echo "### D: a refused config, a read-only slice, a slice of the whole device"
# A claim whose config the node plugin refuses (readOnly is for dax
# slices): the scheduler allocates the device, the Prepare fails, the pod
# stays ContainerCreating, and the device stays free.
dra-claim-pod "$VM2" bad-config "$LOCAL_MEMORY_CLASS" "$(dra-mi "$BAD_REQ")" read-only numa
dra-wait "$VM2" bad-config-event "events -n $DRA_NS --field-selector involvedObject.name=bad-config" \
    "any('LocalDeviceConfig: readOnly needs mode dax' in (e.get('message') or '') for e in items)" 120
dra-kubectl "$VM2" "get events -n $DRA_NS --field-selector involvedObject.name=bad-config"
dra-wait "$VM2" bad-config-creating "pod -n $DRA_NS bad-config" \
    "[(cs.get('state') or {}).get('waiting', {}).get('reason') for cs in j['status'].get('containerStatuses') or []] == ['ContainerCreating']" 60
dra-stays 10 "pod bad-config is ContainerCreating" \
    '[ "$(dra-vm-command-q "$VM2" "kubectl get pod -n $DRA_NS bad-config -o jsonpath={.status.containerStatuses[0].state.waiting.reason}" || echo unread)" == ContainerCreating ]'
pool-cxl-dump "$VM2" bad-config
cxl-assert "regions == []"
dra-json "$VM2" resourceslices
dra-assert "$COMMAND_OUTPUT" "attr($LD, 'mode') == 'none'"
dra-delete-pod "$VM2" bad-config
initial-state bad-config-deleted
# A read-only slice: the claim config says readOnly, the device node of
# the container can only be opened for reading. An eighth of a block
# consumes a block.
dra-claim-pod "$VM2" dax-ro "$LOCAL_DAX_CLASS" "$(dra-mi "$RO_REQ")" read-only
dra-pod-wait "$VM2" dax-ro Running 120
dra-local-claim-check "$VM2" dax-ro "$(dra-local-round "$RO_REQ")"
RO_UID="$DRA_CLAIM_UID"
slice-check dax-ro "$(dra-local-round "$RO_REQ")" ro
RO_DAX="$SLICE_DAX"
RO_DEV="$SLICE_DEV"
dra-local-slices-wait "$VM2" read-only "$NUMA_NODE" "dax:$(dra-local-round "$RO_REQ")"
dra-local-mode-wait "$VM2" ro-mode dax
dra-exec "$VM2" dax-ro python3 /tools/dax-rw.py check-ro "$RO_DAX" 0 ||
    error "dax-ro could open or map $RO_DAX for writing"
for line in "open for writing refused: EPERM" "writable mapping refused: EACCES"; do
    grep -qxF "$line" <<< "$COMMAND_OUTPUT" || error "dax-ro: check-ro did not print '$line'"
done
devices=$(dra-container-devices "$VM2" dax-ro main) || error "cannot read the device cgroup of dax-ro"
echo "device cgroup of dax-ro: $devices"
dra-assert "$(sed -n 's/^spec: //p' <<< "$devices")" \
    "[d.get('access') for d in j if d.get('allow') and d.get('major') == ${RO_DEV%:*} and d.get('minor') == ${RO_DEV#*:}] == ['r']"
# (grep exits 2 if a directory is missing, even if it matched: test the
# output instead)
dra-vm-command "$VM2" "f=\$(grep -l 'local-$RO_UID' /etc/cdi/* /var/run/cdi/* 2>/dev/null); [ -n \"\$f\" ] && echo \$f && grep -h -A20 'name: local-$RO_UID' \$f | grep -E 'permissions: r\$|READONLY_$DRA_LOCAL_HEX=1'" ||
    command-error "no read-only CDI device local-$RO_UID in the VM"
[ "$(grep -cE 'permissions: r$|READONLY_' <<< "$COMMAND_OUTPUT")" == 2 ] ||
    error "the CDI device of dax-ro lacks permissions r or CXL_LOCAL_READONLY_$DRA_LOCAL_HEX"
dra-delete-pod "$VM2" dax-ro
initial-state ro-deleted
# A dax claim without an amount consumes the whole device (the default of
# the requestPolicy): one slice of all of it.
t0=$EPOCHREALTIME
dra-claim-pod "$VM2" dax-whole "$LOCAL_DAX_CLASS" ""
dra-pod-wait "$VM2" dax-whole Running 120
T_WHOLE=$(echo "$EPOCHREALTIME - $t0" | bc)
dra-local-claim-check "$VM2" dax-whole "$DRA_LOCAL_SIZE"
slice-check dax-whole "$DRA_LOCAL_SIZE"
dra-local-slices-wait "$VM2" whole "$NUMA_NODE" "dax:$DRA_LOCAL_SIZE"
dra-delete-pod "$VM2" dax-whole
initial-state whole-deleted

echo "### E: what every component did, in order"
# Every slice is whole memory blocks: the scheduler rounded every claim
# up, and the kernel's first-fit kept every slice block-aligned.
dra-local-slices-aligned "$VM2"
dra-trace-stop
dra-trace-summary
printf 'timings (s, test steps, 1 s polling): pod Running after apply: numa-a (region, first NUMA slice) %.1f, dax-1 %.1f, numa-b (two blocks) %.1f, the whole device as one dax slice %.1f; last claim deleted -> initial state %.1f\n' \
    "$T_NUMA_A" "$T_DAX_1" "$T_NUMA_B" "$T_WHOLE" "$T_RELEASE"
echo "timings (s, test steps): MemTotal of node $NUMA_NODE changed, seen by the test this long after the apply or delete (pod start and checks included): ${NODE_TIMES[*]}"
dra-local-slice-times "$VM2"

echo "### cleanup"
dra-cleanup
dra-local-detach "$VM2"
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
