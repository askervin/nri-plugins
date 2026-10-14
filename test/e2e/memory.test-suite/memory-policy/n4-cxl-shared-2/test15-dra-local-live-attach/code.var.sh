# Lending node-local CXL memory to a running container
#
# test12 lends pool memory to a running container: "cxl-request memory
# 512Mi" in a container whose pod claims the token device "dynamic"
# creates a lease, a companion pod with a claim of a pool device, and the
# node plugin lends the NUMA node of the device to the container. test14
# gives pods NUMA memory and dax slices of a local CXL memory device
# through their claims. Here a running container borrows local memory and
# gives it back, while it keeps running, next to pods that have static
# claims of the same device:
# - "cxl-request memory 128Mi --source local": the companion claim asks
#   for 128Mi of DeviceClass cxl-local-memory. Preparing it, the node
#   plugin carves a slice of the local device, onlines its memory blocks
#   on the NUMA node of the device, and lends the node to the container
#   (cpuset.mems, through NRI). Nothing is attached and there is no
#   binding condition to wait for: a local lease is Ready sooner than a
#   pool lease.
# - "cxl-request memory 64Mi --source local --dax --exec CMD": the claim
#   asks for DeviceClass cxl-local-dax, the lease gets a devdax slice of
#   the device of its own, passed to CMD as fd 3.
# - "--source any": local memory if a local device has room, else memory
#   of the pool (the companion claim has firstAvailable: local, pool).
# Every slice is whole memory blocks: a request is rounded up to them.
# NUMA and dax slices, of leases and of static claims, share the device.
# The NUMA node grows by the blocks of every NUMA slice and shrinks by
# them when it goes. Pods with static claims and leases share the node; a
# container keeps it lent while any of its leases holds it.
#
# What you will see: a pod with a static NUMA claim, then the borrower's
# NUMA lease on the same node, the node growing by exactly its blocks,
# with pages on it; two dax leases with slices of their own next to the
# NUMA slices; a second static pod and a second NUMA lease, and the leases
# given back one by one: the node stays lent while the second lease holds
# it, then the pages move back to DRAM, while the static pods keep the
# node; the device back in its initial state; a lease falling back to the
# pool when the local device is full; and the pod deleted with leases
# active, leaving nothing behind. At the end the trace summary of what
# every component did, in order.
#
# The local device is cxl_memdev1 of the topology (1G, 8 memory blocks of
# 128M in the VM), attached through fake-cxl-pool-server as in test14.
# Sizes are derived from the block size that the VM reports. Create the VM
# first with test00-up of n4-cxl-shared-2. The DRA driver comes from
# ~/github.com/intel/intel-resource-drivers-for-kubernetes, or
# CXL_DRA_DRIVER_SRC; it needs cmd/cxl-request,
# deployments/cxl/pool/device-class-dynamic.yaml and
# deployments/cxl/local/device-classes.yaml.

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

VM2="$OUTPUT_DIR"      # the VM and the cluster of this test
VM2_NAME="$POOL_VM2_NAME"
POOLED0_SERIAL=0xc1ee0001   # 0xc1ee....: exclusive pool devices
POOLED0_SIZE=$(( 512 << 20 ))
PAUSE_IMAGE=registry.k8s.io/pause:3.10   # the image of the companion pods
MiB=$(( 1 << 20 ))
LOCAL_MEMORY_CLASS=cxl-local-memory
LOCAL_DAX_CLASS=cxl-local-dax
LEASE_LABEL=cxl-pool.generic/lease
REQUESTER_LABEL=cxl-pool.generic/requester-uid
CXL_REQUEST=cxl-request     # in $PATH of the container: /usr/local/bin
TAG_BASE="dra-local-live-attach $(date +%Y-%m-%dT%H:%M:%S.%N)"
LEASES=()                   # every lease id of the test, all distinct
NODE_LAST=0                 # the last MemTotal of the node that node-size saw, in bytes
NODE_TIMES=()               # changes of MemTotal of the node: "LABEL OLD->NEW MiB, seconds since t0"
declare -A NUMA_SLICES=()   # NUMA claims of the local device: LABEL -> "daxX.Y BYTES" of its slice

borrower-yaml() {
    # Usage: borrower-yaml
    #
    # Print pod "borrower" (test12): two idle python containers, "main"
    # with the token claim (it can ask for leases) and "idle" without. No
    # memory limit: lent memory is charged to the container. The claim
    # comes from a template, so it lives and dies with the pod.
    cat <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: cxl-lease-token
spec:
  spec:
    devices:
      requests:
      - name: token
        exactly:
          deviceClassName: cxl-dynamic
---
apiVersion: v1
kind: Pod
metadata:
  name: borrower
spec:
  terminationGracePeriodSeconds: 2
  restartPolicy: Never
  resourceClaims:
  - name: cxl
    resourceClaimTemplateName: cxl-lease-token
  volumes:
  - name: tools
    configMap:
      name: dax-rw
  containers:
  - name: main
    image: $DRA_TOOLS_IMAGE
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "trap 'exit 0' TERM; sleep infinity & wait"]
    volumeMounts:
    - name: tools
      mountPath: /tools
    resources:
      claims:
      - name: cxl
  - name: idle
    image: $DRA_TOOLS_IMAGE
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "trap 'exit 0' TERM; sleep infinity & wait"]
    volumeMounts:
    - name: tools
      mountPath: /tools
EOF
}

new-lease() {
    # Usage: new-lease LEASE
    #
    # Record lease id LEASE; fail if the test has seen it before.
    local l
    [[ "$1" =~ ^[0-9a-f]{8}$ ]] || error "lease id '$1' is not 8 hex digits"
    for l in "${LEASES[@]}"; do
        [ "$l" != "$1" ] || error "lease id $1 was used before"
    done
    LEASES+=("$1")
}

request() {
    # Usage: request ARGS...
    #
    # Run "cxl-request ARGS..." in container main of the borrower. REQ_JSON
    # is its JSON response, REQ_STATUS its exit status, REQ_SECONDS how
    # long it took.
    local t0=$EPOCHREALTIME
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" "$@"
    REQ_STATUS=$COMMAND_STATUS
    REQ_SECONDS=$(echo "$EPOCHREALTIME - $t0" | bc)
    REQ_JSON=$(dra-last-json "$COMMAND_OUTPUT") || error "cxl-request $* printed no JSON response"
}

numa-lease() {
    # Usage: numa-lease SIZE SOURCE
    #
    # Container main of the borrower asks for SIZE (a quantity) of NUMA
    # memory from SOURCE ("cxl-request memory SIZE --source SOURCE"). Fail
    # unless the lease is Ready. LEASE is its id, LEASE_NODE its NUMA node,
    # LEASE_SECONDS how long the request took.
    request memory "$1" --source "$2" --wait 120s
    [ "$REQ_STATUS" == 0 ] || error "cxl-request memory $1 --source $2 exited $REQ_STATUS"
    dra-assert "$REQ_JSON" "j.get('state') == 'Ready' and j.get('kind') == 'memory' and int(j['node']) >= $CPU_NODES"
    LEASE=$(dra-value "$REQ_JSON" "j['lease']")
    LEASE_NODE=$(dra-value "$REQ_JSON" "j['node']")
    LEASE_SECONDS="$REQ_SECONDS"
    new-lease "$LEASE"
    printf 'lease %s: %s from %s, NUMA node %s, Ready in %.2f s\n' "$LEASE" "$1" "$2" "$LEASE_NODE" "$LEASE_SECONDS"
}

local-numa-lease() {
    # Usage: local-numa-lease BYTES
    #
    # Container main of the borrower asks for BYTES of local NUMA memory.
    # Check that the lease is Ready on the local device and the NUMA node
    # of the device, with a slice of BYTES rounded up to blocks, and its
    # companion objects (see companion-check). LEASE, LEASE_SECONDS: see
    # numa-lease.
    numa-lease "$(dra-mi "$1")" local
    dra-assert "$REQ_JSON" "j.get('source') == 'local' and j.get('serial') == '$DRA_LOCAL_SERIAL' and int(j['node']) == $NUMA_NODE and int(j['size']) == $(dra-local-round "$1")"
    companion-check "$LEASE" "$LOCAL_MEMORY_CLASS" "$1" "$(dra-local-round "$1")"
}

dax-lease() {
    # Usage: dax-lease SIZE FLAGS SCRIPT [ARG...]
    #
    # Container main of the borrower asks for a dax lease of SIZE ("cxl-request
    # memory SIZE --dax FLAGS --exec") and runs the shell SCRIPT with ARGs
    # as $1... and the dax fd as fd 3. DAX_LEASE, DAX_PATH, DAX_SIZE and
    # DAX_RO are the lease, its dax device, size and read-only flag as the
    # environment of SCRIPT has them, DAX_OUT is what SCRIPT printed,
    # DAX_SECONDS how long it all took.
    local size="$1" flags="$2" script="$3" t0 line
    shift 3
    t0=$EPOCHREALTIME
    # shellcheck disable=SC2086 # FLAGS are separate words
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" memory "$size" --dax $flags --wait 60s --exec \
        sh -c 'echo "lease $CXL_LEASE dax=$CXL_LEASE_DAX size=$CXL_LEASE_SIZE ro=$CXL_LEASE_READONLY fd=$CXL_LEASE_FD"; '"$script" sh "$@" ||
        command-error "cxl-request memory $size --dax $flags --exec failed"
    DAX_SECONDS=$(echo "$EPOCHREALTIME - $t0" | bc)
    line=$(grep '^lease ' <<< "$COMMAND_OUTPUT" | head -n 1)
    read -r DAX_LEASE DAX_PATH DAX_SIZE DAX_RO <<< "$(sed -n 's/^lease \([0-9a-f]*\) dax=\(\S*\) size=\([0-9]*\) ro=\([01]\) fd=3$/\1 \2 \3 \4/p' <<< "$line")"
    [[ -n "$DAX_LEASE" && "$DAX_PATH" == /dev/dax* ]] ||
        error "cxl-request --exec: no lease environment with fd 3: '$line'"
    DAX_OUT=$(grep -v '^lease ' <<< "$COMMAND_OUTPUT")
    new-lease "$DAX_LEASE"
    printf 'lease %s: %s, %s bytes, read-only %s, %.2f s\n' "$DAX_LEASE" "$DAX_PATH" "$DAX_SIZE" "$DAX_RO" "$DAX_SECONDS"
}

dax-fd-read() {
    # Usage: dax-fd-read LEASE EXPECTED
    #
    # Read the string at offset 1M of the dax fd of lease LEASE again
    # ("cxl-request fd LEASE --exec"), and fail unless it is EXPECTED.
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" fd "$1" --exec python3 /tools/dax-rw.py --fd 3 read 1M ||
        command-error "cxl-request fd $1 --exec ... read failed"
    [ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "$2" ] || error "lease $1: read '$(tail -n 1 <<< "$COMMAND_OUTPUT")', expected '$2'"
}

release() {
    # Usage: release LEASE
    #
    # Container main of the borrower gives lease LEASE back.
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" release "$1" ||
        command-error "cxl-request release $1 failed"
    dra-assert "$(dra-last-json "$COMMAND_OUTPUT")" "j.get('lease') == '$1' and j.get('state') == 'Released'"
}

companion-check() {
    # Usage: companion-check LEASE CLASS REQUESTED CONSUMED [dax [ro]]
    #
    # The objects of lease LEASE of local memory: the companion pod and its
    # claim cxl-lease-LEASE, both owned by the borrower. The claim asks for
    # REQUESTED bytes of DeviceClass CLASS, is allocated to the local
    # device on this node, consumes CONSUMED bytes of it, and tells the
    # node plugin (driver cxl.generic) to whom it lends (LendConfig) and,
    # for dax, that it wants a dax slice (LocalDeviceConfig, read-only with
    # ro). The pool attaches nothing for it. COMPANION_UID is the uid of
    # the claim.
    local lease="$1" class="$2" size="$3" consumed="$4" mode="$5" ro=False name="cxl-lease-$1" pod_json claim_json uid cfgs
    [ "$6" != ro ] || ro=True
    dra-pod-wait "$VM2" "$name" Running 60
    dra-json "$VM2" pod -n "$DRA_NS" "$name"
    pod_json="$COMMAND_OUTPUT"
    dra-assert "$pod_json" "[(o['kind'], o['name'], o['uid']) for o in j['metadata']['ownerReferences']] == [('Pod', 'borrower', '$BORROWER_UID')]"
    dra-assert "$pod_json" "j['metadata']['labels']['$LEASE_LABEL'] == '$lease' and j['metadata']['labels']['$REQUESTER_LABEL'] == '$BORROWER_UID'"
    dra-assert "$pod_json" "j['spec']['nodeName'] == '$VM2_NAME' and j['spec']['resourceClaims'] == [{'name': 'lease', 'resourceClaimName': '$name'}]"
    dra-assert "$pod_json" "[c['image'] for c in j['spec']['containers']] == ['$PAUSE_IMAGE'] and not j['spec']['containers'][0]['resources'].get('claims')"
    dra-json "$VM2" resourceclaim -n "$DRA_NS" "$name"
    claim_json="$COMMAND_OUTPUT"
    dra-assert "$claim_json" "[(o['kind'], o['name'], o['uid'], o.get('controller')) for o in j['metadata']['ownerReferences']] == [('Pod', 'borrower', '$BORROWER_UID', True)]"
    dra-assert "$claim_json" "len(j['spec']['devices']['requests']) == 1 and j['spec']['devices']['requests'][0]['exactly']['deviceClassName'] == '$class'"
    dra-assert "$claim_json" "quantity(j['spec']['devices']['requests'][0]['exactly']['capacity']['requests']['memory']) == $size"
    dra-assert "$claim_json" "[(r['driver'], r['device']) for r in results()] == [('$DRA_LOCAL_DRIVER', '$DRA_LOCAL_DEVICE')] and allocated_node() == '$VM2_NAME' and consumed() == $consumed"
    dra-assert "$claim_json" "[r['name'] for r in j['status']['reservedFor']] == ['$name']"
    # The opaque configs for the node plugin: to whom it lends, and how it
    # prepares the device.
    cfgs="[c['opaque'] for c in j['spec']['devices'].get('config') or []]"
    dra-assert "$claim_json" "[(o['driver'], o['parameters']['apiVersion'], o['parameters']['lease'], o['parameters']['container'], o['parameters']['pod']) for o in $cfgs if o['parameters']['kind'] == 'LendConfig'] == [('$DRA_LOCAL_DRIVER', '$DRA_LOCAL_DRIVER/v1alpha1', '$lease', 'main', {'namespace': '$DRA_NS', 'name': 'borrower', 'uid': '$BORROWER_UID'})]"
    if [ "$mode" == dax ]; then
        dra-assert "$claim_json" "[(o['driver'], o['parameters'].get('mode'), bool(o['parameters'].get('readOnly'))) for o in $cfgs if o['parameters']['kind'] == 'LocalDeviceConfig'] == [('$DRA_LOCAL_DRIVER', 'dax', $ro)]"
    else
        dra-assert "$claim_json" "not any(o['parameters']['kind'] == 'LocalDeviceConfig' for o in $cfgs)"
    fi
    uid=$(dra-value "$claim_json" "j['metadata']['uid']")
    COMPANION_UID="$uid"
    if dra-pool-attachments "$VM2_NAME" | grep -qF "$uid"; then
        error "lease $lease: the pool attached a device for the claim of a local lease"
    fi
}

node-size() {
    # Usage: node-size LABEL BYTES [LOCAL]
    #
    # dra-local-node-size on NUMA_NODE. If MemTotal changed, add the time
    # since t0 to NODE_TIMES.
    dra-local-node-size "$VM2" "$1" "$NUMA_NODE" "$2" "$3"
    if [ "$2" != "$NODE_LAST" ]; then
        NODE_TIMES+=("$1 $(( NODE_LAST / MiB ))->$(( $2 / MiB ))MiB $(printf %.1f "$(echo "$EPOCHREALTIME - $t0" | bc)")s")
        NODE_LAST=$2
    fi
}

numa-slice() {
    # Usage: numa-slice LABEL CLAIM-UID BYTES
    #
    # Record in NUMA_SLICES the slice of the NUMA claim CLAIM-UID (LABEL:
    # its pod or lease), as the state of the node plugin names it, and
    # check that sysfs has it as a kmem slice of BYTES.
    local dax
    dax=$(dra-local-claim-slice "$VM2" "$2") ||
        error "$1: the node plugin has no slice of claim $2 in $DRA_LOCAL_STATE"
    NUMA_SLICES[$1]="$dax $3"
    dra-memdev-wait "$VM2" "slice-$1" "$DRA_LOCAL_SERIAL" \
        "[(d['driver'], d['size']) for d in dax_slices() if d['name'] == '$dax'] == [('kmem', $3)]" 10
    echo "$1: NUMA slice $dax, $3 bytes"
}

numa-slice-gone() {
    # Usage: numa-slice-gone LABEL
    #
    # Wait until the slice of LABEL (see numa-slice) is gone or has size
    # 0, while the slices of the other NUMA claims in NUMA_SLICES are kmem
    # slices of their sizes. Forget LABEL.
    local gone="${NUMA_SLICES[$1]%% *}" other dax size expr=""
    [ -n "$gone" ] || error "numa-slice-gone: no slice of $1"
    unset "NUMA_SLICES[$1]"
    for other in "${!NUMA_SLICES[@]}"; do
        read -r dax size <<< "${NUMA_SLICES[$other]}"
        expr+=" and [(d['driver'], d['size']) for d in dax_slices() if d['name'] == '$dax'] == [('kmem', $size)]"
    done
    dra-memdev-wait "$VM2" "slice-$1-gone" "$DRA_LOCAL_SERIAL" \
        "'$gone' not in [d['name'] for d in dax_slices()]$expr" 30
    echo "$1: NUMA slice $gone gone, the others (${!NUMA_SLICES[*]}) kept"
}

main-mems() {
    # Usage: main-mems
    #
    # Set MAIN_MEMS to cpuset.mems of container main of the borrower. Fail
    # the test if it cannot be read.
    MAIN_MEMS=$(dra-container-read "$VM2" borrower main cpuset.mems) ||
        error "cannot read cpuset.mems of container main of the borrower"
}

mems-allowed() {
    # Usage: mems-allowed CONTAINER
    #
    # Print Mems_allowed_list of a process in container CONTAINER of the
    # borrower, as the container sees it.
    dra-exec "$VM2" "borrower/$1" grep Mems_allowed_list /proc/self/status >&2 ||
        command-error "cannot read Mems_allowed_list in $1"
    awk '{print $2}' <<< "$COMMAND_OUTPUT"
}

lent-check() {
    # Usage: lent-check NODES LABEL
    #
    # Check that NUMA nodes NODES (a node list) are lent to container main
    # of the borrower and to nobody else: cpuset.mems of main is the DRAM
    # nodes and NODES (the node plugin wrote it through NRI), and
    # cpuset.mems of container idle is as it was at start.
    local nodes="$1" label="$2" node effective idle idle_effective
    main-mems
    if ! { effective=$(dra-container-read "$VM2" borrower main cpuset.mems.effective) &&
           idle=$(dra-container-read "$VM2" borrower idle cpuset.mems) &&
           idle_effective=$(dra-container-read "$VM2" borrower idle cpuset.mems.effective); }; then
        error "$label: cannot read the cpusets of the containers of the borrower"
    fi
    dra-nodes-eq "$MAIN_MEMS" "$DRAM_NODES,$nodes" ||
        error "$label: cpuset.mems of container main is '$MAIN_MEMS', expected $DRAM_NODES,$nodes"
    for node in ${nodes//,/ }; do
        dra-nodes-has "$effective" "$node" ||
            error "$label: node $node is not in cpuset.mems.effective of container main"
        dra-nodes-has "$(mems-allowed main)" "$node" ||
            error "$label: node $node is not in Mems_allowed_list of container main"
    done
    [ "$idle" == "$IDLE_MEMS" ] ||
        error "$label: cpuset.mems of container idle is '$idle', expected '$IDLE_MEMS'"
    if [ -z "$IDLE_MEMS" ]; then
        # An empty cpuset.mems inherits every memory node of the VM: idle
        # may use the lent nodes too, as a fallback (test12).
        for node in ${nodes//,/ }; do
            dra-nodes-has "$idle_effective" "$node" ||
                error "$label: container idle inherits its nodes, but node $node is not among them"
        done
        echo "$label: container idle inherits its memory nodes: $nodes in its effective nodes without a lend"
    else
        [ "$idle_effective" == "$IDLE_MEMS" ] ||
            error "$label: cpuset.mems.effective of container idle is not '$IDLE_MEMS'"
    fi
    echo "$label: nodes $nodes lent to container main: cpuset.mems $MAIN_MEMS"
}

not-lent-check() {
    # Usage: not-lent-check LABEL
    #
    # Check that container main of the borrower has its DRAM nodes only,
    # and no memory left on NUMA_NODE: the pages of numa-touch.py, which
    # still runs, moved off the node.
    local label="$1"
    retry-until --timeout 30 --interval 1 --message "$label: cpuset.mems of container main back to $DRAM_NODES" \
        'main-mems && dra-nodes-eq "$MAIN_MEMS" "$DRAM_NODES"' ||
        error "$label: cpuset.mems of container main is '$MAIN_MEMS', not back to $DRAM_NODES"
    dra-nodes-eq "$(mems-allowed main)" "$DRAM_NODES" || error "$label: Mems_allowed_list of container main is not back to $DRAM_NODES"
    retry-until --timeout 30 --interval 1 --message "$label: no anonymous memory of container main on node $NUMA_NODE" \
        '[ "$(dra-container-anon "$VM2" borrower main "$NUMA_NODE")" == 0 ]' ||
        error "$label: container main still has memory on node $NUMA_NODE"
    dra-touch-pages "$NUMA_NODE"
    [ "$DRA_TOUCH_PAGES" == 0 ] || error "$label: numa-touch.py still has $DRA_TOUCH_PAGES pages on node $NUMA_NODE"
    echo "$label: numa-touch.py (pid $DRA_TOUCH_PID) lives, its pages moved off node $NUMA_NODE"
}

pool-not-local() {
    # Usage: pool-not-local LABEL
    #
    # Check that the node plugin, since it started, has never published
    # pooled0 as a local memdev (device cxlmem-<serial of pooled0>).
    local n
    n=$(dra-plugin-log "$VM2" | grep -c "discovered local memory device cxlmem-${POOLED0_SERIAL#0x}")
    echo "$1: kubelet-cxl-plugin published cxlmem-${POOLED0_SERIAL#0x} $n times"
    [ "$n" == 0 ] ||
        error "$1: kubelet-cxl-plugin published the pool device pooled0 as local device cxlmem-${POOLED0_SERIAL#0x}"
}

nothing-left() {
    # Usage: nothing-left LABEL [no-borrower]
    #
    # Wait until no lease and no static claim has anything left anywhere:
    # no companion pods, no cxl-lease-* claims, no CXL regions in the VM,
    # no device of the pool attached for a claim, (unless no-borrower) no
    # leases in "cxl-request list" of the borrower, and the local device in
    # its initial state with no memory on NUMA_NODE (see
    # dra-local-initial-state).
    local label="$1"
    dra-wait "$VM2" "$label-no-companions" "pods -n $DRA_NS -l $LEASE_LABEL" "items == []" 90
    dra-wait "$VM2" "$label-no-lease-claims" "resourceclaims -n $DRA_NS" "not any(n.startswith('cxl-lease-') for n in names())" 90
    pool-cxl-wait "$VM2" "$label" \
        "regions == [] and by_serial($DRA_LOCAL_SERIAL) is not None and by_serial($DRA_LOCAL_SERIAL)['Enabled'] and by_serial($POOLED0_SERIAL) is None" 90
    retry-until --timeout 60 --message "no attachments of the pool controller" \
        '[ -z "$(dra-pool-attachments "$VM2_NAME")" ]' ||
        error "$label: the pool still has attachments: $(dra-pool-attachments "$VM2_NAME")"
    pool-host-client -o json devices pooled0 || command-error "cannot get pooled0"
    pool-assert "$COMMAND_OUTPUT" "j['state'] == 'free' and j['attachments'] in (None, [])"
    if [ "$2" != no-borrower ]; then
        dra-leases "$VM2" borrower/main
        dra-assert "$DRA_LEASES" "j == []"
    fi
    dra-local-initial-state "$VM2" "$label-local" "$NUMA_NODE"
    echo "$label: nothing left"
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

echo "### preconditions: the pool controller and the node plugin (with cxl-request) run in the cluster"
dra-build
[ -x "$DRA_REQUEST_BIN" ] || error "dra-build did not build $DRA_REQUEST_BIN: the driver in $DRA_DRIVER_SRC has no cmd/cxl-request"
[ -f "$DRA_DYNAMIC_CLASS" ] || error "the driver in $DRA_DRIVER_SRC has no DeviceClass cxl-dynamic ($DRA_DYNAMIC_CLASS)"
[ -f "$DRA_LOCAL_CLASSES" ] || error "the driver in $DRA_DRIVER_SRC has no DeviceClasses of local devices ($DRA_LOCAL_CLASSES)"
dra-install "$VM2"
dra-pull-images "$VM2" "$DRA_TOOLS_IMAGE" "$PAUSE_IMAGE"
dra-dax-tool-install "$VM2"
dra-trace-start "$VM2"

echo "### preconditions: the local device, and a pod that may want memory later"
dra-local-device "$VM2"
LD="$DRA_LOCAL_LD"             # the device in the ResourceSlices (dra-py)
LREGIONS="$DRA_LOCAL_REGIONS"  # its regions in cxl-dump (cxl-py)
NUMA_NODE=""           # the NUMA node of the device, known when memory of it is online
# Sizes in memory blocks: static-a 1, the NUMA leases 1 and half a block
# (it consumes 1), the dax leases half a block (1) and 1, static-b 2: 7
# blocks of the device at the same time.
BS="$DRA_LOCAL_BLOCK_SIZE"
dra-local-blocks-require "$VM2" "$(basename "$TOPOLOGY_DIR")" 7
STATIC_A=$BS
LEASE1=$BS
DAX1_REQ=$(( BS / 2 ))
DAX2=$BS
STATIC_B=$(( 2 * BS ))
LEASE2_REQ=$(( BS / 2 ))
RO_REQ=$(( BS / 8 ))
TOUCH_MIB=$(( BS / 2 / MiB ))
dra-json "$VM2" resourceslices
dra-assert "$COMMAND_OUTPUT" "attr($LD, 'mode') == 'none' and attr($LD, 'source') == 'local' and attr($LD, 'memoryBlockSize') == $BS"
dra-apply "$VM2" <<< "$(borrower-yaml)"
dra-pod-wait "$VM2" borrower Running 60
dra-json "$VM2" pod -n "$DRA_NS" borrower
BORROWER_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
TOKEN_CLAIM=$(dra-pod-claim "$VM2" borrower) || error "the borrower has no token claim"
dra-json "$VM2" resourceclaim -n "$DRA_NS" "$TOKEN_CLAIM"
TOKEN_CLAIM_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "j == []"
dra-nodes-eq "$(mems-allowed main)" "$DRAM_NODES" || error "container main: Mems_allowed_list is not $DRAM_NODES"
IDLE_MEMS=$(dra-container-read "$VM2" borrower idle cpuset.mems) ||
    error "cannot read cpuset.mems of container idle of the borrower"
main-mems
MAIN_MEMS0="$MAIN_MEMS"
echo "cpuset.mems of container main: '$MAIN_MEMS0', of container idle: '$IDLE_MEMS'"
[ -z "$(dra-pool-attachments "$VM2_NAME")" ] || error "the pool has attachments before any lease"

echo "### A: a pod with a static NUMA claim of the local device"
t0=$EPOCHREALTIME
dra-claim-pod "$VM2" static-a "$LOCAL_MEMORY_CLASS" "$(dra-mi "$STATIC_A")"
dra-pod-wait "$VM2" static-a Running 120
dra-local-claim-check "$VM2" static-a "$STATIC_A"
dra-local-slices-wait "$VM2" static-a "$NUMA_NODE" "numa:$STATIC_A"
NUMA_NODE=$(dra-value "$DRA_MEMDEV" "dax_slices('kmem')[0]['node']")
(( NUMA_NODE >= CPU_NODES )) || error "the NUMA slice of static-a is on node $NUMA_NODE, a CPU node"
echo "the local device is NUMA node $NUMA_NODE of the VM"
numa-slice static-a "$DRA_CLAIM_UID" "$STATIC_A"
node-size static-a "$STATIC_A"
dra-local-mode-wait "$VM2" numa-mode numa
# The region of the local device is not published as node-local CXL
# memory (cxl-node).
dra-assert "$COMMAND_OUTPUT" "not any(attr(d, 'type') == 'cxl-node' for d in devices('$DRA_LOCAL_DRIVER', '$VM2_NAME'))"
dra-mems-wait "$VM2" static-a main "$NUMA_NODE"
# The node is not lent to the borrower. (If its cpuset.mems is empty, the
# borrower inherits every memory node, the new one too.)
main-mems
[ "$MAIN_MEMS" == "$MAIN_MEMS0" ] || error "the static claim of static-a changed cpuset.mems of container main of the borrower to '$MAIN_MEMS'"

echo "### B: the running container borrows a NUMA slice of the same device"
t0=$EPOCHREALTIME
local-numa-lease "$LEASE1"
NUMA_LEASE1="$LEASE"
T_LOCAL_NUMA="$LEASE_SECONDS"
numa-slice lease-1 "$COMPANION_UID" "$LEASE1"
printf 'the local NUMA lease is Ready in %.2f s (a pool lease of test12: about 5.7 s)\n' "$T_LOCAL_NUMA"
dra-local-slices-wait "$VM2" lease-1 "$NUMA_NODE" "numa:$STATIC_A" "numa:$LEASE1"
node-size lease-1 $(( STATIC_A + LEASE1 ))
lent-check "$NUMA_NODE" B
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "[(l['lease'], l['state'], l.get('kind'), l.get('source'), l.get('serial'), int(l.get('size') or 0)) for l in j] == [('$NUMA_LEASE1', 'Ready', 'memory', 'local', '$DRA_LOCAL_SERIAL', $LEASE1)]"
# Container main uses the memory, it keeps it until D.
dra-touch-start "$VM2" borrower/main "$TOUCH_MIB" "$NUMA_NODE"
pages=$(dra-touch-log-pages "$DRA_TOUCH_LOG" "$NUMA_NODE")
[ "$pages" -ge $(( (TOUCH_MIB - 8) << 8 )) ] || error "only $pages pages of numa-touch.py are on node $NUMA_NODE"
anon=$(dra-container-anon "$VM2" borrower main "$NUMA_NODE")
echo "memory.numa_stat of container main: anon N$NUMA_NODE=$anon"
[ "${anon:-0}" -ge $(( (TOUCH_MIB - 8) * MiB )) ] ||
    error "container main has ${anon:-0} bytes anon on node $NUMA_NODE, expected >= $(( TOUCH_MIB - 8 )) MiB"
dra-mems-wait "$VM2" static-a main "$NUMA_NODE"
[ -z "$(dra-pool-attachments "$VM2_NAME")" ] || error "a local lease made the pool attach a device"

echo "### C: dax leases of the same device while the NUMA lease is Ready"
TAG1="$TAG_BASE: dax lease 1"
TAG2="$TAG_BASE: dax lease 2"
# Half a block: the slice is a whole block, and so is CXL_LEASE_SIZE.
t0=$EPOCHREALTIME
dax-lease "$(dra-mi "$DAX1_REQ")" "--source local" 'python3 /tools/dax-rw.py --fd 3 write 1M "$1"' "$TAG1"
DAX1_LEASE="$DAX_LEASE"
DAX1_PATH="$DAX_PATH"
T_DAX="$DAX_SECONDS"
[ "$DAX_SIZE $DAX_RO" == "$(dra-local-round "$DAX1_REQ") 0" ] || error "lease $DAX_LEASE: size $DAX_SIZE read-only $DAX_RO, expected $(dra-local-round "$DAX1_REQ") 0"
dax-lease "$(dra-mi "$DAX2")" "--source local" 't=$(python3 /tools/dax-rw.py --fd 3 read 1M) || exit 1; echo "before: $t"; python3 /tools/dax-rw.py --fd 3 write 1M "$1"' "$TAG2"
DAX2_LEASE="$DAX_LEASE"
DAX2_PATH="$DAX_PATH"
[ "$DAX_SIZE $DAX_RO" == "$DAX2 0" ] || error "lease $DAX_LEASE: size $DAX_SIZE read-only $DAX_RO, expected $DAX2 0"
[ "$DAX2_PATH" != "$DAX1_PATH" ] || error "both dax leases have $DAX1_PATH"
grep -qxF "before: $TAG1" <<< "$DAX_OUT" && error "lease $DAX2_LEASE sees what lease $DAX1_LEASE wrote: not a slice of its own"
companion-check "$DAX1_LEASE" "$LOCAL_DAX_CLASS" "$DAX1_REQ" "$(dra-local-round "$DAX1_REQ")" dax
companion-check "$DAX2_LEASE" "$LOCAL_DAX_CLASS" "$DAX2" "$DAX2" dax
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "sorted((l['lease'], l['state'], l.get('mode'), l.get('source'), int(l.get('size') or 0), l.get('dax')) for l in j if l['lease'] != '$NUMA_LEASE1') == sorted([('$DAX1_LEASE', 'Ready', 'dax', 'local', $(dra-local-round "$DAX1_REQ"), '$DAX1_PATH'), ('$DAX2_LEASE', 'Ready', 'dax', 'local', $DAX2, '$DAX2_PATH')])"
dra-assert "$DRA_LEASES" "[l['state'] for l in j if l['lease'] == '$NUMA_LEASE1'] == ['Ready']"
dra-local-slices-wait "$VM2" dax-leases "$NUMA_NODE" "numa:$STATIC_A" "numa:$LEASE1" "dax:$(dra-local-round "$DAX1_REQ")" "dax:$DAX2"
dra-assert "$DRA_MEMDEV" "sorted(d['name'] for d in dax_slices('device_dax')) == sorted(['${DAX1_PATH#/dev/}', '${DAX2_PATH#/dev/}'])"
# Dax slices add nothing to the node.
node-size dax-leases $(( STATIC_A + LEASE1 ))
dra-local-mode-wait "$VM2" numa-dax-mode numa+dax
lent-check "$NUMA_NODE" C
# The fds again, for other programs: each lease has what was written in it.
dax-fd-read "$DAX1_LEASE" "$TAG1"
dax-fd-read "$DAX2_LEASE" "$TAG2"

echo "### D: more NUMA memory on the node, the leases given back one by one"
t0=$EPOCHREALTIME
dra-claim-pod "$VM2" static-b "$LOCAL_MEMORY_CLASS" "$(dra-mi "$STATIC_B")"
dra-pod-wait "$VM2" static-b Running 120
dra-local-claim-check "$VM2" static-b "$STATIC_B"
numa-slice static-b "$DRA_CLAIM_UID" "$STATIC_B"
node-size static-b $(( STATIC_A + LEASE1 + STATIC_B ))
dra-mems-wait "$VM2" static-b main "$NUMA_NODE"
# A second NUMA lease of half a block: one block more on the same node,
# the node lent to the container by two leases.
t0=$EPOCHREALTIME
local-numa-lease "$LEASE2_REQ"
NUMA_LEASE2="$LEASE"
numa-slice lease-2 "$COMPANION_UID" "$(dra-local-round "$LEASE2_REQ")"
node-size lease-2 $(( STATIC_A + LEASE1 + STATIC_B + $(dra-local-round "$LEASE2_REQ") ))
dra-local-slices-wait "$VM2" lease-2 "$NUMA_NODE" "numa:$STATIC_A" "numa:$LEASE1" "dax:$(dra-local-round "$DAX1_REQ")" "dax:$DAX2" "numa:$STATIC_B" "numa:$(dra-local-round "$LEASE2_REQ")"
lent-check "$NUMA_NODE" D
# Give back the first lease: its block, and no other, goes offline, the
# pages on it move, and the node stays lent: the second lease still holds
# it.
t0=$EPOCHREALTIME
release "$NUMA_LEASE1"
node-size lease-1-released $(( STATIC_A + STATIC_B + $(dra-local-round "$LEASE2_REQ") ))
numa-slice-gone lease-1
dra-wait "$VM2" lease-1-gone "pods,resourceclaims -n $DRA_NS -l $LEASE_LABEL=$NUMA_LEASE1" "items == []" 60
lent-check "$NUMA_NODE" D-lease-1-released
dra-touch-pages "$NUMA_NODE"
echo "numa-touch.py (pid $DRA_TOUCH_PID) lives, $DRA_TOUCH_PAGES of its pages on node $NUMA_NODE"
# Give back the second lease: the node is not lent any more, the pages
# of the container move back to DRAM, the static pods keep the node.
t0=$EPOCHREALTIME
release "$NUMA_LEASE2"
node-size lease-2-released $(( STATIC_A + STATIC_B ))
numa-slice-gone lease-2
not-lent-check D-lease-2-released
dra-wait "$VM2" lease-2-gone "pods,resourceclaims -n $DRA_NS -l $LEASE_LABEL=$NUMA_LEASE2" "items == []" 60
T_GIVE_BACK=$(echo "$EPOCHREALTIME - $t0" | bc)
dra-touch-stop
dra-mems-wait "$VM2" static-a main "$NUMA_NODE"
dra-mems-wait "$VM2" static-b main "$NUMA_NODE"
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "sorted(l['lease'] for l in j) == sorted(['$DAX1_LEASE', '$DAX2_LEASE'])"
t0=$EPOCHREALTIME
dra-delete-pod "$VM2" static-a
node-size static-a-deleted "$STATIC_B"
numa-slice-gone static-a
# The dax leases still have their data.
dax-fd-read "$DAX1_LEASE" "$TAG1"
dax-fd-read "$DAX2_LEASE" "$TAG2"
dra-local-slices-wait "$VM2" static-a-deleted "$NUMA_NODE" "dax:$(dra-local-round "$DAX1_REQ")" "dax:$DAX2" "numa:$STATIC_B"
# A read-only slice (--local is --source local): the fd is opened
# read-only, a writable mapping is refused.
dax-lease "$(dra-mi "$RO_REQ")" "--local --read-only" 'python3 /tools/dax-rw.py --fd 3 check-ro 0'
RO_LEASE="$DAX_LEASE"
[ "$DAX_SIZE $DAX_RO" == "$(dra-local-round "$RO_REQ") 1" ] || error "lease $DAX_LEASE: size $DAX_SIZE read-only $DAX_RO, expected $(dra-local-round "$RO_REQ") 1"
grep -qxF "writable mapping refused: EACCES" <<< "$DAX_OUT" || error "the read-only lease $RO_LEASE could be mapped for writing"
companion-check "$RO_LEASE" "$LOCAL_DAX_CLASS" "$RO_REQ" "$(dra-local-round "$RO_REQ")" dax ro
dra-local-slices-wait "$VM2" read-only "$NUMA_NODE" "dax:$(dra-local-round "$DAX1_REQ")" "dax:$DAX2" "numa:$STATIC_B" "dax:$(dra-local-round "$RO_REQ")"
t0=$EPOCHREALTIME
dra-exec "$VM2" borrower/main "$CXL_REQUEST" release --all ||
    command-error "cxl-request release --all failed"
dra-wait "$VM2" dax-leases-gone "pods -n $DRA_NS -l $LEASE_LABEL" "items == []" 60
dra-local-slices-wait "$VM2" dax-leases-released "$NUMA_NODE" "numa:$STATIC_B"
T_DAX_RELEASE=$(echo "$EPOCHREALTIME - $t0" | bc)
dra-local-mode-wait "$VM2" numa-mode-again numa
t0=$EPOCHREALTIME
dra-delete-pod "$VM2" static-b
node-size static-b-deleted 0
numa-slice-gone static-b
nothing-left released

echo "### E: --source any: local memory first, the pool when the local device is full"
# The whole local device as one lease.
t0=$EPOCHREALTIME
numa-lease "$(dra-mi "$DRA_LOCAL_SIZE")" any
T_ANY_LOCAL="$LEASE_SECONDS"
ANY1_LEASE="$LEASE"
ANY1_NODE="$LEASE_NODE"
dra-assert "$REQ_JSON" "j.get('source') == 'local' and j.get('serial') == '$DRA_LOCAL_SERIAL' and int(j['node']) == $NUMA_NODE and int(j['size']) == $DRA_LOCAL_SIZE"
node-size any-local "$DRA_LOCAL_SIZE"
dra-pod-wait "$VM2" "cxl-lease-$ANY1_LEASE" Running 60
dra-json "$VM2" resourceclaim -n "$DRA_NS" "cxl-lease-$ANY1_LEASE"
dra-assert "$COMMAND_OUTPUT" "[s['name'] for s in j['spec']['devices']['requests'][0]['firstAvailable']] == ['local', 'pool']"
dra-assert "$COMMAND_OUTPUT" "[(r['request'], r['driver'], r['device']) for r in results()] == [('lease/local', '$DRA_LOCAL_DRIVER', '$DRA_LOCAL_DEVICE')] and consumed() == $DRA_LOCAL_SIZE"
# A LendConfig for each driver, each for its own subrequest.
ANY_CONFIGS="sorted((c['opaque']['driver'], c['opaque']['parameters']['kind'], c.get('requests')) for c in j['spec']['devices']['config'])"
dra-assert "$COMMAND_OUTPUT" "$ANY_CONFIGS == [('$DRA_POOL_DRIVER', 'LendConfig', ['lease/pool']), ('$DRA_LOCAL_DRIVER', 'LendConfig', ['lease/local'])]"
[ -z "$(dra-pool-attachments "$VM2_NAME")" ] || error "--source any with room on the local device made the pool attach a device"
# The local device has no room left: the next lease comes from the pool.
t0=$EPOCHREALTIME
numa-lease 256Mi any
T_ANY_POOL="$LEASE_SECONDS"
ANY2_LEASE="$LEASE"
ANY2_NODE="$LEASE_NODE"
dra-assert "$REQ_JSON" "j.get('source') == 'pool' and j.get('serial') == '$POOLED0_SERIAL' and int(j['size']) >= 256 * MiB"
dra-pod-wait "$VM2" "cxl-lease-$ANY2_LEASE" Running 60
dra-json "$VM2" resourceclaim -n "$DRA_NS" "cxl-lease-$ANY2_LEASE"
CLAIM_JSON="$COMMAND_OUTPUT"
dra-assert "$CLAIM_JSON" "[s['name'] for s in j['spec']['devices']['requests'][0]['firstAvailable']] == ['local', 'pool']"
dra-assert "$CLAIM_JSON" "[(r['request'], r['driver'], r['device']) for r in results()] == [('lease/pool', '$DRA_POOL_DRIVER', 'pooled0')]"
dra-assert "$CLAIM_JSON" "$ANY_CONFIGS == [('$DRA_POOL_DRIVER', 'LendConfig', ['lease/pool']), ('$DRA_LOCAL_DRIVER', 'LendConfig', ['lease/local'])]"
dra-assert "$CLAIM_JSON" "condition('$DRA_POOL_DRIVER/Attached') == 'True' and allocated_node() == '$VM2_NAME'"
ANY2_UID=$(dra-value "$CLAIM_JSON" "j['metadata']['uid']")
pool-host-client -o json devices pooled0 || command-error "cannot get pooled0"
pool-assert "$COMMAND_OUTPUT" "[(a['host'], a.get('owner'), a['state']) for a in j['attachments']] == [('$VM2_NAME', 'k8s:resourceclaim/$ANY2_UID', 'attached')]"
pool-cxl-wait "$VM2" any-two-regions \
    "len(regions) == 2 and by_serial($POOLED0_SERIAL) is not None and [(r['Node'], r['OnlineSize']) for r in $LREGIONS] == [($ANY1_NODE, $DRA_LOCAL_SIZE)] and [(r['Node'], r['OnlineSize']) for r in regions if names(r['Memories']) == [by_serial($POOLED0_SERIAL)['Name']]] == [($ANY2_NODE, $POOLED0_SIZE)]"
echo "lease $ANY1_LEASE: local node $ANY1_NODE; lease $ANY2_LEASE: pooled0, node $ANY2_NODE"
# The pool slot of pooled0 is under host bridge 0, like the local device:
# both regions are on the same NUMA node, which both leases lend, and the
# node has the memory of both.
[ "$ANY1_NODE" == "$ANY2_NODE" ] ||
    error "pooled0 is on node $ANY2_NODE, the local device on node $ANY1_NODE: two leases of one node are not exercised"
node-size any-pool $(( DRA_LOCAL_SIZE + POOLED0_SIZE )) "$DRA_LOCAL_SIZE"
dra-json "$VM2" resourceslices
dra-assert "$COMMAND_OUTPUT" "not any(attr(d, 'type') == 'cxl-node' for d in devices('$DRA_LOCAL_DRIVER', '$VM2_NAME'))"
# A pool device is never a local memdev, also while it is attached but
# not prepared yet.
pool-not-local E
lent-check "$ANY1_NODE,$ANY2_NODE" E
# Give the pool memory back: the local lease keeps its node, also when
# both regions are under host bridge 0 and so on the same node.
t0=$EPOCHREALTIME
release "$ANY2_LEASE"
pool-cxl-wait "$VM2" any-pool-released "by_serial($POOLED0_SERIAL) is None and len(regions) == 1" 90
node-size any-pool-released "$DRA_LOCAL_SIZE"
retry-until --timeout 60 --message "pooled0 detached" '[ -z "$(dra-pool-attachments "$VM2_NAME")" ]' ||
    error "pooled0 is still attached: $(dra-pool-attachments "$VM2_NAME")"
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "[(l['lease'], l['state'], l.get('source')) for l in j] == [('$ANY1_LEASE', 'Ready', 'local')]"
lent-check "$ANY1_NODE" E-local-left
t0=$EPOCHREALTIME
release "$ANY1_LEASE"
node-size any-local-released 0
nothing-left released-any

echo "### F: delete the pod while it has leases"
# A NUMA lease of local memory with memory in use, a dax lease of the
# local device and a dax lease of the pool (the default source): the
# companions are owned by the borrower, and the node plugin releases the
# leases of the pod when its token claim is unprepared.
t0=$EPOCHREALTIME
local-numa-lease "$BS"
dra-touch-start "$VM2" borrower/main "$TOUCH_MIB" "$NUMA_NODE"
dax-lease "$(dra-mi "$BS")" "--source local" 'python3 /tools/dax-rw.py --fd 3 write 1M "$1"' "$TAG1"
request memory 64Mi --dax --wait 120s
[ "$REQ_STATUS" == 0 ] || error "cxl-request memory 64Mi --dax exited $REQ_STATUS"
dra-assert "$REQ_JSON" "j.get('state') == 'Ready' and j.get('source') == 'pool' and j.get('serial') == '$POOLED0_SERIAL' and j.get('dax', '').startswith('/dev/dax')"
new-lease "$(dra-value "$REQ_JSON" "j['lease']")"
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "sorted((l['state'], l.get('source'), l.get('mode')) for l in j) == [('Ready', 'local', 'dax'), ('Ready', 'local', 'numa'), ('Ready', 'pool', 'dax')]"
[ -n "$(dra-pool-attachments "$VM2_NAME")" ] || error "the dax lease of the pool has no attachment"
dra-local-slices-wait "$VM2" three-leases "$NUMA_NODE" "numa:$BS" "dax:$BS"
node-size three-leases "$BS"
t_delete=$EPOCHREALTIME
dra-delete "$VM2" pod borrower --grace-period=2 --wait=false
dra-touch-forget    # numa-touch.py goes with the pod
dra-wait "$VM2" borrower-gone "pods -n $DRA_NS" "'borrower' not in names()" 90
nothing-left pod-deleted no-borrower
dra-wait "$VM2" token-claim-gone "resourceclaims -n $DRA_NS" "names() == []" 90
T_DELETE=$(echo "$EPOCHREALTIME - $t_delete" | bc)
vm-command "test -e $DRA_LEASE_DIR/$TOKEN_CLAIM_UID" &&
    error "the lease directory of claim $TOKEN_CLAIM is still in $DRA_LEASE_DIR"
(( $(echo "$T_DELETE <= 60" | bc) )) || error "cleanup after deleting the pod took $T_DELETE s, more than 60 s"
printf 'pod deleted with 3 active leases: everything cleaned up in %.1f s\n' "$T_DELETE"
pool-not-local F
echo "leases of the test: ${LEASES[*]}"

echo "### G: what every component did, in order"
# Every slice is whole memory blocks: the scheduler rounded every claim
# up, and the kernel's first-fit kept every slice block-aligned.
dra-local-slices-aligned "$VM2"
dra-trace-stop
dra-trace-summary
printf 'timings (s, test steps): local NUMA lease Ready %.2f (pool lease of test12: about 5.7); the last NUMA lease of the container given back until its pages left the node %.1f\n' "$T_LOCAL_NUMA" "$T_GIVE_BACK"
printf 'timings (s, test steps): local dax lease with --exec %.2f; three dax leases released until their slices were gone %.1f\n' "$T_DAX" "$T_DAX_RELEASE"
printf 'timings (s, test steps): --source any: local (the whole device) %.2f, pool %.2f; pod deleted with leases, clean %.1f\n' "$T_ANY_LOCAL" "$T_ANY_POOL" "$T_DELETE"
echo "timings (s, test steps): MemTotal of node $NUMA_NODE changed, seen by the test this long after the request, release or delete (checks included): ${NODE_TIMES[*]}"
dra-local-slice-times "$VM2"

echo "### cleanup"
dra-cleanup
dra-local-detach "$VM2"
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
