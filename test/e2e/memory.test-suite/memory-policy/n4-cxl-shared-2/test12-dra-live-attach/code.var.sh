# Attaching pooled CXL memory to a running container ("lease design")
#
# test10 and test11 give a pod CXL memory of the pool when the pod is
# created: the claim is in the pod spec, and the pod waits until the
# memory is there. A pod that runs already cannot get new claims: neither
# the scheduler nor kubelet allocate or prepare devices for a running pod.
# Here a running container asks for memory itself, and gives it back when
# it is done, while it keeps running.
#
# How it works (plan-3-cxl-live-attach/03-summary.txt):
# - The pod opts in when it is created: it claims the device "dynamic" of
#   the node's cxl.generic ResourceSlice (DeviceClass cxl-dynamic). The
#   device is a token: no memory, and any number of pods may claim it.
#   Preparing that claim, kubelet-cxl-plugin mounts a unix socket and the
#   CLI cxl-request into the container (/run/cxl/cxl.sock,
#   /usr/local/bin/cxl-request). Nothing else changes for the pod.
# - "cxl-request memory 512Mi" in the container asks the node plugin over
#   the socket. The plugin knows the caller by the socket (the pod of the
#   claim) and by the pid of the caller (the container). It creates a
#   lease: a ResourceClaim for pool memory and a companion pause pod that
#   holds the claim, both called cxl-lease-<lease id>, both owned by the
#   requesting pod. From there it is test10: the scheduler allocates a
#   device of the pool, fake-cxl-pool-controller attaches it to this node,
#   kubelet asks the node plugin to prepare the claim of the companion,
#   and the memory becomes a new NUMA node. Then the node plugin lends the
#   node to the requesting container: it adds the node to cpuset.mems of
#   that container (only), through NRI.
# - "cxl-request shared 0xc1ae0001 --exec CMD" asks for a shared device
#   (test11). The container gets no device node: the plugin opens the
#   devdax device and passes the open file descriptor over the socket.
#   cxl-request runs CMD with it as fd 3.
# - "cxl-request release LEASE|--all" gives it back: the node is removed
#   from cpuset.mems (the kernel migrates the pages to DRAM, the process
#   lives on), the companion pod and its claim are deleted, and the device
#   goes back to the pool, as in test10.
#
# What you will see: a pod that starts without any CXL memory, gets 512Mi
# of pooled memory as a new NUMA node in one container (but not in the
# other container of the same pod), puts 256 MiB of its memory there,
# gives it back without stopping, writes and reads shared CXL memory
# through a file descriptor without having any /dev/dax device, does this
# four times without leftovers, and finally is deleted with leases active:
# Kubernetes garbage collection and the node plugin clean up everything.
# At the end the trace summary of what every component did, in order.
#
# Create the VM first with test00-up of n4-cxl-shared-2. The DRA driver
# comes from ~/github.com/intel/intel-resource-drivers-for-kubernetes, or
# CXL_DRA_DRIVER_SRC; it needs cmd/cxl-request and
# deployments/cxl/pool/device-class-dynamic.yaml.

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

VM2="$OUTPUT_DIR"      # the VM and the cluster of this test
VM2_NAME="$POOL_VM2_NAME"
POOLED0_SERIAL=0xc1ee0001   # 0xc1ee....: exclusive pool devices
POOLED0_SIZE=$(( 512 << 20 ))
SHARED_SERIAL=0xc1ae0001    # 0xc1ae....: shared pool devices
SHARED_SIZE=$(( 256 << 20 ))
PYTHON_IMAGE=docker.io/library/python:3-alpine
PAUSE_IMAGE=registry.k8s.io/pause:3.10   # the image of the companion pods
TOUCH_MIB=256               # memory that the container puts on the lent node
LEASE_LABEL=cxl-pool.generic/lease
REQUESTER_LABEL=cxl-pool.generic/requester-uid
CXL_REQUEST=cxl-request     # in $PATH of the container: /usr/local/bin
TAG_BASE="dra-live-attach $(date +%Y-%m-%dT%H:%M:%S.%N)"
LEASES=()                   # every lease id of the test, all distinct
T_LEND=()                   # seconds: cxl-request memory until Ready
T_GIVE_BACK=()              # seconds: release until nothing is left
T_SHARE=()                  # seconds: cxl-request shared ... --exec write

borrower-yaml() {
    # Usage: borrower-yaml
    #
    # Pod "borrower": two idle python containers, "main" with the token
    # claim (it can ask for leases) and "idle" without (it cannot, and lent
    # memory is not lent to it). No memory limit: lent memory is charged to
    # the container, a limit would leave it no room to use the memory. The
    # claim comes from a template, so it lives and dies with the pod.
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
    image: $PYTHON_IMAGE
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "trap 'exit 0' TERM; sleep infinity & wait"]
    volumeMounts:
    - name: tools
      mountPath: /tools
    resources:
      claims:
      - name: cxl
  - name: idle
    image: $PYTHON_IMAGE
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "trap 'exit 0' TERM; sleep infinity & wait"]
    volumeMounts:
    - name: tools
      mountPath: /tools
EOF
}

nodelist-py() {
    # Usage: nodelist-py has|eq LIST ARG
    #
    # has: return 0 if node ARG is in the node list LIST ("0-1,3").
    # eq:  return 0 if the node lists LIST and ARG have the same nodes
    #      ("0-2" and "0-1,2": the kernel joins ranges).
    python3 -c '
import sys
def nodes(text):
    out = set()
    for part in text.strip().split(","):
        if part:
            lo, _, hi = part.partition("-")
            out.update(range(int(lo), int(hi or lo) + 1))
    return out
op, a, b = sys.argv[1:4]
sys.exit(0 if (int(b) in nodes(a) if op == "has" else nodes(a) == nodes(b)) else 1)' "$1" "$2" "$3"
}

nodelist-has() {
    # Usage: nodelist-has LIST NODE
    nodelist-py has "$1" "$2"
}

nodelist-eq() {
    # Usage: nodelist-eq LIST1 LIST2
    nodelist-py eq "$1" "$2"
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

cgroup-mems() {
    # Usage: cgroup-mems CONTAINER [FILE]
    #
    # Print cpuset.mems.effective (or FILE, for instance cpuset.mems) of the
    # cgroup of container CONTAINER of the borrower, read in the VM.
    dra-container-file "$VM2" borrower "$1" "${2:-cpuset.mems.effective}" >&2
    echo "$COMMAND_OUTPUT"
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

companion-check() {
    # Usage: companion-check LEASE DEVICE
    #
    # The objects of lease LEASE: the companion pod and its claim
    # cxl-lease-LEASE, both owned by the borrower, the claim allocated to
    # pool device DEVICE on this node and attached by the pool.
    local lease="$1" dev="$2" name="cxl-lease-$1" pod_json claim_json claim_uid lc
    dra-pod-wait "$VM2" "$name" Running 30
    dra-json "$VM2" pod -n "$DRA_NS" "$name"
    pod_json="$COMMAND_OUTPUT"
    dra-assert "$pod_json" "[(o['kind'], o['name'], o['uid']) for o in j['metadata']['ownerReferences']] == [('Pod', 'borrower', '$BORROWER_UID')]"
    dra-assert "$pod_json" "j['metadata']['labels']['$LEASE_LABEL'] == '$lease' and j['metadata']['labels']['$REQUESTER_LABEL'] == '$BORROWER_UID'"
    dra-assert "$pod_json" "j['spec']['nodeName'] == '$VM2_NAME'"
    dra-assert "$pod_json" "j['spec']['affinity']['nodeAffinity']['requiredDuringSchedulingIgnoredDuringExecution']['nodeSelectorTerms'][0]['matchFields'] == [{'key': 'metadata.name', 'operator': 'In', 'values': ['$VM2_NAME']}]"
    dra-assert "$pod_json" "{'operator': 'Exists'} in j['spec']['tolerations']"
    dra-assert "$pod_json" "j['spec']['resourceClaims'] == [{'name': 'lease', 'resourceClaimName': '$name'}]"
    # The companion only holds the claim: a pause container that uses
    # nothing of it, Guaranteed with 1m CPU and 8Mi memory.
    dra-assert "$pod_json" "[c['image'] for c in j['spec']['containers']] == ['$PAUSE_IMAGE'] and not j['spec']['containers'][0]['resources'].get('claims')"
    dra-assert "$pod_json" "j['spec']['containers'][0]['resources']['requests'] == j['spec']['containers'][0]['resources']['limits'] == {'cpu': '100m', 'memory': '8Mi'}"
    dra-json "$VM2" resourceclaim -n "$DRA_NS" "$name"
    claim_json="$COMMAND_OUTPUT"
    dra-claim-conditions "$VM2" "$name"
    dra-assert "$claim_json" "condition('$DRA_POOL_DRIVER/Attached') == 'True'"
    dra-assert "$claim_json" "[(r['driver'], r['device']) for r in results()] == [('$DRA_POOL_DRIVER', '$dev')] and allocated_node() == '$VM2_NAME'"
    dra-assert "$claim_json" "[r['name'] for r in j['status']['reservedFor']] == ['$name']"
    dra-assert "$claim_json" "[(o['kind'], o['name'], o['uid'], o.get('controller')) for o in j['metadata']['ownerReferences']] == [('Pod', 'borrower', '$BORROWER_UID', True)]"
    # The opaque config tells the node plugin, preparing the claim of the
    # companion, to whom it lends the device.
    lc="j['spec']['devices']['config'][0]['opaque']"
    dra-assert "$claim_json" "${lc}['driver'] == '$DRA_POOL_DRIVER' and ${lc}['parameters']['kind'] == 'LendConfig' and ${lc}['parameters']['lease'] == '$lease'"
    dra-assert "$claim_json" "${lc}['parameters']['container'] == 'main' and ${lc}['parameters']['pod'] == {'namespace': '$DRA_NS', 'name': 'borrower', 'uid': '$BORROWER_UID'}"
    claim_uid=$(dra-value "$claim_json" "j['metadata']['uid']")
    pool-host-client -o json devices "$dev" || command-error "cannot get $dev"
    pool-assert "$COMMAND_OUTPUT" "[(a['host'], a.get('owner'), a['state']) for a in j['attachments']] == [('$VM2_NAME', 'k8s:resourceclaim/$claim_uid', 'attached')]"
}

nothing-left() {
    # Usage: nothing-left LABEL [no-borrower]
    #
    # Wait until no lease has anything left anywhere: no companion pods, no
    # cxl-lease-* claims, no CXL memory devices or regions in the VM, no
    # attachments in the pool, no cxl-type3 device in qemu, and (unless
    # no-borrower) no leases in "cxl-request list" of the borrower.
    local label="$1"
    dra-wait "$VM2" "$label-no-companions" "pods -n $DRA_NS -l $LEASE_LABEL" "items == []" 90
    dra-wait "$VM2" "$label-no-lease-claims" "resourceclaims -n $DRA_NS" "not any(n.startswith('cxl-lease-') for n in names())" 90
    pool-cxl-wait "$VM2" "$label" "memdevs == [] and regions == []" 90
    retry-until --timeout 60 --message "no attachments in the pool" \
        'pool-host-client -o json attachments >/dev/null && pool-py assert "$COMMAND_OUTPUT" "j in (None, [])"' ||
        error "$label: the pool still has attachments: $COMMAND_OUTPUT"
    pool-host-client -o json devices || command-error "cannot list the devices of the pool"
    pool-assert "$COMMAND_OUTPUT" "sorted((d['name'], d['state']) for d in j if d['name'] in ('pooled0', 'shared0')) == [('pooled0', 'free'), ('shared0', 'free')]"
    pool-vm-monitor "$VM2" "info qtree -b" | grep -q 'dev: cxl-type3' &&
        error "$label: qemu of the VM still has a CXL memory device"
    if [ "$2" != "no-borrower" ]; then
        dra-leases "$VM2" borrower/main
        dra-assert "$DRA_LEASES" "j == []"
    fi
    echo "$label: nothing left"
}

touch-start() {
    # Usage: touch-start NODE
    #
    # Start numa-touch.py in the background in container main: TOUCH_MIB
    # MiB that prefer NUMA node NODE, held until touch-stop. Wait until it
    # has touched every page. TOUCH_PID is its pid in the container.
    local node="$1"
    # shellcheck disable=SC2016 # $1 is expanded by sh in the container
    dra-exec "$VM2" borrower/main sh -c 'setsid python3 /tools/numa-touch.py --hold "$1" "$2" > /tmp/numa-touch.log 2>&1 < /dev/null &' sh "$TOUCH_MIB" "$node" ||
        command-error "cannot start numa-touch.py"
    retry-until --timeout 60 --interval 1 --message "numa-touch.py has touched $TOUCH_MIB MiB" \
        'dra-vm-command-q "$VM2" "kubectl exec -n $DRA_NS borrower -c main -- cat /tmp/numa-touch.log" | grep -qE "^numa-touch: (ready|.*failed)"' ||
        error "numa-touch.py did not finish touching its memory"
    dra-exec "$VM2" borrower/main cat /tmp/numa-touch.log
    grep -q "^numa-touch: ready" <<< "$COMMAND_OUTPUT" || error "numa-touch.py failed: $COMMAND_OUTPUT"
    TOUCH_PID=$(sed -n 's/^numa-touch: pid \([0-9]*\) .*/\1/p' <<< "$COMMAND_OUTPUT")
    TOUCH_LOG="$COMMAND_OUTPUT"
}

touch-pages() {
    # Usage: touch-pages NODE
    #
    # Ask the running numa-touch.py where its pages are now (SIGUSR1).
    # TOUCH_PAGES is how many of them are on NODE, from its last "pages"
    # line. Fail the test if numa-touch.py does not run any more.
    # shellcheck disable=SC2016 # $1 is expanded by sh in the container
    dra-exec "$VM2" borrower/main sh -c 'kill -0 "$1" && kill -USR1 "$1" && sleep 1 && cat /tmp/numa-touch.log' sh "$TOUCH_PID" ||
        error "numa-touch.py (pid $TOUCH_PID) is not running any more"
    TOUCH_PAGES=$(grep '^numa-touch: pages' <<< "$COMMAND_OUTPUT" | tail -n 1 | tr ' ' '\n' | sed -n "s/^N$1=//p")
    TOUCH_PAGES=${TOUCH_PAGES:-0}
}

touch-stop() {
    # Usage: touch-stop
    [ -n "$TOUCH_PID" ] || return 0
    dra-exec "$VM2" borrower/main kill "$TOUCH_PID"
    TOUCH_PID=""
}

lend-memory() {
    # Usage: lend-memory CYCLE
    #
    # Container main asks for 512Mi of pooled memory and gets pooled0 as
    # NUMA node MEM_NODE, lease MEM_LEASE, in its cpuset.mems only. It puts
    # TOUCH_MIB MiB there (touch-start).
    local cycle="$1" t0 json anon pages
    echo "--- cycle $cycle: cxl-request memory 512Mi"
    t0=$EPOCHREALTIME
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" memory 512Mi --wait 120s ||
        command-error "cycle $cycle: cxl-request memory 512Mi failed"
    T_LEND+=("$(echo "$EPOCHREALTIME - $t0" | bc)")
    json=$(dra-last-json "$COMMAND_OUTPUT") || error "cycle $cycle: cxl-request printed no JSON response"
    dra-assert "$json" "j.get('state') == 'Ready' and j.get('kind') == 'memory' and int(j['size']) >= $POOLED0_SIZE"
    dra-assert "$json" "int(j['node']) >= $CPU_NODES"
    MEM_LEASE=$(dra-value "$json" "j['lease']")
    MEM_NODE=$(dra-value "$json" "j['node']")
    new-lease "$MEM_LEASE"
    echo "cycle $cycle: lease $MEM_LEASE, pooled memory is NUMA node $MEM_NODE"
    companion-check "$MEM_LEASE" pooled0
    # The node is the region of pooled0, onlined as system RAM.
    pool-cxl-wait "$VM2" "lent-$cycle" \
        "by_serial($POOLED0_SERIAL) is not None and [(r['Node'], r['OnlineSize']) for r in regions if names(r['Memories']) == [by_serial($POOLED0_SERIAL)['Name']]] == [($MEM_NODE, $POOLED0_SIZE)]"
    # Lent to container main: the node plugin wrote its DRAM nodes and the
    # new node to cpuset.mems of main (through NRI, so that containerd keeps
    # it), and nothing to the other container of the pod.
    nodelist-eq "$(cgroup-mems main cpuset.mems)" "$DRAM_NODES,$MEM_NODE" ||
        error "cycle $cycle: cpuset.mems of container main is not $DRAM_NODES,$MEM_NODE"
    nodelist-has "$(cgroup-mems main)" "$MEM_NODE" ||
        error "cycle $cycle: node $MEM_NODE is not in cpuset.mems.effective of container main"
    nodelist-has "$(mems-allowed main)" "$MEM_NODE" ||
        error "cycle $cycle: node $MEM_NODE is not in Mems_allowed_list of container main"
    [ "$(cgroup-mems idle cpuset.mems)" == "$IDLE_MEMS" ] ||
        error "cycle $cycle: cpuset.mems of container idle changed, expected '$IDLE_MEMS'"
    if [ -z "$IDLE_MEMS" ]; then
        # Nobody restricts the nodes of idle (an empty cpuset.mems inherits
        # every memory node of the VM): it may use the new node, too,
        # though only as a fallback, it has no CPUs. Lending is exclusive
        # only where containers have their nodes set (03-summary.txt,
        # cpuset.mems ownership; R8 of 02-option-companion-pod-dra-lend).
        nodelist-has "$(cgroup-mems idle)" "$MEM_NODE" ||
            error "cycle $cycle: container idle inherits its nodes, but node $MEM_NODE is not among them"
        echo "cycle $cycle: container idle inherits its memory nodes: node $MEM_NODE is in its effective nodes without a lend"
    else
        [ "$(cgroup-mems idle)" == "$IDLE_MEMS" ] ||
            error "cycle $cycle: cpuset.mems.effective of container idle is not '$IDLE_MEMS'"
        # The idle container cannot even prefer the node: it is not its node.
        dra-exec "$VM2" borrower/idle python3 /tools/numa-touch.py 16 "$MEM_NODE" &&
            error "cycle $cycle: container idle could allocate memory on node $MEM_NODE"
        grep -q "set_mempolicy.*Invalid argument" <<< "$COMMAND_OUTPUT" ||
            error "cycle $cycle: numa-touch.py in idle failed for another reason than an invalid node"
    fi
    dra-leases "$VM2" borrower/main
    dra-assert "$DRA_LEASES" "[(l['lease'], l['state'], l.get('kind')) for l in j] == [('$MEM_LEASE', 'Ready', 'memory')]"
    # Container main uses the memory: 256 MiB on the lent node.
    touch-start "$MEM_NODE"
    pages=$(grep '^numa-touch: pages' <<< "$TOUCH_LOG" | tr ' ' '\n' | sed -n "s/^N$MEM_NODE=//p")
    [ "${pages:-0}" -ge $(( (TOUCH_MIB - 16) << 8 )) ] ||
        error "cycle $cycle: only ${pages:-0} pages of numa-touch.py are on node $MEM_NODE"
    anon=$(dra-container-anon "$VM2" borrower main "$MEM_NODE")
    echo "cycle $cycle: memory.numa_stat of container main: anon N$MEM_NODE=$anon"
    [ "${anon:-0}" -gt $(( 200 << 20 )) ] ||
        error "cycle $cycle: container main has ${anon:-0} bytes anon on node $MEM_NODE, expected > 200 MiB"
}

give-back() {
    # Usage: give-back CYCLE
    #
    # Container main releases lease MEM_LEASE while numa-touch.py holds its
    # memory there. The pages move to DRAM, the process lives on, and the
    # device goes back to the pool.
    local cycle="$1" t0
    echo "--- cycle $cycle: cxl-request release $MEM_LEASE"
    t0=$EPOCHREALTIME
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" release "$MEM_LEASE" ||
        command-error "cycle $cycle: cxl-request release $MEM_LEASE failed"
    dra-assert "$(dra-last-json "$COMMAND_OUTPUT")" "j.get('lease') == '$MEM_LEASE' and j.get('state') == 'Released'"
    retry-until --timeout 30 --interval 1 --message "no anonymous memory of container main on node $MEM_NODE" \
        '[ "$(dra-container-anon "$VM2" borrower main "$MEM_NODE")" == 0 ]' ||
        error "cycle $cycle: container main still has memory on node $MEM_NODE after the release"
    dra-container-file "$VM2" borrower main memory.numa_stat
    touch-pages "$MEM_NODE"
    [ "$TOUCH_PAGES" == 0 ] || error "cycle $cycle: numa-touch.py still has $TOUCH_PAGES pages on node $MEM_NODE"
    echo "cycle $cycle: numa-touch.py (pid $TOUCH_PID) lives, its pages moved off node $MEM_NODE"
    nodelist-eq "$(cgroup-mems main cpuset.mems)" "$DRAM_NODES" ||
        error "cycle $cycle: cpuset.mems of container main is not back to $DRAM_NODES"
    nodelist-eq "$(mems-allowed main)" "$DRAM_NODES" ||
        error "cycle $cycle: Mems_allowed_list of container main is not back to $DRAM_NODES"
    nothing-left "released-$cycle"
    T_GIVE_BACK+=("$(echo "$EPOCHREALTIME - $t0" | bc)")
    touch-stop
}

share() {
    # Usage: share CYCLE
    #
    # Container main writes a string to the shared device through the fd
    # that the node plugin passed it, reads it back through the fd again,
    # and releases. No /dev/dax device in the container, no change in its
    # device cgroup.
    local cycle="$1" tag="$TAG_BASE, cycle $1" t0 lease shared_file found dax devices majmin
    echo "--- cycle $cycle: cxl-request shared $SHARED_SERIAL --exec dax-rw.py --fd 3 write"
    t0=$EPOCHREALTIME
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" shared "$SHARED_SERIAL" --wait 120s \
        --exec python3 /tools/dax-rw.py --fd 3 write 0 "$tag" ||
        command-error "cycle $cycle: cxl-request shared $SHARED_SERIAL --exec ... write failed"
    T_SHARE+=("$(echo "$EPOCHREALTIME - $t0" | bc)")
    dra-leases "$VM2" borrower/main
    dra-assert "$DRA_LEASES" "[(l['state'], l.get('kind'), l.get('serial')) for l in j] == [('Ready', 'shared', '$SHARED_SERIAL')]"
    lease=$(dra-value "$DRA_LEASES" "j[0]['lease']")
    new-lease "$lease"
    echo "cycle $cycle: lease $lease"
    companion-check "$lease" shared0
    # In the VM the device is a devdax region, never system RAM.
    pool-cxl-wait "$VM2" "shared-$cycle" \
        "by_serial($SHARED_SERIAL) is not None and len(regions) == 1 and regions[0]['Enabled'] and regions[0]['OnlineSize'] == 0"
    # The bytes are in the backing file of shared0 on the host.
    pool-host-client -o json devices shared0 || command-error "cannot get shared0"
    shared_file=$(pool-value "$COMMAND_OUTPUT" 'j["path"]')
    found=$(pool-file-string "$shared_file" 0)
    [ "$found" == "$tag" ] || error "cycle $cycle: host: $shared_file has '$found' at 0, expected '$tag'"
    echo "host read at 0 of $shared_file: '$found'"
    # The fd again, for another program: what it gets with it.
    # shellcheck disable=SC2016 # expanded by sh in the container
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" fd "$lease" --exec \
        sh -c 'echo "fd=$CXL_LEASE_FD lease=$CXL_LEASE size=$CXL_LEASE_SIZE dax=$CXL_LEASE_DAX"; readlink /proc/self/fd/3' ||
        command-error "cycle $cycle: cxl-request fd $lease --exec sh failed"
    dax=$(sed -n 's/.* dax=\(\S*\)$/\1/p' <<< "$COMMAND_OUTPUT")
    [[ "$dax" == /dev/dax* ]] || error "cycle $cycle: no CXL_LEASE_DAX=/dev/daxX.Y"
    grep -qx "fd=3 lease=$lease size=$SHARED_SIZE dax=$dax" <<< "$COMMAND_OUTPUT" ||
        error "cycle $cycle: the environment of --exec is not fd=3 lease=$lease size=$SHARED_SIZE dax=$dax"
    [ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "$dax" ] ||
        error "cycle $cycle: fd 3 is not $dax"
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" fd "$lease" --exec \
        python3 /tools/dax-rw.py --fd 3 read 0 ||
        command-error "cycle $cycle: cxl-request fd $lease --exec ... read failed"
    [ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "$tag" ] ||
        error "cycle $cycle: read '$(tail -n 1 <<< "$COMMAND_OUTPUT")' through the fd, expected '$tag'"
    # Nothing of this is a device of the container.
    # shellcheck disable=SC2016 # expanded by sh in the container
    dra-exec "$VM2" borrower/main sh -c 'ls /dev | grep -c "^dax" || true'
    [ "$COMMAND_OUTPUT" == 0 ] || error "cycle $cycle: container main has /dev/dax* devices"
    devices=$(dra-container-devices "$VM2" borrower main)
    echo "cycle $cycle: device cgroup of container main: $devices"
    [ "$(head -n 1 <<< "$devices")" == "$(head -n 1 <<< "$DEVICES_BEFORE")" ] ||
        error "cycle $cycle: the device rules of container main changed: $devices, before: $DEVICES_BEFORE"
    # The device cgroup still denies the device: a node made with mknod
    # cannot be opened, while the passed fd works.
    vm-command "cat /sys/bus/dax/devices/${dax#/dev/}/dev" || command-error "no sysfs entry of $dax"
    majmin="$COMMAND_OUTPUT"
    # shellcheck disable=SC2016 # expanded by sh in the container
    dra-exec "$VM2" borrower/main sh -c 'mknod "/tmp/$1" c "$2" "$3" && echo "mknod ok" && python3 /tools/dax-rw.py read "/tmp/$1" 0' sh "${dax#/dev/}" "${majmin%:*}" "${majmin#*:}" &&
        error "cycle $cycle: container main could open $dax ($majmin) through a node of its own"
    grep -q "^mknod ok" <<< "$COMMAND_OUTPUT" && grep -qE "Operation not permitted|Permission denied" <<< "$DRA_EXEC_STDERR" ||
        error "cycle $cycle: opening $dax through mknod failed for another reason than the device cgroup"
    dra-exec "$VM2" borrower/main rm -f "/tmp/${dax#/dev/}"
    echo "cycle $cycle: the device cgroup of container main denies $dax ($majmin), the fd works"
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" release --all ||
        command-error "cycle $cycle: cxl-request release --all failed"
    nothing-left "shared-released-$cycle"
}

echo "### preconditions: patched qemu, hdm_for_passthrough=on, kernel with CONFIG_FS_DAX"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"

echo "### preconditions: cxl, daxctl and cxl-dump in the VM, no CXL memory devices"
pool-vm-tools-install "$VM2"
pool-vm-reset "$VM2"
pool-cxl-dump "$VM2" no-devices
cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
CPU_NODES=$(cxl-value 'len(nodes)')
vm-command "cat /sys/devices/system/node/has_memory" || command-error "cannot read the memory nodes of the VM"
DRAM_NODES="$COMMAND_OUTPUT"

echo "### preconditions: fake-cxl-pool-server on the host, one exclusive and one shared device"
pool-server-start "
  - name: pooled0
    size: 512M
    shared: false
    pool: default
    serial: $POOLED0_SERIAL
  - name: shared0
    size: 256M
    shared: true
    pool: default
    serial: $SHARED_SERIAL"
pool-client-install "$VM2"

echo "### preconditions: the pool controller and the node plugin (with cxl-request) run in the cluster"
dra-build
[ -x "$DRA_REQUEST_BIN" ] || error "dra-build did not build $DRA_REQUEST_BIN: the driver in $DRA_DRIVER_SRC has no cmd/cxl-request"
[ -f "$DRA_DYNAMIC_CLASS" ] || error "the driver in $DRA_DRIVER_SRC has no DeviceClass cxl-dynamic ($DRA_DYNAMIC_CLASS)"
dra-install "$VM2"
dra-pull-images "$VM2" "$PYTHON_IMAGE" "$PAUSE_IMAGE"
dra-dax-tool-install "$VM2"
dra-trace-start "$VM2"

echo "### A: a pod that may want CXL memory later"
# The token device: published by the node plugin with the memory of the
# node, no capacity, any number of claims.
dra-json "$VM2" deviceclass cxl-dynamic
dra-assert "$COMMAND_OUTPUT" "'dynamic' in j['spec']['selectors'][0]['cel']['expression']"
dra-json "$VM2" resourceslices
TOKEN="device('dynamic', '$DRA_LOCAL_DRIVER')"
dra-assert "$COMMAND_OUTPUT" "$TOKEN is not None and attr($TOKEN, 'type') == 'dynamic' and ${TOKEN}.get('allowMultipleAllocations') == True and not ${TOKEN}.get('capacity')"
dra-assert "$COMMAND_OUTPUT" "any(d['name'] == 'dynamic' for d in devices('$DRA_LOCAL_DRIVER', '$VM2_NAME'))"
dra-apply "$VM2" <<< "$(borrower-yaml)"
t_apply=$EPOCHREALTIME
# No pool device is involved: the pod starts right away.
dra-pod-wait "$VM2" borrower Running 60
t_running=$EPOCHREALTIME
dra-json "$VM2" pod -n "$DRA_NS" borrower
BORROWER_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
TOKEN_CLAIM=$(dra-value "$COMMAND_OUTPUT" "j['status']['resourceClaimStatuses'][0]['resourceClaimName']")
dra-json "$VM2" resourceclaim -n "$DRA_NS" "$TOKEN_CLAIM"
dra-assert "$COMMAND_OUTPUT" "[(r['driver'], r['device']) for r in results()] == [('$DRA_LOCAL_DRIVER', 'dynamic')] and allocated_node() == '$VM2_NAME'"
TOKEN_CLAIM_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
# The socket of the claim, in the VM and in container main.
vm-command "ls -l $DRA_LEASE_DIR/$TOKEN_CLAIM_UID/ && test -S $DRA_LEASE_DIR/$TOKEN_CLAIM_UID/cxl.sock" ||
    command-error "no lease socket of claim $TOKEN_CLAIM in $DRA_LEASE_DIR/$TOKEN_CLAIM_UID"
# shellcheck disable=SC2016 # expanded by sh in the container
dra-exec "$VM2" borrower/main sh -c 'echo "$CXL_LEASE_SOCKET"; test -S /run/cxl/cxl.sock && test -x /usr/local/bin/cxl-request && echo ok' ||
    command-error "container main has no lease socket or cxl-request"
[ "$COMMAND_OUTPUT" == "/run/cxl/cxl.sock
ok" ] || error "container main: expected CXL_LEASE_SOCKET=/run/cxl/cxl.sock, a socket there, and cxl-request"
# Container idle has no claim: no socket, no CLI.
dra-exec "$VM2" borrower/idle sh -c 'test -e /run/cxl/cxl.sock || test -e /usr/local/bin/cxl-request' &&
    error "container idle has the lease socket or cxl-request, it has no claim"
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "j == []"
# The container runs on DRAM only, and the pool has given nothing.
nodelist-eq "$(mems-allowed main)" "$DRAM_NODES" || error "container main: Mems_allowed_list is not $DRAM_NODES"
IDLE_MEMS=$(cgroup-mems idle cpuset.mems)
echo "cpuset.mems of container idle: '$IDLE_MEMS'"
DEVICES_BEFORE=$(dra-container-devices "$VM2" borrower main) ||
    error "cannot read the device cgroup of container main"
echo "device cgroup of container main: $DEVICES_BEFORE"
pool-host-client -o json attachments || command-error "cannot list the attachments of the pool"
pool-assert "$COMMAND_OUTPUT" "j in (None, [])"
pool-cxl-dump "$VM2" borrower-running
cxl-assert 'memdevs == [] and regions == []'

echo "### B: ask for 512Mi of pooled memory from inside the container"
lend-memory 1

echo "### C: give it back while using it"
give-back 1

echo "### D: shared memory as a file descriptor"
share 1

echo "### E: three more times, with new leases and nothing left behind"
for cycle in 2 3 4; do
    lend-memory "$cycle"
    give-back "$cycle"
    share "$cycle"
done
echo "leases of the cycles: ${LEASES[*]}"
[ "${#LEASES[@]}" == 8 ] || error "expected 8 distinct leases, got ${#LEASES[*]}"

echo "### F: delete the pod while it has leases"
# One memory lease with memory in use, one shared lease. Kubernetes
# garbage collection deletes the companions (owned by the borrower), the
# node plugin releases the leases of the pod when its token claim is
# unprepared: either way everything goes back to the pool.
lend-memory 5
dra-exec "$VM2" borrower/main "$CXL_REQUEST" shared "$SHARED_SERIAL" --wait 120s ||
    command-error "cxl-request shared $SHARED_SERIAL failed"
SHARED_JSON=$(dra-last-json "$COMMAND_OUTPUT") || error "cxl-request shared printed no JSON response"
dra-assert "$SHARED_JSON" "j.get('state') == 'Ready' and j.get('kind') == 'shared' and j.get('serial') == '$SHARED_SERIAL' and j.get('dax', '').startswith('/dev/dax')"
new-lease "$(dra-value "$SHARED_JSON" "j['lease']")"
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "sorted(l['state'] for l in j) == ['Ready', 'Ready'] and sorted(l.get('kind') for l in j) == ['memory', 'shared']"
pool-host-client -o json attachments || command-error "cannot list the attachments of the pool"
pool-assert "$COMMAND_OUTPUT" "sorted(a['device'] for a in j) == ['pooled0', 'shared0']"
t_delete=$EPOCHREALTIME
dra-delete "$VM2" pod borrower --grace-period=2 --wait=false
TOUCH_PID=""
dra-wait "$VM2" borrower-gone "pods -n $DRA_NS" "'borrower' not in names()" 90
nothing-left pod-deleted no-borrower
dra-wait "$VM2" token-claim-gone "resourceclaims -n $DRA_NS" "names() == []" 90
t_clean=$EPOCHREALTIME
vm-command "test -e $DRA_LEASE_DIR/$TOKEN_CLAIM_UID" &&
    error "the lease directory of claim $TOKEN_CLAIM is still in $DRA_LEASE_DIR"
T_DELETE=$(echo "$t_clean - $t_delete" | bc)
(( $(echo "$T_DELETE <= 90" | bc) )) || error "cleanup after deleting the pod took $T_DELETE s, more than 90 s"
echo "pod deleted with 2 active leases: everything cleaned up in $T_DELETE s"
vm-command "journalctl --no-pager -o cat -u kubelet-cxl-plugin | grep -iE 'lease|lend|revok' | tail -n 40"

echo "### G: what every component did, in order"
dra-trace-stop
dra-trace-summary
printf 'timings (test steps, 1 s polling): borrower Running %.1f s after apply; deleted with leases, clean %s s after the delete\n' \
    "$(echo "$t_running - $t_apply" | bc)" "$T_DELETE"
echo "timings: cxl-request memory until Ready (s): ${T_LEND[*]}"
echo "timings: release until nothing is left (s): ${T_GIVE_BACK[*]}"
echo "timings: cxl-request shared --exec write (s): ${T_SHARE[*]}"

echo "### cleanup"
dra-cleanup
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
