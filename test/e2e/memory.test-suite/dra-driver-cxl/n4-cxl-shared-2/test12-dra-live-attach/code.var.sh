# Attaching pooled CXL memory to a running container (leases)
#
# test10 and test11 give a pod CXL memory of the pool when the pod is
# created: the claim is in the pod spec, and the pod waits until the
# memory is there. A pod that runs already cannot get new claims: neither
# the scheduler nor kubelet allocate or prepare devices for a running pod.
# Here a running container asks for memory itself, and gives it back when
# it is done, while it keeps running.
#
# How it works (docs/memory/cxl/leases.md):
# - The pod opts in when it is created: it claims the device "lease" of
#   the node's cxl.nri.io ResourceSlice (DeviceClass cxl-lease). The
#   device has no memory, and any number of pods may claim it. Preparing
#   that claim, nri-dra-driver-cxl mounts a unix socket and the CLI
#   cxl-request into the container (/run/cxl/cxl.sock,
#   /usr/local/bin/cxl-request). Nothing else changes for the pod.
# - "cxl-request request --source pool --size 512Mi" in the container
#   asks the node plugin over the socket. The plugin knows the caller by
#   the socket (the pod of the claim) and by the pid of the caller (the
#   container). It creates a lease: a ResourceClaim for pool memory and a
#   companion pause pod that holds the claim, both called
#   cxl-lease-<lease id>, both owned by the requesting pod and labeled
#   cxl.nri.io/lease=<lease id>. From there it is test10: the scheduler
#   allocates a device of the pool, fake-cxl-pool-controller attaches it
#   to this node, kubelet asks the node plugin to prepare the claim of the
#   companion, and the memory becomes a new NUMA node. Then the node
#   plugin lends the node to the requesting container: it adds the node
#   to cpuset.mems of that container (only), through NRI.
#   "cxl-request env --lease ID" prints the environment that a claim of
#   the same memory gives a container (CXL_<KEY>_NODE and the rest).
# - "cxl-request request --serial 0xc1ae0001 --shared --exec CMD" joins a
#   shared device (test11). The container gets no device node: the plugin
#   opens the devdax device and passes the open file descriptor over the
#   socket. cxl-request runs CMD with it as fd 3, CXL_<KEY>_FD=3.
# - "cxl-request release --lease ID" (or --all) gives it back: the node is
#   removed from cpuset.mems (the kernel migrates the pages to DRAM, the
#   process lives on), the companion pod and its claim are deleted, and
#   the device goes back to the pool, as in test10.
#
# What you will see: a pod that starts without any CXL memory, requests
# that cxl-request and the node plugin refuse, 512Mi of pooled memory as
# a new NUMA node in one container (but not in the other container of the
# same pod), 256 MiB of its memory there, the environment of the lease,
# which a claim of the same device gives too, the memory given back
# without stopping, shared CXL memory written and read through a file
# descriptor without any /dev/dax device, all this four times without
# leftovers, and finally the pod deleted with leases active: Kubernetes
# garbage collection and the node plugin clean up everything. At the end
# the trace summary of what every component did, in order.
#
# Create the VM first with test00-up of n4-cxl-shared-2. The DRA driver
# comes from its image, which has cxl-request too, build it first:
#   make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

VM2="$OUTPUT_DIR"      # the VM and the cluster of this test
VM2_NAME="$POOL_VM2_NAME"
POOLED0_SERIAL=0xc1ee0001   # 0xc1ee....: exclusive pool devices
POOLED0_HEX=C1EE0001        # the serial in environment variable names
POOLED0_SIZE=$(( 512 << 20 ))
SHARED_SERIAL=0xc1ae0001    # 0xc1ae....: shared pool devices
SHARED_HEX=C1AE0001
SHARED_SIZE=$(( 256 << 20 ))
PYTHON_IMAGE=docker.io/library/python:3-alpine
PAUSE_IMAGE=registry.k8s.io/pause:3.10   # the image of the companion pods
TOUCH_MIB=256               # memory that the container puts on the lent node
CXL_REQUEST=cxl-request     # in $PATH of the container: /usr/local/bin
TAG_BASE="dra-live-attach $(date +%Y-%m-%dT%H:%M:%S.%N)"
LEASES=()                   # every lease id of the test, all distinct
LEASE_ENV=""                # cxl-request env of the first lease of pooled0
LEASE_NODE=""               # and its NUMA node
T_LEND=()                   # seconds: cxl-request request until Ready
T_GIVE_BACK=()              # seconds: release until nothing is left
T_SHARE=()                  # seconds: cxl-request request --shared ... --exec write

borrower-yaml() {
    # Usage: borrower-yaml
    #
    # Pod "borrower": two idle python containers, "main" with the lease
    # claim (it can ask for leases) and "idle" without (it cannot, and lent
    # memory is not lent to it). No memory limit: lent memory is charged to
    # the container, a limit would leave it no room to use the memory. The
    # claim comes from a template, so it lives and dies with the pod.
    cat <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: cxl-lease
spec:
  spec:
    devices:
      requests:
      - name: lease
        exactly:
          deviceClassName: cxl-lease
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
    resourceClaimTemplateName: cxl-lease
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

refused() {
    # Usage: refused STATUS TEXT ARGS...
    #
    # Run "cxl-request ARGS..." in container main of the borrower, and fail
    # unless it exits with STATUS and prints TEXT (a fixed string).
    local status="$1" text="$2"
    shift 2
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" "$@"
    [ "$COMMAND_STATUS" == "$status" ] || error "cxl-request $* exited $COMMAND_STATUS, expected $status"
    grep -qF -- "$text" <<< "$COMMAND_OUTPUT
$DRA_EXEC_STDERR" || error "cxl-request $* did not print '$text'"
}

companion-check() {
    # Usage: companion-check LEASE DEVICE CLASS MODE
    #
    # The objects of lease LEASE: the companion pod and its claim
    # cxl-lease-LEASE, both owned by the borrower, labeled and annotated
    # with the lease and its requester; the claim asks for a device of
    # DeviceClass CLASS, has a DeviceConfig of mode MODE for the pool
    # driver and no other config, and is allocated to pool device DEVICE on
    # this node and attached by the pool. CLAIM_JSON is the claim.
    local lease="$1" dev="$2" class="$3" mode="$4" name="cxl-lease-$1" pod_json claim_uid
    dra-pod-wait "$VM2" "$name" Running 30
    dra-json "$VM2" pod -n "$DRA_NS" "$name"
    pod_json="$COMMAND_OUTPUT"
    dra-assert "$pod_json" "[(o['kind'], o['name'], o['uid']) for o in j['metadata']['ownerReferences']] == [('Pod', 'borrower', '$BORROWER_UID')]"
    dra-companion-meta-check "$pod_json" "$lease" "$BORROWER_UID" "$VM2_NAME" "$DRA_NS/borrower/main"
    dra-assert "$pod_json" "j['spec']['nodeName'] == '$VM2_NAME'"
    dra-assert "$pod_json" "j['spec']['affinity']['nodeAffinity']['requiredDuringSchedulingIgnoredDuringExecution']['nodeSelectorTerms'][0]['matchFields'] == [{'key': 'metadata.name', 'operator': 'In', 'values': ['$VM2_NAME']}]"
    dra-assert "$pod_json" "{'operator': 'Exists'} in j['spec']['tolerations']"
    dra-assert "$pod_json" "j['spec']['resourceClaims'] == [{'name': 'lease', 'resourceClaimName': '$name'}]"
    # The companion only holds the claim: a pause container that uses
    # nothing of it, Guaranteed with 100m CPU and 16Mi memory.
    dra-assert "$pod_json" "[c['image'] for c in j['spec']['containers']] == ['$PAUSE_IMAGE'] and not j['spec']['containers'][0]['resources'].get('claims')"
    dra-assert "$pod_json" "j['spec']['containers'][0]['resources']['requests'] == j['spec']['containers'][0]['resources']['limits'] == {'cpu': '100m', 'memory': '16Mi'}"
    dra-json "$VM2" resourceclaim -n "$DRA_NS" "$name"
    CLAIM_JSON="$COMMAND_OUTPUT"
    dra-claim-conditions "$VM2" "$name"
    dra-assert "$CLAIM_JSON" "condition('$DRA_POOL_DRIVER/Attached') == 'True'"
    dra-assert "$CLAIM_JSON" "[(r['driver'], r['device']) for r in results()] == [('$DRA_POOL_DRIVER', '$dev')] and allocated_node() == '$VM2_NAME'"
    dra-assert "$CLAIM_JSON" "[r['name'] for r in j['status']['reservedFor']] == ['$name']"
    dra-assert "$CLAIM_JSON" "[(o['kind'], o['name'], o['uid'], o.get('controller')) for o in j['metadata']['ownerReferences']] == [('Pod', 'borrower', '$BORROWER_UID', True)]"
    # The node plugin knows the claim of the companion by its label, the
    # requester by the lease. The claim says what was asked: the class and
    # the mode.
    dra-companion-meta-check "$CLAIM_JSON" "$lease" "$BORROWER_UID" "$VM2_NAME" "$DRA_NS/borrower/main"
    dra-assert "$CLAIM_JSON" "[s['deviceClassName'] for s in subrequests()] == ['$class']"
    dra-assert "$CLAIM_JSON" "[(c['driver'], c['parameters'].get('apiVersion'), c['parameters'].get('kind'), c['parameters'].get('mode'), bool(c['parameters'].get('readOnly'))) for c in configs()] == [('$DRA_POOL_DRIVER', '$DRA_POOL_DRIVER/v1alpha1', 'DeviceConfig', '$mode', False)]"
    claim_uid=$(dra-value "$CLAIM_JSON" "j['metadata']['uid']")
    pool-host-client -o json devices "$dev" || command-error "cannot get $dev"
    pool-assert "$COMMAND_OUTPUT" "[(a['host'], a.get('owner'), a['state']) for a in j['attachments']] == [('$VM2_NAME', 'k8s:resourceclaim/$claim_uid', 'attached')]"
    # The companion pod uses nothing of its claim: no CDI device.
    [ -z "$(dra-cdi-devices-with "$VM2" "$claim_uid")" ] ||
        error "lease $lease: the companion claim has CDI devices: $(dra-cdi-devices-with "$VM2" "$claim_uid")"
}

nothing-left() {
    # Usage: nothing-left LABEL [no-borrower]
    #
    # Wait until no lease has anything left anywhere: no companion pods, no
    # cxl-lease-* claims, no CXL memory devices or regions in the VM, no
    # attachments in the pool, no cxl-type3 device in qemu, and (unless
    # no-borrower) no leases in "cxl-request list" of the borrower.
    local label="$1"
    dra-wait "$VM2" "$label-no-companions" "pods -n $DRA_NS -l $DRA_LEASE_LABEL" "items == []" 90
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
    # TOUCH_MIB MiB there (touch-start). The lease has the environment of
    # pooled0 (lease-env-check).
    local cycle="$1" t0 json anon pages
    echo "--- cycle $cycle: cxl-request request --source pool --size 512Mi"
    t0=$EPOCHREALTIME
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" request --source pool --size 512Mi --wait 120s ||
        command-error "cycle $cycle: cxl-request request --source pool --size 512Mi failed"
    T_LEND+=("$(echo "$EPOCHREALTIME - $t0" | bc)")
    json=$(dra-last-json "$COMMAND_OUTPUT") || error "cycle $cycle: cxl-request printed no JSON response"
    # Exclusive, read-write NUMA memory: the defaults.
    dra-assert "$json" "j.get('state') == 'Ready' and j.get('source') == 'pool' and j.get('mode') == 'numa' and not j.get('shared') and not j.get('readOnly')"
    dra-assert "$json" "j.get('serial') == '$POOLED0_SERIAL' and int(j['size']) == $POOLED0_SIZE and int(j['node']) >= $CPU_NODES and not j.get('dax')"
    MEM_LEASE=$(dra-value "$json" "j['lease']")
    MEM_NODE=$(dra-value "$json" "j['node']")
    new-lease "$MEM_LEASE"
    echo "cycle $cycle: lease $MEM_LEASE, pooled memory is NUMA node $MEM_NODE"
    # The response has the environment that a claim of pooled0 gives.
    dra-assert "$json" "j.get('env') == {'CXL_${POOLED0_HEX}_SERIAL': '$POOLED0_SERIAL', 'CXL_${POOLED0_HEX}_SHARED': '0', 'CXL_${POOLED0_HEX}_MODE': 'numa', 'CXL_${POOLED0_HEX}_SIZE': '$POOLED0_SIZE', 'CXL_${POOLED0_HEX}_NODE': '$MEM_NODE'}"
    companion-check "$MEM_LEASE" pooled0 cxl-pool numa
    dra-assert "$CLAIM_JSON" "[quantity(s['capacity']['requests']['memory']) for s in subrequests()] == [$POOLED0_SIZE]"
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
    dra-assert "$DRA_LEASES" "[(l['lease'], l['state'], l.get('source'), l.get('mode'), bool(l.get('shared'))) for l in j] == [('$MEM_LEASE', 'Ready', 'pool', 'numa', False)]"
    lease-env-check "$cycle"
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

lease-env-check() {
    # Usage: lease-env-check CYCLE
    #
    # The environment of the NUMA lease MEM_LEASE of pooled0: "cxl-request
    # env" prints it, sorted: the variables of pooled0 that a claim gives
    # (test10) and CXL_LEASE; "env --exec" runs a program with them, no fd;
    # "fd" refuses a NUMA lease. LEASE_ENV and LEASE_NODE are those of the
    # first cycle.
    local cycle="$1" key="CXL_${POOLED0_HEX}_" script
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" env --lease "$MEM_LEASE" ||
        command-error "cycle $cycle: cxl-request env --lease $MEM_LEASE failed"
    dra-env-assert "lease $MEM_LEASE" "$COMMAND_OUTPUT" "$POOLED0_HEX" \
        SERIAL="$POOLED0_SERIAL" SHARED=0 MODE=numa SIZE="$POOLED0_SIZE" NODE="$MEM_NODE"
    [ "$COMMAND_OUTPUT" == "$(LC_ALL=C sort <<< "$COMMAND_OUTPUT")" ] ||
        error "cycle $cycle: cxl-request env did not print sorted KEY=VALUE lines"
    grep -qx "CXL_LEASE=$MEM_LEASE" <<< "$COMMAND_OUTPUT" ||
        error "cycle $cycle: cxl-request env did not print CXL_LEASE=$MEM_LEASE"
    [ "$(grep -c . <<< "$COMMAND_OUTPUT")" == 6 ] ||
        error "cycle $cycle: cxl-request env printed more than the environment of pooled0 and CXL_LEASE"
    [ -n "$LEASE_ENV" ] || { LEASE_ENV=$(grep "^$key" <<< "$COMMAND_OUTPUT"); LEASE_NODE="$MEM_NODE"; }
    # The script, expanded by sh in the container:
    # echo "lease=$CXL_LEASE node=$CXL_<KEY>_NODE size=$CXL_<KEY>_SIZE fd=${CXL_<KEY>_FD:-none}"
    script="echo \"lease=\$CXL_LEASE node=\$${key}NODE size=\$${key}SIZE fd=\${${key}FD:-none}\""
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" env --lease "$MEM_LEASE" --exec sh -c "$script" ||
        command-error "cycle $cycle: cxl-request env --lease $MEM_LEASE --exec failed"
    [ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "lease=$MEM_LEASE node=$MEM_NODE size=$POOLED0_SIZE fd=none" ] ||
        error "cycle $cycle: the program of env --exec does not have lease=$MEM_LEASE node=$MEM_NODE size=$POOLED0_SIZE and no fd"
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" fd --lease "$MEM_LEASE" --exec true &&
        error "cycle $cycle: cxl-request fd of the NUMA lease $MEM_LEASE succeeded"
    [ "$COMMAND_STATUS" == 3 ] ||
        error "cycle $cycle: cxl-request fd of the NUMA lease $MEM_LEASE exited $COMMAND_STATUS, expected 3"
    grep -qF "lease $MEM_LEASE is not a dax lease; use env" <<< "$COMMAND_OUTPUT
$DRA_EXEC_STDERR" ||
        error "cycle $cycle: cxl-request fd of the NUMA lease $MEM_LEASE did not print 'lease $MEM_LEASE is not a dax lease; use env'"
}

give-back() {
    # Usage: give-back CYCLE
    #
    # Container main releases lease MEM_LEASE while numa-touch.py holds its
    # memory there. The pages move to DRAM, the process lives on, and the
    # device goes back to the pool.
    local cycle="$1" t0
    echo "--- cycle $cycle: cxl-request release --lease $MEM_LEASE"
    t0=$EPOCHREALTIME
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" release --lease "$MEM_LEASE" ||
        command-error "cycle $cycle: cxl-request release --lease $MEM_LEASE failed"
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
    # Container main joins the shared device (one of its hosts) and writes
    # a string to it through the fd that the node plugin passed it, reads
    # it back through the fd again, and releases. No /dev/dax device in the
    # container, no change in its device cgroup.
    local cycle="$1" tag="$TAG_BASE, cycle $1" t0 lease lease_env shared_file found dax devices majmin
    echo "--- cycle $cycle: cxl-request request --serial $SHARED_SERIAL --shared --exec dax-rw.py --fd 3 write"
    t0=$EPOCHREALTIME
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" request --serial "$SHARED_SERIAL" --shared --wait 120s \
        --exec python3 /tools/dax-rw.py --fd 3 write 0 "$tag" ||
        command-error "cycle $cycle: cxl-request request --serial $SHARED_SERIAL --shared --exec ... write failed"
    T_SHARE+=("$(echo "$EPOCHREALTIME - $t0" | bc)")
    dra-leases "$VM2" borrower/main
    # --shared: mode dax, the default for shared memory, read-write.
    dra-assert "$DRA_LEASES" "[(l['state'], l.get('source'), l.get('mode'), bool(l.get('shared')), bool(l.get('readOnly')), l.get('serial')) for l in j] == [('Ready', 'pool', 'dax', True, False, '$SHARED_SERIAL')]"
    lease=$(dra-value "$DRA_LEASES" "j[0]['lease']")
    new-lease "$lease"
    echo "cycle $cycle: lease $lease"
    companion-check "$lease" shared0 cxl-pool-shared dax
    # One host of the device: no capacity request, the default of the class.
    dra-assert "$CLAIM_JSON" "[s.get('capacity') for s in subrequests()] == [None] and j['status']['allocation']['devices']['results'][0].get('consumedCapacity', {}).get('hosts') == '1'"
    # In the VM the device is a devdax region, never system RAM.
    pool-cxl-wait "$VM2" "shared-$cycle" \
        "by_serial($SHARED_SERIAL) is not None and len(regions) == 1 and regions[0]['Enabled'] and regions[0]['OnlineSize'] == 0"
    # The bytes are in the backing file of shared0 on the host.
    pool-host-client -o json devices shared0 || command-error "cannot get shared0"
    shared_file=$(pool-value "$COMMAND_OUTPUT" 'j["path"]')
    found=$(pool-file-string "$shared_file" 0)
    [ "$found" == "$tag" ] || error "cycle $cycle: host: $shared_file has '$found' at 0, expected '$tag'"
    echo "host read at 0 of $shared_file: '$found'"
    # The environment of the lease names the dax device of the VM, as a
    # claim of shared0 would (test11): read-write, shared.
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" env --lease "$lease" ||
        command-error "cycle $cycle: cxl-request env --lease $lease failed"
    lease_env="$COMMAND_OUTPUT"
    dra-env-assert "lease $lease" "$lease_env" "$SHARED_HEX" \
        SERIAL="$SHARED_SERIAL" SHARED=1 MODE=dax SIZE="$SHARED_SIZE" "DAX=/dev/dax*" READONLY=0
    dax=$(dra-env-value "$lease_env" "CXL_${SHARED_HEX}_DAX")
    dra-assert "$DRA_LEASES" "j[0].get('dax') == '$dax'"
    # The fd again, for another program: its environment has the fd 3
    # instead of the device, and the lease.
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" fd --lease "$lease" --exec \
        sh -c 'env | grep ^CXL_ | sort; readlink /proc/self/fd/3' ||
        command-error "cycle $cycle: cxl-request fd --lease $lease --exec sh failed"
    dra-env-assert "fd --lease $lease --exec" "$COMMAND_OUTPUT" "$SHARED_HEX" \
        SERIAL="$SHARED_SERIAL" SHARED=1 MODE=dax SIZE="$SHARED_SIZE" FD=3 READONLY=0
    grep -qx "CXL_LEASE=$lease" <<< "$COMMAND_OUTPUT" ||
        error "cycle $cycle: the environment of fd --exec has no CXL_LEASE=$lease"
    [ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "$dax" ] ||
        error "cycle $cycle: fd 3 is not $dax"
    dra-exec "$VM2" borrower/main "$CXL_REQUEST" fd --lease "$lease" --exec \
        python3 /tools/dax-rw.py --fd 3 read 0 ||
        command-error "cycle $cycle: cxl-request fd --lease $lease --exec ... read failed"
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

echo "### preconditions: fake-cxl-pool-server on the host, one exclusive and one shared device"
pool-server-start "
  - name: pooled0
    size: 512Mi
    shared: false
    pool: default
    serial: $POOLED0_SERIAL
  - name: shared0
    size: 256Mi
    shared: true
    pool: default
    serial: $SHARED_SERIAL"
pool-client-install "$VM2"

echo "### preconditions: the pool controller and the node plugin (with cxl-request) run in the cluster"
dra-build
dra-install "$VM2"
dra-pull-images "$VM2" "$PYTHON_IMAGE" "$PAUSE_IMAGE"
dra-dax-tool-install "$VM2"
dra-trace-start "$VM2"

echo "### A: a pod that may want CXL memory later"
# The lease device: published by the node plugin with the memory of the
# node, no capacity, any number of claims, only a type.
dra-json "$VM2" deviceclass cxl-lease
dra-assert "$COMMAND_OUTPUT" "'\"lease\"' in j['spec']['selectors'][0]['cel']['expression'] and '\"$DRA_LOCAL_DRIVER\"' in j['spec']['selectors'][0]['cel']['expression']"
dra-json "$VM2" resourceslices
LEASE_DEV="device('lease', '$DRA_LOCAL_DRIVER', '$VM2_NAME')"
dra-assert "$COMMAND_OUTPUT" "$LEASE_DEV is not None and attr($LEASE_DEV, 'type') == 'lease' and ${LEASE_DEV}.get('allowMultipleAllocations') == True and not ${LEASE_DEV}.get('capacity')"
dra-assert "$COMMAND_OUTPUT" "[k.split('/')[-1] for k in ${LEASE_DEV}['attributes']] == ['type']"
dra-apply "$VM2" <<< "$(borrower-yaml)"
t_apply=$EPOCHREALTIME
# No pool device is involved: the pod starts right away.
dra-pod-wait "$VM2" borrower Running 60
t_running=$EPOCHREALTIME
dra-json "$VM2" pod -n "$DRA_NS" borrower
BORROWER_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
LEASE_CLAIM=$(dra-value "$COMMAND_OUTPUT" "j['status']['resourceClaimStatuses'][0]['resourceClaimName']")
dra-json "$VM2" resourceclaim -n "$DRA_NS" "$LEASE_CLAIM"
dra-assert "$COMMAND_OUTPUT" "[(r['driver'], r['device']) for r in results()] == [('$DRA_LOCAL_DRIVER', 'lease')] and allocated_node() == '$VM2_NAME'"
LEASE_CLAIM_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
# The socket of the claim, in the VM and in container main.
vm-command "ls -l $DRA_LEASE_DIR/$LEASE_CLAIM_UID/ && test -S $DRA_LEASE_DIR/$LEASE_CLAIM_UID/cxl.sock" ||
    command-error "no lease socket of claim $LEASE_CLAIM in $DRA_LEASE_DIR/$LEASE_CLAIM_UID"
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

echo "### A2: requests that cxl-request refuses, and one that the node plugin refuses"
# cxl-request checks its options before it connects (exit status 2), the
# node plugin checks them again and knows the devices: pooled0 is not
# shared. Nothing of a refused request is left.
refused 2 "size or serial is required" request
refused 2 'invalid source "remote" (local or pool)' request --source remote --size 64Mi
refused 2 'invalid mode "memory" (numa or dax)' request --mode memory --size 64Mi
refused 2 "shared memory is never onlined as RAM: use mode dax" request --shared --mode numa --size 64Mi
refused 2 "local devices are not shareable; share a ResourceClaim between pods instead" request --shared --source local --size 64Mi
refused 2 "readOnly needs mode dax" request --size 64Mi --read-only
refused 2 'invalid serial "pooled0"' request --serial pooled0
refused 2 "--exec is for request, fd and env" list --exec true
refused 2 "fd needs --exec" fd --lease 0123abcd
refused 2 "release takes --lease ID or --all" release
refused 2 "release takes --lease ID or --all" release --lease 0123abcd --all
refused 2 'invalid wait "soon"' request --size 64Mi --wait soon
refused 1 "device $POOLED0_SERIAL: not shareable" request --serial "$POOLED0_SERIAL" --shared
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "j == []"
dra-json "$VM2" pods -n "$DRA_NS" -l "$DRA_LEASE_LABEL"
dra-assert "$COMMAND_OUTPUT" "items == []"

echo "### B: ask for 512Mi of pooled memory from inside the container"
lend-memory 1

echo "### C: give it back while using it"
give-back 1

echo "### C2: a claim of the same memory gives the same environment"
# A pod with a claim of pooled0 from its creation (test10): its container
# has the variables that cxl-request env printed for the lease of pooled0,
# each with the same value, the NUMA node that of the claim, and the
# marker of the claim.
dra-apply "$VM2" <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: pooled-memory
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool
        capacity:
          requests:
            memory: 512Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: claimer
spec:
  terminationGracePeriodSeconds: 2
  restartPolicy: Never
  resourceClaims:
  - name: mem
    resourceClaimName: pooled-memory
  containers:
  - name: main
    image: $PYTHON_IMAGE
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "env | grep ^CXL_ | sort; trap 'exit 0' TERM; sleep infinity & wait"]
    resources:
      claims:
      - name: mem
EOF
dra-pod-wait "$VM2" claimer Running 120
pool-cxl-wait "$VM2" claimer \
    "by_serial($POOLED0_SERIAL) is not None and [r['OnlineSize'] for r in regions if names(r['Memories']) == [by_serial($POOLED0_SERIAL)['Name']]] == [$POOLED0_SIZE]"
CLAIM_NODE=$(cxl-value "[r['Node'] for r in regions if names(r['Memories']) == [by_serial($POOLED0_SERIAL)['Name']]][0]")
dra-json "$VM2" resourceclaim -n "$DRA_NS" pooled-memory
CLAIMER_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
dra-kubectl "$VM2" "logs -n $DRA_NS claimer" || command-error "cannot get the log of claimer"
grep -qx "CXL_CLAIM_${CLAIMER_UID//-/_}=1" <<< "$COMMAND_OUTPUT" ||
    error "claimer has no claim marker CXL_CLAIM_${CLAIMER_UID//-/_}=1"
[ "$(grep -c '^CXL_' <<< "$COMMAND_OUTPUT")" == 6 ] ||
    error "claimer has other CXL_ variables than the five of $POOLED0_SERIAL and the claim marker"
CLAIMER_ENV=$(grep "^CXL_${POOLED0_HEX}_" <<< "$COMMAND_OUTPUT")
dra-env-assert claimer "$CLAIMER_ENV" "$POOLED0_HEX" \
    SERIAL="$POOLED0_SERIAL" SHARED=0 MODE=numa SIZE="$POOLED0_SIZE" NODE="$CLAIM_NODE"
[ "$(grep -v "_NODE=" <<< "$CLAIMER_ENV")" == "$(grep -v "_NODE=" <<< "$LEASE_ENV")" ] ||
    error "the claim of pooled0 gives
$CLAIMER_ENV
the lease of pooled0 gave (on node $LEASE_NODE)
$LEASE_ENV"
echo "the claim (node $CLAIM_NODE) and the lease (node $LEASE_NODE) of pooled0 have the same environment"
dra-delete "$VM2" pod claimer --grace-period=2 --wait=true --timeout=60s
dra-delete "$VM2" resourceclaim pooled-memory --wait=true --timeout=60s
nothing-left claimer-deleted

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
# One NUMA lease with memory in use, one shared lease. Kubernetes garbage
# collection deletes the companions (owned by the borrower), the node
# plugin releases the leases of the pod when its lease claim is
# unprepared: either way everything goes back to the pool.
lend-memory 5
dra-exec "$VM2" borrower/main "$CXL_REQUEST" request --serial "$SHARED_SERIAL" --shared --wait 120s ||
    command-error "cxl-request request --serial $SHARED_SERIAL --shared failed"
SHARED_JSON=$(dra-last-json "$COMMAND_OUTPUT") || error "cxl-request request --shared printed no JSON response"
dra-assert "$SHARED_JSON" "j.get('state') == 'Ready' and j.get('mode') == 'dax' and j.get('shared') == True and j.get('serial') == '$SHARED_SERIAL' and j.get('dax', '').startswith('/dev/dax')"
new-lease "$(dra-value "$SHARED_JSON" "j['lease']")"
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "sorted(l['state'] for l in j) == ['Ready', 'Ready'] and sorted((l.get('mode'), bool(l.get('shared'))) for l in j) == [('dax', True), ('numa', False)]"
pool-host-client -o json attachments || command-error "cannot list the attachments of the pool"
pool-assert "$COMMAND_OUTPUT" "sorted(a['device'] for a in j) == ['pooled0', 'shared0']"
t_delete=$EPOCHREALTIME
dra-delete "$VM2" pod borrower --grace-period=2 --wait=false
TOUCH_PID=""
dra-wait "$VM2" borrower-gone "pods -n $DRA_NS" "'borrower' not in names()" 90
nothing-left pod-deleted no-borrower
dra-wait "$VM2" lease-claim-gone "resourceclaims -n $DRA_NS" "names() == []" 90
t_clean=$EPOCHREALTIME
vm-command "test -e $DRA_LEASE_DIR/$LEASE_CLAIM_UID" &&
    error "the lease directory of claim $LEASE_CLAIM is still in $DRA_LEASE_DIR"
T_DELETE=$(echo "$t_clean - $t_delete" | bc)
(( $(echo "$T_DELETE <= 90" | bc) )) || error "cleanup after deleting the pod took $T_DELETE s, more than 90 s"
echo "pod deleted with 2 active leases: everything cleaned up in $T_DELETE s"
dra-plugin-log "$VM2" | grep -iE 'lease|lend|revok' | tail -n 40

echo "### G: what every component did, in order"
dra-trace-stop
dra-trace-summary
printf 'timings (test steps, 1 s polling): borrower Running %.1f s after apply; deleted with leases, clean %s s after the delete\n' \
    "$(echo "$t_running - $t_apply" | bc)" "$T_DELETE"
echo "timings: cxl-request request until Ready (s): ${T_LEND[*]}"
echo "timings: release until nothing is left (s): ${T_GIVE_BACK[*]}"
echo "timings: cxl-request request --shared --exec write (s): ${T_SHARE[*]}"

echo "### cleanup"
dra-cleanup
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
