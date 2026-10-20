# One exclusive writer, three read-only readers of a node-local CXL memory
# device, all borrowing it while they run
#
# test13 shows single-writer sharing of a shared device of the pool with
# leases (cxl-request in the container); test17 shares a node-local
# device, listed in the driver configuration as sharedDevices, between
# the claims of pods. Here the same local device is shared through
# leases, step by step as in the local demo of plan-8 (L1-L9):
# - L1 a writer pod with a lease claim starts, without CXL memory.
# - L2 "cxl-request request --serial S --mode dax": the companion claim of
#   the lease asks for the device of class cxl-local-shared without a
#   shares request, so it has the device exclusively; the node plugin
#   creates the region of the device, and the writer gets a dax fd.
# - L3 the writer writes a line into the device ("cxl-request fd --lease
#   ID --exec").
# - L4 three readers start, L5 each asks "cxl-request request --serial S
#   --shared --read-only --wait 0s": the request returns at once, the
#   lease is Pending: its companion claim asks for one share (shares:
#   "1"), which the scheduler cannot allocate while the writer has the
#   device. Each reader waits for its fd ("cxl-request fd --lease ID
#   --wait") and holds it, mapped read-only.
# - L6 the writer releases its lease ("cxl-request release --all"): all
#   readers get the device at once, L7 read the writer's line, and L8 a
#   reader that tries to write is refused by the kernel (its fd is
#   O_RDONLY, a writable mapping fails with EACCES).
# - L9 everything goes away: deleting the pods while the three read-only
#   leases are held and mapped leaves no companion objects and no leases
#   behind, and the region stays while the device is configured shared;
#   a new exclusive lease still reads the line (a shared device is zeroed
#   only when its region is created).
# In between: a late exclusive request times out without leftovers,
# requests by size find the local shared device first (and its
# firstAvailable companion claim has the pool as the alternative), and
# requests that the node plugin refuses.
#
# What you will see: the shared device and the lease device in the
# node's ResourceSlice, the writer's lease Ready in a few seconds with the
# new region, zeros where the test left stale bytes, three readers'
# leases Pending while the writer holds the device (their companion pods
# Unschedulable), all three holding the memory at once right after the
# writer's release, reading the same line, a refused write, the late
# exclusive request failing, nothing left after the pods are deleted
# while the readers hold the memory, the bytes surviving the idle device,
# the region gone when the driver runs without the configuration; the
# timings of the writer's request and of the readers after the release,
# and the trace of what every component did.
#
# The local device is cxl_memdev1 of the topology (1G, host bridge 0),
# attached through fake-cxl-pool-server as in test14; the pool has the
# shared device shared0 for the alternative of requests by size. All
# pods run on this VM (VM2), the control plane of the cluster of the
# test, the companions follow their requesters; VM1 (n4-cxl-shared-1), its
# worker, has no local device attached. Run test00-up of n4-cxl-shared-1
# and -2 first: they create the VMs and make them one cluster. The DRA
# driver comes from its image, which has cxl-request too, build it first:
#   make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

echo "### preconditions: one cluster, VM2 control plane, VM1 worker (test00-up)"
pool-cluster-require

VM1="$POOL_VM1_DIR"    # the worker of the cluster
VM2="$OUTPUT_DIR"      # the VM of this test, the control plane
VM2_NAME="$POOL_VM2_NAME"
SHARED0_SERIAL=0xc1ae0001   # 0xc1ae....: shared pool devices
PAUSE_IMAGE=registry.k8s.io/pause:3.10   # the image of the companion pods
CXL_REQUEST=cxl-request     # in $PATH of the container: /usr/local/bin
SHARED_CLASS=cxl-local-shared
TAG="dra-local-one-writer $(date +%Y-%m-%dT%H:%M:%S.%N)"
TEXT="Hello from the writer, $TAG"
READERS=(reader-a reader-b reader-c)
LEASES_FILE="$(dirname "$DRA_LOCAL_STATE")/leases.json"   # the lease table of the node plugin
declare -A POD_UID=()       # pod -> its uid
declare -A READER_LEASE=()  # reader -> the lease of its share
REQ_JSON=""                 # request: the response
REQ_STATUS=""               # its exit status
REQ_OUT=""                  # what cxl-request printed, stdout and stderr
REQ_SECONDS=""              # how long it took
STALE="stale bytes of $TAG" # dra-local-seed: what the node plugin must zero
COMPANION_JSON=""           # companion-claim: the companion claim of a lease
COMPANION_UID=""            # and its uid
SHARED_REGION=""            # L2: the region of the shared device
SHARED_DAX=""               # and its dax device (daxX.Y)

lease-template-yaml() {
    # Usage: lease-template-yaml
    #
    # The template of the lease claims: a pod with one can ask for leases.
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
EOF
}

lease-pod-yaml() {
    # Usage: lease-pod-yaml NAME
    #
    # Pod NAME on VM2 with a lease claim of its own and the tools of
    # dra-dax-tool-install in /tools: one idle container "main" that asks
    # for leases when the test tells it to.
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
spec:
  nodeSelector:
    kubernetes.io/hostname: $VM2_NAME
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
    image: $DRA_TOOLS_IMAGE
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "trap 'exit 0' TERM; sleep infinity & wait"]
    volumeMounts:
    - name: tools
      mountPath: /tools
    resources:
      claims:
      - name: cxl
EOF
}

lease-pods-start() {
    # Usage: lease-pods-start POD...
    #
    # Create the lease pods POD, wait until they run, and record their
    # uids in POD_UID.
    local p
    for p in "$@"; do
        dra-apply "$VM2" <<< "$(lease-pod-yaml "$p")"
    done
    for p in "$@"; do
        dra-pod-wait "$VM2" "$p" Running 60
        dra-json "$VM2" pod -n "$DRA_NS" "$p"
        POD_UID[$p]=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
    done
}

request() {
    # Usage: request POD ARGS...
    #
    # Run "cxl-request ARGS..." in pod POD. REQ_STATUS is its exit status,
    # REQ_OUT what it printed (stdout, then stderr), REQ_JSON its last JSON
    # line ("{}" if none), REQ_SECONDS how long it took.
    local pod="$1" t0=$EPOCHREALTIME
    shift
    dra-exec "$VM2" "$pod" "$CXL_REQUEST" "$@"
    REQ_STATUS=$COMMAND_STATUS
    REQ_SECONDS=$(echo "$EPOCHREALTIME - $t0" | bc)
    REQ_OUT="$COMMAND_OUTPUT
$DRA_EXEC_STDERR"
    REQ_JSON=$(dra-last-json "$COMMAND_OUTPUT") || REQ_JSON="{}"
}

refused() {
    # Usage: refused STATUS TEXT POD ARGS...
    #
    # Check that "cxl-request ARGS..." in pod POD exits with STATUS and
    # prints TEXT.
    local status="$1" text="$2"
    shift 2
    request "$@"
    [ "$REQ_STATUS" == "$status" ] || error "cxl-request ${*:2} exited $REQ_STATUS, expected $status"
    grep -qF -- "$text" <<< "$REQ_OUT" || error "cxl-request ${*:2} did not print '$text'"
    echo "refused as expected: cxl-request ${*:2}: $text"
}

companion-claim() {
    # Usage: companion-claim LEASE
    #
    # Wait until the companion claim of lease LEASE, cxl-lease-LEASE, is
    # allocated to the local device on VM2, and check that it has no CDI
    # device (the companion pod uses nothing of it) and that the pool
    # attached nothing for it. COMPANION_JSON and COMPANION_UID are the
    # claim.
    dra-wait "$VM2" "companion-$1" "resourceclaim -n $DRA_NS cxl-lease-$1" \
        "[(r['driver'], r['device']) for r in results()] == [('$DRA_LOCAL_DRIVER', '$DRA_LOCAL_DEVICE')] and allocated_node() == '$VM2_NAME'" 60
    COMPANION_JSON="$COMMAND_OUTPUT"
    COMPANION_UID=$(dra-value "$COMPANION_JSON" "j['metadata']['uid']")
    [ -z "$(dra-cdi-devices-with "$VM2" "$COMPANION_UID")" ] ||
        error "lease $1: the companion claim has CDI devices: $(dra-cdi-devices-with "$VM2" "$COMPANION_UID")"
    if dra-pool-attachments "$VM2_NAME" | grep -qF "$COMPANION_UID"; then
        error "lease $1: the pool attached a device for the companion claim of a local lease"
    fi
}

companion-shape() {
    # Usage: companion-shape SHARES READONLY
    #
    # Check the request of the companion claim of companion-claim: one
    # exactly request "lease" of class cxl-local-shared for the serial of
    # the local device, with capacity shares SHARES ("": none, exclusive),
    # one DeviceConfig of the node plugin, mode dax and READONLY (True or
    # False); and that its allocation consumed the shares (all of them
    # without a request).
    local shares="$1" ro="$2" capacity=None consumed="$DRA_SHARES"
    if [ -n "$shares" ]; then
        capacity="{'requests': {'shares': '$shares'}}"
        consumed="$shares"
    fi
    dra-assert "$COMPANION_JSON" "[(s['name'], s['deviceClassName'], s.get('capacity')) for s in subrequests()] == [('lease', '$SHARED_CLASS', $capacity)] and j['spec']['devices']['requests'][0].get('exactly')"
    dra-assert "$COMPANION_JSON" "any('$DRA_LOCAL_SERIAL' in (sel.get('cel') or {}).get('expression', '') for sel in subrequests()[0].get('selectors') or [])"
    dra-assert "$COMPANION_JSON" "[(c['driver'], c['parameters'].get('kind'), c['parameters'].get('mode'), bool(c['parameters'].get('readOnly'))) for c in configs()] == [('$DRA_LOCAL_DRIVER', 'DeviceConfig', 'dax', $ro)]"
    dra-assert "$COMPANION_JSON" "quantity((results()[0].get('consumedCapacity') or {}).get('shares', 0)) == $consumed"
}

companion-pending() {
    # Usage: companion-pending POD
    #
    # Return 0 if the leases of POD have one companion pod, it is Pending
    # and not scheduled because its claim cannot be allocated, and its
    # claim has no allocation.
    local json
    json=$(dra-vm-command-q "$VM2" "kubectl get pods,resourceclaims -n $DRA_NS -l $DRA_REQUESTER_LABEL=${POD_UID[$1]} -o json") || return 1
    dra-py assert "$json" "sorted(o['kind'] for o in items) == ['Pod', 'ResourceClaim'] and all(o['status'].get('phase') == 'Pending' and [c.get('reason') for c in o['status'].get('conditions') or [] if c['type'] == 'PodScheduled'] == ['Unschedulable'] for o in items if o['kind'] == 'Pod') and not any((o.get('status') or {}).get('allocation') for o in items if o['kind'] == 'ResourceClaim')"
}

readers-wait() {
    # Usage: readers-wait
    #
    # Return 0 if the companions of every reader are pending (see
    # companion-pending) and no reader holds the memory yet.
    local r
    for r in "${READERS[@]}"; do
        companion-pending "$r" || return 1
        ! holding "$r" || return 1
    done
}

hold-start() {
    # Usage: hold-start POD LEASE
    #
    # Start, in the background in pod POD, what the demo's /demo/hold does:
    # wait until lease LEASE is Ready and take its fd ("cxl-request fd
    # --lease LEASE --wait 300s --exec"), check that the fd cannot be mapped
    # writable, and keep the memory mapped read-only while watching the
    # string at offset 0, until /tmp/stop exists (pool-dax-rw.py watch:
    # "read: TEXT", "holding", "final: TEXT"). The output, and "fd exit N"
    # at the end, go to /tmp/hold.log in the container.
    dra-exec "$VM2" "$1" sh -c 'setsid sh -c "cxl-request fd --lease $1 --wait 300s --exec sh -c \"python3 /tools/dax-rw.py --fd 3 check-ro 0; exec python3 /tools/dax-rw.py --fd 3 watch 0 /tmp/stop\"; echo \"fd exit \$?\"" > /tmp/hold.log 2>&1 < /dev/null &' sh "$2" ||
        command-error "cannot start holding lease $2 in $1"
}

hold-log() {
    # Usage: hold-log POD
    #
    # Print /tmp/hold.log of pod POD (see hold-start), quietly.
    dra-vm-command-q "$VM2" "kubectl exec -n $DRA_NS $1 -- cat /tmp/hold.log" 2>/dev/null
}

holding() {
    # Usage: holding POD...
    #
    # Return 0 if every pod POD holds its memory (see hold-start): its
    # hold log has "holding" and no "changed:" or "final:".
    local p log
    for p in "$@"; do
        log=$(hold-log "$p")
        grep -qx holding <<< "$log" && ! grep -qE '^(final|changed): ' <<< "$log" || return 1
    done
}

same-region() {
    # Usage: same-region
    #
    # Return 0 if the local device has one region, SHARED_REGION, with one
    # dax device, SHARED_DAX, in sysfs.
    dra-memdev-sysfs "$VM2" "$DRA_LOCAL_SERIAL" &&
        dra-py assert "$DRA_MEMDEV" "[(r['name'], [d['name'] for d in r['dax'] if d['size']]) for r in j['regions']] == [('$SHARED_REGION', ['$SHARED_DAX'])]"
}

lease-objects() {
    # Usage: lease-objects LEASE
    #
    # Print the companion pod and claim of lease LEASE that exist, quietly.
    dra-vm-command-q "$VM2" "kubectl get pods,resourceclaims -n $DRA_NS -l $DRA_LEASE_LABEL=$1 -o name"
}

lease-store-check() {
    # Usage: lease-store-check LEASE SHARED
    #
    # Check that the lease table of the node plugin ($LEASES_FILE) has
    # lease LEASE of a shared device ("sharedDevice": true) with "shared"
    # SHARED (True: one share, False: the device exclusively).
    local json
    json=$(dra-vm-command-q "$VM2" "cat $LEASES_FILE") || error "cannot read $LEASES_FILE"
    dra-assert "$json" "(lambda l: (bool(l.get('sharedDevice')), bool(l.get('shared'))))(j['leases']['$1']) == (True, $2)"
}

lease-table-size() {
    # Usage: lease-table-size
    #
    # Print how many leases the lease table of the node plugin
    # ($LEASES_FILE) has (0 without the file), quietly.
    local json
    json=$(dra-vm-command-q "$VM2" "cat $LEASES_FILE 2>/dev/null || echo '{}'")
    echo "$LEASES_FILE: $json" >&2
    python3 -c '
import json, sys
j = json.loads(sys.stdin.read().strip() or "{}")
leases = j.get("leases") if isinstance(j, dict) else j
print(len(leases or []))' <<< "$json"
}

echo "### preconditions: patched qemu, hdm_for_passthrough=on, kernel with CONFIG_FS_DAX"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"

echo "### preconditions: cxl, daxctl and cxl-dump in the VM, no CXL memory devices in either node"
pool-vm-tools-install "$VM2"
pool-vm-reset "$VM2"
pool-vm-reset "$VM1"
pool-cxl-dump "$VM2" no-devices
cxl-assert 'memdevs == [] and regions == [] and endpoints == []'

echo "### preconditions: fake-cxl-pool-server with shared0, the driver with the local device shared"
pool-server-start "
  - name: shared0
    size: 256Mi
    shared: true
    pool: default
    serial: $SHARED0_SERIAL"
pool-client-install "$VM2"
# The local device attached before the driver runs, with non-zero bytes at
# the start, at 1M and at its end, written through a region of the guest
# tools that is gone again: the first lease must find zeros there.
dra-local-device "$VM2"
SEED_OFFSETS=(0 1M $(( DRA_LOCAL_SIZE - 4096 )))
dra-local-seed "$VM2" "$STALE" "${SEED_OFFSETS[@]}"
DRA_DRIVER_CONFIG="sharedDevices: [\"$DRA_LOCAL_SERIAL\"]"
# Never pool-cleanup while a region of the shared device exists.
DRA_EXIT_TRAP='dra-local-shared-cleanup "$VM2"'
S="$DRA_LOCAL_SERIAL"
dra-build
dra-install
dra-pull-images "$VM2" "$DRA_TOOLS_IMAGE" "$PAUSE_IMAGE"
dra-dax-tool-install "$VM2"
dra-apply "$VM2" <<< "$(lease-template-yaml)"
dra-trace-start "$VM2"

echo "### A: the shared local device and the lease device of the node"
dra-local-device "$VM2"
LD="$DRA_LOCAL_LD"             # the device in the ResourceSlices (dra-py)
dra-kubectl "$VM2" "get resourceslices"
dra-json "$VM2" resourceslices
dra-assert "$COMMAND_OUTPUT" "attr($LD, 'source') == 'local' and attr($LD, 'shared') == True and attr($LD, 'size') == $DRA_LOCAL_SIZE"
dra-assert "$COMMAND_OUTPUT" "sorted(${LD}.get('capacity') or {}) == ['shares'] and quantity(capacity($LD, 'shares')) == $DRA_SHARES and request_policy($LD, 'shares') is None"
dra-assert "$COMMAND_OUTPUT" "attr(device('lease', '$DRA_LOCAL_DRIVER', '$VM2_NAME'), 'type') == 'lease'"
dra-assert "$COMMAND_OUTPUT" "attr(device('shared0', '$DRA_POOL_DRIVER'), 'shared') == True"
pool-cxl-dump "$VM2" local-attached
cxl-assert "by_serial($S) is not None and regions == []"

echo "### L1: a writer pod starts; it has no CXL memory yet"
lease-pods-start writer
dra-leases "$VM2" writer
dra-assert "$DRA_LEASES" "j == []"
dra-json "$VM2" resourceclaims -n "$DRA_NS"
dra-assert "$COMMAND_OUTPUT" "not any(r['device'] == '$DRA_LOCAL_DEVICE' for c in items for r in results(c))"
pool-cxl-dump "$VM2" writer-started
cxl-assert "regions == []"

echo "### L2: the writer asks for the whole device, exclusively"
request writer request --serial "$S" --mode dax --wait 120s
[ "$REQ_STATUS" == 0 ] || error "cxl-request request --serial $S --mode dax exited $REQ_STATUS"
T_WRITER_READY="$REQ_SECONDS"
# A lease of a shared device without --shared: the device exclusively.
dra-assert "$REQ_JSON" "(j.get('state'), j.get('source'), j.get('mode'), bool(j.get('shared')), bool(j.get('readOnly')), j.get('serial')) == ('Ready', 'local', 'dax', False, False, '$S')"
WRITER_LEASE=$(dra-value "$REQ_JSON" "j['lease']")
dra-leases "$VM2" writer
# shared is the --shared of the lease; the device is shared all the same.
dra-assert "$DRA_LEASES" "[(l['state'], bool(l.get('shared')), (l.get('env') or {}).get('CXL_${DRA_LOCAL_HEX}_SHARED')) for l in j] == [('Ready', False, '1')]"
lease-store-check "$WRITER_LEASE" False
printf 'lease %s of the writer: Ready in %.2f s\n' "$WRITER_LEASE" "$T_WRITER_READY"
# The companion claim takes the local shared device without a shares
# request: all shares.
companion-claim "$WRITER_LEASE"
WRITER_COMPANION_UID="$COMPANION_UID"
companion-shape "" False
dra-companion-meta-check "$COMPANION_JSON" "$WRITER_LEASE" "${POD_UID[writer]}" "$VM2_NAME" "$DRA_NS/writer/main"
dra-pod-wait "$VM2" "cxl-lease-$WRITER_LEASE" Running 60
# The first claim of the device creates its region: one devdax device of
# all of it, nothing online.
dra-local-shared-wait "$VM2" writer "$WRITER_COMPANION_UID"
SHARED_REGION="$DRA_LOCAL_SHARED_REGION"
SHARED_DAX="$DRA_LOCAL_SHARED_DAX"
# The environment of the lease: the shared device, read-write.
request writer env --lease "$WRITER_LEASE"
[ "$REQ_STATUS" == 0 ] || error "cxl-request env --lease $WRITER_LEASE exited $REQ_STATUS"
dra-env-assert "writer lease $WRITER_LEASE" "$COMMAND_OUTPUT" "$DRA_LOCAL_HEX" \
    SERIAL="$S" SHARED=1 MODE=dax SIZE="$DRA_LOCAL_SIZE" "DAX=/dev/$SHARED_DAX" READONLY=0

echo "### L3: the writer writes a line into the device"
# The new region was zeroed once: where dra-local-seed left stale bytes,
# the writer finds zeros.
dra-plugin-log "$VM2" | grep -F "zeroed new shared $SHARED_DAX size $DRA_LOCAL_SIZE in " ||
    error "the node plugin did not log zeroing the new region of the shared device"
for off in "${SEED_OFFSETS[@]}"; do
    dra-exec "$VM2" writer "$CXL_REQUEST" fd --lease "$WRITER_LEASE" --exec python3 /tools/dax-rw.py --fd 3 read "$off" ||
        command-error "the writer cannot read at $off through the fd of lease $WRITER_LEASE"
    [ -z "$(tail -n 1 <<< "$COMMAND_OUTPUT")" ] || error "the writer found '$(tail -n 1 <<< "$COMMAND_OUTPUT")' at $off of the new region, expected zeros"
done
dra-exec "$VM2" writer "$CXL_REQUEST" fd --lease "$WRITER_LEASE" --exec python3 /tools/dax-rw.py --fd 3 write 0 "$TEXT" ||
    command-error "the writer cannot write through the fd of lease $WRITER_LEASE"
dra-exec "$VM2" writer "$CXL_REQUEST" fd --lease "$WRITER_LEASE" --exec python3 /tools/dax-rw.py --fd 3 read 0 ||
    command-error "the writer cannot read through the fd of lease $WRITER_LEASE"
[ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "$TEXT" ] || error "the writer read '$(tail -n 1 <<< "$COMMAND_OUTPUT")', expected '$TEXT'"

echo "### L4: three readers start"
lease-pods-start "${READERS[@]}"

echo "### L5: the readers ask for a read-only share: they must wait"
for r in "${READERS[@]}"; do
    # --wait 0s: the response at once, the lease kept Pending.
    request "$r" request --serial "$S" --shared --read-only --wait 0s
    [ "$REQ_STATUS" == 0 ] || error "$r: cxl-request request --serial $S --shared --read-only --wait 0s exited $REQ_STATUS"
    dra-assert "$REQ_JSON" "(j.get('state'), j.get('mode'), bool(j.get('shared')), bool(j.get('readOnly'))) == ('Pending', 'dax', True, True)"
    READER_LEASE[$r]=$(dra-value "$REQ_JSON" "j['lease']")
    printf '%s: lease %s Pending, the request returned in %.2f s\n' "$r" "${READER_LEASE[$r]}" "$REQ_SECONDS"
done
for r in "${READERS[@]}"; do
    retry-until --timeout 60 --interval 1 --message "$r: a Pending, Unschedulable companion" \
        'companion-pending "$r"' ||
        error "$r has no Pending, Unschedulable companion: $(dra-vm-command-q "$VM2" "kubectl get pods,resourceclaims -n $DRA_NS -l $DRA_REQUESTER_LABEL=${POD_UID[$r]}")"
    dra-vm-command "$VM2" "kubectl get pod -n $DRA_NS cxl-lease-${READER_LEASE[$r]} -o jsonpath='{.status.conditions[?(@.type==\"PodScheduled\")].message}'"
    # What the demo's /demo/hold does: wait for the fd and hold it.
    hold-start "$r" "${READER_LEASE[$r]}"
done
# Nothing moves however long they wait: the writer holds all shares.
dra-stays 10 "the companions of the readers stay Pending, no reader holds the memory" readers-wait
for r in "${READERS[@]}"; do
    dra-leases "$VM2" "$r"
    dra-assert "$DRA_LEASES" "[(l['lease'], l['state'], l.get('mode'), bool(l.get('shared')), bool(l.get('readOnly'))) for l in j] == [('${READER_LEASE[$r]}', 'Pending', 'dax', True, True)]"
done
dra-leases "$VM2" writer
dra-assert "$DRA_LEASES" "[(l['lease'], l['state']) for l in j] == [('$WRITER_LEASE', 'Ready')]"

echo "### L6: the writer is done and releases the device"
t0=$EPOCHREALTIME
request writer release --all
[ "$REQ_STATUS" == 0 ] || error "the writer: cxl-request release --all exited $REQ_STATUS"
for r in "${READERS[@]}"; do
    retry-until --timeout 120 --interval 1 --message "$r holds the memory" 'holding "$r"' ||
        error "$r does not hold the memory 120 s after the writer's release: $(hold-log "$r")"
done
T_READERS=$(echo "$EPOCHREALTIME - $t0" | bc)
echo "the writer released, all readers hold the memory: $T_READERS s"
retry-until --timeout 60 --interval 1 --message "the companion of the writer is gone" \
    '[ -z "$(lease-objects "$WRITER_LEASE")" ]' ||
    error "the lease of the writer left $(lease-objects "$WRITER_LEASE")"
dra-leases "$VM2" writer
dra-assert "$DRA_LEASES" "j == []"

echo "### L7: each reader reads the writer's line"
declare -A READER_COMPANION_UID=()
for r in "${READERS[@]}"; do
    log=$(hold-log "$r")
    echo "$r: $log"
    grep -qxF "read: $TEXT" <<< "$log" || error "$r did not read '$TEXT'"
    grep -qxF "writable mapping refused: EACCES" <<< "$log" || error "$r could map the memory for writing"
    dra-leases "$VM2" "$r"
    dra-assert "$DRA_LEASES" "[(l['state'], l.get('source'), l.get('mode'), bool(l.get('shared')), bool(l.get('readOnly')), l.get('serial'), (l.get('env') or {}).get('CXL_${DRA_LOCAL_HEX}_SHARED')) for l in j] == [('Ready', 'local', 'dax', True, True, '$S', '1')]"
    lease-store-check "${READER_LEASE[$r]}" True
    companion-claim "${READER_LEASE[$r]}"
    READER_COMPANION_UID[$r]="$COMPANION_UID"
    companion-shape 1 True
    dra-companion-meta-check "$COMPANION_JSON" "${READER_LEASE[$r]}" "${POD_UID[$r]}" "$VM2_NAME" "$DRA_NS/$r/main"
    request "$r" env --lease "${READER_LEASE[$r]}"
    dra-env-assert "$r lease ${READER_LEASE[$r]}" "$COMMAND_OUTPUT" "$DRA_LOCAL_HEX" \
        SERIAL="$S" SHARED=1 MODE=dax SIZE="$DRA_LOCAL_SIZE" "DAX=/dev/$SHARED_DAX" READONLY=1
    # The demo's /demo/read: the fd once more, read.
    dra-exec "$VM2" "$r" "$CXL_REQUEST" fd --lease "${READER_LEASE[$r]}" --wait 120s --exec python3 /tools/dax-rw.py --fd 3 read 0 ||
        command-error "$r cannot read through the fd of lease ${READER_LEASE[$r]}"
    [ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "$TEXT" ] || error "$r read '$(tail -n 1 <<< "$COMMAND_OUTPUT")', expected '$TEXT'"
done
# All three hold the one region of the writer at the same time.
holding "${READERS[@]}" || error "not all readers hold the memory at the same time"
dra-local-shared-wait "$VM2" readers "${READER_COMPANION_UID[@]}"
same-region || error "the readers have another region or dax device than the writer: $DRA_MEMDEV"

echo "### L8: a reader tries to write: the kernel refuses"
dra-exec "$VM2" reader-a "$CXL_REQUEST" fd --lease "${READER_LEASE[reader-a]}" --exec python3 /tools/dax-rw.py --fd 3 write 0 "overwrite by reader-a" &&
    error "reader-a could write through its read-only lease"
grep -qF "[Errno 13]" <<< "$COMMAND_OUTPUT
$DRA_EXEC_STDERR" || error "the write of reader-a failed, but not with EACCES (errno 13)"
holding "${READERS[@]}" || error "a reader saw a change after the refused write"
dra-exec "$VM2" reader-b "$CXL_REQUEST" fd --lease "${READER_LEASE[reader-b]}" --exec python3 /tools/dax-rw.py --fd 3 read 0 ||
    command-error "reader-b cannot read through the fd of lease ${READER_LEASE[reader-b]}"
[ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "$TEXT" ] || error "after the refused write reader-b read '$(tail -n 1 <<< "$COMMAND_OUTPUT")', expected '$TEXT'"

echo "### E2: a new exclusive request cannot take the device from the readers"
request reader-a request --serial "$S" --wait 15s
[ "$REQ_STATUS" == 3 ] || error "an exclusive request while readers hold $S exited $REQ_STATUS, expected 3 (not Ready in time)"
dra-assert "$REQ_JSON" "j['state'] == 'Failed' and 'timeout' in j['error']"
LATE_LEASE=$(dra-value "$REQ_JSON" "j['lease']")
retry-until --timeout 60 --interval 1 --message "nothing left of the late exclusive lease" \
    '[ -z "$(lease-objects "$LATE_LEASE")" ]' ||
    error "the late exclusive lease left $(lease-objects "$LATE_LEASE")"
holding "${READERS[@]}" || error "a reader lost its memory to the late exclusive request"

echo "### E3: requests by size find the local shared device first"
# --source local --shared: the share of a local shared device of 64Mi at
# least.
request reader-b request --source local --shared --size 64Mi --wait 60s
[ "$REQ_STATUS" == 0 ] || error "cxl-request request --source local --shared --size 64Mi exited $REQ_STATUS"
dra-assert "$REQ_JSON" "(j.get('state'), j.get('source'), j.get('serial'), j.get('mode'), bool(j.get('shared'))) == ('Ready', 'local', '$S', 'dax', True)"
lease=$(dra-value "$REQ_JSON" "j['lease']")
companion-claim "$lease"
dra-assert "$COMPANION_JSON" "[(s['name'], s['deviceClassName'], s.get('capacity')) for s in subrequests()] == [('lease', '$SHARED_CLASS', {'requests': {'shares': '1'}})]"
dra-assert "$COMPANION_JSON" "any('size' in (sel.get('cel') or {}).get('expression', '') for sel in subrequests()[0].get('selectors') or [])"
request reader-b release --lease "$lease"
dra-assert "$REQ_JSON" "j.get('lease') == '$lease' and j.get('state') == 'Released'"
retry-until --timeout 60 --interval 1 --message "nothing left of lease $lease" '[ -z "$(lease-objects "$lease")" ]' ||
    error "lease $lease left $(lease-objects "$lease")"
# --shared without --source: local first, then the pool (shared0 would
# do), a firstAvailable request with one share of either.
request reader-b request --shared --size 64Mi --wait 60s
[ "$REQ_STATUS" == 0 ] || error "cxl-request request --shared --size 64Mi exited $REQ_STATUS"
dra-assert "$REQ_JSON" "(j.get('state'), j.get('source'), j.get('serial')) == ('Ready', 'local', '$S')"
lease=$(dra-value "$REQ_JSON" "j['lease']")
companion-claim "$lease"
dra-assert "$COMPANION_JSON" "[(s['name'], s['deviceClassName'], s.get('capacity')) for s in subrequests()] == [('lease/local', '$SHARED_CLASS', {'requests': {'shares': '1'}}), ('lease/pool', 'cxl-pool-shared', {'requests': {'shares': '1'}})]"
dra-assert "$COMPANION_JSON" "[r['request'] for r in results()] == ['lease/local']"
request reader-b release --lease "$lease"
dra-assert "$REQ_JSON" "j.get('lease') == '$lease' and j.get('state') == 'Released'"
retry-until --timeout 60 --interval 1 --message "nothing left of lease $lease" '[ -z "$(lease-objects "$lease")" ]' ||
    error "lease $lease left $(lease-objects "$lease")"
[ -z "$(dra-pool-attachments "$VM2_NAME")" ] || error "the pool attached devices for local leases: $(dra-pool-attachments "$VM2_NAME")"

echo "### E4: requests that the node plugin and cxl-request refuse"
refused 1 "device $S: not a pool device" reader-c request --serial "$S" --source pool
refused 2 "shared memory is never onlined as RAM: use mode dax" reader-c request --serial "$S" --shared --mode numa
dra-leases "$VM2" reader-c
dra-assert "$DRA_LEASES" "[l['lease'] for l in j] == ['${READER_LEASE[reader-c]}']"
holding "${READERS[@]}" || error "a reader lost its memory to the refused requests"
dra-local-shared-wait "$VM2" readers-again "${READER_COMPANION_UID[@]}"

echo "### L9: everything goes away while the readers hold the memory"
# As the demo's "kubectl delete -f local/": the pods and the template of
# their lease claims, with the three read-only leases Ready and mapped.
holding "${READERS[@]}" || error "not all readers hold the memory before L9"
dra-vm-command "$VM2" "kubectl delete -n $DRA_NS pods writer ${READERS[*]} --grace-period=2 --wait=true --timeout=60s && kubectl delete -n $DRA_NS resourceclaimtemplate cxl-lease" ||
    command-error "cannot delete the pods and the lease template"
dra-wait "$VM2" no-lease-objects "pods,resourceclaims -n $DRA_NS" "items == []" 60
retry-until --timeout 60 --interval 1 --message "no leases in $LEASES_FILE" \
    '[ "$(lease-table-size)" == 0 ]' || error "the node plugin still has leases in $LEASES_FILE"
# Kept while the device is configured shared: the region and its dax
# device, with no claims.
dra-local-shared-wait "$VM2" deleted
same-region || error "the shared device has another region or dax device after the pods went: $DRA_MEMDEV"

echo "### G: the region and the line stay"
# A new exclusive lease of a new pod reads the line: the kept region was
# not zeroed again, neither between the leases nor while idle.
dra-apply "$VM2" <<< "$(lease-template-yaml)"
lease-pods-start later
dra-exec "$VM2" later "$CXL_REQUEST" request --serial "$S" --wait 60s --exec python3 /tools/dax-rw.py --fd 3 read 0 ||
    command-error "later cannot read the device through a new exclusive lease"
[ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "$TEXT" ] || error "the new exclusive lease read '$(tail -n 1 <<< "$COMMAND_OUTPUT")', expected '$TEXT'"
zeroed=$(dra-plugin-log "$VM2" | grep -c "zeroed new shared ")
[ "$zeroed" == 1 ] || error "the node plugin zeroed the shared device $zeroed times, expected once, when the region was created"
request later release --all
[ "$REQ_STATUS" == 0 ] || error "later: cxl-request release --all exited $REQ_STATUS"
dra-delete-pod "$VM2" later
dra-wait "$VM2" no-lease-objects-later "pods,resourceclaims -n $DRA_NS" "items == []" 60
dra-local-shared-wait "$VM2" later-gone
same-region || error "the shared device has another region or dax device after later: $DRA_MEMDEV"

echo "### I: without the configuration the region goes; what every component did"
DRA_DRIVER_CONFIG=""
t0=$EPOCHREALTIME
dra-install
dra-trace-driver-follow "$VM2"
# The node plugin itself released the region: its log says so.
dra-plugin-log-wait "$VM2" "(serial $DRA_LOCAL_SERIAL): not configured shared any more, releasing its region" 60
dra-local-slices-none "$VM2" unshared
T_UNSHARE=$(echo "$EPOCHREALTIME - $t0" | bc)
dra-wait "$VM2" sliced-again resourceslices "attr($LD, 'shared') == False and quantity(capacity($LD, 'memory')) == $DRA_LOCAL_SIZE" 60
dra-trace-stop
dra-trace-summary
echo "TIMING: the writer's request until its lease is Ready (the region created): $T_WRITER_READY s"
echo "TIMING: the writer's release until all readers hold the memory: $T_READERS s"
echo "TIMING: dra-install without sharedDevices until the region is gone: $T_UNSHARE s"

echo "### cleanup"
dra-cleanup
dra-local-detach "$VM2"
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
