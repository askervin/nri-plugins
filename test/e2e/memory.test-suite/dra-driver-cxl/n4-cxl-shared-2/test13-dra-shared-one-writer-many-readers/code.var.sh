# One exclusive writer, many read-only readers of shared CXL memory, on two
# nodes of one Kubernetes cluster
#
# Single-writer data sharing: a writer gets a shared CXL memory device of
# the pool for itself, writes new contents into it and exits. Then several
# readers on several nodes use the same memory at the same time, read-only.
# All of them borrow the memory while they run (test12): "cxl-request
# request --serial SERIAL" in the container, the plugin passes a dax
# device fd.
#
# - Exclusive: "cxl-request request --serial SERIAL" without --shared asks
#   for all of the device's "hosts" capacity (4 in the pool ResourceSlice).
#   While the writer has it, the scheduler cannot allocate the device to
#   any other claim: the readers' requests stay Pending, and
#   fake-cxl-pool-server refuses to attach the device to any other host
#   (the attachment is exclusive, which also keeps out other clusters
#   sharing the pool).
# - Read-only: "cxl-request request --serial SERIAL --shared --read-only"
#   takes one host of the device and gets an fd opened O_RDONLY: the
#   reader can map the memory for reading only, a writable mapping is
#   refused (EACCES) whatever the capabilities of the container. A claim
#   of a pod with the opaque config DeviceConfig readOnly: true gets a
#   device node that the container can only open for reading.
#
# The cluster: the VM of n4-cxl-shared-2 (VM2, the VM of the test) is the
# control plane, the VM of n4-cxl-shared-1 (VM1) a worker, over the VM
# network "cxl-pool" (vm_network.var.sh); test00-up of n4-cxl-shared-2
# makes it. The pool controller runs once, on VM2, the driver on both: one
# DaemonSet, installed with helm on VM2, whose pod on VM1 starts at once
# with the image that dra-install imported there.
#
# What you will see: the writer on VM1 holding shared0 exclusively, three
# readers (two on VM2, one on VM1) asking meanwhile and waiting, the
# writer exiting and all three readers getting the device at once, reading
# what the writer wrote, holding the memory at the same time and failing
# to map it for writing; a late exclusive request that times out without
# leftovers; a fourth reader with a read-only claim from its creation; the
# exclusive device pooled0 used as a dax device too, through a lease and
# through a claim; and the trace of both nodes.
#
# Run test00-up of n4-cxl-shared-1 and -2 first: they create the VMs and
# make them one cluster. The DRA driver comes from its image, build it
# first:
#   make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

echo "### preconditions: one cluster, VM2 control plane, VM1 worker (test00-up)"
pool-cluster-require

VM1="$POOL_VM1_DIR"    # worker
VM2="$OUTPUT_DIR"      # control plane, the VM of this test
VM1_NAME="$POOL_VM1_NAME"
VM2_NAME="$POOL_VM2_NAME"
SHARED_SERIAL=0xc1ae0001    # 0xc1ae....: shared pool devices
SHARED_HEX=C1AE0001         # the serial in environment variable names
POOLED0_SERIAL=0xc1ee0001   # 0xc1ee....: exclusive pool devices
POOLED0_HEX=C1EE0001
PYTHON_IMAGE=docker.io/library/python:3-alpine
PAUSE_IMAGE=registry.k8s.io/pause:3.10   # the image of the companion pods
TAG="dra-one-writer $(date +%Y-%m-%dT%H:%M:%S.%N)"
TEXT="$TAG: written by the exclusive writer"
READERS=(reader-a reader-b reader-c)
declare -A READER_VM=([reader-a]="$VM2" [reader-b]="$VM2" [reader-c]="$VM1")

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

# shellcheck disable=SC2001 # sed indents every line of SCRIPT
lease-pod-yaml() {
    # Usage: lease-pod-yaml NAME VMDIR SCRIPT
    #
    # Pod NAME on the node of VMDIR, restartPolicy Never, with a lease claim
    # of its own and the dax-rw tool in /tools, running the shell SCRIPT in
    # its container "main".
    local name="$1" node script="$3"
    node=$(basename "$2")
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
spec:
  nodeSelector:
    kubernetes.io/hostname: $node
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
    command:
    - sh
    - -c
    - |
$(sed 's/^/      /' <<< "$script")
    volumeMounts:
    - name: tools
      mountPath: /tools
    resources:
      claims:
      - name: cxl
EOF
}

# shellcheck disable=SC2001 # sed indents every line of SCRIPT
claim-pod-yaml() {
    # Usage: claim-pod-yaml NAME VMDIR CLAIM SCRIPT
    #
    # Pod NAME on the node of VMDIR with ResourceClaim CLAIM from its
    # creation (test10, test11) and the dax-rw tool in /tools, running the
    # shell SCRIPT, then sleeping.
    local name="$1" node claim="$3" script="$4"
    node=$(basename "$2")
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
spec:
  nodeSelector:
    kubernetes.io/hostname: $node
  terminationGracePeriodSeconds: 2
  restartPolicy: Never
  resourceClaims:
  - name: mem
    resourceClaimName: $claim
  volumes:
  - name: tools
    configMap:
      name: dax-rw
  containers:
  - name: main
    image: $PYTHON_IMAGE
    imagePullPolicy: IfNotPresent
    command:
    - sh
    - -c
    - |
$(sed 's/^/      /' <<< "$script")
      trap "exit 0" TERM; sleep infinity & wait
    volumeMounts:
    - name: tools
      mountPath: /tools
    resources:
      claims:
      - name: mem
EOF
}

pod-log() {
    # Usage: pod-log POD
    #
    # Print the log of pod POD (quietly).
    dra-vm-command-q "$VM2" "kubectl logs -n $DRA_NS $1 2>/dev/null"
}

wait-log() {
    # Usage: wait-log POD LINE [TIMEOUT]
    #
    # Wait until the log of pod POD has the line LINE (a fixed string that
    # matches the whole line), TIMEOUT seconds at most (default 120).
    local pod="$1" line="$2" tmo="${3:-120}"
    retry-until --timeout "$tmo" --interval 1 --message "$pod: \"$line\"" \
        'pod-log "$pod" | grep -qxF -- "$line"' || {
        dra-vm-command "$VM2" "kubectl logs -n $DRA_NS $pod; kubectl describe pod -n $DRA_NS $pod | tail -n 20"
        error "pod $pod did not log \"$line\" in ${tmo}s"
    }
}

lease-of() {
    # Usage: lease-of POD
    #
    # Print the lease id that pod POD logged ("lease ID ...").
    pod-log "$1" | sed -n 's/^lease \([0-9a-f]\{8\}\) .*/\1/p' | tail -n 1
}

companions-of() {
    # Usage: companions-of POD
    #
    # Print "NAME PHASE" of the companion pods of the leases of pod POD.
    local uid
    uid=$(dra-vm-command-q "$VM2" "kubectl get pod -n $DRA_NS $1 -o jsonpath={.metadata.uid}")
    dra-vm-command-q "$VM2" "kubectl get pods -n $DRA_NS -l $DRA_REQUESTER_LABEL=$uid -o jsonpath='{range .items[*]}{.metadata.name}{\" \"}{.status.phase}{\"\\n\"}{end}'"
}

readers-pending() {
    # Usage: readers-pending
    #
    # Return 0 if every reader has one companion pod, and it is Pending.
    local r
    for r in "${READERS[@]}"; do
        [ "$(companions-of "$r" | awk '{print $2}')" == Pending ] || return 1
    done
}

shared0-attachments() {
    # Usage: shared0-attachments
    #
    # Print the attachments of shared0 on the server as JSON, and keep them
    # in COMMAND_OUTPUT.
    pool-host-client -o json attachments --device shared0 || command-error "cannot list the attachments of shared0"
}

echo "### preconditions: patched qemu, hdm_for_passthrough=on, CONFIG_FS_DAX"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"
pool-vm-require "$VM1" n4-cxl-shared-1

echo "### preconditions: cxl, daxctl and cxl-dump in both VMs, no CXL memory devices"
pool-vm-tools-install "$VM2"
pool-vm-tools-install "$VM1"
pool-vm-reset "$VM2"
pool-vm-reset "$VM1"
for vm in "$VM2" "$VM1"; do
    pool-cxl-dump "$vm" no-devices
    cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
done

echo "### preconditions: fake-cxl-pool-server with shared0 and pooled0"
pool-server-start "
  - name: shared0
    size: 256Mi
    shared: true
    pool: default
    serial: $SHARED_SERIAL
  - name: pooled0
    size: 512Mi
    shared: false
    pool: default
    serial: $POOLED0_SERIAL"
pool-client-install "$VM2" "$VM1"

echo "### preconditions: the pool controller on the control plane, the node plugin on both nodes"
dra-build
dra-install
for vm in "$VM2" "$VM1"; do
    dra-pull-images "$vm" "$PYTHON_IMAGE" "$PAUSE_IMAGE"
done
dra-dax-tool-install "$VM2"
dra-apply "$VM2" <<< "$(lease-template-yaml)"
dra-trace-start "$VM2" "$VM1"

echo "### A: one cluster of two nodes, one pool, the lease device on both nodes"
dra-kubectl "$VM2" "get nodes -o wide"
dra-json "$VM2" nodes
dra-assert "$COMMAND_OUTPUT" "sorted(n['metadata']['name'] for n in j['items']) == sorted(['$VM1_NAME', '$VM2_NAME'])"
dra-kubectl "$VM2" "get resourceslices"
dra-json "$VM2" resourceslices
S0="device('shared0', '$DRA_POOL_DRIVER')"
dra-assert "$COMMAND_OUTPUT" "len(slices('$DRA_POOL_DRIVER')) == 1 and slices('$DRA_LOCAL_DRIVER', '$VM1_NAME') and slices('$DRA_LOCAL_DRIVER', '$VM2_NAME')"
dra-assert "$COMMAND_OUTPUT" "all(attr(device('lease', '$DRA_LOCAL_DRIVER', n), 'type') == 'lease' for n in ['$VM1_NAME', '$VM2_NAME'])"
# "hosts" may be requested as 1 (a share) or as all of it (exclusive).
dra-assert "$COMMAND_OUTPUT" "capacity($S0, 'hosts') == '4' and ${S0}['capacity']['hosts']['requestPolicy']['validValues'] == ['1', '4']"

echo "### B: the writer on VM1 gets shared0 exclusively and writes"
# Without --shared, a request of a shared device takes all of its hosts.
dra-apply "$VM2" <<< "$(lease-pod-yaml writer "$VM1" "echo \"writer: cxl-request request --serial $SHARED_SERIAL\"
cxl-request request --serial $SHARED_SERIAL --wait 120s --exec sh -c '
echo \"lease \$CXL_LEASE read-only \$CXL_${SHARED_HEX}_READONLY shared \$CXL_${SHARED_HEX}_SHARED fd \$CXL_${SHARED_HEX}_FD\"
python3 /tools/dax-rw.py --fd 3 write 0 \"\$1\" || exit 1
echo \"written\"
while [ ! -f /tmp/done ]; do sleep 0.2; done
echo \"writer done\"' sh \"$TEXT\"
echo \"cxl-request exit \$?\"")"
wait-log writer written 120
WRITER_LEASE=$(lease-of writer)
[ -n "$WRITER_LEASE" ] || error "the writer logged no lease id"
pod-log writer | grep -qx "lease $WRITER_LEASE read-only 0 shared 1 fd 3" ||
    error "the writer has not CXL_${SHARED_HEX}_READONLY=0, _SHARED=1 and _FD=3"
dra-wait "$VM2" writer-companion "resourceclaim -n $DRA_NS cxl-lease-$WRITER_LEASE" \
    "condition('$DRA_POOL_DRIVER/Attached') == 'True'" 30
# The companion asks for all hosts of the shared device: one request of
# class cxl-pool-shared with capacity hosts 4 (the serial is that of a
# shared pool device: no local subrequest).
dra-assert "$COMMAND_OUTPUT" "[(s['name'], s['deviceClassName'], s['capacity']['requests']['hosts']) for s in subrequests()] == [('lease', 'cxl-pool-shared', '4')] and j['spec']['devices']['requests'][0].get('exactly')"
dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$VM1_NAME' and j['status']['allocation']['devices']['results'][0]['consumedCapacity']['hosts'] == '4'"
dra-assert "$COMMAND_OUTPUT" "device_data('shared0')['exclusive'] == True"
dra-assert "$COMMAND_OUTPUT" "[(c['driver'], c['parameters']['kind'], c['parameters'].get('mode'), bool(c['parameters'].get('readOnly'))) for c in configs()] == [('$DRA_POOL_DRIVER', 'DeviceConfig', 'dax', False)]"
dra-assert "$COMMAND_OUTPUT" "j['metadata']['labels']['$DRA_LEASE_LABEL'] == '$WRITER_LEASE' and j['metadata']['annotations']['$DRA_REQUESTER_ANNOTATION'] == '$DRA_NS/writer/main'"
dra-claim-conditions "$VM2" "cxl-lease-$WRITER_LEASE"
shared0-attachments
pool-assert "$COMMAND_OUTPUT" "[(a['host'], a.get('exclusive', False)) for a in j] == [('$VM1_NAME', True)]"
pool-host-client -o json devices shared0 || command-error "cannot get shared0"
SHARED_FILE=$(pool-value "$COMMAND_OUTPUT" 'j["path"]')
found=$(pool-file-string "$SHARED_FILE" 0)
[ "$found" == "$TEXT" ] || error "host: $SHARED_FILE has '$found' at 0, expected '$TEXT'"
echo "host read at 0 of $SHARED_FILE: '$found'"

echo "### C: three readers ask meanwhile, two on VM2 and one on VM1: they wait"
for r in "${READERS[@]}"; do
    dra-apply "$VM2" <<< "$(lease-pod-yaml "$r" "${READER_VM[$r]}" "echo \"$r: cxl-request request --serial $SHARED_SERIAL --shared --read-only\"
cxl-request request --serial $SHARED_SERIAL --shared --read-only --wait 300s --exec sh -c '
echo \"lease \$CXL_LEASE read-only \$CXL_${SHARED_HEX}_READONLY\"
python3 /tools/dax-rw.py --fd 3 check-ro 0 || exit 1
exec python3 /tools/dax-rw.py --fd 3 watch 0 /tmp/stop'
echo \"cxl-request exit \$?\"
cxl-request release --all
trap 'exit 0' TERM; sleep infinity & wait")"
done
for r in "${READERS[@]}"; do
    dra-pod-wait "$VM2" "$r" Running 120
    retry-until --timeout 60 --interval 1 --message "$r: a Pending companion" \
        '[ "$(companions-of "$r" | awk "{print \$2}")" == Pending ]' ||
        error "$r has no Pending companion pod: $(companions-of "$r")"
done
# They stay Pending while the writer has the device: the scheduler and the
# controller have time to show that nothing moves.
dra-stays 10 "the companions of the readers stay Pending" readers-pending
for r in "${READERS[@]}"; do
    dra-leases "${READER_VM[$r]}" "$r"
    dra-assert "$DRA_LEASES" "[(l['state'], bool(l.get('readOnly')), bool(l.get('shared')), l.get('mode')) for l in j] == [('Pending', True, True, 'dax')]"
    companion=$(companions-of "$r" | awk '{print $1}')
    dra-json "$VM2" pod -n "$DRA_NS" "$companion"
    dra-assert "$COMMAND_OUTPUT" "j['status']['phase'] == 'Pending' and [c['reason'] for c in j['status'].get('conditions', []) if c['type'] == 'PodScheduled'] == ['Unschedulable']"
done
dra-json "$VM2" resourceclaim -n "$DRA_NS" "${companion}"
dra-assert "$COMMAND_OUTPUT" "j['status'].get('allocation') is None"
shared0-attachments
pool-assert "$COMMAND_OUTPUT" "[(a['host'], a.get('exclusive', False)) for a in j] == [('$VM1_NAME', True)]"

echo "### D: the writer exits, the readers get the device"
t0=$(date +%s.%N)
dra-exec "$VM1" writer touch /tmp/done || command-error "cannot tell the writer to finish"
dra-pod-wait "$VM2" writer Succeeded 60
wait-log writer "cxl-request exit 0" 10
for r in "${READERS[@]}"; do
    wait-log "$r" holding 120
done
t1=$(date +%s.%N)
T_READERS=$(echo "$t1 - $t0" | bc)
echo "the writer exited, all readers hold the memory: $T_READERS s"
retry-until --timeout 60 --interval 1 --message "the companion of the writer is gone" \
    '[ -z "$(dra-vm-command-q "$VM2" "kubectl get pods,resourceclaims -n $DRA_NS -l $DRA_LEASE_LABEL=$WRITER_LEASE -o name")" ]' ||
    error "the lease of the writer left $(dra-vm-command-q "$VM2" "kubectl get pods,resourceclaims -n $DRA_NS -l $DRA_LEASE_LABEL=$WRITER_LEASE -o name")"

echo "### E: the readers read the same bytes at the same time, read-only"
for r in "${READERS[@]}"; do
    dra-kubectl "$VM2" "logs -n $DRA_NS $r"
    grep -qxF "read: $TEXT" <<< "$COMMAND_OUTPUT" || error "$r did not read '$TEXT'"
    grep -qxF "writable mapping refused: EACCES" <<< "$COMMAND_OUTPUT" ||
        error "$r could map the memory for writing"
    grep -qE '^lease [0-9a-f]{8} read-only 1$' <<< "$COMMAND_OUTPUT" ||
        error "$r has no read-only lease"
    dra-leases "${READER_VM[$r]}" "$r"
    dra-assert "$DRA_LEASES" "[(l['state'], l.get('mode'), bool(l.get('shared')), bool(l.get('readOnly')), l.get('serial')) for l in j] == [('Ready', 'dax', True, True, '$SHARED_SERIAL')]"
done
# All three hold their mapping now: none has its stop file yet.
for r in "${READERS[@]}"; do
    pod-log "$r" | grep -q '^final: ' && error "$r stopped holding before the others read"
done
shared0-attachments
pool-assert "$COMMAND_OUTPUT" "sorted((a['host'], a.get('exclusive', False), a['state']) for a in j) == sorted([('$VM1_NAME', False, 'attached'), ('$VM2_NAME', False, 'attached')])"
# The companion claims of the readers ask for read-only devices, one host
# of shared0 each. The readers get read-only fds from the node plugin
# (check-ro above); the companion pods use nothing of their claims, which
# get no CDI device.
READER_A_LEASE=$(lease-of reader-a)
dra-json "$VM2" resourceclaim -n "$DRA_NS" "cxl-lease-$READER_A_LEASE"
dra-assert "$COMMAND_OUTPUT" "[c['parameters'] for c in configs()] == [{'apiVersion': '$DRA_POOL_DRIVER/v1alpha1', 'kind': 'DeviceConfig', 'mode': 'dax', 'readOnly': True}]"
dra-assert "$COMMAND_OUTPUT" "[s['deviceClassName'] for s in subrequests()] == ['cxl-pool-shared'] and not any(s.get('capacity') for s in subrequests())"
READER_A_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
[ -z "$(dra-cdi-devices-with "$VM2" "$READER_A_UID")" ] ||
    error "the companion claim of reader-a has CDI devices: $(dra-cdi-devices-with "$VM2" "$READER_A_UID")"
for vm in "$VM2" "$VM1"; do
    pool-cxl-dump "$vm" readers
    cxl-assert "by_serial($SHARED_SERIAL) is not None and len(regions) == 1 and regions[0]['OnlineSize'] == 0"
done
found=$(pool-file-string "$SHARED_FILE" 0)
[ "$found" == "$TEXT" ] || error "host: $SHARED_FILE has '$found' at 0, expected '$TEXT'"

echo "### E2: a new exclusive request cannot take the device from the readers"
dra-exec "$VM2" reader-a cxl-request request --serial "$SHARED_SERIAL" --wait 15s
[ "$COMMAND_STATUS" == 3 ] || error "an exclusive request while readers hold shared0 exited $COMMAND_STATUS, expected 3 (not Ready in time)"
json=$(dra-last-json "$COMMAND_OUTPUT") || error "the late exclusive request printed no JSON"
dra-assert "$json" "j['state'] == 'Failed' and 'timeout' in j['error']"
# shellcheck disable=SC2034 # used in the snippet of retry-until
LATE_LEASE=$(dra-value "$json" "j['lease']")
retry-until --timeout 60 --interval 1 --message "nothing left of the late exclusive lease" \
    '[ -z "$(dra-vm-command-q "$VM2" "kubectl get pods,resourceclaims -n $DRA_NS -l $DRA_LEASE_LABEL=$LATE_LEASE -o name")" ]' ||
    error "the late exclusive lease left objects behind"
for r in "${READERS[@]}"; do
    pod-log "$r" | grep -q '^final: ' && error "$r lost its memory to the late exclusive request"
done

echo "### F: a fourth reader, on VM1, with a read-only claim from its creation"
dra-apply "$VM2" <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: shared-read-only
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool-shared
        selectors:
        - cel:
            expression: 'device.attributes["$DRA_POOL_DRIVER"].serial == "$SHARED_SERIAL"'
    config:
    - opaque:
        driver: $DRA_POOL_DRIVER
        parameters: {apiVersion: $DRA_POOL_DRIVER/v1alpha1, kind: DeviceConfig, readOnly: true}
EOF
dra-apply "$VM2" <<< "$(claim-pod-yaml reader-d "$VM1" shared-read-only "env | grep ^CXL_${SHARED_HEX}_ | sort
python3 /tools/dax-rw.py check-ro \"\$CXL_${SHARED_HEX}_DAX\" 0 || exit 1
echo \"read: \$(python3 /tools/dax-rw.py read \"\$CXL_${SHARED_HEX}_DAX\" 0)\"")"
dra-pod-wait "$VM2" reader-d Running 120
wait-log reader-d "read: $TEXT" 60
dra-kubectl "$VM2" "logs -n $DRA_NS reader-d"
# readOnly without a mode: mode dax, the only mode of a shared device.
dra-env-assert reader-d "$COMMAND_OUTPUT" "$SHARED_HEX" \
    SERIAL="$SHARED_SERIAL" SHARED=1 MODE=dax SIZE=$(( 256 << 20 )) "DAX=/dev/dax*" READONLY=1
for line in "open for writing refused: EPERM" "writable mapping refused: EACCES"; do
    grep -qxF "$line" <<< "$COMMAND_OUTPUT" || error "reader-d did not log '$line'"
done
dra-json "$VM2" resourceclaim -n "$DRA_NS" shared-read-only
dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$VM1_NAME'"
# The pool driver on VM1 prepared the claim as the CDI device of its
# allocation result, claim-<uid>-0 (spec cxl-pool), with a read-only
# device node, the environment of shared0 and the claim marker.
RO_CLAIM_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
cdi=$(dra-cdi-device "$VM1" "claim-$RO_CLAIM_UID-0")
echo "CDI device claim-$RO_CLAIM_UID-0: $cdi"
grep -qx "kind: nri.io/cxl-pool" <<< "$cdi" || error "no CDI device claim-$RO_CLAIM_UID-0 of kind nri.io/cxl-pool in VM1"
grep -qE '^ *permissions: r$' <<< "$cdi" || error "the CDI device of the claim of reader-d has no device node with permissions r"
grep -qF -- "- CXL_${SHARED_HEX}_READONLY=1" <<< "$cdi" || error "the CDI device of the claim of reader-d has no CXL_${SHARED_HEX}_READONLY=1"
grep -qF -- "- CXL_CLAIM_${RO_CLAIM_UID//-/_}=1" <<< "$cdi" || error "the CDI device of the claim of reader-d has no claim marker"
[ "$(dra-cdi-devices-with "$VM1" "$RO_CLAIM_UID")" == "claim-$RO_CLAIM_UID-0" ] ||
    error "the claim of reader-d has other CDI devices than claim-$RO_CLAIM_UID-0: $(dra-cdi-devices-with "$VM1" "$RO_CLAIM_UID")"
for r in "${READERS[@]}"; do
    pod-log "$r" | grep -q '^final: ' && error "$r stopped holding before reader-d read"
done
echo "four readers, two on each node, read '$TEXT' at the same time"

echo "### G: the readers finish, the device goes back to the pool"
for r in "${READERS[@]}"; do
    dra-exec "${READER_VM[$r]}" "$r" touch /tmp/stop || command-error "cannot stop $r"
done
for r in "${READERS[@]}"; do
    wait-log "$r" "final: $TEXT" 30
    wait-log "$r" "cxl-request exit 0" 30
done
dra-delete "$VM2" pod reader-d --grace-period=2 --wait=true --timeout=60s
dra-delete "$VM2" resourceclaim shared-read-only --wait=true --timeout=60s
for r in "${READERS[@]}"; do
    retry-until --timeout 60 --interval 1 --message "$r has no leases" \
        '[ -z "$(companions-of "$r")" ]' || error "$r still has companions: $(companions-of "$r")"
done
for vm in "$VM2" "$VM1"; do
    pool-cxl-wait "$vm" shared0-released "memdevs == []" 60
done
retry-until --timeout 60 --message "shared0 free" \
    'pool-host-client -o json devices shared0 >/dev/null && pool-py assert "$COMMAND_OUTPUT" "j[\"state\"] == \"free\" and j[\"attachments\"] in (None, [])"' ||
    error "shared0 is not free: $COMMAND_OUTPUT"

echo "### H1: the exclusive device pooled0 as a dax device, through a lease"
TEXT2="$TAG: pooled0 through a dax lease on VM2"
# The script, expanded by sh in the container.
script="echo \"lease \$CXL_LEASE read-only \$CXL_${POOLED0_HEX}_READONLY\"
python3 /tools/dax-rw.py --fd 3 write 0 \"\$1\" && python3 /tools/dax-rw.py --fd 3 read 0"
dra-exec "$VM2" reader-a cxl-request request --source pool --size 256Mi --mode dax --wait 120s --exec sh -c "$script" sh "$TEXT2" ||
    command-error "cxl-request request --source pool --size 256Mi --mode dax failed"
grep -qE '^lease [0-9a-f]{8} read-only 0$' <<< "$COMMAND_OUTPUT" ||
    error "the dax lease of pooled0 has not CXL_${POOLED0_HEX}_READONLY=0"
[ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "$TEXT2" ] || error "read '$(tail -n 1 <<< "$COMMAND_OUTPUT")' through the dax lease, expected '$TEXT2'"
DAX_LEASE=$(sed -n 's/^lease \([0-9a-f]\{8\}\) .*/\1/p' <<< "$COMMAND_OUTPUT")
dra-leases "$VM2" reader-a
dra-assert "$DRA_LEASES" "[(l['lease'], l['state'], l.get('source'), l.get('mode'), bool(l.get('shared')), l.get('serial'), l.get('node')) for l in j] == [('$DAX_LEASE', 'Ready', 'pool', 'dax', False, '$POOLED0_SERIAL', None)]"
dra-json "$VM2" resourceclaim -n "$DRA_NS" "cxl-lease-$DAX_LEASE"
dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$VM2_NAME' and device_data('pooled0')['shared'] == False"
# A devdax region, never onlined: no NUMA node, nothing lent.
pool-cxl-dump "$VM2" pooled0-dax
cxl-assert "by_serial($POOLED0_SERIAL) is not None and len(regions) == 1 and regions[0]['OnlineSize'] == 0"
pool-host-client -o json devices pooled0 || command-error "cannot get pooled0"
POOLED0_FILE=$(pool-value "$COMMAND_OUTPUT" 'j["path"]')
found=$(pool-file-string "$POOLED0_FILE" 0)
[ "$found" == "$TEXT2" ] || error "host: $POOLED0_FILE has '$found' at 0, expected '$TEXT2'"
dra-exec "$VM2" reader-a cxl-request release --lease "$DAX_LEASE" || command-error "cannot release $DAX_LEASE"
pool-cxl-wait "$VM2" pooled0-released "memdevs == []" 60

echo "### H2: the exclusive device pooled0 as a dax device, through a claim on VM1"
TEXT3="$TAG: pooled0 through a dax claim on VM1"
dra-apply "$VM2" <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: pooled-dax
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool
        capacity:
          requests:
            memory: 512Mi
    config:
    - opaque:
        driver: $DRA_POOL_DRIVER
        parameters: {apiVersion: $DRA_POOL_DRIVER/v1alpha1, kind: DeviceConfig, mode: dax}
EOF
dra-apply "$VM2" <<< "$(claim-pod-yaml dax-claimer "$VM1" pooled-dax "env | grep ^CXL_${POOLED0_HEX}_ | sort
echo \"before: \$(python3 /tools/dax-rw.py read \"\$CXL_${POOLED0_HEX}_DAX\" 0)\"
python3 /tools/dax-rw.py write \"\$CXL_${POOLED0_HEX}_DAX\" 0 \"$TEXT3\" || exit 1
echo \"read: \$(python3 /tools/dax-rw.py read \"\$CXL_${POOLED0_HEX}_DAX\" 0)\"")"
dra-pod-wait "$VM2" dax-claimer Running 120
wait-log dax-claimer "read: $TEXT3" 60
dra-kubectl "$VM2" "logs -n $DRA_NS dax-claimer"
# A dax device of its own, read-write, and no NUMA node.
dra-env-assert dax-claimer "$COMMAND_OUTPUT" "$POOLED0_HEX" \
    SERIAL="$POOLED0_SERIAL" SHARED=0 MODE=dax SIZE=$(( 512 << 20 )) "DAX=/dev/dax*" READONLY=0
# The device keeps its bytes from node to node: the lease on VM2 wrote them.
grep -xF "before: $TEXT2" <<< "$COMMAND_OUTPUT" ||
    echo "note: dax-claimer found other contents than the lease on VM2 left"
pool-cxl-dump "$VM1" pooled0-dax
cxl-assert "by_serial($POOLED0_SERIAL) is not None and len(regions) == 1 and regions[0]['OnlineSize'] == 0"
found=$(pool-file-string "$POOLED0_FILE" 0)
[ "$found" == "$TEXT3" ] || error "host: $POOLED0_FILE has '$found' at 0, expected '$TEXT3'"
dra-delete "$VM2" pod dax-claimer --grace-period=2 --wait=true --timeout=60s
dra-delete "$VM2" resourceclaim pooled-dax --wait=true --timeout=60s
pool-cxl-wait "$VM1" pooled0-released "memdevs == []" 60
retry-until --timeout 60 --message "pooled0 and shared0 free" \
    'pool-host-client -o json devices >/dev/null && pool-py assert "$COMMAND_OUTPUT" "sorted((d[\"name\"], d[\"state\"]) for d in j if d[\"name\"] in (\"pooled0\", \"shared0\")) == [(\"pooled0\", \"free\"), (\"shared0\", \"free\")]"' ||
    error "the pool devices are not free: $COMMAND_OUTPUT"
for vm in "$VM2" "$VM1"; do
    pool-vm-monitor "$vm" "info qtree -b" | grep -q 'dev: cxl-type3' &&
        error "qemu of $(pool-vm-label "$vm") still has a CXL memory device"
done

echo "### I: what every component of both nodes did, in order"
dra-trace-stop
dra-trace-summary
echo "TIMING: writer exit until all readers hold the memory: $T_READERS s"

echo "### cleanup"
dra-cleanup
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
