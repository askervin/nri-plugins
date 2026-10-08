# CXL memory sharing between two Kubernetes clusters with DRA
#
# A shared CXL memory device of a pool can be attached to many servers at
# once. They all see the same bytes: what one server writes, the others
# read, without a network in between. Shared memory must never become
# system RAM (two kernels allocating the same memory corrupt each other),
# so the servers map it as a devdax device, /dev/daxX.Y, and programs mmap
# it.
#
# Here the servers are the VMs of n4-cxl-shared-1 (VM1) and n4-cxl-shared-2
# (VM2, the VM of the test). Each is a one-node Kubernetes cluster of its
# own: several clusters sharing one memory pool. Both clusters run
# fake-cxl-pool-controller and kubelet-cxl-plugin (see
# test10-dra-pooling), and both controllers use the same
# fake-cxl-pool-server on the host. A ResourceClaim of class
# cxl-shared-memory gets the shared device: the node plugin creates a
# devdax region on it and gives the container the device node and its name
# in CXL_SHARED_DAX_<serial>. Each cluster attaches and releases the device
# independently.
#
# What you will see: the shared device in the ResourceSlices of both
# clusters, a pod in cluster 1 writing a string to the shared memory, a pod
# in cluster 2 reading the same string, the host finding it in the backing
# file of the device, cluster 1 letting go while cluster 2 still reads,
# and at the end one trace of both clusters, in order.
#
# Create both VMs first with test00-up of n4-cxl-shared-1 and -2. This test
# starts VM1 if it is not running.

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

VM1="$POOL_VM1_DIR"    # cluster 1, driven over ssh from the host
VM2="$OUTPUT_DIR"      # cluster 2, the VM of this test
VM1_NAME="$POOL_VM1_NAME"
VM2_NAME="$POOL_VM2_NAME"
SHARED_SERIAL=0xc1ae0001   # 0xc1ae....: shared pool devices
SHARED_HEX=C1AE0001        # the serial in environment variable names
SHARED_SIZE=$(( 256 << 20 ))
PYTHON_IMAGE=docker.io/library/python:3-alpine
TAG="dra-sharing $(date +%Y-%m-%dT%H:%M:%S.%N)"
TEXT="$TAG from cluster 1"

shared-claim-yaml() {
    # Usage: shared-claim-yaml
    #
    # The claim for the shared device, the same in both clusters.
    cat <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: shared-memory
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-shared-memory
        selectors:
        - cel:
            expression: 'device.attributes["$DRA_POOL_DRIVER"].serial == "$SHARED_SERIAL"'
EOF
}

# shellcheck disable=SC2001 # sed indents every line of SCRIPT
dax-pod-yaml() {
    # Usage: dax-pod-yaml NAME SCRIPT
    #
    # A python:3-alpine pod with the shared claim and the dax-rw tool in
    # /tools, running the shell SCRIPT, then sleeping.
    local name="$1" script="$2"
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
spec:
  terminationGracePeriodSeconds: 2
  restartPolicy: Never
  resourceClaims:
  - name: shared
    resourceClaimName: shared-memory
  volumes:
  - name: tools
    configMap:
      name: dax-rw
  containers:
  - name: $name
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
      - name: shared
EOF
}

echo "### preconditions: VM1 is up"
pool-host-wait "$VM1" "create VM1 first: ./run_tests.sh memory.test-suite/memory-policy/n4-cxl-shared-1/test00-up"

echo "### preconditions: patched qemu, hdm_for_passthrough=on, kernel with CONFIG_FS_DAX"
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

echo "### preconditions: fake-cxl-pool-server on the host, with the shared device shared0"
pool-server-start "
  - name: shared0
    size: 256M
    shared: true
    pool: default
    serial: $SHARED_SERIAL"
pool-client-install "$VM2" "$VM1"

echo "### preconditions: the pool controller and the node plugin run in both clusters"
dra-build
dra-install "$VM2"
dra-install "$VM1"
for vm in "$VM2" "$VM1"; do
    dra-pull-images "$vm" "$PYTHON_IMAGE"
    dra-dax-tool-install "$vm"
done
dra-trace-start "$VM2" "$VM1"

echo "### A: both clusters see the same shared device"
# A shared device has no memory capacity to consume: every cluster, every
# node gets all of it. What it has is "hosts": how many nodes may attach
# it at once, one per claim.
for vm in "$VM1" "$VM2"; do
    dra-kubectl "$vm" "get resourceslices"
    dra-json "$vm" resourceslices
    S0="device('shared0', '$DRA_POOL_DRIVER')"
    dra-assert "$COMMAND_OUTPUT" "$S0 is not None and attr($S0, 'shared') == True and attr($S0, 'serial') == '$SHARED_SERIAL' and attr($S0, 'size') == $SHARED_SIZE"
    dra-assert "$COMMAND_OUTPUT" "${S0}.get('allowMultipleAllocations') == True"
    dra-assert "$COMMAND_OUTPUT" "capacity($S0, 'hosts') == '4' and ${S0}['capacity']['hosts']['requestPolicy']['default'] == '1'"
    dra-assert "$COMMAND_OUTPUT" "${S0}['bindsToNode'] == True and ${S0}['bindingConditions'] == ['$DRA_POOL_DRIVER/Attached']"
done

echo "### B: cluster 1 writes"
dra-apply "$VM1" <<< "$(shared-claim-yaml)"
dra-apply "$VM1" <<< "$(dax-pod-yaml writer "env | grep ^CXL_ | sort
python3 /tools/dax-rw.py write \"\$CXL_SHARED_DAX_$SHARED_HEX\" 0 \"$TEXT\" || exit 1
echo \"wrote at offset 0\"")"
dra-wait "$VM1" attached "resourceclaim -n $DRA_NS shared-memory" \
    "condition('$DRA_POOL_DRIVER/Attached') == 'True'" 60
VM1_CLAIM_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
dra-claim-conditions "$VM1" shared-memory
dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$VM1_NAME' and device_data('shared0')['shared'] == True and device_data('shared0')['serial'] == '$SHARED_SERIAL'"
dra-pod-wait "$VM1" writer Running 120
retry-until --timeout 30 --message "writer has written" \
    'dra-vm-command-q "$VM1" "kubectl logs -n $DRA_NS writer" | grep -q "^wrote at offset 0"' ||
    error "the writer did not write, see: $(dra-vm-command-q "$VM1" "kubectl logs -n $DRA_NS writer")"
dra-kubectl "$VM1" "logs -n $DRA_NS writer"
WRITER_LOG="$COMMAND_OUTPUT"
VM1_DAX=$(sed -n "s|^CXL_SHARED_DAX_$SHARED_HEX=||p" <<< "$WRITER_LOG")
[[ "$VM1_DAX" == /dev/dax* ]] || error "writer has no CXL_SHARED_DAX_$SHARED_HEX=/dev/daxX.Y"
grep -qx "CXL_SHARED_SIZE_$SHARED_HEX=$SHARED_SIZE" <<< "$WRITER_LOG" ||
    error "writer has no CXL_SHARED_SIZE_$SHARED_HEX=$SHARED_SIZE"
# In VM1 the device is a devdax region, never system RAM.
pool-cxl-wait "$VM1" shared0-writer \
    "by_serial($SHARED_SERIAL) is not None and len(regions) == 1 and regions[0]['Enabled'] and regions[0]['OnlineSize'] == 0"
pool-vm-command "$VM1" "ls -l $VM1_DAX && basename \$(readlink /sys/bus/dax/devices/${VM1_DAX#/dev/}/driver)" ||
    command-error "no devdax device $VM1_DAX in VM1"
[ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "device_dax" ] ||
    error "$VM1_DAX in VM1 is not bound to device_dax"

echo "### C: cluster 2 reads the same bytes"
dra-apply "$VM2" <<< "$(shared-claim-yaml)"
dra-apply "$VM2" <<< "$(dax-pod-yaml reader "python3 /tools/dax-rw.py read \"\$CXL_SHARED_DAX_$SHARED_HEX\" 0 || exit 1")"
dra-wait "$VM2" attached "resourceclaim -n $DRA_NS shared-memory" \
    "condition('$DRA_POOL_DRIVER/Attached') == 'True'" 60
VM2_CLAIM_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$VM2_NAME'"
dra-pod-wait "$VM2" reader Running 120
retry-until --timeout 30 --message "reader has read" \
    '[ -n "$(dra-vm-command-q "$VM2" "kubectl logs -n $DRA_NS reader")" ]' ||
    error "the reader printed nothing"
dra-kubectl "$VM2" "logs -n $DRA_NS reader"
[ "$COMMAND_OUTPUT" == "$TEXT" ] ||
    error "cluster 2 read '$COMMAND_OUTPUT', expected '$TEXT'"
echo "cluster 2 read: '$COMMAND_OUTPUT'"
pool-cxl-dump "$VM2" shared0-reader
cxl-assert "len(regions) == 1 and regions[0]['OnlineSize'] == 0"
# One device, two hosts, each attachment owned by the claim of its cluster.
pool-host-client -o json devices shared0 || command-error "cannot get shared0"
pool-assert "$COMMAND_OUTPUT" "sorted((a['host'], a.get('owner'), a['state']) for a in j['attachments']) == sorted([('$VM1_NAME', 'k8s:resourceclaim/$VM1_CLAIM_UID', 'attached'), ('$VM2_NAME', 'k8s:resourceclaim/$VM2_CLAIM_UID', 'attached')])"
SHARED_FILE=$(pool-value "$COMMAND_OUTPUT" 'j["path"]')
found=$(pool-file-string "$SHARED_FILE" 0)
[ "$found" == "$TEXT" ] || error "host: $SHARED_FILE has '$found' at 0, expected '$TEXT'"
echo "host read at 0 of $SHARED_FILE: '$found'"

echo "### D: each cluster releases independently"
dra-delete "$VM1" pod writer --grace-period=2 --wait=true --timeout=60s
dra-delete "$VM1" resourceclaim shared-memory --wait=true --timeout=60s
pool-cxl-wait "$VM1" shared0-released "memdevs == []" 60
retry-until --timeout 30 --message "shared0 attached only to VM2" \
    'pool-host-client -o json devices shared0 >/dev/null && pool-py assert "$COMMAND_OUTPUT" "[a[\"host\"] for a in j[\"attachments\"] or []] == [\"$VM2_NAME\"]"' ||
    error "shared0 is not attached to VM2 only: $COMMAND_OUTPUT"
# Cluster 2 still has the memory, and the bytes are still there.
dra-json "$VM2" pod -n "$DRA_NS" reader
dra-assert "$COMMAND_OUTPUT" "j['status']['phase'] == 'Running'"
dra-kubectl "$VM2" "exec -n $DRA_NS reader -- sh -c 'python3 /tools/dax-rw.py read \"\$CXL_SHARED_DAX_$SHARED_HEX\" 0'" ||
    command-error "cannot read the shared memory in the reader"
[ "$COMMAND_OUTPUT" == "$TEXT" ] ||
    error "after cluster 1 released shared0, cluster 2 read '$COMMAND_OUTPUT', expected '$TEXT'"
dra-delete "$VM2" pod reader --grace-period=2 --wait=true --timeout=60s
dra-delete "$VM2" resourceclaim shared-memory --wait=true --timeout=60s
pool-cxl-wait "$VM2" shared0-released "memdevs == []" 60
retry-until --timeout 30 --message "shared0 free" \
    'pool-host-client -o json devices shared0 >/dev/null && pool-py assert "$COMMAND_OUTPUT" "j[\"state\"] == \"free\" and j[\"attachments\"] in (None, [])"' ||
    error "shared0 is not free: $COMMAND_OUTPUT"
for vm in "$VM2" "$VM1"; do
    pool-vm-monitor "$vm" "info qtree -b" | grep -q 'dev: cxl-type3' &&
        error "qemu of $(pool-vm-label "$vm") still has a CXL memory device"
done
deleted=$(grep -c 'event DEVICE_DELETED' "$POOL_SERVER_LOG")
[ "$deleted" -ge 2 ] || error "expected DEVICE_DELETED from both qemus, see $POOL_SERVER_LOG"
grep -E 'attachment shared0@.*: (attached|detached)|event DEVICE_DELETED' "$POOL_SERVER_LOG"

echo "### E: what every component of both clusters did, in order"
dra-trace-stop
dra-trace-summary

echo "### cleanup"
dra-cleanup
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
