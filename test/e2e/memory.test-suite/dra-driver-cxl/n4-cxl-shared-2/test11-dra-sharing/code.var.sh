# CXL memory sharing between two nodes of a Kubernetes cluster with DRA
#
# A shared CXL memory device of a pool can be attached to many servers at
# once. They all see the same bytes: what one server writes, the others
# read, without a network in between. Shared memory must never become
# system RAM (two kernels allocating the same memory corrupt each other),
# so the servers map it as a devdax device, /dev/daxX.Y, and programs mmap
# it.
#
# Here the servers are the VMs of n4-cxl-shared-2 (VM2, the VM of the test,
# the control plane) and n4-cxl-shared-1 (VM1, a worker): two nodes of one
# Kubernetes cluster, the two that the pool is cabled to (VM0, the third
# node, is not). fake-cxl-pool-controller publishes the devices of
# fake-cxl-pool-server once, for the nodes the pool reaches, and
# nri-dra-driver-cxl runs on every node (see test10-dra-pooling). A pod on
# VM1 and a pod on VM2 have a ResourceClaim of class cxl-pool-shared each,
# both for the same shared device: each claim takes one share of it
# (shares: "1"), and the controller attaches the device to both nodes at
# once. The node plugin of each node creates a devdax region on it and
# gives the container the device node and its name in CXL_<KEY>_DAX, with
# CXL_<KEY>_SHARED=1 and _MODE=dax. Each node attaches and releases the
# device independently.
#
# What you will see: the shared device in the ResourceSlice of the pool,
# a pod on VM1 writing a string to the shared memory, a pod on VM2 reading
# the same string, the host finding it in the backing file of the device,
# VM1 letting go while VM2 still reads, and at the end one trace of both
# nodes, in order.
#
# Run test00-up of n4-cxl-shared-1, -0 and -2 first: they create the VMs and
# make them one cluster. The DRA driver comes from its image, build it
# first:
#   make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

echo "### preconditions: one cluster, VM2 control plane, VM1 and VM0 workers (test00-up)"
pool-cluster-require

VM1="$POOL_VM1_DIR"    # a worker, driven over ssh from the host
VM2="$OUTPUT_DIR"      # the VM of this test, the control plane
VM1_NAME="$POOL_VM1_NAME"
VM2_NAME="$POOL_VM2_NAME"
SHARED_SERIAL=0xc1ae0001   # 0xc1ae....: shared pool devices
SHARED_HEX=C1AE0001        # the serial in environment variable names
SHARED_SIZE=$(( 256 << 20 ))
PYTHON_IMAGE=docker.io/library/python:3-alpine
TAG="dra-sharing $(date +%Y-%m-%dT%H:%M:%S.%N)"
TEXT="$TAG from VM1"

shared-claim-yaml() {
    # Usage: shared-claim-yaml NAME
    #
    # The ResourceClaim NAME for one share of the shared device.
    cat <<EOT
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: $1
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: cxl-pool-shared
        selectors:
        - cel:
            expression: 'device.attributes["$DRA_POOL_DRIVER"].serial == "$SHARED_SERIAL"'
        capacity:
          requests:
            shares: "1"
EOT
}

# shellcheck disable=SC2001 # sed indents every line of SCRIPT
dax-pod-yaml() {
    # Usage: dax-pod-yaml NAME NODE CLAIM SCRIPT
    #
    # A python:3-alpine pod NAME on Kubernetes node NODE with the
    # ResourceClaim CLAIM and the dax-rw tool in /tools, running the shell
    # SCRIPT, then sleeping.
    local name="$1" node="$2" claim="$3" script="$4"
    cat <<EOT
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
  - name: shared
    resourceClaimName: $claim
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
EOT
}

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
    size: 256Mi
    shared: true
    pool: default
    serial: $SHARED_SERIAL"
pool-client-install "$VM2" "$VM1"

echo "### preconditions: the pool controller on the control plane, the node plugin on every node"
dra-build
dra-install
for vm in "$VM2" "$VM1"; do
    dra-pull-images "$vm" "$PYTHON_IMAGE"
done
dra-dax-tool-install "$VM2"
dra-trace-start "$VM2" "$VM1"

echo "### A: the shared device is published once, for VM1 and VM2"
# A shared device has no memory capacity to consume: every node gets all
# of it. What it has is "shares", 1M without a requestPolicy: a claim
# without a shares request takes all of them (exclusive), a claim with
# shares: "1" one of them.
dra-kubectl "$VM2" "get resourceslices"
dra-json "$VM2" resourceslices
S0="device('shared0', '$DRA_POOL_DRIVER')"
dra-assert "$COMMAND_OUTPUT" "len(slices('$DRA_POOL_DRIVER')) == 1 and pool_nodes('$POOL_DEFAULT_NAME') == sorted(['$VM1_NAME', '$VM2_NAME'])"
dra-assert "$COMMAND_OUTPUT" "slices('$DRA_LOCAL_DRIVER', '$VM1_NAME') and slices('$DRA_LOCAL_DRIVER', '$VM2_NAME')"
dra-assert "$COMMAND_OUTPUT" "$S0 is not None and attr($S0, 'type') == 'memdev' and attr($S0, 'source') == 'pool' and attr($S0, 'shared') == True and attr($S0, 'serial') == '$SHARED_SERIAL' and attr($S0, 'size') == $SHARED_SIZE"
dra-assert "$COMMAND_OUTPUT" "${S0}.get('allowMultipleAllocations') == True"
dra-assert "$COMMAND_OUTPUT" "sorted(${S0}['capacity']) == ['shares'] and quantity(capacity($S0, 'shares')) == $DRA_SHARES and request_policy($S0, 'shares') is None"
dra-assert "$COMMAND_OUTPUT" "${S0}['bindsToNode'] == True and ${S0}['bindingConditions'] == ['$DRA_POOL_DRIVER/Attached']"

echo "### B: a pod on VM1 writes"
dra-apply "$VM2" <<< "$(shared-claim-yaml writer-memory)"
dra-apply "$VM2" <<< "$(dax-pod-yaml writer "$VM1_NAME" writer-memory "env | grep ^CXL_ | sort
python3 /tools/dax-rw.py write \"\$CXL_${SHARED_HEX}_DAX\" 0 \"$TEXT\" || exit 1
echo \"wrote at offset 0\"")"
dra-wait "$VM2" writer-attached "resourceclaim -n $DRA_NS writer-memory" \
    "condition('$DRA_POOL_DRIVER/Attached') == 'True'" 60
VM1_CLAIM_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
dra-claim-conditions "$VM2" writer-memory
dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$VM1_NAME' and device_data('shared0')['shared'] == True and device_data('shared0')['serial'] == '$SHARED_SERIAL'"
dra-pod-wait "$VM2" writer Running 120
dra-assert "$(dra-vm-command-q "$VM2" "kubectl get pod -n $DRA_NS writer -o json")" "j['spec']['nodeName'] == '$VM1_NAME'"
retry-until --timeout 30 --message "writer has written" \
    'dra-vm-command-q "$VM2" "kubectl logs -n $DRA_NS writer" | grep -q "^wrote at offset 0"' ||
    error "the writer did not write, see: $(dra-vm-command-q "$VM2" "kubectl logs -n $DRA_NS writer")"
dra-kubectl "$VM2" "logs -n $DRA_NS writer"
WRITER_LOG="$COMMAND_OUTPUT"
# The environment of the shared device, read-write, and the marker of the
# allocation result of the claim (result 0), nothing else.
dra-env-assert writer "$WRITER_LOG" "$SHARED_HEX" \
    SERIAL="$SHARED_SERIAL" SHARED=1 MODE=dax SIZE="$SHARED_SIZE" "DAX=/dev/dax*" READONLY=0
grep -qx "CXL_CLAIM_${VM1_CLAIM_UID//-/_}_0=1" <<< "$WRITER_LOG" ||
    error "writer has no marker CXL_CLAIM_${VM1_CLAIM_UID//-/_}_0=1 of result 0 of its claim"
[ "$(grep -c '^CXL_' <<< "$WRITER_LOG")" == 7 ] ||
    error "writer has other CXL_ variables than the six of $SHARED_SERIAL and the marker of its result: $(grep '^CXL_' <<< "$WRITER_LOG")"
VM1_DAX=$(dra-env-value "$WRITER_LOG" "CXL_${SHARED_HEX}_DAX")
# In VM1 the device is a devdax region, never system RAM.
pool-cxl-wait "$VM1" shared0-writer \
    "by_serial($SHARED_SERIAL) is not None and len(regions) == 1 and regions[0]['Enabled'] and regions[0]['OnlineSize'] == 0"
pool-vm-command "$VM1" "ls -l $VM1_DAX && basename \$(readlink /sys/bus/dax/devices/${VM1_DAX#/dev/}/driver)" ||
    command-error "no devdax device $VM1_DAX in VM1"
[ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "device_dax" ] ||
    error "$VM1_DAX in VM1 is not bound to device_dax"
# VM2 has nothing of it yet.
pool-cxl-dump "$VM2" shared0-writer
cxl-assert "memdevs == [] and regions == []"

echo "### C: a pod on VM2 reads the same bytes"
dra-apply "$VM2" <<< "$(shared-claim-yaml reader-memory)"
dra-apply "$VM2" <<< "$(dax-pod-yaml reader "$VM2_NAME" reader-memory "python3 /tools/dax-rw.py read \"\$CXL_${SHARED_HEX}_DAX\" 0 || exit 1")"
dra-wait "$VM2" reader-attached "resourceclaim -n $DRA_NS reader-memory" \
    "condition('$DRA_POOL_DRIVER/Attached') == 'True'" 60
VM2_CLAIM_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$VM2_NAME'"
dra-pod-wait "$VM2" reader Running 120
retry-until --timeout 30 --message "reader has read" \
    '[ -n "$(dra-vm-command-q "$VM2" "kubectl logs -n $DRA_NS reader")" ]' ||
    error "the reader printed nothing"
dra-kubectl "$VM2" "logs -n $DRA_NS reader"
[ "$COMMAND_OUTPUT" == "$TEXT" ] ||
    error "VM2 read '$COMMAND_OUTPUT', expected '$TEXT'"
echo "VM2 read: '$COMMAND_OUTPUT'"
pool-cxl-dump "$VM2" shared0-reader
cxl-assert "len(regions) == 1 and regions[0]['OnlineSize'] == 0"
# One device, two hosts, each attachment owned by the claim of its node.
pool-host-client -o json devices shared0 || command-error "cannot get shared0"
pool-assert "$COMMAND_OUTPUT" "sorted((a['host'], a.get('owner'), a['state']) for a in j['attachments']) == sorted([('$VM1_NAME', 'k8s:resourceclaim/$VM1_CLAIM_UID', 'attached'), ('$VM2_NAME', 'k8s:resourceclaim/$VM2_CLAIM_UID', 'attached')])"
SHARED_FILE=$(pool-value "$COMMAND_OUTPUT" 'j["path"]')
found=$(pool-file-string "$SHARED_FILE" 0)
[ "$found" == "$TEXT" ] || error "host: $SHARED_FILE has '$found' at 0, expected '$TEXT'"
echo "host read at 0 of $SHARED_FILE: '$found'"

echo "### D: each node releases independently"
dra-delete "$VM2" pod writer --grace-period=2 --wait=true --timeout=60s
dra-delete "$VM2" resourceclaim writer-memory --wait=true --timeout=60s
pool-cxl-wait "$VM1" shared0-released "memdevs == []" 60
retry-until --timeout 30 --message "shared0 attached only to VM2" \
    'pool-host-client -o json devices shared0 >/dev/null && pool-py assert "$COMMAND_OUTPUT" "[a[\"host\"] for a in j[\"attachments\"] or []] == [\"$VM2_NAME\"]"' ||
    error "shared0 is not attached to VM2 only: $COMMAND_OUTPUT"
# VM2 still has the memory, and the bytes are still there.
dra-json "$VM2" pod -n "$DRA_NS" reader
dra-assert "$COMMAND_OUTPUT" "j['status']['phase'] == 'Running'"
dra-kubectl "$VM2" "exec -n $DRA_NS reader -- sh -c 'python3 /tools/dax-rw.py read \"\$CXL_${SHARED_HEX}_DAX\" 0'" ||
    command-error "cannot read the shared memory in the reader"
[ "$COMMAND_OUTPUT" == "$TEXT" ] ||
    error "after VM1 released shared0, VM2 read '$COMMAND_OUTPUT', expected '$TEXT'"
dra-delete "$VM2" pod reader --grace-period=2 --wait=true --timeout=60s
dra-delete "$VM2" resourceclaim reader-memory --wait=true --timeout=60s
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

echo "### E: what every component on VM2 and VM1 did, in order"
dra-trace-stop
dra-trace-summary

echo "### cleanup"
dra-cleanup
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
