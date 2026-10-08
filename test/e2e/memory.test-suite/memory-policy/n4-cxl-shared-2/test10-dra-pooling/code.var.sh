# CXL memory pooling with Dynamic Resource Allocation (DRA)
#
# A CXL memory pool is a box of memory devices that is cabled to many
# servers. The pool attaches a device to one server when that server needs
# more memory, and detaches it when the server is done: memory moves to
# where it is needed, without opening any server.
#
# Here the pool is fake-cxl-pool-server on the host. It hotplugs CXL
# memory devices into the qemu of this VM (n4-cxl-shared-2), the one-node
# Kubernetes cluster of the test. Kubernetes asks for the memory with DRA:
# - fake-cxl-pool-controller (in the VM) publishes the devices of the pool
#   in a ResourceSlice of driver cxl-pool.generic, attaches the device that
#   the scheduler allocated for a ResourceClaim to the node the scheduler
#   picked, and writes the condition cxl-pool.generic/Attached to the claim.
# - kube-scheduler allocates a device for the claim and waits for that
#   binding condition before it binds the pod to the node.
# - kubelet-cxl-plugin (in the VM, the node plugin of the CXL DRA driver)
#   prepares the claim: it finds the hotplugged memory device by its
#   serial number, creates a region on it and onlines its memory. The
#   memory becomes a new NUMA node, and the container gets its id in the
#   environment variable CXL_POOL_NODE_<serial>. When the pod is gone, the
#   node plugin releases the device, the controller detaches it, and the
#   memory is back in the pool.
#
# What you will see: the pool in a ResourceSlice, a claim of 512Mi that
# waits for the attachment, a new 512 MB NUMA node in the VM and in the
# pod, the memory going back to the pool, and at the end the trace summary
# of what every component did, in order.
#
# Create the VM first with test00-up of n4-cxl-shared-2 (see there for the
# patched qemu). The DRA driver comes from
# ~/github.com/intel/intel-resource-drivers-for-kubernetes, or
# CXL_DRA_DRIVER_SRC.

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

VM2="$OUTPUT_DIR"      # the VM and the cluster of this test
VM2_NAME="$POOL_VM2_NAME"
POOLED0_SERIAL=0xc1ee0001   # 0xc1ee....: exclusive pool devices
POOLED0_HEX=C1EE0001        # the serial in environment variable names
POOLED0_SIZE=$(( 512 << 20 ))
POOLED1_SERIAL=0xc1ee0002
POOLED1_SIZE=$(( 256 << 20 ))

echo "### preconditions: patched qemu, hdm_for_passthrough=on, kernel with CONFIG_FS_DAX"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"

echo "### preconditions: cxl, daxctl and cxl-dump in the VM, no CXL memory devices"
pool-vm-tools-install "$VM2"
pool-vm-reset "$VM2"
pool-cxl-dump "$VM2" no-devices
cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
CPU_NODES=$(cxl-value 'len(nodes)')

echo "### preconditions: fake-cxl-pool-server on the host, with two exclusive devices"
pool-server-start "
  - name: pooled0
    size: 512M
    shared: false
    pool: default
    serial: $POOLED0_SERIAL
  - name: pooled1
    size: 256M
    shared: false
    pool: default
    serial: $POOLED1_SERIAL"
pool-client-install "$VM2"

echo "### preconditions: the pool controller and the node plugin run in the cluster"
dra-build
dra-install "$VM2"
dra-pull-images "$VM2" docker.io/library/busybox:latest
dra-trace-start "$VM2"

echo "### A: the pool is visible in Kubernetes"
# The controller publishes the devices of the pool in one ResourceSlice
# for all nodes. The node plugin publishes the memory of the node (DRAM,
# and CXL memory that is already in the node) in a slice of its own.
dra-kubectl "$VM2" "get resourceslices"
dra-json "$VM2" resourceslices
SLICES="$COMMAND_OUTPUT"
dra-assert "$SLICES" "len(slices('$DRA_POOL_DRIVER')) == 1 and slices('$DRA_POOL_DRIVER')[0]['spec'].get('allNodes') == True"
dra-assert "$SLICES" "sorted(d['name'] for d in devices('$DRA_POOL_DRIVER')) == ['pooled0', 'pooled1']"
P0="device('pooled0', '$DRA_POOL_DRIVER')"
P1="device('pooled1', '$DRA_POOL_DRIVER')"
dra-assert "$SLICES" "attr($P0, 'shared') == False and attr($P0, 'size') == $POOLED0_SIZE and attr($P0, 'serial') == '$POOLED0_SERIAL'"
dra-assert "$SLICES" "capacity($P0, 'memory') == '512Mi'"
dra-assert "$SLICES" "attr($P1, 'shared') == False and attr($P1, 'size') == $POOLED1_SIZE and capacity($P1, 'memory') == '256Mi'"
# The device is not on any node yet: the scheduler picks the node
# (bindsToNode), and waits until the pool has attached the device there.
dra-assert "$SLICES" "${P0}['bindsToNode'] == True and ${P0}['bindingConditions'] == ['$DRA_POOL_DRIVER/Attached']"
dra-assert "$SLICES" "${P0}['bindingFailureConditions'] == ['$DRA_POOL_DRIVER/AttachFailed']"
dra-assert "$SLICES" "len(slices('$DRA_LOCAL_DRIVER', '$VM2_NAME')) == 1"
dra-assert "$SLICES" "any(attr(d, 'type') == 'dram' for d in devices('$DRA_LOCAL_DRIVER', '$VM2_NAME'))"
dra-assert "$SLICES" "not any(attr(d, 'type') == 'cxl-node' for d in devices('$DRA_LOCAL_DRIVER', '$VM2_NAME'))"
# The pool itself says the same.
pool-client "$VM2" devices || command-error "cannot list the devices of the pool"
pool-client "$VM2" -o json devices || command-error "cannot list the devices of the pool"
pool-assert "$COMMAND_OUTPUT" "sorted((d['name'], d['state']) for d in j if d['name'].startswith('pooled')) == [('pooled0', 'free'), ('pooled1', 'free')]"

echo "### B: a pod asks for 512Mi of pooled CXL memory"
# Only pooled0 has 512Mi. The pod prints what it got and sleeps.
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
        deviceClassName: cxl-pool-memory
        capacity:
          requests:
            memory: 512Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: pooled-consumer
spec:
  terminationGracePeriodSeconds: 2
  restartPolicy: Never
  resourceClaims:
  - name: pooled
    resourceClaimName: pooled-memory
  containers:
  - name: consumer
    image: docker.io/library/busybox:latest
    imagePullPolicy: IfNotPresent
    command:
    - sh
    - -c
    - |
      env | grep ^CXL_ | sort
      echo
      grep -H . /sys/devices/system/node/node*/meminfo | grep MemTotal
      grep Mems_allowed_list /proc/self/status
      trap "exit 0" TERM; sleep infinity & wait
    resources:
      claims:
      - name: pooled
EOF
t_apply=$EPOCHREALTIME

echo "### C: the scheduler waits for the attachment"
# The scheduler allocates pooled0 for the claim, pins the claim to this
# node, and reports that the binding conditions are pending.
dra-wait "$VM2" binding-conditions-pending "events -n $DRA_NS" \
    "events('BindingConditionsPending', 'pooled-consumer')" 60
dra-kubectl "$VM2" "get events -n $DRA_NS --field-selector involvedObject.name=pooled-consumer"
# The controller sees the allocation, the pool attaches pooled0 to the VM,
# and the controller tells the scheduler with the condition Attached.
dra-wait "$VM2" attached "resourceclaim -n $DRA_NS pooled-memory" \
    "condition('$DRA_POOL_DRIVER/Attached') == 'True'" 60
CLAIM_JSON="$COMMAND_OUTPUT"
t_attached=$EPOCHREALTIME
dra-claim-conditions "$VM2" pooled-memory
dra-assert "$CLAIM_JSON" "[(r['driver'], r['device']) for r in results()] == [('$DRA_POOL_DRIVER', 'pooled0')]"
dra-assert "$CLAIM_JSON" "allocated_node() == '$VM2_NAME'"
# What the node plugin needs to find the device is in the claim status.
dra-assert "$CLAIM_JSON" "device_data('pooled0')['serial'] == '$POOLED0_SERIAL' and device_data('pooled0')['shared'] == False and device_data('pooled0')['size'] == $POOLED0_SIZE"
CLAIM_UID=$(dra-value "$CLAIM_JSON" "j['metadata']['uid']")
pool-client "$VM2" attachments || command-error "cannot list the attachments of the pool"
pool-client "$VM2" -o json attachments || command-error "cannot list the attachments of the pool"
pool-assert "$COMMAND_OUTPUT" "[(a['device'], a['host'], a.get('owner')) for a in j] == [('pooled0', '$VM2_NAME', 'k8s:resourceclaim/$CLAIM_UID')]"

echo "### D: the node makes the memory usable"
# The scheduler binds the pod, kubelet asks the node plugin to prepare the
# claim: a region on the new memory device, its memory online.
dra-pod-wait "$VM2" pooled-consumer Running 120
t_running=$EPOCHREALTIME
pool-cxl-wait "$VM2" pooled0-prepared \
    "by_serial($POOLED0_SERIAL) is not None and len(regions) == 1 and regions[0]['Enabled'] and regions[0]['OnlineSize'] == $POOLED0_SIZE"
cxl-assert "names(regions[0]['Memories']) == [by_serial($POOLED0_SERIAL)['Name']]"
cxl-assert "regions[0]['Node'] >= $CPU_NODES"
CXL_NODE=$(cxl-value "regions[0]['Node']")
echo "pooled0 is NUMA node $CXL_NODE of the VM"
vm-command "numactl -H" || command-error "numactl failed"
grep -q "^node $CXL_NODE size: 512 MB" <<< "$COMMAND_OUTPUT" ||
    error "numactl -H does not show node $CXL_NODE with 512 MB"
# The container knows which node has its memory.
dra-kubectl "$VM2" "logs -n $DRA_NS pooled-consumer" || command-error "cannot get the log of pooled-consumer"
POD_LOG="$COMMAND_OUTPUT"
grep -qx "CXL_POOL_NODE_$POOLED0_HEX=$CXL_NODE" <<< "$POD_LOG" ||
    error "pooled-consumer has no CXL_POOL_NODE_$POOLED0_HEX=$CXL_NODE"
grep -qx "CXL_POOL_SIZE_$POOLED0_HEX=$POOLED0_SIZE" <<< "$POD_LOG" ||
    error "pooled-consumer has no CXL_POOL_SIZE_$POOLED0_HEX=$POOLED0_SIZE"
grep -q "^/sys/devices/system/node/node$CXL_NODE/meminfo:Node $CXL_NODE MemTotal:" <<< "$POD_LOG" ||
    error "pooled-consumer does not see the memory of node $CXL_NODE"
echo "pooled-consumer: $(grep "node$CXL_NODE/meminfo" <<< "$POD_LOG")"

echo "### D: the pool device is not advertised again as node-local CXL memory"
# The new region is CXL memory of the node, which the node plugin offers
# as cxl.generic devices, but not when it is a prepared pool device. Wait
# until the node plugin has rescanned and published after it prepared
# pooled0 (udev events of the region trigger the rescan).
rescanned-after-prepare() {
    vm-command-q "journalctl --no-pager -o cat -u kubelet-cxl-plugin" |
        awk '/cxl-pool.generic: claim .*: prepared pooled0/ {p = 1}
             p && /rescanAndPublish: published updated resources/ {found = 1}
             END {exit !found}'
}
retry-until --timeout 30 --message "node plugin rescan after preparing pooled0" rescanned-after-prepare ||
    error "kubelet-cxl-plugin did not publish its resources after preparing pooled0"
vm-command "journalctl --no-pager -o cat -u kubelet-cxl-plugin | grep -E 'prepared pooled0|ignoring region|rescanAndPublish'"
dra-json "$VM2" resourceslices
dra-assert "$COMMAND_OUTPUT" "not any(attr(d, 'type') == 'cxl-node' for d in devices('$DRA_LOCAL_DRIVER', '$VM2_NAME'))"

echo "### E: delete the pod and the claim, the memory returns to the pool"
# Kubelet unprepares the claim while the pod terminates: the node plugin
# offlines the memory and releases the device. Then the claim is
# deallocated, and the controller detaches the device.
t_delete=$EPOCHREALTIME
dra-delete "$VM2" pod pooled-consumer --grace-period=2 --wait=true --timeout=60s
dra-delete "$VM2" resourceclaim pooled-memory --wait=true --timeout=60s
dra-wait "$VM2" claim-gone "resourceclaims -n $DRA_NS" "'pooled-memory' not in names()" 60
pool-cxl-wait "$VM2" pooled0-detached "memdevs == []" 60
t_detached=$EPOCHREALTIME
cxl-assert 'regions == [] and endpoints == []'
retry-until --timeout 30 --message "no attachments in the pool" \
    'pool-client "$VM2" -o json attachments >/dev/null && pool-py assert "$COMMAND_OUTPUT" "j in (None, [])"' ||
    error "pooled0 is still attached: $COMMAND_OUTPUT"
pool-client "$VM2" -o json devices pooled0 || command-error "cannot get pooled0"
pool-assert "$COMMAND_OUTPUT" "j['state'] == 'free' and j['attachments'] in (None, [])"
pool-vm-monitor "$VM2" "info qtree -b" | grep -q 'dev: cxl-type3' &&
    error "qemu of the VM still has a CXL memory device"
vm-command "journalctl --no-pager -o cat -u kubelet-cxl-plugin | grep -iE 'unprepar|releas'" ||
    command-error "the node plugin did not log the release of pooled0"
deleted=$(grep -c 'event DEVICE_DELETED' "$POOL_SERVER_LOG")
[ "$deleted" -ge 1 ] || error "qemu did not report DEVICE_DELETED, see $POOL_SERVER_LOG"
grep -E 'attachment pooled0@.*: (attached|detached)|event DEVICE_DELETED' "$POOL_SERVER_LOG"

echo "### F: what every component did, in order"
dra-trace-stop
dra-trace-summary
printf 'timings (test steps, 1 s polling): attached %.1f s, pod Running %.1f s after the claim; detached %.1f s after the delete\n' \
    "$(echo "$t_attached - $t_apply" | bc)" "$(echo "$t_running - $t_apply" | bc)" "$(echo "$t_detached - $t_delete" | bc)"

echo "### cleanup"
dra-cleanup
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
