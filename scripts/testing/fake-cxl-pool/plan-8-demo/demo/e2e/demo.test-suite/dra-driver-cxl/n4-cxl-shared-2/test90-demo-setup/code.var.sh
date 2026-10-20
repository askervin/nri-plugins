# Demo setup (plan-8-demo/demo): "demo setup local|pool" runs this through
# the e2e framework, with the helpers of
# test/e2e/memory.test-suite/dra-driver-cxl (dra.source.sh, pool.source.sh,
# cxl.source.sh: the files next to this test are links to them).
#
# Leaves running, until "demo teardown" (test91-demo-teardown):
# - fake-cxl-pool-server on the host: local demo with the local device of
#   VM2 attached, pool demo with shared0 (256Mi, shared, 0xc1ae0001);
# - nri-dra-driver-cxl on both nodes (helm), the local demo with
#   sharedDevices: [<the serial of the local device of VM2>];
# - fake-cxl-pool-controller on VM2;
# - the trace collectors of dra-trace-start (host side, setsid);
# - namespace $DRA_NS with ConfigMap demo-tools, the images pulled on both
#   nodes, node labels cxl-demo/node=vm1|vm2, /root/demo in VM2 (the
#   manifests of the case and a kubeconfig with the demo namespace).
# Writes $DEMO_STATE_DIR/state.env for the views, steps and zooms.
#
# Environment: DEMO_CASE (local or pool), DEMO_DIR (the demo directory),
# DEMO_STATE_DIR (default $DEMO_DIR/run).

DEMO_CASE="${DEMO_CASE:-local}"
DEMO_STATE_DIR="${DEMO_STATE_DIR:-$DEMO_DIR/run}"
[ -n "$DEMO_DIR" ] && [ -d "$DEMO_DIR/manifests/$DEMO_CASE" ] ||
    error "DEMO_DIR ($DEMO_DIR) has no manifests/$DEMO_CASE: run this through \"demo setup local|pool\""
[ ! -f "$DEMO_STATE_DIR/state.env" ] ||
    error "a demo is set up already ($DEMO_STATE_DIR/state.env): demo teardown first"

VM2="$OUTPUT_DIR"      # control plane, the VM of this test
VM1="$POOL_VM1_DIR"    # worker
DRA_NS=cxl-demo
SHARED_SERIAL=0xc1ae0001
PYTHON_IMAGE=docker.io/library/python:3-alpine
PAUSE_IMAGE=registry.k8s.io/pause:3.10
DEMO_TOOLS=(cxl-demo.py write read hold env)

echo "### demo setup $DEMO_CASE: the cluster and the VMs"
pool-cluster-require
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"
pool-vm-require "$VM1" n4-cxl-shared-1
# test00-up installed the tools; cxl-tools-install cannot run from here
# (it finds the source tree through the path of the test).
for vm in "$VM2" "$VM1"; do
    pool-vm-command-q "$vm" "command -v cxl && command -v daxctl && command -v cxl-dump" >/dev/null ||
        error "$(pool-vm-label "$vm") lacks cxl, daxctl or cxl-dump: run memory.test-suite/dra-driver-cxl/n4-cxl-shared-{1,2}/test00-up"
done
pool-vm-reset "$VM2"
pool-vm-reset "$VM1"

echo "### demo setup $DEMO_CASE: fake-cxl-pool-server on the host"
if [ "$DEMO_CASE" == pool ]; then
    pool-server-start "
  - name: shared0
    size: 256Mi
    shared: true
    pool: default
    serial: $SHARED_SERIAL"
else
    pool-server-start " []"
fi
pool-client-install "$VM2" "$VM1"
dra-build

if [ "$DEMO_CASE" == local ]; then
    # The serial of VM2's local device, before the driver runs, for its
    # configuration (plan-9 section 2).
    dra-local-find "$VM2"
    SERIAL="$DRA_LOCAL_SERIAL"
    config="sharedDevices: [\"$SERIAL\"]"
    if declare -p DRA_DRIVER_CONFIG >/dev/null 2>&1; then
        DRA_DRIVER_CONFIG="$config"
    else
        values="$TEST_OUTPUT_DIR/demo-helm-values.yaml"
        { cat "$DRA_HELM_VALUES"; echo "config:"; echo "  $config"; } > "$values"
        DRA_HELM_VALUES="$values"
    fi
    echo "demo setup: driver configuration $config"
else
    SERIAL="$SHARED_SERIAL"
fi

echo "### demo setup $DEMO_CASE: the driver on both nodes, the pool controller on VM2"
dra-install
if [ "$DEMO_CASE" == local ]; then
    dra-local-device "$VM2"
    shared=$(dra-value "$DRA_LOCAL_PUBLISHED" "j['attributes']['shared']['bool']")
    [ "$shared" == True ] ||
        error "the driver publishes $DRA_LOCAL_DEVICE with shared $shared: it does not know sharedDevices (plan-9), build its image again"
fi

echo "### demo setup $DEMO_CASE: images, tools, manifests"
for vm in "$VM2" "$VM1"; do
    dra-pull-images "$vm" "$PYTHON_IMAGE" "$PAUSE_IMAGE"
done
dra-vm-command "$VM2" "rm -rf /root/demo && mkdir -p /root/demo/tools /root/demo/$DEMO_CASE" ||
    command-error "cannot create /root/demo in VM2"
for f in "${DEMO_TOOLS[@]}"; do
    dra-vm-put-file "$VM2" "$DEMO_DIR/bin/tools/$f" "/root/demo/tools/$f"
done
for f in "$DEMO_DIR/manifests/$DEMO_CASE"/*.yaml; do
    dra-vm-put-file "$VM2" "$f" "/root/demo/$DEMO_CASE/${f##*/}"
done
from=""
for f in "${DEMO_TOOLS[@]}"; do
    from+=" --from-file=$f=/root/demo/tools/$f"
done
dra-vm-command "$VM2" "kubectl create configmap demo-tools -n $DRA_NS$from --dry-run=client -o yaml | kubectl apply -f -" ||
    command-error "cannot create ConfigMap demo-tools"
dra-vm-command "$VM2" "cp /root/.kube/config /root/demo/kubeconfig && kubectl --kubeconfig /root/demo/kubeconfig config set-context --current --namespace=$DRA_NS" ||
    command-error "cannot write /root/demo/kubeconfig"
dra-vm-command "$VM2" "kubectl label node $POOL_VM2_NAME cxl-demo/node=vm2 --overwrite && kubectl label node $POOL_VM1_NAME cxl-demo/node=vm1 --overwrite" ||
    command-error "cannot label the nodes"

echo "### demo setup $DEMO_CASE: the trace"
dra-trace-start "$VM2" "$VM1"

# Everything stays up: no cleanup at exit.
trap - EXIT
mkdir -p "$DEMO_STATE_DIR" || error "cannot create $DEMO_STATE_DIR"
{
    echo "# demo setup $DEMO_CASE, $(date '+%Y-%m-%d %H:%M:%S'), $TEST_OUTPUT_DIR"
    for kv in "DEMO_CASE=$DEMO_CASE" "VM2_DIR=$VM2" "VM1_DIR=$VM1" "VM2_NODE=$POOL_VM2_NAME" "VM1_NODE=$POOL_VM1_NAME" \
              "NS=$DRA_NS" "SERIAL=$SERIAL" "POOL_DEVICE=shared0" "POOL_URL=$POOL_URL" \
              "POOL_SERVER_PID=$POOL_SERVER_PID" "POOL_SERVER_LOG=$POOL_SERVER_LOG" \
              "TRACE_DIR=$DRA_TRACE_DIR" "SETUP_OUTPUT_DIR=$TEST_OUTPUT_DIR" "LOCAL_DEVICE_NAME=$DRA_LOCAL_NAME"; do
        printf '%s=%q\n' "${kv%%=*}" "${kv#*=}"
    done
} > "$DEMO_STATE_DIR/state.env"
cat "$DEMO_STATE_DIR/state.env"
echo "demo setup $DEMO_CASE: done"
