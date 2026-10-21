# Demo teardown (plan-8-demo/demo): "demo teardown" runs this through the
# e2e framework. Undoes test90-demo-setup and leaves both VMs without CXL
# memory devices, the host without the pool server:
# - the demo pods and their leases;
# - the shared local device unconfigured first: the driver restarted
#   without sharedDevices destroys its region (plan-9 D4, R9), so that it
#   can be detached;
# - the trace stopped, its summary in the output of this test;
# - the driver, the controller, the namespace (dra-uninstall);
# - the local device detached (dra-local-detach), the pool server stopped
#   (pool-cleanup), node labels and /root/demo removed.
# Works without the state file of setup too (a setup that failed half
# way): then it cleans what it finds.

DEMO_STATE_DIR="${DEMO_STATE_DIR:-$DEMO_DIR/run}"
state="$DEMO_STATE_DIR/state.env"
VM2="$OUTPUT_DIR"
VM1="$POOL_VM1_DIR"
DRA_NS=cxl-demo
DEMO_CASE=unknown
TRACE_DIR=""
POOL_SERVER_PID=""
if [ -f "$state" ]; then
    # The views stop asking when the state is gone.
    mv "$state" "$state.teardown" || error "cannot move $state"
    source "$state.teardown"
    DRA_NS="$NS"
    sleep 2
elif [ -f "$state.teardown" ]; then
    echo "demo teardown: continuing an earlier teardown"
    source "$state.teardown"
    DRA_NS="$NS"
else
    echo "demo teardown: no state file $state: cleaning what is there"
fi
if [ -n "$POOL_SERVER_PID" ] && ! kill -0 "$POOL_SERVER_PID" 2>/dev/null; then
    POOL_SERVER_PID=""
fi
if [ -z "$POOL_SERVER_PID" ] && pool-port-busy; then
    POOL_SERVER_PID=$(ss -ltnpH "sport = :$POOL_PORT" 2>/dev/null | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -n 1)
    echo "demo teardown: fake-cxl-pool-server on port $POOL_PORT: pid ${POOL_SERVER_PID:-unknown}"
fi
DRA_INSTALLED_VMS=("$VM2" "$VM1" "$POOL_VM0_DIR")

echo "### demo teardown: the trace"
if [ -n "$TRACE_DIR" ] && [ -f "$TRACE_DIR/pids" ]; then
    DRA_TRACE_DIR="$TRACE_DIR"
    DRA_TRACE_RUNNING=1
    DRA_TRACE_VMS=("$VM2" "$VM1")
    dra-trace-stop
    dra-trace-summary > /dev/null
    echo "demo teardown: trace $TEST_OUTPUT_DIR/trace.txt, summary $TEST_OUTPUT_DIR/trace-summary.txt"
fi

echo "### demo teardown: the demo pods and leases"
dra-vm-command "$VM2" "kubectl delete pods --all -n $DRA_NS --grace-period=2 --ignore-not-found --wait=true --timeout=60s 2>&1 | grep -v 'No resources found'; true"
retry-until --timeout 90 --interval 2 --message "no lease companions in $DRA_NS" \
    '[ -z "$(dra-vm-command-q "$VM2" "kubectl get pods,resourceclaims -n $DRA_NS -l $DRA_LEASE_LABEL -o name 2>/dev/null")" ]' ||
    echo "demo teardown: WARNING: lease companions remain in $DRA_NS"

echo "### demo teardown: unconfigure the shared local device before detaching it (plan-9 R9)"
local_attached=""
if [ -n "$POOL_SERVER_PID" ]; then
    dra-local-find "$VM2"
    [ "$DRA_LOCAL_ATTACHMENT" == detached ] || local_attached=1
fi
if [ -n "$local_attached" ]; then
    gone="by_serial($DRA_LOCAL_SERIAL) is None or not any(by_serial($DRA_LOCAL_SERIAL)['Name'] in names(r['Memories']) for r in regions)"
    pool-cxl-dump-json "$VM2" before-unconfigure
    if ! cxl-py assert "$gone" >/dev/null && dra-driver-pod "$VM2" >/dev/null; then
        helm_name="$DRA_HELM_RELEASE" helm-reconfigure "$DRA_CHART" "$DRA_HELPER_DIR/dra-driver-cxl.helm-values.yaml"
        dra-vm-command "$VM2" "kubectl rollout status -n kube-system ds/$DRA_DAEMONSET --timeout=120s"
        retry-until --timeout 90 --interval 2 --message "the driver destroys the region of $DRA_LOCAL_SERIAL" \
            'pool-cxl-dump-json "$VM2" unconfigured && cxl-py assert "$gone" >/dev/null' ||
            echo "demo teardown: WARNING: the region of $DRA_LOCAL_SERIAL is still there after the restart without sharedDevices; the guest release of dra-local-detach destroys it"
    fi
fi

echo "### demo teardown: the driver, the controller, the namespace"
dra-uninstall
if [ -n "$local_attached" ]; then
    dra-local-detach "$VM2"
fi
dra-state-cleanup "$VM2"
dra-state-cleanup "$VM1"

echo "### demo teardown: the pool server"
if [ -n "$POOL_SERVER_PID" ]; then
    pool-cleanup
fi
pool-port-busy && error "port $POOL_PORT is still busy: a fake-cxl-pool-server that the demo did not start? stop it"
dra-vm-command "$VM2" "kubectl label node $POOL_VM2_NAME cxl-demo/node- ; kubectl label node $POOL_VM1_NAME cxl-demo/node- ; rm -rf /root/demo; true"

echo "### demo teardown: the VMs are clean"
for vm in "$VM2" "$VM1"; do
    pool-cxl-dump "$vm" clean
    cxl-assert 'memdevs == [] and regions == []'
done
rm -f "$state.teardown"
echo "demo teardown: done"
