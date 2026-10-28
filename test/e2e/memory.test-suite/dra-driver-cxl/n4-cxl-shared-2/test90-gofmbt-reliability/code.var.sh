# Model-based reliability test of the CXL DRA driver and the pool
# controllers with gofmbt (scripts/testing/fake-cxl-pool/plan-13-gofmbt).
#
# The cluster of test19-many-pools (three nodes, three pool servers, three
# pool controllers) with the local memdev of every VM attached, where a
# model (model/, the Go program mbt-cxl, built here with the
# github.com/askervin/gofmbt of model/go.mod) chooses the steps of a long
# run: pods with CXL memory of every kind (exclusive and shared pool
# devices in numa and dax mode, read-only shares, local slices, steering,
# leases, no claim) created, deleted and crashed, data written and read,
# persistent pool devices (amendments A22-A27: a block writer, erofs
# readers direct and cached, read-only block readers, persistent leases
# of block and fs) written, read, held and wiped, and the faults the
# driver must survive (the driver killed in place or restarted, also at
# a chosen point of a persistent Prepare, a pool controller killed,
# started and restarted, a pool server restarted on its state, kubelet
# and containerd restarted). After
# the steps that change the cluster a "settle" observes the pods, claims,
# pool attachments, the CXL devices of the VMs, the driver's state files
# and CDI specs and the cpusets of the containers, and the model compares
# that with its prediction (04-contract.txt: the actions, the protocol,
# the observations). A failure stops the run; the steps are in
# mbt-steps.txt for a replay.
#
# Modes (MBT_MODE):
#   online   mbt-cxl runs as a coprocess and sends one step at a time,
#            planning the next one meanwhile (default)
#   replay   the same, the steps of MBT_REPLAY (an mbt-steps.txt)
#   offline  the steps and predictions of MBT_SCRIPT, a code.gen.sh of
#            "mbt-cxl generate", checked by "mbt-cxl check"
# Parameters (environment of run_tests.sh; contract 8): MBT_SEED (default
# time-based), MBT_DURATION (20m), MBT_STEPS (0: no limit), MBT_DEPTH (3),
# MBT_PROFILE (full), MBT_UNSETTLED (3), MBT_SETTLE_TIMEOUT (180 s),
# MBT_POLL (3 s), MBT_AVOID (verbs or verb:arg to leave out),
# MBT_STALL_WINDOW (--stall-window, A28: default 30s if the kube-scheduler
# of the cluster has the fix of bug-08, its image or version has
# "dra-requeue", else the model's default, 6m), MBT_REPLAY,
# MBT_SCRIPT, GOFMBT_DIR (unset: the gofmbt of model/go.mod; a checkout
# of github.com/askervin/gofmbt: the model is built with a go.work that
# uses it, for developing gofmbt), MBT_ARGS (more flags of mbt-cxl, for
# instance "--plan-ahead=false"). MBT_POLL is the executor's: the
# seconds between settle observations. Executor: MBT_TRACE (1: the
# dra-trace of every component, 0: none), MBT_OBS_KEEP (30 observations
# kept in mbt-obs/), MBT_STUB=1 (run mbt-stub.py, a fixed list of steps
# that exercises every action, instead of the model; also when there is no
# model/; MBT_STUB_LIST=volatile|persistent|all picks its lists, all by
# default, ~15 min; MBT_STUB_STEPS=FILE a list of one's own), MBT_BIN
# (another generator), MBT_KILLAT_TIMEOUT (60 s: a
# driver-kill-at watcher gives up), MBT_PLEASE_PUT_WAIT (20s: lease-put of
# persistent leases waits that long for Released).
#
# Persistent pool devices (A22): pool-c has c-pmem0 (256Mi, shared,
# 0xc1ae2002) and c-pmem1 (256Mi, exclusive, 0xc1ee2002) in every profile,
# their backing files new (removed before the server starts and at the
# end: host RAM); the settle observation reads their content from those
# files ("pdevs"). The pods write and read them with pmem-rw.py and the
# erofs template hello.erofs.hex (a copy of plan-8-demo/demo/testdata; ConfigMap
# dax-rw at /tools): no mkfs.erofs, no image build.
#
# Output in the test output directory: mbt-steps.txt (the steps, for
# MBT_REPLAY), mbt-cxl.log (the generator), mbt-fail.txt (the generator's
# report of a failure), mbt-exec.log (every command of every step and its
# output), mbt-times.tsv and mbt-obs-times.tsv (how long each step and
# observation took), mbt-obs/ (the last observations, fail-N.json),
# trace.txt and trace-summary.txt (dra-trace), and what test19 leaves.
#
# Run test00-up of n4-cxl-shared-1, -0 and -2 first, build fake-cxl-pool
# and the image of the driver (see test19-many-pools).

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

# The MBT_* that the user set (replay: they override the header of the
# steps file, amendment A16).
MBT_USER_SET=" "
for v in MBT_SEED MBT_DEPTH MBT_PROFILE MBT_UNSETTLED MBT_AVOID MBT_STALL_WINDOW; do
    [ -z "${!v+x}" ] || MBT_USER_SET+="$v "
done
MBT_MODE="${MBT_MODE:-online}"
MBT_SEED="${MBT_SEED:-$(date +%s)}"
MBT_DURATION="${MBT_DURATION:-20m}"
MBT_STEPS="${MBT_STEPS:-0}"
MBT_DEPTH="${MBT_DEPTH:-3}"
MBT_PROFILE="${MBT_PROFILE:-full}"
MBT_UNSETTLED="${MBT_UNSETTLED:-3}"
MBT_AVOID="${MBT_AVOID:-}"
MBT_REPLAY="${MBT_REPLAY:-}"
MBT_SCRIPT="${MBT_SCRIPT:-}"
MBT_TRACE="${MBT_TRACE:-1}"
GOFMBT_DIR="${GOFMBT_DIR:-}"
NODE_HB0=2   # the NUMA node of the CXL memory under host bridge 0 (local memdev, pool-a, pool-b)
NODE_HB1=3   # and under host bridge 1 (pool-c)

case "$MBT_MODE" in
    online) ;;
    replay) [ -f "$MBT_REPLAY" ] || error "MBT_MODE=replay needs MBT_REPLAY, a file of steps (mbt-steps.txt), not '$MBT_REPLAY'";;
    offline) [ -f "$MBT_SCRIPT" ] || error "MBT_MODE=offline needs MBT_SCRIPT, a code.gen.sh of mbt-cxl generate, not '$MBT_SCRIPT'";;
    *) error "MBT_MODE is $MBT_MODE: online, replay or offline";;
esac
echo "### mbt: mode $MBT_MODE, seed $MBT_SEED, duration $MBT_DURATION, steps $MBT_STEPS, profile $MBT_PROFILE, depth $MBT_DEPTH"

echo "### 0: the generator"
# Built before the cluster is set up: a model that does not build stops the
# test at once.
if [ -n "$MBT_BIN" ]; then
    echo "MBT_BIN is set: the generator is $MBT_BIN"
elif [ "${MBT_STUB:-0}" == 1 ] || [ ! -f "$TEST_DIR/model/go.mod" ]; then
    [ "${MBT_STUB:-0}" == 1 ] || echo "WARNING: no $TEST_DIR/model/go.mod: the stub generator runs instead of the model"
    MBT_BIN="$TEST_DIR/mbt-stub.py"
else
    # The model is a module of its own (model/go.mod), built without the
    # main module's go.work (GOWORK=off), or with a go.work of the model
    # and a gofmbt checkout if GOFMBT_DIR is set. The go.work is for the
    # model only: other go builds of the test (cxl-dump) are of the main
    # module.
    rm -f "$TEST_OUTPUT_DIR/go.work" "$TEST_OUTPUT_DIR/go.work.sum"
    if [ -n "$GOFMBT_DIR" ]; then
        [ -f "$GOFMBT_DIR/go.mod" ] || error "GOFMBT_DIR=$GOFMBT_DIR is not a checkout of github.com/askervin/gofmbt"
        echo "GOFMBT_DIR is set: building the model with a go.work that uses $GOFMBT_DIR instead of the gofmbt of model/go.mod"
        host-command "cd $(printf %q "$TEST_OUTPUT_DIR") && GOWORK= go work init $(printf %q "$TEST_DIR/model") $(printf %q "$GOFMBT_DIR")" ||
            command-error "cannot make a go.work of the model and $GOFMBT_DIR"
        mbt_gowork="$TEST_OUTPUT_DIR/go.work"
    else
        mbt_gowork=off
    fi
    host-command "cd $(printf %q "$TEST_DIR/model") && GOWORK=$(printf %q "$mbt_gowork") go build -o $(printf %q "$TEST_OUTPUT_DIR/mbt-cxl") . && go version -m $(printf %q "$TEST_OUTPUT_DIR/mbt-cxl") | grep -w github.com/askervin/gofmbt" ||
        command-error "cannot build the model in $TEST_DIR/model (GOWORK=$mbt_gowork)"
    MBT_BIN="$TEST_OUTPUT_DIR/mbt-cxl"
fi
[ -x "$MBT_BIN" ] || error "the generator $MBT_BIN is not executable"
echo "the generator: $MBT_BIN"

echo "### 0: preconditions: one cluster, VM2 control plane, VM1 and VM0 workers (test00-up)"
pool-cluster-require

VM0="$POOL_VM0_DIR"    # worker, the rack of pool-b
VM1="$POOL_VM1_DIR"    # worker, the rack of pool-a
VM2="$OUTPUT_DIR"      # control plane, the rack of pool-a, the VM of this test
VMS=("$VM2" "$VM1" "$VM0")
POOLS=(pool-a pool-b pool-c)
declare -A POOL_HOSTS=([pool-a]="$VM1 $VM2" [pool-b]="$VM0" [pool-c]="$VM0 $VM1 $VM2")
declare -A POOL_CONTROL=([pool-a]=qmp [pool-b]=qmp [pool-c]=hmp)
declare -A POOL_BRIDGE=([pool-a]=cxlhb0 [pool-b]=cxlhb0 [pool-c]=cxlhb1)
# The server that knows the local memdev of each VM: the servers with
# local devices (pool-a and pool-b; pool-c has none) that the VM is cabled
# to.
declare -A LOCAL_SERVER=(["$VM2"]=pool-a ["$VM1"]=pool-a ["$VM0"]=pool-b)

echo "### 0: preconditions: patched qemu, hdm_for_passthrough=on, CONFIG_FS_DAX in the three VMs"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"
pool-vm-require "$VM1" n4-cxl-shared-1
pool-vm-require "$VM0" n4-cxl-shared-0
echo "### 0: preconditions: the kernel features of persistent pool devices (pmem, fsdax, erofs, loop) in the three VMs"
for vm in "${VMS[@]}"; do
    mbt-kernel-require "$vm"
done

echo "### 0: preconditions: cxl, daxctl and cxl-dump in the VMs, no CXL memory devices"
for vm in "${VMS[@]}"; do
    pool-vm-tools-install "$vm"
done
for vm in "${VMS[@]}"; do
    pool-vm-reset "$vm"
    pool-cxl-dump "$vm" no-devices
    cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
    dra-node-size-exact "$vm"
done

echo "### 0: preconditions: three pool servers on the host"
pool-server-start --name pool-a --hosts "$VM1 $VM2" --index 0 --slots "*hb0" "
  - name: a-pooled0
    size: 512Mi
    shared: false
    pool: default
    serial: ${MBT_POOLED_SERIAL[a]}
  - name: a-shared0
    size: 256Mi
    shared: true
    pool: default
    serial: ${MBT_SHARED_SERIAL[a]}"
pool-server-start --name pool-b --port 9910 --hosts "$VM0" --index 1 --slots "*hb0" "
  - name: b-pooled0
    size: 512Mi
    shared: false
    pool: default
    serial: ${MBT_POOLED_SERIAL[b]}
  - name: b-shared0
    size: 256Mi
    shared: true
    pool: default
    serial: ${MBT_SHARED_SERIAL[b]}"
# The persistent devices of pool-c start fresh: no data, no labels (the
# server creates missing files as zeros, and never rewrites them).
mbt-pdev-files-remove "$MBT_PDEV_DIR" c-pmem0 c-pmem1
pool-server-start --name pool-c --port 9911 --hosts "$VM0 $VM1 $VM2" --index 2 --control hmp --slots "*hb1" --local-devices no "
  - name: c-shared0
    size: 256Mi
    shared: true
    pool: default
    serial: ${MBT_SHARED_SERIAL[c]}
  - name: c-pooled0
    size: 256Mi
    shared: false
    pool: default
    serial: ${MBT_POOLED_SERIAL[c]}
  - name: c-pmem0
    size: 256Mi
    shared: true
    persistent: true
    pool: default
    serial: ${MBT_PMEM_SERIAL[c]}
  - name: c-pmem1
    size: 256Mi
    shared: false
    persistent: true
    pool: default
    serial: ${MBT_XPMEM_SERIAL[c]}"
# Until dra-install sets its trap (mbt-exit-trap): the files go too.
trap 'pool-cleanup; mbt-pdev-files-remove "$MBT_PDEV_DIR" c-pmem0 c-pmem1' EXIT
mbt-pdev-files c-pmem0 c-pmem1
for pool in "${POOLS[@]}"; do
    want=""
    for vm in ${POOL_HOSTS[$pool]}; do
        want+="'$(basename "$vm")', "
    done
    pool-host-client --pool "$pool" -o json hosts || command-error "cannot list the hosts of $pool"
    pool-assert "$COMMAND_OUTPUT" "sorted(h['name'] for h in j) == sorted([$want])"
    pool-assert "$COMMAND_OUTPUT" "all(h.get('control') == '${POOL_CONTROL[$pool]}' and h.get('state') == 'running' for h in j)"
    pool-assert "$COMMAND_OUTPUT" "all(len(h['slots']) == 4 and all(s['hostBridge'] == '${POOL_BRIDGE[$pool]}' for s in h['slots']) for h in j)"
done
pool-client-install "$VM2" "$VM1" "$VM0"

echo "### 0: preconditions: three pool controllers, the node plugin on every node"
dra-build
# The EXIT trap of dra-install: stop the generator, bring the controllers
# and drivers back, then the usual dra-cleanup and pool-cleanup.
DRA_EXIT_TRAP=mbt-exit-trap
mbt-setup-ids "$VM2" "$VM1" "$VM0"
dra-install
[ "${DRA_CONTROLLER_UNITS[*]}" == "${MBT_POOL_UNIT[a]} ${MBT_POOL_UNIT[b]} ${MBT_POOL_UNIT[c]}" ] ||
    error "dra-install started the controllers ${DRA_CONTROLLER_UNITS[*]}, expected one per pool"
dra-vm-command "$VM2" "systemctl is-active ${DRA_CONTROLLER_UNITS[*]}" ||
    command-error "the pool controllers do not all run"
for p in "${MBT_POOL_IDS[@]}"; do
    dra-vm-command "$VM2" "journalctl --no-pager -o cat -u ${MBT_POOL_UNIT[$p]} | grep -m1 -F 'pool ${MBT_POOL_SERVER[$p]} (from the server)'" ||
        command-error "${MBT_POOL_UNIT[$p]} did not take the pool name ${MBT_POOL_SERVER[$p]} from its server"
done
trap 'echo "mbt: SIGTERM"; exit 143' TERM

echo "### 0: the local memdev of every VM, attached by the server that knows it"
for vm in "${VMS[@]}"; do
    dra-local-device --pool "${LOCAL_SERVER[$vm]}" "$vm"
    [ "$DRA_LOCAL_SERIAL" == "$MBT_LOCAL_SERIAL" ] ||
        error "the local memdev of $(dra-vm-label "$vm") is $DRA_LOCAL_SERIAL, expected $MBT_LOCAL_SERIAL"
done
LOCAL_BLOCKS=$(mbt-local-blocks) ||
    error "a node does not publish the local memdev memdev-${MBT_LOCAL_HEX,,} with its capacity in its cxl.nri.io ResourceSlice"
echo "local memdevs in blocks of $MBT_SLICE: $LOCAL_BLOCKS"

echo "### 0: images, tools, claim templates, the observer"
for vm in "${VMS[@]}"; do
    dra-pull-images "$vm" "$DRA_TOOLS_IMAGE" "$MBT_PAUSE_IMAGE"
done
dra-dax-tool-install "$VM2" "pmem-rw.py=$TEST_DIR/pmem-rw.py" "hello.erofs.hex=$TEST_DIR/hello.erofs.hex"
mbt-templates-apply
dra-vm-command "$VM2" "kubectl get resourceclaimtemplates -n $DRA_NS" ||
    command-error "cannot list the ResourceClaimTemplates"
mbt-observer-install "$VM2" "$VM1" "$VM0"
mbt-observe 0 1
echo "a settle observation took ${MBT_OBS_SECONDS} s ($(wc -c < "$MBT_OBS_FILE") bytes): $MBT_OBS_FILE"
dra-py assert "$MBT_OBS" "j['errors'] == [] and j['pods'] == [] and all(j['vms'][v] and j['vms'][v]['errors'] == [] for v in ('vm0', 'vm1', 'vm2'))" ||
    error "the first observation has errors or pods: $(head -c 2000 "$MBT_OBS_FILE")"
# The persistent devices are fresh, and no VM has a trace of an earlier
# run: no pmem region, node mount, lease bind or loop device over pmem.
dra-py assert "$MBT_OBS" "all(j['pdevs'][d]['lsa'] == 'zero' and not j['pdevs'][d]['pfn'] for d in ('c-pmem0', 'c-pmem1')) and all(j['vms'][v][k] == [] for v in ('vm0', 'vm1', 'vm2') for k in ('pmem', 'fsMounts', 'leaseBinds', 'loops'))" ||
    error "the first observation has persistent devices that are not fresh, or pmem regions, mounts or loop devices: $(head -c 2000 "$MBT_OBS_FILE")"
[ "$MBT_TRACE" == 0 ] || dra-trace-start "$VM2" "$VM1" "$VM0"

echo "### 0: the kube-scheduler: the stall window of A19/A28"
# A28: a kube-scheduler with the fix of bug-08 (its image or version has
# "dra-requeue") promotes a stalled contender within seconds:
# --stall-window=30s. MBT_STALL_WINDOW set by the user wins.
sched=$(dra-vm-command-q "$VM2" "p=\$(kubectl get pods -n kube-system -l component=kube-scheduler -o jsonpath='{.items[0].metadata.name}')
echo \"image \$(kubectl get pod -n kube-system \$p -o jsonpath='{.spec.containers[0].image}')\"
echo \"version \$(kubectl logs -n kube-system \$p 2>/dev/null | grep -m1 -o 'Starting Kubernetes Scheduler.*version=[^ ]*' | sed 's/.*version=//')\"") ||
    echo "WARNING: cannot read the kube-scheduler of the cluster: $sched"
echo "kube-scheduler: $(tr '\n' ' ' <<< "$sched")"
MBT_STALL_SOURCE="the model's default (6m): the kube-scheduler has no dra-requeue fix"
if [ -n "${MBT_STALL_WINDOW+x}" ]; then
    MBT_STALL_SOURCE="MBT_STALL_WINDOW=$MBT_STALL_WINDOW (set by the user)"
elif grep -q dra-requeue <<< "$sched"; then
    MBT_STALL_WINDOW=30s
    MBT_STALL_SOURCE="30s: the kube-scheduler has the dra-requeue fix of bug-08"
fi
echo "mbt: stall window: $MBT_STALL_SOURCE"

echo "### 1: the run"
export MBT_OUT="$TEST_OUTPUT_DIR"
# Go's flag package keeps the last value of a flag: the flags of the
# header of a replayed file first, then the MBT_* (in replay only those
# the user set), the measured facts, MBT_ARGS.
MBT_FLAGS=()
if [ "$MBT_MODE" == replay ]; then
    mapfile -t MBT_FLAGS < <(mbt-header-flags "$MBT_REPLAY")
    echo "mbt: flags of the header of $MBT_REPLAY: ${MBT_FLAGS[*]:-none}"
    hdr_blocks=$(sed -n 's/^# .*--local-blocks[ =]\([^ ]*\).*/\1/p' "$MBT_REPLAY" | head -n 1)
    [ -z "$hdr_blocks" ] || [ "$hdr_blocks" == "$LOCAL_BLOCKS" ] ||
        echo "WARNING: $MBT_REPLAY was recorded with --local-blocks $hdr_blocks, the cluster has $LOCAL_BLOCKS: the replay may diverge"
    hdr_stall=$(sed -n 's/^# .*--stall-window[ =]\([^ ]*\).*/\1/p' "$MBT_REPLAY" | head -n 1)
    [ -z "$hdr_stall" ] || [ "$hdr_stall" == "${MBT_STALL_WINDOW:-6m}" ] ||
        echo "WARNING: $MBT_REPLAY was recorded with --stall-window $hdr_stall, this run has ${MBT_STALL_WINDOW:-the default}: the replay may diverge"
fi
mbt-flag() {
    # Usage: mbt-flag VAR FLAG=VALUE: add FLAG=VALUE, in replay only if
    # the user set VAR.
    [ "$MBT_MODE" != replay ] || [[ "$MBT_USER_SET" == *" $1 "* ]] || return 0
    MBT_FLAGS+=("$2")
}
mbt-flag MBT_SEED --seed="$MBT_SEED"
mbt-flag MBT_DEPTH --depth="$MBT_DEPTH"
mbt-flag MBT_PROFILE --profile="$MBT_PROFILE"
mbt-flag MBT_UNSETTLED --unsettled="$MBT_UNSETTLED"
[ -z "$MBT_AVOID" ] || mbt-flag MBT_AVOID --avoid="$MBT_AVOID"
MBT_FLAGS+=(
    --duration="$MBT_DURATION"
    --steps="$MBT_STEPS"
    --settle-timeout="${MBT_SETTLE_TIMEOUT}s"
    --local-blocks="$LOCAL_BLOCKS"
    --node-hb0="$NODE_HB0"
    --node-hb1="$NODE_HB1"
    --out="$TEST_OUTPUT_DIR"
)
# The stall window is a fact of the cluster's kube-scheduler, measured
# above, or the user's.
[ -z "${MBT_STALL_WINDOW:-}" ] || MBT_FLAGS+=(--stall-window="$MBT_STALL_WINDOW")
# More flags of mbt-cxl, words: for instance --plan-ahead=false.
read -r -a words <<< "${MBT_ARGS:-}"
MBT_FLAGS+=("${words[@]}")
case "$MBT_MODE" in
    online) mbt-online online "${MBT_FLAGS[@]}";;
    replay) mbt-online online --replay="$MBT_REPLAY" "${MBT_FLAGS[@]}";;
    offline) mbt-offline "$MBT_SCRIPT";;
esac
echo "### mbt: $(( $(wc -l < "$MBT_TIMES") - 1 )) steps, $(( $(wc -l < "$MBT_OBS_TIMES") - 1 )) observations; times in $MBT_TIMES and $MBT_OBS_TIMES"

echo "### 2: teardown: every pod deleted, every device back"
mbt-teardown
for vm in "${VMS[@]}"; do
    pool-vm-monitor "$vm" "info qtree -b" | grep -c 'dev: cxl-type3' | grep -qx 1 ||
        error "qemu of $(pool-vm-label "$vm") does not have exactly its local CXL memory device: $(pool-vm-monitor "$vm" "info qtree -b" | grep -c 'dev: cxl-type3') devices"
done
if [ -n "$DRA_TRACE_RUNNING" ]; then
    dra-trace-stop
    dra-trace-summary > /dev/null
fi

echo "### cleanup"
dra-cleanup
for vm in "${VMS[@]}"; do
    dra-local-detach --pool "${LOCAL_SERVER[$vm]}" "$vm"
done
pool-cleanup
mbt-pdev-files-remove "$MBT_PDEV_DIR" c-pmem0 c-pmem1
trap - EXIT
trap - TERM
for port in "$POOL_PORT" 9910 9911; do
    pool-port-busy "$port" && error "port $port is still busy after stopping the servers"
done
for vm in "${VMS[@]}"; do
    pool-vm-monitor "$vm" "info qtree -b" | grep -q 'dev: cxl-type3' &&
        error "qemu of $(pool-vm-label "$vm") still has a CXL memory device"
done
[ "$MBT_TRACE" == 0 ] || echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
echo "mbt: steps $TEST_OUTPUT_DIR/mbt-steps.txt, executor log $MBT_EXEC_LOG, generator log $MBT_LOG"
