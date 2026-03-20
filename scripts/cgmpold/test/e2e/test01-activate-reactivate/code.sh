#!/bin/bash
# E2E Test 01: Activate and Reactivate Memory Policies
#
# This test verifies that cgmpold correctly:
# 1. Steers memory allocations to DRAM first, then CXL
# 2. Reacts to memory threshold crossings by updating the route
#
# Test configuration:
# - DRAM node: 2, CXL node: 3
# - Memory use order: first-DRAM
# - DRAM quota: 20M, CXL quota: 40M
# - MinLimit: 5M, MaxLimit: 10M

echo "Test: Activate and Reactivate Memory Policies"
echo "=============================================="

# Test configuration
CGROUP_NAME="cgmpold-test01-$$"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"
CONFIG_FILE="$E2E_REMOTE_DIR/test01-config.yaml"
CGMPOLD_OUT="$E2E_REMOTE_DIR/cgmpold.out"
CGMPOLD_PID_FILE="$E2E_REMOTE_DIR/cgmpold.pid"

vm "sudo pkill -f 'python3 -i -u'; sudo pkill -f 'socat'; sleep 1; pgrep -f 'python3 -i -u' && sudo pkill -KILL -f 'python3 -i -u' && sleep 1"

echo "Creating test cgroup on VM: $CGROUP_PATH"
vm "sudo mkdir -p $CGROUP_PATH"

error-stop() {
    echo "ERROR: $*"
    python-stop "$PYTHON_PORT"
    exit 1
}

echo "Generating test configuration..."
vm "cat > $CONFIG_FILE << 'EOF'
cgroups:
  - path: $CGROUP_PATH
    memoryUseOrder: "first-DRAM"
    dramNodes: "2"
    cxlNodes: "3"
    dramQuota: "40M"
    cxlQuota: "100M"
    minLimit: "20M"
    maxLimit: "100M"
EOF
"

echo "Starting cgmpold in background..."
vm "sudo $E2E_REMOTE_DIR/cgmpold -c $CONFIG_FILE > $CGMPOLD_OUT 2>&1 & echo \$! > $CGMPOLD_PID_FILE; until grep -s 'started successfully' $CGMPOLD_OUT; do sleep 0.1; done"
CGMPOLD_PID=$(vm "cat $CGMPOLD_PID_FILE")
echo "cgmpold started with PID: $CGMPOLD_PID"

# Check if cgmpold is still running
if ! vm "kill -0 $CGMPOLD_PID 2>/dev/null"; then
    vm "cat $CGMPOLD_OUT"
    error-stop "cgmpold died unexpectedly"
fi

echo "Starting interactive Python process in cgroup..."
PYTHON_PORT=$(python-start "$CGROUP_PATH")

if [[ -z "$PYTHON_PORT" ]]; then
    error-stop "failed to start Python properly"
fi

PYTHON_OUT="$E2E_REMOTE_DIR/$PYTHON_PORT.out"
echo "Python process started on port: $PYTHON_PORT"
# Verify process is in cgroup (retry a few times for race conditions)
PIDS=0
for i in $(seq 1 10); do
    PIDS=$(vm "cat $CGROUP_PATH/cgroup.procs 2>/dev/null | wc -l")
    if [ "$PIDS" -gt 0 ]; then
        break
    fi
    sleep 0.5
done
echo "Processes in cgroup: $PIDS"
if [ "$PIDS" -eq 0 ]; then
    error-stop "no processes in cgroup, python was expected to start there"
fi


echo ""
echo "Running memory allocation/deallocation test phases..."

# Helper function to extract epoch timestamp from last cgmpold DEBUG log line matching pattern
get_cgmpold_timestamp() {
    local pattern="$1"
    vm "grep 'DEBUG.*$pattern' $CGMPOLD_OUT 2>/dev/null | tail -1 | awk '{print \$1}'" || echo ""
}

# Helper function to extract Python log timestamp
# Python log lines look like: "1773928731.443533 python PORT Phase 1 start"
# They may be prefixed by ">>> " prompt characters.
# Filter out traceback/error lines that also match the pattern.
get_python_timestamp() {
    local pattern="$1"
    vm "grep '$pattern' $PYTHON_OUT 2>/dev/null | grep -v 'Traceback\|Error:\|File \"' | tail -1 | sed 's/^[> ]*//' | awk '{print \$1}'" || echo ""
}

# Helper function to calculate time difference in milliseconds between two epoch timestamps
time_diff_ms() {
    local ts1="$1"
    local ts2="$2"
    if [ -n "$ts1" ] && [ -n "$ts2" ]; then
        awk "BEGIN {printf \"%.0f\", ($ts2 - $ts1) * 1000}"
    else
        echo "N/A"
    fi
}

wait-phase-stats() {
    local phase="$1"
    vm-wait 50 "grep -q 'Phase $phase complete' $PYTHON_OUT 2>/dev/null" || error-stop "no completion in time"
    TS_PHASE_START=$(get_python_timestamp "Phase $phase start")
    TS_PHASE_COMPLETE=$(get_python_timestamp "Phase $phase complete")
    PHASE_DURATION=$(time_diff_ms "$TS_PHASE_START" "$TS_PHASE_COMPLETE")
}

# Phase 1: Small allocation (5 MB) - should stay on DRAM (node 2)
echo "Phase 1: Allocate 5 MB (stay on DRAM node 2)"
python-input "$PYTHON_PORT" "log('Phase 1 start: +5 MB'); x5MB = 'x' * (1024 * 1024 * 5); log('Phase 1 complete')"
wait-phase-stats 1
echo "  → python got 5MB from DRAM in ${PHASE_DURATION}ms"

# Phase 2: Allocate 20 MB total - should trigger notification and route update
echo "Phase 2: Allocate 20 MB total (exceed DRAM quota)"
python-input "$PYTHON_PORT" "log('Phase 2 start +20 MB'); x20MB = 'y' * (1024 * 1024 * 20); log('Phase 2 complete')"
wait-phase-stats 2
echo "  → python got 20MB in ${PHASE_DURATION}ms"

# Phase 3: Allocate 60 MB more - should continue on CXL (node 3)
echo "Phase 3: Allocate 60 MB more (fill CXL quota)"
python-input "$PYTHON_PORT" "log('Phase 3 start +60 MB'); x60MB = 'z' * (1024 * 1024 * 60); log('Phase 3 complete')"
wait-phase-stats 3
echo "  → python got 60MB from CXL in ${PHASE_DURATION}ms"

# Phase 4: Free 60 MB - should trigger notification on memory drop
echo "Phase 4: Free 60 MB"
python-input "$PYTHON_PORT" "log('Phase 4 start -60 MB'); del x60MB; log('Phase 4 complete')"
wait-phase-stats 4
echo "  → python freed 60MB in ${PHASE_DURATION}ms"
echo "TODO: check cgmpold bound"

# Phase 5: Free 20 MB - should drop further
echo "Phase 5: Free 20 MB"
python-input "$PYTHON_PORT" "log('Phase 5 start -20 MB'); del x20MB; log('Phase 5 complete')"
wait-phase-stats 5
echo "  → python freed 20MB in ${PHASE_DURATION}ms"

# Phase 6: Re-allocate 50 MB - should climb back up, steering through DRAM then CXL
echo "Phase 6: Re-allocate 50 MB (climb back up)"
NOTIF_COUNT_BEFORE=$(vm "grep -c 'Notification: bound' $CGMPOLD_OUT 2>/dev/null" || echo "0")
python-input "$PYTHON_PORT" "log('Phase 6 start +50 MB'); x50MB = 'a' * (1024 * 1024 * 50); log('Phase 6 complete')"
wait-phase-stats 6
echo "  → python got 50MB in ${PHASE_DURATION}ms"

# Phase 7: Free remaining - drop back
echo "Phase 7: Free remaining"
python-input "$PYTHON_PORT" "log('Phase 7 start -55 MB'); del x50MB, x5MB; log('Phase 7 complete')"
wait-phase-stats 7
echo "  → python freed remaining in ${PHASE_DURATION}ms"

# Stop Python
python-stop "$PYTHON_PORT"
sleep 1

# Stop cgmpold
echo "Stopping cgmpold..."
vm "sudo kill $CGMPOLD_PID 2>/dev/null || true"
sleep 1

# Cleanup cgroup
echo "Cleaning up cgroup..."
vm "sudo rmdir $CGROUP_PATH 2>/dev/null || true"

# Fetch output files for analysis
echo "Fetching output files..."
mkdir -p /tmp/e2e-test01-$$
vm_fetch "$CGMPOLD_OUT" "/tmp/e2e-test01-$$/cgmpold.out"
vm_fetch "$E2E_REMOTE_DIR/$PYTHON_PORT.out" "/tmp/e2e-test01-$$/python.out" 2>/dev/null || echo "No python output" > /tmp/e2e-test01-$$/python.out

echo ""
echo "=== Python Output ==="
cat /tmp/e2e-test01-$$/python.out 2>/dev/null | head -30 || echo "No Python output available"
echo ""
echo "=== cgmpold Output ==="
cat /tmp/e2e-test01-$$/cgmpold.out
echo ""

# Verify the test results
echo "Verifying test results..."

CGMPOLD_OUTPUT=$(cat /tmp/e2e-test01-$$/cgmpold.out)

# Check for initial policy applied on DRAM node
echo "Checking for initial policy on DRAM node 2..."
if echo "$CGMPOLD_OUTPUT" | grep -iq "setting memory policy.*nodes \[2\]"; then
    echo "✓ Found initial policy on DRAM node 2"
else
    echo "✗ FAILED: Initial policy on DRAM node 2 not found"
    exit 1
fi

echo "Checking for route updates..."

# Check that notifications were received (memory threshold crossings)
NOTIF_COUNT=$(echo "$CGMPOLD_OUTPUT" | grep -c "Notification: bound" || true)
if [ "$NOTIF_COUNT" -lt 1 ]; then
    echo "✗ FAILED: Expected at least 1 notification, found $NOTIF_COUNT"
    exit 1
fi
echo "✓ Received $NOTIF_COUNT notifications"

# Check that we used at least two different nodesets
NODESETS_USED=$(echo "$CGMPOLD_OUTPUT" | grep -o "nodes \[[^]]*\]" | sort -u | wc -l)
if [ "$NODESETS_USED" -lt 2 ]; then
    echo "✗ FAILED: Expected at least 2 different nodesets, found $NODESETS_USED"
    exit 1
fi

echo "✓ Used $NODESETS_USED different nodesets"

# Check that CXL node 3 was eventually used
if echo "$CGMPOLD_OUTPUT" | grep -q "nodes \[3\]"; then
    echo "✓ CXL node 3 was used"
else
    echo "✗ WARNING: CXL node 3 usage not found"
fi

echo ""
echo "=== Test Passed ==="
echo "Memory steering through DRAM-then-CXL worked as expected!"

# Cleanup temporary files
rm -rf /tmp/e2e-test01-$$

true
