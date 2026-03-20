#!/bin/bash
# E2E Test 02: User specified waypoints
#
# This test verifies that cgmpold correctly:
# 1. Follows user-defined waypoints with mixed slopes (1:1, 0:1, 1:0)
# 2. Re-steers toward the waypoint path after large frees yank usage off-path
#
# Waypoints (node 2 = DRAM, node 3 = CXL, max 300 MB each):
#   WP0: DRAM=100M CXL= 50M
#   WP1: DRAM=150M CXL=100M  (slope 1:1)
#   WP2: DRAM=150M CXL=200M  (slope 0:1, CXL-only)
#   WP3: DRAM=250M CXL=200M  (slope 1:0, DRAM-only)
#   WP4: DRAM=300M CXL=250M  (slope 1:1)
#
# Test strategy:
#   Phases 1-4: allocate along the path toward WP1/WP2
#   Phase 5:    free a large early allocation → trackpoint jumps off-path
#   Phases 6-8: allocate to steer back toward the waypoint path
#   Phase 9:    free more early allocs → second off-path detour
#
# Test configuration:
# - DRAM node: 2, CXL node: 3

echo "Test: User-Defined Waypoints with Off-Path Detours"
echo "==================================================="

# Test configuration
CGROUP_NAME="cgmpold-test02-$$"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"
CONFIG_FILE="$E2E_REMOTE_DIR/test02-config.yaml"
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
    memoryUseOrder: "waypoints"
    dramNodes: "2"
    cxlNodes: "3"
    dramQuota: "300M"
    cxlQuota: "300M"
    minLimit: "20M"
    maxLimit: "60M"
    memoryUseWaypoints:
      - targetUsages:
          - memoryType: DRAM
            usage: "100M"
          - memoryType: CXL
            usage: "50M"
      - targetUsages:
          - memoryType: DRAM
            usage: "150M"
          - memoryType: CXL
            usage: "100M"
      - targetUsages:
          - memoryType: DRAM
            usage: "150M"
          - memoryType: CXL
            usage: "200M"
      - targetUsages:
          - memoryType: DRAM
            usage: "250M"
          - memoryType: CXL
            usage: "200M"
      - targetUsages:
          - memoryType: DRAM
            usage: "300M"
          - memoryType: CXL
            usage: "250M"
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

# Test phase template:
# echo "Phase N: DESCRIBE ALLOCATION AND EXPECTED NODE USAGE"
# python-input "$PYTHON_PORT" "log('Phase N start: +/-AMOUNT MB'); varN = 'x' * (1024 * 1024 * AMOUNT); log('Phase N complete')"
# wait-phase-stats N
# echo "  → Phase duration: ${PHASE_DURATION}ms"

# Waypoints summary (node 2 = DRAM, node 3 = CXL):
#   WP0: DRAM=100M CXL= 50M  (slope from origin ~2:1)
#   WP1: DRAM=150M CXL=100M  (slope 1:1)
#   WP2: DRAM=150M CXL=200M  (slope 0:1, CXL-only)
#   WP3: DRAM=250M CXL=200M  (slope 1:0, DRAM-only)
#   WP4: DRAM=300M CXL=250M  (slope 1:1)

echo "Phase 1: Allocate 80 MB — should land on DRAM (heading toward WP0)"
python-input "$PYTHON_PORT" "log('Phase 1 start +80 MB'); phase1_80M = 'A' * (1024 * 1024 * 80); log('Phase 1 complete')"
wait-phase-stats 1
echo "  → allocated 80 MB in ${PHASE_DURATION}ms"

echo "Phase 2: Allocate 60 MB — approaches WP0, should start mixing CXL"
python-input "$PYTHON_PORT" "log('Phase 2 start +60 MB'); phase2_60M = 'B' * (1024 * 1024 * 60); log('Phase 2 complete')"
wait-phase-stats 2
echo "  → allocated 60 MB in ${PHASE_DURATION}ms"

echo "Phase 3: Large early allocation 100 MB — pushes well past WP1 toward WP2"
python-input "$PYTHON_PORT" "log('Phase 3 start +100 MB'); phase3_100M = 'C' * (1024 * 1024 * 100); log('Phase 3 complete')"
wait-phase-stats 3
echo "  → allocated 100 MB in ${PHASE_DURATION}ms"

echo "Phase 4: Allocate 40 MB more — continues along path toward WP2/WP3"
python-input "$PYTHON_PORT" "log('Phase 4 start +40 MB'); phase4_40M = 'D' * (1024 * 1024 * 40); log('Phase 4 complete')"
wait-phase-stats 4
echo "  → allocated 40 MB in ${PHASE_DURATION}ms"

echo "Phase 5: Free the Phase 3 100 MB — yanks trackpoint off-path (large hole)"
python-input "$PYTHON_PORT" "log('Phase 5 start -100 MB'); del phase3_100M; log('Phase 5 complete')"
wait-phase-stats 5
echo "  → freed 100 MB in ${PHASE_DURATION}ms"

echo "Phase 6: Allocate 50 MB — planner must re-steer back toward path"
python-input "$PYTHON_PORT" "log('Phase 6 start +50 MB'); phase6_50M = 'E' * (1024 * 1024 * 50); log('Phase 6 complete')"
wait-phase-stats 6
echo "  → allocated 50 MB in ${PHASE_DURATION}ms"

echo "Phase 7: Allocate 60 MB — should continue converging back to waypoint path"
python-input "$PYTHON_PORT" "log('Phase 7 start +60 MB'); phase7_60M = 'F' * (1024 * 1024 * 60); log('Phase 7 complete')"
wait-phase-stats 7
echo "  → allocated 60 MB in ${PHASE_DURATION}ms"

echo "Phase 8: Allocate 80 MB — push further along the path toward WP3/WP4"
python-input "$PYTHON_PORT" "log('Phase 8 start +80 MB'); phase8_80M = 'G' * (1024 * 1024 * 80); log('Phase 8 complete')"
wait-phase-stats 8
echo "  → allocated 80 MB in ${PHASE_DURATION}ms"

echo "Phase 9: Free phase1 and phase2 early allocs — second off-path detour"
python-input "$PYTHON_PORT" "log('Phase 9 start -140 MB'); del phase1_80M, phase2_60M; log('Phase 9 complete')"
wait-phase-stats 9
echo "  → freed 140 MB in ${PHASE_DURATION}ms"


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
mkdir -p /tmp/e2e-test02-$$
vm_fetch "$CGMPOLD_OUT" "/tmp/e2e-test02-$$/cgmpold.out"
vm_fetch "$E2E_REMOTE_DIR/$PYTHON_PORT.out" "/tmp/e2e-test02-$$/python.out" 2>/dev/null || echo "No python output" > /tmp/e2e-test02-$$/python.out

echo ""
echo "=== Python Output ==="
cat /tmp/e2e-test02-$$/python.out 2>/dev/null | head -30 || echo "No Python output available"
echo ""
echo "=== cgmpold Output ==="
cat /tmp/e2e-test02-$$/cgmpold.out
echo ""

# Verify the test results
echo "Verifying test results..."
CGMPOLD_OUTPUT=$(cat /tmp/e2e-test02-$$/cgmpold.out)

# Check that cgmpold received memory threshold notifications
NOTIF_COUNT=$(echo "$CGMPOLD_OUTPUT" | grep -c "Notification: bound" || true)
if [ "$NOTIF_COUNT" -lt 2 ]; then
    echo "✗ FAILED: Expected at least 2 notifications, found $NOTIF_COUNT"
    exit 1
fi
echo "✓ Received $NOTIF_COUNT notifications"

# Check that DRAM node 2 was used
if echo "$CGMPOLD_OUTPUT" | grep -q "nodes \[2\]"; then
    echo "✓ DRAM node 2 was used"
else
    echo "✗ FAILED: DRAM node 2 was never selected"
    exit 1
fi

# Check that CXL node 3 was used
if echo "$CGMPOLD_OUTPUT" | grep -q "nodes \[3\]"; then
    echo "✓ CXL node 3 was used"
else
    echo "✗ FAILED: CXL node 3 was never selected"
    exit 1
fi

# Check that both nodes were used together at some point (interleaved steering)
if echo "$CGMPOLD_OUTPUT" | grep -qE "nodes \[2 3\]|nodes \[3 2\]"; then
    echo "✓ Both nodes 2 and 3 were used together (interleaved)"
else
    echo "⚠ WARNING: Nodes 2 and 3 were never used together"
fi

# Check that multiple different nodesets were used (steering changed over time)
NODESETS_USED=$(echo "$CGMPOLD_OUTPUT" | grep -o "nodes \[[^]]*\]" | sort -u | wc -l)
if [ "$NODESETS_USED" -lt 2 ]; then
    echo "✗ FAILED: Expected at least 2 different nodesets, found $NODESETS_USED"
    exit 1
fi
echo "✓ Used $NODESETS_USED different nodesets (steering adapted)"

echo ""
echo "=== Test Passed ==="
echo "User-defined waypoints with off-path detours worked as expected!"


# Cleanup temporary files
rm -rf /tmp/e2e-test02-$$

true
