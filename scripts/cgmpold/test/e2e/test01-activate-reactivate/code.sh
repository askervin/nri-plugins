#!/bin/bash
# E2E Test 01: Activate and Reactivate Memory Policies
#
# This test verifies that cgmpold correctly:
# 1. Activates the next memory policy when limit is exceeded
# 2. Reactivates previous policies when memory usage drops below reactivateLimit
#
# Test configuration:
# - Policy 0: nodeset "0",   limit 20M, reactivateLimit 10M
# - Policy 1: nodeset "0,1", limit 40M, reactivateLimit 20M
# - Policy 2: nodeset "1",   limit 60M, reactivateLimit 30M

echo "Test: Activate and Reactivate Memory Policies"
echo "=============================================="

# Test configuration
CGROUP_NAME="cgmpold-test01-$$"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"
CONFIG_FILE="$E2E_REMOTE_DIR/test01-config.yaml"
CGMPOLD_OUT="$E2E_REMOTE_DIR/cgmpold.out"
CGMPOLD_PID_FILE="$E2E_REMOTE_DIR/cgmpold.pid"

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
    memoryPolicies:
      - nodeset: \"0\"
        limit: \"20M\"
        reactivateLimit: \"10M\"
        policy: \"preferred\"
      - nodeset: \"0,1\"
        limit: \"40M\"
        reactivateLimit: \"20M\"
        policy: \"interleave\"
      - nodeset: \"1\"
        policy: \"preferred\"
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
PYTHON_OUT="$E2E_REMOTE_DIR/$PYTHON_PORT.out"
echo "Python process started on port: $PYTHON_PORT"
# Verify process is in cgroup
PIDS=$(vm "cat $CGROUP_PATH/cgroup.procs 2>/dev/null | wc -l")
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
get_python_timestamp() {
    local pattern="$1"
    vm "grep '$pattern' $PYTHON_OUT 2>/dev/null | tail -1 | awk '{print \$1}'" || echo ""
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

# Phase 1: Small allocation (5 MB) - should stay on policy 0
echo "Phase 1: Allocate 5 MB (stay on policy 0)"
python-input "$PYTHON_PORT" "log('Phase 1 start: +5 MB'); x5MB = 'x' * (1024 * 1024 * 5); log('Phase 1 complete')"
TS_START=$(get_python_timestamp "Phase 1 start")
TS_COMPLETE=$(get_python_timestamp "Phase 1 complete")
ALLOC_TIME=$(time_diff_ms "$TS_START" "$TS_COMPLETE")
echo "  → python got 5MB in ${ALLOC_TIME}ms"

# Phase 2: Allocate 20 MB total - should trigger policy 0 -> 1
echo "Phase 2: Allocate 20 MB total (exceed 20M limit)"
python-input "$PYTHON_PORT" "log('Phase 2 start +20 MB'); x20MB = 'y' * (1024 * 1024 * 20); log('Phase 2 complete')"
# Wait for transition
vm-wait 50 "grep -q 'Policy switch from 0 to 1' $CGMPOLD_OUT 2>/dev/null" || error-stop "no policy switch from 0 to 1 in time"

# Get timestamps and calculate reaction time
TS_START=$(get_python_timestamp "Phase 2 start")
TS_SWITCH=$(get_cgmpold_timestamp "Policy switch from 0 to 1")
if [ -n "$TS_START" ] && [ -n "$TS_SWITCH" ]; then
    REACTION_TIME=$(time_diff_ms "$TS_START" "$TS_SWITCH")
    echo "  → Policy 0→1 transition took ${REACTION_TIME}ms"
fi
TS_COMPLETE=$(get_python_timestamp "Phase 2 complete")
ALLOC_TIME=$(time_diff_ms "$TS_START" "$TS_COMPLETE")
echo "  → python got 20MB in ${ALLOC_TIME}ms"

# Phase 3: Allocate 60 MB total - should trigger policy 1 -> 2
echo "Phase 3: Allocate 60 MB total (exceed 40M limit)"
python-input "$PYTHON_PORT" "log('Phase 3 start +60 MB'); x60MB = 'z' * (1024 * 1024 * 60); log('Phase 3 complete')"
vm-wait 50 "grep -q 'Policy switch from 1 to 2' $CGMPOLD_OUT 2>/dev/null" || error-stop "no policy switch from 1 to 2 in time"

TS_START=$(get_python_timestamp "Phase 3 start")
TS_SWITCH=$(get_cgmpold_timestamp "Policy switch from 1 to 2")
if [ -n "$TS_START" ] && [ -n "$TS_SWITCH" ]; then
    REACTION_TIME=$(time_diff_ms "$TS_START" "$TS_SWITCH")
    echo "  → Policy 1→2 transition took ${REACTION_TIME}ms"
fi

# Phase 4: Free memory to ~60 MB - should reactivate policy 1
echo "Phase 4: Free to ~60 MB (drop below 60M reactivateLimit)"
python-input "$PYTHON_PORT" "log('Phase 4 start -60 MB'); del x60MB; log('Phase 4 complete')"
vm-wait 50 "grep -q 'Policy switch from 2 to 1' $CGMPOLD_OUT 2>/dev/null" || error-stop "no policy switch from 2 to 1 in time"

TS_START=$(get_python_timestamp "Phase 4 start")
TS_SWITCH=$(get_cgmpold_timestamp "Policy switch from 2 to 1")
if [ -n "$TS_START" ] && [ -n "$TS_SWITCH" ]; then
    REACTION_TIME=$(time_diff_ms "$TS_START" "$TS_SWITCH")
    echo "  → Policy 2→1 transition took ${REACTION_TIME}ms"
fi

# Phase 5: Free to ~20 MB - should reactivate policy 0
echo "Phase 5: Free to ~20 MB (drop below 20M reactivateLimit)"
python-input "$PYTHON_PORT" "log('Phase 5 start -20 MB'); del x20MB; log('Phase 5 complete')"
vm-wait 50 "grep -q 'Policy switch from 1 to 0' $CGMPOLD_OUT 2>/dev/null" || error-stop "no policy switch from 1 to 0 in time"

TS_START=$(get_python_timestamp "Phase 5 start")
TS_SWITCH=$(get_cgmpold_timestamp "Policy switch from 1 to 0")
if [ -n "$TS_START" ] && [ -n "$TS_SWITCH" ]; then
    REACTION_TIME=$(time_diff_ms "$TS_START" "$TS_SWITCH")
    echo "  → Policy 1→0 transition took ${REACTION_TIME}ms"
fi

# Phase 6: Re-allocate 50 MB - should climb quickly policy 2
echo "Phase 6: Re-allocate 50 MB (climb back up to policy 1)"
python-input "$PYTHON_PORT" "log('Phase 6 start +50 MB'); x50MB = 'a' * (1024 * 1024 * 50); log('Phase 6 complete')"
vm-wait 50 "tail -n 25 $CGMPOLD_OUT | grep -E 'Policy switch from .* to 2' 2>/dev/null" || error-stop "policy did not end up to 2 in time"

TS_START=$(get_python_timestamp "Phase 6 start")
TS_SWITCH=$(vm "grep -E 'Policy switch from .* to 2' $CGMPOLD_OUT 2>/dev/null | tail -1 | awk '{print \$1}'" || echo "")
if [ -n "$TS_START" ] && [ -n "$TS_SWITCH" ]; then
    REACTION_TIME=$(time_diff_ms "$TS_START" "$TS_SWITCH")
    echo "  → Policy 0→1→2 transition took ${REACTION_TIME}ms"
fi
TS_COMPLETE=$(get_python_timestamp "Phase 6 complete")
ALLOC_TIME=$(time_diff_ms "$TS_START" "$TS_COMPLETE")
echo "  → python got 60MB in ${ALLOC_TIME}ms"

# Phase 7: Free to ~50+5 MB - should drop directly to policy 0
echo "Phase 7: Free to ~50+5 MB (drop below 20M reactivateLimit)"
python-input "$PYTHON_PORT" "log('Phase 7 start -50 MB'); del x50MB, x5MB; log('Phase 7 complete')"
vm-wait 50 "grep -q 'Policy switch from 2 to 0' $CGMPOLD_OUT 2>/dev/null" || error-stop "no policy switch from 2 to 0 in time"
TS_START=$(get_python_timestamp "Phase 7 start")
TS_SWITCH=$(vm "grep 'Policy switch from 2 to 0' $CGMPOLD_OUT 2>/dev/null | tail -1 | awk '{print \$1}'" || echo "")
if [ -n "$TS_START" ] && [ -n "$TS_SWITCH" ]; then
    REACTION_TIME=$(time_diff_ms "$TS_START" "$TS_SWITCH")
    echo "  → Policy 2→0 transition took ${REACTION_TIME}ms"
fi

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

# Check for initial policy (policy 0)
echo "Checking for initial policy (policy 0)..."
if echo "$CGMPOLD_OUTPUT" | grep -iq "setting memory policy.*preferred.*nodes \[0\]"; then
    echo "✓ Found initial policy activation (policy 0: preferred on node 0)"
else
    echo "✗ FAILED: Initial policy activation not found"
    exit 1
fi

echo "Checking for policy transitions..."

# Check that we used at least two different nodesets
NODESETS_USED=$(echo "$CGMPOLD_OUTPUT" | grep -o "nodes \[[^]]*\]" | sort -u | wc -l)
if [ "$NODESETS_USED" -lt 2 ]; then
    echo "✗ FAILED: Expected at least 2 different nodesets, found $NODESETS_USED"
    exit 1
fi

echo "✓ Used $NODESETS_USED different nodesets"

# Check for preferred policy
if echo "$CGMPOLD_OUTPUT" | grep -q "preferred"; then
    echo "✓ Preferred policy was applied"
else
    echo "✗ WARNING: Preferred policy was not found"
fi

echo ""
echo "=== Test Passed ==="
echo "Policy activation and reactivation worked as expected!"

# Cleanup temporary files
rm -rf /tmp/e2e-test01-$$

true
