# Test turbo priority: highest-priority active CPU class gets turbo,
# others get base. When the highest-priority balloon is removed,
# the next highest-priority class regains turbo.
#
# Also verifies CPU frequency write minimality:
#  - no duplicate sysfs writes (each (cpu, prop, freq) tuple is logged
#    at most once per recorded snapshot window, thanks to the per-CPU
#    last-written cache in pkg/resmgr/control/cpu),
#  - writes do happen on class transitions (turbo<->base) and when
#    idle CPUs need their initial class settings,
#  - a no-op event (creating a 2nd container that lands in the
#    *same* turbo-low balloon as pod0) does not produce any new
#    enforce writes.

helm-terminate
helm_config=$TEST_DIR/balloons-turbo.cfg helm-launch balloons

# turbo-log fetches the latest turbo recalculation log lines
turbo-log() {
    local last_n=${1:-20}
    vm-command "kubectl -n kube-system logs ds/nri-resource-policy-balloons | grep -E 'turbo:|cpuClass' | tail -n $last_n"
}

# verify-turbo-winner checks that the given class is logged as a turbo winner
# with the expected maxFreq, within the last N turbo log lines.
verify-turbo-winner() {
    local class=$1
    local expected_max_freq=$2
    local last_n=${3:-20}
    echo "verify turbo winner: class=$class maxFreq=$expected_max_freq"
    turbo-log $last_n
    grep "class \"$class\"" <<< "$COMMAND_OUTPUT" | grep "winner=true" | tail -n 1 | grep -q "maxFreq=$expected_max_freq" || {
        command-error "expected class $class as turbo winner with maxFreq=$expected_max_freq"
    }
}

# verify-turbo-loser checks that the given class is logged as NOT a turbo winner
# (winner=false) with the expected maxFreq (base), within the last N turbo log lines.
verify-turbo-loser() {
    local class=$1
    local expected_max_freq=$2
    local last_n=${3:-20}
    echo "verify turbo loser: class=$class maxFreq=$expected_max_freq"
    turbo-log $last_n
    grep "class \"$class\"" <<< "$COMMAND_OUTPUT" | grep "winner=false" | tail -n 1 | grep -q "maxFreq=$expected_max_freq" || {
        command-error "expected class $class as turbo loser with maxFreq=$expected_max_freq"
    }
}

ENFORCE_PATTERN='enforcing cpu frequency'

# enforce-count returns the total number of "enforcing cpu frequency" log lines so far.
enforce-count() {
    vm-command "kubectl -n kube-system logs ds/nri-resource-policy-balloons | grep -c '$ENFORCE_PATTERN' || true" >/dev/null
    echo "$COMMAND_OUTPUT" | tr -d '[:space:]'
}

# enforce-lines-since prints the enforce log lines added since the given absolute count.
enforce-lines-since() {
    local from=$1
    vm-command "kubectl -n kube-system logs ds/nri-resource-policy-balloons | grep '$ENFORCE_PATTERN' | tail -n +$((from+1))" >/dev/null
}

# assert-step-writes <prev_count> <label> <expect_min_writes> [forbid_duplicates=1]
# - asserts that at least <expect_min_writes> enforce lines were emitted since prev_count
# - asserts that all newly emitted enforce lines are unique (no duplicate sysfs writes
#   for the same cpu/property/value/class tuple within this window)
assert-step-writes() {
    local from=$1
    local label=$2
    local expect_min=$3
    local forbid_dup=${4:-1}
    enforce-lines-since "$from"
    local lines="$COMMAND_OUTPUT"
    local total=$(printf '%s\n' "$lines" | grep -c "$ENFORCE_PATTERN" || true)
    total=${total:-0}
    local unique=$(printf '%s\n' "$lines" | grep "$ENFORCE_PATTERN" | sort -u | wc -l | tr -d '[:space:]')
    echo "[$label] new enforce writes: total=$total unique=$unique (expect_min=$expect_min)"
    if [ "$total" -lt "$expect_min" ]; then
        echo "$lines"
        command-error "[$label] expected at least $expect_min enforce writes, got $total"
    fi
    if [ "$forbid_dup" = "1" ] && [ "$total" != "$unique" ]; then
        echo "$lines"
        command-error "[$label] duplicate enforce writes detected: total=$total unique=$unique"
    fi
}

# assert-no-new-writes <prev_count> <label>
assert-no-new-writes() {
    local from=$1
    local label=$2
    enforce-lines-since "$from"
    local lines="$COMMAND_OUTPUT"
    local total=$(printf '%s\n' "$lines" | grep -c "$ENFORCE_PATTERN" || true)
    total=${total:-0}
    if [ "$total" -ne 0 ]; then
        echo "$lines"
        command-error "[$label] expected no new enforce writes, got $total"
    fi
    echo "[$label] no new enforce writes (as expected)"
}

# assert-cpu-written <prev_count> <cpu_id> <label>
# verify that the given cpu had at least one frequency write since prev_count
assert-cpu-written() {
    local from=$1
    local cpu=$2
    local label=$3
    enforce-lines-since "$from"
    if ! grep -q "on cpu $cpu\$" <<< "$COMMAND_OUTPUT"; then
        echo "$COMMAND_OUTPUT"
        command-error "[$label] expected at least one enforce write on cpu $cpu"
    fi
    echo "[$label] cpu $cpu was written (as expected)"
}

# assert-class-written <prev_count> <class> <label>
# verify at least one enforce write was emitted for the given CPU class.
assert-class-written() {
    local from=$1
    local class=$2
    local label=$3
    enforce-lines-since "$from"
    if ! grep -q "from class \"$class\"" <<< "$COMMAND_OUTPUT"; then
        echo "$COMMAND_OUTPUT"
        command-error "[$label] expected at least one enforce write from class $class"
    fi
    echo "[$label] class $class was written (as expected)"
}

# Initial idle: before any pod is created the balloons policy resets
# all available CPUs (cpuset:2-7,10-13 = 10 CPUs) to the configured
# idleCPUClass (default-noturbo), then the reserved balloon claims
# one CPU (here cpu 10 because reservedResources.cpu=750m) and the
# explicit "reserved" balloonType assigns it to default-turbo. With
# no turboPriority>0 class active, default-turbo resolves "turbo" to
# the platform max (3800000), while default-noturbo caps at base
# (2900000). The CPU controller starts after the policy and merges
# policy-pushed (SetClass) class definitions on top of cfg.CPU.Classes
# placeholders, so every assigned CPU must receive enforce writes
# (min + max -> 2 writes/CPU).
echo "initial idle: verifying free CPUs are default-noturbo and reserved CPU is default-turbo"
sleep 3
launch_count=$(enforce-count)
echo "enforce writes after helm-launch: $launch_count"
assert-class-written 0 "default-noturbo" "initial idle (default-noturbo on free CPUs)"
assert-class-written 0 "default-turbo" "initial reserved (default-turbo on reserved CPU)"
# Free CPUs (9 of them) configured with default-noturbo.
for cpu in 2 3 4 5 6 7 11 12 13; do
    assert-cpu-written 0 "$cpu" "initial idle cpu $cpu"
done
# Reserved CPU (10) configured with default-turbo.
assert-cpu-written 0 10 "initial reserved cpu 10"
# Verify the assignment: cpu 10 must have a default-turbo write, NOT default-noturbo;
# and free CPUs must have default-noturbo writes, NOT default-turbo.
enforce-lines-since 0
init_lines="$COMMAND_OUTPUT"
if ! grep 'on cpu 10$' <<< "$init_lines" | grep -q 'default-turbo'; then
    echo "$init_lines"
    command-error "[initial] cpu 10 (reserved) must be configured via default-turbo"
fi
if grep 'on cpu 10$' <<< "$init_lines" | grep -q 'default-noturbo'; then
    echo "$init_lines"
    command-error "[initial] cpu 10 (reserved) must NOT be configured via default-noturbo"
fi
if grep 'on cpu 2$' <<< "$init_lines" | grep -q 'default-turbo'; then
    echo "$init_lines"
    command-error "[initial] cpu 2 (free) must NOT be configured via default-turbo"
fi
# Reserved cpu 10 should initially have maxFreq=3800000 (turbo) since
# no turbo-priority class is active yet.
if ! grep 'on cpu 10$' <<< "$init_lines" | grep 'max 3800000' | grep -q 'default-turbo'; then
    echo "$init_lines"
    command-error "[initial] cpu 10 (default-turbo) must initially get maxFreq=3800000"
fi
# 9 free CPUs * 2 (default-noturbo: min+max) + 1 reserved CPU * 2 (default-turbo: min+max) = >= 20.
assert-step-writes 0 "initial idle" 20

# Step 1: Create a pod with turbo-low balloon.
# turbo-low (prio=1) is the only active class with turboPriority > 0,
# so it should win turbo: maxFreq=3800000 (turbo).
# default-turbo (prio=0) loses turbo immediately: cpu 10 maxFreq drops
# from 3800000 (turbo) to 2900000 (base).
step1_before=$(enforce-count)
CPUREQ="750m" MEMREQ="100M" CPULIM="750m" MEMLIM=""
POD_ANNOTATION="balloon.balloons.resource-policy.nri.io: turbo-low-bln" CONTCOUNT=1 create balloons-busybox
report allowed
verify 'len(cpus["pod0c0"]) == 1'
echo "step 1: turbo-low is the only active turbo class, should win turbo; default-turbo loses turbo"
verify-turbo-winner "turbo-low" "3800000"
verify-turbo-loser "default-turbo" "2900000"
assert-class-written "$step1_before" "turbo-low" "step1 turbo-low write"
assert-class-written "$step1_before" "default-turbo" "step1 default-turbo (turbo->base on cpu 10)"
# Verify the cpu 10 max actually dropped to 2900000.
enforce-lines-since "$step1_before"
if ! grep 'on cpu 10$' <<< "$COMMAND_OUTPUT" | grep 'max 2900000' | grep -q 'default-turbo'; then
    echo "$COMMAND_OUTPUT"
    command-error "[step1] cpu 10 (default-turbo) must drop to maxFreq=2900000 when turbo-low becomes active"
fi
# At least 2 writes (min+max) for pod0c0 + 1 write (max) for cpu 10 = >= 3, in practice >= 4.
assert-step-writes "$step1_before" "step1" 3

# Step 1b: Create a 2nd container in the SAME balloon (turbo-low).
# The balloon already exists with turbo-low at turbo freq, the new
# container reuses the same CPU. recalculateTurbo() must early-out
# (winner unchanged), and the per-CPU lastFreq cache must suppress
# any redundant sysfs write for the unchanged CPU.
step1b_before=$(enforce-count)
CPUREQ="100m" MEMREQ="50M" CPULIM="100m" MEMLIM=""
POD_ANNOTATION="balloon.balloons.resource-policy.nri.io: turbo-low-bln" CONTCOUNT=1 create balloons-busybox
report allowed
echo "step 1b: 2nd container on same turbo-low balloon -- expect no new enforce writes"
assert-no-new-writes "$step1b_before" "step1b same-balloon container"

# Step 2: Create a pod with turbo-high balloon.
# turbo-high (prio=10) now has the highest active priority.
# turbo-high should win (maxFreq=3800000), turbo-low should lose (maxFreq=2900000 = base).
# default-turbo stays at base (no change expected for cpu 10).
step2_before=$(enforce-count)
CPUREQ="750m" MEMREQ="100M" CPULIM="750m" MEMLIM=""
POD_ANNOTATION="balloon.balloons.resource-policy.nri.io: turbo-high-bln" CONTCOUNT=1 create balloons-busybox
report allowed
verify 'len(cpus["pod2c0"]) == 1'
echo "step 2: turbo-high is now active, should win turbo; turbo-low loses; default-turbo stays at base"
verify-turbo-winner "turbo-high" "3800000"
verify-turbo-loser "turbo-low" "2900000"
verify-turbo-loser "default-turbo" "2900000"
assert-class-written "$step2_before" "turbo-low" "step2 turbo-low (turbo->base)"
assert-class-written "$step2_before" "turbo-high" "step2 turbo-high (idle->turbo)"
# cpu 10 (default-turbo) was already at base; should NOT be re-written.
enforce-lines-since "$step2_before"
if grep -q 'on cpu 10$' <<< "$COMMAND_OUTPUT"; then
    echo "$COMMAND_OUTPUT"
    command-error "[step2] cpu 10 (default-turbo) must not be re-written (already at base)"
fi
assert-step-writes "$step2_before" "step2" 4

# Step 3: Delete the turbo-high pod.
# turbo-low (prio=1) is again the highest active priority.
# turbo-low should regain turbo: maxFreq=3800000.
# default-turbo still loses turbo (turbo-low active) -> cpu 10 stays at base.
# The CPU released by turbo-high-bln must be reconfigured back to default-noturbo.
step3_before=$(enforce-count)
vm-command "kubectl delete pod pod2 --now"
sleep 2
report allowed
echo "step 3: turbo-high balloon gone, turbo-low regains turbo, released CPU back to default-noturbo"
verify-turbo-winner "turbo-low" "3800000"
assert-class-written "$step3_before" "turbo-low" "step3 turbo-low (base->turbo)"
assert-class-written "$step3_before" "default-noturbo" "step3 released CPU -> default-noturbo"
# cpu 10 must NOT be re-written (default-turbo still at base because turbo-low active).
enforce-lines-since "$step3_before"
if grep -q 'on cpu 10$' <<< "$COMMAND_OUTPUT"; then
    echo "$COMMAND_OUTPUT"
    command-error "[step3] cpu 10 (default-turbo) must not be re-written (turbo-low still active)"
fi
assert-step-writes "$step3_before" "step3" 4

# Step 4: Delete pod1 (the 2nd container in turbo-low-bln).
# The balloon still has pod0 -> CPU stays assigned to turbo-low.
# No writes expected.
step4_before=$(enforce-count)
vm-command "kubectl delete pod pod1 --now"
sleep 2
echo "step 4: deleting one container of turbo-low-bln, balloon still in use -- expect no new enforce writes"
assert-no-new-writes "$step4_before" "step4 partial deflate"

# Step 5: Delete pod0 (the last remaining container in turbo-low-bln).
# turbo-low-bln deflates and releases its CPU back to the idle pool.
# No more active turbo-priority classes -> default-turbo regains turbo.
# Expected writes:
#  - released CPU reconfigured to default-noturbo (min + max).
#  - cpu 10 (default-turbo) max bumped back to 3800000.
step5_before=$(enforce-count)
vm-command "kubectl delete pod pod0 --now"
sleep 2
report allowed
echo "step 5: last container of turbo-low-bln deleted; default-turbo regains turbo; released CPU -> default-noturbo"
assert-class-written "$step5_before" "default-noturbo" "step5 released CPU -> default-noturbo"
assert-class-written "$step5_before" "default-turbo" "step5 default-turbo regains turbo (cpu 10 max->3800000)"
enforce-lines-since "$step5_before"
if ! grep 'on cpu 10$' <<< "$COMMAND_OUTPUT" | grep 'max 3800000' | grep -q 'default-turbo'; then
    echo "$COMMAND_OUTPUT"
    command-error "[step5] cpu 10 (default-turbo) must regain maxFreq=3800000"
fi
assert-step-writes "$step5_before" "step5" 3

helm-terminate
