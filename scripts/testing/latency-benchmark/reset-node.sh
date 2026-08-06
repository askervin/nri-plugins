#!/bin/bash

# reset-node.sh - return this node to a known, unconfigured state.
#
# Run between benchmark stages so that no stage inherits tuning from
# the previous one. Undoes both what the balloons policy does and what
# the platform may have been left in:
#
#   - uninstall the balloons policy and its CRD, delete benchmark
#     workloads
#   - reset CPU frequency limits and governors to platform defaults
#   - re-enable all cpuidle states (C-states)
#   - reset uncore frequency limits
#   - reset SST-CP/PCT configuration
#   - disable kernel automatic NUMA balancing
#   - clear CPU affinity from IRQs
#
# Uninstalling balloons does not restore CPU/memory pinning of running
# containers, so workloads are deleted before the policy goes away.
#
# Most steps are best-effort: a node without cpufreq, cpuidle, uncore
# or SST support simply skips them, with a note on stderr.

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BENCH_NAMESPACE="${BENCH_NAMESPACE:-latency-benchmark}"
HELM_RELEASE="${HELM_RELEASE:-nri-resource-policy-balloons}"
HELM_NAMESPACE="${HELM_NAMESPACE:-kube-system}"
SYS_CPU=/sys/devices/system/cpu

# NUMA_BALANCING_RESET: value written to kernel.numa_balancing.
# The benchmark wants it off, because page migration causes latency
# spikes that have nothing to do with the balloons configuration.
NUMA_BALANCING_RESET="${NUMA_BALANCING_RESET:-0}"

usage() {
    cat <<EOF
Usage: reset-node.sh [options]

Resets this node to an unconfigured state between benchmark stages.

Options:
  -w          reset workloads and balloons policy only, skip hardware
  -q          quiet, print only warnings and errors
  -h          show this help

Environment:
  BENCH_NAMESPACE          benchmark namespace (default: $BENCH_NAMESPACE)
  HELM_RELEASE             balloons helm release (default: $HELM_RELEASE)
  NUMA_BALANCING_RESET     kernel.numa_balancing value (default: $NUMA_BALANCING_RESET)
  KEEP_CRD                 non-empty: do not delete the BalloonsPolicy CRD
EOF
}

workloads_only=0
quiet=0
while getopts "wqh" opt; do
    case "$opt" in
        w) workloads_only=1 ;;
        q) quiet=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

info() { [ "$quiet" = 1 ] || echo "### $*"; }
warn() { echo "reset-node.sh: warning: $*" >&2; }

# write_all GLOB VALUE - write VALUE into every existing file matching
# GLOB. Returns 1 if no file matched, so callers can report that a
# whole mechanism is missing rather than warning per CPU.
write_all() {
    local glob="$1" value="$2"
    local f found=0
    for f in $glob; do
        [ -w "$f" ] || [ -f "$f" ] || continue
        found=1
        echo "$value" > "$f" 2>/dev/null || warn "cannot write $value to $f"
    done
    [ "$found" = 1 ]
}

###
### 1. Delete benchmark workloads. Do this before uninstalling the
###    policy, while the policy can still react to container removal.
###
info "Deleting benchmark workloads in namespace $BENCH_NAMESPACE ..."
if kubectl get namespace "$BENCH_NAMESPACE" >/dev/null 2>&1; then
    kubectl delete job,deployment,pod --all -n "$BENCH_NAMESPACE" \
            --ignore-not-found --grace-period=2 --timeout=120s >/dev/null 2>&1 ||
        warn "could not delete all workloads in $BENCH_NAMESPACE"
    # Wait for the pods to actually be gone, otherwise the next stage's
    # policy sees stale containers and may allocate CPUs for them.
    kubectl wait --for=delete pod --all -n "$BENCH_NAMESPACE" --timeout=120s >/dev/null 2>&1
fi

###
### 2. Uninstall the balloons policy.
###
if helm list -n "$HELM_NAMESPACE" -q 2>/dev/null | grep -qx "$HELM_RELEASE"; then
    info "Uninstalling helm release $HELM_RELEASE ..."
    helm uninstall "$HELM_RELEASE" -n "$HELM_NAMESPACE" --wait --timeout 120s >/dev/null ||
        warn "helm uninstall failed"
else
    info "Helm release $HELM_RELEASE not installed, nothing to uninstall."
fi

# Installation skips installing a new BalloonsPolicy CRD if one already
# exists, so a stale CRD from an older plugin version would reject new
# configuration options. Remove it unless asked to keep it.
if [ -z "${KEEP_CRD:-}" ]; then
    info "Deleting leftover CRDs ..."
    kubectl delete crd balloonspolicies.config.nri --ignore-not-found >/dev/null 2>&1
    kubectl delete crd noderesourcetopologies.topology.node.k8s.io \
            --ignore-not-found >/dev/null 2>&1
fi

if [ "$workloads_only" = 1 ]; then
    info "Skipping hardware reset (-w)."
    exit 0
fi

###
### 3. Reset CPU frequency limits and governors.
###
info "Resetting CPU frequency limits ..."
if [ -d "$SYS_CPU/cpu0/cpufreq" ]; then
    # Raise the maximum before lowering the minimum, so the two limits
    # never cross and get rejected by the kernel.
    for cpufreq in "$SYS_CPU"/cpu*/cpufreq; do
        [ -d "$cpufreq" ] || continue
        if [ -r "$cpufreq/cpuinfo_max_freq" ] && [ -w "$cpufreq/scaling_max_freq" ]; then
            cat "$cpufreq/cpuinfo_max_freq" > "$cpufreq/scaling_max_freq" 2>/dev/null ||
                warn "cannot reset $cpufreq/scaling_max_freq"
        fi
        if [ -r "$cpufreq/cpuinfo_min_freq" ] && [ -w "$cpufreq/scaling_min_freq" ]; then
            cat "$cpufreq/cpuinfo_min_freq" > "$cpufreq/scaling_min_freq" 2>/dev/null ||
                warn "cannot reset $cpufreq/scaling_min_freq"
        fi
    done
    # Restore the default governor and energy/performance preference.
    if [ -n "${RESET_GOVERNOR:-}" ]; then
        write_all "$SYS_CPU/cpu*/cpufreq/scaling_governor" "$RESET_GOVERNOR" ||
            warn "no scaling_governor files"
    fi
    write_all "$SYS_CPU/cpu*/cpufreq/energy_performance_preference" \
              "${RESET_EPP:-default}" >/dev/null 2>&1
else
    warn "no cpufreq sysfs on this node, skipping frequency reset"
fi

# Intel P-state turbo: make sure turbo is not left disabled.
if [ -w /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
    echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null ||
        warn "cannot re-enable turbo"
fi

###
### 4. Re-enable all cpuidle states.
###
info "Re-enabling all cpuidle states (C-states) ..."
if ! write_all "$SYS_CPU/cpu*/cpuidle/state*/disable" 0; then
    warn "no cpuidle sysfs on this node, skipping C-state reset"
fi

###
### 5. Reset uncore frequency limits.
###
info "Resetting uncore frequency limits ..."
uncore_found=0
for d in "$SYS_CPU"/intel_uncore_frequency/*/; do
    [ -d "$d" ] || continue
    uncore_found=1
    if [ -r "$d/initial_max_freq_khz" ] && [ -w "$d/max_freq_khz" ]; then
        cat "$d/initial_max_freq_khz" > "$d/max_freq_khz" 2>/dev/null ||
            warn "cannot reset $d/max_freq_khz"
    fi
    if [ -r "$d/initial_min_freq_khz" ] && [ -w "$d/min_freq_khz" ]; then
        cat "$d/initial_min_freq_khz" > "$d/min_freq_khz" 2>/dev/null ||
            warn "cannot reset $d/min_freq_khz"
    fi
done
[ "$uncore_found" = 1 ] || warn "no uncore frequency control on this node"

###
### 6. Reset SST-CP / PCT configuration.
###
# The balloons policy in managed PCT mode reconfigures SST-CP CLOSes.
# Disable core-power so that the next stage starts from a clean slate
# and non-PCT stages are not affected by leftover CLOS assignments.
if command -v intel-speed-select >/dev/null 2>&1; then
    info "Resetting SST-CP (PCT) configuration ..."
    intel-speed-select --debug core-power disable >/dev/null 2>&1 ||
        warn "intel-speed-select core-power disable failed (may be unsupported)"
else
    info "intel-speed-select not found, skipping PCT reset."
fi

###
### 7. Disable kernel automatic NUMA balancing.
###
info "Setting kernel.numa_balancing=$NUMA_BALANCING_RESET ..."
if [ -w /proc/sys/kernel/numa_balancing ]; then
    echo "$NUMA_BALANCING_RESET" > /proc/sys/kernel/numa_balancing 2>/dev/null ||
        warn "cannot set kernel.numa_balancing"
else
    warn "kernel.numa_balancing not available"
fi

###
### 8. Clear CPU affinity from IRQs.
###
# Any IRQ pinned to the CPUs the benchmark ends up on would add wakeup
# latency that is not attributable to the balloons configuration. Reset
# every IRQ back to "all CPUs allowed". Many IRQs reject writes (managed
# per-CPU interrupts, timers), which is expected and not an error.
info "Clearing CPU affinity from IRQs ..."
all_cpus_mask="$(printf '%x' $(( (1 << $(nproc)) - 1 )) 2>/dev/null)"
if [ -n "${IRQ_AFFINITY_MASK:-}" ]; then
    all_cpus_mask="$IRQ_AFFINITY_MASK"
fi
irq_reset=0
irq_failed=0
for irq_dir in /proc/irq/[0-9]*; do
    [ -w "$irq_dir/smp_affinity" ] || continue
    if echo "$all_cpus_mask" > "$irq_dir/smp_affinity" 2>/dev/null; then
        irq_reset=$((irq_reset + 1))
    else
        irq_failed=$((irq_failed + 1))
    fi
done
info "IRQ affinity reset on $irq_reset IRQs ($irq_failed rejected, normal for managed IRQs)."
if [ -w /proc/irq/default_smp_affinity ]; then
    echo "$all_cpus_mask" > /proc/irq/default_smp_affinity 2>/dev/null ||
        warn "cannot reset default_smp_affinity"
fi

# irqbalance would re-pin IRQs during the benchmark. Leave it stopped
# if it was running, so IRQ placement stays as reset above.
if [ -n "${STOP_IRQBALANCE:-}" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet irqbalance 2>/dev/null; then
        info "Stopping irqbalance ..."
        systemctl stop irqbalance >/dev/null 2>&1 || warn "cannot stop irqbalance"
    fi
fi

info "Node reset done."
