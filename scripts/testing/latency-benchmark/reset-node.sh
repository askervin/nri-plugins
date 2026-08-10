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

# online_cpus_list - the node's online CPUs, as a cpulist ("0-3,8-11").
#
# From sysfs, not from nproc: nproc reports how many CPUs the calling
# process may run on, so under a restricted affinity it undercounts, and
# it says nothing about which CPUs those are. The kernel already prints
# exactly the ranged form that smp_affinity_list and intel-speed-select
# -c both accept, so it is passed through as-is.
online_cpus_list() {
    local list=""
    if [ -r /sys/devices/system/cpu/online ]; then
        read -r list < /sys/devices/system/cpu/online
    fi
    # A uniprocessor kernel omits the file entirely; anything else means
    # sysfs is not mounted, and CPU 0 is the only safe assumption left.
    echo "${list:-0}"
}

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
    # Restore the governor and energy/performance preference.
    #
    # The governor is set to a fixed value rather than left as found,
    # because it is inherited node state that survives nothing in
    # particular: a reboot changed it from performance to powersave
    # between two campaigns here, and since the governor decides how
    # quickly a core ramps up after an idle period, that silently changed
    # what the benchmark measured. A campaign is only comparable to
    # another if the harness, not the last boot, decided this.
    write_all "$SYS_CPU/cpu*/cpufreq/scaling_governor" \
              "${RESET_GOVERNOR:-performance}" ||
        warn "no scaling_governor files"
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
# The balloons policy in managed PCT mode reconfigures SST-CP, and it
# leaves behind two separate pieces of state, both of which have to be
# undone, and in the right way:
#
#   - the CLOS frequency limits, and
#   - which CLOS each CPU is associated with.
#
# The limits are what cripple the node. The policy programs its CLOSes
# with min=0 max=0 (it expresses "no limit" as zero), and in SST-CP a
# clos-max of 0 means zero, not unlimited. Measured on a Xeon 6776P, that
# left every one of the 128 CPUs running at 500 MHz of a 4600 MHz part --
# IA32_PERF_STATUS ratio 0x05 -- while HWP_REQUEST asked for 4600 and the
# package drew 86 W of its 350 W limit. A fixed integer loop took 2.83 s
# instead of 0.30 s, so the whole node was 9x slow, on an idle machine,
# with the governor at performance and turbo enabled. Nothing in cpufreq,
# cpuidle, RAPL or thermal state showed a cause; only IA32_THERM_STATUS
# bit 10 ("power limitation") hinted at it. A benchmark that inherits
# that state measures a crippled node and has no way to tell.
#
# Reprogramming every CLOS to an explicit "unlimited" is what clears it.
# Disabling core-power does not: the limits stay programmed, and the
# clamp survives with them. Verified against that exact leftover state --
# a busy CPU went from 500 MHz back to 4600 as soon as the CLOSes were
# reprogrammed, with core-power still enabled.
#
# SST-TF (turbo-freq) and SST-BF (base-freq) are deliberately NOT
# disabled here. Disabling them also clears the clamp -- it was how the
# clamp was first cleared by hand -- but it breaks the PCT stage
# outright: the plugin's managed mode re-enables SST-TF while handling
# NRI Synchronize, and starting from a disabled state made that call
# exceed containerd's plugin_request_timeout every time, so containerd
# closed the connection, the plugin exited with "connection to
# NRI/runtime lost" and restarted, and the stage measured an
# unconfigured system. With the disable in place the PCT stage failed 6
# times out of 6; with the CLOS reprogramming instead, it passed.
# Set RESET_SST_PRIORITY_CORES=1 to disable them anyway, when handing the
# node back rather than benchmarking on it again.
if command -v intel-speed-select >/dev/null 2>&1; then
    info "Resetting SST-CP (PCT) configuration ..."
    # 25500 MHz is the maximum the ratio-encoded mailbox field can hold,
    # and is how intel-speed-select spells "Max Turbo frequency".
    for clos in 0 1 2 3; do
        intel-speed-select core-power config -c "$clos" \
            --min 0 --max 25500 >/dev/null 2>&1 ||
            warn "intel-speed-select core-power config -c $clos failed"
    done
    # Un-associate every CPU from its CLOS. Disabling core-power does not
    # clear the associations, and they are what a later stage or campaign
    # inherits: after the PCT stage here, 127 of 128 CPUs were still
    # associated with CLOS 3, the low-priority class.
    intel-speed-select -c "$(online_cpus_list)" core-power assoc --clos 0 \
        >/dev/null 2>&1 ||
        warn "intel-speed-select core-power assoc --clos 0 failed"
    intel-speed-select --debug core-power disable >/dev/null 2>&1 ||
        warn "intel-speed-select core-power disable failed (may be unsupported)"
    if [ -n "${RESET_SST_PRIORITY_CORES:-}" ]; then
        # -a applies to all packages. Both are expected to fail on parts
        # without the feature, hence the note rather than a warning.
        info "Disabling SST-TF / SST-BF (priority core) configuration ..."
        intel-speed-select turbo-freq disable -a >/dev/null 2>&1 ||
            info "intel-speed-select turbo-freq disable failed (may be unsupported)"
        intel-speed-select base-freq disable -a >/dev/null 2>&1 ||
            info "intel-speed-select base-freq disable failed (may be unsupported)"
    fi
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
# Use smp_affinity_list rather than the hexadecimal smp_affinity mask.
# Building the mask arithmetically breaks above 63 CPUs, where 1 << nproc
# overflows bash's 64-bit integers and yields a zero mask; the list form
# needs no arithmetic and no comma-separated 32-bit groups.
#
# The online set comes from sysfs rather than from nproc. nproc reports
# how many CPUs the *calling process* may run on, so a reset run under a
# restricted affinity would silently narrow every IRQ to a subset of the
# node; and "0-$((nproc - 1))" additionally assumes the online CPUs are
# contiguous and start at 0, which offlining any CPU makes false.
all_cpus_list="$(online_cpus_list)"
if [ -n "${IRQ_AFFINITY_LIST:-}" ]; then
    all_cpus_list="$IRQ_AFFINITY_LIST"
fi
irq_reset=0
irq_failed=0
for irq_dir in /proc/irq/[0-9]*; do
    [ -w "$irq_dir/smp_affinity_list" ] || continue
    if echo "$all_cpus_list" > "$irq_dir/smp_affinity_list" 2>/dev/null; then
        irq_reset=$((irq_reset + 1))
    else
        irq_failed=$((irq_failed + 1))
    fi
done
info "IRQ affinity reset on $irq_reset IRQs ($irq_failed rejected, normal for managed IRQs)."
if [ -w /proc/irq/default_smp_affinity ]; then
    # default_smp_affinity has no list form, so it keeps the mask. Write
    # it as comma-separated 32-bit groups, which is what the kernel
    # expects for more than 32 CPUs.
    #
    # Built from the same cpulist as above rather than from a CPU count,
    # so that an offline CPU in the middle of the range leaves its bit
    # clear instead of the mask claiming every CPU below the highest.
    default_mask="$(awk -v list="$all_cpus_list" 'BEGIN {
        n = split(list, ranges, ",")
        for (i = 1; i <= n; i++) {
            if (split(ranges[i], se, "-") == 2) { lo = se[1]; hi = se[2] }
            else { lo = ranges[i] + 0; hi = lo }
            for (c = lo; c <= hi; c++) {
                bit[int(c / 32)] += 2 ^ (c % 32)
                if (int(c / 32) > top) top = int(c / 32)
            }
        }
        out = ""
        for (g = 0; g <= top; g++) {
            s = sprintf("%08x", bit[g])
            out = (out == "") ? s : s "," out
        }
        print out }')"
    echo "$default_mask" > /proc/irq/default_smp_affinity 2>/dev/null ||
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
