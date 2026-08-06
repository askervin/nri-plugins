#!/bin/bash

# stages.sh - benchmark stage definitions.
#
# Sourced by run-benchmark.sh. Each stage is a function named
# stage_<NAME> that exports the environment variables read by
# gen-balloons-config.sh, plus the STAGE_* variables that describe the
# stage itself:
#
#   STAGE_DESCRIPTION  human-readable one-liner
#   STAGE_NO_BALLOONS  non-empty: do not install balloons at all
#
# and the CSV feature columns (see csv_columns in report.sh), where 0
# means "this configuration option was not in use".
#
# Stages 1-6 are incremental: each one keeps everything the previous
# stage configured and adds one more mechanism. Stage 7 is NOT
# incremental: it replaces the cpufreq/turboPriority controls of stages
# 5-6 with PCT priority cores.

# STAGES - stage names in execution order.
STAGES=(
    baseline-no-balloons
    default-balloon
    dedicated-cpus
    realtime-sched
    disabled-cstates
    max-freq-turbo-prio
    pct-priority-cores
)

# stage_reset_vars - clear every variable a stage may set, so that
# stages never leak configuration into each other.
stage_reset_vars() {
    unset STAGE_DESCRIPTION STAGE_NO_BALLOONS STAGE_NEEDS_PCT
    unset RESERVED_CPU AVAILABLE_CPU PINCPU PINMEMORY
    unset ALLOCATORTOPOLOGYBALANCING IDLECPUCLASS TURBODOMAIN LOG_DEBUG_CPU
    # Pod labels are not stage-specific: the same Job and Deployment
    # yaml is used in every stage, so the labels the balloon types match
    # must stay as configured for the whole run.
    unset BENCH_BTYPE_NAME BENCH_BTYPE_SKIP
    unset BENCH_MINCPUS BENCH_MAXCPUS BENCH_MINBALLOONS BENCH_PREFERNEWBALLOONS
    unset BENCH_ALLOCATORPRIORITY BENCH_SCHEDULINGCLASS BENCH_CPUCLASS
    unset BENCH_SHAREIDLECPUS BENCH_HIDEHYPERTHREADS BENCH_LOADS
    unset NOISE_BTYPE_SKIP NOISE_BTYPE_NAME
    unset NOISE_MINCPUS NOISE_MAXCPUS NOISE_ALLOCATORPRIORITY
    unset NOISE_PREFERNEWBALLOONS NOISE_CPUCLASS NOISE_SCHEDULINGCLASS
    unset NOISE_SHAREIDLECPUS NOISE_LOADS
    unset DEFAULT_MINCPUS DEFAULT_MAXCPUS DEFAULT_CPUCLASS
    unset DEFAULT_SHAREIDLECPUS DEFAULT_LOADS
    unset LOADCLASS_NAME LOADCLASS_LEVEL LOADCLASS_OVERLOADS
    unset SCHEDCLASS_NAME SCHEDCLASS_POLICY SCHEDCLASS_PRIORITY
    unset SCHEDCLASS_IOCLASS SCHEDCLASS_IOPRIORITY
    local prefix suffix
    for prefix in CPUCLASS_BENCH CPUCLASS_OTHER CPUCLASS_IDLE; do
        for suffix in NAME MINFREQ MAXFREQ UNCOREMINFREQ UNCOREMAXFREQ \
                      DISABLEDCSTATES TURBOPRIORITY EPP FREQGOVERNOR \
                      PCTPRIORITY PCTMINFREQ PCTMAXFREQ; do
            unset "${prefix}_${suffix}"
        done
    done
}

# Stage 1: absolute zero baseline. No balloons policy installed at all,
# so the benchmark container runs wherever the kernel puts it, with
# whatever frequencies and C-states the platform defaults to.
stage_baseline-no-balloons() {
    STAGE_DESCRIPTION="no balloons policy installed at all (absolute baseline)"
    STAGE_NO_BALLOONS=1
}

# Stage 2: balloons installed, but the benchmark shares the default
# balloon with the stress-ng noise. This isolates the cost of sharing
# CPUs with other workloads.
stage_default-balloon() {
    STAGE_DESCRIPTION="benchmark in the default balloon, shared with other workloads"
    BENCH_BTYPE_SKIP=1
    NOISE_BTYPE_SKIP=1
}

# Stage 3: the benchmark gets its own balloon with dedicated CPUs.
# Noise gets a balloon of its own, so it can no longer run on the
# benchmark's CPUs.
stage_dedicated-cpus() {
    STAGE_DESCRIPTION="benchmark on dedicated CPUs (preferNewBalloons)"
    BENCH_PREFERNEWBALLOONS=true
    BENCH_MINCPUS=${BENCH_CPUS:-2}
    BENCH_MAXCPUS=${BENCH_CPUS:-2}
    BENCH_MINBALLOONS=1
    BENCH_ALLOCATORPRIORITY=high
}

# Stage 4: add a realtime scheduling policy on the benchmark container.
# Requires sleep-accuracy to run without -p, otherwise the tool sets its
# own scheduling policy and erases the one set here.
stage_realtime-sched() {
    stage_dedicated-cpus
    STAGE_DESCRIPTION="dedicated CPUs + realtime scheduling class (SCHED_FIFO)"
    BENCH_SCHEDULINGCLASS=realtime
    SCHEDCLASS_NAME=realtime
    SCHEDCLASS_POLICY=${SCHEDCLASS_POLICY:-fifo}
    SCHEDCLASS_PRIORITY=${SCHEDCLASS_PRIORITY:-80}
    SCHEDCLASS_IOCLASS=rt
    SCHEDCLASS_IOPRIORITY=0
}

# Stage 5: disable C-states on the benchmark's CPUs so they never enter
# deep sleep and pay the wakeup cost. Other CPUs keep their C-states.
stage_disabled-cstates() {
    stage_realtime-sched
    STAGE_DESCRIPTION="realtime + deep C-states disabled on benchmark CPUs"
    BENCH_CPUCLASS=latency-critical
    CPUCLASS_BENCH_NAME=latency-critical
    CPUCLASS_BENCH_DISABLEDCSTATES=${DISABLED_CSTATES:-C1E,C6}
    LOG_DEBUG_CPU=1
}

# Stage 6: maximize the frequency of the benchmark's CPUs and use
# turboPriority so that the benchmark class wins exclusive turbo
# access, capping every other class at base frequency.
stage_max-freq-turbo-prio() {
    stage_disabled-cstates
    STAGE_DESCRIPTION="C-states off + max/turbo frequency, other CPUs capped via turboPriority"
    CPUCLASS_BENCH_MINFREQ=base
    CPUCLASS_BENCH_MAXFREQ=turbo
    CPUCLASS_BENCH_TURBOPRIORITY=10
    # Every other CPU competes for turbo at a lower priority, so
    # turboPriority arbitration resolves their "turbo" to base.
    NOISE_CPUCLASS=other
    DEFAULT_CPUCLASS=other
    IDLECPUCLASS=other
    CPUCLASS_OTHER_NAME=other
    CPUCLASS_OTHER_MINFREQ=min
    CPUCLASS_OTHER_MAXFREQ=turbo
    CPUCLASS_OTHER_TURBOPRIORITY=1
    TURBODOMAIN=${TURBODOMAIN:-package}
}

# Stage 7: replacement, not an increment. Drop the soft cpufreq turbo
# arbitration of stages 5-6 and let PCT hardware do the priority
# work: benchmark CPUs go to the high-priority CLOS, everything else
# (including idle CPUs) to the low-priority CLOS.
stage_pct-priority-cores() {
    stage_realtime-sched
    STAGE_DESCRIPTION="realtime + C-states off + PCT priority cores (replaces cpufreq/turboPriority)"
    BENCH_CPUCLASS=hp-pct
    CPUCLASS_BENCH_NAME=hp-pct
    CPUCLASS_BENCH_DISABLEDCSTATES=${DISABLED_CSTATES:-C1E,C6}
    CPUCLASS_BENCH_PCTPRIORITY=high
    # An LP class is required: idle CPUs must be routed to the LP CLOS
    # so that they do not inflate the active HP core count.
    NOISE_CPUCLASS=lp-pct
    DEFAULT_CPUCLASS=lp-pct
    IDLECPUCLASS=lp-pct
    CPUCLASS_OTHER_NAME=lp-pct
    CPUCLASS_OTHER_PCTPRIORITY=low
    LOG_DEBUG_CPU=1
    STAGE_NEEDS_PCT=1
}
