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
# Stages 1-7 are incremental: each one keeps everything the previous
# stage configured and adds one more mechanism. Stage 8 is NOT
# incremental: it replaces the cpufreq/turboPriority controls of stages
# 6-7 with PCT priority cores. Stage 9 is incremental again, on top of
# stage 8.
#
# A stage may also declare a precondition the node must already satisfy,
# with STAGE_REQUIRES_ISOLCPUS. Such a stage refuses to run rather than
# measuring a mechanism that is not there -- see run-benchmark.sh.

# STAGES - stage names in execution order.
STAGES=(
    baseline-no-balloons
    default-balloon
    dedicated-cpus
    realtime-sched
    isolate-irqs
    disabled-cstates
    max-freq-turbo-prio
    pct-priority-cores
    isolcpus
)

# stage_reset_vars - clear every variable a stage may set, so that
# stages never leak configuration into each other.
stage_reset_vars() {
    unset STAGE_DESCRIPTION STAGE_NO_BALLOONS STAGE_NEEDS_PCT
    unset STAGE_REQUIRES_ISOLCPUS
    # RESERVED_CPU, AVAILABLE_CPU, PINCPU, PINMEMORY and
    # ALLOCATORTOPOLOGYBALANCING are deliberately not reset here. No
    # stage sets them: they describe the node and the run as a whole, so
    # they come from the environment and must survive every stage. Only
    # variables a stage may set belong below.
    #
    # CLIENT_* is not reset either, and for a stronger reason: it
    # describes the load generator of an application that needs one, and
    # the whole point of that balloon is that it is identical in every
    # stage. An application module owns those variables; no stage does.
    unset IDLECPUCLASS TURBODOMAIN LOG_DEBUG_CPU
    unset LOG_DEBUG_IRQ
    # Pod labels are not stage-specific: the same Job and Deployment
    # yaml is used in every stage, so the labels the balloon types match
    # must stay as configured for the whole run.
    unset BENCH_BTYPE_NAME BENCH_BTYPE_SKIP
    unset BENCH_MINCPUS BENCH_MAXCPUS BENCH_MINBALLOONS BENCH_PREFERNEWBALLOONS
    unset BENCH_ALLOCATORPRIORITY BENCH_SCHEDULINGCLASS BENCH_CPUCLASS
    unset BENCH_PREFERISOLCPUS
    unset BENCH_SHAREIDLECPUS BENCH_HIDEHYPERTHREADS BENCH_LOADS
    unset BENCH_IRQCLAIM BENCH_IRQMODE
    unset NOISE_BTYPE_SKIP NOISE_BTYPE_NAME
    unset NOISE_MINCPUS NOISE_MAXCPUS NOISE_ALLOCATORPRIORITY
    unset NOISE_PREFERNEWBALLOONS NOISE_CPUCLASS NOISE_SCHEDULINGCLASS
    unset NOISE_SHAREIDLECPUS NOISE_LOADS NOISE_IRQCLAIM NOISE_IRQMODE
    unset DEFAULT_MINCPUS DEFAULT_MAXCPUS DEFAULT_CPUCLASS
    unset DEFAULT_SHAREIDLECPUS DEFAULT_LOADS DEFAULT_IRQCLAIM DEFAULT_IRQMODE
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

# Stage 5: keep hardware interrupts off the benchmark's CPUs. With
# irqMode isolate the policy removes those CPUs from the affinity of
# every IRQ that no balloon claims or sinks.
#
# The noise and default balloons become IRQ sinks. Without a sink, an
# isolated CPU is only dropped from an IRQ's affinity if some other
# allowed CPU remains, so IRQs whose affinity is a subset of the
# benchmark's CPUs would stay there. Sinking them on the CPUs that run
# the noise moves them out of the way for good.
stage_isolate-irqs() {
    stage_realtime-sched
    STAGE_DESCRIPTION="realtime + IRQs kept off benchmark CPUs (irqMode isolate)"
    BENCH_IRQMODE=isolate
    NOISE_IRQMODE=sink
    DEFAULT_IRQMODE=sink
    LOG_DEBUG_IRQ=1
}

# Stage 6: disable C-states on the benchmark's CPUs so they never enter
# deep sleep and pay the wakeup cost. Other CPUs keep their C-states.
stage_disabled-cstates() {
    stage_isolate-irqs
    STAGE_DESCRIPTION="realtime + isolated IRQs + deep C-states disabled on benchmark CPUs"
    BENCH_CPUCLASS=latency-critical
    CPUCLASS_BENCH_NAME=latency-critical
    CPUCLASS_BENCH_DISABLEDCSTATES=${DISABLED_CSTATES:-C1E,C6}
    LOG_DEBUG_CPU=1
}

# Stage 7: maximize the frequency of the benchmark's CPUs and use
# turboPriority so that the benchmark class wins exclusive turbo
# access, capping every other class at base frequency.
stage_max-freq-turbo-prio() {
    stage_disabled-cstates
    STAGE_DESCRIPTION="isolated IRQs + C-states off + max/turbo frequency, other CPUs capped via turboPriority"
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

# Stage 8: replacement, not an increment. Drop the soft cpufreq turbo
# arbitration of stages 6-7 and let PCT hardware do the priority
# work: benchmark CPUs go to the high-priority CLOS, everything else
# (including idle CPUs) to the low-priority CLOS. IRQ isolation is not a
# frequency control, so it stays.
stage_pct-priority-cores() {
    stage_isolate-irqs
    STAGE_DESCRIPTION="realtime + isolated IRQs + C-states off + PCT priority cores (replaces cpufreq/turboPriority)"
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

# Stage 9: on top of PCT, take the benchmark's CPUs from the set the
# kernel isolated with the isolcpus= boot parameter.
#
# This is the one stage that cannot be set up from userspace. isolcpus is
# a kernel command line parameter, so the node must already have been
# booted with it; the stage refuses to run otherwise rather than
# measuring a preferIsolCpus that silently fell back to ordinary CPUs.
#
# What isolcpus adds on top of everything before it: the kernel keeps its
# own load balancer off those CPUs entirely. Stages 3-8 stop *other
# containers* from running there and stop interrupts and frequency
# competition; none of them stops the kernel scheduler from considering
# the CPU a normal member of a scheduling domain. This is the difference
# between "nothing else is placed here" and "the scheduler does not even
# look here".
#
# Exclusivity is not configured here and does not need to be. Given any
# isolated CPUs, the policy puts them on the avoid-list of every balloon
# type that does not set preferIsolCpus, and never offers them as shared
# idle CPUs. So one balloon prefers them and every other balloon keeps
# away. The state checks verify both halves of that rather than trusting
# it: the benchmark must be on isolated CPUs only, and nothing else may
# be on them at all.
#
# Which CPUs to isolate is an operator decision made on the kernel
# command line, not here. Two rules: never the first CPU of a socket,
# which carries timers and workqueues that would land in the measurement
# as jitter; and few enough that the ~95 other containers still fit on
# what is left, because "avoid" is a preference and a node with nowhere
# else to go will spill onto isolated CPUs anyway. run-benchmark.sh
# prints a suitable cpulist for this node when the precondition fails.
stage_isolcpus() {
    stage_pct-priority-cores
    STAGE_DESCRIPTION="PCT priority cores + benchmark CPUs taken from kernel isolcpus"
    BENCH_PREFERISOLCPUS=true
    STAGE_REQUIRES_ISOLCPUS=1
}

###
### The ablation set: one reference, one option removed at a time.
###
# The ladder above answers "what does adding X on top of everything before
# it buy?". That conflates an option's effect with its position: PCT is only
# ever measured after turboPriority, isolcpus only ever after PCT, so the
# combinations that were never tried -- maxfreq+isolcpus against
# pct+isolcpus, for one -- simply have no data.
#
# This set answers the question an operator actually has: "can I leave this
# out?" It fixes the best known configuration for minimal wakeup latency as
# the reference and removes one thing at a time, so the picture is a floor
# with bumps rather than a staircase, and every bump is the cost of dropping
# one option from a configuration that is otherwise identical.
#
# Every arm is defined as stage_ab_ref followed by unsetting or replacing
# exactly what it ablates. That is deliberate: re-listing the whole
# configuration per arm would let the arms drift apart, and then a bump
# would no longer be attributable to the one thing the arm is named for.
#
# THE TWO-OPTION ARMS ARE NO LONGER IN THE SET. ab-no-freq-no-isolcpus and
# ab-no-cstates-no-freq are still defined below, so the v4 result can be
# reproduced, but they are not run by default: a pair arm costs a full stage and
# answers a question about redundancy rather than about any one option. The one
# interaction they did find -- frequency control and isolcpus are partially
# redundant, so removing both costs 1.42-1.47x on the 1 us p99 where either
# alone costs 1.07-1.20x -- is recorded in analysis/V4-SERIES.md and does not
# need re-measuring.
#
# Two arms are NOT single-option ablations and are named "anchor" to say so.
# They exist to make bump heights interpretable: without the full range
# between the reference and no policy at all, a 2 us bump is a number
# without a scale.
#
# STAGES_ABLATION - the arms, in the order they should read on an x axis:
# reference first, then the single-option ablations, then the pairs that
# test for redundancy, then the anchors.
STAGES_ABLATION=(
    ab-ref
    ab-no-realtime
    ab-no-cstates
    ab-no-irqs
    ab-no-isolcpus
    ab-freq-not-pct
    ab-no-freq
    ab-anchor-shared-balloon
    ab-anchor-no-policy
)

# ab-ref: the reference. Best known configuration for minimal wakeup
# latency: own balloon with dedicated CPUs, SCHED_FIFO, every C-state
# disabled, PCT high-priority cores, CPUs taken from kernel isolcpus, and
# interrupts kept off those CPUs.
#
# DISABLED_CSTATES defaults to every sleep state this class of part has.
# POLL is deliberately not in the list: it is not a sleep state but the
# busy-poll idle loop, and with everything else disabled it is what the CPU
# falls back to -- which is the whole point. The cost is power, paid
# continuously, and that belongs in any report of these numbers.
stage_ab-ref() {
    stage_isolcpus
    STAGE_DESCRIPTION="reference: dedicated + FIFO + all C-states off + PCT + isolcpus + IRQs off"
    CPUCLASS_BENCH_DISABLEDCSTATES="${DISABLED_CSTATES:-C1,C1E,C6,C6P}"
}

# Every arm below requires the node to have isolcpus, including the arms
# that do not use them: without isolated CPUs on the node the reference and
# ab-no-isolcpus would be the same configuration, and the set as a whole
# would silently answer a different question.

stage_ab-no-realtime() {
    stage_ab-ref
    STAGE_DESCRIPTION="reference minus the realtime scheduling class"
    unset BENCH_SCHEDULINGCLASS SCHEDCLASS_NAME SCHEDCLASS_POLICY
    unset SCHEDCLASS_PRIORITY SCHEDCLASS_IOCLASS SCHEDCLASS_IOPRIORITY
}

stage_ab-no-cstates() {
    stage_ab-ref
    STAGE_DESCRIPTION="reference minus C-state disabling (all idle states allowed)"
    unset CPUCLASS_BENCH_DISABLEDCSTATES
}

stage_ab-no-irqs() {
    stage_ab-ref
    STAGE_DESCRIPTION="reference minus IRQ isolation"
    unset BENCH_IRQMODE NOISE_IRQMODE DEFAULT_IRQMODE LOG_DEBUG_IRQ
}

stage_ab-no-isolcpus() {
    stage_ab-ref
    STAGE_DESCRIPTION="reference minus preferIsolCpus (ordinary CPUs instead)"
    unset BENCH_PREFERISOLCPUS
}

# PCT replaced by the soft cpufreq route: max/turbo on the benchmark class
# and turboPriority arbitration capping every other class at base. This is
# the comparison the ladder could never make, because it only ever reached
# PCT by passing through turboPriority first.
stage_ab-freq-not-pct() {
    stage_ab-ref
    STAGE_DESCRIPTION="reference with cpufreq max+turboPriority instead of PCT"
    unset CPUCLASS_BENCH_PCTPRIORITY CPUCLASS_OTHER_PCTPRIORITY STAGE_NEEDS_PCT
    BENCH_CPUCLASS=latency-critical
    CPUCLASS_BENCH_NAME=latency-critical
    CPUCLASS_BENCH_MINFREQ=base
    CPUCLASS_BENCH_MAXFREQ=turbo
    CPUCLASS_BENCH_TURBOPRIORITY=10
    NOISE_CPUCLASS=other
    DEFAULT_CPUCLASS=other
    IDLECPUCLASS=other
    CPUCLASS_OTHER_NAME=other
    CPUCLASS_OTHER_MINFREQ=min
    CPUCLASS_OTHER_MAXFREQ=turbo
    CPUCLASS_OTHER_TURBOPRIORITY=1
    TURBODOMAIN="${TURBODOMAIN:-package}"
}

# No frequency control of any kind. The benchmark class survives because it
# still carries disabledCstates; the class covering everything else goes
# away entirely, so no other CPU is capped or promoted.
stage_ab-no-freq() {
    stage_ab-ref
    STAGE_DESCRIPTION="reference minus all frequency control (no PCT, no cpufreq)"
    unset CPUCLASS_BENCH_PCTPRIORITY CPUCLASS_BENCH_MINFREQ CPUCLASS_BENCH_MAXFREQ
    unset CPUCLASS_BENCH_TURBOPRIORITY STAGE_NEEDS_PCT
    unset CPUCLASS_OTHER_NAME CPUCLASS_OTHER_PCTPRIORITY CPUCLASS_OTHER_MINFREQ
    unset CPUCLASS_OTHER_MAXFREQ CPUCLASS_OTHER_TURBOPRIORITY
    unset NOISE_CPUCLASS DEFAULT_CPUCLASS IDLECPUCLASS TURBODOMAIN
    # The class survives to carry disabledCstates, so rename it: a class
    # still called hp-pct while doing no PCT at all would misdescribe the
    # configuration in the stored record.
    BENCH_CPUCLASS=latency-critical
    CPUCLASS_BENCH_NAME=latency-critical
}

# The pairs. A leave-one-out design cannot see redundancy: if either of two
# options alone is enough, removing each in turn shows nothing and both look
# useless. These remove both members of the two pairs where that is most
# plausible -- two ways of protecting frequency, and two ways of keeping the
# CPU responsive.
stage_ab-no-freq-no-isolcpus() {
    stage_ab-no-freq
    STAGE_DESCRIPTION="reference minus all frequency control AND minus isolcpus"
    unset BENCH_PREFERISOLCPUS
}

stage_ab-no-cstates-no-freq() {
    stage_ab-no-freq
    STAGE_DESCRIPTION="reference minus C-state disabling AND minus all frequency control"
    unset CPUCLASS_BENCH_DISABLEDCSTATES
}

# The anchors. Not ablations of one option: the balloon type the benchmark
# would be in stops existing, so everything attached to it goes too. They
# are here to give the bumps a scale.
stage_ab-anchor-shared-balloon() {
    STAGE_DESCRIPTION="anchor: benchmark shares the default balloon with the noise"
    BENCH_BTYPE_SKIP=1
    NOISE_BTYPE_SKIP=1
    STAGE_REQUIRES_ISOLCPUS=1
}

stage_ab-anchor-no-policy() {
    STAGE_DESCRIPTION="anchor: no balloons policy installed at all"
    STAGE_NO_BALLOONS=1
    STAGE_REQUIRES_ISOLCPUS=1
}


###
### The PCT tuning set: frequency floors, independently controllable.
###
# v4 showed PCT's benefit is real but sleep-length dependent: removing all
# frequency control costs 1.21x on the p50 of a 1 us sleep and 1.22x at 50 us,
# but only 1.05x at 1 ms -- and at 50 us it makes the p999 *better* (0.84x).
#
# The reference's own recorded state explains why. Its HP class sets neither
# minFreq nor pctMinFreq, so:
#
#   clos 0: clos-min:0 MHz clos-max:4600 MHz        <- no hardware floor
#   /cpu1/cpufreq: min=800000 max=4600000           <- no OS floor
#
# The high-priority core is *permitted* max turbo and reaches it when busy, but
# nothing holds it there. At a 1 us sleep it never has time to fall; at 50 us
# and 1 ms it does, and the ramp back up lands inside the measured overshoot.
#
# THERE ARE TWO FLOORS AND THEY ARE SET SEPARATELY.
#
#   minFreq / maxFreq        the OS floor and ceiling, written to cpufreq's
#                            scaling_min_freq / scaling_max_freq
#   pctMinFreq / pctMaxFreq  the hardware floor and ceiling, programmed into
#                            the SST-CP CLOS this class is associated with
#
# pctMinFreq DEFAULTS TO minFreq and pctMaxFreq to maxFreq, so setting the OS
# floor silently sets the hardware floor too. The only way to move one without
# the other is to state both, which is why every variable below is emitted
# explicitly rather than left to default. To leave the CLOS deliberately open
# while flooring the OS, set the CLOS range to min..turbo -- an open range is
# how "no hardware limit" is spelled.
#
# The four frequencies are variables so a campaign can sweep them without
# editing this file. Each accepts min | base | turbo, a value with units
# ("2900MHz"), or a plain kHz number; empty means "do not set this field".
#
#   PT_HP_CLOS_MIN / PT_HP_CLOS_MAX   hardware range for the sensitive workload
#   PT_HP_OS_MIN   / PT_HP_OS_MAX     OS range for the sensitive workload
#   PT_LP_CLOS_MIN / PT_LP_CLOS_MAX   hardware range for every background CPU
#   PT_LP_OS_MIN   / PT_LP_OS_MAX     OS range for every background CPU
#
# WHY THE BACKGROUND IS PINNED TO base, AND WHY NOTHING IS EVER CAPPED TO min.
#
# base is not a compromise, it is the definition of the target: the background
# frequency wanted here is the highest one that still leaves enough package
# power headroom for PCT to lift the high-priority cores to the maximum turbo
# the platform can reach. On this part SST-TF grants the top turbo bucket to 8
# HP cores per punit *because* the remaining cores are held down, so pinning the
# background any higher spends the very budget the HP floor depends on -- pinned
# to turbo it could defeat PCT outright rather than merely costing background
# throughput. PT_LP_* stays a variable so that cost can be measured rather than
# assumed, but base is the answer this experiment is built around.
#
# No frequency is ever CAPPED to min. A ceiling of min would clamp a core to
# the hardware floor -- the 500 MHz failure that cost three early campaigns --
# so every ceiling here is base or turbo. A FLOOR of min is a different thing
# and is legitimate: it means "no floor", which is how pt-hp-os leaves the
# hardware CLOS open while pinning the OS.
PT_HP_CLOS_MIN="${PT_HP_CLOS_MIN:-turbo}"
PT_HP_CLOS_MAX="${PT_HP_CLOS_MAX:-turbo}"
PT_HP_OS_MIN="${PT_HP_OS_MIN:-turbo}"
PT_HP_OS_MAX="${PT_HP_OS_MAX:-turbo}"
PT_LP_CLOS_MIN="${PT_LP_CLOS_MIN:-base}"
PT_LP_CLOS_MAX="${PT_LP_CLOS_MAX:-base}"
PT_LP_OS_MIN="${PT_LP_OS_MIN:-base}"
PT_LP_OS_MAX="${PT_LP_OS_MAX:-base}"

# STAGES_PCTTUNE - the reference, the two arms PCT has to beat, then each floor
# separately, then together.
#
# ab-freq-not-pct and ab-no-freq are in the set on purpose. They are what PCT is
# being compared *against*: v4 measured them as 1.22x and 1.22x on the p50 of a
# 50 us sleep, and 0.74x and 0.84x on its p999 -- the tail case where the
# reference was actually worse than having no frequency control at all. Adding
# floors is only interesting if it beats those two, so they belong in the same
# run rather than in a table from a different week.
#
# Every arm shares the v4 reference, so each is comparable with its v4 twin.
STAGES_PCTTUNE=(
    ab-ref
    ab-freq-not-pct
    ab-no-freq
    pt-hp-clos
    pt-hp-os
    pt-hp-both
    pt-lp-only
    pt-hp-and-lp
)

# Hardware floor only: the HP CLOS is pinned, cpufreq is left as the reference
# had it (800 MHz .. 4.6 GHz).
stage_pt-hp-clos() {
    stage_ab-ref
    STAGE_DESCRIPTION="reference + HP hardware CLOS pinned ${PT_HP_CLOS_MIN}..${PT_HP_CLOS_MAX}"
    CPUCLASS_BENCH_PCTMINFREQ="$PT_HP_CLOS_MIN"
    CPUCLASS_BENCH_PCTMAXFREQ="$PT_HP_CLOS_MAX"
}

# OS floor only: cpufreq is pinned and the CLOS is deliberately left open, which
# has to be said explicitly because pctMinFreq would otherwise inherit minFreq.
stage_pt-hp-os() {
    stage_ab-ref
    STAGE_DESCRIPTION="reference + HP OS cpufreq pinned ${PT_HP_OS_MIN}..${PT_HP_OS_MAX}, CLOS left open"
    CPUCLASS_BENCH_MINFREQ="$PT_HP_OS_MIN"
    CPUCLASS_BENCH_MAXFREQ="$PT_HP_OS_MAX"
    CPUCLASS_BENCH_PCTMINFREQ=min
    CPUCLASS_BENCH_PCTMAXFREQ=turbo
}

# Both floors on the sensitive workload.
stage_pt-hp-both() {
    stage_ab-ref
    STAGE_DESCRIPTION="reference + HP pinned at both levels (OS ${PT_HP_OS_MIN}..${PT_HP_OS_MAX}, CLOS ${PT_HP_CLOS_MIN}..${PT_HP_CLOS_MAX})"
    CPUCLASS_BENCH_MINFREQ="$PT_HP_OS_MIN"
    CPUCLASS_BENCH_MAXFREQ="$PT_HP_OS_MAX"
    CPUCLASS_BENCH_PCTMINFREQ="$PT_HP_CLOS_MIN"
    CPUCLASS_BENCH_PCTMAXFREQ="$PT_HP_CLOS_MAX"
}

# Only the background is pinned, the sensitive workload is left as the
# reference had it. Isolates what holding the neighbours steady is worth on its
# own -- if this alone helps, the mechanism is interference and power budget
# rather than the HP core's own frequency.
stage_pt-lp-only() {
    stage_ab-ref
    STAGE_DESCRIPTION="reference + background pinned (OS ${PT_LP_OS_MIN}..${PT_LP_OS_MAX}, CLOS ${PT_LP_CLOS_MIN}..${PT_LP_CLOS_MAX})"
    CPUCLASS_OTHER_MINFREQ="$PT_LP_OS_MIN"
    CPUCLASS_OTHER_MAXFREQ="$PT_LP_OS_MAX"
    CPUCLASS_OTHER_PCTMINFREQ="$PT_LP_CLOS_MIN"
    CPUCLASS_OTHER_PCTMAXFREQ="$PT_LP_CLOS_MAX"
}

# Everything pinned: the sensitive workload at both levels and every background
# CPU at both levels. The configuration an operator would deploy if the parts
# help, and the only way to ask whether holding the neighbours steady lets the
# HP floor actually hold.
stage_pt-hp-and-lp() {
    stage_pt-hp-both
    STAGE_DESCRIPTION="everything pinned: HP ${PT_HP_OS_MIN}..${PT_HP_OS_MAX}, background ${PT_LP_OS_MIN}..${PT_LP_OS_MAX}"
    CPUCLASS_OTHER_MINFREQ="$PT_LP_OS_MIN"
    CPUCLASS_OTHER_MAXFREQ="$PT_LP_OS_MAX"
    CPUCLASS_OTHER_PCTMINFREQ="$PT_LP_CLOS_MIN"
    CPUCLASS_OTHER_PCTMAXFREQ="$PT_LP_CLOS_MAX"
}


###
### The p999 verification set: is a tail difference real, or is it the noise?
###
# The 50 us probe showed pt-hp-os at 0.85x of the reference on p999 under cpumem
# noise. That is worth checking rather than believing, because three things
# argue it is noise:
#
#  1. v4 gives five cycles of the IDENTICAL reference at this operating point:
#     p999 = 5.35, 5.54, 5.78, 5.82, 5.99 us, a 0.92x..1.04x spread from
#     configuration changes of exactly zero. 0.85x is barely outside a band
#     already known to be +-8%.
#  2. pt-hp-os and pt-hp-both both pin the OS floor to 4600..4600. If the OS
#     floor caused 0.85x, pt-hp-both would show it too; it showed 1.08x. An
#     effect that depends on an unrelated CLOS setting is not an effect.
#  3. The mechanism is absent. Achieved frequency is 4600 MHz in the reference
#     and in every floor arm, so there is no frequency deficit for a floor to
#     close.
#
# THE NEGATIVE CONTROL IS THE POINT OF THIS SET. pt-ref-dup is a byte-identical
# duplicate of ab-ref run as its own arm. Whatever it differs from ab-ref by is
# the resolution of the whole comparison: any candidate effect smaller than that
# is not measurable here, no matter how many cycles are added. Without it, five
# more cycles yield a prettier number of unknown meaning.
#
# Pair this set with a high iteration count. p999 from 20000 samples is the
# 20th-highest value, a wobbly estimator; from 200000 it is the 200th, and at a
# 50 us sleep the extra samples cost 30 s per arm.
STAGES_PCTP999=(
    ab-ref
    pt-ref-dup
    pt-hp-os
    pt-hp-both
)

# A second, identical reference. Nothing is changed -- that is the entire
# purpose. Its distance from ab-ref measures what this comparison can resolve.
stage_pt-ref-dup() {
    stage_ab-ref
    STAGE_DESCRIPTION="negative control: identical to the reference, measures the noise floor"
}
