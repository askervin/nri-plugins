#!/bin/bash

# apps/sleep-accuracy.sh - process wakeup latency from nanosleep.
#
# The original and still the reference application: a single thread that
# sleeps and measures how late it is woken, reported as a latency
# distribution per requested sleep duration. Lower is better and the
# interesting part is the tail, which is what the whole ladder exists to
# move.
#
# The tool can set CPU frequencies, C-states, affinity and scheduling
# policy itself, and is deliberately run without -p, -c, -f and -i so
# that it configures none of them: everything that affects latency is
# left to the container runtime and the balloons policy, which is what
# the benchmark is trying to measure. Without -p the tool does not call
# sched_setscheduler() at all and reports the policy it inherited in the
# schedpol column, which is also this application's own witness that a
# realtime stage really was realtime.

app_sleep-accuracy_defaults() {
    APP_NAME=sleep-accuracy
    APP_LOG=sleep-accuracy.log
    # BENCH_JOB_NAME is what this was called before there were modules.
    APP_JOB_NAME="${SLEEP_ACCURACY_JOB_NAME:-${BENCH_JOB_NAME:-sleep-accuracy}}"
    APP_POD_SELECTOR="app=sleep-accuracy"
    APP_SUBJECT_POD="$APP_JOB_NAME"
    APP_SUBJECT_PROCESS=sleep-accuracy

    SLEEP_ACCURACY_IMAGE="${SLEEP_ACCURACY_IMAGE:-localhost/sleep-accuracy:latest}"
    BENCH_SLEEPS="${BENCH_SLEEPS:-1000,50000,1000000}"
    BENCH_BUSYS="${BENCH_BUSYS:-0}"
    BENCH_ITERATIONS="${BENCH_ITERATIONS:-20000}"
    BENCH_REPEATS="${BENCH_REPEATS:-3}"
    BENCH_BENCHMARKS="${BENCH_BENCHMARKS:-nanosleep}"
    # BENCH_ARGS is the name this override had before there were
    # application modules, and campaign scripts still set it. Keep it
    # working as an alias of SLEEP_ACCURACY_ARGS.
    SLEEP_ACCURACY_ARGS="${SLEEP_ACCURACY_ARGS:-${BENCH_ARGS:-}}"
    SLEEP_ACCURACY_ARGS="${SLEEP_ACCURACY_ARGS:--b $BENCH_BENCHMARKS -B $BENCH_BUSYS -s $BENCH_SLEEPS -I $BENCH_ITERATIONS -r $BENCH_REPEATS}"
    APP_ARGS="$SLEEP_ACCURACY_ARGS"
}

app_sleep-accuracy_manifest() {
    instantiate "$SCRIPT_DIR/apps/sleep-accuracy.yaml.in"
}

# app_sleep-accuracy_metrics LOGFILE - the tool's own output as canonical
# metric rows.
#
# The 23-field measurement line holds ten distribution columns; each
# becomes one row, keyed by the requested sleep duration as the operating
# point. Everything is nanoseconds and lower is better, so no conversion
# and no direction question arises here -- the two things that make the
# other applications more work.
app_sleep-accuracy_metrics() {
    local logfile="$1"
    [ -f "$logfile" ] || return 0
    awk '
        $1 == "nanosleep" || $1 == "networking" || $1 == "futex" {
            # A complete measurement line has 23 fields. Fields 14-23 are
            # the distribution, in the order named below; field 13 is the
            # requested sleep duration and field 2 the round.
            if (NF != 23) next
            n = split("min p5 p50 p80 p90 p95 p99 p999 max avg", m, " ")
            for (i = 1; i <= n; i++)
                printf "sleep-accuracy,%s,%s,%s,sleep_ns,%s,ns,lower,%s\n", \
                       $1, $2, $13, m[i], $(13 + i)
        }
    ' "$logfile"
}

# app_sleep-accuracy_witness STAGE_DIR LOGFILE - did these numbers come
# from the configuration the stage asked for?
#
# The tool reports the scheduling policy it inherited, so a stage that
# configured a scheduling class and measured schedpol 0 measured the
# baseline. This is the strongest witness any of the applications has,
# because it comes from inside the measured process itself.
app_sleep-accuracy_witness() {
    local logfile="$2"
    [ -f "$logfile" ] || return 0
    [ -n "${BENCH_SCHEDULINGCLASS:-}" ] || return 0
    local unconfigured
    unconfigured="$(awk '$1 == "nanosleep" && $6 == 0' "$logfile" | wc -l)"
    [ "$unconfigured" -gt 0 ] || return 0
    echo "$unconfigured measurements ran with scheduling policy 0," \
         "but the stage configured $BENCH_SCHEDULINGCLASS"
}
