#!/bin/bash

# report.sh - turn sleep-accuracy output into a CSV of tail latencies
# and the configuration options that produced them.
#
# Sourced by run-benchmark.sh, but also usable stand-alone to rebuild
# the CSV from stored stage logs:
#
#   ./report.sh RESULTS_DIR > latencies.csv
#
# The CSV has one row per sleep-accuracy measurement line. Latency
# columns come from the tool, configuration columns describe the
# balloons configuration that was in effect. In configuration columns
# 0 means "this option was not configured", and 1 (or the actual value,
# where a value is more informative than a flag) means it was in use.

# CSV_CONFIG_COLUMNS - configuration columns, in order.
CSV_CONFIG_COLUMNS=(
    stage_index
    stage
    balloons_installed
    own_balloon
    dedicated_cpus
    bln_min_cpus
    bln_max_cpus
    bln_min_balloons
    sched_class
    sched_policy
    sched_priority
    irq_mode
    irq_claim
    other_irq_mode
    disabled_cstates
    cpu_min_freq
    cpu_max_freq
    turbo_priority
    other_turbo_priority
    turbo_domain
    pct_priority
    idle_cpu_class
    noise_replicas
    noise_workload
    pin_cpu
    pin_memory
)

# CSV_VERIFY_COLUMNS - what the node was actually found to be in,
# as opposed to what the stage asked for.
#
# The configuration columns above say what was requested. These say what
# the harness could verify afterwards, which is not the same thing: a
# stage can request a C-state be disabled, have the policy report
# success, and still run on a CPU where it is enabled. Keeping both in
# the same row is what lets an analysis tell "configured" from
# "configured and confirmed".
#
#   bench_cpus     effective cpuset of the benchmark container, read
#                  from its cgroup while it was running, with commas
#                  replaced by + so the field stays one CSV column.
#                  0 when it could not be determined.
#   state_checks   ok, or a +-joined list of the state checks that
#                  failed. See check_stage_configured_state.
#                  0 for rows collected before this check existed.
CSV_VERIFY_COLUMNS=(
    bench_cpus
    state_checks
)

# CSV_MEASUREMENT_COLUMNS - columns from the sleep-accuracy output.
CSV_MEASUREMENT_COLUMNS=(
    benchmark
    round
    cpu0
    cpu1
    cpumigr_ns
    schedpol
    schedprio
    idlemin
    idlemax
    freqmin
    freqmax
    busy_ns
    sleep_ns
    min
    p5
    p50
    p80
    p90
    p95
    p99
    p999
    max
    avg
)

# csv_header - print the CSV header line.
csv_header() {
    local IFS=,
    echo "${CSV_CONFIG_COLUMNS[*]},${CSV_VERIFY_COLUMNS[*]},${CSV_MEASUREMENT_COLUMNS[*]}"
}

# csv_verify_row_unknown - a verification row of all zeros, for a stage
# whose logs predate these columns or where the checks could not run.
csv_verify_row_unknown() {
    local row=() i
    for ((i = 0; i < ${#CSV_VERIFY_COLUMNS[@]}; i++)); do
        row+=(0)
    done
    local IFS=,
    echo "${row[*]}"
}

# csv_flag VALUE - normalise a configuration value for the CSV.
# Empty, unset and "false" all become 0. "true" becomes 1. Anything
# else is passed through, because the actual value (a frequency, a
# priority, a class name) says more than a bare 1.
csv_flag() {
    local value="${1:-}"
    case "$value" in
        ""|false) echo 0 ;;
        true)     echo 1 ;;
        *)        echo "$value" ;;
    esac
}

# csv_config_row - print the configuration columns for the current
# stage, reading the same environment variables the config generator
# uses. Expects STAGE_INDEX and STAGE_NAME to be set.
csv_config_row() {
    local balloons_installed=1
    [ -n "${STAGE_NO_BALLOONS:-}" ] && balloons_installed=0

    local own_balloon=1
    [ -n "${BENCH_BTYPE_SKIP:-}" ] && own_balloon=0
    [ "$balloons_installed" = 0 ] && own_balloon=0

    # Fields that only exist when a cpuClass is attached to the
    # benchmark balloon.
    local cstates="${CPUCLASS_BENCH_DISABLEDCSTATES:-}"
    # Keep the C-state names, but make the field CSV-safe.
    cstates="${cstates//,/+}"

    # irqClaim is a list of patterns that may contain commas and spaces.
    # Join the items with + so that the field stays a single CSV column.
    local irq_claim="${BENCH_IRQCLAIM:-}"
    irq_claim="${irq_claim//,/+}"
    irq_claim="${irq_claim// /_}"

    # pinCPU and pinMemory default to on in the generated configuration,
    # but nothing pins anything when no policy is installed.
    local pin_cpu="${PINCPU:-true}" pin_memory="${PINMEMORY:-false}"
    if [ "$balloons_installed" = 0 ]; then
        pin_cpu=false
        pin_memory=false
    fi

    local row=(
        "$STAGE_INDEX"
        "$STAGE_NAME"
        "$balloons_installed"
        "$own_balloon"
        "$(csv_flag "${BENCH_PREFERNEWBALLOONS:-}")"
        "$(csv_flag "${BENCH_MINCPUS:-}")"
        "$(csv_flag "${BENCH_MAXCPUS:-}")"
        "$(csv_flag "${BENCH_MINBALLOONS:-}")"
        "$(csv_flag "${BENCH_SCHEDULINGCLASS:-}")"
        "$(csv_flag "${SCHEDCLASS_POLICY:-}")"
        "$(csv_flag "${SCHEDCLASS_PRIORITY:-}")"
        "$(csv_flag "${BENCH_IRQMODE:-}")"
        "$(csv_flag "$irq_claim")"
        "$(csv_flag "${NOISE_IRQMODE:-}")"
        "$(csv_flag "$cstates")"
        "$(csv_flag "${CPUCLASS_BENCH_MINFREQ:-}")"
        "$(csv_flag "${CPUCLASS_BENCH_MAXFREQ:-}")"
        "$(csv_flag "${CPUCLASS_BENCH_TURBOPRIORITY:-}")"
        "$(csv_flag "${CPUCLASS_OTHER_TURBOPRIORITY:-}")"
        "$(csv_flag "${TURBODOMAIN:-}")"
        "$(csv_flag "${CPUCLASS_BENCH_PCTPRIORITY:-}")"
        "$(csv_flag "${IDLECPUCLASS:-}")"
        "$(csv_flag "${NOISE_REPLICAS:-}")"
        "$(csv_flag "${NOISE_WORKLOAD:-}")"
        "$(csv_flag "$pin_cpu")"
        "$(csv_flag "$pin_memory")"
    )
    local IFS=,
    echo "${row[*]}"
}

# csv_append_stage LOGFILE CONFIG_ROW CSVFILE [VERIFY_ROW] - append one
# CSV row per measurement line found in LOGFILE.
#
# sleep-accuracy prints a header line followed by one line per
# measurement. Lines that do not start with a known benchmark name are
# ignored, which skips the header and any container noise on stdout.
csv_append_stage() {
    local logfile="$1" config_row="$2" csvfile="$3"
    local verify_row="${4:-$(csv_verify_row_unknown)}"
    [ -f "$logfile" ] || return 0
    awk -v prefix="$config_row,$verify_row" '
        $1 == "nanosleep" || $1 == "networking" || $1 == "futex" {
            # A complete measurement line has 23 fields.
            if (NF != 23) next
            line = $1
            for (i = 2; i <= NF; i++) line = line "," $i
            print prefix "," line
        }
    ' "$logfile" >> "$csvfile"
}

# csv_summary CSVFILE - print a short human-readable table of the tail
# latencies per stage, averaged over rounds, for a quick look at the
# results without a spreadsheet.
csv_summary() {
    local csvfile="$1"
    [ -f "$csvfile" ] || return 0
    awk -F, '
        NR == 1 {
            for (i = 1; i <= NF; i++) col[$i] = i
            next
        }
        {
            key = $col["stage_index"] " " $col["stage"] " " $col["sleep_ns"]
            n[key]++
            p50[key] += $col["p50"]
            p90[key] += $col["p90"]
            p99[key] += $col["p99"]
            p999[key] += $col["p999"]
            if (max[key] == "" || $col["max"] + 0 > max[key] + 0) max[key] = $col["max"]
        }
        END {
            printf "%-2s %-24s %10s %9s %9s %9s %9s %9s\n", \
                   "#", "stage", "sleep_ns", "p50", "p90", "p99", "p999", "max"
            n_keys = 0
            for (key in n) keys[++n_keys] = key
            # Sort by stage index, then requested sleep duration.
            for (i = 1; i <= n_keys; i++)
                for (j = i + 1; j <= n_keys; j++) {
                    split(keys[i], a, " "); split(keys[j], b, " ")
                    if (a[1] + 0 > b[1] + 0 || \
                        (a[1] + 0 == b[1] + 0 && a[3] + 0 > b[3] + 0)) {
                        tmp = keys[i]; keys[i] = keys[j]; keys[j] = tmp
                    }
                }
            for (i = 1; i <= n_keys; i++) {
                key = keys[i]
                split(key, f, " ")
                printf "%-2s %-24s %10s %9d %9d %9d %9d %9s\n", \
                       f[1], f[2], f[3], \
                       p50[key] / n[key], p90[key] / n[key], \
                       p99[key] / n[key], p999[key] / n[key], max[key]
            }
        }
    ' "$csvfile"
}

# Stand-alone mode: rebuild the CSV from a results directory.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -u
    results_dir="${1:-}"
    if [ -z "$results_dir" ] || [ ! -d "$results_dir" ]; then
        echo "Usage: report.sh RESULTS_DIR > latencies.csv" >&2
        exit 1
    fi
    csv_header
    for stage_dir in "$results_dir"/[0-9]*; do
        [ -d "$stage_dir" ] || continue
        # Each stage directory stores the configuration row it was run
        # with, so the CSV can be rebuilt without re-deriving it.
        if [ -f "$stage_dir/config-row.csv" ] && \
           [ -f "$stage_dir/sleep-accuracy.log" ]; then
            # verify-row.csv only exists for stages collected by a
            # harness that has the state checks. Older stage directories
            # rebuild with zeros, meaning "not verified", rather than
            # failing or silently shifting the columns.
            local verify_row
            if [ -f "$stage_dir/verify-row.csv" ]; then
                verify_row="$(cat "$stage_dir/verify-row.csv")"
            else
                verify_row="$(csv_verify_row_unknown)"
            fi
            csv_append_stage "$stage_dir/sleep-accuracy.log" \
                             "$(cat "$stage_dir/config-row.csv")" /dev/stdout \
                             "$verify_row"
        fi
    done
fi
