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

# CSV_METRIC_COLUMNS - the canonical measurement record, which every
# application emits and which is the file the plot pipeline consumes.
#
# The three applications measure genuinely different things -- a wakeup
# latency distribution in nanoseconds, a cipher throughput in bytes per
# second, a request latency in milliseconds plus a request rate -- so no
# fixed set of wide columns can hold them all. These nine hold any of
# them:
#
#   app        which application produced the row
#   benchmark  its own sub-benchmark (nanosleep, aes-128-cbc, get)
#   round      repetition within the stage
#   op         the operating point, as a number
#   op_unit    what op counts (sleep_ns, block_bytes, clients)
#   metric     what is measured (p99, throughput, ns_per_op, rps)
#   unit       of value (ns, bytes_per_s, ops_per_s)
#   better     lower or higher, so a reader never has to guess
#   value      the number, in unit
#
# op and op_unit are two columns rather than one because a plot has to
# label its panel rows per application -- "sleep 1 us", "16 KB blocks",
# "50 clients" -- and a bare number cannot be labelled.
CSV_METRIC_COLUMNS=(
    app
    benchmark
    round
    op
    op_unit
    metric
    unit
    better
    value
)

# csv_header - print the CSV header line of latencies.csv.
csv_header() {
    local IFS=,
    echo "${CSV_CONFIG_COLUMNS[*]},${CSV_VERIFY_COLUMNS[*]},${CSV_MEASUREMENT_COLUMNS[*]}"
}

# csv_metrics_header - print the CSV header line of metrics.csv.
csv_metrics_header() {
    local IFS=,
    echo "${CSV_CONFIG_COLUMNS[*]},${CSV_VERIFY_COLUMNS[*]},${CSV_METRIC_COLUMNS[*]}"
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

# csv_append_metrics APP LOGFILE CONFIG_ROW CSVFILE [VERIFY_ROW] - append
# one canonical metric row per figure APP's log holds.
#
# The application's own app_<name>_metrics turns its output into the nine
# metric columns; this adds the configuration and verification prefix,
# exactly as csv_append_stage composes a latencies.csv row.
#
# Sets METRIC_ROWS_APPENDED rather than printing the count, so that
# CSVFILE can be /dev/stdout: a count on stdout would land in the CSV,
# and a count returned through stderr would be read back by any caller
# that redirects stderr.
METRIC_ROWS_APPENDED=0
csv_append_metrics() {
    local app="$1" logfile="$2" config_row="$3" csvfile="$4"
    local verify_row="${5:-$(csv_verify_row_unknown)}"
    METRIC_ROWS_APPENDED=0
    [ -f "$logfile" ] || return 0
    declare -F "app_${app}_metrics" >/dev/null || return 0
    local tmp
    tmp="$(mktemp)"
    "app_${app}_metrics" "$logfile" |
        awk -v prefix="$config_row,$verify_row" \
            'NF > 0 { print prefix "," $0 }' > "$tmp"
    METRIC_ROWS_APPENDED="$(grep -c . "$tmp" 2>/dev/null || true)"
    METRIC_ROWS_APPENDED="${METRIC_ROWS_APPENDED:-0}"
    cat "$tmp" >> "$csvfile"
    rm -f "$tmp"
    return 0
}

# csv_metrics_summary CSVFILE - a per-stage table of what each
# application measured, for a look at the results without a spreadsheet.
#
# One line per stage, application, operating point and metric, with the
# median over rounds rather than the mean: a single slow round should not
# move the figure that gets read first.
csv_metrics_summary() {
    local csvfile="$1"
    [ -f "$csvfile" ] || return 0
    printf '%-2s %-24s %-14s %16s %-14s %14s %-12s %s\n' \
        "#" "stage" "app" "op" "metric" "median" "unit" "better"
    # Three plain steps rather than one awk holding everything: sorting
    # and grouping are what sort(1) is for, and the alternative needs
    # arrays of arrays and asort(), which are gawk extensions the awk on
    # a stock Ubuntu node does not have.
    awk -F, '
        NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i; next }
        {
            printf "%03d|%s|%s|%s %s|%s|%s|%s\t%s\n", \
                $col["stage_index"], $col["stage"], $col["app"], \
                $col["op"], $col["op_unit"], $col["metric"], \
                $col["unit"], $col["better"], $col["value"] + 0
        }
    ' "$csvfile" |
    sort -t"$(printf '\t')" -k1,1 -k2,2g |
    awk -F"$(printf '\t')" '
        function flush() {
            if (nk == 0) return
            med = (nk % 2) ? v[int((nk + 1) / 2)] \
                           : (v[nk / 2] + v[nk / 2 + 1]) / 2
            split(key, f, "|")
            printf "%-2d %-24s %-14s %16s %-14s %14.0f %-12s %s\n", \
                   f[1] + 0, f[2], f[3], f[4], f[5], med, f[6], f[7]
        }
        $1 != key { flush(); key = $1; nk = 0 }
        { v[++nk] = $2 + 0 }
        END { flush() }
    '
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

# stage_verify_row STAGE_DIR [APP] - the verification columns recorded
# for this stage, per application where the harness recorded them that
# way, or for the stage as a whole where it did not.
#
# Stage directories written before there was more than one application
# have a single verify-row.csv, and ones written before the state checks
# existed have none at all; both rebuild without failing and without
# silently shifting the columns, the second with zeros meaning "not
# verified".
stage_verify_row() {
    local stage_dir="$1" app="${2:-}"
    if [ -n "$app" ] && [ -f "$stage_dir/$app-verify-row.csv" ]; then
        cat "$stage_dir/$app-verify-row.csv"
    elif [ -f "$stage_dir/verify-row.csv" ]; then
        cat "$stage_dir/verify-row.csv"
    else
        csv_verify_row_unknown
    fi
}

# Stand-alone mode: rebuild a CSV from a results directory, without
# re-running anything. Each stage directory keeps the configuration row it
# was run with and the applications' raw logs, so both CSVs are
# reproducible from stored logs -- never the other way round.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -u
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    want=latencies
    while getopts "mh" opt; do
        case "$opt" in
            m) want=metrics ;;
            *) echo "Usage: report.sh [-m] RESULTS_DIR > latencies.csv" >&2
               echo "  -m   write the canonical metrics.csv instead" >&2
               exit 1 ;;
        esac
    done
    shift $((OPTIND - 1))

    results_dir="${1:-}"
    if [ -z "$results_dir" ] || [ ! -d "$results_dir" ]; then
        echo "Usage: report.sh [-m] RESULTS_DIR > latencies.csv" >&2
        exit 1
    fi

    if [ "$want" = metrics ]; then
        # The metric emitters live in the application modules.
        # shellcheck disable=SC1091
        source "$SCRIPT_DIR/apps.sh"
        csv_metrics_header
        for stage_dir in "$results_dir"/[0-9]*; do
            [ -d "$stage_dir" ] || continue
            [ -f "$stage_dir/config-row.csv" ] || continue
            config_row="$(cat "$stage_dir/config-row.csv")"
            for app in "${APPS[@]}"; do
                [ -f "$stage_dir/$app.log" ] || continue
                csv_append_metrics "$app" "$stage_dir/$app.log" \
                    "$config_row" /dev/stdout \
                    "$(stage_verify_row "$stage_dir" "$app")"
            done
        done
        exit 0
    fi

    csv_header
    for stage_dir in "$results_dir"/[0-9]*; do
        [ -d "$stage_dir" ] || continue
        if [ -f "$stage_dir/config-row.csv" ] && \
           [ -f "$stage_dir/sleep-accuracy.log" ]; then
            csv_append_stage "$stage_dir/sleep-accuracy.log" \
                             "$(cat "$stage_dir/config-row.csv")" /dev/stdout \
                             "$(stage_verify_row "$stage_dir" sleep-accuracy)"
        fi
    done
fi
