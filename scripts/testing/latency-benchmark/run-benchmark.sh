#!/bin/bash

# run-benchmark.sh - benchmark how much the NRI balloons policy helps
# latency-sensitive and realtime workloads.
#
# Runs the sleep-accuracy tool in a container through a ladder of
# balloons policy configurations, from an absolute baseline with no
# policy at all to priority core turbo, and collects process wakeup
# latencies with an emphasis on tail latencies (P90, P99, P999).
#
# For each stage the script
#   1. resets the node to a known state (see reset-node.sh),
#   2. generates the BalloonsPolicy for the stage (gen-balloons-config.sh),
#   3. installs the balloons policy with that configuration,
#   4. starts the stress-ng background workload,
#   5. runs sleep-accuracy as a Job and collects its output,
#   6. gathers logs and appends the results to a CSV.
#
# The benchmark tool itself never configures CPU frequencies, C-states
# or scheduling policies: it is run without the options that would do
# that, so whatever the container runtime and the balloons policy set is
# what gets measured.
#
# Run on the Kubernetes node under test, as a user who can sudo:
#
#   ./build-images.sh          # once, to create the container images
#   ./run-benchmark.sh         # run all stages
#
# See -h for options.

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/stages.sh"
source "$SCRIPT_DIR/report.sh"

###
### Configuration
###

# CHART - balloons helm chart. Defaults to the chart in this checkout
# if run from the repository, otherwise the published chart.
CHART="${CHART:-}"
HELM_RELEASE="${HELM_RELEASE:-nri-resource-policy-balloons}"
HELM_NAMESPACE="${HELM_NAMESPACE:-kube-system}"
HELM_REPO_NAME="${HELM_REPO_NAME:-nri-plugins}"
HELM_REPO_URL="${HELM_REPO_URL:-https://containers.github.io/nri-plugins}"
PLUGIN_IMAGE="${PLUGIN_IMAGE:-}"

BENCH_NAMESPACE="${BENCH_NAMESPACE:-latency-benchmark}"
NODE_NAME="${NODE_NAME:-$(hostname)}"

SLEEP_ACCURACY_IMAGE="${SLEEP_ACCURACY_IMAGE:-localhost/sleep-accuracy:latest}"
STRESS_NG_IMAGE="${STRESS_NG_IMAGE:-localhost/stress-ng:latest}"

# BENCH_ARGS - sleep-accuracy arguments.
#
# No -p, -c, -f or -i: scheduling policy and priority, CPU affinity,
# frequencies and idle states are all left entirely to the container
# runtime and the balloons policy. Without those options the tool
# configures none of them, and reports the effective scheduling policy
# and priority it inherited in the schedpol and schedprio columns.
BENCH_SLEEPS="${BENCH_SLEEPS:-1000,50000,1000000}"
BENCH_BUSYS="${BENCH_BUSYS:-0}"
BENCH_ITERATIONS="${BENCH_ITERATIONS:-20000}"
BENCH_REPEATS="${BENCH_REPEATS:-3}"
BENCH_BENCHMARKS="${BENCH_BENCHMARKS:-nanosleep}"
BENCH_ARGS="${BENCH_ARGS:--b $BENCH_BENCHMARKS -B $BENCH_BUSYS -s $BENCH_SLEEPS -I $BENCH_ITERATIONS -r $BENCH_REPEATS}"

# Resources requested by the benchmark container. The CPU request must
# match the balloon size wanted for it: balloons sizes dynamic balloons
# from container CPU requests.
BENCH_CPUS="${BENCH_CPUS:-2}"
BENCH_CPU_REQUEST="${BENCH_CPU_REQUEST:-$BENCH_CPUS}"
BENCH_MEM_REQUEST="${BENCH_MEM_REQUEST:-256Mi}"
BENCH_LABEL_KEY="${BENCH_LABEL_KEY:-latency}"
BENCH_LABEL_VALUE="${BENCH_LABEL_VALUE:-critical}"
BENCH_JOB_NAME="${BENCH_JOB_NAME:-sleep-accuracy}"
BENCH_TIMEOUT="${BENCH_TIMEOUT:-1800}"

# NOISE_WORKLOAD - what the background containers stress:
#   cpu    busy loops on the CPU
#   mem    memory bandwidth
#   both   CPU and memory bandwidth
#   vector wide vector and matrix instructions, which draw enough
#          current to pull the whole frequency domain down
#   none   no background workload at all
NOISE_WORKLOAD="${NOISE_WORKLOAD:-both}"
NOISE_REPLICAS="${NOISE_REPLICAS:-}"
NOISE_CPU_REQUEST="${NOISE_CPU_REQUEST:-1}"
NOISE_MEM_REQUEST="${NOISE_MEM_REQUEST:-512Mi}"
NOISE_LABEL_KEY="${NOISE_LABEL_KEY:-latency}"
NOISE_LABEL_VALUE="${NOISE_LABEL_VALUE:-noise}"
NOISE_DEPLOYMENT_NAME="${NOISE_DEPLOYMENT_NAME:-stress-ng-noise}"
NOISE_SETTLE_SECONDS="${NOISE_SETTLE_SECONDS:-15}"

# STAGE_RETRIES - how many times to run a stage that turns out to have
# measured a system the policy had not configured. Such a run is a lost
# measurement rather than a result, so repeating it is the only way to
# get the stage's data at all. 1 disables retrying.
STAGE_RETRIES="${STAGE_RETRIES:-3}"

# RESULTS_DIR - where logs and the CSV go.
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results/$(date +%Y%m%d-%H%M%S)}"

# ALLOW_PCT - give the plugin the privileges it needs for PCT.
ALLOW_PCT="${ALLOW_PCT:-}"

# PATCH_RUNTIME_CONFIG - non-empty: let the chart's patch-runtime init
# container edit the runtime configuration to enable NRI.
#
# Off by default, because the runtimes this benchmark targets enable NRI
# themselves: containerd has done so since 2.0. Patching an already
# working runtime gains nothing and can lose everything, since the init
# container rewrites /etc/containerd/config.toml and restarts containerd.
# On a config that is entirely comments, as shipped by the containerd.io
# packages, the init container also panics on a nil map and the plugin
# never starts. check_nri_enabled turns this on by itself if it finds a
# runtime where NRI really is off.
PATCH_RUNTIME_CONFIG="${PATCH_RUNTIME_CONFIG:-}"

# OVERRIDE_* - simulated sysfs and SST for the plugin, as used by the
# e2e tests: OVERRIDE_SYS_CSTATES, OVERRIDE_SYS_CPUFREQ, OVERRIDE_SST,
# OVERRIDE_SST_STATE_DIR. Any variable whose name starts with OVERRIDE_
# is forwarded to the plugin container. Set these only to verify that
# the harness and the policy behave correctly on a virtual machine that
# has no real cpufreq, cpuidle or SST support. Latencies measured
# against a simulated platform say nothing about real hardware.
#
# overridden_vars - names of the OVERRIDE_* variables set in the
# environment, in a stable order.
overridden_vars() {
    compgen -v | grep '^OVERRIDE_' | sort | while read -r name; do
        [ -n "${!name:-}" ] && echo "$name"
    done
}

# check_nri_enabled - make sure the runtime offers NRI to the plugin.
#
# The plugin can only do its work if the runtime talks NRI, so NRI being
# off has to be dealt with before the first stage rather than showing up
# as a plugin that installs but never pins anything. Enabling it is left
# to the chart's init container, which is only requested when NRI really
# is off: that container rewrites the runtime configuration and restarts
# containerd, which is not something to do to a node already working.
#
# Ask containerd what it resolved rather than looking for the socket:
# /run/nri is mode 0700 root:root, so an unprivileged test never sees the
# socket even when it is there. The dumped configuration also covers the
# defaults, and containerd has enabled NRI by default since 2.0.
check_nri_enabled() {
    if [ -n "$PATCH_RUNTIME_CONFIG" ]; then
        info "Runtime configuration patching requested (PATCH_RUNTIME_CONFIG)."
        return 0
    fi
    local dump
    dump="$($SUDO containerd config dump 2>/dev/null)"
    if [ -n "$dump" ]; then
        # The nri section carries "disable = true|false". Read that flag
        # from the section rather than grepping the whole dump, where
        # other plugins have disable flags of their own.
        local disabled
        disabled="$(printf '%s\n' "$dump" | awk '
            /io\.containerd\.nri\.v1\.nri/ { inside = 1; next }
            inside && /^ *\[/            { exit }
            inside && /disable/          { print $3; exit }')"
        case "$disabled" in
            false)
                info "containerd reports NRI enabled, no runtime patching needed."
                return 0
                ;;
            true)
                warn "containerd reports NRI disabled, asking the chart to enable it;"
                warn "this rewrites the runtime configuration and restarts containerd"
                PATCH_RUNTIME_CONFIG=1
                return 0
                ;;
        esac
    fi
    # Neither the dump nor the flag was readable. Say so instead of
    # silently patching a runtime that may well be fine.
    warn "cannot tell whether the runtime has NRI enabled;"
    warn "assuming it does, set PATCH_RUNTIME_CONFIG=1 if the plugin does not start"
}

# check_node_capabilities - warn about tuning mechanisms this node does
# not have. Without these, the corresponding stages still run, but they
# cannot change anything, so their latencies are not meaningful.
check_node_capabilities() {
    local missing=()
    [ -d /sys/devices/system/cpu/cpu0/cpufreq ] || missing+=("cpufreq (CPU frequency scaling)")
    [ -d /sys/devices/system/cpu/cpu0/cpuidle ] || missing+=("cpuidle (C-states)")
    [ -e /dev/isst_interface ] || missing+=("SST/PCT (/dev/isst_interface)")
    [ ${#missing[@]} = 0 ] && return 0
    warn "this node does not support:"
    printf '  - %s\n' "${missing[@]}" >&2
    warn "stages that rely on them cannot affect the hardware, so their"
    warn "latency numbers are not comparable to a real deployment."
    if [ -n "$(overridden_vars)" ]; then
        warn "OVERRIDE_* is set: the policy sees a SIMULATED platform:"
        printf '  - %s\n' $(overridden_vars) >&2
        warn "Use this only to validate the harness, never to draw"
        warn "conclusions about latency."
    fi
}

usage() {
    cat <<EOF
Usage: run-benchmark.sh [options] [stage ...]

Benchmarks process wakeup latency under a ladder of NRI balloons policy
configurations. With no stage arguments, runs all stages in order.

Stages:
$(printf '  %s\n' "${STAGES[@]}")

Options:
  -l          list stages with descriptions and exit
  -d          dry run: generate and print configurations, run nothing
  -k          keep the last stage's policy and workloads running at exit
  -h          show this help

Key environment variables:
  RESULTS_DIR          results directory (default: results/<timestamp>)
  BENCH_CPUS           CPUs for the benchmark balloon (default: $BENCH_CPUS)
  BENCH_ITERATIONS     sleep-accuracy iterations (default: $BENCH_ITERATIONS)
  BENCH_REPEATS        sleep-accuracy repeats (default: $BENCH_REPEATS)
  BENCH_SLEEPS         requested sleep durations [ns] (default: $BENCH_SLEEPS)
  BENCH_ARGS           full sleep-accuracy argument override
  NOISE_WORKLOAD       cpu|mem|both|vector|none (default: $NOISE_WORKLOAD)
  NOISE_REPLICAS       background containers (default: CPUs/2)
  CHART                balloons helm chart path or name
  PLUGIN_IMAGE         override plugin image, as name:tag
  ALLOW_PCT            non-empty: helm --set allowPCT=true
  PATCH_RUNTIME_CONFIG non-empty: let the chart rewrite the runtime
                       configuration to enable NRI (default: only when
                       the runtime reports NRI disabled)
  DISABLED_CSTATES     C-states to disable (default: C1E,C6)
  STAGE_RETRIES        attempts for a stage that measured an
                       unconfigured system (default: $STAGE_RETRIES, 1 disables)
  OVERRIDE_*           simulated platform for the plugin, for validating
                       this harness on a VM only (see comments in script)

Examples:
  ./run-benchmark.sh -l
  ./run-benchmark.sh -d
  ./run-benchmark.sh baseline-no-balloons dedicated-cpus
  BENCH_ITERATIONS=100000 BENCH_REPEATS=5 ./run-benchmark.sh
EOF
}

dry_run=0
keep_last=0
list_stages=0
while getopts "ldkh" opt; do
    case "$opt" in
        l) list_stages=1 ;;
        d) dry_run=1 ;;
        k) keep_last=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

error() { echo "run-benchmark.sh: error: $*" >&2; exit 1; }
warn()  { echo "run-benchmark.sh: warning: $*" >&2; }
info()  { echo "### $*"; }

# online_cpus_list - the node's online CPUs, as a cpulist ("0-3,8-11").
# online_cpus       - the same set, one CPU number per line.
#
# From sysfs, not from nproc: nproc reports how many CPUs the calling
# process may run on, so under a restricted affinity it undercounts, and
# it says nothing about which CPUs those are. "0-$((nproc - 1))"
# additionally assumes the online CPUs are contiguous and start at 0,
# which offlining any CPU makes false.
online_cpus_list() {
    local list=""
    if [ -r /sys/devices/system/cpu/online ]; then
        read -r list < /sys/devices/system/cpu/online
    fi
    # A uniprocessor kernel omits the file entirely; anything else means
    # sysfs is not mounted, and CPU 0 is the only safe assumption left.
    echo "${list:-0}"
}

online_cpus() {
    local range lo hi
    local IFS=,
    for range in $(online_cpus_list); do
        case "$range" in
            *-*) lo="${range%%-*}"; hi="${range##*-}"
                 while [ "$lo" -le "$hi" ]; do echo "$lo"; lo=$((lo + 1)); done ;;
            *)   echo "$range" ;;
        esac
    done
}

if [ "$list_stages" = 1 ]; then
    for stage in "${STAGES[@]}"; do
        stage_reset_vars
        "stage_$stage"
        printf '%-24s %s\n' "$stage" "$STAGE_DESCRIPTION"
    done
    exit 0
fi

# Stages to run: the command line, or all of them.
if [ $# -gt 0 ]; then
    run_stages=("$@")
    for stage in "${run_stages[@]}"; do
        declare -F "stage_$stage" >/dev/null ||
            error "unknown stage: $stage (see -l)"
    done
else
    run_stages=("${STAGES[@]}")
fi

###
### Preflight
###

for tool in kubectl helm awk; do
    command -v "$tool" >/dev/null || error "$tool not found"
done

# The reset step needs root for sysfs, IRQs and sysctl.
SUDO=""
if [ "$(id -u)" != 0 ]; then
    sudo -n true 2>/dev/null || error "passwordless sudo is required"
    SUDO="sudo -E"
fi

# Locate the helm chart. Prefer this checkout, so the benchmark tests
# the plugin version being developed rather than a released one.
if [ -z "$CHART" ]; then
    repo_chart="$SCRIPT_DIR/../../../deployment/helm/balloons"
    if [ -d "$repo_chart" ]; then
        CHART="$(cd "$repo_chart" && pwd)"
    else
        info "Chart not found in checkout, using helm repository $HELM_REPO_URL"
        helm repo add "$HELM_REPO_NAME" "$HELM_REPO_URL" >/dev/null 2>&1
        helm repo update "$HELM_REPO_NAME" >/dev/null 2>&1
        CHART="$HELM_REPO_NAME/nri-resource-policy-balloons"
    fi
fi

# The chart installs the BalloonsPolicy CRD, and the CRD rejects fields
# it does not know about. A released chart therefore cannot run stages
# that use options added after that release: the configuration is
# refused outright. Check the fields the stages need up front instead of
# letting a stage fail mid-run with a page of decoding errors.
crd_file=""
if [ -d "$CHART" ]; then
    crd_file="$CHART/crds/config.nri_balloonspolicies.yaml"
elif helm show crds "$CHART" > /dev/null 2>&1; then
    crd_file="$(mktemp)"
    helm show crds "$CHART" > "$crd_file" 2>/dev/null
fi
if [ -n "$crd_file" ] && [ -s "$crd_file" ]; then
    for field in irqMode irqClaim pctPriority turboPriority; do
        grep -q "^ *${field}:" "$crd_file" ||
            warn "the chart's BalloonsPolicy CRD does not support $field," \
                 "stages using it will fail: set CHART to a checkout of" \
                 "deployment/helm/balloons"
    done
fi

# Default the noise to half the node's CPUs, so it competes for CPU time
# without completely starving the node.
node_cpus="$(online_cpus | wc -l)"
if [ -z "$NOISE_REPLICAS" ]; then
    NOISE_REPLICAS=$(( node_cpus / 2 ))
    [ "$NOISE_REPLICAS" -lt 1 ] && NOISE_REPLICAS=1
fi

# NOISE_ARGS - stress-ng arguments for the selected workload.
#
# --cpu spins on integer/float ALU work, competing for core resources.
# --vm allocates and touches memory, competing for memory bandwidth and
# cache. Both are given a timeout far beyond the benchmark duration and
# restarted by the Deployment if they ever exit.
#
# vector is a different kind of neighbour: wide vector instructions draw
# enough current that the core cannot hold its frequency, and the
# licence-based downclocking that follows reaches every core in the
# frequency domain, including one running nothing but a latency-sensitive
# task. That makes it the interesting case for a policy whose job is to
# protect such a task, and the one thing a CPU and memory bandwidth load
# does not exercise.
#
# vecwide, not the other vector stressors: which of them actually costs
# frequency is a property of the silicon and of what the stress-ng build
# was compiled to emit, and it has to be measured rather than assumed. On
# a Xeon 6776P (Granite Rapids), all at one instance per CPU and ~99.8%
# busy, the busy frequency was 2198 MHz for vecwide, 2300 for vecfp, 2396
# for matrix-3d, and 2444 for vecmath, fma, matrix and the cpu+vm load
# above -- so vecmath and matrix downclock no more than plain integer
# work, and only vecwide is clearly a licence-limited load. Mixing
# anything into vecwide only raised the frequency again (2223 MHz at
# vecwide:vecfp 3:1), so the default is vecwide alone.
#
# Confirm this on any new part before drawing conclusions from a vector
# campaign: turbostat's Bzy_MHz under each load, compared at equal Busy%,
# is what settles it. If the frequency does not move, the campaign
# measured a differently-shaped CPU load and says nothing about
# downclocking.
case "$NOISE_WORKLOAD" in
    cpu)  NOISE_ARGS="${NOISE_ARGS:---cpu 1 --timeout 0}" ;;
    mem)  NOISE_ARGS="${NOISE_ARGS:---vm 1 --vm-bytes 256M --vm-keep --timeout 0}" ;;
    both) NOISE_ARGS="${NOISE_ARGS:---cpu 1 --vm 1 --vm-bytes 256M --vm-keep --timeout 0}" ;;
    vector)
          NOISE_ARGS="${NOISE_ARGS:---vecwide 1 --timeout 0}" ;;
    none) NOISE_ARGS="" ;;
    *)    error "invalid NOISE_WORKLOAD: $NOISE_WORKLOAD" \
                "(cpu|mem|both|vector|none)" ;;
esac

export NODE_NAME BENCH_NAMESPACE
export SLEEP_ACCURACY_IMAGE STRESS_NG_IMAGE
export BENCH_ARGS BENCH_CPU_REQUEST BENCH_MEM_REQUEST BENCH_JOB_NAME
export BENCH_LABEL_KEY BENCH_LABEL_VALUE
export NOISE_ARGS NOISE_REPLICAS NOISE_CPU_REQUEST NOISE_MEM_REQUEST
export NOISE_DEPLOYMENT_NAME NOISE_LABEL_KEY NOISE_LABEL_VALUE

mkdir -p "$RESULTS_DIR"
CSV_FILE="$RESULTS_DIR/latencies.csv"
RUN_LOG="$RESULTS_DIR/run.log"

# instantiate TEMPLATE - expand a yaml template the same way the e2e
# tests do, so templates can use ${VAR:-default} and $(command).
instantiate() {
    local template="$1"
    [ -f "$template" ] || error "template not found: $template"
    eval "echo -e \"$(<"$template")\"" | grep -v '^ *$'
}

# NODE_SPEED_MIN_MHZ - the frequency a single busy CPU must reach after a
# reset for the node to be considered usable.
#
# Defaults to the node's own base frequency where cpufreq reports one, so
# that the threshold means "this node can still reach the speed it is
# specified for" rather than an absolute number that would be wrong on
# the next part. A clamp deep enough to matter takes the achieved
# frequency well below base -- 500 MHz against a base of 2300 on the node
# this was found on -- while a healthy node under a single-threaded load
# reaches base or turbo. 0 disables the check.
if [ -z "${NODE_SPEED_MIN_MHZ:-}" ]; then
    base_khz="$(cat /sys/devices/system/cpu/cpu0/cpufreq/base_frequency \
                2>/dev/null)"
    if [ -n "$base_khz" ] && [ "$base_khz" -gt 0 ] 2>/dev/null; then
        # Just under base: HWP may sit a bin below it even when healthy.
        NODE_SPEED_MIN_MHZ=$(( base_khz / 1000 * 9 / 10 ))
    else
        NODE_SPEED_MIN_MHZ=1000
    fi
fi

# check_node_speed - is this node running at a sane frequency at all?
#
# Left-over SST-CP CLOS limits from an earlier PCT stage can clamp every
# CPU to the hardware minimum -- 500 MHz of a 4600 MHz part on the machine
# this was found on -- while cpufreq, cpuidle, RAPL and thermal state all
# look normal and HWP still reports the full range as requested. The
# policy programs its CLOSes with max=0 meaning "no limit", but the
# hardware reads 0 as zero. Two campaign cycles were measured on such a
# node before anyone noticed, because latency numbers from a uniformly
# 9x-slow machine still look like plausible latency numbers.
#
# IA32_PERF_STATUS bits 15:8 hold the ratio the core is actually running
# at, in 100 MHz units. That was the only reading that told the truth:
# /proc/cpuinfo reported a nominal 2300 MHz regardless, and turbostat's
# Bzy_MHz agreed with the clamp but is not always installed. The MSR has
# to be sampled while the CPU is busy, since an idle core sits at the
# minimum quite legitimately.
#
# Returns 0 when the node looks healthy or cannot be checked, 1 when it
# is clamped.
check_node_speed() {
    [ "$NODE_SPEED_MIN_MHZ" -gt 0 ] || return 0
    command -v rdmsr >/dev/null 2>&1 || {
        info "rdmsr not available, skipping node speed check" \
             "(install msr-tools to enable it)."
        return 0
    }

    # Load one CPU and read what it achieves. cpu 1 rather than 0:
    # cpu 0 is reserved for kube-system and is never idle enough to be a
    # clean sample, but it is also not where the benchmark runs.
    local cpu=1 mhz=0 best=0 ps
    taskset -c "$cpu" timeout 3 \
        bash -c 'i=0; while :; do i=$((i + 1)); done' >/dev/null 2>&1 &
    local spinner=$!
    sleep 1
    # A few samples: HWP can take a moment to ramp, and the highest
    # observed value is the one that says what the node is capable of.
    local n
    for n in 1 2 3; do
        ps="$($SUDO rdmsr -p "$cpu" 0x198 2>/dev/null)" || continue
        [ -n "$ps" ] || continue
        mhz=$(( ((0x$ps >> 8) & 0xff) * 100 ))
        [ "$mhz" -gt "$best" ] && best="$mhz"
        sleep 0.5
    done
    kill "$spinner" 2>/dev/null
    wait "$spinner" 2>/dev/null

    [ "$best" -gt 0 ] || {
        info "could not read IA32_PERF_STATUS, skipping node speed check."
        return 0
    }

    info "Node speed check: cpu$cpu reached ${best} MHz under load."
    [ "$best" -ge "$NODE_SPEED_MIN_MHZ" ] && return 0

    warn "node is clamped to ${best} MHz, below" \
         "NODE_SPEED_MIN_MHZ=$NODE_SPEED_MIN_MHZ"
    warn "left-over SST-CP CLOS limits are the usual cause: check" \
         "'intel-speed-select -c $cpu core-power get-config -c 0' for a" \
         "clos-max of 0 MHz, and rerun reset-node.sh"
    return 1
}

# node_state_snapshot FILE - record the hardware state actually in
# effect, so results can be checked against what was intended.
node_state_snapshot() {
    local out="$1"
    {
        echo "=== date ==="
        date -Is
        echo "=== kernel ==="
        uname -a
        # The runtime's NRI timeouts decide whether a stage can be
        # measured at all: the plugin's initial Synchronize has to fit
        # inside plugin_request_timeout, or the runtime closes the
        # connection and the plugin restarts, and containers created
        # while it is away never reach a balloon. On a large node that
        # budget can be the difference between a measured stage and a
        # gap, so it belongs in the record next to the hardware state.
        echo "=== runtime NRI timeouts ==="
        $SUDO containerd config dump 2>/dev/null |
            grep -E "plugin_re(quest|gistration)_timeout" ||
            echo "n/a (not containerd, or config dump unavailable)"
        echo "=== kernel.numa_balancing ==="
        cat /proc/sys/kernel/numa_balancing 2>/dev/null || echo "n/a"
        echo "=== cpufreq scaling_min_freq/scaling_max_freq/governor per CPU ==="
        for c in /sys/devices/system/cpu/cpu*/cpufreq; do
            [ -d "$c" ] || continue
            echo "$c: min=$(cat "$c/scaling_min_freq" 2>/dev/null) max=$(cat "$c/scaling_max_freq" 2>/dev/null) gov=$(cat "$c/scaling_governor" 2>/dev/null)"
        done
        echo "=== cpuidle disabled states per CPU ==="
        for c in /sys/devices/system/cpu/cpu*/cpuidle; do
            [ -d "$c" ] || continue
            for s in "$c"/state*; do
                [ -d "$s" ] || continue
                echo "$s: name=$(cat "$s/name" 2>/dev/null) disable=$(cat "$s/disable" 2>/dev/null)"
            done
        done
        echo "=== uncore frequency ==="
        for d in /sys/devices/system/cpu/intel_uncore_frequency/*/; do
            [ -d "$d" ] || continue
            echo "$d: min=$(cat "$d/min_freq_khz" 2>/dev/null) max=$(cat "$d/max_freq_khz" 2>/dev/null)"
        done
        echo "=== SST / PCT ==="
        # Through $SUDO: intel-speed-select needs root for every
        # subcommand, and without it this section recorded only "Must run
        # as root" -- which is how a node left clamped by leftover SST-TF
        # state got through a whole campaign undetected.
        if command -v intel-speed-select >/dev/null 2>&1; then
            echo "--- core-power (CLOS definitions) ---"
            # One CLOS at a time: get-config requires -c and fails with
            # "Invalid clos id" without it, which is how every run up to
            # this point recorded the frequency limits of no CLOS at all
            # while a policy-programmed clos-max of 0 MHz was clamping
            # the whole node to 500 MHz. The achieved-frequency section
            # above showed the symptom; this shows the cause.
            #
            # Only the min and max lines are kept, on one line per CLOS,
            # because get-config repeats the whole block for every CPU in
            # the package and the interesting part is four numbers.
            for clos in 0 1 2 3; do
                echo -n "clos $clos: "
                $SUDO intel-speed-select core-power get-config -c "$clos" 2>&1 |
                    grep -E "clos-(min|max)" | head -2 |
                    sed 's/^ *//' | tr '\n' ' '
                echo
            done
            echo "--- core-power associations ---"
            # Per-CPU, because a CLOS association surviving a reset is
            # exactly the state that needs to be visible afterwards.
            $SUDO intel-speed-select -c "$(online_cpus_list)" \
                  core-power get-assoc 2>&1 | grep -E "cpu-|clos:" | head -40
            echo "--- turbo-freq (SST-TF) ---"
            $SUDO intel-speed-select turbo-freq info -l 1 2>&1 |
                grep -iE "enable|high-priority-cores-count" | head -10
            echo "--- base-freq (SST-BF) ---"
            $SUDO intel-speed-select base-freq info -l 1 2>&1 |
                grep -iE "enable|high-priority-base" | head -10
            echo "--- perf-profile level ---"
            $SUDO intel-speed-select perf-profile get-config-current-level 2>&1 |
                grep -m4 current_level
        else
            echo "intel-speed-select not available"
        fi
        echo "=== achieved frequency (IA32_PERF_STATUS bits 15:8 x 100 MHz) ==="
        # The one reading that told the truth when the node was clamped:
        # cpufreq and /proc/cpuinfo both reported a nominal value while
        # the cores actually ran at 500 MHz.
        #
        # Each CPU is loaded for a moment before it is read, because an
        # idle core sits at the minimum quite legitimately and this
        # snapshot is taken after the benchmark job has finished. Without
        # the load, the reading for the benchmark's own CPUs says what the
        # policy permits rather than what the benchmark achieved -- which
        # is enough to catch a clamp, since a clos-max of 0 caps a core
        # busy or idle, but not enough to compare two stages' frequencies
        # against each other. Three campaigns' worth of snapshots were
        # read that way before the difference was noticed.
        if command -v rdmsr >/dev/null 2>&1; then
            local ps spinner mhz best n
            # First two online CPUs (reserved, and where the benchmark
            # runs), the middle one and the last one -- picked out of the
            # online list rather than computed from a count, so that an
            # offline CPU is never sampled and never silently skipped.
            local -a oc
            mapfile -t oc < <(online_cpus)
            for c in "${oc[0]}" "${oc[1]}" \
                     "${oc[$(( ${#oc[@]} / 2 ))]}" "${oc[-1]}"; do
                [ -n "$c" ] || continue
                taskset -c "$c" timeout 2 \
                    bash -c 'i=0; while :; do i=$((i + 1)); done' \
                    >/dev/null 2>&1 &
                spinner=$!
                # HWP takes a moment to ramp, so sample a few times and
                # keep the highest: that is what the CPU is capable of
                # under this configuration.
                best=0 ps=""
                for n in 1 2 3; do
                    sleep 0.3
                    ps="$($SUDO rdmsr -p "$c" 0x198 2>/dev/null)" || continue
                    [ -n "$ps" ] || continue
                    mhz=$(( ((0x$ps >> 8) & 0xff) * 100 ))
                    [ "$mhz" -gt "$best" ] && best="$mhz"
                done
                kill "$spinner" 2>/dev/null
                wait "$spinner" 2>/dev/null
                [ -n "$ps" ] || continue
                echo "cpu$c: perf_status=$ps ratio=$(( (0x$ps >> 8) & 0xff ))" \
                     "=> $(( ((0x$ps >> 8) & 0xff) * 100 )) MHz" \
                     "(busy max of 3 samples: ${best} MHz)"
            done
        else
            echo "rdmsr not available (install msr-tools for this)"
        fi
        echo "=== IRQ affinities ==="
        # "ro" marks an affinity the kernel manages itself and refuses to
        # let anyone change, so the balloons policy cannot isolate it.
        # The mode bits are read rather than tested with -w, because this
        # snapshot does not run as root and the files belong to root.
        local num writable
        for irq in /proc/irq/[0-9]*; do
            [ -r "$irq/smp_affinity_list" ] || continue
            num="$(basename "$irq")"
            case "$(stat -c %A "$irq/smp_affinity_list" 2>/dev/null)" in
                ??w*) writable=rw ;;
                *)    writable=ro ;;
            esac
            # /proc/interrupts has the IRQ number, one count per CPU and
            # then the description. Drop the all-digit count fields.
            printf '%s: %s (%s) %s\n' "$num" \
                "$(cat "$irq/smp_affinity_list" 2>/dev/null)" "$writable" \
                "$(awk -v n="$num:" '$1 == n {
                       for (i = 2; i <= NF; i++)
                           if ($i !~ /^[0-9]+$/) d = d " " $i
                       sub(/^ +/, "", d); print d; exit }' \
                   /proc/interrupts 2>/dev/null)"
        done
    } > "$out" 2>&1
}

# plugin_pod - name of the plugin pod on this node, or empty.
#
# Takes the selector from the DaemonSet rather than assuming the chart's
# label values, so it keeps working if the chart changes them.
plugin_pod() {
    local selector
    selector="$(kubectl get ds "$HELM_RELEASE" -n "$HELM_NAMESPACE" \
                    -o go-template='{{range $k, $v := .spec.selector.matchLabels}}{{$k}}={{$v}},{{end}}' \
                    2>/dev/null | sed 's/,$//')"
    [ -n "$selector" ] || selector="app.kubernetes.io/name=nri-resource-policy-balloons"
    kubectl get pods -n "$HELM_NAMESPACE" -l "$selector" \
        --field-selector "spec.nodeName=$NODE_NAME" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# PLUGIN_LOG_PID - pid of the running "kubectl logs -f" follower, if any.
PLUGIN_LOG_PID=""

# start_plugin_log FILE - begin streaming the plugin's log into FILE.
#
# Streamed from the moment the pod is ready rather than read once after
# the stage, because a single post-hoc "kubectl logs --tail=-1" can only
# return what the kubelet still holds. The kubelet rotates container logs
# at containerLogMaxSize, 10Mi by default, and the debug logging these
# stages enable is far from small: an IRQ-isolating stage on a node with
# per-CPU NVMe and QAT queues emits ~13500 "failed to set affinity of irq"
# lines and ~11500 "set affinity of irq" lines, and reached 8.2 MB in
# 52000 lines here. 56 of 133 collected logs were truncated at the head
# by exactly that, and what falls off the front is the startup and
# configuration phase -- the part that says what the policy programmed.
# The "programmed CLOS ... max=0" line that named the clamp defect
# appeared in none of the truncated stage-8 logs and in all five of the
# untruncated ones, and the "cpu class commit produced an error" message
# that cpu_tuning_applied=0 greps for is emitted at configuration time
# too, so on a truncated log that check cannot fire even when it should.
#
# Following the log keeps the whole stage regardless of rotation: the
# stream is read as it is produced, so the file on disk grows past
# whatever the kubelet is willing to retain.
start_plugin_log() {
    local out="$1"
    local pod
    pod="$(plugin_pod)"
    if [ -z "$pod" ]; then
        warn "no plugin pod to follow logs from"
        return 1
    fi
    # --tail=-1 to include what the pod has already logged between
    # becoming ready and this call, so the startup phase is not lost in
    # the gap; -f to keep receiving the rest.
    kubectl logs -f --tail=-1 -n "$HELM_NAMESPACE" "$pod" > "$out" 2>&1 &
    PLUGIN_LOG_PID=$!
    echo "following logs of plugin pod $pod (pid $PLUGIN_LOG_PID)"
}

# stop_plugin_log FILE - stop the follower and make sure FILE has the
# whole stage in it.
#
# A followed stream can end early: the plugin restarting closes it, and
# so does any transient API server error. Both leave a short file that
# still looks like a log. So the follower's output is compared against a
# final direct read, and whichever has more lines is kept -- the direct
# read wins on a stream that died at the start, the follower wins once
# rotation has thrown away what the direct read would return.
stop_plugin_log() {
    local out="$1"
    if [ -n "$PLUGIN_LOG_PID" ]; then
        # SIGTERM, then reap. kubectl exits on its own once the stream
        # closes, so a failed wait here is expected, not an error.
        kill "$PLUGIN_LOG_PID" 2>/dev/null
        wait "$PLUGIN_LOG_PID" 2>/dev/null
        PLUGIN_LOG_PID=""
    fi

    local pod direct followed_lines direct_lines
    pod="$(plugin_pod)"
    [ -n "$pod" ] || return 0
    direct="$out.direct"
    kubectl logs --tail=-1 -n "$HELM_NAMESPACE" "$pod" > "$direct" 2>/dev/null
    followed_lines="$(wc -l < "$out" 2>/dev/null || echo 0)"
    direct_lines="$(wc -l < "$direct" 2>/dev/null || echo 0)"
    if [ "$direct_lines" -gt "$followed_lines" ]; then
        warn "followed plugin log has $followed_lines lines against" \
             "$direct_lines from a direct read; keeping the direct read." \
             "The follower may have been disconnected."
        mv "$direct" "$out"
    else
        rm -f "$direct"
    fi

    # Record whether the log starts where the plugin does. A log missing
    # its startup phase cannot witness what the policy programmed, and
    # that has to be visible in the results rather than inferred later.
    if [ -s "$out" ] && ! head -5 "$out" |
            grep -qE 'registering controller|level=(INFO|WARN)'; then
        warn "plugin log does not start at plugin startup:" \
             "the configuration phase may have been rotated away"
        return 1
    fi
    return 0
}

# wait_for_daemonset - wait until the plugin is running on this node.
#
# "rollout status" is not enough on its own. It reports the generation
# helm installed, but a stage that changes the pod spec (allowPCT does,
# because it makes the container privileged) replaces the pod, and the
# rollout can be reported complete against the outgoing generation while
# the incoming pod is still starting. A benchmark started then runs with
# no plugin at all: nothing is pinned, no scheduling class is applied,
# and the stage silently measures an unconfigured system.
#
# So wait for a pod of the current generation to be Ready on this node,
# and for its container to have stopped restarting.
wait_for_daemonset() {
    local timeout="${1:-180}"
    kubectl rollout status -n "$HELM_NAMESPACE" \
            "ds/$HELM_RELEASE" --timeout="${timeout}s" || return 1

    # Take the selector from the DaemonSet rather than assuming the
    # chart's label values, so this keeps working if they change.
    local selector
    selector="$(kubectl get ds "$HELM_RELEASE" -n "$HELM_NAMESPACE" \
                    -o go-template='{{range $k, $v := .spec.selector.matchLabels}}{{$k}}={{$v}},{{end}}' \
                    2>/dev/null | sed 's/,$//')"
    [ -n "$selector" ] || selector="app.kubernetes.io/name=nri-resource-policy-balloons"

    local deadline=$((SECONDS + timeout))
    local pod ready
    while [ "$SECONDS" -lt "$deadline" ]; do
        # The plugin is a DaemonSet, so exactly one pod is expected here.
        pod="$(kubectl get pods -n "$HELM_NAMESPACE" \
                   -l "$selector" \
                   --field-selector "spec.nodeName=$NODE_NAME" \
                   -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
        if [ -n "$pod" ]; then
            ready="$(kubectl get pod "$pod" -n "$HELM_NAMESPACE" \
                         -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null)"
            if [ "$ready" = true ]; then
                echo "plugin pod $pod is ready"
                return 0
            fi
        fi
        sleep 2
    done
    warn "no ready plugin pod on $NODE_NAME after ${timeout}s"
    return 1
}

# wait_for_policy_status TIMEOUT - wait until the plugin reports that it
# has applied the current configuration on this node.
#
# The policy records, per node, the generation of the BalloonsPolicy it
# last processed and whether that succeeded. Comparing the reported
# generation with the CR's own tells apart "applied" from "not seen yet",
# which a status value alone cannot: right after an apply the status
# still describes the previous generation and reads Success.
wait_for_policy_status() {
    local timeout="${1:-10}"
    local deadline=$((SECONDS + timeout))
    # Node names may contain dots, which jsonpath would read as field
    # separators, so index the map with a quoted key.
    local key="{.status.nodes['$NODE_NAME']}"
    local generation reported status node_status
    while [ "$SECONDS" -lt "$deadline" ]; do
        generation="$(kubectl get balloonspolicy default -n "$HELM_NAMESPACE" \
                          -o jsonpath='{.metadata.generation}' 2>/dev/null)"
        node_status="$(kubectl get balloonspolicy default -n "$HELM_NAMESPACE" \
                           -o jsonpath="$key" 2>/dev/null)"
        reported="$(printf '%s' "$node_status" | sed -n 's/.*"generation":\([0-9]*\).*/\1/p')"
        status="$(printf '%s' "$node_status" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
        if [ -n "$generation" ] && [ "$reported" = "$generation" ]; then
            echo "policy generation $generation reported as $status on $NODE_NAME"
            [ "$status" = Success ] && return 0
            # A rejected configuration will not become valid by waiting.
            printf '%s\n' "$node_status"
            return 1
        fi
        sleep 1
    done
    echo "timeout: policy generation $generation, node reported ${reported:-none}"
    return 1
}

# check_stage_measured_config STAGE_DIR - decide whether the numbers this
# stage produced describe the configuration it asked for.
#
# A stage can pass every check above and still measure an unconfigured
# system. The policy reports a configuration as applied before it has
# finished acting on it, and the plugin can die afterwards: a stage that
# rewrites thousands of IRQ affinities on a loaded node can exceed
# containerd's NRI request timeout, at which point containerd closes the
# connection, the plugin exits and restarts, and any container created
# while it was away never reaches a balloon. Nothing upstream of the
# measurement notices, and the resulting row looks like a plausible
# regression rather than a missing configuration.
#
# The measurement itself is the witness: sleep-accuracy reports the
# scheduling policy and priority it inherited, so a stage that asked for
# a scheduling class and got schedpol 0 measured the baseline. Stages
# that configure no scheduling class have nothing to check this way, so
# they fall back to the plugin's own record of the assignment.
#
# Returns 0 when the measurement is trustworthy, 1 when it is not.
check_stage_measured_config() {
    local stage_dir="$1"
    local log="$stage_dir/sleep-accuracy.log"
    [ -f "$log" ] || return 0
    [ -z "${STAGE_NO_BALLOONS:-}" ] || return 0

    local reason=""

    if [ -n "${BENCH_SCHEDULINGCLASS:-}" ]; then
        # Field 6 is schedpol, field 7 schedprio; 0 means the container
        # inherited the default policy, so the class never reached it.
        local unconfigured
        unconfigured="$(awk '$1 == "nanosleep" && $6 == 0' "$log" | wc -l)"
        if [ "$unconfigured" -gt 0 ]; then
            reason="$unconfigured measurements ran with scheduling policy 0,"
            reason="$reason but the stage configured $BENCH_SCHEDULINGCLASS"
        fi
    elif [ -f "$stage_dir/nri-resource-policy.log" ]; then
        grep -q "assigning container $BENCH_NAMESPACE/.* to balloon" \
             "$stage_dir/nri-resource-policy.log" ||
            reason="the plugin never assigned the benchmark container to a balloon"
    fi

    [ -n "$reason" ] || return 0

    warn "stage $STAGE_NAME measured an unconfigured system: $reason"
    # Name the likely cause when the plugin's log shows it, so that the
    # run log says what to do rather than only that something was wrong.
    if grep -q "connection to NRI/runtime lost" \
            "$stage_dir/nri-resource-policy.log" 2>/dev/null; then
        warn "the plugin lost its connection to the runtime during this stage"
    fi
    echo "measured_config_valid=0" >> "$stage_dir/stage-env.txt"
    return 1
}

# capture_cgroups STAGE_DIR - record the effective cpusets of the
# benchmark and noise containers, while the benchmark is still running.
#
# Called as soon as the benchmark pod is Running, not after the Job
# completes. A completed Job's container is gone and so is its cgroup, so
# the post-hoc capture this replaces recorded only the noise containers:
# every collected cgroups.txt of a loaded campaign holds 90 stress-ng
# entries and no sleep-accuracy entry at all, and on the unloaded
# campaign the file is empty in all 45 stages. That left the CPUs the
# benchmark actually ran on unwitnessed by anything except a single line
# in the plugin's log -- which is the policy's intent, not the kernel's
# cgroup.
#
# Prints the benchmark container's effective cpuset on stdout, empty if
# it could not be read.
capture_cgroups() {
    local stage_dir="$1"
    local kube_cgroups="$SCRIPT_DIR/../kube-cgroups"
    [ -x "$kube_cgroups" ] || return 0

    $SUDO "$kube_cgroups" -n "$BENCH_NAMESPACE" \
        -f 'cpuset.cpus.effective|cpuset.mems.effective' \
        > "$stage_dir/cgroups.txt" 2>&1

    # kube-cgroups prints a pod block, a container line under it, and
    # then one "file: value" line per file. Pick the cpuset of the
    # container inside the benchmark pod, whose name is the Job's.
    awk -v job="$BENCH_JOB_NAME" '
        /^[^ ]/            { inpod = (index($0, job) > 0); next }
        inpod && /cpuset\.cpus\.effective:/ {
            sub(/^ *cpuset\.cpus\.effective: */, ""); print; exit }
    ' "$stage_dir/cgroups.txt" 2>/dev/null
}

# wait_for_bench_pod_running TIMEOUT - wait until the benchmark pod has a
# running container, so its cgroup exists and can be read.
wait_for_bench_pod_running() {
    local timeout="${1:-120}"
    local deadline=$((SECONDS + timeout))
    local pod phase
    while [ "$SECONDS" -lt "$deadline" ]; do
        pod="$(kubectl get pod -n "$BENCH_NAMESPACE" -l app=sleep-accuracy \
                   -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
        if [ -n "$pod" ]; then
            phase="$(kubectl get pod -n "$BENCH_NAMESPACE" "$pod" \
                         -o jsonpath='{.status.phase}' 2>/dev/null)"
            # Succeeded too: a short benchmark can finish before this
            # loop first looks, and there is nothing left to wait for.
            case "$phase" in
                Running|Succeeded|Failed) echo "$pod"; return 0 ;;
            esac
        fi
        sleep 1
    done
    return 1
}

# cpulist_expand LIST - expand "0-3,8" into one CPU number per line.
cpulist_expand() {
    local range lo hi
    local IFS=,
    for range in $1; do
        case "$range" in
            "")  ;;
            *-*) lo="${range%%-*}"; hi="${range##*-}"
                 while [ "$lo" -le "$hi" ] 2>/dev/null; do
                     echo "$lo"; lo=$((lo + 1))
                 done ;;
            *)   echo "$range" ;;
        esac
    done
}

# resolve_freq SYMBOL - turn base/turbo/min into a kHz value from this
# node's own cpufreq, so the comparison means "the frequency the stage
# asked for" on any part. Numeric values pass through. Empty output
# means the symbol could not be resolved and the check must be skipped.
resolve_freq() {
    local want="$1" cpufreq=/sys/devices/system/cpu/cpu0/cpufreq
    case "$want" in
        base)   cat "$cpufreq/base_frequency" 2>/dev/null ;;
        turbo)  cat "$cpufreq/cpuinfo_max_freq" 2>/dev/null ;;
        min)    cat "$cpufreq/cpuinfo_min_freq" 2>/dev/null ;;
        [0-9]*) echo "$want" ;;
        *)      echo "" ;;
    esac
}

# check_stage_configured_state STAGE_DIR BENCH_CPUS - is the node in the
# state this stage asked for?
#
# Everything here is read out of the snapshot the harness already writes,
# which until now was recorded and never looked at: a "grep node-state"
# over the harness found one write and no reads. That is how campaign 1
# was lost. Every fact needed to catch its 500 MHz clamp was in those
# files from the first stage onwards, and nothing compared them against
# what the stage had configured, so five cycles of stages 4-7 were
# collected against a crippled node and looked like results.
#
# The checks are deliberately about the benchmark's own CPUs, since those
# are what the latencies describe. Each writes one name into
# STATE_CHECK_FAILURES when it fails; a check that cannot be evaluated --
# no snapshot section, an unresolvable symbolic frequency, a stage that
# does not configure the mechanism -- is skipped rather than failed, so a
# node without some piece of hardware does not produce a wall of noise.
#
# Returns 0 when every evaluated check passed, 1 otherwise.
STATE_CHECK_FAILURES=""
check_stage_configured_state() {
    local stage_dir="$1" bench_cpus="$2"
    local snapshot="$stage_dir/node-state.txt"
    local plugin_log="$stage_dir/nri-resource-policy.log"
    STATE_CHECK_FAILURES=""
    [ -f "$snapshot" ] || return 0
    [ -z "${STAGE_NO_BALLOONS:-}" ] || return 0

    local -a failed=()
    local -a bench=()
    if [ -n "$bench_cpus" ] && [ "$bench_cpus" != 0 ]; then
        mapfile -t bench < <(cpulist_expand "$bench_cpus")
    fi

    ###
    ### PCT: a CLOS maximum of 0 is the defect that cost three campaigns.
    ###
    # SST-CP reads clos-max 0 as zero MHz, not as "no limit", so a CLOS
    # programmed that way clamps its CPUs to the hardware minimum. The
    # snapshot prints "clos N: clos-min:X MHz clos-max:Y MHz", or
    # "clos-max:Max Turbo frequency" when unlimited.
    if [ -n "${CPUCLASS_BENCH_PCTPRIORITY:-}" ]; then
        local zero_clos
        zero_clos="$(awk '/^clos [0-9]+:/ && /clos-max:0 MHz/ { print $2 }' \
                     "$snapshot" | tr -d ':' | tr '\n' '+' | sed 's/+$//')"
        if [ -n "$zero_clos" ]; then
            failed+=("clos-max-zero($zero_clos)")
            warn "CLOS $zero_clos has clos-max 0 MHz, which SST-CP reads" \
                 "as zero: these CPUs are clamped to the hardware minimum"
        fi
        # get-config needs -c per CLOS; without it the snapshot records
        # "Invalid clos id" and says nothing. That was true of every run
        # of the first three campaigns, and is why the clamp hid.
        if grep -q "Invalid clos id" "$snapshot"; then
            failed+=("clos-limits-unreadable")
        fi
    fi

    ###
    ### Achieved frequency: is the node running at a sane speed at all?
    ###
    # Each sampled CPU is loaded before being read, so a low reading here
    # is a real clamp rather than an idle core at its minimum. Requiring
    # every sampled CPU to be low is what distinguishes the two: one idle
    # CPU at 500 MHz is legitimate, all of them is not.
    local sampled low
    sampled="$(grep -cE '^cpu[0-9]+: perf_status=' "$snapshot" 2>/dev/null)"
    if [ "${sampled:-0}" -gt 0 ] && [ "$NODE_SPEED_MIN_MHZ" -gt 0 ]; then
        low="$(awk -v lim="$NODE_SPEED_MIN_MHZ" '
            /^cpu[0-9]+: perf_status=/ {
                # Prefer "(busy max of N samples: NNNN MHz)", which says
                # what the CPU reached rather than what it happened to be
                # at in the final sample. Snapshots taken before that was
                # recorded only have the "=> NNNN MHz" figure, and those
                # were sampled idle, so they are counted but cannot be
                # trusted to mean a clamp on their own.
                #
                # The number is matched and extracted as its own field
                # rather than by offset arithmetic from the label, which
                # is how "4600" first got read as "600" here and made a
                # healthy node look clamped.
                mhz = ""
                if (match($0, /busy max of [0-9]+ samples: [0-9]+/)) {
                    s = substr($0, RSTART, RLENGTH)
                    n_f = split(s, f, " ")
                    mhz = f[n_f]
                } else if (match($0, /=> [0-9]+ MHz/)) {
                    s = substr($0, RSTART, RLENGTH)
                    split(s, f, " ")
                    mhz = f[2]
                }
                if (mhz != "" && mhz + 0 < lim) n++
            } END { print n + 0 }' "$snapshot")"
        if [ "$low" = "$sampled" ]; then
            failed+=("node-clamped")
            warn "every sampled CPU is below ${NODE_SPEED_MIN_MHZ} MHz:" \
                 "the node was clamped while this stage was measured"
        fi
    fi

    ###
    ### C-states: disabled where asked, and only where asked.
    ###
    if [ -n "${CPUCLASS_BENCH_DISABLEDCSTATES:-}" ] && [ ${#bench[@]} -gt 0 ]; then
        local want_cstates="${CPUCLASS_BENCH_DISABLEDCSTATES}"
        local cstate missing_on="" leaked_on=""
        local IFS=,
        for cstate in $want_cstates; do
            unset IFS
            local c n_enabled=0
            for c in "${bench[@]}"; do
                # "cpuN/cpuidle/stateM: name=C1E disable=1"
                awk -v cpu="cpu$c/" -v name="name=$cstate " '
                    index($0, cpu) && index($0, name) &&
                    index($0, "disable=1") { found = 1 }
                    END { exit(found ? 0 : 1) }' "$snapshot" ||
                    n_enabled=$((n_enabled + 1))
            done
            [ "$n_enabled" = 0 ] || missing_on="$missing_on $cstate"
            # And a CPU the class does not cover should still have it.
            # Checking one such CPU is enough to tell "the policy scoped
            # this to the benchmark" from "something disabled it
            # globally", which would make the stage measure the whole
            # node rather than the mechanism.
            local other=""
            local oc
            for oc in $(online_cpus); do
                local is_bench=0 b
                for b in "${bench[@]}"; do
                    [ "$oc" = "$b" ] && { is_bench=1; break; }
                done
                [ "$is_bench" = 0 ] && { other="$oc"; break; }
            done
            if [ -n "$other" ]; then
                awk -v cpu="cpu$other/" -v name="name=$cstate " '
                    index($0, cpu) && index($0, name) &&
                    index($0, "disable=1") { found = 1 }
                    END { exit(found ? 0 : 1) }' "$snapshot" &&
                    leaked_on="$leaked_on $cstate"
            fi
            IFS=,
        done
        unset IFS
        # The lists are accumulated with a leading space per item; strip
        # it before joining, or the label reads "(+C6)".
        missing_on="${missing_on# }"
        leaked_on="${leaked_on# }"
        if [ -n "$missing_on" ]; then
            failed+=("cstates-not-disabled(${missing_on// /+})")
            warn "C-states${missing_on} are still enabled on the benchmark" \
                 "CPUs ($bench_cpus), but the stage disabled them"
        fi
        if [ -n "$leaked_on" ]; then
            failed+=("cstates-disabled-node-wide(${leaked_on// /+})")
            warn "C-states${leaked_on} are disabled outside the benchmark" \
                 "CPUs too: this stage measures the node, not the mechanism"
        fi
    fi

    ###
    ### cpufreq limits on the benchmark's CPUs.
    ###
    if [ ${#bench[@]} -gt 0 ]; then
        local field want got resolved c bad
        for field in MAXFREQ MINFREQ; do
            eval "want=\${CPUCLASS_BENCH_${field}:-}"
            [ -n "$want" ] || continue
            resolved="$(resolve_freq "$want")"
            [ -n "$resolved" ] || continue
            local key=max; [ "$field" = MINFREQ ] && key=min
            bad=""
            for c in "${bench[@]}"; do
                got="$(awk -v cpu="/cpu$c/cpufreq:" -v k="$key=" '
                    index($0, cpu) {
                        n = split($0, f, " ")
                        for (i = 1; i <= n; i++)
                            if (index(f[i], k) == 1) {
                                sub(k, "", f[i]); print f[i]; exit }
                    }' "$snapshot")"
                [ -n "$got" ] || continue
                # Exact equality: both sides are kHz straight out of
                # sysfs, and the policy writes the value it resolved.
                [ "$got" = "$resolved" ] || bad="$bad cpu$c($got)"
            done
            if [ -n "$bad" ]; then
                failed+=("cpufreq-$key-wrong")
                warn "scaling_${key}_freq is not the requested $want" \
                     "(${resolved} kHz) on:${bad}"
            fi
        done
    fi

    ###
    ### IRQ isolation: nothing left pointing at the benchmark's CPUs.
    ###
    # Only meaningful when the stage asked for isolation. IRQs the kernel
    # manages itself cannot be moved -- smp_affinity_list is read-only
    # for some, and writes fail with EIO for NVMe and QAT per-queue
    # interrupts -- so those are exempt. The exemption list is taken from
    # the plugin's own failures rather than assumed, which also means a
    # newly unmovable IRQ shows up as a finding instead of hiding.
    #
    # Also exempt are IRQs with no /proc/interrupts line, which the
    # snapshot records with an empty description: unallocated legacy ISA
    # vectors with no driver attached. The policy enumerates interrupts
    # from /proc/interrupts, so these are never candidates for isolation
    # and never fire -- but they keep a default affinity of every CPU,
    # which without this exemption reads as a dozen offenders on every
    # isolate stage.
    if [ "${BENCH_IRQMODE:-}" = isolate ] && [ ${#bench[@]} -gt 0 ]; then
        local exempt_file="$stage_dir/.irq-exempt"
        {
            # Kernel-managed, marked ro in the snapshot.
            awk '/^[0-9]+: / && /\(ro\)/ { sub(":", "", $1); print $1 }' \
                "$snapshot"
            # No device behind them: "NUM: LIST (rw)" and nothing after.
            awk '/^[0-9]+: / && NF == 3 { sub(":", "", $1); print $1 }' \
                "$snapshot"
            # Writes refused with EIO, as reported by the plugin.
            grep -oE "failed to set affinity of irq [0-9]+" "$plugin_log" \
                2>/dev/null | awk '{print $NF}'
        } | sort -u > "$exempt_file"

        local offenders
        offenders="$(awk -v cpus="$(printf '%s,' "${bench[@]}")" '
            BEGIN {
                n = split(cpus, c, ",")
                for (i = 1; i <= n; i++) if (c[i] != "") bench[c[i]] = 1
            }
            # First file: the exemption list, one IRQ number per line.
            FNR == NR { exempt[$1] = 1; next }
            /^[0-9]+: / {
                irq = $1; sub(":", "", irq)
                if (irq in exempt) next
                # "NUM: LIST (rw) description"
                list = $2
                nr = split(list, ranges, ",")
                for (i = 1; i <= nr; i++) {
                    if (split(ranges[i], se, "-") == 2) { lo = se[1]; hi = se[2] }
                    else { lo = ranges[i] + 0; hi = lo }
                    for (cpu = lo; cpu <= hi; cpu++)
                        if (cpu in bench) { print irq; next }
                }
            }' "$exempt_file" "$snapshot" | sort -un | tr '\n' '+' | sed 's/+$//')"
        rm -f "$exempt_file"
        if [ -n "$offenders" ]; then
            local n_off
            # Count the items, not the newlines: printf writes no trailing
            # newline, so "wc -l" reported one fewer than there were and a
            # single offender was announced as "0 movable IRQs".
            n_off="$(printf '%s\n' "$offenders" | tr '+' '\n' | grep -c .)"
            failed+=("irqs-on-bench-cpus($n_off)")
            warn "$n_off movable IRQs still allow the benchmark CPUs" \
                 "($bench_cpus) despite irqMode isolate: $offenders"
        fi
    fi

    ###
    ### The cpuset itself: did the benchmark get its own CPUs?
    ###
    if [ -n "${BENCH_PREFERNEWBALLOONS:-}" ] && [ ${#bench[@]} -gt 0 ]; then
        local want_n="${BENCH_MAXCPUS:-$BENCH_CPUS}"
        if [ "${#bench[@]}" != "$want_n" ]; then
            failed+=("bench-cpuset-size(${#bench[@]}!=$want_n)")
            warn "the benchmark ran on ${#bench[@]} CPUs ($bench_cpus)," \
                 "but the stage asked for $want_n"
        fi
        # And the noise must not be on them. cgroups.txt holds every
        # container's effective cpuset, so this is a direct check rather
        # than an inference from the policy's intent.
        local shared
        shared="$(awk -v cpus="$(printf '%s,' "${bench[@]}")" '
            BEGIN {
                n = split(cpus, c, ",")
                for (i = 1; i <= n; i++) if (c[i] != "") bench[c[i]] = 1
            }
            /^[^ ]/ { pod = $0; sub(":$", "", pod); next }
            /cpuset\.cpus\.effective:/ {
                if (pod ~ /sleep-accuracy/) next
                list = $2
                nr = split(list, ranges, ",")
                for (i = 1; i <= nr; i++) {
                    if (split(ranges[i], se, "-") == 2) { lo = se[1]; hi = se[2] }
                    else { lo = ranges[i] + 0; hi = lo }
                    for (cpu = lo; cpu <= hi; cpu++)
                        if (cpu in bench) { print pod; next }
                }
            }' "$stage_dir/cgroups.txt" 2>/dev/null | sort -u | wc -l)"
        if [ "${shared:-0}" -gt 0 ]; then
            failed+=("noise-shares-bench-cpus($shared)")
            warn "$shared other containers have the benchmark's CPUs" \
                 "($bench_cpus) in their cpuset"
        fi
    fi

    if [ ${#failed[@]} = 0 ]; then
        STATE_CHECK_FAILURES=ok
        info "State checks passed for the configuration of stage $STAGE_NAME."
        return 0
    fi
    STATE_CHECK_FAILURES="$(IFS=+; echo "${failed[*]}")"
    echo "state_checks=$STATE_CHECK_FAILURES" >> "$stage_dir/stage-env.txt"
    return 1
}

# deploy_noise - start the background workload, if any.
deploy_noise() {
    local stage_dir="$1"
    if [ "$NOISE_WORKLOAD" = none ] || [ "$NOISE_REPLICAS" = 0 ]; then
        info "No background workload (NOISE_WORKLOAD=$NOISE_WORKLOAD)."
        return 0
    fi
    info "Deploying $NOISE_REPLICAS stress-ng containers ($NOISE_WORKLOAD) ..."
    instantiate "$SCRIPT_DIR/stress-ng-deployment.yaml.in" \
        > "$stage_dir/stress-ng-deployment.yaml"
    kubectl apply -f "$stage_dir/stress-ng-deployment.yaml" >/dev/null ||
        { warn "cannot deploy background workload"; return 1; }
    # Wait for the noise to be running and settled, so that the
    # benchmark measures a loaded system from its very first iteration.
    kubectl rollout status -n "$BENCH_NAMESPACE" \
            "deployment/$NOISE_DEPLOYMENT_NAME" --timeout=300s ||
        warn "background workload did not become ready"
    info "Letting the background workload settle for ${NOISE_SETTLE_SECONDS}s ..."
    sleep "$NOISE_SETTLE_SECONDS"
}

# run_stage STAGE_INDEX STAGE_NAME
run_stage() {
    local STAGE_INDEX="$1" STAGE_NAME="$2"
    local stage_dir
    stage_dir="$(printf '%s/%02d-%s' "$RESULTS_DIR" "$STAGE_INDEX" "$STAGE_NAME")"
    mkdir -p "$stage_dir"

    # Load the stage's configuration into the environment. The stage
    # functions assign plain variables, but gen-balloons-config.sh and
    # the yaml templates read them from the environment of a child
    # process, so auto-export everything the stage sets.
    stage_reset_vars
    # BENCH_CPUS is read by some stages, keep it visible to them.
    export BENCH_CPUS
    set -a
    "stage_$STAGE_NAME"
    set +a

    info "=============================================================="
    info "Stage $STAGE_INDEX: $STAGE_NAME"
    info "$STAGE_DESCRIPTION"
    info "=============================================================="

    # Generate the configuration for this stage, whether or not it will
    # be applied, so that every stage directory documents its intent.
    local config_yaml="$stage_dir/balloons-config.yaml"
    if [ -n "${STAGE_NO_BALLOONS:-}" ]; then
        echo "# Stage $STAGE_NAME runs without the balloons policy." \
            > "$config_yaml"
    else
        "$SCRIPT_DIR/gen-balloons-config.sh" > "$config_yaml" ||
            { warn "config generation failed for $STAGE_NAME"; return 1; }
    fi

    # Record the configuration row for the CSV, and the stage variables
    # in a readable form.
    csv_config_row > "$stage_dir/config-row.csv"
    {
        echo "stage=$STAGE_NAME"
        echo "description=$STAGE_DESCRIPTION"
        echo "bench_args=$BENCH_ARGS"
        echo "noise_workload=$NOISE_WORKLOAD replicas=$NOISE_REPLICAS"
        echo "noise_args=$NOISE_ARGS"
        set | grep -E '^(BENCH|NOISE|DEFAULT|CPUCLASS|SCHEDCLASS|LOADCLASS|IDLECPUCLASS|TURBODOMAIN|PINCPU|PINMEMORY|RESERVED_CPU|AVAILABLE_CPU|ALLOCATORTOPOLOGY|STAGE)_?[A-Z_]*=' | sort
    } > "$stage_dir/stage-env.txt" 2>/dev/null

    if [ "$dry_run" = 1 ]; then
        info "Dry run, generated configuration:"
        cat "$config_yaml"
        return 0
    fi

    ###
    ### 1. Reset the node.
    ###
    info "Resetting node ..."
    $SUDO "$SCRIPT_DIR/reset-node.sh" > "$stage_dir/reset.log" 2>&1 ||
        warn "node reset reported problems, see $stage_dir/reset.log"

    # Check after the reset, not before: the reset is what is supposed to
    # have cleared any clamp, so this asks whether it worked. Recorded
    # rather than fatal, because on a node with no SST at all there is
    # nothing to undo and the run is still meaningful.
    if ! check_node_speed; then
        echo "node_speed_clamped=1" >> "$stage_dir/stage-env.txt"
    fi

    kubectl create namespace "$BENCH_NAMESPACE" >/dev/null 2>&1

    ###
    ### 2. Install the balloons policy, unless this is the baseline.
    ###
    if [ -z "${STAGE_NO_BALLOONS:-}" ]; then
        if [ -n "${STAGE_NEEDS_PCT:-}" ] && [ -z "$ALLOW_PCT" ]; then
            info "Stage needs PCT, enabling allowPCT for it."
        fi
        local -a helm_args=(
            install "$HELM_RELEASE" "$CHART"
            --namespace "$HELM_NAMESPACE"
            --wait --timeout 300s
        )
        if [ -n "$PATCH_RUNTIME_CONFIG" ]; then
            helm_args+=(--set nri.runtime.patchConfig=true)
        fi
        if [ -n "$ALLOW_PCT" ] || [ -n "${STAGE_NEEDS_PCT:-}" ]; then
            helm_args+=(--set allowPCT=true)
        fi
        if [ -n "$PLUGIN_IMAGE" ]; then
            helm_args+=(--set "image.name=${PLUGIN_IMAGE%:*}")
            helm_args+=(--set "image.tag=${PLUGIN_IMAGE##*:}")
            helm_args+=(--set image.pullPolicy=IfNotPresent)
        fi
        # Simulated platform for validating the harness on a virtual
        # machine. These values are JSON containing commas and brackets,
        # which helm's --set parser would read as list and index syntax,
        # so pass them through a values file instead.
        local -a overrides
        readarray -t overrides < <(overridden_vars)
        if [ ${#overrides[@]} -gt 0 ]; then
            local values_file="$stage_dir/helm-values.yaml"
            # The values are JSON documents that must reach the
            # container as plain strings. The chart renders extraEnv as
            # an unquoted "value: {{ $value }}", so the value has to
            # carry its own quotes into the rendered manifest. Tripled
            # single quotes do that: YAML reduces them to a quoted
            # string, and the chart passes those quotes through. This is
            # the same trick the e2e test configs use.
            {
                echo "extraEnv:"
                local name
                for name in "${overrides[@]}"; do
                    echo "  ${name}: '''${!name}'''"
                done
            } > "$values_file"
            helm_args+=(-f "$values_file")
        fi
        info "Installing balloons policy ..."
        if ! helm "${helm_args[@]}" > "$stage_dir/helm-install.log" 2>&1; then
            warn "helm install failed, see $stage_dir/helm-install.log"
            return 1
        fi
        if ! wait_for_daemonset 240 >> "$stage_dir/helm-install.log" 2>&1; then
            warn "balloons daemonset not ready, see $stage_dir/helm-install.log"
        fi

        # Start following the plugin's log before the configuration is
        # applied, so that what the policy programs is captured as it
        # happens rather than read back afterwards from a log the kubelet
        # may have rotated. See start_plugin_log.
        start_plugin_log "$stage_dir/nri-resource-policy.log" \
            >> "$stage_dir/helm-install.log" 2>&1

        info "Applying BalloonsPolicy configuration ..."
        if ! kubectl apply -f "$config_yaml" > "$stage_dir/kubectl-apply.log" 2>&1; then
            warn "applying BalloonsPolicy failed, see $stage_dir/kubectl-apply.log"
            cat "$stage_dir/kubectl-apply.log" >&2
            return 1
        fi
        # The policy watches its configuration and reconfigures
        # asynchronously, so wait for it to report that it accepted this
        # configuration before starting any workload. Waiting on the
        # status beats sleeping a fixed time: a rejected configuration is
        # caught here instead of turning into a stage that quietly
        # measures an unconfigured system.
        if ! wait_for_policy_status "${CONFIG_SETTLE_SECONDS:-10}" \
                 >> "$stage_dir/kubectl-apply.log" 2>&1; then
            warn "policy did not report success for this configuration," \
                 "see $stage_dir/kubectl-apply.log"
        fi
        # Even after the policy accepts the configuration, applying CPU
        # tuning to the hardware takes a moment.
        sleep "${CONFIG_SETTLE_SECONDS:-10}"
    else
        info "Baseline stage: no balloons policy installed."
    fi

    ###
    ### 3. Background workload.
    ###
    deploy_noise "$stage_dir"

    ###
    ### 4. Run the benchmark.
    ###
    info "Running sleep-accuracy: $BENCH_ARGS"
    instantiate "$SCRIPT_DIR/sleep-accuracy-job.yaml.in" \
        > "$stage_dir/sleep-accuracy-job.yaml"
    kubectl delete job "$BENCH_JOB_NAME" -n "$BENCH_NAMESPACE" \
            --ignore-not-found >/dev/null 2>&1
    if ! kubectl apply -f "$stage_dir/sleep-accuracy-job.yaml" >/dev/null; then
        warn "cannot start the benchmark job"
        return 1
    fi

    # Read the benchmark's own cgroup while its container still exists.
    # After the Job completes the cgroup is gone, which is why the
    # capture that used to happen in the collection step below recorded
    # only the noise containers.
    local bench_cpus=""
    if wait_for_bench_pod_running 300 >/dev/null; then
        bench_cpus="$(capture_cgroups "$stage_dir")"
        if [ -n "$bench_cpus" ]; then
            info "Benchmark container cpuset: $bench_cpus"
        else
            warn "could not read the benchmark container's cpuset"
        fi
    else
        warn "benchmark pod never started running"
    fi

    # Wait for completion. On failure, keep going: the pod logs and the
    # policy logs are collected below and explain what happened.
    local job_ok=1
    if ! kubectl wait --for=condition=complete \
            "job/$BENCH_JOB_NAME" -n "$BENCH_NAMESPACE" \
            --timeout="${BENCH_TIMEOUT}s" >/dev/null 2>&1; then
        job_ok=0
        warn "benchmark job did not complete within ${BENCH_TIMEOUT}s"
    fi

    ###
    ### 5. Collect everything.
    ###
    local bench_pod
    bench_pod="$(kubectl get pod -n "$BENCH_NAMESPACE" \
        -l "app=sleep-accuracy" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"

    if [ -n "$bench_pod" ]; then
        kubectl logs -n "$BENCH_NAMESPACE" "$bench_pod" \
            > "$stage_dir/sleep-accuracy.log" 2>&1
        kubectl get pod -n "$BENCH_NAMESPACE" "$bench_pod" -o yaml \
            > "$stage_dir/sleep-accuracy-pod.yaml" 2>&1
    else
        warn "benchmark pod not found"
    fi

    # What the policy decided, and what the node actually looks like.
    if [ -z "${STAGE_NO_BALLOONS:-}" ]; then
        # Stop the follower started before the configuration was applied,
        # and note it if the log still does not reach back to startup.
        if ! stop_plugin_log "$stage_dir/nri-resource-policy.log"; then
            echo "plugin_log_truncated=1" >> "$stage_dir/stage-env.txt"
        fi
        kubectl get balloonspolicies.config.nri -n "$HELM_NAMESPACE" \
            -o yaml > "$stage_dir/balloonspolicy-status.yaml" 2>&1
        # A stage can be configured correctly and still change nothing,
        # if the node lacks the hardware. Make that visible instead of
        # letting it hide behind plausible-looking latencies.
        if grep -q "cpu class commit produced an error" \
                "$stage_dir/nri-resource-policy.log" 2>/dev/null; then
            warn "the policy could not apply CPU tuning in this stage:"
            grep -m3 "cpu class commit produced an error" \
                 "$stage_dir/nri-resource-policy.log" >&2
            echo "cpu_tuning_applied=0" >> "$stage_dir/stage-env.txt"
        fi
        # Some IRQ affinities cannot be changed at all, because the
        # kernel manages them itself: either smp_affinity_list is
        # read-only, as for virtio per-queue MSI-X interrupts, or writes
        # to it fail with EIO, as for NVMe and QAT per-queue interrupts.
        # Record how many were refused and how many distinct IRQs that
        # was. The count alone is alarming but not informative: those
        # drivers put one queue on every CPU, so on a large node no
        # choice of benchmark CPUs avoids them, and they only cost
        # anything while something drives the device. Note it as a fact
        # to weigh against the load, not as a failure.
        local irq_failed irq_distinct
        irq_failed="$(grep -c "failed to set affinity of irq" \
            "$stage_dir/nri-resource-policy.log" 2>/dev/null || true)"
        if [ "${irq_failed:-0}" -gt 0 ]; then
            irq_distinct="$(grep -oE "failed to set affinity of irq [0-9]+" \
                "$stage_dir/nri-resource-policy.log" 2>/dev/null |
                awk '{print $NF}' | sort -u | wc -l)"
            info "$irq_distinct IRQs are kernel-managed and stayed where they" \
                 "were ($irq_failed refused updates); normal on nodes with" \
                 "per-CPU NVMe or accelerator queues, see node-state.txt"
            echo "irq_affinity_failures=$irq_failed" >> "$stage_dir/stage-env.txt"
            echo "irq_unmovable_count=$irq_distinct" >> "$stage_dir/stage-env.txt"
        fi
    fi
    kubectl get pods -n "$BENCH_NAMESPACE" -o wide \
        > "$stage_dir/pods.txt" 2>&1
    node_state_snapshot "$stage_dir/node-state.txt"

    # Compare the snapshot against what the stage configured. Until this
    # existed the snapshot was written and never read, so a stage could
    # be misconfigured in every way the snapshot records and still
    # produce a row that looked like a result.
    local state_checks=0
    if [ -z "${STAGE_NO_BALLOONS:-}" ]; then
        check_stage_configured_state "$stage_dir" "$bench_cpus"
        state_checks="${STATE_CHECK_FAILURES:-0}"
    fi

    ###
    ### 6. Append to the CSV, unless the stage measured something else
    ### than what it configured.
    ###
    # Keep such a run out of the CSV rather than in it with a marker:
    # every consumer of the CSV would otherwise have to know to filter
    # it, and the numbers are baseline numbers under a stage's name,
    # which is worse than no numbers at all. The logs stay on disk.
    if ! check_stage_measured_config "$stage_dir"; then
        # A retry writes into the same directory, so move this attempt
        # aside first. Both the discarded run and the one that replaces
        # it stay available for working out why the first one failed.
        local attempt_dir="$stage_dir.unconfigured"
        local n=1
        while [ -e "$attempt_dir" ]; do
            n=$((n + 1))
            attempt_dir="$stage_dir.unconfigured-$n"
        done
        mv "$stage_dir" "$attempt_dir"
        warn "not adding stage $STAGE_NAME to the CSV," \
             "logs kept in $(basename "$attempt_dir")"
        return 2
    fi

    # What could be verified about the state the stage actually ran in,
    # alongside what it asked for. Stored in the stage directory too, so
    # that report.sh can rebuild the CSV from logs without re-deriving it.
    # The cpuset is a cpulist that may contain commas, so join it with +
    # to keep it inside a single CSV column.
    local verify_row="${bench_cpus:-0}"
    verify_row="${verify_row//,/+},${state_checks}"
    echo "$verify_row" > "$stage_dir/verify-row.csv"

    local measurements=0
    if [ -f "$stage_dir/sleep-accuracy.log" ]; then
        csv_append_stage "$stage_dir/sleep-accuracy.log" \
                         "$(cat "$stage_dir/config-row.csv")" "$CSV_FILE" \
                         "$verify_row"
        measurements="$(grep -cE '^(nanosleep|networking|futex) ' \
            "$stage_dir/sleep-accuracy.log" 2>/dev/null || echo 0)"
    fi

    if [ "$measurements" = 0 ]; then
        warn "stage $STAGE_NAME produced no measurements"
        [ -f "$stage_dir/sleep-accuracy.log" ] &&
            tail -20 "$stage_dir/sleep-accuracy.log" >&2
        return 1
    fi
    info "Stage $STAGE_NAME done: $measurements measurements."
    [ "$job_ok" = 1 ] || warn "results may be incomplete"
    return 0
}

###
### Main
###

info "Results directory: $RESULTS_DIR"
info "Node: $NODE_NAME ($node_cpus CPUs)"
info "Chart: $CHART"
info "Stages: ${run_stages[*]}"
[ "$dry_run" = 1 ] || check_nri_enabled
[ "$dry_run" = 1 ] || check_node_capabilities

if [ "$dry_run" = 0 ]; then
    csv_header > "$CSV_FILE"
fi

failed_stages=()
invalid_stages=()
stage_index=0
for stage in "${run_stages[@]}"; do
    stage_index=$((stage_index + 1))
    # A stage that measured an unconfigured system (exit 2) is worth
    # repeating: the cause is a transient loss of the plugin's runtime
    # connection, not a bad configuration, so the next attempt usually
    # succeeds. A stage that failed outright (exit 1) is not retried,
    # because nothing about it would be different the second time.
    attempt=1
    while :; do
        run_stage "$stage_index" "$stage" 2>&1 | tee -a "$RUN_LOG"
        rc="${PIPESTATUS[0]}"
        [ "$rc" = 2 ] || break
        if [ "$attempt" -ge "$STAGE_RETRIES" ]; then
            warn "stage $stage measured an unconfigured system in" \
                 "$attempt attempts, giving up"
            invalid_stages+=("$stage")
            break
        fi
        attempt=$((attempt + 1))
        warn "retrying stage $stage (attempt $attempt/$STAGE_RETRIES)"
    done
    if [ "$rc" != 0 ] && [ "$rc" != 2 ]; then
        failed_stages+=("$stage")
    fi
done

if [ "$dry_run" = 1 ]; then
    info "Dry run complete. Configurations are in $RESULTS_DIR."
    exit 0
fi

###
### Clean up, unless asked to keep the last stage running.
###
if [ "$keep_last" = 0 ]; then
    info "Final cleanup ..."
    $SUDO "$SCRIPT_DIR/reset-node.sh" -q >> "$RUN_LOG" 2>&1 ||
        warn "final reset reported problems"
else
    info "Keeping the last stage's policy and workloads running (-k)."
fi

###
### Summary
###
info "=============================================================="
info "Results: $CSV_FILE"
info "=============================================================="
csv_summary "$CSV_FILE" | tee "$RESULTS_DIR/summary.txt"

stages_with_data="$(awk -F, 'NR > 1 { print $2 }' "$CSV_FILE" | sort -u | wc -l)"
info "Stages with measurements: $stages_with_data / ${#run_stages[@]}"
if [ ${#invalid_stages[@]} -gt 0 ]; then
    warn "stages left out of the CSV, having measured an unconfigured" \
         "system: ${invalid_stages[*]}"
fi
if [ ${#failed_stages[@]} -gt 0 ]; then
    warn "stages that failed or produced no measurements: ${failed_stages[*]}"
fi
if [ ${#failed_stages[@]} -gt 0 ] || [ ${#invalid_stages[@]} -gt 0 ]; then
    warn "see $RUN_LOG and the stage directories for details"
    exit 1
fi
