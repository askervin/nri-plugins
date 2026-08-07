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
#   cpu   busy loops on the CPU
#   mem   memory bandwidth
#   both  CPU and memory bandwidth
#   none  no background workload at all
NOISE_WORKLOAD="${NOISE_WORKLOAD:-both}"
NOISE_REPLICAS="${NOISE_REPLICAS:-}"
NOISE_CPU_REQUEST="${NOISE_CPU_REQUEST:-1}"
NOISE_MEM_REQUEST="${NOISE_MEM_REQUEST:-512Mi}"
NOISE_LABEL_KEY="${NOISE_LABEL_KEY:-latency}"
NOISE_LABEL_VALUE="${NOISE_LABEL_VALUE:-noise}"
NOISE_DEPLOYMENT_NAME="${NOISE_DEPLOYMENT_NAME:-stress-ng-noise}"
NOISE_SETTLE_SECONDS="${NOISE_SETTLE_SECONDS:-15}"

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
  NOISE_WORKLOAD       cpu|mem|both|none (default: $NOISE_WORKLOAD)
  NOISE_REPLICAS       background containers (default: CPUs/2)
  CHART                balloons helm chart path or name
  PLUGIN_IMAGE         override plugin image, as name:tag
  ALLOW_PCT            non-empty: helm --set allowPCT=true
  PATCH_RUNTIME_CONFIG non-empty: let the chart rewrite the runtime
                       configuration to enable NRI (default: only when
                       the runtime reports NRI disabled)
  DISABLED_CSTATES     C-states to disable (default: C1E,C6)
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
node_cpus="$(nproc)"
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
case "$NOISE_WORKLOAD" in
    cpu)  NOISE_ARGS="${NOISE_ARGS:---cpu 1 --timeout 0}" ;;
    mem)  NOISE_ARGS="${NOISE_ARGS:---vm 1 --vm-bytes 256M --vm-keep --timeout 0}" ;;
    both) NOISE_ARGS="${NOISE_ARGS:---cpu 1 --vm 1 --vm-bytes 256M --vm-keep --timeout 0}" ;;
    none) NOISE_ARGS="" ;;
    *)    error "invalid NOISE_WORKLOAD: $NOISE_WORKLOAD (cpu|mem|both|none)" ;;
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

# node_state_snapshot FILE - record the hardware state actually in
# effect, so results can be checked against what was intended.
node_state_snapshot() {
    local out="$1"
    {
        echo "=== date ==="
        date -Is
        echo "=== kernel ==="
        uname -a
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
        if command -v intel-speed-select >/dev/null 2>&1; then
            intel-speed-select core-power get-config 2>&1 | head -60
        else
            echo "intel-speed-select not available"
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
        kubectl logs -n "$HELM_NAMESPACE" "daemonset/$HELM_RELEASE" \
            --tail=-1 > "$stage_dir/nri-resource-policy.log" 2>&1
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
        # Some IRQ affinities cannot be changed at all: the kernel
        # manages them itself and makes smp_affinity_list read-only even
        # for root. Typical examples are the per-queue MSI-X interrupts
        # of virtio devices. If such an IRQ happens to sit on a CPU the
        # stage wanted to isolate, the isolation is incomplete, which
        # the latencies will show but nothing else would explain.
        local irq_failed
        irq_failed="$(grep -c "failed to set affinity of irq" \
            "$stage_dir/nri-resource-policy.log" 2>/dev/null || true)"
        if [ "${irq_failed:-0}" -gt 0 ]; then
            warn "$irq_failed IRQ affinity updates were refused by the kernel," \
                 "IRQ isolation is incomplete"
            echo "irq_affinity_failures=$irq_failed" >> "$stage_dir/stage-env.txt"
        fi
    fi
    kubectl get pods -n "$BENCH_NAMESPACE" -o wide \
        > "$stage_dir/pods.txt" 2>&1
    node_state_snapshot "$stage_dir/node-state.txt"

    # Effective cpusets of the benchmark and noise containers, to
    # confirm the balloons actually took effect.
    if [ -x "$SCRIPT_DIR/../kube-cgroups" ]; then
        $SUDO "$SCRIPT_DIR/../kube-cgroups" -n "$BENCH_NAMESPACE" \
            -f 'cpuset.cpus.effective|cpuset.mems.effective' \
            > "$stage_dir/cgroups.txt" 2>&1
    fi

    ###
    ### 6. Append to the CSV.
    ###
    local measurements=0
    if [ -f "$stage_dir/sleep-accuracy.log" ]; then
        csv_append_stage "$stage_dir/sleep-accuracy.log" \
                         "$(cat "$stage_dir/config-row.csv")" "$CSV_FILE"
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
stage_index=0
for stage in "${run_stages[@]}"; do
    stage_index=$((stage_index + 1))
    # Keep the console output and the run log in sync, but read the
    # exit status of run_stage itself rather than of tee.
    run_stage "$stage_index" "$stage" 2>&1 | tee -a "$RUN_LOG"
    if [ "${PIPESTATUS[0]}" != 0 ]; then
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
if [ ${#failed_stages[@]} -gt 0 ]; then
    warn "stages that failed or produced no measurements: ${failed_stages[*]}"
    warn "see $RUN_LOG and the stage directories for details"
    exit 1
fi
