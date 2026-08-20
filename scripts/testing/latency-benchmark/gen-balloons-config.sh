#!/bin/bash

# gen-balloons-config.sh - generate a BalloonsPolicy for latency benchmarking.
#
# Prints a BalloonsPolicy custom resource to stdout. Everything is
# controlled with environment variables, in the spirit of the e2e test
# yaml templates, but written as a plain generator so that deeply
# nested optional fields stay readable.
#
# Every variable is optional. An unset or empty variable means "leave
# the field out of the configuration", which is what the benchmark
# stages rely on: each stage sets only the variables it wants to add on
# top of the previous stage.
#
# Run with -h for the list of variables.

set -u

usage() {
    cat <<'EOF'
Usage: gen-balloons-config.sh > balloons-config.yaml

Generates a BalloonsPolicy custom resource from environment variables.
Unset variables are omitted from the generated configuration.

Policy-level:
  RESERVED_CPU                  reservedResources.cpu (default: 1000m)
  AVAILABLE_CPU                 availableResources.cpu
  PINCPU, PINMEMORY             pinCPU, pinMemory (default: true, false)
  ALLOCATORTOPOLOGYBALANCING    allocatorTopologyBalancing (default: false)
  IDLECPUCLASS                  idleCPUClass
  TURBODOMAIN                   turboDomain (package|system)
  LOG_DEBUG_CPU                 non-empty: add cpu+cpuclass debug logging
  LOG_DEBUG_IRQ                 non-empty: add irq debug logging

Benchmark balloon (runs the application under test):
  BENCH_BTYPE_NAME              balloon type name (default: latency-critical)
  BENCH_LABEL_KEY/VALUE         pod label matched (default: latency/critical)
  BENCH_MINCPUS, BENCH_MAXCPUS  balloon size (default: 1, 2)
  BENCH_MINBALLOONS             pre-created instances
  BENCH_PREFERNEWBALLOONS       true: dedicated CPUs (default: false)
  BENCH_ALLOCATORPRIORITY       default: high
  BENCH_SCHEDULINGCLASS         name from SCHEDCLASS_* below
  BENCH_CPUCLASS                name from CPUCLASS_BENCH_* below
  BENCH_SHAREIDLECPUS           shareIdleCPUsInSame
  BENCH_HIDEHYPERTHREADS        hideHyperthreads
  BENCH_LOADS                   single load class name
  BENCH_IRQCLAIM                comma-separated irqClaim patterns/numbers
  BENCH_IRQMODE                 irqMode (sink|isolate)
  BENCH_BTYPE_SKIP              non-empty: do not define this type at all,
                                the benchmark falls back to the default balloon

Noise balloon (runs stress-ng):
  NOISE_BTYPE_SKIP              non-empty: no separate noise type, noise
                                shares the default balloon
  NOISE_BTYPE_NAME              default: noise
  NOISE_LABEL_KEY/VALUE         default: latency/noise
  NOISE_MINCPUS, NOISE_MAXCPUS, NOISE_ALLOCATORPRIORITY (default: low),
  NOISE_PREFERNEWBALLOONS, NOISE_CPUCLASS, NOISE_SCHEDULINGCLASS,
  NOISE_SHAREIDLECPUS, NOISE_LOADS, NOISE_IRQCLAIM, NOISE_IRQMODE

Client balloon (emitted only if CLIENT_BTYPE_NAME is set, which an
application module does when its measurement needs a load generator):
  CLIENT_BTYPE_NAME             balloon type name
  CLIENT_LABEL_KEY/VALUE        pod label matched (default: latency/client)
  CLIENT_MINCPUS, CLIENT_MAXCPUS, CLIENT_ALLOCATORPRIORITY (default: normal),
  CLIENT_PREFERNEWBALLOONS (default: true), CLIENT_CPUCLASS,
  CLIENT_SCHEDULINGCLASS, CLIENT_SHAREIDLECPUS, CLIENT_IRQMODE

Default balloon:
  DEFAULT_MINCPUS, DEFAULT_MAXCPUS, DEFAULT_CPUCLASS,
  DEFAULT_SHAREIDLECPUS, DEFAULT_LOADS, DEFAULT_IRQCLAIM, DEFAULT_IRQMODE

loadClasses (emitted only if LOADCLASS_NAME is set):
  LOADCLASS_NAME, LOADCLASS_LEVEL (default: l2cache),
  LOADCLASS_OVERLOADS (default: false)

schedulingClasses (emitted only if SCHEDCLASS_NAME is set):
  SCHEDCLASS_NAME, SCHEDCLASS_POLICY (default: fifo),
  SCHEDCLASS_PRIORITY (default: 80), SCHEDCLASS_IOCLASS, SCHEDCLASS_IOPRIORITY

cpuClasses (each emitted only if its _NAME is set):
  CPUCLASS_BENCH_NAME  + _MINFREQ _MAXFREQ _UNCOREMINFREQ _UNCOREMAXFREQ
                         _DISABLEDCSTATES _TURBOPRIORITY _EPP _FREQGOVERNOR
                         _PCTPRIORITY _PCTMINFREQ _PCTMAXFREQ
  CPUCLASS_OTHER_NAME  + same suffixes
  CPUCLASS_IDLE_NAME   + same suffixes
EOF
}

[ "${1:-}" = "-h" ] && { usage; exit 0; }

# opt FIELD VALUE [INDENT] - print "FIELD: VALUE" if VALUE is non-empty.
opt() {
    local field="$1" value="$2" indent="${3:-    }"
    [ -n "$value" ] && echo "${indent}${field}: ${value}"
    return 0
}

# optq - like opt, but quotes the value. Needed for frequencies, where
# YAML would otherwise read "2900000" as an integer and symbolic names
# like turbo must stay strings.
optq() {
    local field="$1" value="$2" indent="${3:-    }"
    [ -n "$value" ] && echo "${indent}${field}: \"${value}\""
    return 0
}

# opt_list FIELD VALUE - print a single-item YAML list if VALUE is non-empty.
opt_list() {
    local field="$1" value="$2" indent="${3:-    }"
    if [ -n "$value" ]; then
        echo "${indent}${field}:"
        echo "${indent}- ${value}"
    fi
    return 0
}

# opt_qlist FIELD VALUE - print a YAML list of quoted items, one per
# comma-separated item in VALUE. Used for irqClaim, whose items are IRQ
# numbers or /proc/interrupts patterns like "*eth0 *": they contain
# wildcards and spaces, so they must stay quoted strings.
opt_qlist() {
    local field="$1" value="$2" indent="${3:-    }"
    [ -z "$value" ] && return 0
    echo "${indent}${field}:"
    local item
    while IFS= read -r item; do
        [ -n "$item" ] && echo "${indent}- \"${item}\""
    done <<< "${value//,/$'\n'}"
    return 0
}

# cpu_class NAME_VAR_PREFIX - emit one cpuClasses entry if its name is set.
cpu_class() {
    local prefix="$1"
    local name
    eval "name=\${${prefix}_NAME:-}"
    [ -z "$name" ] && return 0

    local minfreq maxfreq uncoremin uncoremax cstates turboprio epp gov
    local pctprio pctmin pctmax
    eval "minfreq=\${${prefix}_MINFREQ:-}"
    eval "maxfreq=\${${prefix}_MAXFREQ:-}"
    eval "uncoremin=\${${prefix}_UNCOREMINFREQ:-}"
    eval "uncoremax=\${${prefix}_UNCOREMAXFREQ:-}"
    eval "cstates=\${${prefix}_DISABLEDCSTATES:-}"
    eval "turboprio=\${${prefix}_TURBOPRIORITY:-}"
    eval "epp=\${${prefix}_EPP:-}"
    eval "gov=\${${prefix}_FREQGOVERNOR:-}"
    eval "pctprio=\${${prefix}_PCTPRIORITY:-}"
    eval "pctmin=\${${prefix}_PCTMINFREQ:-}"
    eval "pctmax=\${${prefix}_PCTMAXFREQ:-}"

    echo "  - name: ${name}"
    optq minFreq "$minfreq"
    optq maxFreq "$maxfreq"
    optq uncoreMinFreq "$uncoremin"
    optq uncoreMaxFreq "$uncoremax"
    # disabledCstates takes a comma-separated list of C-state names,
    # for example "C6,C8,C10". The special value "none" emits an empty
    # list, which explicitly re-enables all C-states.
    if [ "$cstates" = "none" ]; then
        echo "    disabledCstates: []"
    elif [ -n "$cstates" ]; then
        echo "    disabledCstates: [${cstates//,/, }]"
    fi
    opt energyPerformancePreference "$epp"
    opt freqGovernor "$gov"
    opt turboPriority "$turboprio"
    opt pctPriority "$pctprio"
    optq pctMinFreq "$pctmin"
    optq pctMaxFreq "$pctmax"
    return 0
}

cat <<EOF
apiVersion: config.nri/v1alpha1
kind: BalloonsPolicy
metadata:
  name: default
  namespace: kube-system
spec:
  pinCPU: ${PINCPU:-true}
  pinMemory: ${PINMEMORY:-false}
  allocatorTopologyBalancing: ${ALLOCATORTOPOLOGYBALANCING:-false}
  reservedResources:
    cpu: ${RESERVED_CPU:-1000m}
EOF

if [ -n "${AVAILABLE_CPU:-}" ]; then
    echo "  availableResources:"
    echo "    cpu: ${AVAILABLE_CPU}"
fi
opt idleCPUClass "${IDLECPUCLASS:-}" "  "
opt turboDomain "${TURBODOMAIN:-}" "  "

echo "  balloonTypes:"

# Benchmark balloon. Skipped in the stage where sleep-accuracy is
# supposed to land in the default balloon together with other workloads.
if [ -z "${BENCH_BTYPE_SKIP:-}" ]; then
    cat <<EOF
  - name: ${BENCH_BTYPE_NAME:-latency-critical}
    matchExpressions:
    - key: pod/labels/${BENCH_LABEL_KEY:-latency}
      operator: In
      values:
      - ${BENCH_LABEL_VALUE:-critical}
    minCPUs: ${BENCH_MINCPUS:-1}
    maxCPUs: ${BENCH_MAXCPUS:-2}
    preferNewBalloons: ${BENCH_PREFERNEWBALLOONS:-false}
    allocatorPriority: ${BENCH_ALLOCATORPRIORITY:-high}
EOF
    opt minBalloons "${BENCH_MINBALLOONS:-}"
    opt hideHyperthreads "${BENCH_HIDEHYPERTHREADS:-}"
    opt schedulingClass "${BENCH_SCHEDULINGCLASS:-}"
    opt cpuClass "${BENCH_CPUCLASS:-}"
    opt shareIdleCPUsInSame "${BENCH_SHAREIDLECPUS:-}"
    opt_list loads "${BENCH_LOADS:-}"
    opt_qlist irqClaim "${BENCH_IRQCLAIM:-}"
    opt irqMode "${BENCH_IRQMODE:-}"
fi

# Noise balloon for the stress-ng background workload.
if [ -z "${NOISE_BTYPE_SKIP:-}" ]; then
    cat <<EOF
  - name: ${NOISE_BTYPE_NAME:-noise}
    matchExpressions:
    - key: pod/labels/${NOISE_LABEL_KEY:-latency}
      operator: In
      values:
      - ${NOISE_LABEL_VALUE:-noise}
    allocatorPriority: ${NOISE_ALLOCATORPRIORITY:-low}
    preferNewBalloons: ${NOISE_PREFERNEWBALLOONS:-false}
EOF
    opt minCPUs "${NOISE_MINCPUS:-}"
    opt maxCPUs "${NOISE_MAXCPUS:-}"
    opt cpuClass "${NOISE_CPUCLASS:-}"
    opt schedulingClass "${NOISE_SCHEDULINGCLASS:-}"
    opt shareIdleCPUsInSame "${NOISE_SHAREIDLECPUS:-}"
    opt_list loads "${NOISE_LOADS:-}"
    opt_qlist irqClaim "${NOISE_IRQCLAIM:-}"
    opt irqMode "${NOISE_IRQMODE:-}"
fi

# Client balloon, for an application whose measurement needs a load
# generator. Emitted only when an application module asked for it, so
# every other application's configuration is unchanged.
#
# Deliberately NOT configured by any stage: the client is measurement
# apparatus, and its stage-independence is what lets a change in the
# measured latency be attributed to the server's configuration rather
# than to the instrument. See apps/redis.sh for the full argument.
if [ -n "${CLIENT_BTYPE_NAME:-}" ]; then
    cat <<EOF
  - name: ${CLIENT_BTYPE_NAME}
    matchExpressions:
    - key: pod/labels/${CLIENT_LABEL_KEY:-latency}
      operator: In
      values:
      - ${CLIENT_LABEL_VALUE:-client}
    preferNewBalloons: ${CLIENT_PREFERNEWBALLOONS:-true}
    allocatorPriority: ${CLIENT_ALLOCATORPRIORITY:-normal}
EOF
    opt minCPUs "${CLIENT_MINCPUS:-}"
    opt maxCPUs "${CLIENT_MAXCPUS:-}"
    opt cpuClass "${CLIENT_CPUCLASS:-}"
    opt schedulingClass "${CLIENT_SCHEDULINGCLASS:-}"
    opt shareIdleCPUsInSame "${CLIENT_SHAREIDLECPUS:-}"
    opt irqMode "${CLIENT_IRQMODE:-}"
fi

# Catch-all balloon.
echo "  - name: default"
opt minCPUs "${DEFAULT_MINCPUS:-}"
opt maxCPUs "${DEFAULT_MAXCPUS:-}"
opt cpuClass "${DEFAULT_CPUCLASS:-}"
opt shareIdleCPUsInSame "${DEFAULT_SHAREIDLECPUS:-}"
opt_list loads "${DEFAULT_LOADS:-}"
opt_qlist irqClaim "${DEFAULT_IRQCLAIM:-}"
opt irqMode "${DEFAULT_IRQMODE:-}"

if [ -n "${LOADCLASS_NAME:-}" ]; then
    cat <<EOF
  loadClasses:
  - name: ${LOADCLASS_NAME}
    level: ${LOADCLASS_LEVEL:-l2cache}
    overloadsLevelInBalloon: ${LOADCLASS_OVERLOADS:-false}
EOF
fi

if [ -n "${SCHEDCLASS_NAME:-}" ]; then
    cat <<EOF
  schedulingClasses:
  - name: ${SCHEDCLASS_NAME}
    policy: ${SCHEDCLASS_POLICY:-fifo}
    priority: ${SCHEDCLASS_PRIORITY:-80}
EOF
    opt ioClass "${SCHEDCLASS_IOCLASS:-}"
    opt ioPriority "${SCHEDCLASS_IOPRIORITY:-}"
fi

if [ -n "${CPUCLASS_BENCH_NAME:-}${CPUCLASS_OTHER_NAME:-}${CPUCLASS_IDLE_NAME:-}" ]; then
    echo "  cpuClasses:"
    cpu_class CPUCLASS_BENCH
    cpu_class CPUCLASS_OTHER
    cpu_class CPUCLASS_IDLE
fi

cat <<EOF
  log:
    debug:
    - policy
EOF
if [ -n "${LOG_DEBUG_CPU:-}" ]; then
    echo "    - cpu"
    echo "    - cpuclass"
fi
if [ -n "${LOG_DEBUG_IRQ:-}" ]; then
    echo "    - irq"
fi
echo "    source: true"
