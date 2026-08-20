#!/bin/bash

# apps/redis.sh - latency-sensitive request/response service.
#
# A redis server in the balloon under test, and redis-benchmark driving
# it, as Intel's optimization-zone quick start measures a dedicated
# balloon against a shared one. What comes out is a request latency
# distribution and a request rate, so unlike the other two applications
# this one measures a latency that includes a full network round trip and
# a scheduler wakeup at both ends.
#
# THE CLIENT'S PLACEMENT IS THE DESIGN DECISION HERE.
#
# A measured round trip is client wakeup + network + server work + server
# wakeup. Put the load generator in the noise or the default balloon and
# it contributes its own delay to every stage equally badly, so a ladder
# that is working flattens into a false negative. Worse, in the
# max-freq-turbo-prio stage a client in the "other" cpuClass is capped at
# base frequency, so the stage would look like a regression caused by its
# own instrument.
#
# So the client gets a balloon that NO STAGE CONFIGURES: dedicated CPUs,
# no cpuClass, no scheduling class, identical in all eight stages. Its
# stage-independence is exactly what lets a change in p99 be attributed
# to the server's configuration. The consequence, stated rather than
# hidden: the max-freq-turbo-prio stage's "every other class capped at
# base" is no longer literally true of the whole node, because the client
# is deliberately exempt.
#
# The subject of every state check is the SERVER, not the client: the
# server is what sits in the balloon the ladder configures.
#
# Two caveats worth carrying into the campaign notes. redis-benchmark
# reports milliseconds with three decimals, so every latency here is an
# exact multiple of 1000 ns and the quantisation must not be read as
# jitter. And the client is a single event loop, so its own p99 floor is
# part of every figure; memtier_benchmark would give real percentiles and
# its own pinning, which is why REDIS_CLIENT_ARGS is a variable.

app_redis_defaults() {
    APP_NAME=redis
    APP_LOG=redis.log
    APP_JOB_NAME="${REDIS_CLIENT_JOB_NAME:-redis-client}"
    APP_POD_SELECTOR="app=redis-client"
    # The server, not the client: the server is in the balloon under test.
    REDIS_SERVER_NAME="${REDIS_SERVER_NAME:-redis-server}"
    APP_SUBJECT_POD="$REDIS_SERVER_NAME"
    APP_SUBJECT_PROCESS=redis-server

    REDIS_IMAGE="${REDIS_IMAGE:-docker.io/library/redis:7-alpine}"
    REDIS_IMAGE_PULL_POLICY="${REDIS_IMAGE_PULL_POLICY:-IfNotPresent}"
    REDIS_PORT="${REDIS_PORT:-6379}"
    REDIS_CLIENTS="${REDIS_CLIENTS:-50}"
    REDIS_REQUESTS="${REDIS_REQUESTS:-200000}"
    REDIS_TESTS="${REDIS_TESTS:-get}"
    REDIS_CLIENT_ARGS="${REDIS_CLIENT_ARGS:--n $REDIS_REQUESTS -c $REDIS_CLIENTS -t $REDIS_TESTS}"
    REDIS_ROUNDS="${REDIS_ROUNDS:-${BENCH_REPEATS:-3}}"
    REDIS_CLIENT_CPUS="${REDIS_CLIENT_CPUS:-2}"
    REDIS_CLIENT_MEM_REQUEST="${REDIS_CLIENT_MEM_REQUEST:-256Mi}"
    # REDIS_HOST_NETWORK puts both ends on the host network and the
    # client on 127.0.0.1, which takes CNI variability out of the
    # measurement at the cost of being less representative. Either way
    # the network path is a constant added to every stage, so the
    # ladder's differences survive it.
    if [ -n "${REDIS_HOST_NETWORK:-}" ]; then
        REDIS_SERVER_HOST_NETWORK=true
        REDIS_CLIENT_HOST_NETWORK=true
    else
        REDIS_SERVER_HOST_NETWORK=false
        REDIS_CLIENT_HOST_NETWORK=false
    fi

    APP_ARGS="$REDIS_CLIENT_ARGS"
    APP_NEEDS_CLIENT=1

    # The client balloon. Set here rather than in stages.sh because it is
    # a property of this application's measurement method, not of any
    # stage: gen-balloons-config.sh emits it only when CLIENT_BTYPE_NAME
    # is set, so no other application is affected.
    CLIENT_BTYPE_NAME="${CLIENT_BTYPE_NAME:-client}"
    CLIENT_LABEL_KEY="${CLIENT_LABEL_KEY:-latency}"
    CLIENT_LABEL_VALUE="${CLIENT_LABEL_VALUE:-client}"
    CLIENT_MINCPUS="${CLIENT_MINCPUS:-$REDIS_CLIENT_CPUS}"
    CLIENT_MAXCPUS="${CLIENT_MAXCPUS:-$REDIS_CLIENT_CPUS}"
    CLIENT_PREFERNEWBALLOONS="${CLIENT_PREFERNEWBALLOONS:-true}"
    CLIENT_ALLOCATORPRIORITY="${CLIENT_ALLOCATORPRIORITY:-normal}"
}

# app_redis_start STAGE_DIR - bring up the server and find it.
#
# The server is a Deployment rather than part of the Job because it has to
# outlive every round and be readable by the state checks throughout, and
# because its cgroup then does not have to be raced for the way a
# short-lived Job's does.
#
# The client is given the server's pod IP directly rather than a Service
# name: one less moving part, and no kube-proxy hop inside the
# measurement.
app_redis_start() {
    local stage_dir="$1"
    instantiate "$SCRIPT_DIR/apps/redis-server.yaml.in" \
        > "$stage_dir/redis-server.yaml"
    kubectl apply -f "$stage_dir/redis-server.yaml" >/dev/null ||
        { warn "cannot deploy the redis server"; return 1; }
    if ! kubectl rollout status -n "$BENCH_NAMESPACE" \
             "deployment/$REDIS_SERVER_NAME" --timeout=180s >/dev/null; then
        warn "the redis server did not become ready"
        return 1
    fi

    if [ -n "${REDIS_HOST_NETWORK:-}" ]; then
        REDIS_HOST=127.0.0.1
    else
        REDIS_HOST="$(kubectl get pod -n "$BENCH_NAMESPACE" \
                          -l app=redis-server \
                          -o jsonpath='{.items[0].status.podIP}' 2>/dev/null)"
        [ -n "$REDIS_HOST" ] || { warn "no pod IP for the redis server"; return 1; }
    fi
    info "redis server at $REDIS_HOST:$REDIS_PORT"

    # Built here, not in _defaults, because it needs the server's address.
    # \r to \n so the progress redraws do not arrive as one enormous line.
    app_shell "set -u
redis-cli -h $REDIS_HOST -p $REDIS_PORT info server | grep -i redis_version
r=1
while [ \$r -le $REDIS_ROUNDS ]; do
    echo \"=== round \$r\"
    redis-benchmark -h $REDIS_HOST -p $REDIS_PORT $REDIS_CLIENT_ARGS 2>&1 |
        tr '\\r' '\\n'
    r=\$((r + 1))
done
echo '=== done'"
    return 0
}

app_redis_manifest() {
    instantiate "$SCRIPT_DIR/apps/redis-client.yaml.in"
}

# app_redis_stop - remove the server, so the next stage starts clean.
app_redis_stop() {
    kubectl delete deployment "$REDIS_SERVER_NAME" -n "$BENCH_NAMESPACE" \
        --ignore-not-found --wait=false >/dev/null 2>&1
    return 0
}

# app_redis_metrics LOGFILE - the benchmark summary as canonical metric
# rows.
#
# The output being parsed:
#
#   ====== GET ======
#   Summary:
#     throughput summary: 108108.11 requests per second
#     latency summary (msec):
#             avg       min       p50       p95       p99       max
#           0.311     0.088     0.303     0.415     0.559     1.303
#
# Percentile names are read from the header line rather than assumed,
# because --precision and the redis release both change which columns
# appear. Milliseconds become nanoseconds so that these latencies share a
# unit, a log axis and a direction with every other latency in the
# archive.
app_redis_metrics() {
    local logfile="$1"
    [ -f "$logfile" ] || return 0
    awk -v clients="${REDIS_CLIENTS:-0}" '
        /^=== round / { round = $3; next }
        # "====== GET ======" names the test the following summary is for.
        /^=+ [A-Za-z]/ && /=+$/ { test = tolower($2); next }
        # "  50 parallel clients" -- the operating point, taken from the
        # output rather than from the environment so that this function
        # gives the same answer over a stored log as it does live.
        /parallel clients/ { clients = $1; next }
        /throughput summary:/ { rps = $3; next }
        # The percentile header, then the row of values under it.
        /latency summary/ { want_header = 1; next }
        want_header {
            nh = NF
            for (i = 1; i <= NF; i++) names[i] = $i
            want_header = 0; want_values = 1; next
        }
        want_values {
            want_values = 0
            if (NF != nh) next
            for (i = 1; i <= nh; i++)
                printf "redis,%s,%s,%s,clients,%s,ns,lower,%.0f\n", \
                       test, round, clients, names[i], $i * 1000000
            if (rps > 0) {
                printf "redis,%s,%s,%s,clients,rps,ops_per_s,higher,%.0f\n", \
                       test, round, clients, rps
                # The same measurement as a cost, so it shares a unit and
                # a direction with the latencies above.
                printf "redis,%s,%s,%s,clients,ns_per_op,ns,lower,%.0f\n", \
                       test, round, clients, 1000000000 / rps
            }
            rps = 0
        }
    ' "$logfile"
}
