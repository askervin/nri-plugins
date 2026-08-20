#!/bin/bash

# apps/openssl.sh - compute-intensive cipher throughput.
#
# "openssl speed" encrypts a buffer in a loop for a fixed wall-clock time
# and reports bytes per second for each of six block sizes. It is pure CPU
# work with no I/O, no network and no warm-up, so what it measures is how
# much work the balloon's CPUs got done -- the quantity the frequency and
# priority stages of the ladder act on most directly. This is the
# measurement the PCT quick start uses to show the HP/LP difference.
#
# Single-threaded by default: -multi is not passed unless OPENSSL_MULTI is
# set. That keeps the premise the sleep-accuracy campaigns rest on, where
# the workload is one thread and the size of the cpuset only decides
# whether the scheduler may migrate it. Setting OPENSSL_MULTI to the CPU
# count is the throughput-maximising alternative and a different
# experiment, not a better default.
#
# Throughput is higher-is-better, which inverts the reading every figure
# in this benchmark is built around. The metric rows therefore carry the
# reciprocal, ns_per_op -- the time to process one block -- alongside the
# raw figure, so the default plots stay lower-is-better nanoseconds on the
# same axis as every latency in the archive. See DESIGN-apps.md.

app_openssl_defaults() {
    APP_NAME=openssl
    APP_LOG=openssl.log
    APP_JOB_NAME="${OPENSSL_JOB_NAME:-openssl}"
    APP_POD_SELECTOR="app=openssl"
    APP_SUBJECT_POD="$APP_JOB_NAME"
    APP_SUBJECT_PROCESS=openssl

    OPENSSL_IMAGE="${OPENSSL_IMAGE:-localhost/openssl:latest}"
    OPENSSL_CIPHER="${OPENSSL_CIPHER:-aes-128-cbc}"
    OPENSSL_SECONDS="${OPENSSL_SECONDS:-5}"
    # Rounds, not repeats inside one invocation: openssl speed has no
    # repeat option, and a fresh process per round is what makes the
    # spread across rounds comparable to sleep-accuracy's -r.
    OPENSSL_ROUNDS="${OPENSSL_ROUNDS:-${BENCH_REPEATS:-3}}"
    OPENSSL_MULTI="${OPENSSL_MULTI:-}"

    local multi=""
    [ -n "$OPENSSL_MULTI" ] && multi=" -multi $OPENSSL_MULTI"
    APP_ARGS="speed -seconds $OPENSSL_SECONDS -evp $OPENSSL_CIPHER$multi"

    # The version goes in the log because a throughput number is only
    # comparable against another one from the same build: which
    # instruction set openssl uses for AES is decided at build time.
    app_shell "set -u
openssl version -a
echo \"=== args $APP_ARGS\"
r=1
while [ \$r -le $OPENSSL_ROUNDS ]; do
    echo \"=== round \$r\"
    openssl $APP_ARGS 2>&1
    r=\$((r + 1))
done
echo '=== done'"
}

app_openssl_manifest() {
    instantiate "$SCRIPT_DIR/apps/openssl.yaml.in"
}

# app_openssl_metrics LOGFILE - the speed table as canonical metric rows.
#
# The output being parsed is a header naming the block sizes and one row
# per cipher holding a figure per size:
#
#   type             16 bytes     64 bytes  ...  16384 bytes
#   AES-128-CBC    1788838.33k  2156328.92k  ...  2221617.97k
#
# The k suffix is 1000 bytes per second and is resolved here, so that the
# unit column says what the value actually is. Block sizes are read from
# the header rather than assumed, because -evp on a different algorithm
# and a different openssl release do not agree on them.
app_openssl_metrics() {
    local logfile="$1"
    [ -f "$logfile" ] || return 0
    awk '
        /^=== round / { round = $3; next }
        # "type    16 bytes    64 bytes ..." -- sizes are every other field.
        /^type +[0-9]+ bytes/ {
            nb = 0
            for (i = 2; i <= NF; i += 2) sizes[++nb] = $i
            next
        }
        # The cipher row: one figure per block size, so NF is nb + 1. A
        # count check rather than a name match, because -evp accepts
        # algorithms whose printed names vary in case and punctuation.
        nb > 0 && NF == nb + 1 && $1 ~ /^[A-Za-z]/ {
            cipher = tolower($1)
            for (i = 1; i <= nb; i++) {
                v = $(i + 1)
                sub(/k$/, "", v)
                bps = v * 1000
                if (bps <= 0) continue
                printf "openssl,%s,%s,%s,block_bytes,throughput,bytes_per_s,higher,%.0f\n", \
                       cipher, round, sizes[i], bps
                # Time to process one block: the same measurement stated
                # as a cost, so it shares a unit, an axis and a direction
                # with every latency in the archive.
                printf "openssl,%s,%s,%s,block_bytes,ns_per_op,ns,lower,%.0f\n", \
                       cipher, round, sizes[i], sizes[i] / bps * 1000000000
            }
        }
    ' "$logfile"
}
