#!/bin/bash

# build-images.sh - build the benchmark container images on this node.
#
# Builds the workload images with podman or docker, whichever is
# available, and imports them into the containerd k8s.io namespace, so
# that Kubernetes can run them with imagePullPolicy: Never and no
# registry in the measurement path:
#
#   localhost/sleep-accuracy:latest  the wakeup latency benchmark tool
#   localhost/stress-ng:latest       the background workload
#   localhost/openssl:latest         the cipher throughput workload
#
# The redis workload uses the upstream docker.io/library/redis image
# rather than a locally built one, since nothing in it needs building.
# It is pulled straight into containerd's k8s.io namespace, so the Job
# can still run without the kubelet reaching a registry.
#
# Run this once per node before run-benchmark.sh. Re-running rebuilds
# the images. With no options, everything is built.

set -e -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="${TOOL_DIR:-$(cd "$SCRIPT_DIR/../sleep-accuracy" && pwd)}"

SLEEP_ACCURACY_IMAGE="${SLEEP_ACCURACY_IMAGE:-localhost/sleep-accuracy:latest}"
STRESS_NG_IMAGE="${STRESS_NG_IMAGE:-localhost/stress-ng:latest}"
OPENSSL_IMAGE="${OPENSSL_IMAGE:-localhost/openssl:latest}"
REDIS_IMAGE="${REDIS_IMAGE:-docker.io/library/redis:7-alpine}"

usage() {
    cat <<EOF
Usage: build-images.sh [options]

Builds the benchmark container images and imports them into containerd.
With no options, all of them.

Options:
  -s          only the sleep-accuracy image
  -n          only the stress-ng image
  -o          only the openssl image
  -r          only pull the redis image
  -h          show this help

Environment:
  TOOL_DIR               directory with sleep-accuracy.c and Makefile
                         (default: $TOOL_DIR)
  SLEEP_ACCURACY_IMAGE   default: $SLEEP_ACCURACY_IMAGE
  STRESS_NG_IMAGE        default: $STRESS_NG_IMAGE
  OPENSSL_IMAGE          default: $OPENSSL_IMAGE
  REDIS_IMAGE            default: $REDIS_IMAGE
  BUILDER                podman or docker (default: whichever is found)
EOF
}

build_sleep_accuracy=1
build_stress_ng=1
build_openssl=1
pull_redis=1

# Any explicit selection turns the others off, so that -s still means
# "only this one" and two flags mean "these two". Collected first and
# applied afterwards, because deciding inside the loop would make -s -o
# mean whichever of them came last.
selected=0
declare -A want=()
while getopts "snorh" opt; do
    case "$opt" in
        s|n|o|r) selected=1; want[$opt]=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
if [ "$selected" = 1 ]; then
    build_sleep_accuracy="${want[s]:-0}"
    build_stress_ng="${want[n]:-0}"
    build_openssl="${want[o]:-0}"
    pull_redis="${want[r]:-0}"
fi

error() {
    echo "build-images.sh: $*" >&2
    exit 1
}

# Either builder can produce the images. Only the save syntax differs,
# so pick one here and branch on it in import_to_containerd.
BUILDER="${BUILDER:-}"
if [ -z "$BUILDER" ]; then
    for candidate in podman docker; do
        command -v "$candidate" >/dev/null && { BUILDER="$candidate"; break; }
    done
fi
[ -n "$BUILDER" ] || error "neither podman nor docker found, cannot build images"
command -v "$BUILDER" >/dev/null || error "BUILDER=$BUILDER not found"
echo "### Building images with $BUILDER."

# BUILD_ARGS - the proxy environment, forwarded into the build.
#
# Neither builder passes the invoking shell's proxy variables into a RUN
# step, so on a node that only reaches the internet through a proxy the
# package installs in the Dockerfiles hang with no error and no output
# until something times out. Passed as build args, which the base images'
# package managers read from the environment, so an unproxied node is
# unaffected: an unset variable is simply not passed.
BUILD_ARGS=()
for var in http_proxy https_proxy ftp_proxy no_proxy \
           HTTP_PROXY HTTPS_PROXY FTP_PROXY NO_PROXY; do
    [ -n "${!var:-}" ] && BUILD_ARGS+=(--build-arg "$var=${!var}")
done
if [ ${#BUILD_ARGS[@]} -gt 0 ]; then
    echo "### Forwarding the proxy environment into the build" \
         "(${#BUILD_ARGS[@]} build args)."
fi

# import_to_containerd IMAGE - make IMAGE available to kubelet.
#
# Kubernetes talks to containerd, which has its own image store,
# separate from the builder's. Export from the builder and import into
# the k8s.io namespace of containerd.
import_to_containerd() {
    local image="$1"
    local tarball
    tarball="$(mktemp -t "$(basename "${image%%:*}").XXXXXX.tar")"
    echo "### Exporting $image ..."
    if [ "$BUILDER" = podman ]; then
        podman save --format docker-archive -o "$tarball" "$image"
    else
        # docker save always writes a docker archive, and unlike podman
        # it has no --format option.
        docker save -o "$tarball" "$image"
    fi
    echo "### Importing $image into containerd (namespace k8s.io) ..."
    # --digests avoids "ctr: content digest not found" on some versions.
    sudo ctr -n k8s.io images import --no-unpack=false "$tarball"
    rm -f "$tarball"
}

if [ "$build_sleep_accuracy" = 1 ]; then
    [ -f "$TOOL_DIR/sleep-accuracy.c" ] ||
        error "$TOOL_DIR/sleep-accuracy.c not found, set TOOL_DIR"
    echo "### Building $SLEEP_ACCURACY_IMAGE from $TOOL_DIR ..."
    # Build context is the tool directory, so that the Dockerfile can
    # COPY the sources, but the Dockerfile itself lives here.
    "$BUILDER" build "${BUILD_ARGS[@]}" \
        -f "$SCRIPT_DIR/Dockerfile.sleep-accuracy" \
        -t "$SLEEP_ACCURACY_IMAGE" \
        "$TOOL_DIR"
    import_to_containerd "$SLEEP_ACCURACY_IMAGE"
fi

if [ "$build_stress_ng" = 1 ]; then
    echo "### Building $STRESS_NG_IMAGE ..."
    "$BUILDER" build "${BUILD_ARGS[@]}" \
        -f "$SCRIPT_DIR/Dockerfile.stress-ng" \
        -t "$STRESS_NG_IMAGE" \
        "$SCRIPT_DIR"
    import_to_containerd "$STRESS_NG_IMAGE"
fi

if [ "$build_openssl" = 1 ]; then
    echo "### Building $OPENSSL_IMAGE ..."
    "$BUILDER" build "${BUILD_ARGS[@]}" \
        -f "$SCRIPT_DIR/Dockerfile.openssl" \
        -t "$OPENSSL_IMAGE" \
        "$SCRIPT_DIR"
    import_to_containerd "$OPENSSL_IMAGE"
fi

if [ "$pull_redis" = 1 ]; then
    # Straight into containerd's own namespace rather than through the
    # builder and an export: there is nothing to build, and this way the
    # image is present for imagePullPolicy IfNotPresent without the
    # kubelet needing a registry at measurement time.
    echo "### Pulling $REDIS_IMAGE into containerd (namespace k8s.io) ..."
    sudo ctr -n k8s.io images pull "$REDIS_IMAGE"
fi

echo "### Done. Images in containerd:"
sudo ctr -n k8s.io images ls -q |
    grep -E 'sleep-accuracy|stress-ng|openssl|redis' || true
