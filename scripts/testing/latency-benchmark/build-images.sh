#!/bin/bash

# build-images.sh - build the benchmark container images on this node.
#
# Builds two images with podman or docker, whichever is available, and
# imports them into the containerd k8s.io namespace, so that Kubernetes
# can run them with imagePullPolicy: Never and no registry involved:
#
#   localhost/sleep-accuracy:latest  the latency benchmark tool
#   localhost/stress-ng:latest       the background workload
#
# Run this once per node before run-benchmark.sh. Re-running rebuilds
# the images.

set -e -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="${TOOL_DIR:-$(cd "$SCRIPT_DIR/../sleep-accuracy" && pwd)}"

SLEEP_ACCURACY_IMAGE="${SLEEP_ACCURACY_IMAGE:-localhost/sleep-accuracy:latest}"
STRESS_NG_IMAGE="${STRESS_NG_IMAGE:-localhost/stress-ng:latest}"

usage() {
    cat <<EOF
Usage: build-images.sh [options]

Builds the benchmark container images and imports them into containerd.

Options:
  -s          build only the sleep-accuracy image
  -n          build only the stress-ng image
  -h          show this help

Environment:
  TOOL_DIR               directory with sleep-accuracy.c and Makefile
                         (default: $TOOL_DIR)
  SLEEP_ACCURACY_IMAGE   default: $SLEEP_ACCURACY_IMAGE
  STRESS_NG_IMAGE        default: $STRESS_NG_IMAGE
  BUILDER                podman or docker (default: whichever is found)
EOF
}

build_sleep_accuracy=1
build_stress_ng=1

while getopts "snh" opt; do
    case "$opt" in
        s) build_stress_ng=0 ;;
        n) build_sleep_accuracy=0 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

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
    "$BUILDER" build \
        -f "$SCRIPT_DIR/Dockerfile.sleep-accuracy" \
        -t "$SLEEP_ACCURACY_IMAGE" \
        "$TOOL_DIR"
    import_to_containerd "$SLEEP_ACCURACY_IMAGE"
fi

if [ "$build_stress_ng" = 1 ]; then
    echo "### Building $STRESS_NG_IMAGE ..."
    "$BUILDER" build \
        -f "$SCRIPT_DIR/Dockerfile.stress-ng" \
        -t "$STRESS_NG_IMAGE" \
        "$SCRIPT_DIR"
    import_to_containerd "$STRESS_NG_IMAGE"
fi

echo "### Done. Images in containerd:"
sudo ctr -n k8s.io images ls -q | grep -E 'sleep-accuracy|stress-ng' || true
