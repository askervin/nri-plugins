#!/bin/bash
# Usage: run-all.sh [--image TAR] [--prepare-node] [TEST...]
#
# Deploy nri-dra-driver-cxl in the sliced configuration (deploy.sh) and run
# the tests (default: all test*.sh in this directory), each with its output
# in results/<test>.log. The driver is left deployed sliced.
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
deploy_args=() tests=()
while [ $# -gt 0 ]; do
    case "$1" in
        --image) deploy_args+=(--image "$2"); shift ;;
        --prepare-node) deploy_args+=(--prepare-node) ;;
        *) tests+=("$1") ;;
    esac
    shift
done
[ ${#tests[@]} -gt 0 ] || tests=("$DIR"/test[0-9]*.sh)
mkdir -p "$DIR/results"
"$DIR/deploy.sh" "${deploy_args[@]}" sliced > "$DIR/results/deploy.log" 2>&1 ||
    { cat "$DIR/results/deploy.log"; exit 1; }
rc=0
for t in "${tests[@]}"; do
    name=$(basename "$t" .sh)
    echo "=== running $name"
    "$DIR/$name.sh" > "$DIR/results/$name.log" 2>&1 || rc=1
    sed -n '/^=== /,$p' "$DIR/results/$name.log"
done
exit $rc
