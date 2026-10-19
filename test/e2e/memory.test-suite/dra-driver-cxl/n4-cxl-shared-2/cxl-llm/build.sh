#!/bin/bash
# Build cxl-llm (cxl-llm.cpp next to this script) on llama.cpp
# $LLAMA_CPP_COMMIT as one static, CPU-only binary for x86-64 CPUs with
# AVX2, FMA, F16C and BMI2 (no AVX-512, no GPU, no network code), in a
# fedora:43 container (podman). Print the path of the binary.
#
# Usage: build.sh
#
# Environment:
#   CACHE_DIR      cache directory, default ~/.cache/nri-plugins/e2e. The
#                  binary is $CACHE_DIR/llm/cxl-llm-<hash>/cxl-llm, <hash> of
#                  cxl-llm.cpp, this script, the llama.cpp commit and the
#                  digest of the build image; an existing one is not built
#                  again. Next to it, source.txt has the image digest and
#                  the toolchain versions, build.log the build output; the
#                  output of a failed build is $CACHE_DIR/llm/build-failed.log.
#   LLAMA_CPP_SRC  a git repository of llama.cpp that has the commit, for
#                  instance a local clone. Default: $CACHE_DIR/llm/llama.cpp,
#                  which gets the commit from $LLAMA_CPP_URL if it lacks it.
#   http_proxy, https_proxy  passed to the container (dnf)
#
# Time limits: 10 min for fetching llama.cpp and for pulling the image, 30
# min for the build in the container.

set -e -o pipefail

LLAMA_CPP_COMMIT=25a1d63f4346b472e508c6dbd9ab2ed1d81ace2e
LLAMA_CPP_URL=https://github.com/ggml-org/llama.cpp
BUILD_IMAGE=registry.fedoraproject.org/fedora:43

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${CACHE_DIR:-$HOME/.cache/nri-plugins/e2e}"
LLM_CACHE="$CACHE_DIR/llm"

die() {
    echo "build.sh: $*" >&2
    exit 1
}

mkdir -p "$LLM_CACHE" || die "cannot create $LLM_CACHE"
if ! podman image exists "$BUILD_IMAGE"; then
    echo "build.sh: pulling $BUILD_IMAGE" >&2
    timeout 600 podman pull -q "$BUILD_IMAGE" >&2 || die "cannot pull $BUILD_IMAGE"
fi
digest=$(podman image inspect --format '{{.Digest}}' "$BUILD_IMAGE") || die "cannot inspect $BUILD_IMAGE"
hash=$( { sha256sum "$SRC_DIR/cxl-llm.cpp" "$SRC_DIR/build.sh" | cut -d' ' -f1; echo "$LLAMA_CPP_COMMIT"; echo "$digest"; } | sha256sum | cut -c1-16)
out="$LLM_CACHE/cxl-llm-$hash"
if [ -x "$out/cxl-llm" ]; then
    echo "$out/cxl-llm"
    exit 0
fi

repo="${LLAMA_CPP_SRC:-$LLM_CACHE/llama.cpp}"
if ! git -C "$repo" cat-file -e "$LLAMA_CPP_COMMIT^{commit}" 2>/dev/null; then
    [ -z "$LLAMA_CPP_SRC" ] || die "LLAMA_CPP_SRC=$LLAMA_CPP_SRC has no commit $LLAMA_CPP_COMMIT"
    echo "build.sh: fetching llama.cpp $LLAMA_CPP_COMMIT from $LLAMA_CPP_URL into $repo" >&2
    mkdir -p "$repo"
    git -C "$repo" init -q
    timeout 600 git -C "$repo" fetch -q --depth 1 "$LLAMA_CPP_URL" "$LLAMA_CPP_COMMIT" >&2 ||
        die "cannot fetch llama.cpp $LLAMA_CPP_COMMIT from $LLAMA_CPP_URL in 10 min"
fi

work=$(mktemp -d "$LLM_CACHE/build.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/llama.cpp" "$work/out"
git -C "$repo" archive "$LLAMA_CPP_COMMIT" | tar -x -C "$work/llama.cpp"
cp "$SRC_DIR/cxl-llm.cpp" "$work/cxl-llm.cpp"

echo "build.sh: building cxl-llm with llama.cpp $LLAMA_CPP_COMMIT in $BUILD_IMAGE ($digest)" >&2
# The container sees only the exported sources (read-only) and the output
# directory. SELinux labels would keep it from reading the bind mounts.
timeout 1800 podman run --rm --security-opt label=disable -e http_proxy -e https_proxy \
    -v "$work/llama.cpp:/src/llama.cpp:ro" -v "$work/cxl-llm.cpp:/src/cxl-llm.cpp:ro" -v "$work/out:/out" \
    "$BUILD_IMAGE" bash -c '
set -e -o pipefail
timeout 900 dnf -y -q install gcc-c++ cmake ninja-build glibc-static libstdc++-static
rpm -q gcc-c++ glibc-static libstdc++-static cmake ninja-build > /out/toolchain.txt
cmake -S /src/llama.cpp -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF -DGGML_STATIC=ON -DGGML_NATIVE=OFF \
    -DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_F16C=ON -DGGML_BMI2=ON \
    -DGGML_OPENMP=OFF -DGGML_BLAS=OFF -DLLAMA_OPENSSL=OFF \
    -DLLAMA_BUILD_COMMON=OFF -DLLAMA_BUILD_TOOLS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
    -DLLAMA_BUILD_SERVER=OFF -DLLAMA_BUILD_APP=OFF -DLLAMA_BUILD_UI=OFF \
    -DLLAMA_BUILD_TESTS=OFF -DGGML_BUILD_TESTS=OFF -DGGML_BUILD_EXAMPLES=OFF
cmake --build /build --target llama
g++ -O2 -std=c++17 -static -I/src/llama.cpp/include -I/src/llama.cpp/ggml/include /src/cxl-llm.cpp -o /out/cxl-llm \
    /build/src/libllama.a /build/ggml/src/libggml.a /build/ggml/src/libggml-cpu.a /build/ggml/src/libggml-base.a \
    -lpthread -lm
strip /out/cxl-llm
' > "$work/build.log" 2>&1 || {
    tail -n 40 "$work/build.log" >&2
    cp "$work/build.log" "$LLM_CACHE/build-failed.log"
    die "the build failed (in 30 min at most), see the lines above and $LLM_CACHE/build-failed.log"
}

mkdir -p "$out.tmp"
mv "$work/out/cxl-llm" "$out.tmp/cxl-llm"
cp "$work/build.log" "$out.tmp/build.log"
{
    echo "llama.cpp $LLAMA_CPP_COMMIT"
    echo "image $BUILD_IMAGE $digest"
    cat "$work/out/toolchain.txt"
    echo "built $(date -Is)"
} > "$out.tmp/source.txt"
rm -f "$LLM_CACHE/build-failed.log"
rm -rf "$out"
mv "$out.tmp" "$out"
echo "$out/cxl-llm"
