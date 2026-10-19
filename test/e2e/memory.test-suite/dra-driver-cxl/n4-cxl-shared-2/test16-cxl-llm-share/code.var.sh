# An LLM shared through pooled CXL memory: one writer, three readers on two
# nodes of one Kubernetes cluster
#
# A writer puts a small language model (Qwen3-0.6B, a 378 MiB GGUF file)
# into a shared CXL memory device of the pool, and three readers on two
# nodes answer a prompt with that one copy of the model, mapped straight
# from the device.
#
# - The writer claims the device (class cxl-pool-shared) with all of its
#   "hosts": exclusive and writable. It copies the model from its node
#   (VM1, the only node that has the model file) to offset 0 of the devdax
#   device and exits; the host checks the bytes in the backing file of the
#   device.
# - The readers, two on VM2 and one on VM1, each claim the device with
#   DeviceConfig {mode: dax, readOnly: true}: one host each, a read-only
#   device node. They run at the same time; the engine maps the device, so
#   every access to the weights goes to the CXL memory and nothing is
#   copied. They hold the model mapped while the test looks at them.
#
# The engine is cxl-llm (cxl-llm/cxl-llm.cpp, llm.source.sh), a small
# program on llama.cpp's public API. Stock llama.cpp cannot load
# /dev/daxX.Y: a devdax device has no read(), lseek() gives it size 0, and
# it maps only shared, in lengths aligned to 2 MiB. cxl-llm reads the GGUF
# header from a mapping of the device and gives llama.cpp a FILE whose fd
# is the device, so llama.cpp maps the device itself; weight repacking is
# off, so llama.cpp copies no weights. The answers are the same in every
# reader: greedy decoding, the same binary and thread count on the same CPU
# model, and an empty think block (Qwen3 thinks by default).
#
# Proofs: every reader answers "hello" with the expected text; llama.cpp's
# mapping of the model, the model rounded up to the device alignment, has
# every page present and all of them in the CXL window of the device, by
# /proc/PID/pagemap and /proc/iomem on its node; the anonymous memory of
# each reader is less than half the model and the page cache of the nodes
# (FilePages) grows by less than 5% of it, so no copy of the weights exists;
# opening the device node for writing and mapping it writable are refused
# in every reader; the writer's bytes in the backing file equal the model;
# nothing is left at the end. In qemu, CXL memory is host RAM mapped into
# the VMs: timing cannot tell CXL from DRAM, page frames and page cache
# counters can.
#
# What you will see: the writer on VM1 holding llm0 exclusively and copying
# the model into it in about half a second, the host finding the model in
# the backing file, three readers on two nodes answering "hello" in a few
# seconds each from the one copy in CXL memory, the frames of their model
# mappings in "CXL Window N > regionM > daxM.0", and the trace of both
# nodes.
#
# The cluster: the VM of n4-cxl-shared-2 (VM2, the VM of the test) is the
# control plane, the VM of n4-cxl-shared-1 (VM1) a worker, over the VM
# network "cxl-pool" (vm_network.var.sh); test00-up of n4-cxl-shared-2
# makes it. The pool controller runs once, on VM2, the driver on both: one
# DaemonSet, installed with helm on VM2.
#
# Host prerequisites: podman, git and curl, and through http_proxy and
# https_proxy huggingface.co (the model), github.com (llama.cpp, unless
# LLAMA_CPP_SRC is given), registry.fedoraproject.org and the Fedora
# mirrors (the build image and its compiler). The first run downloads the
# model (378 MiB) and builds the engine (about 45 s); $CACHE_DIR/llm keeps
# both, about 420 MB. The VMs keep /opt/cxl-llm/cxl-llm and
# /usr/local/bin/cxl-where.py, VM1 also the model in /opt/cxl-llm/model.
#
# Configuration (environment variables):
#   llm_threads=N      threads of each reader, default 2
#   llm_expect=TEXT    the expected answer, default
#                      "Hello! How can I assist you today?"
#   llm_model=PATH     a local copy of the model instead of the download
#                      into $CACHE_DIR/llm
#   LLAMA_CPP_SRC=DIR  a llama.cpp repository to build the engine from
#                      (cxl-llm/build.sh)
#
# Run test00-up of n4-cxl-shared-1 and -2 first: they create the VMs and
# make them one cluster. The DRA driver comes from its image, build it
# first:
#   make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

echo "### preconditions: one cluster, VM2 control plane, VM1 worker (test00-up)"
pool-cluster-require

LLM_THREADS="${llm_threads:-2}"
LLM_EXPECT="${llm_expect:-Hello! How can I assist you today?}"

VM1="$POOL_VM1_DIR"    # worker, the node of the writer
VM2="$OUTPUT_DIR"      # control plane, the VM of this test
VM1_NAME="$POOL_VM1_NAME"
VM2_NAME="$POOL_VM2_NAME"
LLM_DEVICE=llm0
LLM_SERIAL=0xc1ae0001   # 0xc1ae....: shared pool devices
LLM_HEX=C1AE0001        # the serial in environment variable names
LLM_DEV_SIZE=$(( 512 << 20 ))
LLM_ALIGN=""            # the alignment of the devdax device, read by the writer,
LLM_PADDED=""           # and the model rounded up to it: what llama.cpp maps
LLM_BACKING="$POOL_DIR/$LLM_DEVICE.raw"
READERS=(reader-a reader-b reader-c)
declare -A READER_VM=([reader-a]="$VM2" [reader-b]="$VM2" [reader-c]="$VM1")
declare -A READER_LOG=()
TIMINGS=()

llm0-free() {
    # Usage: llm0-free
    #
    # Wait until neither VM has a CXL memory device and the device is free
    # in the server (pool-device-free-wait), and check that neither VM has
    # a CXL region. Fail the test on timeout or if a region is left.
    local vm
    pool-device-free-wait "$LLM_DEVICE" "$VM2" "$VM1"
    for vm in "$VM2" "$VM1"; do
        pool-cxl-dump "$vm" "$LLM_DEVICE-free"
        cxl-assert 'regions == []'
    done
}

readers-start() {
    # Usage: readers-start READER...
    #
    # Create the ResourceClaim and the pod READER of every READER, on its
    # node, with a read-only claim of the device, and wait until all of
    # them have answered and hold the model mapped. READER_LOG[READER] has
    # the log of each then.
    local r
    for r in "$@"; do
        dra-apply "$VM2" <<< "$(dra-shared-claim-yaml "$r" "$LLM_SERIAL" "" "mode: dax, readOnly: true")
---
$(llm-pod-yaml reader "$r" "${READER_VM[$r]}" "$r" "$(llm-reader-script "$LLM_HEX" "$LLM_THREADS")")"
    done
    for r in "$@"; do
        llm-wait-holding "$VM2" "$r"
        READER_LOG["$r"]="$LLM_LOG"
    done
}

readers-check() {
    # Usage: readers-check READER...
    #
    # Fail the test unless every READER answered the expected text, got the
    # environment and the CDI device of a read-only claim of the device and
    # could neither open it for writing nor map it writable, sees only the
    # engine of $LLM_VM_DIR, has llama.cpp's mapping of the model wholly in
    # the CXL window of the device, and has not copied the weights into its
    # memory.
    local r log answer path uid cdi dax anon
    for r in "$@"; do
        log="${READER_LOG[$r]}"
        echo "### $r on $(pool-vm-label "${READER_VM[$r]}"):"
        echo "$log"
        answer=$(llm-log-answer "$log") || error "$r logged no answer"
        [ "$answer" == "$LLM_EXPECT" ] || error "$r answered '$answer', expected '$LLM_EXPECT'"
        [ "$(llm-log-value "$log" source)" == dax ] || error "$r did not map the model from the devdax device"
        grep -qxF "$LLM_VM_DIR: cxl-llm " <<< "$log" ||
            error "$r has more than the engine of $LLM_VM_DIR: $(grep "^$LLM_VM_DIR: " <<< "$log")"
        dra-env-assert "$r" "$log" "$LLM_HEX" \
            SERIAL="$LLM_SERIAL" SHARED=1 MODE=dax SIZE="$LLM_DEV_SIZE" "DAX=/dev/dax*" READONLY=1
        path=$(dra-env-value "$log" "CXL_${LLM_HEX}_DAX")
        # Read-only for every process of the container: the device cgroup
        # refuses to open the node for writing, the read-only fd refuses a
        # writable mapping.
        for line in "open for writing refused: EPERM" "writable mapping refused: EACCES"; do
            grep -qxF "$line" <<< "$log" || error "$r did not log '$line'"
        done
        # One host of the device on the node of the reader, and the CDI
        # device of the claim, claim-<uid>-0 of the pool driver, with a
        # read-only device node.
        dra-json "$VM2" resourceclaim -n "$DRA_NS" "$r"
        dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$(basename "${READER_VM[$r]}")' and j['status']['allocation']['devices']['results'][0]['consumedCapacity']['hosts'] == '1'"
        uid=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
        cdi=$(dra-cdi-device "${READER_VM[$r]}" "claim-$uid-0")
        echo "CDI device claim-$uid-0: $cdi"
        grep -qx "kind: nri.io/cxl-pool" <<< "$cdi" || error "no CDI device claim-$uid-0 of kind nri.io/cxl-pool for $r"
        grep -qE '^ *permissions: r$' <<< "$cdi" || error "the CDI device of $r has no device node with permissions r"
        # Where the weights are: llama.cpp maps the model rounded up to the
        # device alignment, and every page of that mapping is the device.
        [ "$(llm-log-value "$log" model_bytes)" == "$LLM_PADDED" ] ||
            error "$r: llama.cpp maps $(llm-log-value "$log" model_bytes) bytes, expected the model rounded up to the device alignment, $LLM_PADDED"
        dax=$(basename "$path")
        llm-where-assert "${READER_VM[$r]}" "$r" "$path" "$LLM_PADDED" "^CXL Window [0-9]+ > .* > ${dax//./\\.}\$"
        # No copy of the weights in the process: a copy (llama.cpp reading
        # the tensors instead of mapping them, or repacking them) is at
        # least the model, or 205 MiB more for repacking.
        anon=$(llm-log-value "$log" rss_anon_kb) || error "$r logged no rss_anon_kb"
        [ $(( anon * 1024 )) -lt $(( LLM_MODEL_SIZE / 2 )) ] ||
            error "$r has $anon kB of anonymous memory, not less than half the model ($(( LLM_MODEL_SIZE / 2048 )) kB): the weights were copied into the process"
        echo "memory.stat of $r: $(dra-container-read "${READER_VM[$r]}" "$r" main memory.stat | grep -E '^(anon|file|file_mapped|shmem) ' | tr '\n' ' ')"
        TIMINGS+=("$r on $(pool-vm-label "${READER_VM[$r]}"): load $(llm-log-value "$log" load_ms) ms, first token $(llm-log-value "$log" ttft_ms) ms, $(llm-log-value "$log" gen_tps) tokens/s on $(llm-log-value "$log" threads) threads, anonymous $anon kB")
    done
}

readers-stop() {
    # Usage: readers-stop READER...
    #
    # Tell the engines of the READERs to finish, wait until they exit,
    # delete their pods and claims, and wait until the device is free
    # again (llm0-free).
    local r
    for r in "$@"; do
        dra-exec "${READER_VM[$r]}" "$r" touch "$LLM_STOP" || command-error "cannot stop $r"
    done
    for r in "$@"; do
        llm-wait-exit "$VM2" "$r" 30
    done
    for r in "$@"; do
        dra-delete-pod "$VM2" "$r"
        dra-delete "$VM2" resourceclaim "$r" --wait=true --timeout=60s
    done
    llm0-free
}

cache-assert() {
    # Usage: cache-assert LABEL VMDIR BEFORE-KB
    #
    # Fail the test unless the page cache of the VM of VMDIR (llm-page-cache)
    # has grown by less than 5% of the model since it had BEFORE-KB kB.
    local label="$1" vmdir="$2" before="$3" bytes limit
    bytes=$(( ($(llm-page-cache "$vmdir") - before) * 1024 ))
    limit=$(( LLM_MODEL_SIZE * 5 / 100 ))
    echo "page cache: $label: $(( bytes >> 10 )) kB, the model $(( LLM_MODEL_SIZE >> 10 )) kB"
    [ "$bytes" -lt "$limit" ] || error "$label: the page cache grew by $bytes bytes, not less than 5% of the model ($limit)"
    TIMINGS+=("page cache: $label: $(( bytes >> 10 )) kB")
}

echo "### preconditions: patched qemu, hdm_for_passthrough=on, CONFIG_FS_DAX"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"
pool-vm-require "$VM1" n4-cxl-shared-1

echo "### preconditions: the model and the engine on the host"
llm-model-fetch
llm-build

echo "### preconditions: cxl, daxctl and cxl-dump in both VMs, no CXL memory devices"
pool-vm-tools-install "$VM2"
pool-vm-tools-install "$VM1"
pool-vm-reset "$VM2"
pool-vm-reset "$VM1"
for vm in "$VM2" "$VM1"; do
    pool-cxl-dump "$vm" no-devices
    cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
done

echo "### preconditions: the engine on both nodes, the model only on VM1"
llm-install "$VM1" model
llm-install "$VM2"

echo "### preconditions: fake-cxl-pool-server with $LLM_DEVICE, its backing file new"
# A new backing file is all zeros: a writer that writes nothing cannot pass.
rm -f "$LLM_BACKING" || error "cannot remove $LLM_BACKING"
pool-server-start "
  - name: $LLM_DEVICE
    size: 512Mi
    shared: true
    pool: default
    serial: $LLM_SERIAL"
# The backing file is host RAM (/tmp) and holds the model: remove it on
# exit, also after a failure.
trap 'pool-cleanup; rm -f "$LLM_BACKING"' EXIT
pool-client-install "$VM2" "$VM1"

echo "### preconditions: the pool controller on the control plane, the node plugin on both nodes"
dra-build
dra-install
trap 'dra-cleanup; pool-cleanup; rm -f "$LLM_BACKING"' EXIT
for vm in "$VM2" "$VM1"; do
    dra-pull-images "$vm" "$DRA_TOOLS_IMAGE"
done
dra-dax-tool-install "$VM2"
dra-trace-start "$VM2" "$VM1"

echo "### A: one cluster of two nodes, one pool with the shared device $LLM_DEVICE"
dra-kubectl "$VM2" "get nodes -o wide"
dra-json "$VM2" nodes
dra-assert "$COMMAND_OUTPUT" "sorted(n['metadata']['name'] for n in j['items']) == sorted(['$VM1_NAME', '$VM2_NAME'])"
dra-kubectl "$VM2" "get resourceslices"
dra-json "$VM2" resourceslices
D0="device('$LLM_DEVICE', '$DRA_POOL_DRIVER')"
dra-assert "$COMMAND_OUTPUT" "len(slices('$DRA_POOL_DRIVER')) == 1 and attr($D0, 'shared') == True and attr($D0, 'serial') == '$LLM_SERIAL' and attr($D0, 'size') == $LLM_DEV_SIZE"
dra-assert "$COMMAND_OUTPUT" "capacity($D0, 'hosts') == '4' and ${D0}['capacity']['hosts']['requestPolicy']['validValues'] == ['1', '4']"
pool-vm-command "$VM2" "test ! -e $LLM_VM_DIR/model && ls -la $LLM_VM_DIR" ||
    error "VM2 has the model: its readers must get it from CXL memory only"

echo "### B: the writer on VM1 takes $LLM_DEVICE exclusively and writes the model into it"
t0=$(date +%s.%N)
dra-apply "$VM2" <<< "$(dra-shared-claim-yaml llm-writer "$LLM_SERIAL" 4)
---
$(llm-pod-yaml writer writer "$VM1" llm-writer "env | grep ^CXL_${LLM_HEX}_ | sort
echo \"align: \$(cat /sys/bus/dax/devices/\${CXL_${LLM_HEX}_DAX##*/}/align)\"
$LLM_VM_BIN --write $LLM_VM_MODEL -m \"\$CXL_${LLM_HEX}_DAX\"
echo \"cxl-llm exit \$?\"")"
llm-wait-exit "$VM2" writer 180
T_WRITER=$(echo "$(date +%s.%N) - $t0" | bc)
echo "$LLM_LOG"
dra-env-assert writer "$LLM_LOG" "$LLM_HEX" \
    SERIAL="$LLM_SERIAL" SHARED=1 MODE=dax SIZE="$LLM_DEV_SIZE" "DAX=/dev/dax*" READONLY=0
LLM_ALIGN=$(sed -n 's/^align: \([0-9][0-9]*\)$/\1/p' <<< "$LLM_LOG")
[ -n "$LLM_ALIGN" ] && [ "$LLM_ALIGN" -gt 0 ] || error "the writer found no alignment of its devdax device: $(grep '^align:' <<< "$LLM_LOG")"
LLM_PADDED=$(( (LLM_MODEL_SIZE + LLM_ALIGN - 1) / LLM_ALIGN * LLM_ALIGN ))
echo "the devdax device is aligned to $LLM_ALIGN bytes: the model and its padding are $LLM_PADDED bytes"
line=$(grep "^cxl-llm: wrote $LLM_MODEL_SIZE bytes of $LLM_VM_MODEL to /dev/dax.* (mapping $LLM_PADDED bytes) in [0-9.]* ms$" <<< "$LLM_LOG") ||
    error "the writer did not write the $LLM_MODEL_SIZE bytes of the model into a mapping of $LLM_PADDED bytes of the device"
T_WRITE_MS="${line##* in }"
T_WRITE_MS="${T_WRITE_MS% ms}"
dra-json "$VM2" resourceclaim -n "$DRA_NS" llm-writer
dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$VM1_NAME' and j['status']['allocation']['devices']['results'][0]['consumedCapacity']['hosts'] == '4'"
dra-assert "$COMMAND_OUTPUT" "device_data('$LLM_DEVICE')['exclusive'] == True"
pool-attachments "$LLM_DEVICE"
pool-assert "$COMMAND_OUTPUT" "[(a['host'], a.get('exclusive', False)) for a in j] == [('$VM1_NAME', True)]"
pool-host-client -o json devices "$LLM_DEVICE" || command-error "cannot get $LLM_DEVICE"
[ "$(pool-value "$COMMAND_OUTPUT" 'j["path"]')" == "$LLM_BACKING" ] ||
    error "the backing file of $LLM_DEVICE is not $LLM_BACKING: $(pool-value "$COMMAND_OUTPUT" 'j["path"]')"
sum=$(llm-file-sha256 "$LLM_BACKING" "$LLM_MODEL_SIZE")
[ "$sum" == "$LLM_MODEL_SHA256" ] ||
    error "host: the first $LLM_MODEL_SIZE bytes of $LLM_BACKING have sha256 $sum, not that of the model, $LLM_MODEL_SHA256"
llm-file-zero "$LLM_BACKING" "$LLM_MODEL_SIZE" $(( LLM_PADDED - LLM_MODEL_SIZE )) ||
    error "host: $LLM_BACKING is not zero from the end of the model to $LLM_PADDED"
echo "host: $LLM_BACKING has the model at offset 0 (sha256 $sum) and zeros to $LLM_PADDED"
dra-delete-pod "$VM2" writer
dra-delete "$VM2" resourceclaim llm-writer --wait=true --timeout=60s
llm0-free

echo "### C: three readers map the model from the device, two on VM2 and one on VM1"
cache2=$(llm-page-cache "$VM2")
cache1=$(llm-page-cache "$VM1")
t0=$(date +%s.%N)
readers-start "${READERS[@]}"
T_READERS=$(echo "$(date +%s.%N) - $t0" | bc)
# The weights are not copied anywhere: the page cache of the nodes has not
# grown by any notable part of the model.
cache-assert "VM2, reader-a and reader-b" "$VM2" "$cache2"
cache-assert "VM1, reader-c" "$VM1" "$cache1"
readers-check "${READERS[@]}"
pool-attachments "$LLM_DEVICE"
pool-assert "$COMMAND_OUTPUT" "sorted((a['host'], a.get('exclusive', False), a['state']) for a in j) == sorted([('$VM1_NAME', False, 'attached'), ('$VM2_NAME', False, 'attached')])"
for vm in "$VM2" "$VM1"; do
    pool-cxl-dump "$vm" readers
    cxl-assert "by_serial($LLM_SERIAL) is not None and len(regions) == 1 and regions[0]['OnlineSize'] == 0"
done
readers-stop "${READERS[@]}"

echo "### D: nothing left"
left=$(dra-vm-command-q "$VM2" "kubectl get pods,resourceclaims -n $DRA_NS -o name 2>/dev/null")
[ -z "$left" ] || error "objects left in $DRA_NS: $left"
for vm in "$VM2" "$VM1"; do
    [ -z "$(dra-cdi-devices-with "$vm" "CXL_${LLM_HEX}_")" ] ||
        error "$(pool-vm-label "$vm") still has CDI devices of $LLM_DEVICE: $(dra-cdi-devices-with "$vm" "CXL_${LLM_HEX}_")"
    pool-vm-monitor "$vm" "info qtree -b" | grep -q 'dev: cxl-type3' &&
        error "qemu of $(pool-vm-label "$vm") still has a CXL memory device"
done
echo "no pods, claims, CDI devices, memory devices or regions of $LLM_DEVICE left"

echo "### E: what every component of both nodes did, in order"
dra-trace-stop
dra-trace-summary
echo "TIMING: writer pod created until the model is written: $T_WRITER s (the copy into the device: $T_WRITE_MS ms)"
echo "TIMING: readers created until all three answered: $T_READERS s"
for t in "${TIMINGS[@]}"; do
    echo "TIMING: $t"
done

echo "### cleanup"
dra-cleanup
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
rm -f "$LLM_BACKING" || error "cannot remove $LLM_BACKING"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
