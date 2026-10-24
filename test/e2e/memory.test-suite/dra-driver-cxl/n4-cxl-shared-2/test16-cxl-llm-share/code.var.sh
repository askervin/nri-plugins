# An LLM shared through persistent pooled CXL memory: one writer, six
# readers of an erofs on two nodes of one Kubernetes cluster
#
# A writer flashes an erofs image of a small language model (Qwen3-0.6B, a
# 378 MiB GGUF file) into a shared persistent CXL memory device of the
# pool, and stock llama.cpp servers on two nodes answer a prompt with the
# model mapped from the file system on that device: direct readers straight
# from the CXL memory (DAX), cached readers through the page cache of their
# node.
#
# - The device llm0 is persistent: fake-cxl-pool backs it with a data file
#   and a label storage area (LSA) file on the host, shared by the qemu of
#   both VMs. Class cxl-pool-persistent selects it, cxl-pool-shared does
#   not.
# - The writer claims it without a "shares" request, which takes all of
#   them (exclusive, writable), MemoryConfig device {mode: block}: the
#   driver creates a pmem region and an fsdax namespace and gives the
#   container the block device /dev/pmemK.
#   The writer runs on VM1, the only node with the model; VM1 builds the
#   erofs image with "mkfs.erofs -b4096 --dsunit=512 -Enoinline_data", the
#   writer writes it with dd and exits. The host finds the model in the data
#   file at a 2 MiB-aligned offset, and labels in the LSA file.
# - The readers claim it with one share each (shares: "1"), MemoryConfig
#   device {mode: fs, readOnly: true, access: direct|cached}: the driver
#   mounts the erofs on the node once per access (direct: the pmem block
#   device with dax=always; cached: a read-only direct-I/O loop device over
#   it) and binds the mount read-only into the container, with no device
#   node. Three direct readers (two on VM2, one on VM1) start first, then
#   three cached readers in the same places, one at a time, while the
#   direct ones still run.
# - Two readers mount the device dynamically, into their running
#   container: direct-b on VM2 and cached-c on VM1 start with a lease
#   claim only (DeviceClass cxl-lease), and the container asks for the
#   erofs itself with "cxl-request request --serial 0xc1ae0001 --shared
#   --read-only --mode fs --access direct|cached [--name models] --exec
#   sh /tmp/reader.sh". The driver creates a companion claim of class
#   cxl-pool-persistent for the lease, prepares it on the node like the
#   claim of a reader (the same node mount), and binds the node mount at
#   /run/cxl/fs/<name> into the container: the lease claim gave the
#   container a read-only slave mount of a host directory of the driver
#   there, and the bind propagates into it. So VM2 has a static and a
#   dynamic mount of the same device and access, VM1 a static direct and
#   a dynamic cached one.
# - With the claim of direct-a gone, the direct node mount of VM2 has one
#   user left, the lease of direct-b. Its release is refused while
#   llama-server maps the model: the driver cannot unmount the bind (the
#   lease stays Releasing, the companion pod Terminating, the model keeps
#   serving). Once llama-server is killed, the lease, its bind and the
#   direct node mount go, and the region stays for the cached readers of
#   VM2: the device is released only when every reference, static and
#   dynamic, is gone.
#
# Proofs: every reader answers "hello" with the expected text, asked from
# its node on its pod IP. Direct readers: every page of llama-server's
# mapping of the model is in "CXL Window N > Persistent Memory > regionM >
# namespaceM.0" (/proc/PID/pagemap and /proc/iomem on the node), the
# anonymous memory of the server is less than half the model, the page
# cache charged to its pod is less than 5% of the model and that of the
# node grows by less than half of it: no copy of the weights exists.
# Cached readers: the first one on a node is charged the model (90% at
# least), grows the page cache of its node by it and pulls it from CXL
# through the loop device (90% at least of its block reads), the second
# one on VM2 is charged less than 5%, grows the page cache by less than
# half the model and reads less than 5% from CXL (one copy per node); the
# model is resident in the page cache of the node (fincore), and while a
# cached reader generates 128 tokens the present pages of its mappings are
# all in System RAM and its loop device reads less than 1 MiB: inference
# is served from the page cache of the node, not from CXL. (Presence of
# every page is not asserted for cached readers: khugepaged may unmap
# page-cached ranges at any time; block reads of the only path to CXL are
# the measure.) The mounts, loop devices, environment and CDI devices are
# what the driver promises, writes under the mount fail, the readers change
# neither the data nor the labels of the device, and nothing is left at the
# end. The leases of the dynamic readers, their companion objects, the CDI
# device of their lease claim and their binds on the node are what the
# lease protocol promises. In qemu, CXL memory is host RAM mapped into the
# VMs: timing cannot tell CXL from DRAM, page frames and page cache
# counters can.
#
# What you will see: VM1 building the erofs image (the first time), the
# writer on VM1 flashing it into llm0 in about a second, the host finding
# the model in the data file, three direct and three cached llama.cpp
# servers on two nodes answering "hello" from the one copy in CXL memory or
# from one page cache copy per node, two of them on a filesystem that
# appeared in their running container, the frames of their model mappings,
# the page cache deltas, the tokens per second, a release refused while
# the model is in use and done once its user is gone, and the trace of
# both nodes.
#
# The "shares" capacity of llm0 is 1M without a requestPolicy: every reader
# claim, and every companion claim of a lease, takes one share of it,
# whatever its node, so the six readers fit at once; the writer, with no
# shares request, takes all of them.
#
# The cluster: the VM of n4-cxl-shared-2 (VM2, the VM of the test) is the
# control plane, the VMs of n4-cxl-shared-1 (VM1) and n4-cxl-shared-0
# (VM0) workers, over the VM network "cxl-pool" (vm_network.var.sh);
# test00-up of n4-cxl-shared-2 makes it. The pool is cabled to VM1 and VM2
# only, and the test uses those two nodes. The pool controller runs once,
# on VM2, the driver on every node: one DaemonSet, installed with helm on
# VM2.
#
# Host prerequisites: curl, and through http_proxy and https_proxy
# huggingface.co (the model). The first run downloads the model (378 MiB)
# into $CACHE_DIR/llm. The VMs pull $LLM_SERVER_IMAGE
# (ghcr.io/ggml-org/llama.cpp:server-b11681, about 310 MB) and the image of
# the companion pods, and VM1 installs erofs-utils with dnf, through their
# own proxies. The VMs keep
# /usr/local/bin/cxl-where.py, VM1 also the model in /opt/cxl-llm/model and
# its erofs image /opt/cxl-llm/llm.erofs. The data and LSA files of llm0
# (/tmp/fake-cxl-pool/llm0.raw and llm0.lsa, host RAM) are removed at the
# end, also after a failure.
#
# Configuration (environment variables):
#   llm_threads=N      threads of each reader, default 2
#   llm_expect=TEXT    the expected answer, default
#                      "Hello! How can I assist you today?"
#   llm_model=PATH     a local copy of the model instead of the download
#                      into $CACHE_DIR/llm
#
# Run test00-up of n4-cxl-shared-1, -0 and -2 first: they create the VMs,
# boot them on the CXL kernel (with CONFIG_EROFS_FS) and make them one
# cluster. The DRA driver comes from its image, build it first:
#   make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

echo "### preconditions: one cluster, VM2 control plane, VM1 and VM0 workers (test00-up)"
pool-cluster-require

LLM_THREADS="${llm_threads:-2}"
LLM_EXPECT="${llm_expect:-Hello! How can I assist you today?}"

VM1="$POOL_VM1_DIR"    # worker, the node of the writer
VM2="$OUTPUT_DIR"      # control plane, the VM of this test
VM0_NAME="$POOL_VM0_NAME"   # the other worker, not cabled to the pool
VM1_NAME="$POOL_VM1_NAME"
VM2_NAME="$POOL_VM2_NAME"
LLM_DEVICE=llm0
LLM_SERIAL=0xc1ae0001   # 0xc1ae....: shared pool devices
LLM_HEX=C1AE0001        # the serial in environment variable names
LLM_MOUNT_ID=c1ae0001   # the serial in the names of the node mounts
LLM_DEV_SIZE=$(( 512 << 20 ))
LLM_DATA="$POOL_DIR/$LLM_DEVICE.raw"   # the files of the device on the host
LLM_LSA="$POOL_DIR/$LLM_DEVICE.lsa"
LLM_LSA_SIZE=262144
LLM_NS_SIZE=""          # the size of the fsdax namespace, as the writer got it
LLM_DEFAULT_PATH="/run/cxl-fs/$LLM_HEX"   # the mount in a container without "path"
LLM_FIVE_PCT=$(( LLM_MODEL_SIZE * 5 / 100 ))
LLM_NINETY_PCT=$(( LLM_MODEL_SIZE * 90 / 100 ))
LLM_HALF=$(( LLM_MODEL_SIZE / 2 ))
LLM_ONE_HALF=$(( LLM_MODEL_SIZE * 3 / 2 ))
# The model mapping of llama.cpp: it unmaps the GGUF header part of its
# whole-file mapping, so the mappings cover most of the model, not all.
LLM_MAPPED_MIN=$(( LLM_MODEL_SIZE * 90 / 100 ))
CHAIN_CXL='^CXL Window [0-9]+ > Persistent Memory > region[0-9]+ > namespace[0-9]+\.[0-9]+$'
CHAIN_RAM='^System RAM$'
DIRECT=(direct-a direct-b direct-c)
CACHED=(cached-a cached-b cached-c)
declare -A READER_VM=([direct-a]="$VM2" [direct-b]="$VM2" [direct-c]="$VM1"
                      [cached-a]="$VM2" [cached-b]="$VM2" [cached-c]="$VM1")
declare -A READER_ACCESS=([direct-a]=direct [direct-b]=direct [direct-c]=direct
                          [cached-a]=cached [cached-b]=cached [cached-c]=cached)
# Lease readers mount the device dynamically: their pod has a claim from
# the ResourceClaimTemplate $LEASE_TEMPLATE, and their container leases the
# erofs (llm-lease-reader-script) at /run/cxl/fs/<name>, <name> from
# READER_NAME or the lease id. The others are claim readers.
declare -A READER_KIND=([direct-b]=lease [cached-c]=lease)
declare -A READER_NAME=([direct-b]=models)
# The path of the erofs in a reader: claim readers $LLM_DEFAULT_PATH unless
# set here; lease readers the path of their lease (lease-reader-found).
declare -A READER_PATH=([cached-b]=/models)
declare -A READER_LEASE=()     # lease reader -> its lease id,
declare -A READER_UID=()       # the uid of its pod,
declare -A READER_CLAIM=()     # and the name and uid of its lease claim
declare -A READER_CLAIM_UID=()
LEASE_TEMPLATE=cxl-lease
PAUSE_IMAGE=registry.k8s.io/pause:3.10   # the image of the companion pods of leases
CACHE_DELTA=""            # reader-start: the growth of the page cache of the node in bytes,
POD_FILE=""               # and the page cache charged to the pod of the reader in bytes,
LOOP_READ=""              # and, for a cached reader, the bytes read meanwhile through the loop device
declare -A READER_LOOP=() # cached reader -> the loop device (loopN) over pmem on its node
LLM_SERVE_TOKENS=128      # the tokens of the long request to each cached reader
LLM_MIB=$(( 1 << 20 ))
TIMINGS=()

llm0-free() {
    # Usage: llm0-free
    #
    # Wait until neither VM has a CXL memory device and the device is free
    # in the server (pool-device-free-wait), and check that neither VM has
    # a CXL region. Fail the test on timeout or if a region is left.
    local vm regions
    pool-device-free-wait "$LLM_DEVICE" "$VM2" "$VM1"
    for vm in "$VM2" "$VM1"; do
        pool-cxl-dump "$vm" "$LLM_DEVICE-free"
        cxl-assert 'regions == []'
        regions=$(pool-vm-command-q "$vm" "ls /sys/bus/cxl/devices/") ||
            error "cannot list the CXL devices of $(pool-vm-label "$vm")"
        ! grep -q '^region[0-9]' <<< "$regions" ||
            error "$(pool-vm-label "$vm") still has a CXL region: $(grep '^region[0-9]' <<< "$regions" | tr '\n' ' ')"
    done
    echo "$LLM_DEVICE is free, no CXL memory devices or regions in either VM"
}

exit-cleanup() {
    # Usage: exit-cleanup
    #
    # The EXIT trap after dra-install: dra-cleanup, then pool-cleanup and
    # the removal of the files of the device, unless a node still has a
    # mount under $DRA_POOL_MOUNT_DIR or $DRA_LEASE_FS_DIR or a loop device
    # over a pmem device, or they cannot be read. Then stop the server
    # only, leave the device, the VMs and the files as they are for
    # debugging, and print what holds the device and how to clean up by
    # hand.
    local vm label held="" loops
    dra-cleanup
    for vm in "$VM2" "$VM1"; do
        label=$(pool-vm-label "$vm")
        if ! dra-fs-mounts "$vm" >/dev/null; then
            held+="
  $label: cannot read its mounts"
        elif [ "$COMMAND_OUTPUT" != "[]" ]; then
            held+="
  $label: mounts $COMMAND_OUTPUT"
        fi
        if ! dra-lease-fs-mounts "$vm" >/dev/null; then
            held+="
  $label: cannot read its lease mounts"
        elif [ "$COMMAND_OUTPUT" != "[]" ]; then
            held+="
  $label: lease mounts $COMMAND_OUTPUT"
        fi
        if ! loops=$(dra-pmem-loops "$vm"); then
            held+="
  $label: cannot list its loop devices"
        elif [ -n "$loops" ]; then
            held+="
  $label: loop devices over pmem: $(tr '\n' ' ' <<< "$loops")"
        fi
    done
    if [ -z "$held" ]; then
        pool-cleanup
        rm -f "$LLM_DATA" "$LLM_LSA"
        return 0
    fi
    # Releasing a region under a live erofs can crash the guest.
    echo "exit-cleanup: $LLM_DEVICE is still held, not releasing or detaching it:$held
  To clean up by hand in each VM above: stop what uses the mount (fuser -vm MOUNT),
  umount MOUNT (never umount -l; the lease mounts first), check that no /sys/block/loop*/loop/backing_file
  names the pmem device, then: fake-cxl-pool-client guest release $LLM_SERIAL.
  Or run the test again: it restarts a VM that still has CXL memory devices
  (pool-vm-reset). Remove $LLM_DATA and $LLM_LSA after that."
    pool-server-stop
}

reader-kind() {
    # Usage: reader-kind READER
    #
    # Print "lease" for a lease reader, else "claim".
    echo "${READER_KIND[$1]:-claim}"
}

reader-path() {
    # Usage: reader-path READER
    #
    # Print the path of the erofs mount in the container of READER.
    echo "${READER_PATH[$1]:-$LLM_DEFAULT_PATH}"
}

lease-reader-found() {
    # Usage: lease-reader-found READER
    #
    # Set READER_LEASE and READER_PATH of the lease reader READER from its
    # only lease ("cxl-request list" in it), READER_UID from its pod, and
    # READER_CLAIM and READER_CLAIM_UID from its lease claim. Fail the test
    # unless the lease is Ready at /run/cxl/fs/<name>, <name> its
    # READER_NAME or else the lease id, and the lease claim is allocated
    # the lease device of its node.
    local r="$1" node lease
    node=$(basename "${READER_VM[$r]}")
    dra-leases "$VM2" "$r/main"
    dra-assert "$DRA_LEASES" "len(j) == 1 and j[0].get('state') == 'Ready' and j[0].get('path')"
    lease=$(dra-value "$DRA_LEASES" "j[0]['lease']")
    [[ "$lease" =~ ^[0-9a-f]{8}$ ]] || error "$r: lease id '$lease' is not 8 hex digits"
    READER_LEASE[$r]=$lease
    READER_PATH[$r]=$(dra-value "$DRA_LEASES" "j[0]['path']")
    [ "${READER_PATH[$r]}" == "$DRA_LEASE_FS_CTR_DIR/${READER_NAME[$r]:-$lease}" ] ||
        error "$r: lease $lease has the path ${READER_PATH[$r]}, expected $DRA_LEASE_FS_CTR_DIR/${READER_NAME[$r]:-$lease}"
    dra-json "$VM2" pod -n "$DRA_NS" "$r"
    READER_UID[$r]=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
    READER_CLAIM[$r]=$(dra-value "$COMMAND_OUTPUT" "[s['resourceClaimName'] for s in j['status']['resourceClaimStatuses'] if s['name'] == 'lease'][0]")
    dra-json "$VM2" resourceclaim -n "$DRA_NS" "${READER_CLAIM[$r]}"
    dra-assert "$COMMAND_OUTPUT" "[(x['driver'], x['device']) for x in results()] == [('$DRA_LOCAL_DRIVER', 'lease')] and allocated_node() == '$node'"
    READER_CLAIM_UID[$r]=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
    echo "$r: lease $lease at ${READER_PATH[$r]}, lease claim ${READER_CLAIM[$r]} (uid ${READER_CLAIM_UID[$r]})"
}

reader-start() {
    # Usage: reader-start READER
    #
    # Create the pod READER on its node and wait until llama-server serves:
    # a claim reader with a ResourceClaim of its own, a read-only fs claim
    # of the device with its access and path; a lease reader with a claim
    # from $LEASE_TEMPLATE, leasing the erofs of the device with its access
    # and name (lease-reader-found). Print the page cache of the node
    # before and after and the cgroups it was charged to meanwhile, and set
    # CACHE_DELTA to its growth in bytes. Ask the reader for its answer,
    # then set POD_FILE to the page cache charged to its pod. For a cached
    # reader set READER_LOOP to the loop device over pmem on its node and
    # LOOP_READ to the bytes read through it meanwhile.
    local r="$1" vm="${READER_VM[$1]}" params before after t0 charges loops0="" loop now base
    params="mode: fs, readOnly: true, access: ${READER_ACCESS[$r]}"
    [ -z "${READER_PATH[$r]}" ] || params+=", path: ${READER_PATH[$r]}"
    charges=$(llm-file-charges "$vm")
    if [ "${READER_ACCESS[$r]}" == cached ]; then
        # Loop devices keep their counters when they are reused: the
        # baseline is that of every loop device now.
        loops0=$(llm-loop-reads "$vm") || error "cannot read the loop devices of $(pool-vm-label "$vm")"
    fi
    before=$(llm-page-cache "$vm")
    t0=$(date +%s.%N)
    if [ "$(reader-kind "$r")" == lease ]; then
        dra-apply "$VM2" <<< "$(llm-server-pod-yaml "$r" "$vm" lease "$LEASE_TEMPLATE" \
            "$(llm-lease-reader-script "$LLM_HEX" "${READER_ACCESS[$r]}" "${READER_NAME[$r]}" "$LLM_THREADS")")"
    else
        dra-apply "$VM2" <<< "$(dra-shared-claim-yaml "$r" "$LLM_SERIAL" 1 "$params" cxl-pool-persistent)
---
$(llm-server-pod-yaml "$r" "$vm" claim "$r" "$(llm-reader-script "$LLM_HEX" "$LLM_THREADS")")"
    fi
    llm-server-wait "$vm" "$r"
    TIMINGS+=("$r on $(pool-vm-label "$vm") ($(reader-kind "$r")): pod created until llama-server serves: $(echo "$(date +%s.%N) - $t0" | bc) s")
    after=$(llm-page-cache "$vm")
    CACHE_DELTA=$(( (after - before) * 1024 ))
    [ "$(reader-kind "$r")" != lease ] || lease-reader-found "$r"
    echo "page cache charged meanwhile in $(pool-vm-label "$vm"): $(llm-file-charges-delta "$charges" "$(llm-file-charges "$vm")")"
    echo "page cache of $(pool-vm-label "$vm") around $r: $before kB -> $after kB, $(( CACHE_DELTA >> 10 )) kB, the model $(( LLM_MODEL_SIZE >> 10 )) kB"
    llm-ask "$vm" "$r"
    POD_FILE=$(llm-pod-file "$vm" "$r") || error "$r: no page cache counter of its pod"
    echo "page cache charged to the pod $r: $(( POD_FILE >> 10 )) kB"
    TIMINGS+=("page cache of $(pool-vm-label "$vm") around $r (${READER_ACCESS[$r]}): $(( CACHE_DELTA >> 10 )) kB, of the pod $(( POD_FILE >> 10 )) kB")
    [ "${READER_ACCESS[$r]}" == cached ] || return 0
    loop=$(dra-pmem-loops "$vm") || error "cannot list the loop devices of $(pool-vm-label "$vm")"
    [ "$(wc -l <<< "$loop")" == 1 ] && [ -n "$loop" ] || error "$(pool-vm-label "$vm") has not one loop device over pmem: $loop"
    loop=${loop%% *}
    READER_LOOP[$r]=$loop
    now=$(llm-loop-reads "$vm" "$loop") || error "cannot read $loop of $(pool-vm-label "$vm")"
    base=$(awk -v l="$loop" '$1 == l {print $2}' <<< "$loops0")
    LOOP_READ=$(( ${now#* } - ${base:-0} ))
    echo "read through $loop of $(pool-vm-label "$vm") (from CXL) around $r: $LOOP_READ bytes, the model $LLM_MODEL_SIZE"
    TIMINGS+=("$r: read from CXL through $loop of $(pool-vm-label "$vm") until it answered: $(( LOOP_READ >> 10 )) kB")
}

cache-cmp() {
    # Usage: cache-cmp VALUE -lt|-ge LIMIT
    #
    # Return 0 if VALUE is less than (-lt) or at least (-ge) LIMIT.
    case "$2" in
        -lt) (( $1 < $3 ));;
        -ge) (( $1 >= $3 ));;
        *) error "cache-cmp: unknown operator $2";;
    esac
}

cache-assert() {
    # Usage: cache-assert READER POD-OP POD-LIMIT NODE-OP NODE-LIMIT WHAT
    #
    # Fail the test unless POD_FILE POD-OP POD-LIMIT and CACHE_DELTA
    # NODE-OP NODE-LIMIT hold (cache-cmp) for READER, saying WHAT is wrong
    # otherwise.
    local r="$1" vm
    vm=$(pool-vm-label "${READER_VM[$1]}")
    cache-cmp "$POD_FILE" "$2" "$3" ||
        error "$r: the page cache charged to its pod is $POD_FILE bytes, not $2 $3: $6"
    cache-cmp "$CACHE_DELTA" "$4" "$5" ||
        error "$r: the page cache of $vm grew by $CACHE_DELTA bytes, not $4 $5: $6"
    echo "page cache ok: $r: pod $POD_FILE $2 $3, node +$CACHE_DELTA $4 $5"
}

reader-check() {
    # Usage: reader-check READER CHAIN
    #
    # Fail the test unless READER answers the expected text, got the
    # environment and the read-only mount of an fs claim of the device with
    # its access and path and no pmem device, could not write under the
    # mount, maps the model with every page in resources of /proc/iomem
    # that match CHAIN, and has not copied the weights into its anonymous
    # memory; a claim reader its claim and CDI device (claim-check), a
    # lease reader its lease, the companion objects, the CDI device of its
    # lease claim and the bind on its node (lease-check).
    local r="$1" chain="$2" vm="${READER_VM[$1]}" access="${READER_ACCESS[$1]}" path log anon
    path=$(reader-path "$r")
    log=$(dra-pod-log "$VM2" "$r")
    echo "$log" > "$TEST_OUTPUT_DIR/$r.log"
    echo "### $r on $(pool-vm-label "$vm"), $access, $(reader-kind "$r") reader, at $path (log: $TEST_OUTPUT_DIR/$r.log):"
    grep -E '^(CXL_|mount: |files: |no pmem devices$|pmem devices: |write under |cxl-request )' <<< "$log"
    dra-env-assert "$r" "$log" "$LLM_HEX" \
        SERIAL="$LLM_SERIAL" SHARED=1 MODE=fs SIZE="$LLM_NS_SIZE" PATH="$path" ACCESS="$access" READONLY=1
    grep -qx "no pmem devices" <<< "$log" ||
        error "$r has pmem devices: $(grep '^pmem devices:' <<< "$log")"
    grep -qE "^write under $path refused: .*Read-only file system$" <<< "$log" ||
        error "$r: a write under $path did not fail with \"Read-only file system\": $(grep "^write under " <<< "$log")"
    # The container sees a read-only erofs at the path.
    grep -qE "^mount: .* $path ro[, ].* - erofs " <<< "$log" ||
        error "$r: $path is not a read-only erofs mount in the container: $(grep '^mount:' <<< "$log")"
    llm-ask "$vm" "$r"
    [ "$LLM_CONTENT" == "$LLM_EXPECT" ] || error "$r answered '$LLM_CONTENT', expected '$LLM_EXPECT'"
    TIMINGS+=("$r on $(pool-vm-label "$vm"): $(llm-answer-value 'j["tokens_predicted"]') tokens, prompt $(llm-answer-value 'round(j["timings"]["prompt_per_second"], 1)') tokens/s, generation $(llm-answer-value 'round(j["timings"]["predicted_per_second"], 1)') tokens/s on $LLM_THREADS threads")
    if [ "$(reader-kind "$r")" == lease ]; then
        lease-check "$r" "$log"
    else
        claim-check "$r"
    fi
    # Where the weights are. Direct: every page of the model mappings in
    # the CXL window. Cached: the present pages in System RAM; khugepaged
    # may unmap page-cached ranges of a mapping at any time (until the
    # process touches them again), so presence is not a property to assert
    # there: residency in the page cache and the block reads of the loop
    # device, the only path to CXL, are (cached-serve-check).
    if [ "$access" == direct ]; then
        llm-where-assert "$vm" "$r" "$path/$LLM_MODEL_FILE" "$LLM_MAPPED_MIN" "$chain" all
    else
        llm-where-assert "$vm" "$r" "$path/$LLM_MODEL_FILE" "$LLM_MAPPED_MIN" "$chain" present
        cached-serve-check "$r" "$path"
    fi
    # No copy of the weights in the process: a copy (llama.cpp reading the
    # tensors instead of mapping them, or repacking them) is at least the
    # model, or 205 MiB more for repacking.
    anon=$(llm-rss-anon "$vm" "$r") || error "$r: no RssAnon of llama-server"
    [ $(( anon * 1024 )) -lt $(( LLM_MODEL_SIZE / 2 )) ] ||
        error "$r has $anon kB of anonymous memory, not less than half the model ($(( LLM_MODEL_SIZE / 2048 )) kB): the weights were copied into the process"
    echo "memory.stat of $r: $(dra-container-read "$vm" "$r" main memory.stat | grep -E '^(anon|file|file_mapped|shmem) ' | tr '\n' ' ')"
    TIMINGS+=("$r: anonymous memory of llama-server $anon kB")
}

claim-check() {
    # Usage: claim-check READER
    #
    # Fail the test unless the claim of the claim reader READER has one
    # share of the device on the node of READER, persistent and not
    # exclusive, and its CDI device claim-<uid>-0 of the pool driver is a
    # read-only bind of the node mount of its access at its path, without
    # device nodes.
    local r="$1" vm="${READER_VM[$1]}" access="${READER_ACCESS[$1]}" path uid cdi
    path=$(reader-path "$r")
    dra-json "$VM2" resourceclaim -n "$DRA_NS" "$r"
    dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$(basename "$vm")' and quantity(j['status']['allocation']['devices']['results'][0]['consumedCapacity']['shares']) == 1"
    dra-assert "$COMMAND_OUTPUT" "device_data('$LLM_DEVICE').get('persistent') == True and not device_data('$LLM_DEVICE').get('exclusive')"
    uid=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
    cdi=$(dra-cdi-device "$vm" "claim-$uid-0")
    echo "CDI device claim-$uid-0: $cdi"
    grep -qx "kind: nri.io/cxl-pool" <<< "$cdi" || error "no CDI device claim-$uid-0 of kind nri.io/cxl-pool for $r"
    grep -q 'deviceNodes:' <<< "$cdi" && error "the CDI device of $r has device nodes"
    grep -qxE " *(- )?hostPath: \"?${DRA_POOL_MOUNT_DIR//./\\.}/$LLM_MOUNT_ID-$access\"?" <<< "$cdi" ||
        error "the CDI device of $r does not mount $DRA_POOL_MOUNT_DIR/$LLM_MOUNT_ID-$access"
    grep -qE "^ *(- )?containerPath: \"?$path\"?$" <<< "$cdi" || error "the CDI device of $r does not mount at $path"
    grep -qE '^ *(- )?type: "?bind"?$' <<< "$cdi" || error "the CDI mount of $r is not a bind mount"
    grep -qE '^ *- "?ro"?$' <<< "$cdi" || error "the CDI mount of $r is not read-only"
}

lease-check() {
    # Usage: lease-check READER LOG
    #
    # Fail the test unless the lease reader READER, whose log is LOG, has
    # exactly its lease in "cxl-request list": Ready, a read-only share of
    # the persistent pool device in mode fs with its access, the namespace
    # size, its path and the environment of the log; "cxl-request env"
    # prints that environment and CXL_LEASE; "cxl-request fd" refuses the
    # lease (exit status 3); and the companion objects (lease-companion-check),
    # the CDI device of its lease claim (dra-lease-cdi-assert) and the bind
    # on its node (lease-bind-assert) are those of the lease.
    local r="$1" log="$2" vm="${READER_VM[$1]}" access="${READER_ACCESS[$1]}" lease="${READER_LEASE[$1]}" path="${READER_PATH[$1]}" env want
    [ "$(dra-env-value "$log" CXL_LEASE)" == "$lease" ] ||
        error "$r: the command of cxl-request has CXL_LEASE=$(dra-env-value "$log" CXL_LEASE), expected $lease"
    env=$(grep -E "^CXL_${LLM_HEX}_[A-Z]+=" <<< "$log" | LC_ALL=C sort)
    dra-leases "$VM2" "$r/main"
    dra-assert "$DRA_LEASES" "[(l['lease'], l['state'], l.get('source'), l.get('mode'), l.get('access'), l.get('shared'), l.get('readOnly'), l.get('serial'), int(l.get('size', 0)), l.get('path')) for l in j] == [('$lease', 'Ready', 'pool', 'fs', '$access', True, True, '$LLM_SERIAL', $LLM_NS_SIZE, '$path')]"
    dra-assert "$DRA_LEASES" "'node' not in j[0] and 'dax' not in j[0]"
    dra-assert "$DRA_LEASES" "j[0].get('env') == $(python3 -c 'import json, sys; print(json.dumps(dict(l.split("=", 1) for l in sys.argv[1].splitlines())))' "$env")"
    # The environment again, with the lease, and no fd: the lease has none.
    dra-exec "$VM2" "$r/main" "$DRA_REQUEST_CTR_BIN" env --lease "$lease" ||
        command-error "$r: cxl-request env --lease $lease failed"
    want=$(LC_ALL=C sort <<< "$env
CXL_LEASE=$lease")
    [ "$COMMAND_OUTPUT" == "$want" ] ||
        error "$r: cxl-request env --lease $lease printed
$COMMAND_OUTPUT
expected
$want"
    dra-exec "$VM2" "$r/main" "$DRA_REQUEST_CTR_BIN" fd --lease "$lease" --exec true &&
        error "$r: cxl-request fd of the fs lease $lease succeeded"
    [ "$COMMAND_STATUS" == 3 ] || error "$r: cxl-request fd of the fs lease $lease exited $COMMAND_STATUS, expected 3"
    grep -qF "lease $lease is not a dax or block lease; use env" <<< "$COMMAND_OUTPUT
$DRA_EXEC_STDERR" || error "$r: cxl-request fd of the fs lease $lease did not print 'lease $lease is not a dax or block lease; use env'"
    lease-companion-check "$r"
    dra-lease-cdi-assert "$vm" "${READER_CLAIM_UID[$r]}"
    lease-bind-assert "$r"
}

lease-companion-check() {
    # Usage: lease-companion-check READER
    #
    # Fail the test unless the companion pod and claim cxl-lease-<id> of the
    # lease of the lease reader READER are owned by the pod of READER and
    # labeled and annotated with the lease and its requester (container
    # main), the pod runs on the node of READER and holds the claim, and
    # the claim asks for one share of the device in class
    # cxl-pool-persistent with a MemoryConfig of the pool driver, device
    # section {mode: fs, readOnly: true, access} and no path, is allocated the device on
    # that node, attached, persistent and not exclusive, and has no CDI
    # device.
    local r="$1" vm="${READER_VM[$1]}" access="${READER_ACCESS[$1]}" lease="${READER_LEASE[$1]}" uid="${READER_UID[$1]}" node name json claim_uid cdis
    node=$(basename "$vm")
    name="cxl-lease-$lease"
    dra-pod-wait "$VM2" "$name" Running 30
    dra-json "$VM2" pod -n "$DRA_NS" "$name"
    json="$COMMAND_OUTPUT"
    dra-assert "$json" "[(o['kind'], o['name'], o['uid']) for o in j['metadata']['ownerReferences']] == [('Pod', '$r', '$uid')]"
    dra-companion-meta-check "$json" "$lease" "$uid" "$node" "$DRA_NS/$r/main"
    dra-assert "$json" "j['spec']['nodeName'] == '$node' and j['spec']['resourceClaims'] == [{'name': 'lease', 'resourceClaimName': '$name'}]"
    dra-assert "$json" "[c['image'] for c in j['spec']['containers']] == ['$PAUSE_IMAGE'] and not j['spec']['containers'][0]['resources'].get('claims')"
    dra-json "$VM2" resourceclaim -n "$DRA_NS" "$name"
    json="$COMMAND_OUTPUT"
    dra-claim-conditions "$VM2" "$name"
    dra-assert "$json" "[(o['kind'], o['name'], o['uid'], o.get('controller')) for o in j['metadata']['ownerReferences']] == [('Pod', '$r', '$uid', True)]"
    dra-companion-meta-check "$json" "$lease" "$uid" "$node" "$DRA_NS/$r/main"
    dra-assert "$json" "[(s['deviceClassName'], [x['cel']['expression'] for x in s.get('selectors') or []], s.get('capacity')) for s in subrequests()] == [('cxl-pool-persistent', ['device.attributes[\"$DRA_POOL_DRIVER\"].serial == \"$LLM_SERIAL\"'], {'requests': {'shares': '1'}})]"
    dra-assert "$json" "[(c['driver'], c['parameters']) for c in configs()] == [('$DRA_POOL_DRIVER', {'apiVersion': '$DRA_CONFIG_API', 'kind': '$DRA_CONFIG_KIND', 'device': {'mode': 'fs', 'readOnly': True, 'access': '$access'}})]"
    dra-assert "$json" "[(x['driver'], x['device']) for x in results()] == [('$DRA_POOL_DRIVER', '$LLM_DEVICE')] and allocated_node() == '$node'"
    dra-assert "$json" "condition('$DRA_POOL_DRIVER/Attached') == 'True' and quantity(results()[0]['consumedCapacity']['shares']) == 1"
    dra-assert "$json" "device_data('$LLM_DEVICE').get('persistent') == True and not device_data('$LLM_DEVICE').get('exclusive')"
    # The companion pod uses nothing of its claim: no CDI device.
    claim_uid=$(dra-value "$json" "j['metadata']['uid']")
    cdis=$(dra-cdi-devices-with "$vm" "$claim_uid") || error "cannot read the CDI specs of $(pool-vm-label "$vm")"
    [ -z "$cdis" ] || error "$r: the companion claim $name has CDI devices: $cdis"
}

lease-bind-assert() {
    # Usage: lease-bind-assert READER
    #
    # Fail the test unless the node of the lease reader READER has exactly
    # one mount at $DRA_LEASE_FS_DIR/<lease claim uid>/<name of its path>:
    # the erofs of the node mount of its access (the same source and
    # superblock options), with the mount options ro, nosuid and nodev.
    local r="$1" vm="${READER_VM[$1]}" label nodes target
    label=$(pool-vm-label "$vm")
    target="$DRA_LEASE_FS_DIR/${READER_CLAIM_UID[$r]}/${READER_PATH[$r]##*/}"
    dra-fs-mounts "$vm" || error "cannot read the mounts of $label"
    nodes="$COMMAND_OUTPUT"
    dra-lease-fs-mounts "$vm" || error "cannot read the lease mounts of $label"
    python3 -c '
import json, sys
nodes, binds, target, node_mount, label = json.loads(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
n = [m for m in nodes if m["target"] == node_mount]
b = [m for m in binds if m["target"] == target]
if len(n) != 1:
    sys.exit("%s: no node mount %s: %s" % (label, node_mount, nodes))
if len(b) != 1:
    sys.exit("%s: not one mount at %s: %s" % (label, target, binds))
n, b = n[0], b[0]
if b["fstype"] != "erofs" or b["source"] != n["source"] or b["options"] != n["options"]:
    sys.exit("%s: %s is %s on %s (%s), not the erofs of %s on %s (%s)" % (label, target, b["fstype"], b["source"], b["options"], node_mount, n["source"], n["options"]))
if not {"ro", "nosuid", "nodev"} <= set(b["vfs"].split(",")):
    sys.exit("%s: %s has the mount options %s, not ro, nosuid and nodev" % (label, target, b["vfs"]))
print("%s: lease bind %s: erofs on %s (%s), %s, the node mount %s" % (label, target, b["source"], b["options"], b["vfs"], node_mount))' \
        "$nodes" "$COMMAND_OUTPUT" "$target" "$DRA_POOL_MOUNT_DIR/$LLM_MOUNT_ID-${READER_ACCESS[$r]}" "$label" ||
        error "$r: no read-only bind of the node mount of its lease on $label"
}

cached-serve-check() {
    # Usage: cached-serve-check READER PATH
    #
    # Fail the test unless, on the node of the cached READER, the model in
    # the cached node mount is resident in the page cache (90% at least,
    # fincore), and a request of $LLM_SERVE_TOKENS tokens to READER
    # (llm-serve-sampled) gives that many tokens while two samples at least
    # of its mappings of PATH/<model> have present pages, all in System
    # RAM, and its loop device over pmem reads less than 1 MiB from CXL.
    local r="$1" path="$2" vm="${READER_VM[$1]}" label res tokens weights
    label=$(pool-vm-label "$vm")
    res=$(llm-fincore "$vm" "$DRA_POOL_MOUNT_DIR/$LLM_MOUNT_ID-cached/$LLM_MODEL_FILE") ||
        error "$r: fincore of the model in the cached node mount of $label failed"
    echo "$r: page cache of $label holds $res bytes of the model (fincore), the model $LLM_MODEL_SIZE"
    cache-cmp "$res" -ge "$LLM_NINETY_PCT" ||
        error "$r: only $res bytes of the model are in the page cache of $label, less than 90% ($LLM_NINETY_PCT)"
    llm-serve-sampled "$vm" "$r" "$path/$LLM_MODEL_FILE" "${READER_LOOP[$r]}" "$LLM_SERVE_TOKENS"
    tokens=$(llm-answer-value 'j["tokens_predicted"]')
    [ "$tokens" == "$LLM_SERVE_TOKENS" ] || error "$r: the long request gave $tokens tokens, not $LLM_SERVE_TOKENS"
    python3 -c '
import json, sys
print("%d samples while it served: %s" % (len(json.loads(sys.argv[1])), "; ".join(
    "%d of %d pages present" % (sum(m["present"] for m in s), sum(m["pages"] for m in s)) for s in json.loads(sys.argv[1]))))' "$LLM_SAMPLES"
    [ "$(python3 -c 'import json, sys; print(len(json.loads(sys.argv[1])))' "$LLM_SAMPLES")" -ge 2 ] ||
        error "$r: fewer than two samples of its mappings while it served $LLM_SERVE_TOKENS tokens"
    python3 -c 'import json, sys; [print(json.dumps(s)) for s in json.loads(sys.argv[1])]' "$LLM_SAMPLES" | while read -r sample; do
        llm-where-check "$sample" "$LLM_MAPPED_MIN" "$CHAIN_RAM" present >/dev/null || exit 1
    done || error "$r: a sample while it served has no present page, or frames outside System RAM: $LLM_SAMPLES"
    cache-cmp "$LLM_LOOP_READ" -lt "$LLM_MIB" ||
        error "$r: ${READER_LOOP[$r]} read $LLM_LOOP_READ bytes from CXL while it served, not less than 1 MiB"
    weights=$(( tokens * LLM_MODEL_SIZE ))
    echo "$r on $label: $tokens tokens, ~$(( weights / 1000000000 )).$(( weights / 100000000 % 10 )) GB of weights read, $LLM_LOOP_READ bytes from CXL (${READER_LOOP[$r]})"
    TIMINGS+=("$r: $tokens tokens served, ~$(( weights / 1000000000 )).$(( weights / 100000000 % 10 )) GB of weights read, $LLM_LOOP_READ bytes from CXL, generation $(llm-answer-value 'round(j["timings"]["predicted_per_second"], 1)') tokens/s")
}

mounts-assert() {
    # Usage: mounts-assert VMDIR ACCESS...
    #
    # Fail the test unless the node mounts of the VM of VMDIR under
    # $DRA_POOL_MOUNT_DIR are exactly one erofs per ACCESS of the device:
    # direct on its pmem block device with dax=always, cached on a
    # read-only direct-I/O loop device over that pmem block device without
    # dax=always.
    local vm="$1" label
    shift
    label=$(pool-vm-label "$vm")
    dra-fs-mounts "$vm" || error "cannot read the mounts of $label"
    python3 -c '
import json, re, sys
mounts, base, mid, accesses = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[5:]
want = sorted("%s/%s-%s" % (base, mid, a) for a in accesses)
got = sorted(m["target"] for m in mounts)
if got != want:
    sys.exit("mounts %s, expected %s" % (got, want))
by = {m["target"].rsplit("-", 1)[1]: m for m in mounts}
pmem = set()
for a, m in by.items():
    if m["fstype"] != "erofs":
        sys.exit("%s is %s, not erofs" % (m["target"], m["fstype"]))
    opts = m["options"].split(",")
    if a == "direct":
        if not re.match(r"^/dev/pmem[0-9]+$", m["source"]) or "dax=always" not in opts:
            sys.exit("direct: %s on %s with %s, expected a pmem block device and dax=always" % (m["target"], m["source"], m["options"]))
        pmem.add(m["source"])
    else:
        if not re.match(r"^/dev/loop[0-9]+$", m["source"]) or not re.match(r"^/dev/pmem[0-9]+$", m["backing"]) or m["dio"] != "1" or m["ro"] != "1" or "dax=always" in opts:
            sys.exit("cached: %s on %s (backing %r, dio %r, ro %r) with %s, expected a read-only direct-I/O loop device over a pmem block device, no dax=always" % (m["target"], m["source"], m["backing"], m["dio"], m["ro"], m["options"]))
        pmem.add(m["backing"])
if len(pmem) > 1:
    sys.exit("the mounts are on different pmem devices: %s" % sorted(pmem))
print(sys.argv[4] + ": mounts: " + ", ".join("%s on %s%s" % (m["target"], m["source"], " over " + m["backing"] if m["backing"] else "") for m in mounts))' \
        "$COMMAND_OUTPUT" "$DRA_POOL_MOUNT_DIR" "$LLM_MOUNT_ID" "$label" "$@" ||
        error "$label: the node mounts of $LLM_DEVICE are not one erofs per access ($*)"
}

readers-stop() {
    # Usage: readers-stop [--keep] READER...
    #
    # Delete the pods of the READERs, then the claims of the claim readers,
    # wait until the lease claims and the companion objects of the lease
    # readers are gone, 90 s at most, and, unless --keep, until the device
    # is free again (llm0-free).
    local r free=1 gone=()
    if [ "$1" == --keep ]; then
        free=""
        shift
    fi
    dra-vm-command "$VM2" "kubectl delete pod -n $DRA_NS --grace-period=2 --wait=true --timeout=120s $*" ||
        command-error "cannot delete the readers"
    for r in "$@"; do
        if [ "$(reader-kind "$r")" == lease ]; then
            gone+=("'${READER_CLAIM[$r]}'" "'cxl-lease-${READER_LEASE[$r]}'")
        else
            dra-delete "$VM2" resourceclaim "$r" --wait=true --timeout=120s
        fi
    done
    if [ "${#gone[@]}" -gt 0 ]; then
        dra-wait "$VM2" "leases-gone-$(IFS=-; echo "$*")" "pods,resourceclaims -n $DRA_NS" \
            "not set(names()) & {$(IFS=,; echo "${gone[*]}")}" 90
    fi
    [ -z "$free" ] || llm0-free
}

lease-dirs-gone() {
    # Usage: lease-dirs-gone READER...
    #
    # Wait until the node of each lease reader READER has neither the
    # socket directory nor the filesystem directory of its lease claim,
    # $DRA_LEASE_DIR/<uid> and $DRA_LEASE_FS_DIR/<uid>, 60 s at most. Fail
    # the test on timeout.
    local r vm dirs
    for r in "$@"; do
        vm="${READER_VM[$r]}"
        dirs="$DRA_LEASE_DIR/${READER_CLAIM_UID[$r]} $DRA_LEASE_FS_DIR/${READER_CLAIM_UID[$r]}"
        retry-until --timeout 60 --interval 1 --message "$(pool-vm-label "$vm") has no $dirs" \
            'pool-vm-command-q "$vm" "for d in $dirs; do test ! -e \$d || exit 1; done"' ||
            error "$r: $(pool-vm-label "$vm") still has $(pool-vm-command-q "$vm" "ls -d $dirs 2>/dev/null; findmnt -rn -o TARGET | grep -F $DRA_LEASE_FS_DIR/")"
        echo "$r: $(pool-vm-label "$vm") has no directories of its lease claim"
    done
}

vm-region-assert() {
    # Usage: vm-region-assert VMDIR
    #
    # Fail the test unless the VM of VMDIR has a CXL region.
    local regions
    regions=$(pool-vm-command-q "$1" "ls /sys/bus/cxl/devices/") ||
        error "cannot list the CXL devices of $(pool-vm-label "$1")"
    grep -q '^region[0-9]' <<< "$regions" || error "$(pool-vm-label "$1") has no CXL region"
    echo "$(pool-vm-label "$1") has the region $(grep '^region[0-9]' <<< "$regions" | tr '\n' ' ')"
}

lease-fs-empty() {
    # Usage: lease-fs-empty VMDIR
    #
    # Fail the test unless the VM of VMDIR has no mount and no directory
    # under $DRA_LEASE_FS_DIR, waiting 60 s at most for the directories.
    local vm="$1" label
    label=$(pool-vm-label "$vm")
    dra-lease-fs-mounts "$vm" || error "cannot read the lease mounts of $label"
    [ "$COMMAND_OUTPUT" == "[]" ] || error "$label still has mounts under $DRA_LEASE_FS_DIR: $COMMAND_OUTPUT"
    retry-until --timeout 60 --interval 1 --message "$label has nothing under $DRA_LEASE_FS_DIR" \
        '[ "$(pool-vm-command-q "$vm" "{ test ! -d $DRA_LEASE_FS_DIR || find $DRA_LEASE_FS_DIR -mindepth 1; } && echo end")" == end ]' ||
        error "$label still has under $DRA_LEASE_FS_DIR: $(pool-vm-command-q "$vm" "find $DRA_LEASE_FS_DIR -mindepth 1")"
}

echo "### preconditions: patched qemu, hdm_for_passthrough=on, CONFIG_FS_DAX, CONFIG_EROFS_FS"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"
pool-vm-require "$VM1" n4-cxl-shared-1
llm-kernel-require "$VM2" "$(basename "$TOPOLOGY_DIR")"
llm-kernel-require "$VM1" n4-cxl-shared-1

echo "### preconditions: the model on the host"
llm-model-fetch

echo "### preconditions: cxl, daxctl and cxl-dump in both VMs, no CXL memory devices"
pool-vm-tools-install "$VM2"
pool-vm-tools-install "$VM1"
pool-vm-reset "$VM2"
pool-vm-reset "$VM1"
for vm in "$VM2" "$VM1"; do
    pool-cxl-dump "$vm" no-devices
    cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
done

echo "### preconditions: cxl-where.py on both nodes, the model and its erofs image only on VM1"
# Only the VM of the writer has the model: the readers get it from the
# device.
llm-install "$VM1" model
llm-install "$VM2"
llm-image-build "$VM1"
[ "$LLM_IMAGE_SIZE" -le "$LLM_DEV_SIZE" ] || error "the erofs image ($LLM_IMAGE_SIZE bytes) is larger than $LLM_DEVICE"

echo "### preconditions: fake-cxl-pool-server with the persistent device $LLM_DEVICE, its files new"
# New files are all zeros: a writer that writes nothing cannot pass, and
# the labels in the LSA file are the writer's.
rm -f "$LLM_DATA" "$LLM_LSA" || error "cannot remove $LLM_DATA and $LLM_LSA"
pool-server-start "
  - name: $LLM_DEVICE
    size: 512Mi
    shared: true
    persistent: true
    pool: default
    serial: $LLM_SERIAL"
# The files are host RAM (/tmp) and hold the model: remove them on exit,
# also after a failure.
trap 'pool-cleanup; rm -f "$LLM_DATA" "$LLM_LSA"' EXIT
pool-client-install "$VM2" "$VM1"
pool-device-files "$LLM_DEVICE"
pool-assert "$COMMAND_OUTPUT" "j['persistent'] == True and j['shared'] == True"
[ "$POOL_DEVICE_DATA" == "$LLM_DATA" ] || error "the data file of $LLM_DEVICE is $POOL_DEVICE_DATA, expected $LLM_DATA"
[ "$POOL_DEVICE_LSA" == "$LLM_LSA" ] || error "the LSA file of $LLM_DEVICE is $POOL_DEVICE_LSA, expected $LLM_LSA"
[ "$(stat -c %s "$LLM_LSA")" == "$LLM_LSA_SIZE" ] || error "the LSA file $LLM_LSA is not $LLM_LSA_SIZE bytes: $(stat -c %s "$LLM_LSA")"
llm-file-zero "$LLM_LSA" 0 "$LLM_LSA_SIZE" || error "the new LSA file $LLM_LSA is not all zeros"
echo "host: $LLM_DATA and $LLM_LSA ($LLM_LSA_SIZE bytes, all zeros)"

echo "### preconditions: the pool controller on the control plane, the node plugin on every node"
dra-build
dra-install
trap exit-cleanup EXIT
for vm in "$VM2" "$VM1"; do
    dra-pull-images "$vm" "$DRA_TOOLS_IMAGE" "$LLM_SERVER_IMAGE" "$PAUSE_IMAGE"
done
dra-dax-tool-install "$VM2"
# The first container of an image on a node reads its files into the page
# cache: do that before the readers, whose page cache deltas count the
# model.
for vm in "$VM2" "$VM1"; do
    llm-warm "$vm"
done
dra-trace-start "$VM2" "$VM1"

echo "### A: one cluster of three nodes, one pool with the persistent device $LLM_DEVICE, its class"
dra-kubectl "$VM2" "get nodes -o wide"
dra-json "$VM2" nodes
dra-assert "$COMMAND_OUTPUT" "sorted(n['metadata']['name'] for n in j['items']) == sorted(['$VM0_NAME', '$VM1_NAME', '$VM2_NAME'])"
dra-kubectl "$VM2" "get resourceslices"
dra-json "$VM2" resourceslices
D0="device('$LLM_DEVICE', '$DRA_POOL_DRIVER')"
dra-assert "$COMMAND_OUTPUT" "len(slices('$DRA_POOL_DRIVER')) == 1 and attr($D0, 'persistent') == True and attr($D0, 'shared') == True and attr($D0, 'serial') == '$LLM_SERIAL' and attr($D0, 'size') == $LLM_DEV_SIZE"
dra-assert "$COMMAND_OUTPUT" "sorted(${D0}.get('capacity') or {}) == ['shares'] and quantity(capacity($D0, 'shares')) == $DRA_SHARES and request_policy($D0, 'shares') is None"
dra-json "$VM2" deviceclass cxl-pool-persistent cxl-pool-shared
dra-assert "$COMMAND_OUTPUT" "names() == ['cxl-pool-persistent', 'cxl-pool-shared']"
# cxl-pool-shared does not match llm0: a pod with a claim of that class for
# it cannot be scheduled, because its claim cannot be allocated.
dra-apply "$VM2" <<< "$(dra-shared-claim-yaml unmatched "$LLM_SERIAL")
---
$(dra-script-pod-yaml unmatched "$VM2" unmatched "echo started")"
dra-wait "$VM2" unmatched "pod -n $DRA_NS unmatched" \
    "any(c['type'] == 'PodScheduled' and c['status'] == 'False' and c.get('reason') == 'Unschedulable' and 'cannot allocate all claims' in c.get('message', '') for c in (j.get('status') or {}).get('conditions') or [])" 60
dra-vm-command "$VM2" "kubectl get pod -n $DRA_NS unmatched -o jsonpath='{.status.conditions[?(@.type==\"PodScheduled\")].message}'"
dra-json "$VM2" resourceclaim -n "$DRA_NS" unmatched
dra-assert "$COMMAND_OUTPUT" "not (j.get('status') or {}).get('allocation')"
dra-delete-pod "$VM2" unmatched
dra-delete "$VM2" resourceclaim unmatched --wait=true --timeout=60s
pool-vm-command "$VM2" "test ! -e $LLM_VM_MODEL_DIR && test ! -e $LLM_VM_IMAGE && ls -la $LLM_VM_DIR" ||
    error "VM2 has the model or its image: its readers must get it from CXL memory only"

echo "### B: the writer on VM1 takes $LLM_DEVICE exclusively and flashes the erofs image into it"
t0=$(date +%s.%N)
dra-apply "$VM2" <<< "$(dra-shared-claim-yaml llm-writer "$LLM_SERIAL" "" "mode: block" cxl-pool-persistent)
---
$(dra-script-pod-yaml writer "$VM1" llm-writer "$(llm-writer-script "$LLM_HEX")" "File:$LLM_VM_IMAGE")"
llm-writer-wait "$VM2" writer 180
T_WRITER=$(echo "$(date +%s.%N) - $t0" | bc)
echo "$LLM_LOG"
dra-env-assert writer "$LLM_LOG" "$LLM_HEX" \
    SERIAL="$LLM_SERIAL" SHARED=1 MODE=block "SIZE=[1-9]*" "PATH=/dev/pmem*" READONLY=0
LLM_NS_SIZE=$(dra-env-value "$LLM_LOG" "CXL_${LLM_HEX}_SIZE")
[[ "$LLM_NS_SIZE" =~ ^[0-9]+$ ]] && [ "$LLM_NS_SIZE" -ge "$LLM_IMAGE_SIZE" ] && [ "$LLM_NS_SIZE" -le "$LLM_DEV_SIZE" ] ||
    error "the fsdax namespace of the writer has $LLM_NS_SIZE bytes, expected the image ($LLM_IMAGE_SIZE) at least and the device ($LLM_DEV_SIZE) at most"
grep -qE "^block device: /dev/pmem[0-9]+$" <<< "$LLM_LOG" || error "the writer has no block device: $(grep 'block device' <<< "$LLM_LOG")"
line=$(grep -E "^dd exit 0 in [0-9]+ ms$" <<< "$LLM_LOG") || error "dd of the writer failed: $(grep '^dd exit' <<< "$LLM_LOG")"
T_WRITE_MS="${line#dd exit 0 in }"
T_WRITE_MS="${T_WRITE_MS% ms}"
grep -qx "device sha256: $LLM_IMAGE_SHA256" <<< "$LLM_LOG" ||
    error "the device of the writer does not have the image (sha256 $LLM_IMAGE_SHA256): $(grep '^device sha256:' <<< "$LLM_LOG")"
dra-json "$VM2" resourceclaim -n "$DRA_NS" llm-writer
dra-assert "$COMMAND_OUTPUT" "allocated_node() == '$VM1_NAME' and quantity(j['status']['allocation']['devices']['results'][0]['consumedCapacity']['shares']) == $DRA_SHARES"
dra-assert "$COMMAND_OUTPUT" "device_data('$LLM_DEVICE')['exclusive'] == True and device_data('$LLM_DEVICE').get('persistent') == True"
uid=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
cdi=$(dra-cdi-device "$VM1" "claim-$uid-0")
echo "CDI device claim-$uid-0: $cdi"
grep -qx "kind: nri.io/cxl-pool" <<< "$cdi" || error "no CDI device claim-$uid-0 of kind nri.io/cxl-pool for the writer"
pmem=$(dra-env-value "$LLM_LOG" "CXL_${LLM_HEX}_PATH")
grep -qxE " *(- )?path: \"?$pmem\"?" <<< "$cdi" ||
    error "the CDI device of the writer has no device node $pmem, the CXL_${LLM_HEX}_PATH of the writer"
grep -qE '^ *(- )?type: "?b"?$' <<< "$cdi" ||
    error "the device node of the CDI device of the writer is not a block device"
pool-attachments "$LLM_DEVICE"
pool-assert "$COMMAND_OUTPUT" "[(a['host'], a.get('exclusive', False)) for a in j] == [('$VM1_NAME', True)]"
# The host: the labels of the namespace in the LSA file, the model in the
# data file at a 2 MiB-aligned offset (the fsdax namespace data and the
# erofs file data are both 2 MiB aligned).
llm-file-zero "$LLM_LSA" 0 "$LLM_LSA_SIZE" && error "host: the LSA file $LLM_LSA is still all zeros: no namespace labels"
offset=$(llm-file-find "$LLM_DATA" "$LLM_MODEL" $(( 2 << 20 ))) ||
    error "host: the model (sha256 $LLM_MODEL_SHA256) is at no 2 MiB-aligned offset of $LLM_DATA"
echo "host: $LLM_LSA has labels, $LLM_DATA has the model at offset $offset ($(( offset >> 20 )) MiB)"
dra-delete-pod "$VM2" writer
dra-delete "$VM2" resourceclaim llm-writer --wait=true --timeout=60s
llm0-free
SHA_DATA=$(llm-file-sha256 "$LLM_DATA")
SHA_LSA=$(llm-file-sha256 "$LLM_LSA")
echo "host: sha256 of $LLM_DATA $SHA_DATA, of $LLM_LSA $SHA_LSA"

echo "### C: three direct readers map the model from CXL memory, two on VM2 (direct-b dynamically) and one on VM1"
# The lease readers claim the lease device of their node through this
# template: the claim lives and dies with their pod.
dra-apply "$VM2" <<< "$(dra-lease-template-yaml "$LEASE_TEMPLATE")"
# Page cache proofs: the page cache charged to the pod of a reader (its
# first toucher is charged; the warm-up pod already holds the files of the
# image) is the exact measure of what the reader put there. The page cache
# of the whole node is a coarse bound only: it moves by tens of MB from
# things outside the test, while a copy of the model is at least 90% of
# it, so a growth below 50% still proves that no copy was made.
for r in "${DIRECT[@]}"; do
    reader-start "$r"
    # The weights are not copied anywhere.
    cache-assert "$r" -lt "$LLM_FIVE_PCT" -lt "$LLM_HALF" "a direct reader copied the model into the page cache"
done
for r in "${DIRECT[@]}"; do
    reader-check "$r" "$CHAIN_CXL"
done
for vm in "$VM2" "$VM1"; do
    mounts-assert "$vm" direct
done
pool-attachments "$LLM_DEVICE"
pool-assert "$COMMAND_OUTPUT" "sorted((a['host'], a.get('exclusive', False), a['state']) for a in j) == sorted([('$VM1_NAME', False, 'attached'), ('$VM2_NAME', False, 'attached')])"

echo "### D: three cached readers map the model from the page cache of their node, started one by one (cached-c dynamically)"
for r in "${CACHED[@]}"; do
    vm="${READER_VM[$r]}"
    first=1
    for o in "${CACHED[@]}"; do
        [ "$o" != "$r" ] || break
        [ "${READER_VM[$o]}" != "$vm" ] || first=""
    done
    reader-start "$r"
    if [ -n "$first" ]; then
        # The first cached reader of a node reads the model into the page
        # cache of the node, once, and is charged for it.
        cache-assert "$r" -ge "$LLM_NINETY_PCT" -ge "$LLM_NINETY_PCT" "the first cached reader of the node did not read the model into the page cache"
        # One copy: no second one in the page cache of the pmem block
        # device under the loop device (direct I/O).
        cache-cmp "$CACHE_DELTA" -lt "$LLM_ONE_HALF" ||
            error "$r: the page cache of $(pool-vm-label "$vm") grew by $CACHE_DELTA bytes, not less than 150% of the model ($LLM_ONE_HALF): the model is cached twice"
        # It pulled the model from CXL: the loop device is the only path.
        cache-cmp "$LOOP_READ" -ge "$LLM_NINETY_PCT" ||
            error "$r: ${READER_LOOP[$r]} read $LOOP_READ bytes from CXL, less than 90% of the model ($LLM_NINETY_PCT)"
    else
        # The others of the node share that copy and read nothing from CXL.
        cache-assert "$r" -lt "$LLM_FIVE_PCT" -lt "$LLM_HALF" "a second copy of the model in the page cache of the node"
        cache-cmp "$LOOP_READ" -lt "$LLM_FIVE_PCT" ||
            error "$r: ${READER_LOOP[$r]} read $LOOP_READ bytes from CXL, not less than 5% of the model ($LLM_FIVE_PCT)"
    fi
done
for r in "${CACHED[@]}"; do
    reader-check "$r" "$CHAIN_RAM"
done
for vm in "$VM2" "$VM1"; do
    mounts-assert "$vm" direct cached
done

echo "### D2: a static and a dynamic mount of the same device on VM2: the device is released only when both are gone"
# Without direct-a, the lease of direct-b is the only user of the direct
# node mount of VM2; the cached readers of VM2 keep the region.
LEASE_B="${READER_LEASE[direct-b]}"
BIND_B="$DRA_LEASE_FS_DIR/${READER_CLAIM_UID[direct-b]}/${READER_PATH[direct-b]##*/}"
readers-stop --keep direct-a
mounts-assert "$VM2" direct cached
lease-bind-assert direct-b
vm-region-assert "$VM2"
llm-ask "$VM2" direct-b
[ "$LLM_CONTENT" == "$LLM_EXPECT" ] || error "direct-b answered '$LLM_CONTENT', expected '$LLM_EXPECT'"
# The release cannot finish while llama-server maps the model: the driver
# cannot unmount the bind (EBUSY), kubelet retries the Unprepare of the
# companion claim, the companion pod stays Terminating.
t0=$EPOCHREALTIME
dra-exec "$VM2" direct-b/main "$DRA_REQUEST_CTR_BIN" release --lease "$LEASE_B" --wait 5s &&
    error "cxl-request release of lease $LEASE_B of direct-b succeeded while llama-server maps the model"
[ "$COMMAND_STATUS" == 3 ] || error "cxl-request release of lease $LEASE_B exited $COMMAND_STATUS, expected 3 (not Released in time)"
TIMINGS+=("direct-b: release of the mapped lease $LEASE_B refused (still Releasing) after $(echo "$EPOCHREALTIME - $t0" | bc) s (--wait 5s)")
dra-assert "$(dra-last-json "$COMMAND_OUTPUT")" "j.get('lease') == '$LEASE_B' and j.get('state') == 'Releasing'"
busy_re="lease $LEASE_B: unmounting ${BIND_B//./\\.}: .*device or resource busy"
retry-until --timeout 60 --interval 1 --message "the driver of VM2 cannot unmount $BIND_B: busy" \
    'dra-plugin-log "$VM2" | grep -qE "$busy_re"' ||
    error "the driver of VM2 did not log that it cannot unmount $BIND_B (lease $LEASE_B: unmounting ...: device or resource busy)"
dra-plugin-log "$VM2" | grep -E "$busy_re" | tail -n 2
lease-bind-assert direct-b
mounts-assert "$VM2" direct cached
vm-region-assert "$VM2"
llm-ask "$VM2" direct-b
[ "$LLM_CONTENT" == "$LLM_EXPECT" ] || error "direct-b answered '$LLM_CONTENT' while its lease is Releasing, expected '$LLM_EXPECT'"
dra-json "$VM2" pod -n "$DRA_NS" "cxl-lease-$LEASE_B" ||
    error "the companion pod cxl-lease-$LEASE_B is gone while its bind is busy"
dra-assert "$COMMAND_OUTPUT" "j['metadata'].get('deletionTimestamp')"
dra-json "$VM2" resourceclaim -n "$DRA_NS" "cxl-lease-$LEASE_B" ||
    error "the companion claim cxl-lease-$LEASE_B is gone while its bind is busy"
dra-leases "$VM2" direct-b/main
dra-assert "$DRA_LEASES" "[(l['lease'], l['state']) for l in j] == [('$LEASE_B', 'Releasing')]"
pool-attachments "$LLM_DEVICE"
pool-assert "$COMMAND_OUTPUT" "('$VM2_NAME', 'attached') in [(a['host'], a['state']) for a in j]"
# The user of the mount goes: cxl-request passes the SIGKILL of
# llama-server on as its exit status, the container ends and the pod
# fails (restartPolicy Never). The broker releases the leases of the pod,
# the next Unprepare of the companion claim unmounts the bind, the node
# mount it was the last user of, and keeps the region for the cached
# readers.
pid=$(llm-server-pid "$VM2" direct-b) || error "no llama-server runs in direct-b"
t0=$EPOCHREALTIME
pool-vm-command "$VM2" "kill -KILL $pid" || command-error "cannot kill llama-server (pid $pid) of direct-b"
dra-pod-wait "$VM2" direct-b Failed 60
dra-json "$VM2" pod -n "$DRA_NS" direct-b
dra-assert "$COMMAND_OUTPUT" "j['status']['containerStatuses'][0]['state']['terminated']['exitCode'] == 137"
dra-wait "$VM2" d2-lease-b-gone "pods,resourceclaims -n $DRA_NS" "'cxl-lease-$LEASE_B' not in names()" 90
TIMINGS+=("direct-b: lease $LEASE_B and its companion gone $(echo "$EPOCHREALTIME - $t0" | bc) s after llama-server was killed")
dra-lease-fs-mounts "$VM2" || error "cannot read the lease mounts of $(pool-vm-label "$VM2")"
[ "$COMMAND_OUTPUT" == "[]" ] || error "$(pool-vm-label "$VM2") still has mounts under $DRA_LEASE_FS_DIR: $COMMAND_OUTPUT"
mounts-assert "$VM2" cached
vm-region-assert "$VM2"
for r in cached-a cached-b; do
    llm-ask "$VM2" "$r"
    [ "$LLM_CONTENT" == "$LLM_EXPECT" ] || error "$r answered '$LLM_CONTENT' after direct-b, expected '$LLM_EXPECT'"
done
# VM1 is unchanged: its direct claim and its cached lease.
mounts-assert "$VM1" direct cached
lease-bind-assert cached-c
dra-pod-wait "$VM2" "cxl-lease-${READER_LEASE[cached-c]}" Running 5
# The pod goes with its lease claim; the broker removes the directories of
# the claim once it is closed and no bind is left in them.
dra-delete-pod "$VM2" direct-b
dra-wait "$VM2" d2-lease-claim-b-gone "resourceclaims -n $DRA_NS" "'${READER_CLAIM[direct-b]}' not in names()" 60
lease-dirs-gone direct-b

echo "### E: all readers stop, nothing is left"
readers-stop direct-c "${CACHED[@]}"
dra-delete "$VM2" resourceclaimtemplate "$LEASE_TEMPLATE" --wait=true --timeout=60s
left=$(dra-vm-command-q "$VM2" "kubectl get pods,resourceclaims,resourceclaimtemplates -n $DRA_NS -o name") ||
    error "cannot list the pods, claims and claim templates in $DRA_NS"
[ -z "$left" ] || error "objects left in $DRA_NS: $left"
lease-dirs-gone cached-c
for vm in "$VM2" "$VM1"; do
    label=$(pool-vm-label "$vm")
    dra-fs-mounts "$vm" || error "cannot read the mounts of $label"
    [ "$COMMAND_OUTPUT" == "[]" ] || error "$label still has mounts under $DRA_POOL_MOUNT_DIR: $COMMAND_OUTPUT"
    lease-fs-empty "$vm"
    loops=$(dra-pmem-loops "$vm") || error "cannot list the loop devices of $label"
    [ -z "$loops" ] || error "$label still has loop devices over pmem devices: $loops"
    cdis=$(dra-cdi-devices-with "$vm" "CXL_${LLM_HEX}_") || error "cannot read the CDI specs of $label"
    [ -z "$cdis" ] || error "$label still has CDI devices of $LLM_DEVICE: $cdis"
    qtree=$(pool-vm-monitor "$vm" "info qtree -b") || error "cannot read the qemu device tree of $label"
    grep -q '^ *bus: ' <<< "$qtree" || error "no qemu device tree of $label: $qtree"
    ! grep -q 'dev: cxl-type3' <<< "$qtree" || error "qemu of $label still has a CXL memory device"
done
# erofs never writes the device, and the readers never touch the labels.
[ "$(llm-file-sha256 "$LLM_DATA")" == "$SHA_DATA" ] || error "host: the readers changed $LLM_DATA"
[ "$(llm-file-sha256 "$LLM_LSA")" == "$SHA_LSA" ] || error "host: the readers changed $LLM_LSA"
echo "no pods, claims, leases, mounts, lease directories, loop devices, CDI devices, memory devices or regions of $LLM_DEVICE left; its data and labels are as the writer left them"

echo "### what every component of VM2 and VM1 did, in order"
dra-trace-stop
dra-trace-summary
echo "TIMING: writer pod created until the image is written: $T_WRITER s (dd of $LLM_IMAGE_SIZE bytes: $T_WRITE_MS ms)"
for t in "${TIMINGS[@]}"; do
    echo "TIMING: $t"
done

echo "### cleanup"
trap - EXIT
exit-cleanup
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
[ ! -e "$LLM_DATA" ] && [ ! -e "$LLM_LSA" ] || error "$LLM_DATA or $LLM_LSA is left, see exit-cleanup above"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
