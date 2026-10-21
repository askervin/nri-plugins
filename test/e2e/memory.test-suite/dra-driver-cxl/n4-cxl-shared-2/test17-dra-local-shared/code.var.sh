# A node-local CXL memory device shared by the claims of pods: one
# exclusive writer, then read-only readers that wait for it
#
# test14 slices a local CXL memory device: every claim of DeviceClass
# cxl-local gets a piece of its own, zeroed for it. A local device can be
# shared instead, like a shared device of the pool (test11, test13): the
# driver configuration lists it, sharedDevices: ["<serial>"], and the node
# plugin then publishes it whole as a shared device, attributes type
# memdev, source local, shared true, serial, size and nodeAffinity, and
# one capacity, "shares", 1M without a requestPolicy. Claims of class
# cxl-local-shared get the whole device as one devdax device:
# - A claim without a shares request consumes all shares: the device is
#   its own, and the scheduler allocates the device to no other claim
#   until it is gone. Claims that ask meanwhile wait, their pods Pending.
# - A claim with capacity.requests.shares: "1" is one share: any number
#   of such claims hold the device at the same time, each with its own
#   DeviceConfig (readOnly: true gives a device node that the container
#   can only open for reading).
# All of them get the same /dev/daxX.0 of the one region of the device,
# CXL_<KEY>_SHARED=1 and _MODE=dax, and see the same bytes. The node
# plugin zeroes the device once, when it creates the region for the first
# claim; the region stays while the device is configured shared, also
# when no claim uses it, and what the last writer wrote stays there.
# The region goes only when the driver runs without the device in
# sharedDevices; then the device is a sliced local device again.
#
# What you will see: the shared device in the node's ResourceSlice, a
# claim of cxl-local that it does not match, the writer creating the
# region, finding zeros where the test left stale bytes, and writing, two
# readers waiting while it runs and both getting the device when it goes,
# a third reader joining, an exclusive claim waiting for the readers, two
# pods of one claim, refused configurations (mode numa, readOnly with
# mode numa, access, shares "0" that the scheduler allocates and the
# driver refuses), the bytes surviving a period without claims and two
# restarts of the driver, and the region going when the device is no
# longer shared; at the end the trace of what every component did.
#
# The local device is cxl_memdev1 of the topology (1G, host bridge 0),
# attached through fake-cxl-pool-server as in test14; all pods run on this
# VM (VM2), the control plane of the cluster of the test; VM1
# (n4-cxl-shared-1) and VM0 (n4-cxl-shared-0), its workers, have no local
# device attached. Run test00-up of n4-cxl-shared-1, -0 and -2 first: they
# create the VMs and make them one cluster. The DRA driver comes from its
# image, build it first:
#   make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

echo "### preconditions: one cluster, VM2 control plane, VM1 and VM0 workers (test00-up)"
pool-cluster-require

VM1="$POOL_VM1_DIR"    # a worker of the cluster
VM2="$OUTPUT_DIR"      # the VM of this test, the control plane
VM2_NAME="$POOL_VM2_NAME"
SHARED_CLASS=cxl-local-shared
TAG="dra-local-shared $(date +%Y-%m-%dT%H:%M:%S.%N)"
TEXT0="$TAG: at 0, from the writer"
TEXT1M="$TAG: at 1M, from the writer"
STALE="stale bytes of $TAG"   # dra-local-seed: what the node plugin must zero
CLAIM_JSON=""          # claim-check: the claim
CLAIM_UID=""           # and its uid
POD_ENV=""             # env-check: the CXL_ variables of the pod
POD_DAX=""             # and its dax device
CDI_NODE=""            # cdi-check: the device node lines of the CDI device
SHARED_REGION=""       # B: the region of the shared device, kept until H
SHARED_DAX=""          # and its dax device (daxX.Y)
SHARED_DEV=""          # and the major:minor of that

py-str() {
    # Usage: py-str TEXT
    #
    # Print TEXT as a Python string literal.
    python3 -c 'import sys; print(repr(sys.argv[1]))' "$1"
}

claim-pod() {
    # Usage: claim-pod NAME SHARES PARAMETERS SCRIPT
    #
    # Create ResourceClaim NAME of class cxl-local-shared for the local
    # device with SHARES ("1" a share, "" exclusive) and the DeviceConfig
    # PARAMETERS (see dra-shared-claim-yaml), and pod NAME on VM2 with the
    # claim, running the shell SCRIPT (see dra-script-pod-yaml).
    dra-apply "$VM2" <<< "$(dra-shared-claim-yaml "$1" "$DRA_LOCAL_SERIAL" "$2" "$3" "$SHARED_CLASS")
---
$(dra-script-pod-yaml "$1" "$VM2" "$1" "$4")"
}

claim-pod-delete() {
    # Usage: claim-pod-delete NAME...
    #
    # Delete pods NAME and then their claims NAME, and wait until they are
    # gone.
    local n
    for n in "$@"; do
        dra-delete-pod "$VM2" "$n"
    done
    for n in "$@"; do
        dra-delete "$VM2" resourceclaim "$n" --wait=true --timeout=60s
    done
}

reader-script() {
    # Usage: reader-script
    #
    # Print the script of a reader: print its CXL_ variables, check that
    # the device can be neither opened for writing nor mapped writable,
    # and watch the string at offset 0 in the background, holding a
    # read-only mapping until /tmp/stop exists (pool-dax-rw.py watch: "read:
    # TEXT", "holding", "final: TEXT").
    cat <<EOF
env | grep ^CXL_ | sort
python3 /tools/dax-rw.py check-ro "\$CXL_${DRA_LOCAL_HEX}_DAX" 0 || exit 1
python3 /tools/dax-rw.py watch "\$CXL_${DRA_LOCAL_HEX}_DAX" 0 /tmp/stop &
EOF
}

claim-check() {
    # Usage: claim-check NAME SHARES
    #
    # Check that ResourceClaim NAME is allocated to the local device on VM2
    # and consumed SHARES shares of it. CLAIM_JSON and CLAIM_UID are the
    # claim.
    dra-json "$VM2" resourceclaim -n "$DRA_NS" "$1"
    CLAIM_JSON="$COMMAND_OUTPUT"
    dra-assert "$CLAIM_JSON" "[(r['driver'], r['device']) for r in results()] == [('$DRA_LOCAL_DRIVER', '$DRA_LOCAL_DEVICE')] and allocated_node() == '$VM2_NAME'"
    dra-assert "$CLAIM_JSON" "quantity((results()[0].get('consumedCapacity') or {}).get('shares', 0)) == $2"
    CLAIM_UID=$(dra-value "$CLAIM_JSON" "j['metadata']['uid']")
}

env-check() {
    # Usage: env-check POD READONLY
    #
    # Check the CXL_ variables of container main of pod POD: the shared
    # local device in mode dax, the whole device, READONLY (0 or 1), and
    # the marker of its claim, nothing else; its dax device is the dax
    # device of the region of the shared device (DRA_LOCAL_SHARED_DAX), a
    # character device with the numbers of that dax device (SHARED_DEV).
    # POD_ENV are the variables, POD_DAX the device.
    local pod="$1" ro="$2"
    # shellcheck disable=SC2016 # expanded by sh in the container
    dra-exec "$VM2" "$pod" sh -c 'env | grep ^CXL_ | sort' ||
        command-error "cannot read the environment of $pod"
    POD_ENV="$COMMAND_OUTPUT"
    dra-env-assert "$pod" "$POD_ENV" "$DRA_LOCAL_HEX" \
        SERIAL="$DRA_LOCAL_SERIAL" SHARED=1 MODE=dax SIZE="$DRA_LOCAL_SIZE" "DAX=/dev/dax*" READONLY="$ro"
    [ "$(grep -cE '^CXL_CLAIM_[0-9a-f_]+=1$' <<< "$POD_ENV")" == 1 ] && [ "$(grep -c '^CXL_' <<< "$POD_ENV")" == 7 ] ||
        error "$pod does not have the six variables of the device and one claim marker: $POD_ENV"
    POD_DAX=$(dra-env-value "$POD_ENV" "CXL_${DRA_LOCAL_HEX}_DAX")
    [ "$POD_DAX" == "/dev/$DRA_LOCAL_SHARED_DAX" ] ||
        error "$pod has $POD_DAX, expected /dev/$DRA_LOCAL_SHARED_DAX, the dax device of the shared device"
    dra-exec "$VM2" "$pod" python3 -c 'import os, stat, sys; s = os.stat(sys.argv[1]); print("%s %d:%d" % ("c" if stat.S_ISCHR(s.st_mode) else "-", os.major(s.st_rdev), os.minor(s.st_rdev)))' "$POD_DAX" ||
        command-error "no $POD_DAX in $pod"
    [ "$COMMAND_OUTPUT" == "c $SHARED_DEV" ] || error "$POD_DAX in $pod is '$COMMAND_OUTPUT', expected the character device $SHARED_DEV"
}

cdi-check() {
    # Usage: cdi-check UID READONLY
    #
    # Check the CDI device of the allocation result of claim UID,
    # claim-UID-0 (spec cxl-claims): the device node of the shared device,
    # with permissions r if READONLY is 1, the environment of the device
    # and the claim marker, and no other CDI device of the claim. CDI_NODE
    # are its device node lines.
    local uid="$1" ro="$2" cdi
    cdi=$(dra-cdi-device "$VM2" "claim-$uid-0")
    echo "CDI device claim-$uid-0: $cdi"
    grep -qx "kind: nri.io/cxl" <<< "$cdi" || error "no CDI device claim-$uid-0 of kind nri.io/cxl"
    grep -qE "^ *(- )?path: /dev/$DRA_LOCAL_SHARED_DAX\$" <<< "$cdi" || error "the CDI device claim-$uid-0 has no device node /dev/$DRA_LOCAL_SHARED_DAX"
    if [ "$ro" == 1 ]; then
        grep -qE '^ *permissions: r$' <<< "$cdi" || error "the CDI device claim-$uid-0 has no device node with permissions r"
    else
        ! grep -qE '^ *permissions:' <<< "$cdi" || error "the CDI device claim-$uid-0 has a device node with restricted permissions"
    fi
    grep -qF -- "- CXL_${DRA_LOCAL_HEX}_READONLY=$ro" <<< "$cdi" || error "the CDI device claim-$uid-0 has no CXL_${DRA_LOCAL_HEX}_READONLY=$ro"
    grep -qF -- "- CXL_CLAIM_${uid//-/_}=1" <<< "$cdi" || error "the CDI device claim-$uid-0 has no claim marker"
    [ "$(dra-cdi-devices-with "$VM2" "$uid")" == "claim-$uid-0" ] ||
        error "the claim $uid has other CDI devices than claim-$uid-0: $(dra-cdi-devices-with "$VM2" "$uid")"
    CDI_NODE=$(grep -E '^ *(- )?(path|type|major|minor|permissions): ' <<< "$cdi")
}

waiting() {
    # Usage: waiting POD...
    #
    # Return 0 if every pod POD is Pending and its claim, named like the
    # pod, has no allocation.
    local p json
    for p in "$@"; do
        json=$(dra-vm-command-q "$VM2" "kubectl get pod,resourceclaim -n $DRA_NS $p -o json") || return 1
        dra-py assert "$json" "sorted(o['kind'] for o in items) == ['Pod', 'ResourceClaim'] and all(o['status'].get('phase') == 'Pending' for o in items if o['kind'] == 'Pod') and not any((o.get('status') or {}).get('allocation') for o in items if o['kind'] == 'ResourceClaim')" || return 1
    done
}

unschedulable-wait() {
    # Usage: unschedulable-wait POD
    #
    # Wait until pod POD is not scheduled because its claim cannot be
    # allocated, and that its claim (named like the pod) has no
    # allocation.
    dra-wait "$VM2" "$1-unschedulable" "pod -n $DRA_NS $1" \
        "any(c['type'] == 'PodScheduled' and c['status'] == 'False' and c.get('reason') == 'Unschedulable' and 'cannot allocate all claims' in c.get('message', '') for c in (j.get('status') or {}).get('conditions') or [])" 60
    dra-vm-command "$VM2" "kubectl get pod -n $DRA_NS $1 -o jsonpath='{.status.conditions[?(@.type==\"PodScheduled\")].message}'"
    waiting "$1" || error "$1 is not Pending with an unallocated claim"
}

event-wait() {
    # Usage: event-wait POD TEXT
    #
    # Wait until an Event of pod POD has TEXT in its message: the kubelet
    # reports so that the node plugin refused to prepare the claim.
    dra-wait "$VM2" "$1-event" "events -n $DRA_NS --field-selector involvedObject.name=$1" \
        "any($(py-str "$2") in (e.get('message') or '') for e in items)" 120
    dra-kubectl "$VM2" "get events -n $DRA_NS --field-selector involvedObject.name=$1"
}

creating() {
    # Usage: creating POD...
    #
    # Return 0 if the container of every pod POD waits in
    # ContainerCreating.
    local p
    for p in "$@"; do
        [ "$(dra-vm-command-q "$VM2" "kubectl get pod -n $DRA_NS $p -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}'")" == ContainerCreating ] || return 1
    done
}

holding() {
    # Usage: holding POD...
    #
    # Return 0 if every reader POD holds its mapping: its log has
    # "holding" and no "final:" or "changed:".
    local p log
    for p in "$@"; do
        log=$(dra-pod-log "$VM2" "$p")
        grep -qx holding <<< "$log" && ! grep -qE '^(final|changed): ' <<< "$log" || return 1
    done
}

plugin-log-has() {
    # Usage: plugin-log-has TEXT
    #
    # Fail the test unless a line of the log of the driver on VM2 has the
    # fixed string TEXT.
    dra-plugin-log "$VM2" | grep -F -- "$1" ||
        error "the log of $DRA_CONTAINER on VM2 has no line with '$1'"
}

restart-kept() {
    # Usage: restart-kept CLAIM-UID...
    #
    # Check by the log of the driver pod that runs now on VM2 that, when it
    # started, it kept the region of the shared device for the claims
    # CLAIM-UID (none: idle), and did neither zero nor release it.
    local log
    dra-plugin-log-wait "$VM2" "(serial $DRA_LOCAL_SERIAL): keeping shared $SHARED_REGION and $SHARED_DAX, claims [$*]"
    log=$(dra-plugin-log "$VM2")
    ! grep -E "zeroed new shared |releasing its region|released $SHARED_REGION" <<< "$log" ||
        error "the restarted node plugin zeroed or released the region of the shared device, see above"
}

same-region() {
    # Usage: same-region
    #
    # Return 0 if the local device has one region, SHARED_REGION, with one
    # dax device, SHARED_DAX, in sysfs.
    dra-memdev-sysfs "$VM2" "$DRA_LOCAL_SERIAL" &&
        dra-py assert "$DRA_MEMDEV" "[(r['name'], [d['name'] for d in r['dax'] if d['size']]) for r in j['regions']] == [('$SHARED_REGION', ['$SHARED_DAX'])]"
}

echo "### preconditions: patched qemu, hdm_for_passthrough=on, kernel with CONFIG_FS_DAX"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"

echo "### preconditions: cxl, daxctl and cxl-dump in the VM, no CXL memory devices in VM2 and VM1"
pool-vm-tools-install "$VM2"
pool-vm-reset "$VM2"
pool-vm-reset "$VM1"
pool-cxl-dump "$VM2" no-devices
cxl-assert 'memdevs == [] and regions == [] and endpoints == []'

echo "### preconditions: fake-cxl-pool-server on the host, stale bytes in the local device"
pool-server-start
pool-client-install "$VM2"
# The local device attached before the driver runs, with non-zero bytes at
# the start, at 1M and at its end, written through a region of the guest
# tools that is gone again: the first claim must find zeros there.
dra-local-device "$VM2"
SEED_OFFSETS=(0 1M $(( DRA_LOCAL_SIZE - 4096 )))
dra-local-seed "$VM2" "$STALE" "${SEED_OFFSETS[@]}"

echo "### preconditions: the driver with the local device shared"
DRA_DRIVER_CONFIG="sharedDevices: [\"$DRA_LOCAL_SERIAL\"]"
# Never pool-cleanup while a region of the shared device exists.
DRA_EXIT_TRAP='dra-local-shared-cleanup "$VM2"'
dra-build
dra-install
dra-pull-images "$VM2" "$DRA_TOOLS_IMAGE"
dra-dax-tool-install "$VM2"
dra-trace-start "$VM2"

echo "### A: the local device is published whole, as a shared device"
dra-local-device "$VM2"
LD="$DRA_LOCAL_LD"             # the device in the ResourceSlices (dra-py)
pool-cxl-dump "$VM2" local-attached
cxl-assert "by_serial($DRA_LOCAL_SERIAL) is not None and by_serial($DRA_LOCAL_SERIAL)['Enabled'] and by_serial($DRA_LOCAL_SERIAL)['RamSize'] == $DRA_LOCAL_SIZE"
# The first claim creates the region.
cxl-assert "regions == []"
dra-kubectl "$VM2" "get resourceslices"
dra-json "$VM2" resourceslices
SLICES="$COMMAND_OUTPUT"
dra-assert "$SLICES" "attr($LD, 'type') == 'memdev' and attr($LD, 'source') == 'local' and attr($LD, 'shared') == True"
dra-assert "$SLICES" "attr($LD, 'serial') == '$DRA_LOCAL_SERIAL' and attr($LD, 'size') == $DRA_LOCAL_SIZE"
# No memoryBlockSize: a shared device is never sliced.
dra-assert "$SLICES" "sorted(k.split('/')[-1] for k in ${LD}['attributes']) == ['nodeAffinity', 'serial', 'shared', 'size', 'source', 'type']"
# One capacity, shares, without a requestPolicy: no memory to consume,
# and nothing to put online.
dra-assert "$SLICES" "sorted(${LD}.get('capacity') or {}) == ['shares'] and quantity(capacity($LD, 'shares')) == $DRA_SHARES and request_policy($LD, 'shares') is None"
dra-assert "$SLICES" "${LD}.get('allowMultipleAllocations') == True and not ${LD}.get('nodeAllocatableResources')"
dra-json "$VM2" deviceclasses
dra-assert "$COMMAND_OUTPUT" "sorted(n for n in names() if n.startswith('cxl-')) == sorted([$(printf "'%s', " "${DRA_CLASSES[@]}")])"
dra-assert "$COMMAND_OUTPUT" "all(t in by_name('$SHARED_CLASS')['spec']['selectors'][0]['cel']['expression'] for t in ['\"$DRA_LOCAL_DRIVER\"', '\"memdev\"', 'shared == true'])"
dra-assert "$COMMAND_OUTPUT" "'shared == false' in by_name('cxl-local')['spec']['selectors'][0]['cel']['expression']"
# A claim for a slice of local memory, without an amount, does not match
# the shared device: the class cxl-local has only devices that are not
# shared.
dra-claim-pod "$VM2" sliced cxl-local "" dax
dra-wait "$VM2" sliced-unschedulable "pod -n $DRA_NS sliced" \
    "any(c['type'] == 'PodScheduled' and c['status'] == 'False' and c.get('reason') == 'Unschedulable' and 'cannot allocate all claims' in c.get('message', '') for c in (j.get('status') or {}).get('conditions') or [])" 60
dra-vm-command "$VM2" "kubectl get pod -n $DRA_NS sliced -o jsonpath='{.status.conditions[?(@.type==\"PodScheduled\")].message}'"
dra-delete-pod "$VM2" sliced
pool-cxl-dump "$VM2" sliced-refused
cxl-assert "regions == []"

echo "### B: the writer claims the device exclusively and writes"
# No capacity request: the claim consumes all shares. No DeviceConfig:
# mode dax, the only mode of a shared device, read-write.
t0=$EPOCHREALTIME
claim-pod writer "" "" "env | grep ^CXL_ | sort"
dra-pod-wait "$VM2" writer Running 120
T_WRITER=$(echo "$EPOCHREALTIME - $t0" | bc)
claim-check writer "$DRA_SHARES"
WRITER_UID="$CLAIM_UID"
dra-assert "$CLAIM_JSON" "configs() == [] and [s.get('capacity') for s in subrequests()] == [None]"
# The claim created the region: one devdax device of all of the device,
# nothing online.
dra-local-shared-wait "$VM2" writer "$WRITER_UID"
SHARED_REGION="$DRA_LOCAL_SHARED_REGION"
SHARED_DAX="$DRA_LOCAL_SHARED_DAX"
SHARED_DEV=$(dra-value "$DRA_MEMDEV" "dax_slices()[0]['dev']")
env-check writer 0
cdi-check "$WRITER_UID" 0
plugin-log-has "claim $WRITER_UID request mem: shared $SHARED_DAX size $DRA_LOCAL_SIZE read-only false exclusive"
# The new region was zeroed once: where dra-local-seed left stale bytes,
# the writer finds zeros.
plugin-log-has "zeroed new shared $SHARED_DAX size $DRA_LOCAL_SIZE in "
for off in "${SEED_OFFSETS[@]}"; do
    dra-exec "$VM2" writer python3 /tools/dax-rw.py read "$POD_DAX" "$off" || command-error "the writer cannot read at $off"
    [ -z "$COMMAND_OUTPUT" ] || error "the writer found '$COMMAND_OUTPUT' at $off of the new region, expected zeros"
done
dra-local-unchanged "$VM2"
dra-exec "$VM2" writer python3 /tools/dax-rw.py write "$POD_DAX" 0 "$TEXT0" ||
    command-error "the writer cannot write at 0"
dra-exec "$VM2" writer python3 /tools/dax-rw.py write "$POD_DAX" 1M "$TEXT1M" ||
    command-error "the writer cannot write at 1M"
dra-exec "$VM2" writer python3 /tools/dax-rw.py read "$POD_DAX" 0 || command-error "the writer cannot read"
[ "$COMMAND_OUTPUT" == "$TEXT0" ] || error "the writer read '$COMMAND_OUTPUT' at 0, expected '$TEXT0'"

echo "### C: two readers ask for a share while the writer has the device: they wait"
for r in reader-a reader-b; do
    claim-pod "$r" 1 "readOnly: true" "$(reader-script)"
done
for r in reader-a reader-b; do
    unschedulable-wait "$r"
done
dra-stays 10 "reader-a and reader-b stay Pending, their claims unallocated" 'waiting reader-a reader-b'

echo "### D: the writer goes, both readers get the device and read what it wrote"
t0=$EPOCHREALTIME
claim-pod-delete writer
for r in reader-a reader-b; do
    dra-pod-wait "$VM2" "$r" Running 60
done
T_READERS=$(echo "$EPOCHREALTIME - $t0" | bc)
echo "the writer's claim deleted until both readers run: $T_READERS s"
declare -A READER_UID=()
for r in reader-a reader-b; do
    claim-check "$r" 1
    READER_UID[$r]="$CLAIM_UID"
    dra-assert "$CLAIM_JSON" "[c['parameters'] for c in configs()] == [{'apiVersion': '$DRA_LOCAL_DRIVER/v1alpha1', 'kind': 'DeviceConfig', 'readOnly': True}]"
    dra-wait-log "$VM2" "$r" "read: $TEXT0" 60
    dra-wait-log "$VM2" "$r" holding 30
    for line in "open for writing refused: EPERM" "writable mapping refused: EACCES"; do
        dra-pod-log "$VM2" "$r" | grep -qxF "$line" || error "$r did not log '$line'"
    done
    env-check "$r" 1
    cdi-check "$CLAIM_UID" 1
    plugin-log-has "claim $CLAIM_UID request mem: shared $SHARED_DAX size $DRA_LOCAL_SIZE read-only true 1 share"
done
# The same device node in both, the region of the writer.
dra-local-shared-wait "$VM2" readers "${READER_UID[reader-a]}" "${READER_UID[reader-b]}"
same-region || error "the readers have another region or dax device than the writer: $DRA_MEMDEV"
# A third reader joins while the two hold the device.
claim-pod reader-c 1 "readOnly: true" "$(reader-script)"
dra-pod-wait "$VM2" reader-c Running 60
claim-check reader-c 1
READER_UID[reader-c]="$CLAIM_UID"
dra-wait-log "$VM2" reader-c "read: $TEXT0" 60
dra-wait-log "$VM2" reader-c holding 30
env-check reader-c 1
dra-local-shared-wait "$VM2" three-readers "${READER_UID[@]}"
same-region || error "reader-c has another region or dax device: $DRA_MEMDEV"
# An exclusive claim cannot take the device from the readers: it waits.
claim-pod late-writer "" "" "echo started"
unschedulable-wait late-writer
dra-stays 10 "late-writer stays Pending while the readers hold the device" 'waiting late-writer && holding reader-a reader-b reader-c'
claim-pod-delete late-writer

echo "### E: two pods of one claim are one share"
claim-pod two-1 1 "readOnly: true" "echo \"read: \$(python3 /tools/dax-rw.py read \"\$CXL_${DRA_LOCAL_HEX}_DAX\" 0)\""
dra-apply "$VM2" <<< "$(dra-script-pod-yaml two-2 "$VM2" two-1 "echo \"read: \$(python3 /tools/dax-rw.py read \"\$CXL_${DRA_LOCAL_HEX}_DAX\" 0)\"")"
for p in two-1 two-2; do
    dra-pod-wait "$VM2" "$p" Running 60
    dra-wait-log "$VM2" "$p" "read: $TEXT0" 60
done
claim-check two-1 1
TWO_UID="$CLAIM_UID"
dra-assert "$CLAIM_JSON" "sorted(r['name'] for r in j['status']['reservedFor']) == ['two-1', 'two-2']"
dra-local-shared-wait "$VM2" two-pods "${READER_UID[@]}" "$TWO_UID"
same-region || error "two-1 and two-2 have another region or dax device: $DRA_MEMDEV"

echo "### F: configurations and requests that the node plugin refuses"
# The scheduler allocates the device to these claims, next to the
# readers; the node plugin refuses to prepare them, the pods stay
# ContainerCreating. A shared device is dax only, readOnly needs mode dax
# (checked first), and access is of mode fs.
claim-pod bad-numa 1 "mode: numa" "echo started"
claim-pod bad-numa-ro 1 "mode: numa, readOnly: true" "echo started"
claim-pod bad-access 1 "access: cached" "echo started"
# shares "0" passes the API and fits next to any holder: the scheduler
# allocates it, consuming nothing, and the node plugin refuses it.
claim-pod zero-shares 0 "readOnly: true" "echo started"
event-wait bad-numa "DeviceConfig: mode numa: a shared device is used as dax only"
event-wait bad-numa-ro "DeviceConfig: readOnly needs mode dax"
event-wait bad-access "DeviceConfig: access needs mode fs"
event-wait zero-shares "device $DRA_LOCAL_SERIAL: consumed shares \"0\" is less than 1: request shares: 1 (a share) or no shares (exclusive)"
claim-check zero-shares 0
for p in bad-numa bad-numa-ro bad-access zero-shares; do
    dra-wait "$VM2" "$p-creating" "pod -n $DRA_NS $p" \
        "[(cs.get('state') or {}).get('waiting', {}).get('reason') for cs in j['status'].get('containerStatuses') or []] == ['ContainerCreating']" 60
done
dra-stays 10 "the refused pods stay ContainerCreating, the readers hold the device" 'creating bad-numa bad-numa-ro bad-access zero-shares && holding reader-a reader-b reader-c'
claim-pod-delete bad-numa bad-numa-ro bad-access zero-shares
dra-local-shared-wait "$VM2" refused-gone "${READER_UID[@]}" "$TWO_UID"
same-region || error "the refused claims changed the region: $DRA_MEMDEV"

echo "### G: all claims go, the region and the bytes stay"
for r in reader-a reader-b reader-c; do
    dra-exec "$VM2" "$r" touch /tmp/stop || command-error "cannot stop $r"
    dra-wait-log "$VM2" "$r" "final: $TEXT0" 30
done
# two-2 first: the claim two-1 goes when no pod has it any more.
dra-delete-pod "$VM2" two-2
claim-pod-delete reader-a reader-b reader-c two-1
dra-wait "$VM2" no-claims "resourceclaims -n $DRA_NS" "items == []" 60
# Kept while the device is configured shared: the region, its dax device,
# the memdev enabled, the device published as before.
dra-local-shared-wait "$VM2" idle
same-region || error "the idle shared device has another region or dax device: $DRA_MEMDEV"
dra-local-unchanged "$VM2"
[ -z "$(dra-cdi-devices-with "$VM2" "CXL_${DRA_LOCAL_HEX}_")" ] ||
    error "CDI devices of claims of the local device are left: $(dra-cdi-devices-with "$VM2" "CXL_${DRA_LOCAL_HEX}_")"
# A new exclusive claim finds what the writer wrote: the kept region was
# not zeroed again, neither between the claims nor while idle.
claim-pod after-idle "" "" "echo \"at 0: \$(python3 /tools/dax-rw.py read \"\$CXL_${DRA_LOCAL_HEX}_DAX\" 0)\"
echo \"at 1M: \$(python3 /tools/dax-rw.py read \"\$CXL_${DRA_LOCAL_HEX}_DAX\" 1M)\""
dra-pod-wait "$VM2" after-idle Running 60
claim-check after-idle "$DRA_SHARES"
dra-wait-log "$VM2" after-idle "at 0: $TEXT0" 60
dra-wait-log "$VM2" after-idle "at 1M: $TEXT1M" 10
same-region || error "after-idle has another region or dax device: $DRA_MEMDEV"
zeroed=$(dra-plugin-log "$VM2" | grep -c "zeroed new shared ")
[ "$zeroed" == 1 ] || error "the node plugin zeroed the shared device $zeroed times, expected once, when the region was created"
claim-pod-delete after-idle

echo "### H: restarts of the driver keep the region; without the configuration it goes"
claim-pod holder 1 "readOnly: true" "$(reader-script)"
dra-pod-wait "$VM2" holder Running 60
dra-wait-log "$VM2" holder holding 60
claim-check holder 1
HOLDER_UID="$CLAIM_UID"
cdi-check "$HOLDER_UID" 1
CDI_BEFORE="$CDI_NODE"
t0=$EPOCHREALTIME
dra-driver-restart "$VM2"
T_RESTART=$(echo "$EPOCHREALTIME - $t0" | bc)
# The new node plugin kept the region for the holder's claim (its log
# says so), the reader keeps its mapping, and the CDI device of the claim
# has the same device node.
restart-kept "$HOLDER_UID"
holding holder || error "holder lost its mapping with the restart: $(dra-pod-log "$VM2" holder)"
same-region || error "the region changed with the restart: $DRA_MEMDEV"
dra-local-shared-wait "$VM2" restarted "$HOLDER_UID"
cdi-check "$HOLDER_UID" 1
[ "$CDI_NODE" == "$CDI_BEFORE" ] || error "the device node of the claim of holder changed with the restart: '$CDI_BEFORE' -> '$CDI_NODE'"
dra-exec "$VM2" holder python3 /tools/dax-rw.py read "$POD_DAX" 0 || command-error "holder cannot read after the restart"
[ "$COMMAND_OUTPUT" == "$TEXT0" ] || error "holder read '$COMMAND_OUTPUT' after the restart, expected '$TEXT0'"
dra-exec "$VM2" holder touch /tmp/stop || command-error "cannot stop holder"
dra-wait-log "$VM2" holder "final: $TEXT0" 30
claim-pod-delete holder
dra-local-shared-wait "$VM2" holder-gone
# No claims, still configured shared: a restart keeps the region.
dra-driver-restart "$VM2"
restart-kept
same-region || error "the region changed with the restart: $DRA_MEMDEV"
dra-local-shared-wait "$VM2" restarted-idle
# Without the device in the configuration the node plugin destroys the
# region of the idle device and publishes the device for slices again
# (as test14).
DRA_DRIVER_CONFIG=""
t0=$EPOCHREALTIME
dra-install
dra-trace-driver-follow "$VM2"
# The node plugin itself released the region: its log says so.
dra-plugin-log-wait "$VM2" "(serial $DRA_LOCAL_SERIAL): not configured shared any more, releasing its region" 60
dra-local-slices-none "$VM2" unshared
T_UNSHARE=$(echo "$EPOCHREALTIME - $t0" | bc)
dra-wait "$VM2" sliced-again resourceslices \
    "attr($LD, 'shared') == False and sorted(k.split('/')[-1] for k in ${LD}['attributes']) == ['memoryBlockSize', 'nodeAffinity', 'serial', 'shared', 'size', 'source', 'type'] and quantity(capacity($LD, 'memory')) == $DRA_LOCAL_SIZE" 60

echo "### I: what every component did, in order"
dra-trace-stop
dra-trace-summary
echo "TIMING: writer claim and pod created until Running (the region created): $T_WRITER s"
echo "TIMING: writer claim deleted until both readers Running: $T_READERS s"
echo "TIMING: driver restart with a reader until a new Ready pod: $T_RESTART s"
echo "TIMING: dra-install without sharedDevices until the region is gone: $T_UNSHARE s"

echo "### cleanup"
dra-cleanup
dra-local-detach "$VM2"
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "trace: $TEST_OUTPUT_DIR/trace.txt, summary: $TEST_OUTPUT_DIR/trace-summary.txt"
