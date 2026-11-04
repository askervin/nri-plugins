# Demo setup (the demo directory demo01-share-write-read, README.txt):
# "demo setup local|pool|pool-shared-fs|pool-fs [TYPE]|wizard" runs this through
# the e2e framework, with the helpers of
# test/e2e/memory.test-suite/dra-driver-cxl (dra.source.sh, pool.source.sh,
# cxl.source.sh: the files next to this test are links to them).
#
# Leaves running, until "demo teardown" (test91-demo-teardown):
# - fake-cxl-pool-server on the host: local demo with the local device of
#   VM2 attached, pool demo with shared0 (256Mi, shared, 0xc1ae0001),
#   pool-shared-fs demo with shared0 persistent (its data and LSA files in
#   $POOL_DIR removed first: a new device without a file system), pool-fs
#   demo with fs0 (512Mi, shared, persistent, 0xc1ae0001; its files
#   removed first too); the wizard demo with pooled0 (512Mi, exclusive,
#   0xc1ee0001), shared0 and fs0 (512Mi, shared, persistent, 0xc1ae0002)
#   on host bridge 0 and three ports of host bridge 1, the local devices
#   of VM2 and VM1 attached, and a second server local-pmem (port 9912,
#   no pool controller) with lp0 (512Mi, persistent, 0xc100f5e1) attached
#   to VM2 as a local memdev; fs0 and lp0 formatted with an ext4 holding
#   hello.txt (manifests/wizard/formatter.yaml);
# - nri-dra-driver-cxl on every node of the three-node cluster (helm,
#   DaemonSet; VM0 is the second worker, pool A reaches VM1 and VM2
#   only), the local demo with
#   sharedDevices: [<the serial of the local device of VM2>], the pool-fs
#   demo with fsTypes: [erofs, $DEMO_FSTYPE], the wizard demo with
#   fsTypes: [erofs, ext4, xfs, btrfs];
# - fake-cxl-pool-controller on VM2;
# - the trace collectors of dra-trace-start (host side, setsid), in
#   pool-shared-fs and pool-fs also of the udev events of block devices of
#   both VMs;
# - namespace $DRA_NS with ConfigMap demo-tools, the images pulled on both
#   nodes (pool-shared-fs, pool-fs: the demo image
#   localhost/cxl-demo-tools:demo, built on the host with docker from
#   $DEMO_DIR/image/Dockerfile and imported instead of python:3-alpine),
#   node labels cxl-demo/node=vm1|vm2, /root/demo in VM2 (the manifests of
#   the case and a kubeconfig with the demo namespace).
# Writes $DEMO_STATE_DIR/state.env for the views, steps, zooms and truth
# dumps.
#
# Environment: DEMO_CASE (local, pool, pool-shared-fs, pool-fs or wizard),
# DEMO_FSTYPE (pool-fs: ext4, xfs or btrfs, default ext4), DEMO_DIR (the
# demo directory), DEMO_STATE_DIR (default $DEMO_DIR/run).

DEMO_CASE="${DEMO_CASE:-local}"
DEMO_SETUP_START=$(date +%s)   # zoom kernel shows the kernel lines since then
DEMO_STATE_DIR="${DEMO_STATE_DIR:-$DEMO_DIR/run}"
[ -n "$DEMO_DIR" ] && [ -d "$DEMO_DIR/manifests/$DEMO_CASE" ] ||
    error "DEMO_DIR ($DEMO_DIR) has no manifests/$DEMO_CASE: run this through \"demo setup local|pool|pool-shared-fs|pool-fs|wizard\""
DEMO_FSTYPE="${DEMO_FSTYPE:-ext4}"
[ "$DEMO_CASE" != pool-fs ] || [[ "$DEMO_FSTYPE" =~ ^(ext4|xfs|btrfs)$ ]] ||
    error "DEMO_FSTYPE is $DEMO_FSTYPE: pool-fs takes ext4, xfs or btrfs"
[ "$DEMO_CASE" == pool-fs ] || DEMO_FSTYPE=""
[ ! -f "$DEMO_STATE_DIR/state.env" ] ||
    error "a demo is set up already ($DEMO_STATE_DIR/state.env): demo teardown first"

VM2="$OUTPUT_DIR"      # control plane, the VM of this test
VM1="$POOL_VM1_DIR"    # worker
DRA_NS=cxl-demo
SHARED_SERIAL=0xc1ae0001
PYTHON_IMAGE=docker.io/library/python:3-alpine
PAUSE_IMAGE=registry.k8s.io/pause:3.10
DEMO_TOOLS=(cxl-demo.py write read hold env mkfs fswrite)
DEMO_IMAGE=localhost/cxl-demo-tools:demo   # the pods of pool-shared-fs and pool-fs
POOL_DEVICE=shared0
POOL_DEVICE_FILES=""
PMEM_CASE=""   # the cases of a persistent pool device: the demo image, block udev events
case "$DEMO_CASE" in pool-shared-fs|pool-fs|wizard) PMEM_CASE=1;; esac
# The wizard: pooled0, shared0 and fs0 of pool A, lp0 of the second server
# local-pmem (no pool controller: the node's driver publishes it as local).
POOLED_SERIAL=0xc1ee0001
FS0_SERIAL=0xc1ae0002
LP_SERVER=local-pmem
LP_PORT=9912
LP_DEVICE=lp0
LP_SERIAL=0xc100f5e1
WIZARD_FS_TYPES="erofs ext4 xfs btrfs"
VM2_LOCAL_SERIAL=""
VM1_LOCAL_SERIAL=""
[ "$DEMO_CASE" != wizard ] || DEMO_TOOLS+=(cxl-wizard.py)

wizard-format() {
    # Usage: wizard-format NAME SERIAL CLASS DRIVER
    #
    # Make an ext4 with hello.txt on the persistent device SERIAL of
    # DeviceClass CLASS and driver DRIVER: ResourceClaim and pod
    # format-NAME on VM2 of manifests/wizard/formatter.yaml, the whole
    # device in mode block. Fail the test unless the writer exits 0. Delete
    # the pod and the claim.
    local name="format-$1" serial="$2" class="$3" driver="$4" key text
    key=${serial#0x}
    key=${key^^}
    text="Hello from the wizard setup, $(date +%T)"
    dra-apply "$VM2" <<< "$(sed -e "s|__NAME__|$name|g; s|__CLASS__|$class|g; s|__DRIVER__|$driver|g" \
        -e "s|__SERIAL__|$serial|g; s|__KEY__|$key|g; s|__TEXT__|$text|g" \
        "$DEMO_DIR/manifests/wizard/formatter.yaml")"
    fs-writer-wait "$VM2" "$name" 240
    dra-delete-pod "$VM2" "$name"
    dra-delete "$VM2" resourceclaim "$name" --wait=true --timeout=90s
    echo "wizard-format: $1 ($serial) has an ext4 with hello.txt: \"$text\""
}

demo-image-build() {
    # Usage: demo-image-build
    #
    # Build the demo image from $DEMO_DIR/image/Dockerfile with docker on
    # the host, unless it exists, and save it to a tarball. Set
    # DEMO_IMAGE_TAG to localhost/cxl-demo-tools:<the first 12 hex digits
    # of the sha256 of the Dockerfile> and DEMO_IMAGE_TAR to the tarball.
    local sha12
    command -v docker >/dev/null ||
        error "docker is needed to build the demo image localhost/cxl-demo-tools (as for the driver image)"
    sha12=$(sha256sum "$DEMO_DIR/image/Dockerfile" | cut -c1-12)
    [ -n "$sha12" ] || error "cannot read $DEMO_DIR/image/Dockerfile"
    DEMO_IMAGE_TAG="localhost/cxl-demo-tools:$sha12"
    DEMO_IMAGE_TAR="$DEMO_STATE_DIR/cxl-demo-tools-$sha12.tar"
    if docker image inspect "$DEMO_IMAGE_TAG" >/dev/null 2>&1; then
        echo "demo-image-build: $DEMO_IMAGE_TAG exists"
    else
        host-command "docker build -t $DEMO_IMAGE_TAG $(printf %q "$DEMO_DIR/image")" ||
            command-error "cannot build the demo image $DEMO_IMAGE_TAG"
    fi
    mkdir -p "$DEMO_STATE_DIR" || error "cannot create $DEMO_STATE_DIR"
    host-command "docker save $DEMO_IMAGE_TAG -o $(printf %q "$DEMO_IMAGE_TAR")" ||
        command-error "cannot save $DEMO_IMAGE_TAG"
}

demo-image-put() {
    # Usage: demo-image-put VMDIR TAR TAG REF
    #
    # Import the image TAG of the docker save tarball TAR into the
    # containerd of the VM of VMDIR and tag it REF, unless REF is TAG there
    # already (the same digest), the way dra-image-put imports the driver.
    local vmdir="$1" tar="$2" tag="$3" ref="$4" label file
    label=$(dra-vm-label "$vmdir")
    file=${tar##*/}
    [ "${k8scri:-containerd}" == containerd ] ||
        error "demo-image-put: the demo image is imported with ctr, $label runs ${k8scri}"
    if dra-vm-command-q "$vmdir" "ctr -n k8s.io images ls | awk -v ref=$ref -v tag=$tag '\$1 == ref {r = \$3} \$1 == tag {t = \$3} END {exit !(r != \"\" && r == t)}'"; then
        echo "demo-image-put $label: $ref is $tag already"
        return 0
    fi
    host-command "scp -F \"$vmdir/.ssh-config\" \"$tar\" node:\"$file\"" ||
        command-error "cannot copy $tar to $label"
    dra-vm-command "$vmdir" "ctr -n k8s.io images import $file && ctr -n k8s.io images tag --force $tag $ref; rc=\$?; rm -f $file; exit \$rc" ||
        command-error "cannot import $file as $ref in $label"
}

echo "### demo setup $DEMO_CASE: the cluster and the VMs"
pool-cluster-require
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"
pool-vm-require "$VM1" n4-cxl-shared-1
# test00-up installed the tools; cxl-tools-install cannot run from here
# (it finds the source tree through the path of the test).
for vm in "$VM2" "$VM1"; do
    pool-vm-command-q "$vm" "command -v cxl && command -v daxctl && command -v cxl-dump" >/dev/null ||
        error "$(pool-vm-label "$vm") lacks cxl, daxctl or cxl-dump: run memory.test-suite/dra-driver-cxl/n4-cxl-shared-{1,2}/test00-up"
done
pool-vm-reset "$VM2"
pool-vm-reset "$VM1"
if [ "$DEMO_CASE" == wizard ]; then
    # fs0 and lp0 get pmem regions: the root decoders of both host bridges
    # must allow persistent memory (lp0 is on host bridge 1 of VM2).
    fs-kernel-require "$VM2" "$(basename "$TOPOLOGY_DIR")"
    fs-kernel-require "$VM1" n4-cxl-shared-1
    for vm in "$VM2" "$VM1"; do
        # shellcheck disable=SC2016 # expanded in the VM
        pool-vm-command "$vm" 'cd /sys/bus/cxl/devices && for d in decoder0.*; do echo "$d cap_pmem $(cat $d/cap_pmem)"; [ "$(cat $d/cap_pmem)" == 1 ] || exit 1; done' ||
            error "a root decoder of $(pool-vm-label "$vm") has no cap_pmem: fs0 or lp0 gets no region there"
    done
fi

echo "### demo setup $DEMO_CASE: fake-cxl-pool-server on the host"
if [ "$DEMO_CASE" == pool ]; then
    pool-server-start "
  - name: shared0
    size: 256Mi
    shared: true
    pool: default
    serial: $SHARED_SERIAL"
elif [ "$DEMO_CASE" == pool-shared-fs ]; then
    # A new device: no file system until the writer makes one.
    rm -f "$POOL_DIR/shared0.raw" "$POOL_DIR/shared0.lsa" ||
        error "cannot remove $POOL_DIR/shared0.raw and $POOL_DIR/shared0.lsa"
    pool-server-start "
  - name: shared0
    size: 256Mi
    shared: true
    persistent: true
    pool: default
    serial: $SHARED_SERIAL"
    pool-device-files shared0
    pool-assert "$COMMAND_OUTPUT" "j['persistent'] == True and j['shared'] == True"
    [ "$POOL_DEVICE_DATA" == "$POOL_DIR/shared0.raw" ] && [ "$POOL_DEVICE_LSA" == "$POOL_DIR/shared0.lsa" ] ||
        error "the files of shared0 are $POOL_DEVICE_DATA and $POOL_DEVICE_LSA, expected $POOL_DIR/shared0.raw and $POOL_DIR/shared0.lsa"
    POOL_DEVICE_FILES="$POOL_DEVICE_DATA $POOL_DEVICE_LSA"
elif [ "$DEMO_CASE" == pool-fs ]; then
    # A new device without a filesystem; 512Mi: mkfs.xfs needs 300 MB.
    POOL_DEVICE=fs0
    rm -f "$POOL_DIR/fs0.raw" "$POOL_DIR/fs0.lsa" ||
        error "cannot remove $POOL_DIR/fs0.raw and $POOL_DIR/fs0.lsa"
    pool-server-start "
  - name: fs0
    size: 512Mi
    shared: true
    persistent: true
    pool: default
    serial: $SHARED_SERIAL"
    pool-device-files fs0
    pool-assert "$COMMAND_OUTPUT" "j['persistent'] == True and j['shared'] == True"
    [ "$POOL_DEVICE_DATA" == "$POOL_DIR/fs0.raw" ] && [ "$POOL_DEVICE_LSA" == "$POOL_DIR/fs0.lsa" ] ||
        error "the files of fs0 are $POOL_DEVICE_DATA and $POOL_DEVICE_LSA, expected $POOL_DIR/fs0.raw and $POOL_DIR/fs0.lsa"
    POOL_DEVICE_FILES="$POOL_DEVICE_DATA $POOL_DEVICE_LSA"
elif [ "$DEMO_CASE" == wizard ]; then
    # Pool A: host bridge 0 (two pool ports and the port of the local
    # devices) and three ports of host bridge 1; the fourth one of VM2 is
    # local-pmem's. fs0 and lp0 start without files: setup formats them.
    POOL_DEVICE=fs0
    rm -f "$POOL_DIR/fs0.raw" "$POOL_DIR/fs0.lsa" "/tmp/fake-cxl-pool-$LP_SERVER/$LP_DEVICE.raw" "/tmp/fake-cxl-pool-$LP_SERVER/$LP_DEVICE.lsa" ||
        error "cannot remove the files of fs0 and $LP_DEVICE"
    DRA_UNCONTROLLED_POOLS=("$LP_SERVER")
    pool-server-start --slots "*hb0 cxlsw_ds[012]_usrp0hb1" "
  - name: pooled0
    size: 512Mi
    shared: false
    pool: default
    serial: $POOLED_SERIAL
  - name: shared0
    size: 256Mi
    shared: true
    pool: default
    serial: $SHARED_SERIAL
  - name: fs0
    size: 512Mi
    shared: true
    persistent: true
    pool: default
    serial: $FS0_SERIAL"
    pool-device-files fs0
    pool-assert "$COMMAND_OUTPUT" "j['persistent'] == True and j['shared'] == True"
    POOL_DEVICE_FILES="$POOL_DEVICE_DATA $POOL_DEVICE_LSA"
else
    pool-server-start " []"
fi
pool-client-install "$VM2" "$VM1"
dra-build

if [ "$DEMO_CASE" == local ]; then
    # The serial of VM2's local device, before the driver runs, for its
    # configuration (plan-9 section 2).
    dra-local-find "$VM2"
    SERIAL="$DRA_LOCAL_SERIAL"
    config="sharedDevices: [\"$SERIAL\"]"
    if declare -p DRA_DRIVER_CONFIG >/dev/null 2>&1; then
        DRA_DRIVER_CONFIG="$config"
    else
        values="$TEST_OUTPUT_DIR/demo-helm-values.yaml"
        { cat "$DRA_HELM_VALUES"; echo "config:"; echo "  $config"; } > "$values"
        DRA_HELM_VALUES="$values"
    fi
    echo "demo setup: driver configuration $config"
else
    SERIAL="$SHARED_SERIAL"
fi
if [ "$DEMO_CASE" == pool-fs ]; then
    # The driver mounts erofs only, unless its configuration lists more.
    DRA_DRIVER_CONFIG="fsTypes: [erofs, $DEMO_FSTYPE]"
    echo "demo setup: driver configuration $DRA_DRIVER_CONFIG"
    echo "demo setup: NOTE: the nodes mount $DEMO_FSTYPE now, a type that is not hardened against crafted images:"
    echo "  this trusts every party that can write fs0 raw (a read-write block claim or lease of it, as the"
    echo "  writer's of R2, on any node of any cluster that shares the pool, and a read-write fs claim);"
    echo "  erofs alone, the default, trusts nobody (docs/memory/cxl/usage.md, Filesystems)"
fi
if [ "$DEMO_CASE" == wizard ]; then
    SERIAL="$FS0_SERIAL"
    DRA_DRIVER_CONFIG="fsTypes: [${WIZARD_FS_TYPES// /, }]"
    echo "demo setup: driver configuration $DRA_DRIVER_CONFIG"
    echo "demo setup: NOTE: the nodes mount ext4, xfs and btrfs too, types that are not hardened against"
    echo "  crafted images: this trusts every party that can write fs0 or lp0 raw (a read-write block claim"
    echo "  or lease of it, on any node of any cluster that shares the pool, and a read-write fs claim);"
    echo "  erofs alone, the default, trusts nobody (docs/memory/cxl/usage.md, Filesystems)"
fi

echo "### demo setup $DEMO_CASE: the driver on every node, the pool controller on VM2"
dra-install
if [ "$DEMO_CASE" == local ]; then
    dra-local-device "$VM2"
    shared=$(dra-value "$DRA_LOCAL_PUBLISHED" "j['attributes']['shared']['bool']")
    [ "$shared" == True ] ||
        error "the driver publishes $DRA_LOCAL_DEVICE with shared $shared: it does not know sharedDevices (plan-9), build its image again"
fi
if [ "$DEMO_CASE" == wizard ]; then
    # The local devices of both nodes, sliced.
    dra-local-device "$VM2"
    VM2_LOCAL_SERIAL="$DRA_LOCAL_SERIAL"
    dra-local-device "$VM1"
    VM1_LOCAL_SERIAL="$DRA_LOCAL_SERIAL"
    echo "### demo setup wizard: $LP_SERVER, a second server without a pool controller, hot-plugs $LP_DEVICE into VM2"
    pool-server-start --name "$LP_SERVER" --port "$LP_PORT" --hosts "$VM2" --control hmp --slots cxlsw_ds3_usrp0hb1 --local-devices no "
  - name: $LP_DEVICE
    size: 512Mi
    shared: false
    persistent: true
    pool: default
    serial: $LP_SERIAL"
    pool-device-files --pool "$LP_SERVER" "$LP_DEVICE"
    POOL_DEVICE_FILES+=" $POOL_DEVICE_DATA $POOL_DEVICE_LSA"
    pool-host-client --pool "$LP_SERVER" -o json attach "$LP_DEVICE" --host "$POOL_VM2_NAME" --owner demo:wizard ||
        command-error "cannot attach $LP_DEVICE to VM2"
    # The driver publishes a hot-added memdev at once, or holds it back for
    # up to 5 minutes (poolSerials, docs/memory/cxl/local.md).
    lp="device('memdev-${LP_SERIAL#0x}', '$DRA_LOCAL_DRIVER', '$POOL_VM2_NAME')"
    dra-wait "$VM2" lp0-published resourceslices "$lp is not None and attr($lp, 'persistent') == True" 360
fi

echo "### demo setup $DEMO_CASE: images, tools, manifests"
if [ -n "$PMEM_CASE" ]; then
    demo-image-build
    for vm in "$VM2" "$VM1"; do
        demo-image-put "$vm" "$DEMO_IMAGE_TAR" "$DEMO_IMAGE_TAG" "$DEMO_IMAGE"
    done
    rm -f "$DEMO_IMAGE_TAR"
    for vm in "$VM2" "$VM1"; do
        dra-pull-images "$vm" "$PAUSE_IMAGE"
    done
else
    for vm in "$VM2" "$VM1"; do
        dra-pull-images "$vm" "$PYTHON_IMAGE" "$PAUSE_IMAGE"
    done
fi
dra-vm-command "$VM2" "rm -rf /root/demo && mkdir -p /root/demo/tools /root/demo/$DEMO_CASE" ||
    command-error "cannot create /root/demo in VM2"
for f in "${DEMO_TOOLS[@]}"; do
    dra-vm-put-file "$VM2" "$DEMO_DIR/bin/tools/$f" "/root/demo/tools/$f"
done
for f in "$DEMO_DIR/manifests/$DEMO_CASE"/*.yaml; do
    dra-vm-put-file "$VM2" "$f" "/root/demo/$DEMO_CASE/${f##*/}"
done
from=""
for f in "${DEMO_TOOLS[@]}"; do
    from+=" --from-file=$f=/root/demo/tools/$f"
done
dra-vm-command "$VM2" "kubectl create configmap demo-tools -n $DRA_NS$from --dry-run=client -o yaml | kubectl apply -f -" ||
    command-error "cannot create ConfigMap demo-tools"
dra-vm-command "$VM2" "cp /root/.kube/config /root/demo/kubeconfig && kubectl --kubeconfig /root/demo/kubeconfig config set-context --current --namespace=$DRA_NS" ||
    command-error "cannot write /root/demo/kubeconfig"
dra-vm-command "$VM2" "kubectl label node $POOL_VM2_NAME cxl-demo/node=vm2 --overwrite && kubectl label node $POOL_VM1_NAME cxl-demo/node=vm1 --overwrite" ||
    command-error "cannot label the nodes"
if [ "$DEMO_CASE" == wizard ]; then
    echo "### demo setup wizard: an ext4 with hello.txt on fs0 and $LP_DEVICE"
    wizard-format fs0 "$FS0_SERIAL" cxl-pool-persistent "$DRA_POOL_DRIVER"
    wizard-format "$LP_DEVICE" "$LP_SERIAL" cxl-local-persistent "$DRA_LOCAL_DRIVER"
    # shellcheck disable=SC2016 # retry-until evaluates the condition
    retry-until --timeout 90 --message "fs0 free and attached nowhere" \
        'pool-host-client -o json devices fs0 >/dev/null && pool-py assert "$COMMAND_OUTPUT" "j[\"state\"] == \"free\" and j[\"attachments\"] in (None, [])"' ||
        error "fs0 is not free after its formatter: $COMMAND_OUTPUT"
    pool-cxl-wait "$VM2" lp0-no-region "by_serial($LP_SERIAL) is not None and not any(by_serial($LP_SERIAL)['Name'] in names(r['Memories']) for r in regions)" 90
fi

echo "### demo setup $DEMO_CASE: the trace"
dra-trace-start "$VM2" "$VM1"
if [ -n "$PMEM_CASE" ]; then
    # The pmem block devices: the udev stream of dra-trace-start has cxl,
    # dax, memory and node only. T5 reads <vm>.block.udev as udev events.
    for vm in "$VM2" "$VM1"; do
        tag="$(dra-vm-label "$vm").block.udev"
        dra-trace-collect-vm "$vm" "$tag" lines "stdbuf -oL udevadm monitor -k -s block"
        # shellcheck disable=SC2016 # retry-until evaluates the condition
        retry-until --timeout 30 --message "trace collector $tag" \
            '[ -n "$(dra-vm-command-q "$vm" "ls /run/dra-trace/$tag.pid 2>/dev/null")" ]' ||
            error "the trace collector $tag did not start in $(dra-vm-label "$vm")"
    done
fi

# Everything stays up: no cleanup at exit.
trap - EXIT
mkdir -p "$DEMO_STATE_DIR" || error "cannot create $DEMO_STATE_DIR"
rm -f "$DEMO_STATE_DIR/step.env"   # the last step of an earlier demo
{
    echo "# demo setup $DEMO_CASE, $(date '+%Y-%m-%d %H:%M:%S'), $TEST_OUTPUT_DIR"
    image="$PYTHON_IMAGE"
    [ -z "$PMEM_CASE" ] || image="$DEMO_IMAGE"
    for kv in "DEMO_CASE=$DEMO_CASE" "DEMO_FSTYPE=$DEMO_FSTYPE" "DEMO_SETUP_START=$DEMO_SETUP_START" "VM2_DIR=$VM2" "VM1_DIR=$VM1" \
              "VM2_NODE=$POOL_VM2_NAME" "VM1_NODE=$POOL_VM1_NAME" \
              "NS=$DRA_NS" "SERIAL=$SERIAL" "POOL_DEVICE=$POOL_DEVICE" "POOL_DEVICE_FILES=$POOL_DEVICE_FILES" \
              "DEMO_IMAGE=$image" "POOL_URL=$POOL_URL" \
              "POOL_SERVER_PID=$POOL_SERVER_PID" "POOL_SERVER_LOG=$POOL_SERVER_LOG" \
              "TRACE_DIR=$DRA_TRACE_DIR" "SETUP_OUTPUT_DIR=$TEST_OUTPUT_DIR" "LOCAL_DEVICE_NAME=$DRA_LOCAL_NAME"; do
        printf '%s=%q\n' "${kv%%=*}" "${kv#*=}"
    done
    if [ "$DEMO_CASE" == wizard ]; then
        # Lists with commas: the views read the file without a shell.
        for kv in "VM2_LOCAL_SERIAL=$VM2_LOCAL_SERIAL" "VM1_LOCAL_SERIAL=$VM1_LOCAL_SERIAL" \
                  "LP_SERVER=$LP_SERVER" "LP_PORT=$LP_PORT" "LP_URL=http://127.0.0.1:$LP_PORT" "LP_DEVICE=$LP_DEVICE" \
                  "LP_SERIAL=$LP_SERIAL" "LP_SERVER_PID=${POOL_SERVER_PIDS[$LP_SERVER]}" \
                  "FS_TYPES=${WIZARD_FS_TYPES// /,}" "FS_SETUP=ext4" "FS_SERIALS=$FS0_SERIAL,$LP_SERIAL"; do
            printf '%s=%q\n' "${kv%%=*}" "${kv#*=}"
        done
    fi
} > "$DEMO_STATE_DIR/state.env"
cat "$DEMO_STATE_DIR/state.env"
echo "demo setup $DEMO_CASE: done"
