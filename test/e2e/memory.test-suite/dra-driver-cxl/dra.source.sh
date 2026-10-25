# Helpers for testing CXL memory pooling and sharing with Dynamic Resource
# Allocation (DRA): nri-dra-driver-cxl (the CXL DRA driver, drivers
# cxl.nri.io and cxl-pool.nri.io) runs on every node of the cluster of the
# VM of the test as a DaemonSet that helm installs from
# deployment/helm/dra-driver-cxl, fake-cxl-pool-controller (the pool
# controller of fake-cxl-pool, see scripts/testing/fake-cxl-pool) runs in
# the VM of the test as a transient systemd unit, one per pool server,
# fake-cxl-pool-server runs on the host (pool.source.sh), once per pool.
#
# The driver comes from its image, built like the images of the other
# plugins:
#   make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images
# The e2e framework imports the newest image into the VM of the test
# (playbook/nri-dra-driver-cxl-plugin-deploy.yaml), dra-image-put into the
# other nodes of its cluster.
#
# The contract between the controller and the driver is
# docs/memory/cxl/pool.md, the lease protocol and cxl-request are
# docs/memory/cxl/leases.md.
#
# This file is sourced for every topology of dra-driver-cxl, so it only
# defines functions and variables. The helpers take VMDIR, the output
# directory of a VM, first, like those of pool.source.sh: $OUTPUT_DIR for
# the VM of the test. Other VMs work where pool.source.sh is sourced too
# (n4-cxl-shared-2: $POOL_VM1_DIR and $POOL_VM0_DIR, the workers of the
# cluster).
#
# Typical use:
#   pool-server-start "DEVICES"   # first: dra-install chains its EXIT trap
#   dra-build
#   dra-install
#   dra-trace-start "$VM"
#   dra-apply "$VM" <<EOF ... EOF
#   dra-wait "$VM" LABEL "resourceclaim -n $DRA_NS NAME" "condition('cxl-pool.nri.io/Attached') == 'True'"
#   dra-trace-stop; dra-trace-summary

# The driver in the cluster: its helm chart and release, the values that
# dra-install gives on top of helm-set-args, the directory of the image
# tarballs of "make images", the image of helm-set-args, and the
# DaemonSet, container and pod label of the chart.
DRA_CHART=dra-driver-cxl
DRA_HELM_RELEASE="test"
DRA_HELPER_DIR="$(dirname "${BASH_SOURCE[0]}")"
DRA_HELM_VALUES="$DRA_HELPER_DIR/dra-driver-cxl.helm-values.yaml"
DRA_IMAGE_DIR="$nri_resource_policy_src/build/images"
DRA_TEST_IMAGE=localhost/$DRA_CHART:testing
DRA_DAEMONSET=nri-dra-driver-cxl
DRA_CONTAINER=nri-dra-driver-cxl
DRA_POD_LABEL=app.kubernetes.io/name=nri-dra-driver-cxl
# The DeviceClasses that the chart creates.
DRA_CLASSES=(cxl-local cxl-local-shared cxl-pool cxl-pool-shared cxl-pool-persistent cxl-region cxl-dram cxl-lease)
# The "shares" capacity of every shared device, local or pool
# (device.SharesUnlimited, printed 1M). A claim that requests no shares
# consumes all of them, the device exclusively; shares: "1" is one share.
DRA_SHARES=1000000
# The configuration file of the driver (YAML, .Values.config of the chart,
# docs/memory/cxl/usage.md), "" for none: dra-install gives it to the chart.
# Example: DRA_DRIVER_CONFIG="sharedDevices: [\"$DRA_LOCAL_SERIAL\"]"
DRA_DRIVER_CONFIG=""
# The EXIT trap that dra-install sets, "" for "dra-cleanup; pool-cleanup".
DRA_EXIT_TRAP=""
# Lending memory to running containers (docs/memory/cxl/leases.md): the CLI
# that the driver puts on the node and mounts into containers that claim
# the lease device "lease" (DeviceClass cxl-lease), there and in the
# containers, and the directory of the per-claim lease sockets on the node.
DRA_REQUEST_NODE_BIN=/var/lib/kubelet/plugins/cxl.nri.io/cxl-request
DRA_REQUEST_CTR_BIN=/usr/local/bin/cxl-request
DRA_LEASE_DIR=/var/lib/kubelet/plugins/cxl.nri.io/leases
# The filesystems of fs leases: the host directory of each lease claim
# (<claim uid>) under DRA_LEASE_FS_DIR, a read-only slave bind at
# DRA_LEASE_FS_CTR_DIR in the containers of the claim; the driver binds the
# filesystem of a lease at <claim uid>/<name>, /run/cxl/fs/<name> in them.
DRA_LEASE_FS_DIR=/var/lib/kubelet/plugins/cxl.nri.io/lease-fs
DRA_LEASE_FS_CTR_DIR=/run/cxl/fs
# The labels of the companion pods and claims of leases.
DRA_LEASE_LABEL=cxl.nri.io/lease
DRA_REQUESTER_LABEL=cxl.nri.io/requester-uid
DRA_NODE_LABEL=cxl.nri.io/node
DRA_REQUESTER_ANNOTATION=cxl.nri.io/requester
# Node-local CXL memory devices that the driver publishes whole and
# partitions on demand (cxl.nri.io devices memdev-<serial>, DeviceClass
# cxl-local, docs/memory/cxl/local.md): the state file of the regions and
# slices that the driver created.
DRA_LOCAL_STATE=/var/lib/kubelet/plugins/cxl.nri.io/localDevices.json
DRA_CONTROLLER_BIN="$nri_resource_policy_src/scripts/testing/fake-cxl-pool/bin/fake-cxl-pool-controller"
# The systemd units of the pool controllers in the VM of the test:
# fake-cxl-pool-controller for the first pool server, and
# fake-cxl-pool-controller-<name> for every other server of
# pool.source.sh; the units that dra-install started.
DRA_CONTROLLER_UNIT=fake-cxl-pool-controller
DRA_CONTROLLER_UNITS_GLOB="$DRA_CONTROLLER_UNIT*"
DRA_CONTROLLER_UNITS=()
declare -A DRA_CONTROLLER_URLS=()  # dra-install: unit -> the URL of its pool server, seen from the VMs
DRA_POOL_DRIVER=cxl-pool.nri.io    # pool devices, published by the controller
# The node mounts of the file systems of persistent pool devices (mode fs),
# one per device and access: <serial hex without 0x>-<direct|cached>.
DRA_POOL_MOUNT_DIR=/var/lib/kubelet/plugins/$DRA_POOL_DRIVER/mounts
DRA_LOCAL_DRIVER=cxl.nri.io        # node-local CXL and DRAM, published by the driver
# The opaque configuration of the claims and DeviceClasses of both drivers
# (docs/memory/cxl/usage.md): one kind with the sections device (how the
# kubelet plugin prepares a device), container (how the NRI plugin manages
# the containers that use it: steering is opt-in, policy none by default)
# and pool (pool.opaque.<controller key> for the pool controllers). The
# reference controller's key is fake-cxl-pool (slot, numaNode).
DRA_CONFIG_API=cxl.nri.io/v1alpha1
DRA_CONFIG_KIND=MemoryConfig
DRA_POOL_CONFIG_KEY=fake-cxl-pool
DRA_NS=cxl-pool-demo               # namespace of the test objects
DRA_INSTALLED_VMS=()               # dra-install: the VMDIRs of the nodes, the VM of the test first,
declare -A DRA_WORKERS=()          # and VMDIR -> 1 of the other nodes, the workers
DRA_DAX_TOOL="$DRA_HELPER_DIR/n4-cxl-shared-2/pool-dax-rw.py"
DRA_NUMA_TOOL="$DRA_HELPER_DIR/n4-cxl-shared-2/numa-touch.py"
DRA_JSON=""                        # JSON of the last dra-json/dra-wait
DRA_LOCAL_NAME=""                  # dra-local-device: the device in fake-cxl-pool-server,
DRA_LOCAL_SERIAL=""                # its serial (0x<lower-case hex>),
DRA_LOCAL_HEX=""                   # the serial in environment variable names (upper-case hex),
DRA_LOCAL_SIZE=""                  # its size in bytes,
DRA_LOCAL_DEVICE=""                # its device in the cxl.nri.io ResourceSlice (memdev-<hex>),
DRA_LOCAL_BLOCK_SIZE=""            # the memory block size of the VM in bytes,
DRA_LOCAL_LD=""                    # dra-py expression of its ResourceSlice device,
DRA_LOCAL_REGIONS=""               # cxl-py expression of its regions in cxl-dump,
DRA_LOCAL_PUBLISHED=""             # its ResourceSlice device as JSON,
DRA_LOCAL_ATTACHMENT=""            # and the state of its attachment to the VM
DRA_LOCAL_STATE_JSON=""            # dra-local-state-shared: the state file of the node plugin
DRA_LOCAL_SHARED_REGION=""         # dra-local-shared-wait: the region of the shared local device
DRA_LOCAL_SHARED_DAX=""            # and its dax device (daxX.Y)
DRA_DRIVER_POD=""                  # dra-driver-restart: the new pod of the driver
DRA_CLAIM_JSON=""                  # dra-local-claim-check: the claim
DRA_CLAIM_UID=""                   # and its uid
DRA_NODE_KB=""                     # dra-node-wait: the last MemTotal of the node in kB
DRA_TOOLS_IMAGE=docker.io/library/python:3-alpine   # the image of pods that run the tools of dra-dax-tool-install
DRA_MEMDEV=""                      # JSON of the last dra-memdev-sysfs/dra-memdev-wait
DRA_TOUCH_VM=""                    # dra-touch-start: the VM and POD/CONTAINER of numa-touch.py,
DRA_TOUCH_TARGET=""
DRA_TOUCH_EXEC=""                  # kubectl exec into that container,
DRA_TOUCH_PID=""                   # its pid in the container,
DRA_TOUCH_LOG=""                   # and its output when it had touched its memory
DRA_TOUCH_PAGES=""                 # dra-touch-pages: its pages on the node
DRA_MEM_HIGH=""                    # dra-memory-wait: memory.high of the container
DRA_MEMPOLICY=""                   # and the memory policy of its main process
# The main process of the containers of dra-pod-yaml: it runs /tmp/run
# (written by dra-run) when it appears, so that the workloads are its
# descendants and inherit the memory policy that the driver sets on the
# processes of a steered container. Processes of kubectl exec do not.
DRA_RUNNER='trap "exit 0" TERM
while :; do
    if [ -f /tmp/run ]; then
        mv /tmp/run /tmp/run.sh
        sh /tmp/run.sh > /tmp/run.out 2>&1
        echo $? > /tmp/run.rc.new
        mv /tmp/run.rc.new /tmp/run.rc
    fi
    sleep 0.2 & wait
done'
DRA_TRACE_DIR=""                   # $TEST_OUTPUT_DIR/trace of a running trace
DRA_TRACE_RUNNING=""
DRA_TRACE_VMS=()
# Kill the trace collectors in a VM: each runs in a process group of its own.
DRA_TRACE_KILL='for f in /run/dra-trace/*.pid; do [ -f "$f" ] || continue; kill -TERM -- "-$(cat "$f")" 2>/dev/null; rm -f "$f"; done'

###
### Commands in the VMs
###

dra-vm-command() { # script API
    # Usage: dra-vm-command VMDIR COMMAND
    #
    # vm-command in the VM of VMDIR: through pool-vm-command where
    # pool.source.sh is sourced, else only in the VM of the test.
    if type -t pool-vm-command >/dev/null; then
        pool-vm-command "$1" "$2"
    else
        [ "$1" == "$OUTPUT_DIR" ] || error "dra-vm-command: no pool.source.sh, only the VM of the test is available, not $1"
        vm-command "$2"
    fi
}

dra-vm-command-q() {
    # Usage: dra-vm-command-q VMDIR COMMAND
    #
    # Quiet dra-vm-command: print only the output of COMMAND.
    if type -t pool-vm-command-q >/dev/null; then
        pool-vm-command-q "$1" "$2"
    else
        vm-command-q "$2"
    fi
}

dra-vm-put-file() { # script API
    # Usage: dra-vm-put-file VMDIR SRC-HOST-FILE DST-VM-FILE
    if type -t pool-vm-put-file >/dev/null; then
        pool-vm-put-file "$1" "$2" "$3"
    else
        vm-put-file "$2" "$3"
    fi
}

dra-vm-label() {
    # Usage: dra-vm-label VMDIR
    #
    # Short name of the VM in prompts, file names and trace tags: vm for
    # the VM of the test, vm1 for the VM of n4-cxl-shared-1.
    if type -t pool-vm-label >/dev/null; then
        pool-vm-label "$1"
    elif [ "$1" == "$OUTPUT_DIR" ]; then
        echo "vm"
    else
        basename "$1"
    fi
}

dra-vm-name() {
    # Usage: dra-vm-name VMDIR
    #
    # The host name of the VM, which is also its Kubernetes node name and
    # its host name in fake-cxl-pool.
    basename "$1"
}

dra-kubectl() { # script API
    # Usage: dra-kubectl VMDIR ARGS...
    #
    # Run "kubectl ARGS" in the VM of VMDIR, in its cluster. COMMAND_OUTPUT
    # has the output. ARGS are joined with spaces, quote them for the shell
    # of the VM.
    local vmdir="$1"
    shift
    dra-vm-command "$vmdir" "kubectl $*"
}

dra-apply() { # script API
    # Usage: dra-apply VMDIR <<EOF
    #        YAML
    #        EOF
    #
    # Show the YAML from stdin and "kubectl apply" it in the cluster of the
    # VM of VMDIR, in namespace $DRA_NS unless the YAML names another one.
    # Fail the test if kubectl fails.
    local vmdir="$1" yaml
    yaml=$(cat)
    dra-vm-command "$vmdir" "kubectl apply -n $DRA_NS -f - <<'DRA_APPLY_EOF'
$yaml
DRA_APPLY_EOF" || command-error "kubectl apply failed in $(dra-vm-label "$vmdir")"
}

dra-delete() { # script API
    # Usage: dra-delete VMDIR KIND NAME [KUBECTL-ARGS...]
    #
    # Delete object NAME of KIND in namespace $DRA_NS of the cluster of the
    # VM of VMDIR. Not found is fine. Fail the test if kubectl fails.
    # Example: dra-delete "$VM" pod pooled-consumer --grace-period=2
    local vmdir="$1" kind="$2" name="$3"
    shift 3
    dra-vm-command "$vmdir" "kubectl delete -n $DRA_NS $kind $name --ignore-not-found $*" ||
        command-error "cannot delete $kind $name in $(dra-vm-label "$vmdir")"
}

dra-pull-images() { # script API
    # Usage: dra-pull-images VMDIR IMAGE...
    #
    # Pull IMAGEs in the VM of VMDIR with crictl, so that pull times do not
    # dominate pod start times in the tests.
    local vmdir="$1" image
    shift
    for image in "$@"; do
        dra-vm-command "$vmdir" "crictl pull $image 2>&1 | grep -v 'level=warning'; exit \${PIPESTATUS[0]}" ||
            command-error "cannot pull $image in $(dra-vm-label "$vmdir")"
    done
}

dra-dax-tool-install() { # script API
    # Usage: dra-dax-tool-install VMDIR
    #
    # Create ConfigMap dax-rw in $DRA_NS of the cluster of the VM of VMDIR,
    # with the tools that pods mount at /tools and run with python3 (image
    # $DRA_TOOLS_IMAGE):
    #   dax-rw.py      = pool-dax-rw.py: write and read strings in a devdax
    #                    device, or through an inherited fd (--fd N)
    #   numa-touch.py  = numa-touch.py: allocate and touch memory that
    #                    prefers one NUMA node, or with the memory policy
    #                    of the process, report where the pages are
    local vmdir="$1"
    dra-vm-put-file "$vmdir" "$DRA_DAX_TOOL" /root/dax-rw.py
    dra-vm-put-file "$vmdir" "$DRA_NUMA_TOOL" /root/numa-touch.py
    dra-vm-command "$vmdir" "kubectl create configmap dax-rw -n $DRA_NS --from-file=dax-rw.py=/root/dax-rw.py --from-file=numa-touch.py=/root/numa-touch.py --dry-run=client -o yaml | kubectl apply -f -" ||
        command-error "cannot create ConfigMap dax-rw in $(dra-vm-label "$vmdir")"
}

###
### Installing the DRA components
###

dra-build() { # script API
    # Usage: dra-build
    #
    # Build fake-cxl-pool (server, client and controller) on the host, static
    # amd64 binaries. dra-install copies the controller to the VMs. The
    # driver is not built here: it comes from its image, see the top of this
    # file.
    host-command "make -C \"$nri_resource_policy_src/scripts/testing/fake-cxl-pool\"" ||
        command-error "cannot build fake-cxl-pool"
    [ -x "$DRA_CONTROLLER_BIN" ] ||
        error "dra-build: make did not build $DRA_CONTROLLER_BIN"
}

dra-image-put() { # script API
    # Usage: dra-image-put VMDIR
    #
    # Import the newest image of the driver ($DRA_IMAGE_DIR) into the
    # container runtime of the VM of VMDIR as $DRA_TEST_IMAGE, the way the
    # e2e framework imports it into the VM of the test
    # (playbook/nri-dra-driver-cxl-plugin-deploy.yaml). Skip the copy if
    # $DRA_TEST_IMAGE is that image already.
    local vmdir="$1" label tar file id
    label=$(dra-vm-label "$vmdir")
    # shellcheck disable=SC2012 # the newest by mtime, like the playbook
    tar=$(ls -1t "$DRA_IMAGE_DIR"/nri-dra-driver-cxl-image-*.tar 2>/dev/null | head -n 1)
    [ -n "$tar" ] ||
        error "dra-image-put: no image of the driver in $DRA_IMAGE_DIR, build it: make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images"
    file=${tar##*/}
    id=${file##*-image-}
    id=${id%.tar}
    if [ "${k8scri:-containerd}" == containerd ] &&
           dra-vm-command-q "$vmdir" "ctr -n k8s.io images ls | awk -v ref=$DRA_TEST_IMAGE -v id=sha256:$id '\$1 == ref {t = \$3} index(\$1, id) == 1 {s = \$3} END {exit !(t != \"\" && t == s)}'"; then
        echo "dra-image-put $label: $DRA_TEST_IMAGE is $file already"
        return 0
    fi
    host-command "scp -F \"$vmdir/.ssh-config\" \"$tar\" node:\"$file\"" ||
        command-error "cannot copy $tar to $label"
    if [ "${k8scri:-containerd}" == containerd ]; then
        dra-vm-command "$vmdir" "ctr -n k8s.io images import $file && ref=\$(ctr -n k8s.io images ls | grep sha256:$id | tr -s '\t' ' ' | cut -d ' ' -f1 | head -n 1) && [ -n \"\$ref\" ] && ctr -n k8s.io images tag --force \$ref $DRA_TEST_IMAGE; rc=\$?; rm -f $file; exit \$rc"
    else
        dra-vm-command "$vmdir" "ref=\$(podman image load -i $file | sed -n 's/^Loaded image[^:]*: *//p' | tr ',' '\n' | head -n 1) && [ -n \"\$ref\" ] && podman image tag \$ref $DRA_TEST_IMAGE; rc=\$?; rm -f $file; exit \$rc"
    fi || command-error "cannot import $file as $DRA_TEST_IMAGE in $label"
}

dra-install() { # script API
    # Usage: dra-install
    #
    # Install the driver with helm in the cluster of the VM of the test,
    # on every node of it (release $DRA_HELM_RELEASE in kube-system, with
    # the values of helm-set-args and $DRA_HELM_VALUES, and with the driver
    # configuration $DRA_DRIVER_CONFIG unless it is empty, see
    # dra-helm-values), and run fake-cxl-pool-controller in the VM of the
    # test as a transient systemd unit of the same name, with the admin
    # kubeconfig of the VM: one per pool server that pool-server-start
    # started, unit fake-cxl-pool-controller for the first one and
    # fake-cxl-pool-controller-<name> for the others, each with the URL of
    # its server; the controller names its DRA pool after its server. The
    # chart
    # creates the DeviceClasses of the driver (DRA_CLASSES), and the driver
    # puts cxl-request on its nodes ($DRA_REQUEST_NODE_BIN) for the
    # containers of lease claims. The other nodes get the image of the
    # driver first (dra-image-put). Remove what an earlier run left first:
    # the release, the controller, DeviceClasses, and driver state that
    # refers to CXL regions which are gone (dra-state-cleanup). Create
    # namespace $DRA_NS empty (delete objects that an earlier run left).
    # Wait until the cluster has the pool ResourceSlices of the controllers
    # and the driver is up on every node (dra-wait-node).
    #
    # Call pool-server-start first: the controller needs the server, and
    # dra-install chains its EXIT trap: dra-cleanup, then pool-cleanup, or
    # $DRA_EXIT_TRAP if it is set.
    local vmdir="$OUTPUT_DIR" label url names name v nodes values i units=() urls=()
    label=$(dra-vm-label "$vmdir")
    [ -x "$DRA_CONTROLLER_BIN" ] || error "dra-install: no $DRA_CONTROLLER_BIN, run dra-build first"
    values=$(dra-helm-values) || error "dra-install: no helm values file, see above"
    url="${POOL_GUEST_URL:-http://192.168.76.2:${FAKE_CXL_POOL_PORT:-9909}}"
    # One controller per pool server, the first one with the URL above.
    units=("$DRA_CONTROLLER_UNIT")
    urls=("$url")
    for name in "${POOL_SERVERS[@]:1}"; do
        v=$(pool-guest-url "$name") || error "dra-install: no URL of the pool server $name"
        units+=("$DRA_CONTROLLER_UNIT-$name")
        urls+=("$v")
    done
    # The nodes of the cluster are VMs next to the VM of the test, named
    # after their output directories, the VM of the test first.
    names=$(dra-vm-command-q "$vmdir" "kubectl get nodes -o jsonpath='{.items[*].metadata.name}'") ||
        error "dra-install: cannot list the nodes of the cluster of $label"
    nodes=("$vmdir")
    for name in $names; do
        [ "$name" != "$(dra-vm-name "$vmdir")" ] || continue
        v=$(vmdir-of "$name")
        [ -f "$v/.ssh-config" ] || error "dra-install: node $name of the cluster of $label is not a VM in $v"
        nodes+=("$v")
    done
    echo "dra-install: the cluster of $label has ${#nodes[@]} nodes: $names"
    for v in "${nodes[@]:1}"; do
        dra-image-put "$v"
    done

    echo "dra-install: removing components of an earlier run, if any"
    dra-helm-uninstall ||
        error "dra-install: pods of $DRA_DAEMONSET of an earlier run are left in the cluster of $label"
    dra-vm-command "$vmdir" "systemctl stop '$DRA_CONTROLLER_UNITS_GLOB' 2>/dev/null; systemctl reset-failed '$DRA_CONTROLLER_UNITS_GLOB' 2>/dev/null; kubectl delete deviceclass --ignore-not-found ${DRA_CLASSES[*]}" ||
        command-error "cannot remove the components of an earlier run in $label"
    for v in "${nodes[@]}"; do
        dra-state-cleanup "$v"
    done
    dra-vm-put-file "$vmdir" "$DRA_CONTROLLER_BIN" /usr/local/bin/fake-cxl-pool-controller
    dra-vm-command "$vmdir" "chmod 755 /usr/local/bin/fake-cxl-pool-controller" ||
        command-error "cannot install fake-cxl-pool-controller in $label"

    echo "dra-install: installing $DRA_CHART with helm on ${#nodes[@]} nodes, starting ${units[*]} in $label"
    DRA_INSTALLED_VMS=("${nodes[@]}")
    DRA_WORKERS=()
    for v in "${nodes[@]:1}"; do
        DRA_WORKERS["$v"]=1
    done
    if [ -n "$DRA_EXIT_TRAP" ]; then
        # shellcheck disable=SC2064 # the value is the trap command itself
        trap "$DRA_EXIT_TRAP" EXIT
    elif type -t pool-cleanup >/dev/null; then
        trap 'dra-cleanup; pool-cleanup' EXIT
    else
        trap dra-cleanup EXIT
    fi
    # helm-launch also collects the log of the driver into the test output
    # (nri-resource-policy.output.txt).
    helm_config="$values" helm_name="$DRA_HELM_RELEASE" launch_available="${#nodes[@]}" launch_timeout=120s \
        helm-launch "$DRA_CHART"
    DRA_CONTROLLER_UNITS=()
    DRA_CONTROLLER_URLS=()
    for i in "${!units[@]}"; do
        DRA_CONTROLLER_URLS["${units[$i]}"]="${urls[$i]}"
        dra-controller-run "${units[$i]}" ||
            command-error "cannot start ${units[$i]} in $label"
        DRA_CONTROLLER_UNITS+=("${units[$i]}")
    done
    dra-vm-command "$vmdir" "kubectl get deviceclass ${DRA_CLASSES[*]}" ||
        command-error "the chart $DRA_CHART does not create the DeviceClasses ${DRA_CLASSES[*]} in $label"

    for v in "${nodes[@]}"; do
        dra-wait-node "$v"
    done

    dra-vm-command "$vmdir" "kubectl delete pods --all -n $DRA_NS --grace-period=2 --ignore-not-found --wait=true --timeout=60s 2>&1 | grep -v 'No resources found'; kubectl delete namespace $DRA_NS --ignore-not-found --wait=true --timeout=120s && kubectl create namespace $DRA_NS" ||
        command-error "cannot create namespace $DRA_NS in $label"
}

dra-controller-run() {
    # Usage: dra-controller-run UNIT
    #
    # Start fake-cxl-pool-controller as the transient systemd unit UNIT in
    # the VM of the test, with the URL of its pool server
    # (DRA_CONTROLLER_URLS), Restart=no and the admin kubeconfig of the VM:
    # the command line of dra-install. Return the status of systemd-run.
    local unit="$1" url="${DRA_CONTROLLER_URLS[$1]:-}"
    if [ -z "$url" ]; then
        echo "dra-controller-run: no pool server URL of $unit: dra-install starts the controllers" >&2
        return 2
    fi
    dra-vm-command "$OUTPUT_DIR" "systemd-run --unit $unit --property=Restart=no -E KUBECONFIG=/root/.kube/config /usr/local/bin/fake-cxl-pool-controller -server $url -v"
}

dra-controller-start() { # script API
    # Usage: dra-controller-start UNIT
    #
    # Start the pool controller UNIT of dra-install (one of
    # DRA_CONTROLLER_UNITS) again after it stopped or was killed: the unit
    # is transient with Restart=no, so a killed one stays failed until
    # "systemctl reset-failed", which also removes it, and systemd-run
    # creates it again with the command line of dra-install
    # (dra-controller-run). Wait until it is active, 10 s at most. Return
    # non-zero if it does not start, for instance because it runs already.
    local unit="$1"
    dra-vm-command "$OUTPUT_DIR" "systemctl reset-failed $unit 2>/dev/null; systemctl is-active $unit" &&
        { echo "dra-controller-start: $unit is active already" >&2; return 1; }
    dra-controller-run "$unit" || return 1
    retry-until --timeout 10 --interval 1 --message "$unit active" \
        'dra-vm-command-q "$OUTPUT_DIR" "systemctl -q is-active $unit"'
}

dra-controller-stop() { # script API
    # Usage: dra-controller-stop UNIT
    #
    # Stop the pool controller UNIT of dra-install gracefully (systemctl
    # stop: SIGTERM, the controller deletes the ResourceSlices of its pool
    # before it exits) and remove the unit (reset-failed). Return non-zero
    # if it is still active.
    dra-vm-command "$OUTPUT_DIR" "systemctl stop $1; systemctl reset-failed $1 2>/dev/null; ! systemctl -q is-active $1"
}

dra-controller-kill() { # script API
    # Usage: dra-controller-kill UNIT
    #
    # Kill the pool controller UNIT of dra-install with SIGKILL: it leaves
    # its ResourceSlices behind and, with Restart=no, its unit stays failed
    # until dra-controller-start. Wait until it is not active any more, 5 s
    # at most. Return non-zero if it was not active or is still active.
    dra-vm-command "$OUTPUT_DIR" "systemctl -q is-active $1 || { echo '$1 is not active'; exit 1; }
systemctl kill --signal=SIGKILL $1 || exit 1
for i in \$(seq 50); do systemctl -q is-active $1 || break; sleep 0.1; done
systemctl is-active $1; ! systemctl -q is-active $1"
}

dra-helm-values() {
    # Usage: dra-helm-values
    #
    # Print the path of the helm values file of dra-install: $DRA_HELM_VALUES
    # when DRA_DRIVER_CONFIG is empty, else
    # $TEST_OUTPUT_DIR/dra-driver-cxl.helm-values.yaml, written now: the
    # values of $DRA_HELM_VALUES and "config:" with DRA_DRIVER_CONFIG, the
    # configuration file of the driver. Show the file. Fail the test if
    # $DRA_HELM_VALUES is missing or has a config already.
    local file="$TEST_OUTPUT_DIR/dra-driver-cxl.helm-values.yaml"
    [ -f "$DRA_HELM_VALUES" ] || error "dra-install: no helm values $DRA_HELM_VALUES"
    if [ -z "$DRA_DRIVER_CONFIG" ]; then
        echo "$DRA_HELM_VALUES"
        return 0
    fi
    ! grep -q '^config:' "$DRA_HELM_VALUES" ||
        error "dra-install: $DRA_HELM_VALUES has a config, DRA_DRIVER_CONFIG cannot be added to it"
    # shellcheck disable=SC2001 # sed indents every line of the configuration
    { cat "$DRA_HELM_VALUES"
      echo ""
      echo "# DRA_DRIVER_CONFIG of $(basename "${TEST_DIR:-test}"), written by dra-install"
      echo "config:"
      sed 's/^/  /' <<< "$DRA_DRIVER_CONFIG"
    } > "$file" || error "dra-install: cannot write $file"
    echo "dra-install: helm values with the driver configuration, $file:" >&2
    cat "$file" >&2
    echo "$file"
}

dra-helm-uninstall() {
    # Usage: dra-helm-uninstall
    #
    # Uninstall release $DRA_HELM_RELEASE from the cluster of the VM of the
    # test, if it has one, and wait until no pod of the driver is left in
    # the cluster. Return non-zero if some are left.
    helm_name="$DRA_HELM_RELEASE" helm-terminate
    retry-until --timeout 60 --interval 1 --message "no pods of $DRA_DAEMONSET in the cluster" \
        '[ -z "$(vm-command-q "kubectl get pods -n kube-system -l $DRA_POD_LABEL -o name" 2>/dev/null)" ]'
}

dra-state-cleanup() {
    # Usage: dra-state-cleanup VMDIR
    #
    # Remove the state of the driver in the VM of VMDIR that refers to CXL
    # regions, if the VM has no regions: then it is a leftover of an earlier
    # VM boot. That is the prepared pool claims (preparedPoolClaims.json),
    # the regions and slices of local devices (localDevices.json), the
    # leases (leases.json) and the lease sockets of lease claims (leases/).
    dra-vm-command "$1" "if ls /sys/bus/cxl/devices/ | grep -q '^region[0-9]'; then echo 'CXL regions exist, keeping the CXL state of the driver'; else rm -fv /var/lib/kubelet/plugins/$DRA_POOL_DRIVER/preparedPoolClaims.json $DRA_LOCAL_STATE /var/lib/kubelet/plugins/$DRA_LOCAL_DRIVER/leases.json; rm -rfv /var/lib/kubelet/plugins/$DRA_LOCAL_DRIVER/leases; fi"
}

dra-wait-node() {
    # Usage: dra-wait-node VMDIR
    #
    # Wait until the cluster of the VM of VMDIR has a pool ResourceSlice of
    # every started pool server (dra-pool-names) and the cxl.nri.io
    # ResourceSlice of the node, and the node has the kubelet plugin socket
    # of cxl-pool.nri.io and the cxl-request of the driver.
    local vmdir="$1" name label pools
    name=$(dra-vm-name "$vmdir")
    label=$(dra-vm-label "$vmdir")
    pools=$(dra-pool-names | tr '\n' ' ')
    retry-until --timeout 60 --interval 2 --message "$label: ResourceSlices of $DRA_POOL_DRIVER${pools:+ (pools ${pools% })} and $DRA_LOCAL_DRIVER on $name, $DRA_POOL_DRIVER kubelet plugin socket, $DRA_REQUEST_NODE_BIN" \
        'dra-install-ready "$vmdir" "$name"' || {
        dra-vm-command "$vmdir" "kubectl get pods -n kube-system -l $DRA_POD_LABEL -o wide; kubectl logs -n kube-system --tail=40 -c $DRA_CONTAINER \$(kubectl get pods -n kube-system -l $DRA_POD_LABEL --field-selector spec.nodeName=$name -o name | head -n 1); systemctl status --no-pager '$DRA_CONTROLLER_UNITS_GLOB'; journalctl --no-pager -n 40 -u '$DRA_CONTROLLER_UNITS_GLOB'; kubectl get resourceslices; ls -l /var/lib/kubelet/plugins/*"
        error "dra-install: the DRA components did not come up in $label"
    }
    dra-vm-command "$vmdir" "kubectl get resourceslices; ls -l /var/lib/kubelet/plugins/$DRA_POOL_DRIVER/ $DRA_REQUEST_NODE_BIN"
}

dra-install-ready() {
    # Usage: dra-install-ready VMDIR NODENAME
    local vmdir="$1" name="$2" json pools="" pool
    json=$(dra-vm-command-q "$vmdir" "kubectl get resourceslices -o json") || return 1
    for pool in $(dra-pool-names); do
        pools+="'$pool', "
    done
    dra-py assert "$json" "slices(\"$DRA_POOL_DRIVER\") and set([$pools]) <= set(s['spec']['pool']['name'] for s in slices(\"$DRA_POOL_DRIVER\")) and slices(\"$DRA_LOCAL_DRIVER\", \"$name\")" || return 1
    dra-vm-command-q "$vmdir" "test -S /var/lib/kubelet/plugins/$DRA_POOL_DRIVER/dra.sock && test -x $DRA_REQUEST_NODE_BIN"
}

dra-driver-pod() {
    # Usage: dra-driver-pod VMDIR
    #
    # Print the name of the running pod of the driver on the node of the VM
    # of VMDIR, quietly. Return 1 if there is none.
    local pod
    pod=$(dra-vm-command-q "$1" "kubectl get pods -n kube-system -l $DRA_POD_LABEL --field-selector spec.nodeName=$(dra-vm-name "$1"),status.phase=Running -o name" 2>/dev/null | head -n 1)
    [ -n "$pod" ] || return 1
    echo "${pod#pod/}"
}

dra-plugin-log-save() {
    # Usage: dra-plugin-log-save VMDIR
    #
    # Store the log of the driver on the node of the VM of VMDIR as
    # $TEST_OUTPUT_DIR/nri-dra-driver-cxl.<vm>.log, if the driver runs there.
    local pod file
    pod=$(dra-driver-pod "$1") || return 0
    file="$TEST_OUTPUT_DIR/$DRA_CONTAINER.$(dra-vm-label "$1").log"
    dra-vm-command-q "$1" "kubectl logs -n kube-system $pod -c $DRA_CONTAINER" > "$file" 2>&1
    echo "log of $DRA_CONTAINER in $(dra-vm-label "$1"): $file"
}

dra-pool-names() {
    # Usage: dra-pool-names
    #
    # Print the DRA pool names of the pool servers that pool-server-start
    # started, one per line: their names. Print nothing if there are none.
    local name
    for name in "${POOL_SERVERS[@]}"; do
        echo "$name"
    done
}

dra-pool-urls() {
    # Usage: dra-pool-urls
    #
    # Print the URLs on the host of the pool servers that pool-server-start
    # started, one per line, or $POOL_URL if it started none. Print nothing
    # if there is no server.
    local name
    if [ "${#POOL_SERVERS[@]}" -gt 0 ]; then
        for name in "${POOL_SERVERS[@]}"; do
            pool-url "$name"
        done
    elif [ -n "$POOL_URL" ]; then
        echo "$POOL_URL"
    fi
}

dra-pool-attachments() {
    # Usage: dra-pool-attachments HOST [URL]
    #
    # Print the attachments on HOST of the server at URL (default:
    # $POOL_URL) that a pool controller owns (owner k8s:...), one
    # "device@host owner state" per line. Print nothing if there is no
    # server.
    local url="${2:-$POOL_URL}"
    [ -n "$url" ] || return 0
    curl -s --max-time 10 "$url/api/v1/attachments" 2>/dev/null | python3 -c '
import json, sys
try:
    atts = json.load(sys.stdin) or []
except ValueError:
    sys.exit(0)
for a in atts:
    if a.get("host") == sys.argv[1] and (a.get("owner") or "").startswith("k8s:"):
        print(a["device"] + "@" + a["host"], a.get("owner"), a.get("state"))' "$1"
}

dra-uninstall() { # script API
    # Usage: dra-uninstall
    #
    # Undo dra-install: delete namespace $DRA_NS (its pods first,
    # gracefully: the driver unprepares their claims, and the controllers
    # detach the devices when the claims are gone), wait until the
    # controllers have detached the devices of every node on every pool
    # server, store the log of the driver of every node
    # (dra-plugin-log-save), uninstall the driver and its DeviceClasses
    # (dra-helm-uninstall), stop the controllers (every unit
    # fake-cxl-pool-controller*), delete the pool ResourceSlices they left
    # and remove the driver state of every node (dra-state-cleanup). Never
    # fails the test: it runs in the EXIT trap.
    local vmdir="$OUTPUT_DIR" label left v host url urls
    [ "${#DRA_INSTALLED_VMS[@]}" -gt 0 ] || return 0
    label=$(dra-vm-label "$vmdir")
    echo "dra-uninstall: the cluster of $label"
    dra-vm-command "$vmdir" "kubectl delete pods --all -n $DRA_NS --grace-period=2 --ignore-not-found --wait=true --timeout=60s 2>&1 | grep -v 'No resources found'; kubectl delete namespace $DRA_NS --ignore-not-found --wait=true --timeout=120s"
    retry-until --timeout 60 --interval 2 --message "no ResourceClaims in $DRA_NS" \
        '[ -z "$(dra-vm-command-q "$vmdir" "kubectl get resourceclaims -n $DRA_NS -o name 2>/dev/null")" ]' ||
        echo "dra-uninstall: ResourceClaims remain in $DRA_NS"
    urls=$(dra-pool-urls)
    for v in "${DRA_INSTALLED_VMS[@]}"; do
        host=$(dra-vm-name "$v")
        for url in $urls; do
            if [ -n "$(dra-pool-attachments "$host" "$url")" ]; then
                retry-until --timeout 60 --interval 2 --message "the controller of $url detaches the pool devices of $host" \
                    '[ -z "$(dra-pool-attachments "$host" "$url")" ]' || {
                    echo "dra-uninstall: attachments left on $url, pool-cleanup releases and detaches them:"
                    dra-pool-attachments "$host" "$url"
                }
            fi
        done
    done
    for v in "${DRA_INSTALLED_VMS[@]}"; do
        dra-plugin-log-save "$v"
    done
    dra-helm-uninstall ||
        echo "dra-uninstall: pods of $DRA_DAEMONSET are left"
    dra-vm-command "$vmdir" "systemctl stop '$DRA_CONTROLLER_UNITS_GLOB' 2>/dev/null; systemctl reset-failed '$DRA_CONTROLLER_UNITS_GLOB' 2>/dev/null; true"
    DRA_CONTROLLER_UNITS=()
    left=$(dra-vm-command-q "$vmdir" "kubectl get resourceslices -o jsonpath='{range .items[?(@.spec.driver==\"$DRA_POOL_DRIVER\")]}{.metadata.name}{\"\\n\"}{end}'")
    if [ -n "$left" ]; then
        dra-vm-command "$vmdir" "kubectl delete resourceslices $(tr "\n" " " <<< "$left")"
    fi
    for v in "${DRA_INSTALLED_VMS[@]}"; do
        dra-state-cleanup "$v"
    done
    DRA_INSTALLED_VMS=()
    DRA_WORKERS=()
    return 0
}

dra-cleanup() {
    # Usage: dra-cleanup
    #
    # The EXIT trap of dra-install (before pool-cleanup): dra-uninstall,
    # then stop the trace if it runs. Report CXL memory devices that are
    # still in the nodes: pool-cleanup, which runs next, releases and
    # detaches them.
    local vmdir vms memdevs
    vms=("${DRA_INSTALLED_VMS[@]}")
    dra-uninstall
    dra-trace-stop
    for vmdir in "${vms[@]}"; do
        memdevs=$(dra-vm-command-q "$vmdir" "ls /sys/bus/cxl/devices/ | grep -E '^mem[0-9]'")
        if [ -n "$memdevs" ]; then
            echo "dra-cleanup: $(dra-vm-label "$vmdir") still has CXL memory devices: $(tr "\n" " " <<< "$memdevs")"
        else
            echo "dra-cleanup: $(dra-vm-label "$vmdir") has no CXL memory devices"
        fi
    done
    return 0
}

###
### Node-local CXL memory devices
###

dra-local-find() {
    # Usage: dra-local-find [--pool NAME] VMDIR
    #
    # Set DRA_LOCAL_NAME, DRA_LOCAL_SERIAL, DRA_LOCAL_HEX, DRA_LOCAL_SIZE,
    # DRA_LOCAL_DEVICE and DRA_LOCAL_ATTACHMENT (attached, detached, or
    # another attachment state) of the local CXL memory device of the VM of
    # VMDIR in fake-cxl-pool-server NAME (default: the first started
    # server; a server knows the local devices of the VMs it is cabled to):
    # the device of scope local that is bound to this VM only and is not
    # shared (a memory-backend-ram device of the topology). Fail the test
    # unless there is exactly one.
    local server=() host found
    if [ "$1" == "--pool" ]; then
        server=(--pool "$2")
        shift 2
    fi
    type -t pool-host-client >/dev/null ||
        error "${FUNCNAME[1]}: needs pool.source.sh and fake-cxl-pool-server (pool-server-start)"
    host=$(dra-vm-name "$1")
    pool-host-client "${server[@]}" -o json devices || command-error "cannot list the devices of fake-cxl-pool-server${server[1]:+ ${server[1]}}"
    found=$(pool-value "$COMMAND_OUTPUT" "chr(10).join(' '.join([d['name'], d['serial'], str(d['size']), next((a['state'] for a in d.get('attachments') or [] if a['host'] == '$host'), 'detached')]) for d in j if d.get('scope') == 'local' and not d.get('shared') and (d.get('localHosts') or [d.get('localHost')]) == ['$host'])")
    [ -n "$found" ] && [ "$(wc -l <<< "$found")" == 1 ] ||
        error "${FUNCNAME[1]}: expected one local, not shared device of $host in fake-cxl-pool-server, found: '$found'"
    read -r DRA_LOCAL_NAME DRA_LOCAL_SERIAL DRA_LOCAL_SIZE DRA_LOCAL_ATTACHMENT <<< "$found"
    DRA_LOCAL_HEX=${DRA_LOCAL_SERIAL#0x}
    DRA_LOCAL_DEVICE="memdev-${DRA_LOCAL_HEX,,}"
    DRA_LOCAL_HEX=${DRA_LOCAL_HEX^^}
}

dra-local-device() { # script API
    # Usage: dra-local-device [--pool NAME] VMDIR
    #
    # Attach the local CXL memory device of the VM of VMDIR (see
    # dra-local-find) through fake-cxl-pool-server NAME (default: the first
    # started server), unless it is attached, and wait until pkg/cxl sees
    # it in the VM. If dra-install runs in the
    # VM, wait also until the node's cxl.nri.io ResourceSlice has its
    # device. Print and set DRA_LOCAL_NAME (the device in the server),
    # DRA_LOCAL_SERIAL (0x<lower-case hex>), DRA_LOCAL_HEX (the serial in
    # environment variable names, upper-case hex), DRA_LOCAL_SIZE (bytes),
    # DRA_LOCAL_DEVICE (memdev-<lower-case hex>, its device in the
    # ResourceSlice), DRA_LOCAL_BLOCK_SIZE (the memory block size of the
    # VM in bytes, see dra-block-size), DRA_LOCAL_LD (its device in the
    # ResourceSlices of dra-py), DRA_LOCAL_REGIONS (its regions in cxl-dump
    # of cxl-py) and, if dra-install runs in the VM, DRA_LOCAL_PUBLISHED
    # (its device in the ResourceSlice as JSON, see dra-local-unchanged).
    # The attachment has the owner e2e:dra-local-device, not a k8s: owner of
    # the pool controller.
    local server=() vmdir host label v installed=""
    if [ "$1" == "--pool" ]; then
        server=(--pool "$2")
        shift 2
    fi
    vmdir="$1"
    host=$(dra-vm-name "$vmdir")
    label=$(dra-vm-label "$vmdir")
    dra-local-find "${server[@]}" "$vmdir"
    case "$DRA_LOCAL_ATTACHMENT" in
        attached)
            echo "dra-local-device $label: $DRA_LOCAL_NAME is attached already";;
        detached)
            pool-host-client "${server[@]}" -o json attach "$DRA_LOCAL_NAME" --host "$host" --owner e2e:dra-local-device ||
                command-error "cannot attach the local device $DRA_LOCAL_NAME to $label";;
        *)
            error "dra-local-device: the attachment of $DRA_LOCAL_NAME to $host is $DRA_LOCAL_ATTACHMENT";;
    esac
    pool-cxl-wait "$vmdir" local-device "by_serial($DRA_LOCAL_SERIAL) is not None" 60
    for v in "${DRA_INSTALLED_VMS[@]}"; do
        [ "$v" != "$vmdir" ] || installed=1
    done
    DRA_LOCAL_LD="device('$DRA_LOCAL_DEVICE', '$DRA_LOCAL_DRIVER', '$host')"
    DRA_LOCAL_PUBLISHED=""
    if [ -n "$installed" ]; then
        dra-wait "$vmdir" local-device resourceslices "$DRA_LOCAL_LD is not None and attr($DRA_LOCAL_LD, 'type') == 'memdev' and attr($DRA_LOCAL_LD, 'serial') == '$DRA_LOCAL_SERIAL'" 60
        DRA_LOCAL_PUBLISHED=$(dra-value "$COMMAND_OUTPUT" "json.dumps($DRA_LOCAL_LD, sort_keys=True)")
    fi
    DRA_LOCAL_BLOCK_SIZE=$(dra-block-size "$vmdir") ||
        error "dra-local-device: cannot read the memory block size of $label"
    DRA_LOCAL_REGIONS="[r for r in regions if by_serial($DRA_LOCAL_SERIAL) is not None and names(r['Memories']) == [by_serial($DRA_LOCAL_SERIAL)['Name']]]"
    echo "dra-local-device $label: $DRA_LOCAL_NAME, serial $DRA_LOCAL_SERIAL ($DRA_LOCAL_HEX), $DRA_LOCAL_SIZE bytes, ResourceSlice device $DRA_LOCAL_DEVICE, memory block size $DRA_LOCAL_BLOCK_SIZE bytes"
}

dra-local-detach() { # script API
    # Usage: dra-local-detach [--pool NAME] VMDIR
    #
    # Detach the local CXL memory device of the VM of VMDIR (see
    # dra-local-device) if it is attached, and wait until pkg/cxl does not
    # see it any more. While the driver runs on the node, wait first until
    # it has released the regions of the device. Then release what is left of it
    # in the VM (fake-cxl-pool-client guest release: offline, destroy the
    # regions, disable the memdev) and detach it through
    # fake-cxl-pool-server NAME (default: the first started server).
    local server=() vmdir host label expr
    if [ "$1" == "--pool" ]; then
        server=(--pool "$2")
        shift 2
    fi
    vmdir="$1"
    host=$(dra-vm-name "$vmdir")
    label=$(dra-vm-label "$vmdir")
    dra-local-find "${server[@]}" "$vmdir"
    if [ "$DRA_LOCAL_ATTACHMENT" == detached ]; then
        echo "dra-local-detach $label: $DRA_LOCAL_NAME is not attached"
        return 0
    fi
    expr="by_serial($DRA_LOCAL_SERIAL) is None or not any(by_serial($DRA_LOCAL_SERIAL)['Name'] in names(r['Memories']) for r in regions)"
    if dra-driver-pod "$vmdir" >/dev/null; then
        pool-cxl-wait "$vmdir" local-released "$expr" 60
    fi
    pool-client "${server[@]}" "$vmdir" guest release "$DRA_LOCAL_SERIAL" ||
        command-error "cannot release $DRA_LOCAL_NAME in $label"
    pool-host-client "${server[@]}" detach "$DRA_LOCAL_NAME" --host "$host" ||
        command-error "cannot detach $DRA_LOCAL_NAME from $label"
    pool-cxl-wait "$vmdir" local-detached "by_serial($DRA_LOCAL_SERIAL) is None" 60
    echo "dra-local-detach $label: $DRA_LOCAL_NAME detached"
}

dra-memdev-sysfs() { # script API
    # Usage: dra-memdev-sysfs VMDIR SERIAL
    #
    # Read in the sysfs of the VM of VMDIR what the CXL memory device with
    # SERIAL (0x<lower-case hex>) has, as one JSON object:
    #   memdev    its name (memN), null if it is not there
    #   enabled   whether its driver is bound
    #   regions   its regions: name, size, and of its dax region available
    #             (available_size), align and dax: the dax devices (name,
    #             size, node = target_node, dev = "major:minor", driver)
    # DRA_MEMDEV and COMMAND_OUTPUT have the JSON. Return non-zero if the VM
    # cannot be read.
    local vmdir="$1" serial="$2" script text
    script="s=$serial
$(cat <<'EOF'
for m in /sys/bus/cxl/devices/mem[0-9]*; do
    [ "$(cat "$m/serial" 2>/dev/null)" == "$s" ] || continue
    mem=${m##*/} ep="" drv=$(readlink "$m/driver" 2>/dev/null)
    drv=${drv##*/}
    for e in /sys/bus/cxl/devices/endpoint[0-9]*; do
        [ "$(basename "$(readlink "$e/uport" 2>/dev/null)")" == "$mem" ] && ep=${e##*/}
    done
    echo "memdev $mem ${ep:--} ${drv:--}"
    [ -n "$ep" ] || break
    for r in /sys/bus/cxl/devices/region[0-9]*; do
        [ -e "$r" ] || continue
        cat "$r"/target* 2>/dev/null | grep -q "^decoder${ep#endpoint}\." || continue
        dr=$(ls -d "$r"/dax_region[0-9]* 2>/dev/null | head -n 1)
        echo "region ${r##*/} $(cat "$r/size") $(cat "$dr/dax_region/available_size" 2>/dev/null || echo -1) $(cat "$dr/dax_region/align" 2>/dev/null || echo -1)"
        for x in "$dr"/dax[0-9]*.[0-9]*; do
            [ -n "$dr" ] && [ -e "$x" ] || continue
            d=$(readlink "$x/driver" 2>/dev/null)
            d=${d##*/}
            echo "dax ${x##*/} $(cat "$x/size") $(cat "$x/target_node") $(cat "$x/dev") ${d:--}"
        done
    done
    break
done
EOF
)"
    text=$(dra-vm-command-q "$vmdir" "$script") || return 1
    DRA_MEMDEV=$(python3 -c '
import json, sys
out = {"serial": sys.argv[1], "memdev": None, "enabled": False, "regions": []}
for line in sys.stdin.read().splitlines():
    w = line.split()
    if len(w) == 4 and w[0] == "memdev":
        out.update(memdev=w[1], endpoint=None if w[2] == "-" else w[2], enabled=w[3] != "-")
    elif len(w) == 5 and w[0] == "region":
        out["regions"].append({"name": w[1], "size": int(w[2], 0), "available": int(w[3], 0), "align": int(w[4], 0), "dax": []})
    elif len(w) == 6 and w[0] == "dax" and out["regions"]:
        out["regions"][-1]["dax"].append({"name": w[1], "size": int(w[2], 0), "node": int(w[3]), "dev": w[4], "driver": None if w[5] == "-" else w[5]})
print(json.dumps(out))' "$serial" <<< "$text") || return 1
    COMMAND_OUTPUT="$DRA_MEMDEV"
}

dra-memdev-wait() { # script API
    # Usage: dra-memdev-wait VMDIR LABEL SERIAL EXPRESSION [TIMEOUT]
    #
    # Repeat dra-memdev-sysfs VMDIR SERIAL until the Python EXPRESSION (see
    # dra-py, j is the document, dax_slices() its dax devices with a size)
    # is true on it, TIMEOUT seconds at most (default 60). Store the last
    # JSON in $TEST_OUTPUT_DIR/memdev.LABEL.<vm>.json and in DRA_MEMDEV and
    # COMMAND_OUTPUT. Fail the test on timeout, showing the JSON.
    local vmdir="$1" label="$2" serial="$3" expression="$4" tmo="${5:-60}" file
    file="$TEST_OUTPUT_DIR/memdev.$label.$(dra-vm-label "$vmdir").json"
    retry-until --timeout "$tmo" --message "$(dra-vm-label "$vmdir"): sysfs of CXL memory device $serial: $expression" \
        'dra-memdev-sysfs "$vmdir" "$serial" && dra-py assert "$DRA_MEMDEV" "$expression" 2>/dev/null' || {
        echo "$DRA_MEMDEV" > "$file"
        error "$(dra-vm-label "$vmdir"): CXL memory device $serial did not reach the expected state in ${tmo}s: $expression
sysfs: $DRA_MEMDEV"
    }
    echo "$DRA_MEMDEV" > "$file"
    COMMAND_OUTPUT="$DRA_MEMDEV"
    echo "memdev ok: $label: $expression"
    echo "memdev $serial: $DRA_MEMDEV"
}

dra-block-size() { # script API
    # Usage: dra-block-size VMDIR
    #
    # Print the memory block size of the VM of VMDIR in bytes, the unit in
    # which memory goes online and offline: block_size_bytes in
    # /sys/devices/system/memory, parsed by cxl-block-size-parse
    # (cxl.source.sh). Return non-zero if it cannot be read.
    local text
    type -t cxl-block-size-parse >/dev/null ||
        error "${FUNCNAME[1]}: needs cxl.source.sh"
    text=$(dra-vm-command-q "$1" "cat /sys/devices/system/memory/block_size_bytes") || return 1
    cxl-block-size-parse "$text"
}

dra-node-memtotal() { # script API
    # Usage: dra-node-memtotal VMDIR NODE
    #
    # Print MemTotal of NUMA node NODE of the VM of VMDIR in kB
    # (/sys/devices/system/node/nodeNODE/meminfo), 0 if the node is not
    # there, quietly. Return non-zero if it cannot be read or NODE is not a
    # number.
    local kb
    [[ "$2" =~ ^[0-9]+$ ]] || return 1
    kb=$(dra-vm-command-q "$1" "d=/sys/devices/system/node/node$2; if [ -d \$d ]; then awk '\$3 == \"MemTotal:\" {print \$4}' \$d/meminfo; else echo 0; fi") || return 1
    [[ "$kb" =~ ^[0-9]+$ ]] || return 1
    echo "$kb"
}

dra-node-wait() { # script API
    # Usage: dra-node-wait VMDIR NODE KB [TIMEOUT]
    #
    # Wait until MemTotal of NUMA node NODE of the VM of VMDIR is KB kB (0:
    # the node has no memory or is not there), TIMEOUT seconds at most
    # (default 30), and print the line of the node in "numactl -H".
    # DRA_NODE_KB is the last MemTotal read. Fail the test on timeout.
    local vmdir="$1" node="$2" kb="$3" tmo="${4:-30}" label
    label=$(dra-vm-label "$vmdir")
    [[ "$node" =~ ^[0-9]+$ ]] || error "dra-node-wait: NUMA node '$node' is not a number"
    DRA_NODE_KB=""
    retry-until --timeout "$tmo" --interval 1 --message "$label: MemTotal of NUMA node $node is $kb kB" \
        'DRA_NODE_KB=$(dra-node-memtotal "$vmdir" "$node") && [ "$DRA_NODE_KB" == "$kb" ]' ||
        error "$label: MemTotal of NUMA node $node is ${DRA_NODE_KB:-unreadable} kB after ${tmo}s, expected $kb kB"
    echo "node ok: $label: MemTotal of NUMA node $node is $kb kB, numactl -H: $(dra-vm-command-q "$vmdir" "numactl -H | grep '^node $node size:'" || echo "no node $node")"
}

dra-node-size-exact() { # script API
    # Usage: dra-node-size-exact VMDIR
    #
    # Fail the test unless MemTotal of a NUMA node of the VM of VMDIR grows
    # and shrinks by exactly the memory blocks that go online and offline
    # on it: memory_hotplug.memmap_on_memory is off (the parameter is
    # missing or N).
    local value
    value=$(dra-vm-command-q "$1" "cat /sys/module/memory_hotplug/parameters/memmap_on_memory 2>/dev/null || echo missing")
    echo "$(dra-vm-label "$1"): memory_hotplug.memmap_on_memory: $value"
    [ "$value" == missing ] || [ "$value" == N ] ||
        error "memory_hotplug.memmap_on_memory is '$value' in $(dra-vm-label "$1"), expected missing or N: with it, the vmemmap of hotplugged memory blocks comes from the blocks themselves, and MemTotal of a node is not the size of its online blocks. Boot the VM without memory_hotplug.memmap_on_memory"
}

dra-mi() { # script API
    # Usage: dra-mi BYTES
    #
    # Print BYTES as a quantity in Mi.
    echo "$(( $1 >> 20 ))Mi"
}

dra-local-round() { # script API
    # Usage: dra-local-round BYTES
    #
    # Print BYTES rounded up to whole memory blocks of DRA_LOCAL_BLOCK_SIZE
    # bytes (see dra-local-device): what a claim of BYTES consumes of a
    # local device, the step of its capacity.
    local bs="$DRA_LOCAL_BLOCK_SIZE"
    echo $(( ($1 + bs - 1) / bs * bs ))
}

dra-local-blocks-require() { # script API
    # Usage: dra-local-blocks-require VMDIR TOPOLOGY BLOCKS
    #
    # Fail the test unless the memory block size of the VM of VMDIR
    # (DRA_LOCAL_BLOCK_SIZE) is a multiple of 16 MiB and its local device
    # (see dra-local-device) is whole blocks, at least BLOCKS of them. The
    # VM was created from TOPOLOGY.
    local vmdir="$1" topology="$2" blocks="$3" bs="$DRA_LOCAL_BLOCK_SIZE" mib=$(( 1 << 20 ))
    if ! [[ "$bs" =~ ^[0-9]+$ ]] || (( bs < 16 * mib || bs % (16 * mib) != 0 )); then
        error "unexpected memory block size '$bs' bytes in $(dra-vm-label "$vmdir")"
    fi
    (( DRA_LOCAL_SIZE % bs == 0 && DRA_LOCAL_SIZE >= blocks * bs )) ||
        error "the local device $DRA_LOCAL_NAME has $DRA_LOCAL_SIZE bytes, the test needs $blocks memory blocks of $bs bytes. The VM was created from an older topology.var.json of $topology: recreate it: vagrant destroy in $vmdir, remove the directory, and run
  qemu_bin=\$HOME/github.com/qemu/qemu/build/qemu-system-x86_64 ./run_tests.sh memory.test-suite/dra-driver-cxl/$topology/test00-up"
    echo "memory block size $bs bytes ($(dra-mi "$bs")), the local device has $(( DRA_LOCAL_SIZE / bs )) blocks"
}

dra-local-slices-wait() { # script API
    # Usage: dra-local-slices-wait VMDIR LABEL NODE numa|dax:BYTES...
    #
    # Wait until the local device of the VM of VMDIR (see dra-local-device)
    # has one region with exactly these slices: numa slices bound to kmem,
    # dax slices bound to device_dax, all of them dax devices of NUMA node
    # NODE ("": any one node), and the rest of the region available.
    # DRA_MEMDEV is the sysfs view of the device.
    local vmdir="$1" label="$2" node="$3" want="" total=0 s kind size
    shift 3
    for s in "$@"; do
        kind=${s%%:*} size=${s#*:}
        case "$kind" in
            numa) want+="('kmem', $size), ";;
            dax) want+="('device_dax', $size), ";;
            *) error "dra-local-slices-wait: unknown slice $s";;
        esac
        total=$(( total + size ))
    done
    dra-memdev-wait "$vmdir" "$label" "$DRA_LOCAL_SERIAL" \
        "len(j['regions']) == 1 and sorted((d['driver'], d['size']) for d in dax_slices()) == sorted([$want]) and len(set(d['node'] for d in dax_slices())) == 1${node:+ and dax_slices()[0]['node'] == $node} and j['regions'][0]['available'] == $DRA_LOCAL_SIZE - $total"
}

dra-local-node-size() { # script API
    # Usage: dra-local-node-size VMDIR LABEL NODE BYTES [LOCAL]
    #
    # Wait until NUMA node NODE of the VM of VMDIR has BYTES of memory,
    # whole memory blocks (MemTotal; 0: no memory or no node), and until
    # the region of its local device (see dra-local-device), if there is
    # one, has LOCAL bytes online in cxl-dump (default BYTES).
    local vmdir="$1" label="$2" node="$3" bytes="$4" local_bytes="${5:-$4}" bs="$DRA_LOCAL_BLOCK_SIZE" blocks
    (( bytes % bs == 0 )) || error "dra-local-node-size $label: $bytes bytes are not whole memory blocks of $bs bytes"
    blocks=$(( bytes / bs ))
    dra-node-wait "$vmdir" "$node" "$(( blocks * (bs / 1024) ))" 30
    pool-cxl-wait "$vmdir" "node-$label" "len($DRA_LOCAL_REGIONS) <= 1 and all(r['OnlineSize'] == $local_bytes for r in $DRA_LOCAL_REGIONS)" 10
}

dra-local-slices-none() { # script API
    # Usage: dra-local-slices-none VMDIR LABEL
    #
    # Wait until the local device of the VM of VMDIR (see dra-local-device)
    # has no slice and no region: its memdev enabled and no region of it,
    # neither in pkg/cxl (cxl-dump) nor in sysfs. DRA_MEMDEV is the sysfs
    # view of the device.
    local vmdir="$1" label="$2"
    pool-cxl-wait "$vmdir" "$label" "by_serial($DRA_LOCAL_SERIAL) is not None and by_serial($DRA_LOCAL_SERIAL)['Enabled'] and $DRA_LOCAL_REGIONS == []" 60
    dra-memdev-wait "$vmdir" "$label" "$DRA_LOCAL_SERIAL" "j['memdev'] and j['enabled'] and j['regions'] == []" 10
}

dra-local-unchanged() { # script API
    # Usage: dra-local-unchanged VMDIR
    #
    # Fail the test unless the node's cxl.nri.io ResourceSlice publishes
    # the local device of the VM of VMDIR exactly as dra-local-device saw
    # it (DRA_LOCAL_PUBLISHED): the slices, regions and modes of its claims
    # and leases are not published. COMMAND_OUTPUT has the ResourceSlices.
    [ -n "$DRA_LOCAL_PUBLISHED" ] ||
        error "dra-local-unchanged: no published device, call dra-local-device after dra-install"
    dra-json "$1" resourceslices
    dra-assert "$COMMAND_OUTPUT" "json.dumps($DRA_LOCAL_LD, sort_keys=True) == $(python3 -c 'import sys; print(repr(sys.argv[1]))' "$DRA_LOCAL_PUBLISHED")"
}

dra-local-claim-check() { # script API
    # Usage: dra-local-claim-check VMDIR POD BYTES
    #
    # Check that the claim of pod POD in $DRA_NS is allocated to the local
    # device of the VM of VMDIR (see dra-local-device) on its node and
    # consumes BYTES of its memory. DRA_CLAIM_JSON and DRA_CLAIM_UID are
    # the claim.
    local vmdir="$1" pod="$2" bytes="$3" claim
    claim=$(dra-pod-claim "$vmdir" "$pod") || error "pod $pod has no ResourceClaim"
    dra-json "$vmdir" resourceclaim -n "$DRA_NS" "$claim"
    DRA_CLAIM_JSON="$COMMAND_OUTPUT"
    dra-assert "$DRA_CLAIM_JSON" "[(r['driver'], r['device']) for r in results()] == [('$DRA_LOCAL_DRIVER', '$DRA_LOCAL_DEVICE')] and allocated_node() == '$(dra-vm-name "$vmdir")'"
    dra-assert "$DRA_CLAIM_JSON" "consumed() == $bytes"
    DRA_CLAIM_UID=$(dra-value "$DRA_CLAIM_JSON" "j['metadata']['uid']")
}

dra-local-claim-slice() { # script API
    # Usage: dra-local-claim-slice VMDIR CLAIM-UID
    #
    # Print the dax device (daxX.Y) of the slice of the claim with
    # CLAIM-UID in the state of the node plugin in the VM of VMDIR
    # ($DRA_LOCAL_STATE: devices[].claims[CLAIM-UID][0].dax). Return 1 if
    # the claim has no slice there.
    local json
    json=$(dra-vm-command-q "$1" "cat $DRA_LOCAL_STATE") || return 1
    python3 -c '
import json, sys
uid = sys.argv[1]
for d in json.loads(sys.stdin.read()).get("devices") or []:
    slices = (d.get("claims") or {}).get(uid) or []
    if slices and slices[0].get("dax"):
        print(slices[0]["dax"])
        sys.exit(0)
sys.exit(1)' "$2" <<< "$json"
}

dra-delete-pod() { # script API
    # Usage: dra-delete-pod VMDIR POD
    #
    # Delete pod POD in $DRA_NS and wait until it is gone.
    dra-delete "$1" pod "$2" --grace-period=2 --wait=true --timeout=60s
}

dra-cdi-device() { # script API
    # Usage: dra-cdi-device VMDIR NAME
    #
    # Print CDI device NAME of the CDI spec files (YAML) of the VM of VMDIR,
    # in /etc/cdi and /var/run/cdi, quietly: a line "file: FILE" and a line
    # "kind: KIND" of its spec, then its own lines of the spec. Print
    # nothing if there is no such device.
    # Example: dra-cdi-device "$VM" "claim-$CLAIM_UID-0"
    local script
    script="want=$(printf %q "$2")
$(cat <<'EOF2'
for f in /etc/cdi/* /var/run/cdi/*; do
    [ -f "$f" ] || continue
    awk -v want="$want" '
        /^kind:/ { kind = $2 }
        /^[^ -]/ { p = 0 }
        /^ *- name: / { n = $NF; gsub(/"/, "", n); p = (n == want); if (p) { print "file: " FILENAME; print "kind: " kind } }
        p { print }' "$f"
done
EOF2
)"
    dra-vm-command-q "$1" "$script"
}

dra-cdi-devices-with() { # script API
    # Usage: dra-cdi-devices-with VMDIR TEXT
    #
    # Print the names of the CDI devices of the CDI spec files (YAML) of the
    # VM of VMDIR that have a line with TEXT (a fixed string, for instance
    # an environment variable name), one per line, quietly. Return
    # non-zero if neither CDI spec directory can be read.
    local script
    script="text=$(printf %q "$2")
$(cat <<'EOF2'
[ -r /etc/cdi ] || [ -r /var/run/cdi ] || exit 1
for f in /etc/cdi/* /var/run/cdi/*; do
    [ -f "$f" ] || continue
    awk -v t="$text" '
        /^[^ -]/ { n = "" }
        /^ *- name: / { n = $NF; gsub(/"/, "", n) }
        n != "" && index($0, t) { print n }' "$f"
done | sort -u
exit "${PIPESTATUS[0]}"
EOF2
)"
    dra-vm-command-q "$1" "$script"
}

dra-cdi-mounts() { # script API
    # Usage: dra-cdi-mounts CDI
    #
    # Print the mounts of the CDI device CDI (the lines that dra-cdi-device
    # printed) as a JSON list in the order of the spec, one object per
    # mount with its fields (hostPath, containerPath, type, options).
    # Return non-zero if CDI has a mount line that cannot be parsed.
    python3 -c '
import json, sys

def value(text):
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        return [value(t) for t in text[1:-1].split(",") if t.strip()]
    if text.startswith("\""):
        return json.loads(text)
    if text.startswith("\x27") and text.endswith("\x27"):
        return text[1:-1]
    return text

mounts, base, item, opts, cur = [], None, None, None, None
for line in sys.argv[1].splitlines():
    if not line.strip():
        continue
    indent = len(line) - len(line.lstrip())
    s = line.strip()
    if base is None:
        if s == "mounts:":
            base = indent
        continue
    if indent < base or (indent == base and not s.startswith("- ")):
        break
    if s.startswith("- ") and (item is None or indent == item):
        item, cur, opts = indent, {}, None
        mounts.append(cur)
        s = s[2:]
    elif s.startswith("- "):
        if opts is None:
            sys.exit("dra-cdi-mounts: an item outside options: %r" % line)
        opts.append(value(s[2:]))
        continue
    key, sep, rest = s.partition(":")
    if not sep or cur is None:
        sys.exit("dra-cdi-mounts: cannot parse: %r" % line)
    if rest.strip():
        cur[key] = value(rest)
        opts = None
    else:
        opts = cur[key] = []
print(json.dumps(mounts))' "$1"
}

dra-lease-cdi-assert() { # script API
    # Usage: dra-lease-cdi-assert VMDIR CLAIM-UID
    #
    # Fail the test unless the VM of VMDIR has the CDI device lease-CLAIM-UID
    # of kind nri.io/cxl, the device of a lease claim that may lease
    # filesystems: env CXL_LEASE_SOCKET=/run/cxl/cxl.sock and exactly three
    # bind mounts, $DRA_LEASE_DIR/CLAIM-UID at /run/cxl (rbind, rw), then
    # $DRA_LEASE_FS_DIR/CLAIM-UID at $DRA_LEASE_FS_CTR_DIR (rbind, ro,
    # rslave), and $DRA_REQUEST_NODE_BIN at $DRA_REQUEST_CTR_BIN (bind, ro).
    local vmdir="$1" uid="$2" cdi mounts
    cdi=$(dra-cdi-device "$vmdir" "lease-$uid")
    echo "CDI device lease-$uid: $cdi"
    grep -qx "kind: nri.io/cxl" <<< "$cdi" || error "no CDI device lease-$uid of kind nri.io/cxl in $(dra-vm-label "$vmdir")"
    grep -qxE ' *- "?CXL_LEASE_SOCKET=/run/cxl/cxl\.sock"?' <<< "$cdi" ||
        error "the CDI device lease-$uid has no env CXL_LEASE_SOCKET=/run/cxl/cxl.sock"
    mounts=$(dra-cdi-mounts "$cdi") || error "cannot parse the mounts of the CDI device lease-$uid"
    echo "mounts of lease-$uid: $mounts"
    dra-assert "$mounts" "sorted((m.get('hostPath'), m.get('containerPath'), m.get('type'), m.get('options')) for m in j) == sorted([('$DRA_LEASE_DIR/$uid', '/run/cxl', 'bind', ['rbind', 'rw']), ('$DRA_LEASE_FS_DIR/$uid', '$DRA_LEASE_FS_CTR_DIR', 'bind', ['rbind', 'ro', 'rslave']), ('$DRA_REQUEST_NODE_BIN', '$DRA_REQUEST_CTR_BIN', 'bind', ['bind', 'ro'])])"
    # The socket directory first: the filesystem directory is mounted inside it.
    dra-assert "$mounts" "[m['containerPath'] for m in j].index('/run/cxl') < [m['containerPath'] for m in j].index('$DRA_LEASE_FS_CTR_DIR')"
}

dra-fs-mounts() { # script API
    # Usage: dra-fs-mounts VMDIR
    #
    # Print the mounts under $DRA_POOL_MOUNT_DIR in the mount namespace of
    # the VM of VMDIR as a JSON list, quietly, one object per mount:
    # target, source, fstype, options (the superblock options), and for a
    # loop device source its backing file (backing), direct I/O (dio) and
    # read-only (ro) flags ("" for other sources). COMMAND_OUTPUT has the
    # list. Return non-zero if the mounts cannot be read or a line of
    # findmnt cannot be parsed.
    local lines
    lines=$(dra-vm-command-q "$1" "findmnt -rn -o TARGET,SOURCE,FSTYPE,FS-OPTIONS | while read -r t s f o; do
    case \"\$t\" in $DRA_POOL_MOUNT_DIR/*) ;; *) continue;; esac
    o=\${o:--} b=- d=- r=-
    case \"\$s\" in /dev/loop[0-9]*) l=/sys/block/\${s#/dev/}; b=\$(cat \$l/loop/backing_file); d=\$(cat \$l/loop/dio); r=\$(cat \$l/ro);; esac
    echo \"\$t \$s \$f \$o \$b \$d \$r\"
done") || return 1
    COMMAND_OUTPUT=$(python3 -c '
import json, sys
keys = ["target", "source", "fstype", "options", "backing", "dio", "ro"]
out = []
for line in sys.stdin.read().splitlines():
    fields = line.split()
    if not fields:
        continue
    if len(fields) != len(keys):
        sys.exit("dra-fs-mounts: cannot parse: %r" % line)
    out.append({k: ("" if v == "-" else v) for k, v in zip(keys, fields)})
print(json.dumps(out, sort_keys=True))' <<< "$lines") || return 1
    echo "$COMMAND_OUTPUT"
}

dra-pmem-loops() { # script API
    # Usage: dra-pmem-loops VMDIR
    #
    # Print the loop devices of the VM of VMDIR whose backing file is a
    # pmem block device, one "loopN /dev/pmemK" per line, quietly. Return
    # non-zero if the loop devices cannot be listed.
    dra-vm-command-q "$1" "test -d /sys/block || exit 1; for f in /sys/block/loop*/loop/backing_file; do [ -f \"\$f\" ] || continue; b=\$(cat \"\$f\") || exit 1; case \"\$b\" in /dev/pmem*) n=\${f#/sys/block/}; echo \"\${n%%/*} \$b\";; esac; done; exit 0"
}

dra-lease-fs-mounts() { # script API
    # Usage: dra-lease-fs-mounts VMDIR
    #
    # Print the mounts under $DRA_LEASE_FS_DIR in the mount namespace of the
    # VM of VMDIR as a JSON list sorted by target, quietly, one object per
    # mount: target, source, fstype, options (the superblock options) and
    # vfs (the options of the mount itself, for instance
    # ro,nosuid,nodev,relatime). COMMAND_OUTPUT has the list. Return
    # non-zero if the mounts cannot be read.
    local json
    json=$(dra-vm-command-q "$1" "findmnt -J -l -o TARGET,SOURCE,FSTYPE,FS-OPTIONS,VFS-OPTIONS") || return 1
    COMMAND_OUTPUT=$(python3 -c '
import json, sys
base = sys.argv[1].rstrip("/") + "/"
out = [{"target": m["target"], "source": m.get("source") or "", "fstype": m.get("fstype") or "",
        "options": m.get("fs-options") or "", "vfs": m.get("vfs-options") or ""}
       for m in json.loads(sys.stdin.read())["filesystems"] if m["target"].startswith(base)]
print(json.dumps(sorted(out, key=lambda m: m["target"]), sort_keys=True))' "$DRA_LEASE_FS_DIR" <<< "$json") || return 1
    echo "$COMMAND_OUTPUT"
}

dra-local-state-claims() {
    # Usage: dra-local-state-claims VMDIR
    #
    # Print how many claims the node plugin in the VM of VMDIR has in its
    # state file of local devices (0 without a file): the entries of every
    # "claims" object or list in it, whatever the case of the key.
    local json
    json=$(dra-vm-command-q "$1" "cat $DRA_LOCAL_STATE 2>/dev/null || echo '{}'")
    echo "$DRA_LOCAL_STATE: $json" >&2
    python3 -c '
import json, sys
def count(o):
    if isinstance(o, dict):
        return sum(len(v) if k.lower() == "claims" and isinstance(v, (dict, list)) else count(v) for k, v in o.items())
    if isinstance(o, list):
        return sum(count(v) for v in o)
    return 0
print(count(json.loads(sys.stdin.read().strip() or "{}")))' <<< "$json"
}

dra-local-initial-state() { # script API
    # Usage: dra-local-initial-state VMDIR LABEL [NODE]
    #
    # Wait until the local device of the VM of VMDIR (see dra-local-device)
    # is in its initial state again: the memdev enabled, no region (see
    # dra-local-slices-none), the device published as it was
    # (dra-local-unchanged), and no memory on its NUMA node NODE (if
    # given). Check that nothing of its claims is left: no CDI device with
    # an environment variable of the device (CXL_<KEY>_), no claims in the
    # state of the node plugin, which must have its state file.
    local vmdir="$1" label="$2" node="$3"
    dra-local-slices-none "$vmdir" "$label"
    dra-local-unchanged "$vmdir"
    [ -z "$(dra-cdi-devices-with "$vmdir" "CXL_${DRA_LOCAL_HEX}_")" ] ||
        error "$label: CDI devices of claims of the local device are left: $(dra-cdi-devices-with "$vmdir" "CXL_${DRA_LOCAL_HEX}_")"
    dra-vm-command-q "$vmdir" "test -s $DRA_LOCAL_STATE" ||
        error "$label: the node plugin has no $DRA_LOCAL_STATE"
    [ "$(dra-local-state-claims "$vmdir")" == 0 ] ||
        error "$label: the node plugin still has claims in $DRA_LOCAL_STATE"
    [ -z "$node" ] || dra-node-wait "$vmdir" "$node" 0 10
    echo "$label: the local device is in its initial state"
}

dra-local-state-shared() {
    # Usage: dra-local-state-shared VMDIR CLAIM-UID...
    #
    # Return 0 if the state file of the node plugin in the VM of VMDIR
    # ($DRA_LOCAL_STATE) has the local device (DRA_LOCAL_SERIAL) with
    # "shared": true and exactly the claims CLAIM-UID (none: no claims).
    # DRA_LOCAL_STATE_JSON is the state file as it was read.
    local vmdir="$1"
    shift
    DRA_LOCAL_STATE_JSON=$(dra-vm-command-q "$vmdir" "cat $DRA_LOCAL_STATE 2>/dev/null || echo '{}'") || return 1
    python3 -c '
import json, sys
serial, want = int(sys.argv[1], 16), sorted(sys.argv[2:])
for d in json.loads(sys.stdin.read().strip() or "{}").get("devices") or []:
    hexs = str(d.get("serialHex") or "").lower()
    if d.get("serial") == serial or (hexs and int(hexs, 16) == serial):
        sys.exit(0 if d.get("shared") is True and sorted((d.get("claims") or {}).keys()) == want else 1)
sys.exit(1)' "$DRA_LOCAL_SERIAL" "$@" <<< "$DRA_LOCAL_STATE_JSON"
}

dra-local-shared-wait() { # script API
    # Usage: dra-local-shared-wait VMDIR LABEL [CLAIM-UID...]
    #
    # Wait until the local device of the VM of VMDIR (see dra-local-device)
    # is a shared device that exactly the claims CLAIM-UID use (none: an
    # idle shared device, which keeps its region): the state file of the
    # node plugin has the device with "shared": true and these claims;
    # pkg/cxl (cxl-dump) sees one region of the device, enabled, nothing of
    # it online; in sysfs the memdev is enabled and its one region is the
    # whole device, with one dax device of that size bound to device_dax.
    # DRA_LOCAL_SHARED_REGION and DRA_LOCAL_SHARED_DAX are the region
    # (regionN) and its dax device (daxX.Y), DRA_MEMDEV the sysfs view.
    local vmdir="$1" label="$2" vmlabel claims
    shift 2
    claims=("$@")
    vmlabel=$(dra-vm-label "$vmdir")
    retry-until --timeout 60 --interval 1 --message "$vmlabel: $DRA_LOCAL_STATE has $DRA_LOCAL_SERIAL shared, with claims [$*]" \
        'dra-local-state-shared "$vmdir" "${claims[@]}"' ||
        error "$vmlabel: $DRA_LOCAL_STATE does not have $DRA_LOCAL_SERIAL shared with claims [$*]: $DRA_LOCAL_STATE_JSON"
    echo "$vmlabel: $DRA_LOCAL_STATE: $DRA_LOCAL_SERIAL shared, claims [$*]"
    pool-cxl-wait "$vmdir" "$label" "len($DRA_LOCAL_REGIONS) == 1 and ${DRA_LOCAL_REGIONS}[0]['Enabled'] and ${DRA_LOCAL_REGIONS}[0]['OnlineSize'] == 0" 30
    dra-memdev-wait "$vmdir" "$label" "$DRA_LOCAL_SERIAL" \
        "j['enabled'] and len(j['regions']) == 1 and j['regions'][0]['size'] == $DRA_LOCAL_SIZE and [(d['size'], d['driver']) for d in dax_slices()] == [($DRA_LOCAL_SIZE, 'device_dax')]" 30
    DRA_LOCAL_SHARED_REGION=$(dra-value "$DRA_MEMDEV" "j['regions'][0]['name']")
    DRA_LOCAL_SHARED_DAX=$(dra-value "$DRA_MEMDEV" "dax_slices()[0]['name']")
    echo "$vmlabel: the shared local device is $DRA_LOCAL_SHARED_REGION, /dev/$DRA_LOCAL_SHARED_DAX"
}

dra-local-seed() { # script API
    # Usage: dra-local-seed VMDIR TEXT OFFSET...
    #
    # Write TEXT at every OFFSET of the local CXL memory device of the VM
    # of VMDIR (see dra-local-device) and read it back, through a devdax
    # region that fake-cxl-pool-client creates in the VM, then destroy the
    # region, leaving the memdev enabled and without regions. Fail the
    # test if any step fails.
    local vmdir="$1" text="$2" label region dax off
    shift 2
    label=$(dra-vm-label "$vmdir")
    pool-client "$vmdir" guest region create "$DRA_LOCAL_SERIAL" --mode dax ||
        command-error "cannot create a devdax region of the local device in $label"
    dra-memdev-wait "$vmdir" seed-region "$DRA_LOCAL_SERIAL" "len(j['regions']) == 1 and len(dax_slices()) == 1" 30
    region=$(dra-value "$DRA_MEMDEV" "j['regions'][0]['name']")
    dax=/dev/$(dra-value "$DRA_MEMDEV" "dax_slices()[0]['name']")
    for off in "$@"; do
        dra-vm-command "$vmdir" "pool-dax-rw.py write $dax $off $(printf %q "$text") && pool-dax-rw.py read $dax $off" ||
            command-error "cannot write to $dax at $off in $label"
        [ "$(tail -n 1 <<< "$COMMAND_OUTPUT")" == "$text" ] ||
            error "read '$(tail -n 1 <<< "$COMMAND_OUTPUT")' at $off of $dax in $label, expected '$text'"
    done
    dra-vm-command "$vmdir" "cxl destroy-region -f $region" ||
        command-error "cannot destroy $region in $label"
    dra-memdev-wait "$vmdir" seed-gone "$DRA_LOCAL_SERIAL" "j['memdev'] and j['enabled'] and j['regions'] == []" 30
    echo "dra-local-seed $label: '$text' at $* of the local device, $region destroyed"
}

dra-plugin-log-wait() { # script API
    # Usage: dra-plugin-log-wait VMDIR TEXT [TIMEOUT]
    #
    # Wait until the log of the driver on the node of the VM of VMDIR (see
    # dra-plugin-log) has a line with the fixed string TEXT, TIMEOUT
    # seconds at most (default 30), and print the line. Fail the test on
    # timeout.
    local vmdir="$1" text="$2" tmo="${3:-30}"
    retry-until --timeout "$tmo" --interval 1 --message "$(dra-vm-label "$vmdir"): the log of $DRA_CONTAINER has '$text'" \
        'dra-plugin-log "$vmdir" | grep -qF -- "$text"' ||
        error "the log of $DRA_CONTAINER in $(dra-vm-label "$vmdir") has no line with '$text'"
    dra-plugin-log "$vmdir" | grep -F -- "$text"
}

dra-local-shared-cleanup() { # script API
    # Usage: dra-local-shared-cleanup VMDIR
    #
    # The EXIT trap of a test that configures the local device of the VM of
    # VMDIR shared (DRA_DRIVER_CONFIG sharedDevices): such a device keeps
    # its region while the driver runs. dra-cleanup, then, with the driver
    # gone, release the regions of the device in the VM (fake-cxl-pool-client
    # guest release) and wait until none is left, then pool-cleanup, which
    # detaches the device. If a region is left, or the device cannot be
    # read, stop the server only and leave the device attached: a detach
    # cannot hot-remove it, and pool-vm-reset of the next test restarts the
    # VM. Never fails the test.
    local vmdir="$1" label
    label=$(dra-vm-label "$vmdir")
    dra-cleanup
    if [ -n "$DRA_LOCAL_SERIAL" ] && dra-memdev-sysfs "$vmdir" "$DRA_LOCAL_SERIAL" &&
           dra-py assert "$DRA_MEMDEV" "j['memdev'] and j['regions']"; then
        echo "dra-local-shared-cleanup: $label: the local device $DRA_LOCAL_SERIAL has regions, releasing them"
        pool-client "$vmdir" guest release "$DRA_LOCAL_SERIAL"
    fi
    if [ -n "$DRA_LOCAL_SERIAL" ] && ! retry-until --timeout 60 --interval 1 --message "$label: no region of the local device $DRA_LOCAL_SERIAL" \
           'dra-memdev-sysfs "$vmdir" "$DRA_LOCAL_SERIAL" && dra-py assert "$DRA_MEMDEV" "j[\"regions\"] == []"'; then
        echo "dra-local-shared-cleanup: $label: the local device $DRA_LOCAL_SERIAL still has regions or cannot be read, not detaching it: $DRA_MEMDEV
  The next test restarts the VM (pool-vm-reset), or by hand in the VM: fake-cxl-pool-client guest release $DRA_LOCAL_SERIAL"
        pool-server-stop
        return 0
    fi
    pool-cleanup
    return 0
}

dra-driver-restart() { # script API
    # Usage: dra-driver-restart VMDIR
    #
    # Restart the driver on the node of the VM of VMDIR: store the log of
    # its pod as $TEST_OUTPUT_DIR/nri-dra-driver-cxl.<vm>.<pod>.log, delete
    # the pod, and wait until the DaemonSet runs a new pod there that is
    # Ready, and the node has what dra-wait-node waits for. A running trace
    # follows the log of the new pod (dra-trace-driver-follow).
    # DRA_DRIVER_POD is the new pod.
    local vmdir="$1" label old
    label=$(dra-vm-label "$vmdir")
    old=$(dra-driver-pod "$vmdir") ||
        error "dra-driver-restart: $DRA_DAEMONSET does not run on $(dra-vm-name "$vmdir")"
    dra-vm-command-q "$vmdir" "kubectl logs -n kube-system $old -c $DRA_CONTAINER" > "$TEST_OUTPUT_DIR/$DRA_CONTAINER.$label.$old.log" 2>&1
    echo "dra-driver-restart $label: log of $old in $TEST_OUTPUT_DIR/$DRA_CONTAINER.$label.$old.log"
    dra-vm-command "$vmdir" "kubectl delete pod -n kube-system $old --wait=true --timeout=60s" ||
        command-error "cannot delete the pod $old of $DRA_DAEMONSET in $label"
    DRA_DRIVER_POD=""
    retry-until --timeout 120 --interval 1 --message "$label: a new Ready pod of $DRA_DAEMONSET" \
        'DRA_DRIVER_POD=$(dra-driver-pod "$vmdir") && [ "$DRA_DRIVER_POD" != "$old" ] && dra-vm-command-q "$vmdir" "kubectl wait -n kube-system --for=condition=Ready pod/$DRA_DRIVER_POD --timeout=1s" >/dev/null 2>&1' || {
        dra-vm-command "$vmdir" "kubectl get pods -n kube-system -l $DRA_POD_LABEL -o wide"
        error "dra-driver-restart: no new Ready pod of $DRA_DAEMONSET in $label"
    }
    echo "dra-driver-restart $label: $old replaced by $DRA_DRIVER_POD"
    dra-wait-node "$vmdir"
    dra-trace-driver-follow "$vmdir"
}

dra-driver-kill() { # script API
    # Usage: dra-driver-kill VMDIR
    #
    # Kill the driver on the node of the VM of VMDIR in place: SIGKILL to
    # the process of its container (found with crictl in the VM), so that
    # kubelet starts the container again in the same pod (restartPolicy
    # Always of the DaemonSet, with the back-off of a crashing container),
    # unlike dra-driver-restart, which replaces the pod. Do not wait for the
    # restart. COMMAND_OUTPUT has "killed POD CONTAINER-ID pid PID". Return
    # non-zero if no container of the driver runs there or the kill fails.
    dra-vm-command "$1" "id=\$(crictl ps -q --state running --namespace '^kube-system\$' --name '^$DRA_CONTAINER\$' 2>/dev/null | head -n 1)
[ -n \"\$id\" ] || { echo 'no running container $DRA_CONTAINER'; exit 1; }
set -- \$(crictl inspect -o go-template --template '{{index .status.labels \"io.kubernetes.pod.name\"}} {{.info.pid}}' \$id 2>/dev/null)
[ -n \"\$2\" ] && [ \"\$2\" != 0 ] || { echo \"no pid of container \$id\"; exit 1; }
kill -KILL \"\$2\" && echo \"killed \$1 \$id pid \$2\""
}

dra-node-service-restart() { # script API
    # Usage: dra-node-service-restart VMDIR kubelet|containerd [TIMEOUT]
    #
    # Restart kubelet or containerd in the VM of VMDIR (systemctl restart;
    # the containers keep running) and wait until the service is active
    # and answers again (kubelet: its healthz endpoint, containerd: crictl
    # info) and its node is Ready in the cluster of the VM of the test,
    # TIMEOUT seconds at most (default 120). Return non-zero on failure or
    # timeout.
    local vmdir="$1" service="$2" tmo="${3:-120}" name check
    name=$(dra-vm-name "$vmdir")
    # shellcheck disable=SC2034 # check is used in the snippet of retry-until
    case "$service" in
        kubelet) check="curl -sf --max-time 2 http://127.0.0.1:10248/healthz >/dev/null";;
        containerd) check="crictl info >/dev/null 2>&1";;
        *) echo "dra-node-service-restart: unknown service '$service' (kubelet or containerd)" >&2; return 2;;
    esac
    dra-vm-command "$vmdir" "systemctl restart $service" || return 1
    retry-until --timeout "$tmo" --interval 1 --message "$(dra-vm-label "$vmdir"): $service active and answering, node $name Ready" \
        'dra-vm-command-q "$vmdir" "systemctl -q is-active $service && $check" && dra-node-ready "$vmdir"'
}

dra-node-ready() {
    # Usage: dra-node-ready VMDIR
    #
    # Return 0 if the node of the VM of VMDIR is Ready in the cluster of the
    # VM of the test.
    local status
    status=$(dra-vm-command-q "$OUTPUT_DIR" "kubectl get node $(dra-vm-name "$1") -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}'") || return 1
    [ "$status" == True ]
}

dra-plugin-log() { # script API
    # Usage: dra-plugin-log VMDIR
    #
    # Print the log of the driver on the node of the VM of VMDIR since its
    # container started (kubectl logs of its pod), quietly. Fail the test if
    # the driver does not run there.
    local pod
    pod=$(dra-driver-pod "$1") ||
        error "dra-plugin-log: $DRA_DAEMONSET does not run on $(dra-vm-name "$1")"
    dra-vm-command-q "$1" "kubectl logs -n kube-system $pod -c $DRA_CONTAINER"
}

dra-local-slices-aligned() { # script API
    # Usage: dra-local-slices-aligned VMDIR
    #
    # Fail the test if the node plugin in the VM of VMDIR, since it started,
    # created a region of a local device that does not start at a memory
    # block boundary, placed a slice explicitly (the range that the kernel
    # chose was not whole memory blocks) or rounded a slice up (a claim
    # consumed less than whole memory blocks).
    local log
    log=$(dra-plugin-log "$1")
    if grep -E 'local: .*(does not start at a memory block boundary|placing it explicitly|rounded up to)' <<< "$log"; then
        error "the node plugin aligned, placed or rounded regions or slices of local devices itself, see above"
    fi
    echo "the node plugin's regions and slices were block-aligned: no slice placed explicitly or rounded up"
}

dra-local-slice-times() { # script API
    # Usage: dra-local-slice-times VMDIR
    #
    # Print how long the node plugin in the VM of VMDIR took, by its log
    # since it started, for the regions and slices of local devices:
    # region created and released, slice created, onlined, offlined,
    # zeroed and deleted, per mode of the slice (count, min, median, max).
    echo "### regions and slices of local devices, times from the log of $DRA_CONTAINER"
    dra-plugin-log "$1" | python3 -c '
import re, statistics, sys
units = {"s": 1000.0, "ms": 1.0, "us": 0.001, "ns": 0.000001}
times = {}
for line in sys.stdin:
    m = re.search(r"local: .*: (?:claim \S+: )?(created|onlined|offlined|zeroed|deleted) slice \S+ mode (\S+) .* in ([0-9.]+)(ms|us|ns|s)$", line) or \
        re.search(r"local: .*: (created|released) region\S*() .*?in ([0-9.]+)(ms|us|ns|s)$", line)
    if not m:
        continue
    what, mode, value, unit = m.groups()
    key = "%s %s" % (what, "slice (%s)" % mode if mode else "region")
    times.setdefault(key, []).append(float(value) * units[unit])
if not times:
    print("no region or slice times in the log")
for key in sorted(times):
    t = sorted(times[key])
    print("%-24s n=%-3d min %8.3f ms  median %8.3f ms  max %8.3f ms" % (key, len(t), t[0], statistics.median(t), t[-1]))
'
}

dra-memory-config() { # script API
    # Usage: dra-memory-config SECTIONS
    #
    # Print the parameters of an opaque config entry of a claim or a
    # DeviceClass, either driver, as a YAML flow mapping: apiVersion
    # $DRA_CONFIG_API, kind $DRA_CONFIG_KIND and SECTIONS, the sections of
    # the configuration as flow YAML ("": none).
    # Example: dra-memory-config "device: {mode: dax}, container: {steering: {policy: auto}}"
    echo "{apiVersion: $DRA_CONFIG_API, kind: $DRA_CONFIG_KIND${1:+, $1}}"
}

dra-config-sections() {
    # Usage: dra-config-sections DEVICE CONTAINER POOL
    #
    # Print the sections device, container and pool of a configuration as
    # flow YAML, each with its fields (flow YAML, "": no such section).
    local out="" name fields
    for name in device container pool; do
        fields="$1"
        shift
        [ -n "$fields" ] || continue
        out+="${out:+, }$name: {$fields}"
    done
    echo "$out"
}

dra-claim-yaml() { # script API
    # Usage: dra-claim-yaml claim|template NAME CLASS SIZE [MODE [read-only]] [SECTION=FIELDS...]
    #
    # Print a ResourceClaim (claim) or a ResourceClaimTemplate (template)
    # NAME with one request "mem" of DeviceClass CLASS for SIZE of memory
    # ("": no amount). The claim has an opaque config of kind
    # $DRA_CONFIG_KIND for the driver of CLASS ($DRA_POOL_DRIVER for
    # cxl-pool*, else $DRA_LOCAL_DRIVER) if any of these is given:
    #   MODE            device.mode (numa, dax, ...; "": none)
    #   read-only       device.readOnly: true
    #   device=FIELDS   more fields of the device section (flow YAML)
    #   container=FIELDS  the container section, for instance
    #                   "steering: {policy: auto}"
    #   pool=FIELDS     the pool section, for instance
    #                   "opaque: {fake-cxl-pool: {numaNode: 1}}"
    # Examples:
    #   dra-claim-yaml template dax-ro cxl-local 64Mi dax read-only
    #   dra-claim-yaml claim steered cxl-local 128Mi "container=steering: {policy: auto}"
    local kind="$1" name="$2" class="$3" size="$4" driver="$DRA_LOCAL_DRIVER" mode="" ro="" device="" container="" pool="" a n=0 sections devices
    shift 4
    for a in "$@"; do
        case "$a" in
            device=*) device="${a#device=}";;
            container=*) container="${a#container=}";;
            pool=*) pool="${a#pool=}";;
            *)
                case "$n" in
                    0) mode="$a";;
                    1) ro="$a";;
                    *) error "dra-claim-yaml: unexpected argument '$a'";;
                esac
                n=$(( n + 1 ));;
        esac
    done
    [ -z "$ro" ] || [ "$ro" == read-only ] || error "dra-claim-yaml: '$ro' is not read-only"
    [[ "$class" != cxl-pool* ]] || driver="$DRA_POOL_DRIVER"
    [ -z "$ro" ] || device="readOnly: true${device:+, $device}"
    [ -z "$mode" ] || device="mode: $mode${device:+, $device}"
    sections=$(dra-config-sections "$device" "$container" "$pool")
    devices="devices:
  requests:
  - name: mem
    exactly:
      deviceClassName: $class"
    if [ -n "$size" ]; then
        devices+="
      capacity:
        requests:
          memory: $size"
    fi
    if [ -n "$sections" ]; then
        devices+="
  config:
  - opaque:
      driver: $driver
      parameters: $(dra-memory-config "$sections")"
    fi
    # shellcheck disable=SC2001 # sed indents every line
    if [ "$kind" == claim ]; then
        cat <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: $name
spec:
$(sed 's/^/  /' <<< "$devices")
EOF
    else
        cat <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: $name
spec:
  spec:
$(sed 's/^/    /' <<< "$devices")
EOF
    fi
}

dra-pod-yaml() { # script API
    # Usage: dra-pod-yaml NAME NODE [CLAIM...] [-- CONTAINER...]
    #
    # Print pod NAME on Kubernetes node NODE (nodeSelector
    # kubernetes.io/hostname), restartPolicy Never, no memory limits, with
    # containers of $DRA_TOOLS_IMAGE that have the tools of
    # dra-dax-tool-install in /tools and run $DRA_RUNNER as their main
    # process (see dra-run). Every CLAIM is a claim of the pod:
    #   CNAME=claim:CLAIM        the ResourceClaim CLAIM
    #   CNAME=template:TEMPLATE  a claim made from the ResourceClaimTemplate
    # Every CONTAINER is a container of the pod and the claims it uses:
    #   CTR=REF[,REF...]         REF: a claim CNAME (every result of it) or
    #                            CNAME/REQUEST (only the result of REQUEST)
    #   CTR                      no claims
    # Without CONTAINERs the pod has one container "main" with every claim.
    # Example: dra-pod-yaml split "$VM2_NAME" mem=claim:split -- c-numa=mem/numa c-dax=mem/dax
    local name="$1" node="$2" claims=() ctrs=() a cname src ctr refs ref yaml
    shift 2
    [ -n "$node" ] || error "dra-pod-yaml: no node for pod $name"
    while [ $# -gt 0 ] && [ "$1" != -- ]; do
        claims+=("$1")
        shift
    done
    [ "$1" != -- ] || shift
    ctrs=("$@")
    if [ "${#ctrs[@]}" == 0 ]; then
        refs=""
        for a in "${claims[@]}"; do
            refs+="${refs:+,}${a%%=*}"
        done
        ctrs=("main${refs:+=$refs}")
    fi
    yaml="apiVersion: v1
kind: Pod
metadata:
  name: $name
spec:
  nodeSelector:
    kubernetes.io/hostname: $node
  terminationGracePeriodSeconds: 2
  restartPolicy: Never"
    if [ "${#claims[@]}" -gt 0 ]; then
        yaml+="
  resourceClaims:"
        for a in "${claims[@]}"; do
            cname=${a%%=*} src=${a#*=}
            case "$src" in
                claim:*) yaml+="
  - name: $cname
    resourceClaimName: ${src#claim:}";;
                template:*) yaml+="
  - name: $cname
    resourceClaimTemplateName: ${src#template:}";;
                *) error "dra-pod-yaml: claim '$a' is not CNAME=claim:CLAIM or CNAME=template:TEMPLATE";;
            esac
        done
    fi
    yaml+="
  volumes:
  - name: tools
    configMap:
      name: dax-rw
  containers:"
    for a in "${ctrs[@]}"; do
        ctr=${a%%=*} refs=""
        [[ "$a" != *=* ]] || refs=${a#*=}
        # shellcheck disable=SC2001 # sed indents every line of the runner
        yaml+="
  - name: $ctr
    image: $DRA_TOOLS_IMAGE
    imagePullPolicy: IfNotPresent
    command:
    - sh
    - -c
    - |
$(sed 's/^/      /' <<< "$DRA_RUNNER")
    volumeMounts:
    - name: tools
      mountPath: /tools"
        [ -n "$refs" ] || continue
        yaml+="
    resources:
      claims:"
        for ref in ${refs//,/ }; do
            yaml+="
      - name: ${ref%%/*}"
            [[ "$ref" != */* ]] || yaml+="
        request: ${ref#*/}"
        done
    done
    echo "$yaml"
}

dra-claim-pod-yaml() { # script API
    # Usage: dra-claim-pod-yaml NAME claim|template SOURCE NODE
    #
    # Print pod NAME on Kubernetes node NODE (see dra-pod-yaml) whose claim
    # "mem" is the ResourceClaim SOURCE (claim) or is made from the
    # ResourceClaimTemplate SOURCE (template): one container "main" that
    # uses the claim, the tools of dra-dax-tool-install in /tools, its main
    # process $DRA_RUNNER (see dra-run), no memory limit.
    [ -n "$4" ] || error "dra-claim-pod-yaml: no node for pod $1"
    dra-pod-yaml "$1" "$4" "mem=$2:$3"
}

dra-claim-pod() { # script API
    # Usage: dra-claim-pod VMDIR NAME CLASS SIZE [MODE [read-only]] [SECTION=FIELDS...]
    #
    # Create pod NAME on the node of the VM of VMDIR with a claim of
    # DeviceClass CLASS for SIZE, with the configuration of MODE, read-only
    # and SECTION=FIELDS (see dra-claim-yaml), made from a
    # ResourceClaimTemplate NAME of its own: the claim lives and dies with
    # the pod.
    # Example: dra-claim-pod "$VM" steered cxl-local 128Mi "container=steering: {policy: auto}"
    local vmdir="$1" name="$2"
    shift 2
    dra-apply "$vmdir" <<< "$(dra-claim-yaml template "$name" "$@")
---
$(dra-claim-pod-yaml "$name" template "$name" "$(dra-vm-name "$vmdir")")"
}

dra-run() { # script API
    # Usage: dra-run VMDIR POD[/CONTAINER] SCRIPT [TIMEOUT]
    #
    # Run the shell SCRIPT as a child of the main process of a container of
    # dra-pod-yaml (the default container of POD when CONTAINER is not
    # given), so that it inherits the memory policy of that process, and
    # wait until it exits, TIMEOUT seconds at most (default 120). One
    # kubectl exec writes the script for $DRA_RUNNER and waits in the
    # container. COMMAND_OUTPUT has what SCRIPT printed (stdout and
    # stderr), COMMAND_STATUS its exit status (124 on timeout), which is
    # also returned.
    # Example: dra-run "$VM" steered "python3 /tools/numa-touch.py 64 -"
    local vmdir="$1" target="$2" script="$3" tmo="${4:-120}"
    # shellcheck disable=SC2016 # expanded by sh in the container
    dra-exec "$vmdir" "$target" sh -c '
rm -f /tmp/run.rc /tmp/run.out
printf "%s\n" "$1" > /tmp/run.new && mv /tmp/run.new /tmp/run || exit 125
i=0
while [ ! -f /tmp/run.rc ]; do
    if [ "$i" -ge "$2" ]; then
        echo "dra-run: the script did not finish in $(( $2 / 10 )) s" >&2
        exit 124
    fi
    sleep 0.1
    i=$(( i + 1 ))
done
cat /tmp/run.out
exit "$(cat /tmp/run.rc)"' sh "$script" "$(( tmo * 10 ))"
}

dra-shared-claim-yaml() { # script API
    # Usage: dra-shared-claim-yaml NAME SERIAL [SHARES [PARAMETERS [CLASS]]]
    #
    # Print ResourceClaim NAME with one request "mem" of DeviceClass CLASS
    # (default cxl-pool-shared) for the shared device SERIAL. SHARES is the
    # "shares" capacity to request: "1" for one share of the device, ""
    # for none, which is the device exclusively (the request consumes all
    # of its shares). PARAMETERS are the fields of the device section of
    # its configuration, for instance "mode: dax, readOnly: true" ("": no
    # configuration), or, when they start with "device:", "container:" or
    # "pool:", its sections (see dra-memory-config). The selector and the
    # configuration are of the driver of CLASS: $DRA_LOCAL_DRIVER for
    # cxl-local*, else $DRA_POOL_DRIVER.
    # Examples:
    #   dra-shared-claim-yaml writer 0xc1ae0001 "" "mode: block" cxl-pool-persistent
    #   dra-shared-claim-yaml placed 0xc1ee0002 "" "pool: {opaque: {fake-cxl-pool: {numaNode: 1}}}" cxl-pool
    local name="$1" serial="$2" shares="$3" params="$4" class="${5:-cxl-pool-shared}" driver="$DRA_POOL_DRIVER"
    [[ "$class" != cxl-local* ]] || driver="$DRA_LOCAL_DRIVER"
    [[ -z "$params" || "$params" =~ ^(device|container|pool): ]] || params="device: {$params}"
    cat <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: $name
spec:
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: $class
        selectors:
        - cel:
            expression: 'device.attributes["$driver"].serial == "$serial"'
EOF
    if [ -n "$shares" ]; then
        cat <<EOF
        capacity:
          requests:
            shares: "$shares"
EOF
    fi
    if [ -n "$params" ]; then
        cat <<EOF
    config:
    - opaque:
        driver: $driver
        parameters: $(dra-memory-config "$params")
EOF
    fi
}

# shellcheck disable=SC2001 # sed indents every line of SCRIPT
dra-script-pod-yaml() { # script API
    # Usage: dra-script-pod-yaml NAME VMDIR CLAIM SCRIPT [TYPE:PATH...]
    #
    # Print pod NAME on the node of VMDIR, restartPolicy Never, with
    # ResourceClaim CLAIM as its claim "mem" and the tools of
    # dra-dax-tool-install in /tools, running the shell SCRIPT in its
    # container "main" (image $DRA_TOOLS_IMAGE), then idling until it is
    # deleted. Every TYPE:PATH is a hostPath volume of the node, mounted
    # read-only at the same path: TYPE is its hostPath type (File,
    # Directory).
    # Example: dra-script-pod-yaml reader "$VM" shared-ro 'ls /opt/x' Directory:/opt/x
    local name="$1" node claim="$3" script="$4" volumes="" mounts="" n=0 spec
    node=$(basename "$2")
    shift 4
    for spec in "$@"; do
        volumes+="
  - name: host$n
    hostPath:
      path: ${spec#*:}
      type: ${spec%%:*}"
        mounts+="
    - name: host$n
      mountPath: ${spec#*:}
      readOnly: true"
        n=$(( n + 1 ))
    done
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
spec:
  nodeSelector:
    kubernetes.io/hostname: $node
  terminationGracePeriodSeconds: 2
  restartPolicy: Never
  resourceClaims:
  - name: mem
    resourceClaimName: $claim
  volumes:
  - name: tools
    configMap:
      name: dax-rw$volumes
  containers:
  - name: main
    image: $DRA_TOOLS_IMAGE
    imagePullPolicy: IfNotPresent
    command:
    - sh
    - -c
    - |
$(sed 's/^/      /' <<< "$script")
      trap "exit 0" TERM; sleep infinity & wait
    volumeMounts:
    - name: tools
      mountPath: /tools$mounts
    resources:
      claims:
      - name: mem
EOF
}

###
### Containers of pods, and leases of pool memory
###

dra-pod-container() {
    # Usage: dra-pod-container POD[/CONTAINER]
    #
    # Print "POD CONTAINER" (CONTAINER empty if not given).
    local pod="${1%%/*}" container=""
    [[ "$1" == */* ]] && container="${1#*/}"
    echo "$pod $container"
}

dra-exec() { # script API
    # Usage: dra-exec VMDIR POD[/CONTAINER] COMMAND [ARGS...]
    #
    # Run COMMAND with ARGS in a container of pod POD in $DRA_NS (kubectl
    # exec; the default container when CONTAINER is not given). The
    # arguments reach the container as they are, one argv word each.
    # COMMAND_OUTPUT has what COMMAND printed to stdout, DRA_EXEC_STDERR what
    # it printed to stderr (both are shown), COMMAND_STATUS its exit status,
    # which is also returned.
    # Example: dra-exec "$VM" borrower/main cxl-request request --size 512Mi
    local vmdir="$1" pod container cmd errfile
    read -r pod container <<< "$(dra-pod-container "$2")"
    shift 2
    cmd="kubectl exec -n $DRA_NS $pod${container:+ -c $container} --$(printf ' %q' "$@")"
    echo -e "\e[38;5;13mroot@$(dra-vm-label "$vmdir")>\e[0m $cmd"
    errfile=$(mktemp)
    COMMAND_OUTPUT=$(dra-vm-command-q "$vmdir" "$cmd" 2>"$errfile")
    COMMAND_STATUS=$?
    DRA_EXEC_STDERR=$(cat "$errfile")
    rm -f "$errfile"
    [ -z "$COMMAND_OUTPUT" ] || echo "$COMMAND_OUTPUT"
    [ -z "$DRA_EXEC_STDERR" ] || echo "(stderr) $DRA_EXEC_STDERR"
    [ "$COMMAND_STATUS" == 0 ] || echo "(exit status $COMMAND_STATUS)"
    return "$COMMAND_STATUS"
}

dra-last-json() { # script API
    # Usage: dra-last-json TEXT
    #
    # Print the last line of TEXT that is a JSON object, for instance the
    # response of "cxl-request request --size 512Mi" among other output.
    # Return 1 if there is none.
    python3 -c '
import json, sys
last = None
for line in sys.stdin.read().splitlines():
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        last = json.loads(line)
    except ValueError:
        continue
if last is None:
    sys.exit(1)
print(json.dumps(last))' <<< "$1"
}

dra-env-assert() { # script API
    # Usage: dra-env-assert LABEL TEXT KEY FIELD=VALUE...
    #
    # Fail the test unless the lines CXL_KEY_FIELD=VALUE of TEXT (what env
    # or "cxl-request env" printed) are exactly the FIELD=VALUE pairs given,
    # no field missing and none more, the environment of one memory device
    # (docs/memory/cxl/usage.md). KEY is the upper-case hex serial of a memdev,
    # REGION<n> or DRAM. VALUE is a shell pattern, for instance
    # DAX=/dev/dax*.
    # Example: dra-env-assert consumer "$LOG" C1EE0001 SERIAL=0xc1ee0001 SHARED=0 MODE=numa SIZE=536870912 NODE=2
    local label="$1" text="$2" key="$3"
    shift 3
    python3 -c '
import fnmatch, sys
text, key, want = sys.argv[1], sys.argv[2], sys.argv[3:]
prefix = "CXL_%s_" % key
got = {}
for line in text.splitlines():
    name, sep, value = line.strip().partition("=")
    # A field is a word without "_": CXL_C100E2E1_2_SIZE is another key.
    if sep and name.startswith(prefix) and "_" not in name[len(prefix):]:
        got[name[len(prefix):]] = value
want = dict(w.partition("=")[::2] for w in want)
bad = sorted(set(got) ^ set(want)) + sorted(f for f in set(got) & set(want) if not fnmatch.fnmatchcase(got[f], want[f]))
if bad:
    print("got:  %s\nwant: %s\nfields that differ: %s" % (
        " ".join("%s%s=%s" % (prefix, f, got[f]) for f in sorted(got)),
        " ".join("%s%s=%s" % (prefix, f, want[f]) for f in sorted(want)), " ".join(bad)))
    sys.exit(1)' "$text" "$key" "$@" ||
        error "$label: the environment of CXL_${key}_ is not $*"
    echo "env ok: $label: CXL_${key}_: $*"
}

dra-env-value() { # script API
    # Usage: dra-env-value TEXT NAME
    #
    # Print the value of the line NAME=VALUE of TEXT (what env or
    # "cxl-request env" printed). Return 1 if there is none.
    local value
    value=$(sed -n "s/^$2=//p" <<< "$1" | head -n 1)
    [ -n "$value" ] || grep -q "^$2=" <<< "$1" || return 1
    echo "$value"
}

dra-companion-meta-check() { # script API
    # Usage: dra-companion-meta-check JSON LEASE REQUESTER_UID NODE NS/POD/CONTAINER
    #
    # Fail the test unless the companion pod or claim of lease LEASE in
    # JSON has exactly the labels of the lease ($DRA_LEASE_LABEL=LEASE,
    # $DRA_REQUESTER_LABEL=REQUESTER_UID, $DRA_NODE_LABEL=NODE) and the
    # annotation $DRA_REQUESTER_ANNOTATION=NS/POD/CONTAINER, the requesting
    # container.
    dra-assert "$1" "j['metadata']['labels'] == {'$DRA_LEASE_LABEL': '$2', '$DRA_REQUESTER_LABEL': '$3', '$DRA_NODE_LABEL': '$4'}"
    dra-assert "$1" "j['metadata']['annotations']['$DRA_REQUESTER_ANNOTATION'] == '$5'"
}

dra-lease-template-yaml() { # script API
    # Usage: dra-lease-template-yaml [NAME]
    #
    # Print the ResourceClaimTemplate NAME (default cxl-lease) with one
    # request "lease" of DeviceClass cxl-lease: a pod with a claim from it
    # may lease memory and filesystems for its containers that use the
    # claim, and the claim lives and dies with the pod.
    cat <<EOF2
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: ${1:-cxl-lease}
spec:
  spec:
    devices:
      requests:
      - name: lease
        exactly:
          deviceClassName: cxl-lease
EOF2
}

dra-leases() { # script API
    # Usage: dra-leases VMDIR POD[/CONTAINER]
    #
    # Run "cxl-request list" in the container (the default container of
    # POD when not given) and print its leases as one JSON list, whatever
    # form cxl-request printed them in (a list, {"leases": [...]}, or one
    # object per line). COMMAND_OUTPUT and DRA_LEASES have the list. Fail
    # the test if cxl-request fails.
    local vmdir="$1" target="$2"
    dra-exec "$vmdir" "$target" "$DRA_REQUEST_CTR_BIN" list ||
        command-error "cxl-request list failed in $target"
    DRA_LEASES=$(python3 -c '
import json, sys
text = sys.stdin.read().strip()
leases = []
try:
    j = json.loads(text) if text else []
    if isinstance(j, dict):
        j = j.get("leases", [j] if "lease" in j else [])
    leases = j or []
except ValueError:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            leases.append(json.loads(line))
print(json.dumps(leases))' <<< "$COMMAND_OUTPUT") ||
        error "dra-leases: cannot parse the output of cxl-request list: $COMMAND_OUTPUT"
    COMMAND_OUTPUT="$DRA_LEASES"
    echo "leases of $target: $DRA_LEASES"
}

dra-container-cgroup() { # script API
    # Usage: dra-container-cgroup VMDIR POD CONTAINER
    #
    # Print the cgroup v2 directory of container CONTAINER of pod POD in
    # $DRA_NS, in the VM of VMDIR: the cgroup of its init process (crictl
    # inspect .info.pid, /proc/PID/cgroup). Processes of "kubectl exec" run
    # in the same cgroup.
    local vmdir="$1" pod="$2" container="$3"
    dra-vm-command-q "$vmdir" "id=\$(kubectl get pod -n $DRA_NS $pod -o jsonpath='{.status.containerStatuses[?(@.name==\"$container\")].containerID}') && id=\${id#*://} && [ -n \"\$id\" ] &&
        pid=\$(crictl inspect -o go-template --template '{{.info.pid}}' \$id 2>/dev/null) && [ -n \"\$pid\" ] &&
        cg=\$(sed -n 's/^0:://p' /proc/\$pid/cgroup) && [ -d \"/sys/fs/cgroup\$cg\" ] && echo \"/sys/fs/cgroup\$cg\""
}

dra-container-file() { # script API
    # Usage: dra-container-file VMDIR POD CONTAINER FILE
    #
    # Show cgroup FILE (for instance cpuset.mems.effective or
    # memory.numa_stat) of container CONTAINER of pod POD, read in the VM
    # of VMDIR. COMMAND_OUTPUT has its contents. Fail the test if the
    # container or the file cannot be found.
    local vmdir="$1" pod="$2" container="$3" file="$4" cg
    cg=$(dra-container-cgroup "$vmdir" "$pod" "$container") ||
        error "dra-container-file: no cgroup of container $container of pod $pod in $(dra-vm-label "$vmdir")"
    dra-vm-command "$vmdir" "cat $cg/$file" ||
        command-error "cannot read $file of container $container of pod $pod"
}

dra-container-read() { # script API
    # Usage: dra-container-read VMDIR POD CONTAINER FILE
    #
    # Print cgroup FILE of container CONTAINER of pod POD in $DRA_NS, read
    # in the VM of VMDIR, quietly. Return non-zero if the container or the
    # file cannot be found.
    local cg
    cg=$(dra-container-cgroup "$1" "$2" "$3") || return 1
    dra-vm-command-q "$1" "cat $cg/$4"
}

dra-mems-wait() { # script API
    # Usage: dra-mems-wait VMDIR POD CONTAINER NODE
    #
    # Wait until cpuset.mems of container CONTAINER of pod POD in $DRA_NS
    # has NUMA node NODE, 30 s at most, and print its cpuset.mems,
    # cpuset.mems.effective and the Mems_allowed_list of a process in it.
    # Fail the test on timeout.
    local vmdir="$1" pod="$2" container="$3" node="$4" mems
    retry-until --timeout 30 --interval 1 --message "cpuset.mems of container $container of $pod has node $node" \
        'mems=$(dra-container-read "$vmdir" "$pod" "$container" cpuset.mems) && dra-nodes-has "$mems" "$node"' ||
        error "cpuset.mems of container $container of pod $pod is '$(dra-container-read "$vmdir" "$pod" "$container" cpuset.mems)', expected that it has node $node"
    echo "$pod/$container: cpuset.mems $mems (has node $node), effective $(dra-container-read "$vmdir" "$pod" "$container" cpuset.mems.effective)"
    dra-exec "$vmdir" "$pod/$container" grep Mems_allowed_list /proc/self/status ||
        command-error "cannot read Mems_allowed_list in container $container of pod $pod"
}

dra-mems-fenced() { # script API
    # Usage: dra-mems-fenced VMDIR NODE [NS/POD/CONTAINER...]
    #
    # Wait until NUMA node NODE is in cpuset.mems.effective of the listed
    # containers and of no other running container of the node of the VM
    # of VMDIR, 30 s at most, and print the cpusets of every running
    # container (see dra-mems-table). Containers are those of crictl ps:
    # pod sandboxes are not containers. Fail the test on timeout, naming
    # the offenders: a container that has the node without being listed,
    # one that is listed and lacks it, a listed one that does not run.
    # Example: dra-mems-fenced "$VM" "$CXL_NODE" "$DRA_NS/pooled-consumer/consumer"
    local vmdir="$1" node="$2" label wanted table="" status=""
    shift 2
    local ctrs=("$@")
    label=$(dra-vm-label "$vmdir")
    if [ "${#ctrs[@]}" == 0 ]; then
        wanted="of no container"
    else
        wanted="of ${ctrs[*]} and of no other container"
    fi
    retry-until --timeout 30 --interval 1 --message "$label: node $node in cpuset.mems.effective $wanted" \
        'table=$(dra-mems-table "$vmdir" "$node" "${ctrs[@]}"); status=$?; [ "$status" == 0 ]'
    echo "$table"
    case "$status" in
        0) return 0;;
        3) error "$label: node $node is allowed only in ${ctrs[*]:-no container}, offenders:
$(grep -F '  <- ' <<< "$table")";;
        *) error "dra-mems-fenced: cannot list the containers of $label and their cpusets (status $status)";;
    esac
}

dra-mems-table() {
    # Usage: dra-mems-table VMDIR NODE [NS/POD/CONTAINER...]
    #
    # Print one line per running container of the node of the VM of VMDIR,
    # sorted, read in one go:
    #   NS/POD/CONTAINER cpuset.mems MEMS effective EFFECTIVE[  <- REASON]
    # MEMS and EFFECTIVE are its cpuset.mems and cpuset.mems.effective
    # ('""' when empty). REASON marks an offender: "has node NODE" (not
    # listed), "lacks node NODE" (listed), "cannot read its cpuset: ...",
    # and "not running" for a listed container that does not run (MEMS and
    # EFFECTIVE are "-").
    # Return 0 if there is no offender, 3 if there is one, other values if
    # the containers cannot be listed.
    local vmdir="$1" prog
    shift
    # The cgroup of a container is that of its init process (crictl
    # inspect .info.pid, /proc/PID/cgroup). A container that exits during
    # the listing is left out.
    prog='
import json, os, subprocess, sys
def nodes(text):
    out = set()
    for part in text.strip().split(","):
        if part.strip():
            lo, _, hi = part.strip().partition("-")
            out.update(range(int(lo), int(hi or lo) + 1))
    return out
def crictl(*args):
    return subprocess.run(["crictl"] + list(args), capture_output=True, text=True)
def inspected(text):
    j = json.loads(text)
    return j if isinstance(j, list) else [j]
node, allowed = int(sys.argv[1]), set(sys.argv[2:])
ps = crictl("ps", "-q")
if ps.returncode != 0:
    sys.exit("crictl ps failed: " + ps.stderr.strip())
ids = ps.stdout.split()
infos = []
if ids:
    r = crictl("inspect", "-o", "json", *ids)
    if r.returncode == 0:
        infos = inspected(r.stdout)
    else:
        # A container was removed after the listing: the others one by one.
        for i in ids:
            r = crictl("inspect", "-o", "json", i)
            if r.returncode == 0:
                infos += inspected(r.stdout)
rows, seen = [], set()
for c in infos:
    st = c.get("status") or {}
    if st.get("state") != "CONTAINER_RUNNING":
        continue
    lb = st.get("labels") or {}
    name = "/".join([lb.get("io.kubernetes.pod.namespace", "-"), lb.get("io.kubernetes.pod.name", "-"),
                     lb.get("io.kubernetes.container.name") or (st.get("metadata") or {}).get("name", "-")])
    pid = (c.get("info") or {}).get("pid") or 0
    try:
        with open("/proc/%d/cgroup" % pid) as f:
            cg = "/sys/fs/cgroup" + [l[3:].strip() for l in f if l.startswith("0::")][0]
        with open(cg + "/cpuset.mems") as f:
            mems = f.read().strip()
        with open(cg + "/cpuset.mems.effective") as f:
            eff = f.read().strip()
    except (OSError, IndexError) as e:
        if pid == 0 or not os.path.exists("/proc/%d" % pid):
            continue
        seen.add(name)
        rows.append((name, "?", "?", "cannot read its cpuset: %s" % e))
        continue
    seen.add(name)
    has = node in nodes(eff)
    why = ""
    if has and name not in allowed:
        why = "has node %d" % node
    elif not has and name in allowed:
        why = "lacks node %d" % node
    rows.append((name, mems or "\"\"", eff or "\"\"", why))
rows += [(name, "-", "-", "not running") for name in allowed - seen]
w = max([len(r[0]) for r in rows] + [1])
for name, mems, eff, why in sorted(rows):
    print(("%-*s cpuset.mems %-5s effective %-5s%s" % (w, name, mems, eff, "  <- " + why if why else "")).rstrip())
sys.exit(3 if any(r[3] for r in rows) else 0)'
    dra-vm-command-q "$vmdir" "python3 -c $(printf %q "$prog")$(printf ' %q' "$@")"
}

dra-container-anon() { # script API
    # Usage: dra-container-anon VMDIR POD CONTAINER NODE
    #
    # Print the anonymous memory of container CONTAINER of pod POD on NUMA
    # node NODE in bytes ("anon N<NODE>=" of memory.numa_stat, 0 if the
    # node is not listed), quietly.
    local vmdir="$1" pod="$2" container="$3" node="$4" cg
    cg=$(dra-container-cgroup "$vmdir" "$pod" "$container") || return 1
    dra-vm-command-q "$vmdir" "cat $cg/memory.numa_stat" |
        awk -v n="N$node" '$1 == "anon" { for (i = 2; i <= NF; i++) { split($i, kv, "="); if (kv[1] == n) v = kv[2] } } END { print v + 0 }'
}

dra-container-mempolicy() { # script API
    # Usage: dra-container-mempolicy VMDIR POD CONTAINER
    #
    # Print the memory policy of the main process of container CONTAINER
    # of pod POD in $DRA_NS (its init process, crictl inspect .info.pid),
    # read in the VM of VMDIR, quietly: the policies of the mappings in its
    # numa_maps, which show the policy of the process where a mapping has
    # none of its own, distinct, space-separated, for instance "default",
    # "prefer:2" or "interleave:0-2". Return non-zero if it cannot be read.
    local vmdir="$1" pod="$2" container="$3"
    dra-vm-command-q "$vmdir" "id=\$(kubectl get pod -n $DRA_NS $pod -o jsonpath='{.status.containerStatuses[?(@.name==\"$container\")].containerID}') && id=\${id#*://} && [ -n \"\$id\" ] &&
        pid=\$(crictl inspect -o go-template --template '{{.info.pid}}' \$id 2>/dev/null) && [ -n \"\$pid\" ] &&
        p=\$(awk '{print \$2}' /proc/\$pid/numa_maps | sort -u | tr '\n' ' ') && [ -n \"\$p\" ] && echo \"\${p% }\""
}

dra-memory-state() {
    # Usage: dra-memory-state VMDIR POD CONTAINER
    #
    # Set DRA_MEM_HIGH to memory.high of container CONTAINER of pod POD and
    # DRA_MEMPOLICY to the memory policy of its main process (see
    # dra-container-mempolicy). Return non-zero if either cannot be read.
    DRA_MEM_HIGH=$(dra-container-read "$1" "$2" "$3" memory.high) || return 1
    DRA_MEMPOLICY=$(dra-container-mempolicy "$1" "$2" "$3") || return 1
}

dra-memory-wait() { # script API
    # Usage: dra-memory-wait VMDIR POD CONTAINER steered|fenced|none [STEERING]
    #
    # Wait until the driver on the node of the VM of VMDIR has logged how
    # it manages the memory of container CONTAINER of pod POD in $DRA_NS
    # ("NRI CreateContainer: ctr=NS/POD/CONTAINER: memory MANAGEMENT
    # (steering STEERING, fencing ..."; STEERING is the effective policy
    # and its origin, for instance "none (default)" or "auto from claim
    # NS/NAME request mem"; any if not given), and check the container:
    #   steered        memory.high is not max and the main process has a
    #                  memory policy (waits until the steering has started)
    #   fenced, none   memory.high is max and the main process has the
    #                  default memory policy
    # DRA_MEM_HIGH and DRA_MEMPOLICY are what was read last. Fail the test
    # on timeout or a mismatch.
    # Example: dra-memory-wait "$VM" numa-a main fenced "none (default)"
    local vmdir="$1" pod="$2" container="$3" mgmt="$4" steering="$5" ctr label
    ctr="$DRA_NS/$pod/$container"
    label=$(dra-vm-label "$vmdir")
    case "$mgmt" in
        steered|fenced|none) ;;
        *) error "dra-memory-wait: unknown management '$mgmt'";;
    esac
    dra-plugin-log-wait "$vmdir" "NRI CreateContainer: ctr=$ctr: memory $mgmt (${steering:+steering $steering}" 60
    DRA_MEM_HIGH="" DRA_MEMPOLICY=""
    if [ "$mgmt" == steered ]; then
        retry-until --timeout 30 --interval 1 --message "$label: $ctr is steered: memory.high is not max, its main process has a memory policy" \
            'dra-memory-state "$vmdir" "$pod" "$container" && [ "$DRA_MEM_HIGH" != max ] && [ "$DRA_MEMPOLICY" != default ]' ||
            error "$label: $ctr is not steered: memory.high '$DRA_MEM_HIGH', memory policy of its main process '$DRA_MEMPOLICY'"
    else
        dra-memory-state "$vmdir" "$pod" "$container" ||
            error "$label: cannot read memory.high or the memory policy of the main process of $ctr"
        [ "$DRA_MEM_HIGH" == max ] && [ "$DRA_MEMPOLICY" == default ] ||
            error "$label: $ctr is $mgmt, not steered, but memory.high is '$DRA_MEM_HIGH' and the memory policy of its main process '$DRA_MEMPOLICY', expected max and default"
    fi
    echo "memory ok: $label: $ctr $mgmt${steering:+, steering $steering}: memory.high $DRA_MEM_HIGH, memory policy of the main process $DRA_MEMPOLICY"
}

dra-container-bpf-count() {
    # Usage: dra-container-bpf-count VMDIR POD CONTAINER
    local cg
    cg=$(dra-container-cgroup "$1" "$2" "$3") || return 1
    dra-vm-command-q "$1" "bpftool cgroup show $cg 2>/dev/null | grep -c cgroup_device"
}

dra-container-devices() { # script API
    # Usage: dra-container-devices VMDIR POD CONTAINER
    #
    # Print what the device cgroup of container CONTAINER of pod POD allows,
    # in a form to compare before and after: the device rules of its runtime
    # spec (crictl inspect, line "spec: ...") and the distinct eBPF device
    # programs attached to its cgroup (line "bpf: ...", hashes of their code,
    # bpftool). Measured in VM2 (containerd, systemd cgroup driver): the
    # first runtime update of a container (crictl update, NRI
    # UpdateContainers) attaches one more, different program; later updates
    # add none. Compare the spec line to see whether the rules changed.
    # Quietly. dra-container-bpf-count prints how many are attached.
    local vmdir="$1" pod="$2" container="$3" cg
    cg=$(dra-container-cgroup "$vmdir" "$pod" "$container") || return 1
    dra-vm-command-q "$vmdir" "id=\$(kubectl get pod -n $DRA_NS $pod -o jsonpath='{.status.containerStatuses[?(@.name==\"$container\")].containerID}'); id=\${id#*://}
        echo \"spec: \$(crictl inspect \$id 2>/dev/null | jq -c .info.runtimeSpec.linux.resources.devices)\"
        echo \"bpf: \$(for p in \$(bpftool cgroup show $cg 2>/dev/null | awk '\$2 == \"cgroup_device\" {print \$1}'); do bpftool prog dump xlated id \$p | sha256sum | cut -c1-16; done | sort -u | tr '\\n' ' ')\""
}

dra-pod-claim() { # script API
    # Usage: dra-pod-claim VMDIR POD [NAME]
    #
    # Print the name of the ResourceClaim of pod POD in $DRA_NS, the claim
    # that the pod calls NAME (default: its first claim): the claim made
    # from its template (status.resourceClaimStatuses), or the claim it
    # references. Return 1 if there is none yet.
    local vmdir="$1" pod="$2" name="$3" json claim
    json=$(dra-vm-command-q "$vmdir" "kubectl get pod -n $DRA_NS $pod -o json") || return 1
    claim=$(dra-py eval "$json" "next((s.get('resourceClaimName') for s in (j.get('status') or {}).get('resourceClaimStatuses') or [] if '$name' in ('', s.get('name'))), None) or next((c.get('resourceClaimName') for c in j['spec'].get('resourceClaims') or [] if '$name' in ('', c.get('name'))), None) or ''") || return 1
    [ -n "$claim" ] || return 1
    echo "$claim"
}

dra-nodes-py() {
    # Usage: dra-nodes-py has|eq LIST ARG
    #
    # has: return 0 if node ARG is in the node list LIST ("0-1,3").
    # eq:  return 0 if the node lists LIST and ARG have the same nodes
    #      ("0-2" and "0-1,2": the kernel joins ranges).
    # sub: return 0 if LIST has nodes and all of them are in the node list
    #      ARG.
    python3 -c '
import sys
def nodes(text):
    out = set()
    for part in text.strip().split(","):
        if part:
            lo, _, hi = part.partition("-")
            out.update(range(int(lo), int(hi or lo) + 1))
    return out
op, a, b = sys.argv[1:4]
if op == "has":
    ok = int(b) in nodes(a)
elif op == "sub":
    ok = bool(nodes(a)) and nodes(a) <= nodes(b)
else:
    ok = nodes(a) == nodes(b)
sys.exit(0 if ok else 1)' "$1" "$2" "$3"
}

dra-nodes-has() { # script API
    # Usage: dra-nodes-has LIST NODE
    #
    # Return 0 if NUMA node NODE is in the node list LIST ("0-1,3").
    dra-nodes-py has "$1" "$2"
}

dra-nodes-eq() { # script API
    # Usage: dra-nodes-eq LIST1 LIST2
    #
    # Return 0 if the node lists LIST1 and LIST2 have the same nodes.
    dra-nodes-py eq "$1" "$2"
}

dra-nodes-subset() { # script API
    # Usage: dra-nodes-subset LIST1 LIST2
    #
    # Return 0 if the node list LIST1 has nodes and every one of them is in
    # the node list LIST2.
    dra-nodes-py sub "$1" "$2"
}

dra-touch-start() { # script API
    # Usage: dra-touch-start VMDIR POD/CONTAINER MIB NODE
    #
    # Start numa-touch.py (dra-dax-tool-install) in the background in
    # container CONTAINER of pod POD in $DRA_NS (kubectl exec: not a child
    # of the main process, see dra-run): MIB MiB that prefer NUMA node NODE
    # ("-": the policy of the process), held until dra-touch-stop. Wait
    # until it has touched every
    # page. DRA_TOUCH_PID is its pid in the container, DRA_TOUCH_LOG its
    # output then, with the pages per node. Fail the test if it fails.
    local vmdir="$1" target="$2" mib="$3" node="$4" pod container
    read -r pod container <<< "$(dra-pod-container "$target")"
    DRA_TOUCH_VM="$vmdir"
    DRA_TOUCH_TARGET="$target"
    DRA_TOUCH_EXEC="kubectl exec -n $DRA_NS $pod${container:+ -c $container} --"
    DRA_TOUCH_PID=""
    # shellcheck disable=SC2016 # $1 and $2 are expanded by sh in the container
    dra-exec "$vmdir" "$target" sh -c 'setsid python3 /tools/numa-touch.py --hold "$1" "$2" > /tmp/numa-touch.log 2>&1 < /dev/null &' sh "$mib" "$node" ||
        command-error "cannot start numa-touch.py in $target"
    retry-until --timeout 60 --interval 1 --message "numa-touch.py in $target has touched $mib MiB" \
        'dra-vm-command-q "$vmdir" "$DRA_TOUCH_EXEC cat /tmp/numa-touch.log" | grep -qE "^numa-touch: (ready|.*failed)"' ||
        error "numa-touch.py in $target did not finish touching its memory"
    dra-exec "$vmdir" "$target" cat /tmp/numa-touch.log
    grep -q "^numa-touch: ready" <<< "$COMMAND_OUTPUT" || error "numa-touch.py in $target failed: $COMMAND_OUTPUT"
    DRA_TOUCH_PID=$(sed -n 's/^numa-touch: pid \([0-9]*\) .*/\1/p' <<< "$COMMAND_OUTPUT")
    DRA_TOUCH_LOG="$COMMAND_OUTPUT"
}

dra-touch-log-pages() { # script API
    # Usage: dra-touch-log-pages TEXT NODES
    #
    # Print the pages on the NUMA nodes NODES (a node list, "2" or "0-1")
    # in the last "numa-touch: pages" line of TEXT, the output of
    # numa-touch.py (0 for a node that is not listed).
    python3 -c '
import sys
text, spec = sys.argv[1], sys.argv[2]
want = set()
for part in spec.strip().split(","):
    if part:
        lo, _, hi = part.partition("-")
        want.update(range(int(lo), int(hi or lo) + 1))
lines = [l for l in text.splitlines() if l.startswith("numa-touch: pages")]
pages = 0
for w in (lines[-1].split()[2:] if lines else []):
    k, sep, v = w.partition("=")
    if sep and k[:1] == "N" and k[1:].isdigit() and int(k[1:]) in want:
        pages += int(v)
print(pages)' "$1" "$2"
}

dra-touch-pages() { # script API
    # Usage: dra-touch-pages NODE
    #
    # Ask the numa-touch.py of dra-touch-start where its pages are now
    # (SIGUSR1) and wait for its answer. DRA_TOUCH_PAGES is how many of
    # them are on NUMA node NODE. Fail the test if it does not run any more.
    local node="$1" before
    [ -n "$DRA_TOUCH_PID" ] || error "dra-touch-pages: numa-touch.py does not run, call dra-touch-start first"
    before=$(dra-touch-reports)
    dra-exec "$DRA_TOUCH_VM" "$DRA_TOUCH_TARGET" kill -USR1 "$DRA_TOUCH_PID" ||
        error "numa-touch.py (pid $DRA_TOUCH_PID) in $DRA_TOUCH_TARGET is not running any more"
    retry-until --timeout 10 --interval 1 --message "numa-touch.py reports its pages" \
        '[ "$(dra-touch-reports)" -gt "${before:-0}" ]' ||
        error "numa-touch.py (pid $DRA_TOUCH_PID) in $DRA_TOUCH_TARGET did not report its pages"
    dra-exec "$DRA_TOUCH_VM" "$DRA_TOUCH_TARGET" cat /tmp/numa-touch.log
    DRA_TOUCH_PAGES=$(dra-touch-log-pages "$COMMAND_OUTPUT" "$node")
}

dra-touch-reports() {
    # Usage: dra-touch-reports
    #
    # Print how many "pages" lines the numa-touch.py of dra-touch-start has
    # written (0 if its log cannot be read).
    local n
    n=$(dra-vm-command-q "$DRA_TOUCH_VM" "$DRA_TOUCH_EXEC grep -c '^numa-touch: pages' /tmp/numa-touch.log")
    echo "${n:-0}"
}

dra-touch-forget() { # script API
    # Usage: dra-touch-forget
    #
    # Forget the numa-touch.py of dra-touch-start without stopping it, for
    # instance when its pod is deleted.
    DRA_TOUCH_PID=""
}

dra-touch-stop() { # script API
    # Usage: dra-touch-stop
    #
    # Stop the numa-touch.py of dra-touch-start, if it runs.
    [ -n "$DRA_TOUCH_PID" ] || return 0
    dra-exec "$DRA_TOUCH_VM" "$DRA_TOUCH_TARGET" kill "$DRA_TOUCH_PID"
    DRA_TOUCH_PID=""
}

dra-stays() { # script API
    # Usage: dra-stays SECONDS MESSAGE SNIPPET
    #
    # Evaluate SNIPPET on the host at once and then once a second for
    # SECONDS seconds, and fail the test with MESSAGE as soon as it is not
    # true. SNIPPET must not refer to variables named _stays_*.
    local _stays_secs="$1" _stays_msg="$2" _stays_snippet="$3" _stays_end
    echo "checking for ${_stays_secs}s: $_stays_msg"
    _stays_end=$(( SECONDS + _stays_secs ))
    while true; do
        eval "$_stays_snippet" ||
            error "not true any more after $(( _stays_secs - _stays_end + SECONDS ))s: $_stays_msg"
        [ "$SECONDS" -lt "$_stays_end" ] || break
        sleep 1
    done
    echo "held for ${_stays_secs}s: $_stays_msg"
}

###
### Querying and waiting
###

dra-py() {
    # Usage: dra-py assert|eval JSON EXPRESSION
    #
    # Evaluate the Python EXPRESSION on the JSON document (output of
    # "kubectl get ... -o json"). Names in EXPRESSION:
    #   j                      the document
    #   items                  j["items"] of a list, [j] of a single object
    #   names()                sorted metadata.name of items
    #   by_name(name)          the item called name, None if not found
    #   slices(driver, node)   ResourceSlices of driver (and node, if given)
    #   pool_slices(pool, driver)  ResourceSlices of driver (default
    #                          cxl-pool.nri.io) of DRA pool pool
    #   pool_nodes(pool, driver)   sorted kubernetes.io/hostname values of
    #                          the nodeSelector of the pool_slices if they
    #                          all have the same selector of exactly one
    #                          term with exactly that one In expression,
    #                          and no allNodes; None otherwise
    #   devices(driver, node)  devices of those slices
    #   device(name, driver, node)  the device called name (of driver, in
    #                          the slice of node, if given), None if not found
    #   attr(dev, name)        value of an attribute ({"string": v} -> v)
    #   capacity(dev, name)    value of a capacity ("512Mi")
    #   request_policy(dev, name)  requestPolicy of a capacity, None if none
    #   quantity(q)            bytes of a quantity ("64Mi", "268435456")
    #   MiB                    1 << 20
    #   results(claim)         allocation results of a ResourceClaim (j)
    #   consumed(claim, name)  bytes of capacity name ("memory") that the
    #                          allocation results of a claim (j) consume
    #   allocated_node(claim)  node of the allocation's nodeSelector
    #   condition(type, claim) status of a condition in status.devices
    #   device_data(dev, claim) data of the status.devices entry of dev
    #   subrequests(claim)     what the device requests of a ResourceClaim
    #                          (j) ask for: the exactly part of a request,
    #                          named like the request, and the subrequests
    #                          of firstAvailable, named request/subrequest
    #   configs(kind, claim)   the opaque configs of a ResourceClaim (j) of
    #                          kind (all if None): {driver, parameters,
    #                          requests}
    #   config_section(c, name)  section name (device, container, pool) of
    #                          the parameters of an entry c of configs(),
    #                          {} if it has none
    #   events(reason, name)   Events with reason, of object name
    #   dax_slices(driver)     dax devices with a size of a dra-memdev-sysfs
    #                          document (j), bound to driver if given
    python3 -c '
import decimal, json, sys

mode, expression = sys.argv[1], sys.argv[2]
text = sys.stdin.read()
try:
    j = json.loads(text)
except ValueError as e:
    print("dra-py: invalid JSON (%s): %s" % (e, text[:2000]), file=sys.stderr)
    sys.exit(2)
items = j.get("items", [j]) if isinstance(j, dict) else j
items = items or []

def names():
    return sorted(o["metadata"]["name"] for o in items)

def by_name(name):
    return next((o for o in items if o["metadata"]["name"] == name), None)

def slices(driver=None, node=None):
    return [s for s in items
            if (driver is None or s["spec"].get("driver") == driver)
            and (node is None or s["spec"].get("nodeName") == node)]

def pool_slices(pool, driver="cxl-pool.nri.io"):
    return [s for s in slices(driver) if (s["spec"].get("pool") or {}).get("name") == pool]

def pool_nodes(pool, driver="cxl-pool.nri.io"):
    sels = [s["spec"].get("nodeSelector") for s in pool_slices(pool, driver) if not s["spec"].get("allNodes")]
    if not sels or len(sels) != len(pool_slices(pool, driver)) or any(sel != sels[0] for sel in sels):
        return None
    terms = (sels[0] or {}).get("nodeSelectorTerms") or []
    if len(terms) != 1 or sorted(terms[0]) != ["matchExpressions"] or len(terms[0]["matchExpressions"]) != 1:
        return None
    e = terms[0]["matchExpressions"][0]
    if e.get("key") != "kubernetes.io/hostname" or e.get("operator") != "In":
        return None
    return sorted(e.get("values") or [])

def devices(driver=None, node=None):
    return [d for s in slices(driver, node) for d in s["spec"].get("devices") or []]

def device(name, driver=None, node=None):
    return next((d for d in devices(driver, node) if d["name"] == name), None)

def attr(dev, name):
    attrs = (dev or {}).get("attributes") or {}
    a = attrs.get(name)
    if a is None:
        a = next((v for k, v in attrs.items() if k.endswith("/" + name)), None)
    if a is None:
        return None
    return next(iter(a.values()))

def capacity(dev, name):
    c = ((dev or {}).get("capacity") or {}).get(name)
    return c.get("value") if c else None

def request_policy(dev, name):
    c = ((dev or {}).get("capacity") or {}).get(name)
    return c.get("requestPolicy") if c else None

MiB = 1 << 20
SUFFIXES = [("Ki", 1 << 10), ("Mi", 1 << 20), ("Gi", 1 << 30), ("Ti", 1 << 40), ("Pi", 1 << 50), ("Ei", 1 << 60),
            ("k", 10 ** 3), ("M", 10 ** 6), ("G", 10 ** 9), ("T", 10 ** 12), ("P", 10 ** 15), ("E", 10 ** 18)]

def quantity(q):
    q = str(q).strip()
    for suffix, mult in SUFFIXES:
        if q.endswith(suffix):
            return int(decimal.Decimal(q[:-len(suffix)]) * mult)
    return int(decimal.Decimal(q))

def results(claim=None):
    claim = claim or j
    alloc = (claim.get("status") or {}).get("allocation") or {}
    return (alloc.get("devices") or {}).get("results") or []

def consumed(claim=None, name="memory"):
    return sum(quantity((r.get("consumedCapacity") or {}).get(name, 0)) for r in results(claim))

def allocated_node(claim=None):
    claim = claim or j
    alloc = (claim.get("status") or {}).get("allocation") or {}
    for term in (alloc.get("nodeSelector") or {}).get("nodeSelectorTerms") or []:
        for f in term.get("matchFields") or []:
            if f.get("key") == "metadata.name" and f.get("values"):
                return f["values"][0]
    return None

def status_devices(claim=None):
    claim = claim or j
    return (claim.get("status") or {}).get("devices") or []

def condition(ctype, claim=None):
    for d in status_devices(claim):
        for c in d.get("conditions") or []:
            if c.get("type") == ctype:
                return c.get("status")
    return None

def device_data(dev, claim=None):
    return next((d.get("data") for d in status_devices(claim) if d.get("device") == dev), None)

def subrequests(claim=None):
    claim = claim or j
    out = []
    for r in claim["spec"]["devices"].get("requests") or []:
        if r.get("exactly"):
            out.append(dict(r["exactly"], name=r["name"]))
        for s in r.get("firstAvailable") or []:
            out.append(dict(s, name=r["name"] + "/" + s["name"]))
    return out

def configs(kind=None, claim=None):
    claim = claim or j
    return [dict(c["opaque"], requests=c.get("requests")) for c in claim["spec"]["devices"].get("config") or []
            if c.get("opaque") and (kind is None or c["opaque"]["parameters"].get("kind") == kind)]

def config_section(c, name):
    return (c.get("parameters") or {}).get(name) or {}

def events(reason=None, name=None):
    return [e for e in items
            if (reason is None or e.get("reason") == reason)
            and (name is None or e["involvedObject"].get("name") == name)]

def dax_slices(driver=None):
    return [d for r in j.get("regions") or [] for d in r.get("dax") or []
            if d.get("size") and (driver is None or d.get("driver") == driver)]

value = eval(expression)
if mode == "eval":
    print(value)
    sys.exit(0)
sys.exit(0 if value else 1)
' "$1" "$3" <<< "$2"
}

dra-json() { # script API
    # Usage: dra-json VMDIR KUBECTL-GET-ARGS...
    #
    # Run "kubectl get KUBECTL-GET-ARGS -o json" in the cluster of the VM
    # of VMDIR. COMMAND_OUTPUT and DRA_JSON have the JSON. Print the command
    # only, the JSON is long. Return the exit status of kubectl.
    local vmdir="$1" args status
    shift
    args="$*"
    echo -e "\e[38;5;13mroot@$(dra-vm-label "$vmdir")>\e[0m kubectl get $args -o json"
    DRA_JSON=$(dra-vm-command-q "$vmdir" "kubectl get $args -o json")
    status=$?
    COMMAND_OUTPUT="$DRA_JSON"
    return $status
}

dra-assert() { # script API
    # Usage: dra-assert JSON EXPRESSION
    #
    # Fail the test unless the Python EXPRESSION is true on the JSON
    # document, see dra-py for the names in EXPRESSION.
    dra-py assert "$1" "$2" ||
        error "DRA assertion failed: $2
on: $(head -c 3000 <<< "$1")"
    echo "dra ok: $2"
}

dra-value() { # script API
    # Usage: dra-value JSON EXPRESSION
    #
    # Print the value of the Python EXPRESSION on the JSON document.
    dra-py eval "$1" "$2" || error "DRA expression failed: $2"
}

dra-wait() { # script API
    # Usage: dra-wait VMDIR LABEL "KUBECTL-GET-ARGS" EXPRESSION [TIMEOUT]
    #
    # Repeat "kubectl get KUBECTL-GET-ARGS -o json" in the cluster of the
    # VM of VMDIR until the Python EXPRESSION (see dra-py) is true on it,
    # TIMEOUT seconds at most (default 60). Store the last JSON in
    # $TEST_OUTPUT_DIR/dra.LABEL.<vm>.json and in COMMAND_OUTPUT. Fail the
    # test on timeout, showing the JSON.
    local vmdir="$1" label="$2" args="$3" expression="$4" tmo="${5:-60}" file
    file="$TEST_OUTPUT_DIR/dra.$label.$(dra-vm-label "$vmdir").json"
    retry-until --timeout "$tmo" --message "$(dra-vm-label "$vmdir"): kubectl get $args: $expression" \
        'DRA_JSON=$(dra-vm-command-q "$vmdir" "kubectl get $args -o json" 2>&1) && dra-py assert "$DRA_JSON" "$expression" 2>/dev/null' || {
        echo "$DRA_JSON" > "$file"
        error "DRA: $(dra-vm-label "$vmdir") did not reach the expected state in ${tmo}s: $expression
kubectl get $args: $(head -c 3000 <<< "$DRA_JSON")
(all in $file)"
    }
    echo "$DRA_JSON" > "$file"
    COMMAND_OUTPUT="$DRA_JSON"
    echo "dra ok: $label: $expression"
}

dra-claim-conditions() { # script API
    # Usage: dra-claim-conditions VMDIR CLAIM
    #
    # Print the conditions of the devices of ResourceClaim CLAIM in $DRA_NS,
    # one "device: type=status reason" line each, and the data that the pool
    # controller wrote for the node plugin.
    local vmdir="$1" claim="$2" json
    json=$(dra-vm-command-q "$vmdir" "kubectl get resourceclaim -n $DRA_NS $claim -o json") ||
        error "dra-claim-conditions: no ResourceClaim $claim in $(dra-vm-label "$vmdir")"
    echo "conditions of ResourceClaim $claim in $(dra-vm-label "$vmdir"):"
    python3 -c '
import json, sys
j = json.loads(sys.stdin.read())
for d in (j.get("status") or {}).get("devices") or []:
    for c in d.get("conditions") or []:
        print("  %s: %s=%s %s" % (d.get("device"), c.get("type"), c.get("status"), c.get("reason", "")))
    if d.get("data"):
        print("  %s: data %s" % (d.get("device"), json.dumps(d["data"], sort_keys=True)))' <<< "$json"
}

dra-claim-condition-watch() { # script API
    # Usage: dra-claim-condition-watch VMDIR CLAIM TYPE REASON [TIMEOUT]
    #
    # Watch ResourceClaim CLAIM in $DRA_NS (kubectl get -w) until the status
    # of one of its devices has condition TYPE with status True and reason
    # REASON, TIMEOUT seconds at most (default 60), and print the condition.
    # The watch sees conditions that last only until the scheduler
    # deallocates the claim, for instance those of bindingFailureConditions.
    # Fail the test on timeout.
    # Example: dra-claim-condition-watch "$VM" bad-pool cxl-pool.nri.io/AttachFailed InvalidConfig
    local vmdir="$1" claim="$2" ctype="$3" reason="$4" tmo="${5:-60}" prog
    prog='
import json, os, select, subprocess, sys, time
ns, claim, ctype, reason, tmo = sys.argv[1:6]
p = subprocess.Popen(["kubectl", "get", "resourceclaim", "-n", ns, claim, "-w", "-o", "json"], stdout=subprocess.PIPE)
deadline = time.monotonic() + int(tmo)
dec, buf = json.JSONDecoder(), ""
while True:
    left = deadline - time.monotonic()
    if left <= 0:
        p.kill()
        sys.exit(1)
    if not select.select([p.stdout], [], [], left)[0]:
        continue
    chunk = os.read(p.stdout.fileno(), 65536)
    if not chunk:
        sys.exit(1)
    buf += chunk.decode(errors="replace")
    while True:
        buf = buf.lstrip()
        try:
            obj, end = dec.raw_decode(buf)
        except ValueError:
            break
        buf = buf[end:]
        for d in (obj.get("status") or {}).get("devices") or []:
            for c in d.get("conditions") or []:
                if c.get("type") == ctype and c.get("status") == "True" and c.get("reason") == reason:
                    print("%s: %s=True reason %s: %s" % (d.get("device"), ctype, reason, c.get("message", "")))
                    p.kill()
                    sys.exit(0)'
    echo "watching ResourceClaim $claim for $ctype=True reason $reason, ${tmo}s at most"
    dra-vm-command "$vmdir" "python3 -c $(printf %q "$prog")$(printf ' %q' "$DRA_NS" "$claim" "$ctype" "$reason" "$tmo")" ||
        error "$(dra-vm-label "$vmdir"): ResourceClaim $claim had no device with condition $ctype=True reason $reason in ${tmo}s"
}

dra-pod-wait() { # script API
    # Usage: dra-pod-wait VMDIR POD PHASE [TIMEOUT]
    #
    # Wait until pod POD in $DRA_NS is in PHASE (Pending, Running,
    # Succeeded, Failed), TIMEOUT seconds at most (default 120). Fail the
    # test on timeout, and show the pod and its events.
    local vmdir="$1" pod="$2" phase="$3" tmo="${4:-120}"
    retry-until --timeout "$tmo" --interval 1 --message "$(dra-vm-label "$vmdir"): pod $pod $phase" \
        '[ "$(dra-vm-command-q "$vmdir" "kubectl get pod -n $DRA_NS $pod -o jsonpath={.status.phase}" 2>/dev/null)" == "$phase" ]' || {
        dra-vm-command "$vmdir" "kubectl describe pod -n $DRA_NS $pod"
        error "pod $pod in $(dra-vm-label "$vmdir") is not $phase after ${tmo}s"
    }
    dra-vm-command "$vmdir" "kubectl get pod -n $DRA_NS $pod -o wide"
}

dra-pod-log() { # script API
    # Usage: dra-pod-log VMDIR POD
    #
    # Print the log of pod POD in $DRA_NS of the cluster of the VM of
    # VMDIR, quietly.
    dra-vm-command-q "$1" "kubectl logs -n $DRA_NS $2 2>/dev/null"
}

dra-wait-log() { # script API
    # Usage: dra-wait-log VMDIR POD LINE [TIMEOUT]
    #
    # Wait until the log of pod POD in $DRA_NS of the cluster of the VM of
    # VMDIR has the line LINE (a fixed string that matches the whole line),
    # TIMEOUT seconds at most (default 120). Fail the test on timeout, and
    # show the log and the end of the description of the pod.
    local vmdir="$1" pod="$2" line="$3" tmo="${4:-120}"
    retry-until --timeout "$tmo" --interval 1 --message "$pod: \"$line\"" \
        'dra-pod-log "$vmdir" "$pod" | grep -qxF -- "$line"' || {
        dra-vm-command "$vmdir" "kubectl logs -n $DRA_NS $pod; kubectl describe pod -n $DRA_NS $pod | tail -n 20"
        error "pod $pod did not log \"$line\" in ${tmo}s"
    }
}

###
### Trace: every component's log in one timeline
###

dra-trace-start() { # script API
    # Usage: dra-trace-start [VMDIR...]
    #
    # Start collecting what every component does, in the background on the
    # host, until dra-trace-stop: the logs of the fake-cxl-pool-servers, and
    # in each VM (default: the VM of the test) the logs of the
    # fake-cxl-pool-controllers, the driver (its pod on the node),
    # kube-scheduler and kubelet (DRA lines), Events, ResourceClaim and Pod
    # watches and udev
    # events of cxl, dax, memory and node devices. Every line is stamped
    # with the host clock when it arrives on the host, so the streams of
    # all VMs merge into one timeline without VM clock skew; ssh adds a few
    # ms. The streams go to $TEST_OUTPUT_DIR/trace/<tag>.log, tag
    # <vm>.<component>, for instance vm.controller or vm1.udev; the first
    # pool server is "server", the others <name>.server. The controllers
    # share the tag <vm>.controller: their lines name their pools.
    local vmdir label name n pod journal_units=""
    [ -z "$DRA_TRACE_RUNNING" ] || error "dra-trace-start: a trace is running already"
    [ $# -gt 0 ] || set -- "$OUTPUT_DIR"
    DRA_TRACE_DIR="$TEST_OUTPUT_DIR/trace"
    rm -rf "$DRA_TRACE_DIR"
    mkdir -p "$DRA_TRACE_DIR" || error "dra-trace-start: cannot create $DRA_TRACE_DIR"
    dra-trace-write-stamper "$DRA_TRACE_DIR/stamp.py"
    : > "$DRA_TRACE_DIR/pids"
    DRA_TRACE_VMS=("$@")
    DRA_TRACE_RUNNING=1
    if [ -n "$POOL_SERVER_LOG" ] && [ -f "$POOL_SERVER_LOG" ]; then
        dra-trace-collect server lines "tail -n0 -F $(printf %q "$POOL_SERVER_LOG")"
    fi
    for name in "${POOL_SERVERS[@]:1}"; do
        # shellcheck disable=SC2153 # POOL_SERVER_LOGS is of pool.source.sh
        dra-trace-collect "$name.server" lines "tail -n0 -F $(printf %q "${POOL_SERVER_LOGS[$name]}")"
    done
    # journalctl -f resolves a unit pattern only once, to the units that
    # have logged already: name the units that dra-install started.
    for name in "${DRA_CONTROLLER_UNITS[@]}"; do
        journal_units+=" -u $name"
    done
    [ -n "$journal_units" ] || journal_units=" -u '$DRA_CONTROLLER_UNITS_GLOB'"
    for vmdir in "$@"; do
        label=$(dra-vm-label "$vmdir")
        name=$(dra-vm-name "$vmdir")
        # Collectors of an aborted trace may still run.
        dra-vm-command-q "$vmdir" "$DRA_TRACE_KILL; rm -rf /run/dra-trace; mkdir -p /run/dra-trace"
        pod=$(dra-driver-pod "$vmdir") ||
            error "dra-trace-start: $DRA_DAEMONSET does not run on $name"
        dra-trace-collect-vm "$vmdir" "$label.driver" lines "kubectl logs -n kube-system -f --tail=0 -c $DRA_CONTAINER $pod"
        dra-trace-collect-vm "$vmdir" "$label.udev" lines "stdbuf -oL udevadm monitor -k -u -s cxl -s dax -s memory -s node"
        dra-trace-collect-vm "$vmdir" "$label.kubelet" lines "journalctl -f -n0 -o cat -u kubelet | grep --line-buffered -iE 'dra|resourceclaim|cxl'"
        # The rest is of the cluster: once per cluster, on its control plane.
        [ -z "${DRA_WORKERS[$vmdir]}" ] || continue
        dra-trace-collect-vm "$vmdir" "$label.controller" lines "journalctl -f -n0 -o cat$journal_units"
        dra-trace-collect-vm "$vmdir" "$label.scheduler" lines "kubectl -n kube-system logs -f --tail=0 kube-scheduler-$name"
        dra-trace-collect-vm "$vmdir" "$label.events" lines "kubectl get events -A --watch-only -o custom-columns=NS:.metadata.namespace,KIND:.involvedObject.kind,NAME:.involvedObject.name,REASON:.reason,MSG:.message --no-headers"
        dra-trace-collect-vm "$vmdir" "$label.claims" claims "kubectl get resourceclaims -A -w --output-watch-events -o json"
        dra-trace-collect-vm "$vmdir" "$label.pods" lines "kubectl get pods -A -w --output-watch-events --no-headers"
    done
    # Every remote collector writes its pid file just before it starts.
    for vmdir in "$@"; do
        n=8
        [ -z "${DRA_WORKERS[$vmdir]}" ] || n=3
        retry-until --timeout 30 --message "trace collectors in $(dra-vm-label "$vmdir")" \
            '[ "$(dra-vm-command-q "$vmdir" "ls /run/dra-trace/ | grep -c .pid\$")" == "$n" ]' ||
            error "dra-trace-start: trace collectors did not start in $(dra-vm-label "$vmdir"), see $DRA_TRACE_DIR"
    done
    sleep 1   # for the watches to be established
    n=$(wc -l < "$DRA_TRACE_DIR/pids")
    echo "dra-trace-start: $n collectors, streams in $DRA_TRACE_DIR"
}

dra-trace-collect() {
    # Usage: dra-trace-collect TAG MODE HOST-COMMAND
    #
    # Run HOST-COMMAND in the background in a process group of its own,
    # stamp its output lines (MODE lines) or the ResourceClaims of its
    # JSON watch stream (MODE claims) to $DRA_TRACE_DIR/TAG.log.
    local tag="$1" mode="$2" cmd="$3" log err
    log="$DRA_TRACE_DIR/$tag.log"
    err="$DRA_TRACE_DIR/$tag.stderr"
    if [ "$mode" == "lines" ]; then
        err="&1"
    else
        err="$(printf %q "$err")"
    fi
    setsid bash -c "$cmd 2>$err | python3 -u $(printf %q "$DRA_TRACE_DIR/stamp.py") $(printf %q "$tag") $mode >> $(printf %q "$log")" </dev/null >/dev/null 2>&1 &
    echo "$! $tag" >> "$DRA_TRACE_DIR/pids"
}

dra-trace-driver-follow() { # script API
    # Usage: dra-trace-driver-follow VMDIR
    #
    # Add the log of the pod of the driver that runs now on the node of the
    # VM of VMDIR to the running trace, from the start of the pod, with the
    # tag <vm>.<pod name suffix>.driver. Nothing if no trace runs.
    local vmdir="$1" pod
    [ -n "$DRA_TRACE_RUNNING" ] || return 0
    pod=$(dra-driver-pod "$vmdir") ||
        error "dra-trace-driver-follow: $DRA_DAEMONSET does not run on $(dra-vm-name "$vmdir")"
    dra-trace-collect-vm "$vmdir" "$(dra-vm-label "$vmdir").${pod##*-}.driver" lines "kubectl logs -n kube-system -f --tail=-1 -c $DRA_CONTAINER $pod"
    echo "dra-trace-driver-follow: the trace follows the log of $pod"
}

dra-trace-collect-vm() {
    # Usage: dra-trace-collect-vm VMDIR TAG MODE COMMAND
    #
    # dra-trace-collect of COMMAND run as root in the VM of VMDIR over a
    # dedicated ssh connection. The remote command runs in a session of
    # its own whose id is in /run/dra-trace/TAG.pid, so that
    # dra-trace-stop can kill it in the VM, not only the ssh client.
    local vmdir="$1" tag="$2" mode="$3" cmd="$4" inner remote
    inner="echo \$\$ > /run/dra-trace/$tag.pid; export KUBECONFIG=/root/.kube/config; $cmd"
    remote="mkdir -p /run/dra-trace && exec setsid -w bash -c $(printf %q "$inner")"
    # Quoted twice: once for "bash -c" on the host, once for the shell
    # that sshd runs in the VM.
    dra-trace-collect "$tag" "$mode" "ssh -n -F $(printf %q "$vmdir/.ssh-config") -o ControlMaster=no -o ControlPath=none node sudo bash -lc $(printf %q "$(printf %q "$remote")")"
}

dra-trace-write-stamper() {
    # Usage: dra-trace-write-stamper FILE
    cat > "$1" <<'EOF'
#!/usr/bin/env python3
"""Stamp lines with the host time of their arrival (dra-trace-start).

Usage: stamp.py TAG lines|claims

lines:  print "<epoch seconds.micro> TAG <line>" for every input line.
claims: read the JSON stream of
        "kubectl get resourceclaims -w --output-watch-events -o json"
        and print one line per change of a claim: event, name,
        allocated devices, node, reserving pods, device conditions.
"""
import json
import sys
import time

tag, mode = sys.argv[1], sys.argv[2]


def emit(text):
    sys.stdout.write("%.6f %s %s\n" % (time.time(), tag, text))
    sys.stdout.flush()


def claim_line(obj):
    o = obj.get("object", obj)
    md = o.get("metadata") or {}
    st = o.get("status") or {}
    alloc = st.get("allocation") or {}
    res = (alloc.get("devices") or {}).get("results") or []
    devs = ",".join("%s/%s/%s" % (r.get("driver"), r.get("pool"), r.get("device")) for r in res) or "-"
    node = "-"
    for term in (alloc.get("nodeSelector") or {}).get("nodeSelectorTerms") or []:
        for f in term.get("matchFields") or []:
            node = ",".join(f.get("values") or []) or node
    reserved = ",".join(r.get("name", "?") for r in st.get("reservedFor") or []) or "-"
    conds = []
    for d in st.get("devices") or []:
        for c in d.get("conditions") or []:
            conds.append("%s:%s=%s" % (d.get("device"), c.get("type"), c.get("status")))
        data = d.get("data") or {}
        if "serial" in data:
            conds.append("%s:serial=%s" % (d.get("device"), data["serial"]))
    text = "claim %s/%s uid=%s allocated=%s node=%s reservedFor=%s status=%s" % (
        md.get("namespace"), md.get("name"), (md.get("uid") or "")[:8],
        devs, node, reserved, ",".join(conds) or "-")
    if md.get("deletionTimestamp"):
        text += " deleting"
    return "%s/%s" % (md.get("namespace"), md.get("name")), obj.get("type", "?"), text


def lines():
    for raw in iter(sys.stdin.buffer.readline, b""):
        emit(raw.decode(errors="replace").rstrip("\r\n"))


def claims():
    decoder = json.JSONDecoder()
    buf = ""
    last = {}
    for raw in iter(sys.stdin.buffer.readline, b""):
        line = raw.decode(errors="replace")
        buf += line
        # kubectl prints one event per line (--output-watch-events) or
        # indented objects: try to decode whenever a line ends an object.
        if not line.rstrip().endswith("}"):
            continue
        while True:
            s = buf.lstrip()
            try:
                obj, end = decoder.raw_decode(s)
            except ValueError:
                buf = s
                break
            buf = s[end:]
            key, event, text = claim_line(obj)
            if event == "MODIFIED" and last.get(key) == text:
                continue
            last[key] = text
            if event == "DELETED":
                last.pop(key, None)
            emit("%s %s" % (event, text))
        if len(buf) > (1 << 24):
            emit("unparsable watch output: %s" % buf[:200].replace("\n", " "))
            buf = ""


{"lines": lines, "claims": claims}[mode]()
EOF
}

dra-trace-stop() { # script API
    # Usage: dra-trace-stop
    #
    # Stop the collectors of dra-trace-start, in the VMs and on the host,
    # and merge their streams into $TEST_OUTPUT_DIR/trace.txt in the order
    # of the host clock, lines "HH:MM:SS.micro <tag> <line>". Never fails
    # the test: it runs in the EXIT trap, too.
    local vmdir pid tag i alive
    [ -n "$DRA_TRACE_RUNNING" ] || return 0
    DRA_TRACE_RUNNING=""
    for vmdir in "${DRA_TRACE_VMS[@]}"; do
        dra-vm-command-q "$vmdir" "$DRA_TRACE_KILL; rmdir /run/dra-trace 2>/dev/null"
    done
    # tail of the server log: the stamper reads to the end and exits.
    while read -r pid tag; do
        [[ "$tag" == server || "$tag" == *.server ]] && pkill -TERM -g "$pid" -x tail
    done < "$DRA_TRACE_DIR/pids"
    # With the remote commands gone, ssh exits and the stampers flush.
    for i in $(seq 10); do
        alive=0
        while read -r pid tag; do
            kill -0 "$pid" 2>/dev/null && alive=1
        done < "$DRA_TRACE_DIR/pids"
        [ "$alive" == 0 ] && break
        sleep 0.5
    done
    while read -r pid tag; do
        kill -TERM -- "-$pid" 2>/dev/null
    done < "$DRA_TRACE_DIR/pids"
    LC_ALL=C sort -s -k1,1n "$DRA_TRACE_DIR"/*.log > "$DRA_TRACE_DIR/merged.txt"
    python3 -c '
import sys, time
width = 0
rows = []
for line in open(sys.argv[1], errors="replace"):
    parts = line.rstrip("\n").split(" ", 2)
    if len(parts) < 2:
        continue
    t, tag, text = float(parts[0]), parts[1], parts[2] if len(parts) > 2 else ""
    rows.append((t, tag, text))
    width = max(width, len(tag))
with open(sys.argv[2], "w") as out:
    for t, tag, text in rows:
        out.write("%s.%06d %-*s  %s\n" % (time.strftime("%H:%M:%S", time.localtime(t)), int(t % 1 * 1e6), width, tag, text))
' "$DRA_TRACE_DIR/merged.txt" "$TEST_OUTPUT_DIR/trace.txt"
    echo "dra-trace-stop: $(wc -l < "$TEST_OUTPUT_DIR/trace.txt") lines in $TEST_OUTPUT_DIR/trace.txt"
    return 0
}

dra-trace-summary() { # script API
    # Usage: dra-trace-summary
    #
    # Pick the lines that tell the story from the trace of dra-trace-stop:
    # claims created, allocated and deleted, binding conditions, attach and
    # detach in the server and the controller, prepare and release in the
    # node plugin (pool devices, and regions and slices of local devices),
    # udev events of the devices, pods starting and stopping.
    # Write them to $TEST_OUTPUT_DIR/trace-summary.txt and print it.
    [ -f "$DRA_TRACE_DIR/merged.txt" ] || error "dra-trace-summary: no trace, run dra-trace-start and dra-trace-stop first"
    python3 -c '
import re, sys, time

merged, out_path, ns, test, vms = sys.argv[1:6]
patterns = {
    # fake-cxl-pool-server on the host: attachments and qemu hotplug events.
    "server": r"attachment \S+: (attaching|attached|detaching|detached|failed)|event DEVICE_DELETED|device \S+: (created|deleted)",
    # fake-cxl-pool-controller: what it attached, detached and wrote.
    "controller": r"(?i)attach|detach|condition|status|publish|slice|error|fail",
    # nri-dra-driver-cxl: the pool driver (prepared, released, unprepared),
    # pool devices skipped by the cxl.nri.io publisher, the lease broker
    # (leases, companions, lends and revokes, fds sent), the local
    # allocator (regions and slices of local memdevs) and the memdev
    # devices it publishes, errors.
    "driver": r"(?i)cxl-pool\.nri\.io|pool device|rescanAndPublish|lease|companion|\blend|revok|local:|memdev-|no room for the slice|error|fail",
    "scheduler": r"(?i)binding|resourceclaim|claim|bound|error",
    "events": r"",
    "claims": r"",
    "pods": r"",
    "udev": r"^KERNEL\[",
    "kubelet": r"(?i)prepar|resourceclaim|error|fail",
}
# Lines that match but tell nothing: the cxl.nri.io publisher reports
# nodeAllocatableResources dropped by the apiserver on every publish
# (DRANodeAllocatableResources is off, D32), the controller logs every
# server event, the udev watcher logs every rescan trigger.
noise = {
    "driver": r"some fields were dropped by the apiserver|udev event triggered rescan|^cxl region: (decoder_region_action|region_action|cmd_disable_region)",
    "controller": r"server event ",
}
rows = []
for line in open(merged, errors="replace"):
    parts = line.rstrip("\n").split(" ", 2)
    if len(parts) < 3:
        continue
    t, tag, text = float(parts[0]), parts[1], parts[2]
    kind = tag.split(".")[-1]
    pattern = patterns.get(kind)
    if pattern is None or not re.search(pattern, text):
        continue
    if kind in noise and re.search(noise[kind], text):
        continue
    words = text.split()
    if kind == "events" and words and words[0] == "kube-system":
        continue
    if kind == "pods" and (len(words) < 2 or words[1] != ns):
        continue
    if kind == "udev" and not re.search(r"\((cxl|dax|node|memory)\)$", text):
        continue
    if kind == "server" and " GET " in text:
        continue
    rows.append((t, tag, text))
width = max([len(r[1]) for r in rows] + [3])
with open(out_path, "w") as out:
    out.write("# What every component did in %s, in order.\n" % test)
    out.write("# Times are host clock receipt times: the host stamped each line when it\n")
    out.write("# arrived. Lines from the VMs come over ssh, which adds a few ms; there is\n")
    out.write("# no VM clock skew. +s is seconds since the first line below.\n")
    out.write("# Tags: server = fake-cxl-pool-server on the host (<name>.server: the pool\n")
    out.write("# server <name> of several); <vm>.controller = the fake-cxl-pool-controllers,\n")
    out.write("# <vm>.driver = nri-dra-driver-cxl, <vm>.scheduler,\n")
    out.write("# <vm>.kubelet, <vm>.events, <vm>.claims (ResourceClaim changes), <vm>.pods,\n")
    out.write("# <vm>.udev (kernel uevents) of the VMs: %s.\n" % vms)
    out.write("# cxl-lease-<id> are the companion pods and claims of leases.\n")
    out.write("# The full trace is trace.txt.\n")
    t0 = rows[0][0] if rows else 0
    for t, tag, text in rows:
        out.write("%s.%06d %+9.3fs %-*s  %s\n" % (time.strftime("%H:%M:%S", time.localtime(t)), int(t % 1 * 1e6), t - t0, width, tag, text))
' "$DRA_TRACE_DIR/merged.txt" "$TEST_OUTPUT_DIR/trace-summary.txt" "$DRA_NS" "$(basename "${TEST_DIR:-test}")" \
        "$(for vmdir in "${DRA_TRACE_VMS[@]}"; do printf '%s = %s ' "$(dra-vm-label "$vmdir")" "$(dra-vm-name "$vmdir")"; done)" ||
        error "dra-trace-summary: cannot summarize $DRA_TRACE_DIR/merged.txt"
    echo "### trace summary ($TEST_OUTPUT_DIR/trace-summary.txt)"
    cat "$TEST_OUTPUT_DIR/trace-summary.txt"
}
