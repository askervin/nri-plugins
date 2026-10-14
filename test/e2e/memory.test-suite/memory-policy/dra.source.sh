# Helpers for testing CXL memory pooling and sharing with Dynamic Resource
# Allocation (DRA): kubelet-cxl-plugin (the node plugin of the CXL DRA
# driver, drivers cxl.generic and cxl-pool.generic) and
# fake-cxl-pool-controller (the pool controller of fake-cxl-pool, see
# scripts/testing/fake-cxl-pool) run in the VMs as transient systemd units,
# fake-cxl-pool-server runs on the host (pool.source.sh).
#
# The contract between the controller and the node plugin is
# scripts/testing/fake-cxl-pool/plan-2-dra/10-contract.md (doc/cxl/POOL.md in
# the driver repository).
#
# This file is sourced for every topology of memory-policy, so it only
# defines functions and variables. The helpers take VMDIR, the output
# directory of a VM, first, like those of pool.source.sh: $OUTPUT_DIR for
# the VM of the test. Other VMs work where pool.source.sh is sourced too
# (n4-cxl-shared-2: $POOL_VM1_DIR).
#
# Typical use:
#   pool-server-start "DEVICES"   # first: dra-install chains its EXIT trap
#   dra-build
#   dra-install "$VM"
#   dra-trace-start "$VM"
#   dra-apply "$VM" <<EOF ... EOF
#   dra-wait "$VM" LABEL "resourceclaim -n $DRA_NS NAME" "condition('cxl-pool.generic/Attached') == 'True'"
#   dra-trace-stop; dra-trace-summary

DRA_DRIVER_SRC="${CXL_DRA_DRIVER_SRC:-$HOME/github.com/intel/intel-resource-drivers-for-kubernetes}"
DRA_DRIVER_BIN="$DRA_DRIVER_SRC/bin/kubelet-cxl-plugin"
DRA_DEVICE_CLASSES="$DRA_DRIVER_SRC/deployments/cxl/pool/device-classes.yaml"
# Lending pool memory to running containers (plan-3-cxl-live-attach): the
# CLI that the node plugin mounts into containers that claim the token
# device "dynamic" (DeviceClass cxl-dynamic), and the directory of the
# per-claim lease sockets in the VM. Both are optional: dra-build and
# dra-install skip them when the driver sources do not have them.
DRA_REQUEST_BIN="$DRA_DRIVER_SRC/bin/cxl-request"
DRA_REQUEST_VM_BIN=/usr/local/bin/cxl-request
DRA_DYNAMIC_CLASS="$DRA_DRIVER_SRC/deployments/cxl/pool/device-class-dynamic.yaml"
DRA_LEASE_DIR=/var/lib/kubelet/plugins/cxl.generic/leases
# Node-local CXL memory devices that the node plugin publishes whole and
# partitions on demand (cxl.generic devices cxlmem-<serial>, doc/cxl/LOCAL.md
# in the driver repository): the DeviceClasses cxl-local-memory and
# cxl-local-dax, optional like the dynamic class, and the state file of the
# regions and slices that the node plugin created.
DRA_LOCAL_CLASSES="$DRA_DRIVER_SRC/deployments/cxl/local/device-classes.yaml"
DRA_LOCAL_STATE=/var/lib/kubelet/plugins/cxl.generic/localDevices.json
DRA_CONTROLLER_BIN="$nri_resource_policy_src/scripts/testing/fake-cxl-pool/bin/fake-cxl-pool-controller"
DRA_POOL_DRIVER=cxl-pool.generic   # pool devices, published by the controller
DRA_LOCAL_DRIVER=cxl.generic       # node-local CXL and DRAM, published by the node plugin
DRA_NS=cxl-pool-demo               # namespace of the test objects
DRA_INSTALLED_VMS=()               # VMDIRs where dra-install started the components
declare -A DRA_NODE_ONLY=()        # VMDIR -> 1: dra-install-node, a worker of a cluster
DRA_HELPER_DIR="$(dirname "${BASH_SOURCE[0]}")"
DRA_DAX_TOOL="$DRA_HELPER_DIR/n4-cxl-shared-2/pool-dax-rw.py"
DRA_NUMA_TOOL="$DRA_HELPER_DIR/n4-cxl-shared-2/numa-touch.py"
DRA_JSON=""                        # JSON of the last dra-json/dra-wait
DRA_LOCAL_NAME=""                  # dra-local-device: the device in fake-cxl-pool-server,
DRA_LOCAL_SERIAL=""                # its serial (0x<lower-case hex>),
DRA_LOCAL_HEX=""                   # the serial in environment variable names (upper-case hex),
DRA_LOCAL_SIZE=""                  # its size in bytes,
DRA_LOCAL_DEVICE=""                # its device in the cxl.generic ResourceSlice (cxlmem-<hex>),
DRA_LOCAL_BLOCK_SIZE=""            # the memory block size of the VM in bytes,
DRA_LOCAL_LD=""                    # dra-py expression of its ResourceSlice device,
DRA_LOCAL_REGIONS=""               # cxl-py expression of its regions in cxl-dump,
DRA_LOCAL_ATTACHMENT=""            # and the state of its attachment to the VM
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
    #                    prefers one NUMA node, report where the pages are
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
    # Build kubelet-cxl-plugin in $DRA_DRIVER_SRC (CXL_DRA_DRIVER_SRC, by
    # default ~/github.com/intel/intel-resource-drivers-for-kubernetes;
    # "go mod vendor" first: vendor/ is not in git there, and go.mod may
    # replace nri-plugins with this checkout) and
    # fake-cxl-pool (server, client and controller) on the host. Both are
    # static amd64 binaries that dra-install copies to the VMs. Build also
    # the lease CLI cxl-request when the driver sources have cmd/cxl-request.
    [ -d "$DRA_DRIVER_SRC/cmd/kubelet-cxl-plugin" ] ||
        error "dra-build: no kubelet-cxl-plugin sources in $DRA_DRIVER_SRC. Clone https://github.com/intel/intel-resource-drivers-for-kubernetes there (a branch with the cxl-pool.generic helper), or point CXL_DRA_DRIVER_SRC to a clone"
    host-command "cd \"$DRA_DRIVER_SRC\" && go mod vendor && CGO_ENABLED=0 GOARCH=amd64 go build -mod vendor -o bin/kubelet-cxl-plugin ./cmd/kubelet-cxl-plugin" ||
        command-error "cannot build kubelet-cxl-plugin in $DRA_DRIVER_SRC"
    if [ -d "$DRA_DRIVER_SRC/cmd/cxl-request" ]; then
        host-command "cd \"$DRA_DRIVER_SRC\" && CGO_ENABLED=0 GOARCH=amd64 go build -mod vendor -o bin/cxl-request ./cmd/cxl-request" ||
            command-error "cannot build cxl-request in $DRA_DRIVER_SRC"
    fi
    host-command "make -C \"$nri_resource_policy_src/scripts/testing/fake-cxl-pool\"" ||
        command-error "cannot build fake-cxl-pool"
    [ -x "$DRA_CONTROLLER_BIN" ] ||
        error "dra-build: make did not build $DRA_CONTROLLER_BIN"
}

dra-install() { # script API
    # Usage: dra-install VMDIR
    #
    # Run kubelet-cxl-plugin and fake-cxl-pool-controller in the VM of
    # VMDIR as transient systemd units of the same names, with the admin
    # kubeconfig of the VM. Apply the DeviceClasses of the driver
    # (cxl-pool-memory, cxl-shared-memory, and cxl-dynamic, cxl-local-memory
    # and cxl-local-dax if the driver has them). If dra-build built
    # cxl-request, install it as
    # $DRA_REQUEST_VM_BIN and tell the node plugin (--cxl-request-bin) to
    # mount it into the containers of lease claims. Create namespace $DRA_NS
    # empty (delete objects that an earlier run left). Wait until the
    # cluster has the pool ResourceSlice of the controller, the node's
    # cxl.generic ResourceSlice and the kubelet plugin socket of
    # cxl-pool.generic.
    #
    # Call pool-server-start first: the controller needs the server, and
    # dra-install chains its EXIT trap: dra-cleanup, then pool-cleanup.
    local vmdir="$1" name label url
    name=$(dra-vm-name "$vmdir")
    label=$(dra-vm-label "$vmdir")
    [ -x "$DRA_CONTROLLER_BIN" ] || error "dra-install: no $DRA_CONTROLLER_BIN, run dra-build first"
    [ -f "$DRA_DEVICE_CLASSES" ] || error "dra-install: no DeviceClasses $DRA_DEVICE_CLASSES in the driver sources"
    url="${POOL_GUEST_URL:-http://192.168.76.2:${FAKE_CXL_POOL_PORT:-9909}}"

    dra-install-files "$vmdir"
    dra-vm-put-file "$vmdir" "$DRA_CONTROLLER_BIN" /usr/local/bin/fake-cxl-pool-controller
    dra-vm-put-file "$vmdir" "$DRA_DEVICE_CLASSES" /root/cxl-pool-device-classes.yaml
    dra-vm-command "$vmdir" "chmod 755 /usr/local/bin/fake-cxl-pool-controller" ||
        command-error "cannot install fake-cxl-pool-controller in $label"
    if [ -f "$DRA_DYNAMIC_CLASS" ]; then
        dra-vm-put-file "$vmdir" "$DRA_DYNAMIC_CLASS" /root/cxl-dynamic-device-class.yaml
    else
        dra-vm-command "$vmdir" "rm -f /root/cxl-dynamic-device-class.yaml"
    fi
    if [ -f "$DRA_LOCAL_CLASSES" ]; then
        dra-vm-put-file "$vmdir" "$DRA_LOCAL_CLASSES" /root/cxl-local-device-classes.yaml
    else
        dra-vm-command "$vmdir" "rm -f /root/cxl-local-device-classes.yaml"
    fi

    echo "dra-install $label: starting kubelet-cxl-plugin and fake-cxl-pool-controller"
    dra-start-plugin "$vmdir"
    dra-vm-command "$vmdir" "systemd-run --unit fake-cxl-pool-controller --property=Restart=no -E KUBECONFIG=/root/.kube/config /usr/local/bin/fake-cxl-pool-controller -server $url -v" ||
        command-error "cannot start fake-cxl-pool-controller in $label"
    dra-installed-add "$vmdir" ""
    dra-vm-command "$vmdir" "kubectl apply -f /root/cxl-pool-device-classes.yaml && for f in /root/cxl-dynamic-device-class.yaml /root/cxl-local-device-classes.yaml; do if [ -f \$f ]; then kubectl apply -f \$f || exit 1; fi; done" ||
        command-error "cannot create the DeviceClasses in $label"

    dra-wait-node "$vmdir"

    dra-vm-command "$vmdir" "kubectl delete pods --all -n $DRA_NS --grace-period=2 --ignore-not-found --wait=true --timeout=60s 2>&1 | grep -v 'No resources found'; kubectl delete namespace $DRA_NS --ignore-not-found --wait=true --timeout=120s && kubectl create namespace $DRA_NS" ||
        command-error "cannot create namespace $DRA_NS in $label"
}

dra-install-node() { # script API
    # Usage: dra-install-node VMDIR
    #
    # Run only kubelet-cxl-plugin in the VM of VMDIR, a worker node of the
    # cluster of a VM where dra-install runs: one pool controller and one
    # set of DeviceClasses per cluster, a node plugin on every node. Call
    # dra-install on the control plane first. Wait until the cluster has
    # the cxl.generic ResourceSlice of the node and the node has the
    # kubelet plugin socket of cxl-pool.generic. dra-cleanup stops it.
    local vmdir="$1" label
    label=$(dra-vm-label "$vmdir")
    dra-install-files "$vmdir"
    echo "dra-install-node $label: starting kubelet-cxl-plugin"
    dra-start-plugin "$vmdir"
    dra-installed-add "$vmdir" 1
    dra-wait-node "$vmdir"
}

dra-install-files() {
    # Usage: dra-install-files VMDIR
    #
    # Stop the DRA components of an earlier run in the VM of VMDIR, install
    # kubelet-cxl-plugin, its configuration and cxl-request (if dra-build
    # built it), and remove node plugin state left by an earlier VM boot.
    local vmdir="$1" label
    label=$(dra-vm-label "$vmdir")
    [ -x "$DRA_DRIVER_BIN" ] || error "dra-install: no $DRA_DRIVER_BIN, run dra-build first"
    echo "dra-install $label: stopping components of an earlier run, if any"
    dra-vm-command "$vmdir" "for u in kubelet-cxl-plugin fake-cxl-pool-controller; do systemctl stop \$u 2>/dev/null; systemctl reset-failed \$u 2>/dev/null; done; true"
    dra-vm-put-file "$vmdir" "$DRA_DRIVER_BIN" /usr/local/bin/kubelet-cxl-plugin
    dra-vm-command "$vmdir" "chmod 755 /usr/local/bin/kubelet-cxl-plugin && echo '{}' > /etc/kubelet-cxl-plugin.yaml" ||
        command-error "cannot install kubelet-cxl-plugin in $label"
    dra-vm-command "$vmdir" "rm -f $DRA_REQUEST_VM_BIN"
    if [ -x "$DRA_REQUEST_BIN" ]; then
        dra-vm-put-file "$vmdir" "$DRA_REQUEST_BIN" "$DRA_REQUEST_VM_BIN"
        dra-vm-command "$vmdir" "chmod 755 $DRA_REQUEST_VM_BIN" ||
            command-error "cannot install cxl-request in $label"
    fi
    dra-state-cleanup "$vmdir"
}

dra-state-cleanup() {
    # Usage: dra-state-cleanup VMDIR
    #
    # Remove the state of the node plugin in the VM of VMDIR that refers to
    # CXL regions, if the VM has no regions: then it is a leftover of an
    # earlier VM boot. That is the prepared pool claims
    # (preparedPoolClaims.json), the regions and slices of local devices
    # (localDevices.json), the leases (leases.json) and the lease sockets of
    # token claims (leases/).
    dra-vm-command "$1" "if ls /sys/bus/cxl/devices/ | grep -q '^region[0-9]'; then echo 'CXL regions exist, keeping the CXL state of the node plugin'; else rm -fv /var/lib/kubelet/plugins/$DRA_POOL_DRIVER/preparedPoolClaims.json $DRA_LOCAL_STATE /var/lib/kubelet/plugins/$DRA_LOCAL_DRIVER/leases.json; rm -rfv /var/lib/kubelet/plugins/$DRA_LOCAL_DRIVER/leases; fi"
}

dra-start-plugin() {
    # Usage: dra-start-plugin VMDIR
    #
    # Start kubelet-cxl-plugin in the VM of VMDIR as a transient systemd
    # unit, with the admin kubeconfig of the VM and, if cxl-request is
    # installed, the flag that mounts it into the containers of lease
    # claims.
    local vmdir="$1" name request_flag=""
    name=$(dra-vm-name "$vmdir")
    [ ! -x "$DRA_REQUEST_BIN" ] || request_flag=" --cxl-request-bin $DRA_REQUEST_VM_BIN"
    dra-vm-command "$vmdir" "systemd-run --unit kubelet-cxl-plugin --property=Restart=no -E NODE_NAME=$name -E KUBECONFIG=/root/.kube/config /usr/local/bin/kubelet-cxl-plugin --node-name $name -f /etc/kubelet-cxl-plugin.yaml$request_flag -v 4" ||
        command-error "cannot start kubelet-cxl-plugin in $(dra-vm-label "$vmdir")"
}

dra-installed-add() {
    # Usage: dra-installed-add VMDIR NODE-ONLY
    #
    # Record that DRA components run in the VM of VMDIR (NODE-ONLY 1: only
    # the node plugin), for dra-cleanup, and chain the EXIT trap:
    # dra-cleanup, then pool-cleanup.
    dra-installed-remove "$1"
    DRA_INSTALLED_VMS+=("$1")
    if [ -n "$2" ]; then
        DRA_NODE_ONLY["$1"]=1
    fi
    if type -t pool-cleanup >/dev/null; then
        trap 'dra-cleanup; pool-cleanup' EXIT
    else
        trap dra-cleanup EXIT
    fi
}

dra-wait-node() {
    # Usage: dra-wait-node VMDIR
    #
    # Wait until the cluster of the VM of VMDIR has the pool ResourceSlice
    # and the cxl.generic ResourceSlice of the node, and the node has the
    # kubelet plugin socket of cxl-pool.generic.
    local vmdir="$1" name label
    name=$(dra-vm-name "$vmdir")
    label=$(dra-vm-label "$vmdir")
    retry-until --timeout 60 --interval 2 --message "$label: ResourceSlices of $DRA_POOL_DRIVER and $DRA_LOCAL_DRIVER on $name, $DRA_POOL_DRIVER kubelet plugin socket" \
        'dra-install-ready "$vmdir" "$name"' || {
        dra-vm-command "$vmdir" "systemctl status --no-pager kubelet-cxl-plugin fake-cxl-pool-controller; journalctl --no-pager -n 40 -u kubelet-cxl-plugin; journalctl --no-pager -n 40 -u fake-cxl-pool-controller; kubectl get resourceslices; ls -l /var/lib/kubelet/plugins/*"
        error "dra-install: the DRA components did not come up in $label"
    }
    dra-vm-command "$vmdir" "kubectl get resourceslices; ls -l /var/lib/kubelet/plugins/$DRA_POOL_DRIVER/"
}

dra-install-ready() {
    # Usage: dra-install-ready VMDIR NODENAME
    local vmdir="$1" name="$2" json
    json=$(dra-vm-command-q "$vmdir" "kubectl get resourceslices -o json") || return 1
    dra-py assert "$json" "slices(\"$DRA_POOL_DRIVER\") and slices(\"$DRA_LOCAL_DRIVER\", \"$name\")" || return 1
    dra-vm-command-q "$vmdir" "test -S /var/lib/kubelet/plugins/$DRA_POOL_DRIVER/dra.sock"
}

dra-pool-attachments() {
    # Usage: dra-pool-attachments HOST
    #
    # Print the attachments of the server on HOST that a pool controller
    # owns (owner k8s:...), one "device@host owner state" per line. Print
    # nothing if there is no server.
    [ -n "$POOL_URL" ] || return 0
    curl -s --max-time 10 "$POOL_URL/api/v1/attachments" 2>/dev/null | python3 -c '
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
    # Usage: dra-uninstall VMDIR
    #
    # Undo dra-install in the VM of VMDIR: delete namespace $DRA_NS (its
    # pods first, gracefully: kubelet unprepares their claims, and the
    # controller detaches the devices when the claims are gone), wait until
    # the controller has detached the devices of the node, stop both
    # units, delete the pool ResourceSlices the controller left and the
    # DeviceClasses (those of local devices too, if dra-install applied
    # them). Never fails the test: it runs in the EXIT trap.
    local vmdir="$1" name label left v host
    name=$(dra-vm-name "$vmdir")
    label=$(dra-vm-label "$vmdir")
    if [ -n "${DRA_NODE_ONLY[$vmdir]}" ]; then
        # A worker: the dra-uninstall of its control plane deleted the
        # objects and waited for the detach of its devices.
        echo "dra-uninstall $label (node plugin only)"
        dra-vm-command "$vmdir" "systemctl stop kubelet-cxl-plugin 2>/dev/null; systemctl reset-failed kubelet-cxl-plugin 2>/dev/null; true"
        dra-state-cleanup "$vmdir"
        dra-installed-remove "$vmdir"
        return 0
    fi
    echo "dra-uninstall $label"
    dra-vm-command "$vmdir" "kubectl delete pods --all -n $DRA_NS --grace-period=2 --ignore-not-found --wait=true --timeout=60s 2>&1 | grep -v 'No resources found'; kubectl delete namespace $DRA_NS --ignore-not-found --wait=true --timeout=120s"
    retry-until --timeout 60 --interval 2 --message "$label: no ResourceClaims in $DRA_NS" \
        '[ -z "$(dra-vm-command-q "$vmdir" "kubectl get resourceclaims -n $DRA_NS -o name 2>/dev/null")" ]' ||
        echo "dra-uninstall $label: ResourceClaims remain in $DRA_NS"
    # The controller of this cluster detaches the devices of every node of
    # it: this one and the workers where dra-install-node runs.
    for v in "$vmdir" "${DRA_INSTALLED_VMS[@]}"; do
        [ "$v" == "$vmdir" ] || [ -n "${DRA_NODE_ONLY[$v]}" ] || continue
        host=$(dra-vm-name "$v")
        if [ -n "$(dra-pool-attachments "$host")" ]; then
            retry-until --timeout 60 --interval 2 --message "$label: the controller detaches the pool devices of $host" \
                '[ -z "$(dra-pool-attachments "$host")" ]' || {
                echo "dra-uninstall $label: attachments left, pool-cleanup releases and detaches them:"
                dra-pool-attachments "$host"
            }
        fi
    done
    dra-vm-command "$vmdir" "for u in kubelet-cxl-plugin fake-cxl-pool-controller; do systemctl stop \$u 2>/dev/null; systemctl reset-failed \$u 2>/dev/null; done; true"
    left=$(dra-vm-command-q "$vmdir" "kubectl get resourceslices -o jsonpath='{range .items[?(@.spec.driver==\"$DRA_POOL_DRIVER\")]}{.metadata.name}{\"\\n\"}{end}'")
    if [ -n "$left" ]; then
        dra-vm-command "$vmdir" "kubectl delete resourceslices $(tr "\n" " " <<< "$left")"
    fi
    dra-vm-command "$vmdir" "kubectl delete --ignore-not-found -f /root/cxl-pool-device-classes.yaml 2>/dev/null || kubectl delete deviceclass --ignore-not-found cxl-pool-memory cxl-shared-memory; kubectl delete deviceclass --ignore-not-found cxl-dynamic cxl-local-memory cxl-local-dax; if [ -f /root/cxl-local-device-classes.yaml ]; then kubectl delete --ignore-not-found -f /root/cxl-local-device-classes.yaml; fi"
    dra-state-cleanup "$vmdir"
    dra-installed-remove "$vmdir"
    return 0
}

dra-installed-remove() {
    # Usage: dra-installed-remove VMDIR
    local v keep=()
    for v in "${DRA_INSTALLED_VMS[@]}"; do
        [ "$v" == "$1" ] || keep+=("$v")
    done
    DRA_INSTALLED_VMS=("${keep[@]}")
    unset "DRA_NODE_ONLY[$1]"
}

dra-cleanup() {
    # Usage: dra-cleanup
    #
    # The EXIT trap of dra-install (before pool-cleanup): dra-uninstall in
    # every VM where dra-install ran, then stop the trace if it runs.
    # Report CXL memory devices that are still in the VMs: pool-cleanup,
    # which runs next, releases and detaches them.
    local vmdir vms memdevs
    vms=("${DRA_INSTALLED_VMS[@]}")
    # Control planes first: they delete the objects of the whole cluster
    # and wait for the detach of the devices of all its nodes, while the
    # node plugins of the workers still run.
    for vmdir in "${vms[@]}"; do
        [ -n "${DRA_NODE_ONLY[$vmdir]}" ] || dra-uninstall "$vmdir"
    done
    for vmdir in "${vms[@]}"; do
        [ -z "${DRA_NODE_ONLY[$vmdir]}" ] || dra-uninstall "$vmdir"
    done
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
    # Usage: dra-local-find VMDIR
    #
    # Set DRA_LOCAL_NAME, DRA_LOCAL_SERIAL, DRA_LOCAL_HEX, DRA_LOCAL_SIZE,
    # DRA_LOCAL_DEVICE and DRA_LOCAL_ATTACHMENT (attached, detached, or
    # another attachment state) of the local CXL memory device of the VM of
    # VMDIR in fake-cxl-pool-server: the device of scope local that is
    # bound to this VM only and is not shared (a memory-backend-ram device
    # of the topology). Fail the test unless there is exactly one.
    local host found
    type -t pool-host-client >/dev/null ||
        error "${FUNCNAME[1]}: needs pool.source.sh and fake-cxl-pool-server (pool-server-start)"
    host=$(dra-vm-name "$1")
    pool-host-client -o json devices || command-error "cannot list the devices of fake-cxl-pool-server"
    found=$(pool-value "$COMMAND_OUTPUT" "chr(10).join(' '.join([d['name'], d['serial'], str(d['size']), next((a['state'] for a in d.get('attachments') or [] if a['host'] == '$host'), 'detached')]) for d in j if d.get('scope') == 'local' and not d.get('shared') and (d.get('localHosts') or [d.get('localHost')]) == ['$host'])")
    [ -n "$found" ] && [ "$(wc -l <<< "$found")" == 1 ] ||
        error "${FUNCNAME[1]}: expected one local, not shared device of $host in fake-cxl-pool-server, found: '$found'"
    read -r DRA_LOCAL_NAME DRA_LOCAL_SERIAL DRA_LOCAL_SIZE DRA_LOCAL_ATTACHMENT <<< "$found"
    DRA_LOCAL_HEX=${DRA_LOCAL_SERIAL#0x}
    DRA_LOCAL_DEVICE="cxlmem-${DRA_LOCAL_HEX,,}"
    DRA_LOCAL_HEX=${DRA_LOCAL_HEX^^}
}

dra-local-device() { # script API
    # Usage: dra-local-device VMDIR
    #
    # Attach the local CXL memory device of the VM of VMDIR (see
    # dra-local-find) through fake-cxl-pool-server, unless it is attached,
    # and wait until pkg/cxl sees it in the VM. If dra-install runs in the
    # VM, wait also until the node's cxl.generic ResourceSlice has its
    # device. Print and set DRA_LOCAL_NAME (the device in the server),
    # DRA_LOCAL_SERIAL (0x<lower-case hex>), DRA_LOCAL_HEX (the serial in
    # environment variable names, upper-case hex), DRA_LOCAL_SIZE (bytes),
    # DRA_LOCAL_DEVICE (cxlmem-<lower-case hex>, its device in the
    # ResourceSlice), DRA_LOCAL_BLOCK_SIZE (the memory block size of the
    # VM in bytes, see dra-block-size), DRA_LOCAL_LD (its device in the
    # ResourceSlices of dra-py) and DRA_LOCAL_REGIONS (its regions in
    # cxl-dump of cxl-py). The attachment has the owner
    # e2e:dra-local-device, not a k8s: owner of the pool controller.
    local vmdir="$1" host label v installed=""
    host=$(dra-vm-name "$vmdir")
    label=$(dra-vm-label "$vmdir")
    dra-local-find "$vmdir"
    case "$DRA_LOCAL_ATTACHMENT" in
        attached)
            echo "dra-local-device $label: $DRA_LOCAL_NAME is attached already";;
        detached)
            pool-host-client -o json attach "$DRA_LOCAL_NAME" --host "$host" --owner e2e:dra-local-device ||
                command-error "cannot attach the local device $DRA_LOCAL_NAME to $label";;
        *)
            error "dra-local-device: the attachment of $DRA_LOCAL_NAME to $host is $DRA_LOCAL_ATTACHMENT";;
    esac
    pool-cxl-wait "$vmdir" local-device "by_serial($DRA_LOCAL_SERIAL) is not None" 60
    for v in "${DRA_INSTALLED_VMS[@]}"; do
        [ "$v" != "$vmdir" ] || installed=1
    done
    if [ -n "$installed" ]; then
        dra-wait "$vmdir" local-device resourceslices "device('$DRA_LOCAL_DEVICE', '$DRA_LOCAL_DRIVER', '$host') is not None" 60
    fi
    DRA_LOCAL_BLOCK_SIZE=$(dra-block-size "$vmdir") ||
        error "dra-local-device: cannot read the memory block size of $label"
    DRA_LOCAL_LD="device('$DRA_LOCAL_DEVICE', '$DRA_LOCAL_DRIVER', '$host')"
    DRA_LOCAL_REGIONS="[r for r in regions if by_serial($DRA_LOCAL_SERIAL) is not None and names(r['Memories']) == [by_serial($DRA_LOCAL_SERIAL)['Name']]]"
    echo "dra-local-device $label: $DRA_LOCAL_NAME, serial $DRA_LOCAL_SERIAL ($DRA_LOCAL_HEX), $DRA_LOCAL_SIZE bytes, ResourceSlice device $DRA_LOCAL_DEVICE, memory block size $DRA_LOCAL_BLOCK_SIZE bytes"
}

dra-local-detach() { # script API
    # Usage: dra-local-detach VMDIR
    #
    # Detach the local CXL memory device of the VM of VMDIR (see
    # dra-local-device) if it is attached, and wait until pkg/cxl does not
    # see it any more. While the node plugin runs, wait first until it has
    # released the regions of the device. Then release what is left of it
    # in the VM (fake-cxl-pool-client guest release: offline, destroy the
    # regions, disable the memdev) and detach it through
    # fake-cxl-pool-server.
    local vmdir="$1" host label expr
    host=$(dra-vm-name "$vmdir")
    label=$(dra-vm-label "$vmdir")
    dra-local-find "$vmdir"
    if [ "$DRA_LOCAL_ATTACHMENT" == detached ]; then
        echo "dra-local-detach $label: $DRA_LOCAL_NAME is not attached"
        return 0
    fi
    expr="by_serial($DRA_LOCAL_SERIAL) is None or not any(by_serial($DRA_LOCAL_SERIAL)['Name'] in names(r['Memories']) for r in regions)"
    if dra-vm-command-q "$vmdir" "systemctl is-active -q kubelet-cxl-plugin"; then
        pool-cxl-wait "$vmdir" local-released "$expr" 60
    fi
    pool-client "$vmdir" guest release "$DRA_LOCAL_SERIAL" ||
        command-error "cannot release $DRA_LOCAL_NAME in $label"
    pool-host-client detach "$DRA_LOCAL_NAME" --host "$host" ||
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
  qemu_bin=\$HOME/github.com/qemu/qemu/build/qemu-system-x86_64 ./run_tests.sh memory.test-suite/memory-policy/$topology/test00-up"
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

dra-local-mode-wait() { # script API
    # Usage: dra-local-mode-wait VMDIR LABEL MODE
    #
    # Wait until the attribute mode of the local device of the VM of VMDIR
    # (see dra-local-device) in its ResourceSlice is MODE. COMMAND_OUTPUT
    # has the ResourceSlices.
    dra-wait "$1" "$2" resourceslices "attr($DRA_LOCAL_LD, 'mode') == '$3'" 60
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

dra-local-cdi-devices() {
    # Usage: dra-local-cdi-devices VMDIR
    #
    # Print the CDI devices of dax slices of local devices (local-<claim
    # uid>) in the CDI spec directories of the VM of VMDIR, quietly.
    dra-vm-command-q "$1" "cat /etc/cdi/* /var/run/cdi/* 2>/dev/null | grep -oE 'name\"?: *\"?local-[0-9a-f-]+' | sed 's/.*local-/local-/' | sort -u"
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
    # is in its initial state again: the memdev enabled, no region, mode
    # none in the ResourceSlice, and no memory on its NUMA node NODE (if
    # given). Check that nothing of its claims is left: no CDI devices of
    # slices, no claims in the state of the node plugin, which must have
    # its state file.
    local vmdir="$1" label="$2" node="$3"
    pool-cxl-wait "$vmdir" "$label" "by_serial($DRA_LOCAL_SERIAL) is not None and by_serial($DRA_LOCAL_SERIAL)['Enabled'] and $DRA_LOCAL_REGIONS == []" 60
    dra-memdev-wait "$vmdir" "$label" "$DRA_LOCAL_SERIAL" "j['memdev'] and j['enabled'] and j['regions'] == []" 10
    dra-local-mode-wait "$vmdir" "$label-mode" none
    [ -z "$(dra-local-cdi-devices "$vmdir")" ] ||
        error "$label: CDI devices of local slices are left: $(dra-local-cdi-devices "$vmdir")"
    dra-vm-command-q "$vmdir" "test -s $DRA_LOCAL_STATE" ||
        error "$label: the node plugin has no $DRA_LOCAL_STATE"
    [ "$(dra-local-state-claims "$vmdir")" == 0 ] ||
        error "$label: the node plugin still has claims in $DRA_LOCAL_STATE"
    [ -z "$node" ] || dra-node-wait "$vmdir" "$node" 0 10
    echo "$label: the local device is in its initial state"
}

dra-plugin-log() { # script API
    # Usage: dra-plugin-log VMDIR
    #
    # Print the log of kubelet-cxl-plugin in the VM of VMDIR since it
    # started (the journal of its current invocation), quietly. Fail the
    # test if it does not run.
    local id
    id=$(dra-vm-command-q "$1" "systemctl show -p InvocationID --value kubelet-cxl-plugin")
    [ -n "$id" ] || error "dra-plugin-log: kubelet-cxl-plugin does not run in $(dra-vm-label "$1")"
    dra-vm-command-q "$1" "journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID=$id"
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
    echo "### regions and slices of local devices, times from the log of kubelet-cxl-plugin"
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

dra-claim-yaml() { # script API
    # Usage: dra-claim-yaml claim|template NAME CLASS SIZE [read-only [MODE]]
    #
    # Print a ResourceClaim (claim) or a ResourceClaimTemplate (template)
    # NAME with one request "mem" of DeviceClass CLASS for SIZE of memory
    # ("": no amount). With read-only the opaque LocalDeviceConfig of the
    # claim asks the node plugin for a read-only device in MODE (default
    # dax).
    local kind="$1" name="$2" class="$3" size="$4" devices
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
    if [ "$5" == read-only ]; then
        devices+="
  config:
  - opaque:
      driver: $DRA_LOCAL_DRIVER
      parameters: {apiVersion: $DRA_LOCAL_DRIVER/v1alpha1, kind: LocalDeviceConfig, mode: ${6:-dax}, readOnly: true}"
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

dra-claim-pod-yaml() { # script API
    # Usage: dra-claim-pod-yaml NAME claim|template SOURCE
    #
    # Print pod NAME whose claim "mem" is the ResourceClaim SOURCE (claim)
    # or is made from the ResourceClaimTemplate SOURCE (template): one idle
    # container "main" of $DRA_TOOLS_IMAGE that uses the claim, the tools
    # of dra-dax-tool-install in /tools, no memory limit.
    local name="$1" ref=resourceClaimName
    [ "$2" == claim ] || ref=resourceClaimTemplateName
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
spec:
  terminationGracePeriodSeconds: 2
  restartPolicy: Never
  resourceClaims:
  - name: mem
    $ref: $3
  volumes:
  - name: tools
    configMap:
      name: dax-rw
  containers:
  - name: main
    image: $DRA_TOOLS_IMAGE
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "trap 'exit 0' TERM; sleep infinity & wait"]
    volumeMounts:
    - name: tools
      mountPath: /tools
    resources:
      claims:
      - name: mem
EOF
}

dra-claim-pod() { # script API
    # Usage: dra-claim-pod VMDIR NAME CLASS SIZE [read-only [MODE]]
    #
    # Create pod NAME in the cluster of the VM of VMDIR with a claim of
    # DeviceClass CLASS for SIZE (see dra-claim-yaml), made from a
    # ResourceClaimTemplate NAME of its own: the claim lives and dies with
    # the pod.
    dra-apply "$1" <<< "$(dra-claim-yaml template "$2" "$3" "$4" "$5" "$6")
---
$(dra-claim-pod-yaml "$2" template "$2")"
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
    # Example: dra-exec "$VM" borrower/main cxl-request memory 512Mi
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
    # response of "cxl-request memory 512Mi" among other output. Return 1
    # if there is none.
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

dra-leases() { # script API
    # Usage: dra-leases VMDIR POD[/CONTAINER]
    #
    # Run "cxl-request list" in the container (the default container of
    # POD when not given) and print its leases as one JSON list, whatever
    # form cxl-request printed them in (a list, {"leases": [...]}, or one
    # object per line). COMMAND_OUTPUT and DRA_LEASES have the list. Fail
    # the test if cxl-request fails.
    local vmdir="$1" target="$2"
    dra-exec "$vmdir" "$target" "$DRA_REQUEST_VM_BIN" list ||
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
sys.exit(0 if (int(b) in nodes(a) if op == "has" else nodes(a) == nodes(b)) else 1)' "$1" "$2" "$3"
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

dra-touch-start() { # script API
    # Usage: dra-touch-start VMDIR POD/CONTAINER MIB NODE
    #
    # Start numa-touch.py (dra-dax-tool-install) in the background in
    # container CONTAINER of pod POD in $DRA_NS: MIB MiB that prefer NUMA
    # node NODE, held until dra-touch-stop. Wait until it has touched every
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

dra-touch-log-pages() {
    # Usage: dra-touch-log-pages TEXT NODE
    #
    # Print the pages on NODE in the last "numa-touch: pages" line of TEXT
    # (0 if the node is not listed).
    local pages
    pages=$(grep '^numa-touch: pages' <<< "$1" | tail -n 1 | tr ' ' '\n' | sed -n "s/^N$2=//p")
    echo "${pages:-0}"
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

###
### Trace: every component's log in one timeline
###

dra-trace-start() { # script API
    # Usage: dra-trace-start [VMDIR...]
    #
    # Start collecting what every component does, in the background on the
    # host, until dra-trace-stop: the log of fake-cxl-pool-server, and in
    # each VM (default: the VM of the test) the logs of
    # fake-cxl-pool-controller, kubelet-cxl-plugin, kube-scheduler and
    # kubelet (DRA lines), Events, ResourceClaim and Pod watches and udev
    # events of cxl, dax, memory and node devices. Every line is stamped
    # with the host clock when it arrives on the host, so the streams of
    # all VMs merge into one timeline without VM clock skew; ssh adds a few
    # ms. The streams go to $TEST_OUTPUT_DIR/trace/<tag>.log, tag
    # <vm>.<component>, for instance vm.controller or vm1.udev.
    local vmdir label name n
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
    for vmdir in "$@"; do
        label=$(dra-vm-label "$vmdir")
        name=$(dra-vm-name "$vmdir")
        # Collectors of an aborted trace may still run.
        dra-vm-command-q "$vmdir" "$DRA_TRACE_KILL; rm -rf /run/dra-trace; mkdir -p /run/dra-trace"
        dra-trace-collect-vm "$vmdir" "$label.driver" lines "journalctl -f -n0 -o cat -u kubelet-cxl-plugin"
        dra-trace-collect-vm "$vmdir" "$label.udev" lines "stdbuf -oL udevadm monitor -k -u -s cxl -s dax -s memory -s node"
        dra-trace-collect-vm "$vmdir" "$label.kubelet" lines "journalctl -f -n0 -o cat -u kubelet | grep --line-buffered -iE 'dra|resourceclaim|cxl'"
        # The rest is of the cluster: once per cluster, on its control plane.
        [ -z "${DRA_NODE_ONLY[$vmdir]}" ] || continue
        dra-trace-collect-vm "$vmdir" "$label.controller" lines "journalctl -f -n0 -o cat -u fake-cxl-pool-controller"
        dra-trace-collect-vm "$vmdir" "$label.scheduler" lines "kubectl -n kube-system logs -f --tail=0 kube-scheduler-$name"
        dra-trace-collect-vm "$vmdir" "$label.events" lines "kubectl get events -A --watch-only -o custom-columns=NS:.metadata.namespace,KIND:.involvedObject.kind,NAME:.involvedObject.name,REASON:.reason,MSG:.message --no-headers"
        dra-trace-collect-vm "$vmdir" "$label.claims" claims "kubectl get resourceclaims -A -w --output-watch-events -o json"
        dra-trace-collect-vm "$vmdir" "$label.pods" lines "kubectl get pods -A -w --output-watch-events --no-headers"
    done
    # Every remote collector writes its pid file just before it starts.
    for vmdir in "$@"; do
        n=8
        [ -z "${DRA_NODE_ONLY[$vmdir]}" ] || n=3
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
        [ "$tag" == "server" ] && pkill -TERM -g "$pid" -x tail
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
    # kubelet-cxl-plugin: the pool helper (prepared, released, unprepared),
    # pool devices skipped by the cxl.generic publisher, the lease broker
    # (leases, companions, lends and revokes, fds sent), the local
    # allocator (regions and slices of local memdevs) and the cxlmem
    # devices it publishes, errors.
    "driver": r"(?i)cxl-pool\.generic|pool device|rescanAndPublish|lease|companion|\blend|revok|local:|cxlmem|no room for the slice|error|fail",
    "scheduler": r"(?i)binding|resourceclaim|claim|bound|error",
    "events": r"",
    "claims": r"",
    "pods": r"",
    "udev": r"^KERNEL\[",
    "kubelet": r"(?i)prepar|resourceclaim|error|fail",
}
# Lines that match but tell nothing: the cxl.generic publisher reports
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
    out.write("# Tags: server = fake-cxl-pool-server on the host; <vm>.controller =\n")
    out.write("# fake-cxl-pool-controller, <vm>.driver = kubelet-cxl-plugin, <vm>.scheduler,\n")
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
