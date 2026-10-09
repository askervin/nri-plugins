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
DRA_CONTROLLER_BIN="$nri_resource_policy_src/scripts/testing/fake-cxl-pool/bin/fake-cxl-pool-controller"
DRA_POOL_DRIVER=cxl-pool.generic   # pool devices, published by the controller
DRA_LOCAL_DRIVER=cxl.generic       # node-local CXL and DRAM, published by the node plugin
DRA_NS=cxl-pool-demo               # namespace of the test objects
DRA_INSTALLED_VMS=()               # VMDIRs where dra-install started the components
DRA_HELPER_DIR="$(dirname "${BASH_SOURCE[0]}")"
DRA_DAX_TOOL="$DRA_HELPER_DIR/n4-cxl-shared-2/pool-dax-rw.py"
DRA_NUMA_TOOL="$DRA_HELPER_DIR/n4-cxl-shared-2/numa-touch.py"
DRA_JSON=""                        # JSON of the last dra-json/dra-wait
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
    # docker.io/library/python:3-alpine):
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
    # (cxl-pool-memory, cxl-shared-memory, and cxl-dynamic if the driver
    # has it). If dra-build built cxl-request, install it as
    # $DRA_REQUEST_VM_BIN and tell the node plugin (--cxl-request-bin) to
    # mount it into the containers of lease claims. Create namespace $DRA_NS
    # empty (delete objects that an earlier run left). Wait until the
    # cluster has the pool ResourceSlice of the controller, the node's
    # cxl.generic ResourceSlice and the kubelet plugin socket of
    # cxl-pool.generic.
    #
    # Call pool-server-start first: the controller needs the server, and
    # dra-install chains its EXIT trap: dra-cleanup, then pool-cleanup.
    local vmdir="$1" name label url request_flag=""
    name=$(dra-vm-name "$vmdir")
    label=$(dra-vm-label "$vmdir")
    [ -x "$DRA_DRIVER_BIN" ] || error "dra-install: no $DRA_DRIVER_BIN, run dra-build first"
    [ -x "$DRA_CONTROLLER_BIN" ] || error "dra-install: no $DRA_CONTROLLER_BIN, run dra-build first"
    [ -f "$DRA_DEVICE_CLASSES" ] || error "dra-install: no DeviceClasses $DRA_DEVICE_CLASSES in the driver sources"
    url="${POOL_GUEST_URL:-http://192.168.76.2:${FAKE_CXL_POOL_PORT:-9909}}"

    echo "dra-install $label: stopping components of an earlier run, if any"
    dra-vm-command "$vmdir" "for u in kubelet-cxl-plugin fake-cxl-pool-controller; do systemctl stop \$u 2>/dev/null; systemctl reset-failed \$u 2>/dev/null; done; true"
    dra-vm-put-file "$vmdir" "$DRA_DRIVER_BIN" /usr/local/bin/kubelet-cxl-plugin
    dra-vm-put-file "$vmdir" "$DRA_CONTROLLER_BIN" /usr/local/bin/fake-cxl-pool-controller
    dra-vm-put-file "$vmdir" "$DRA_DEVICE_CLASSES" /root/cxl-pool-device-classes.yaml
    dra-vm-command "$vmdir" "chmod 755 /usr/local/bin/kubelet-cxl-plugin /usr/local/bin/fake-cxl-pool-controller && echo '{}' > /etc/kubelet-cxl-plugin.yaml" ||
        command-error "cannot install the DRA components in $label"
    if [ -x "$DRA_REQUEST_BIN" ]; then
        dra-vm-put-file "$vmdir" "$DRA_REQUEST_BIN" "$DRA_REQUEST_VM_BIN"
        dra-vm-command "$vmdir" "chmod 755 $DRA_REQUEST_VM_BIN" ||
            command-error "cannot install cxl-request in $label"
        request_flag=" --cxl-request-bin $DRA_REQUEST_VM_BIN"
    fi
    if [ -f "$DRA_DYNAMIC_CLASS" ]; then
        dra-vm-put-file "$vmdir" "$DRA_DYNAMIC_CLASS" /root/cxl-dynamic-device-class.yaml
    else
        dra-vm-command "$vmdir" "rm -f /root/cxl-dynamic-device-class.yaml"
    fi
    # The prepared pool claims of the node plugin refer to regions. Without
    # regions they are leftovers of an earlier VM boot, and so are the
    # leases (leases.json) and the lease sockets of token claims (leases/).
    dra-vm-command "$vmdir" "if ls /sys/bus/cxl/devices/ | grep -q '^region[0-9]'; then echo 'CXL regions exist, keeping the pool state of the node plugin'; else rm -fv /var/lib/kubelet/plugins/$DRA_POOL_DRIVER/preparedPoolClaims.json /var/lib/kubelet/plugins/$DRA_LOCAL_DRIVER/leases.json; rm -rfv /var/lib/kubelet/plugins/$DRA_LOCAL_DRIVER/leases; fi"

    echo "dra-install $label: starting kubelet-cxl-plugin and fake-cxl-pool-controller"
    dra-vm-command "$vmdir" "systemd-run --unit kubelet-cxl-plugin --property=Restart=no -E NODE_NAME=$name -E KUBECONFIG=/root/.kube/config /usr/local/bin/kubelet-cxl-plugin --node-name $name -f /etc/kubelet-cxl-plugin.yaml$request_flag -v 4" ||
        command-error "cannot start kubelet-cxl-plugin in $label"
    dra-vm-command "$vmdir" "systemd-run --unit fake-cxl-pool-controller --property=Restart=no -E KUBECONFIG=/root/.kube/config /usr/local/bin/fake-cxl-pool-controller -server $url -v" ||
        command-error "cannot start fake-cxl-pool-controller in $label"
    dra-installed-remove "$vmdir"
    DRA_INSTALLED_VMS+=("$vmdir")
    if type -t pool-cleanup >/dev/null; then
        trap 'dra-cleanup; pool-cleanup' EXIT
    else
        trap dra-cleanup EXIT
    fi
    dra-vm-command "$vmdir" "kubectl apply -f /root/cxl-pool-device-classes.yaml && if [ -f /root/cxl-dynamic-device-class.yaml ]; then kubectl apply -f /root/cxl-dynamic-device-class.yaml; fi" ||
        command-error "cannot create the DeviceClasses in $label"

    retry-until --timeout 60 --interval 2 --message "$label: ResourceSlices of $DRA_POOL_DRIVER and $DRA_LOCAL_DRIVER on $name, $DRA_POOL_DRIVER kubelet plugin socket" \
        'dra-install-ready "$vmdir" "$name"' || {
        dra-vm-command "$vmdir" "systemctl status --no-pager kubelet-cxl-plugin fake-cxl-pool-controller; journalctl --no-pager -n 40 -u kubelet-cxl-plugin; journalctl --no-pager -n 40 -u fake-cxl-pool-controller; kubectl get resourceslices; ls -l /var/lib/kubelet/plugins/*"
        error "dra-install: the DRA components did not come up in $label"
    }
    dra-vm-command "$vmdir" "kubectl get resourceslices; ls -l /var/lib/kubelet/plugins/$DRA_POOL_DRIVER/"

    dra-vm-command "$vmdir" "kubectl delete pods --all -n $DRA_NS --grace-period=2 --ignore-not-found --wait=true --timeout=60s 2>&1 | grep -v 'No resources found'; kubectl delete namespace $DRA_NS --ignore-not-found --wait=true --timeout=120s && kubectl create namespace $DRA_NS" ||
        command-error "cannot create namespace $DRA_NS in $label"
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
    # DeviceClasses. Never fails the test: it runs in the EXIT trap.
    local vmdir="$1" name label left
    name=$(dra-vm-name "$vmdir")
    label=$(dra-vm-label "$vmdir")
    echo "dra-uninstall $label"
    dra-vm-command "$vmdir" "kubectl delete pods --all -n $DRA_NS --grace-period=2 --ignore-not-found --wait=true --timeout=60s 2>&1 | grep -v 'No resources found'; kubectl delete namespace $DRA_NS --ignore-not-found --wait=true --timeout=120s"
    retry-until --timeout 60 --interval 2 --message "$label: no ResourceClaims in $DRA_NS" \
        '[ -z "$(dra-vm-command-q "$vmdir" "kubectl get resourceclaims -n $DRA_NS -o name 2>/dev/null")" ]' ||
        echo "dra-uninstall $label: ResourceClaims remain in $DRA_NS"
    if [ -n "$(dra-pool-attachments "$name")" ]; then
        retry-until --timeout 60 --interval 2 --message "$label: the controller detaches the pool devices of $name" \
            '[ -z "$(dra-pool-attachments "$name")" ]' || {
            echo "dra-uninstall $label: attachments left, pool-cleanup releases and detaches them:"
            dra-pool-attachments "$name"
        }
    fi
    dra-vm-command "$vmdir" "for u in kubelet-cxl-plugin fake-cxl-pool-controller; do systemctl stop \$u 2>/dev/null; systemctl reset-failed \$u 2>/dev/null; done; true"
    left=$(dra-vm-command-q "$vmdir" "kubectl get resourceslices -o jsonpath='{range .items[?(@.spec.driver==\"$DRA_POOL_DRIVER\")]}{.metadata.name}{\"\\n\"}{end}'")
    if [ -n "$left" ]; then
        dra-vm-command "$vmdir" "kubectl delete resourceslices $(tr "\n" " " <<< "$left")"
    fi
    dra-vm-command "$vmdir" "kubectl delete --ignore-not-found -f /root/cxl-pool-device-classes.yaml 2>/dev/null || kubectl delete deviceclass --ignore-not-found cxl-pool-memory cxl-shared-memory; kubectl delete deviceclass --ignore-not-found cxl-dynamic"
    dra-vm-command "$vmdir" "if ls /sys/bus/cxl/devices/ | grep -q '^region[0-9]'; then echo 'CXL regions left, keeping the pool state of the node plugin'; else rm -fv /var/lib/kubelet/plugins/$DRA_POOL_DRIVER/preparedPoolClaims.json /var/lib/kubelet/plugins/$DRA_LOCAL_DRIVER/leases.json; rm -rfv /var/lib/kubelet/plugins/$DRA_LOCAL_DRIVER/leases; fi"
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
    for vmdir in "${vms[@]}"; do
        dra-uninstall "$vmdir"
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
    #   device(name, driver)   the device called name, None if not found
    #   attr(dev, name)        value of an attribute ({"string": v} -> v)
    #   capacity(dev, name)    value of a capacity ("512Mi")
    #   results(claim)         allocation results of a ResourceClaim (j)
    #   allocated_node(claim)  node of the allocation's nodeSelector
    #   condition(type, claim) status of a condition in status.devices
    #   device_data(dev, claim) data of the status.devices entry of dev
    #   events(reason, name)   Events with reason, of object name
    python3 -c '
import json, sys

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

def device(name, driver=None):
    return next((d for d in devices(driver) if d["name"] == name), None)

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

def results(claim=None):
    claim = claim or j
    alloc = (claim.get("status") or {}).get("allocation") or {}
    return (alloc.get("devices") or {}).get("results") or []

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
        dra-trace-collect-vm "$vmdir" "$label.controller" lines "journalctl -f -n0 -o cat -u fake-cxl-pool-controller"
        dra-trace-collect-vm "$vmdir" "$label.driver" lines "journalctl -f -n0 -o cat -u kubelet-cxl-plugin"
        dra-trace-collect-vm "$vmdir" "$label.scheduler" lines "kubectl -n kube-system logs -f --tail=0 kube-scheduler-$name"
        dra-trace-collect-vm "$vmdir" "$label.events" lines "kubectl get events -A --watch-only -o custom-columns=NS:.metadata.namespace,KIND:.involvedObject.kind,NAME:.involvedObject.name,REASON:.reason,MSG:.message --no-headers"
        dra-trace-collect-vm "$vmdir" "$label.claims" claims "kubectl get resourceclaims -A -w --output-watch-events -o json"
        dra-trace-collect-vm "$vmdir" "$label.pods" lines "kubectl get pods -A -w --output-watch-events --no-headers"
        dra-trace-collect-vm "$vmdir" "$label.udev" lines "stdbuf -oL udevadm monitor -k -u -s cxl -s dax -s memory -s node"
        dra-trace-collect-vm "$vmdir" "$label.kubelet" lines "journalctl -f -n0 -o cat -u kubelet | grep --line-buffered -iE 'dra|resourceclaim|cxl'"
    done
    # Every remote collector writes its pid file just before it starts.
    for vmdir in "$@"; do
        retry-until --timeout 30 --message "trace collectors in $(dra-vm-label "$vmdir")" \
            '[ "$(dra-vm-command-q "$vmdir" "ls /run/dra-trace/ | grep -c .pid\$")" == 8 ]' ||
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
    # node plugin, udev events of the devices, pods starting and stopping.
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
    # (leases, companions, lends and revokes, fds sent), errors.
    "driver": r"(?i)cxl-pool\.generic|pool device|rescanAndPublish|lease|companion|\blend|revok|error|fail",
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
