# Helpers for testing CXL memory pooling and sharing with fake-cxl-pool
# (scripts/testing/fake-cxl-pool) in the VMs of n4-cxl-shared-0,
# n4-cxl-shared-1 and n4-cxl-shared-2.
#
# fake-cxl-pool-server runs on the host, next to qemu, and hotplugs CXL
# memory devices into running VMs over their QMP (or HMP) sockets. Tests
# run fake-cxl-pool-client in the VMs. The test runs against the VM of
# n4-cxl-shared-2 (vm-command, "VM2") and drives the VMs of
# n4-cxl-shared-1 ("VM1") and n4-cxl-shared-0 ("VM0") over ssh from the
# host: the VMs reach the host at 192.168.76.2, the slirp gateway. They
# reach each other only over their VM network "cxl-pool"
# (vm_network.var.sh), over which they are one Kubernetes cluster of three
# nodes: VM2 the control plane, VM1 and VM0 workers. test00-up of
# n4-cxl-shared-2 makes that cluster (vm-k8s-reinit), the other tests only
# check it (pool-cluster-require).
#
# A pool server is one CXL memory pool appliance, cabled to some of the
# VMs. The server of most tests, pool-server-start without options, is
# cabled to VM1 and VM2 only (pool A of test19-many-pools); VM0 is a node
# that it cannot reach. A test can start several servers (pool-server-start
# --name ...): each has its own port, devices, pool directory and VMs, and
# dra-install runs a pool controller for each.
#
# The helpers that work on any VM take the output directory of the VM,
# VMDIR: $OUTPUT_DIR for VM2, $POOL_VM1_DIR for VM1, $POOL_VM0_DIR for VM0.
# The commands in other VMs are those of lib/k8s.bash (vmdir-*), under the
# names that the tests use.

POOL_SRC_DIR="$nri_resource_policy_src/scripts/testing/fake-cxl-pool"
POOL_BIN_DIR="$POOL_SRC_DIR/bin"
POOL_HELPER_DIR="$(dirname "${BASH_SOURCE[0]}")"
POOL_DIR="/tmp/fake-cxl-pool"                   # pool of device backing files of the default server
POOL_PORT="${FAKE_CXL_POOL_PORT:-9909}"         # the port of a server without --port
POOL_URL="http://127.0.0.1:$POOL_PORT"          # the first server, seen from the host
POOL_GUEST_URL="http://192.168.76.2:$POOL_PORT" # the first server, seen from the VMs
POOL_DEFAULT_NAME="fake-cxl-pool"               # the name of a server without --name
POOL_VM2_DIR="$OUTPUT_DIR"
POOL_VM2_NAME="$VM_HOSTNAME"
# The VMs of n4-cxl-shared-1 and -0 with the same distro and runtime as
# this one.
POOL_VM1_DIR="${POOL_VM1_DIR:-$(dirname "$OUTPUT_DIR")/n4-cxl-shared-1${VM_HOSTNAME#"$(basename "$TOPOLOGY_DIR")"}}"
POOL_VM1_NAME="$(basename "$POOL_VM1_DIR")"
POOL_VM0_DIR="${POOL_VM0_DIR:-$(dirname "$OUTPUT_DIR")/n4-cxl-shared-0${VM_HOSTNAME#"$(basename "$TOPOLOGY_DIR")"}}"
POOL_VM0_NAME="$(basename "$POOL_VM0_DIR")"
# The first server that pool-server-start started: its pid and log. The
# URLs above are its URLs.
POOL_SERVER_PID=""
POOL_SERVER_LOG=""
# Every server that pool-server-start started: their names in start order,
# and by name their pids, ports, logs and VMs (VMDIRs separated by spaces).
POOL_SERVERS=()
declare -A POOL_SERVER_PIDS=()
declare -A POOL_SERVER_PORTS=()
declare -A POOL_SERVER_LOGS=()
declare -A POOL_SERVER_HOSTS=()
POOL_BUILT=""                                   # pool-server-start built fake-cxl-pool
POOL_DEVICE_DATA=""                             # pool-device-files: the backing file of a device
POOL_DEVICE_LSA=""                              # and its label storage area file

pool-vm-label() {
    # Usage: pool-vm-label VMDIR
    #
    # Print the short name of a VM in prompts and file names: vm for the
    # VM of the test, vm1 for the VM of n4-cxl-shared-1, vm0 for the VM of
    # n4-cxl-shared-0.
    case "$1" in
        "$POOL_VM2_DIR") echo "vm";;
        "$POOL_VM1_DIR") echo "vm1";;
        "$POOL_VM0_DIR") echo "vm0";;
        *) basename "$1";;
    esac
}

pool-vm-dir() {
    # Usage: pool-vm-dir VMNAME
    #
    # Print the output directory of a VM, given its name (the host name in
    # fake-cxl-pool).
    case "$1" in
        "$POOL_VM2_NAME") echo "$POOL_VM2_DIR";;
        "$POOL_VM1_NAME") echo "$POOL_VM1_DIR";;
        "$POOL_VM0_NAME") echo "$POOL_VM0_DIR";;
        *) return 1;;
    esac
}

other-vm-command() { # script API
    # Usage: other-vm-command VMDIR COMMAND
    #
    # Execute COMMAND as root in the VM of the output directory VMDIR, which
    # is not the VM of the test, the way vm-command does in the VM of the
    # test (vmdir-command of lib/k8s.bash).
    vmdir-command "$1" "$2"
}

other-vm-command-q() {
    # Usage: other-vm-command-q VMDIR COMMAND
    #
    # Execute COMMAND as root in the VM of VMDIR quietly, like vm-command-q.
    vmdir-command-q "$1" "$2"
}

other-vm-put-file() { # script API
    # Usage: other-vm-put-file VMDIR SRC-HOST-FILE DST-VM-FILE
    #
    # Copy a file from the host to the VM of VMDIR, like vm-put-file.
    vmdir-put-file "$1" "$2" "$3"
}

pool-vm-command() { # script API
    # Usage: pool-vm-command VMDIR COMMAND
    #
    # vm-command in the VM of VMDIR: the VM of the test or another one.
    vmdir-command "$1" "$2"
}

pool-vm-command-q() {
    # Usage: pool-vm-command-q VMDIR COMMAND
    vmdir-command-q "$1" "$2"
}

pool-vm-put-file() { # script API
    # Usage: pool-vm-put-file VMDIR SRC-HOST-FILE DST-VM-FILE
    vmdir-put-file "$1" "$2" "$3"
}

pool-vm-qmp() { # script API
    # Usage: pool-vm-qmp VMDIR COMMAND [ARGUMENTS_JSON]
    #
    # vm-qmp on the qemu of the VM of VMDIR, on its qmp-e2e.sock. (qmp.sock
    # belongs to fake-cxl-pool-server.)
    local vmdir="$1"
    shift
    VM_QMP="$vmdir/qmp-e2e.sock" vm-qmp "$@"
}

pool-vm-monitor() { # script API
    # Usage: pool-vm-monitor VMDIR COMMAND
    #
    # vm-monitor on the qemu of the VM of VMDIR.
    VM_MONITOR="(cd \"$1\" && socat STDIO unix-connect:monitor.sock)" vm-monitor "$2"
}

pool-vm-ssh-wait() {
    # Usage: pool-vm-ssh-wait VMDIR [TIMEOUT]
    #
    # Wait until ssh to the VM of VMDIR works, TIMEOUT seconds at most
    # (default 180).
    vmdir-ssh-wait "$@"
}

pool-host-wait() { # script API
    # Usage: pool-host-wait VMDIR HINT
    #
    # Make sure that the VM of VMDIR is up. Start it if it is not. Fail
    # with HINT, how to create the VM, if there is no VM in VMDIR.
    vmdir-up "$1" "$2"
    echo "pool-host-wait: $(basename "$1") is up"
}

pool-vm-restart() { # script API
    # Usage: pool-vm-restart VMDIR
    #
    # Restart qemu of the VM of VMDIR. That is the only way to get rid of a
    # CXL memory device that qemu cannot delete (a zombie device of a detach
    # without release).
    vmdir-restart "$1"
}

pool-vm-require() { # script API
    # Usage: pool-vm-require VMDIR TOPOLOGY
    #
    # Fail unless the VM of VMDIR, created from TOPOLOGY, can share CXL
    # memory devices with other VMs through fake-cxl-pool:
    # - Its qemu can hot-remove CXL memory devices: the patched build where
    #   cxl-downstream ports have power_controller_present. Stock qemu
    #   cannot delete a device from a cxl-downstream port: every detach
    #   would leave a zombie device in qemu until it restarts.
    # - Its host bridges have hdm_for_passthrough=on: HDM decoders, so that
    #   a host bridge can have more than one region.
    # - Its kernel has CONFIG_FS_DAX=y: without it devdax devices cannot be
    #   mmapped ("vma is not DAX capable"), and devdax is the only safe way
    #   to share memory: onlining the same memory as system RAM in two VMs
    #   corrupts them both.
    local vmdir="$1" topology="$2" name version qemu_bin hb response
    local recreate="recreate the VM: vagrant destroy in $vmdir, remove the directory, and run
  qemu_bin=\$HOME/github.com/qemu/qemu/build/qemu-system-x86_64 ./run_tests.sh memory.test-suite/dra-driver-cxl/$topology/test00-up"
    name="$(basename "$vmdir")"
    version=$(pool-vm-qmp "$vmdir" query-version) ||
        error "QMP query-version failed on $name: $version"
    qemu_bin=$(readlink "/proc/$(vm-qemu-pid "$vmdir" | head -n 1)/exe")
    echo "$name: qemu $qemu_bin: $version"
    response=$(pool-vm-qmp "$vmdir" qom-get '{"path": "/machine/peripheral/cxlsw_ds0_usrp0hb0", "property": "power_controller_present"}')
    [ "$response" == '{"return": true}' ] ||
        error "qemu $qemu_bin of $name cannot hot-remove CXL memory devices: cxl-downstream port has no power_controller_present ($response). A detach would leave a zombie device in qemu. Use the patched qemu (branch 5jL-fix-cxl-hot-remove): set QEMU_BIN in $vmdir/env and restart the VM (vagrant halt; vagrant up --no-provision in $vmdir), or $recreate"
    for hb in cxlhb0 cxlhb1; do
        response=$(pool-vm-qmp "$vmdir" qom-get "{\"path\": \"/machine/peripheral/$hb\", \"property\": \"hdm_for_passthrough\"}")
        [ "$response" == '{"return": true}' ] ||
            error "host bridge $hb of $name has no hdm_for_passthrough=on ($response): one region per host bridge only. The VM was created before \"hdm-for-passthrough\" was in the topology, $recreate"
    done
    pool-vm-command "$vmdir" 'uname -r; grep -x CONFIG_FS_DAX=y /boot/config-$(uname -r)' ||
        error "kernel of $name lacks CONFIG_FS_DAX=y: devdax devices cannot be mmapped. Build the kernel with scripts/testing/fake-cxl-pool/proto/build-kernel-rpms.sh and $recreate"
    echo "$name: patched qemu, hdm_for_passthrough=on, CONFIG_FS_DAX=y"
}

pool-vm-tools-install() { # script API
    # Usage: pool-vm-tools-install VMDIR
    #
    # Install cxl, daxctl and numactl in the VM of VMDIR if they are
    # missing. In the VM of the test install also cxl-dump (cxl-tools-install
    # builds it), in other VMs copy the cxl-dump that it built.
    local vmdir="$1"
    if [ "$vmdir" == "$OUTPUT_DIR" ]; then
        cxl-tools-install
    else
        [ -f "$OUTPUT_DIR/cxl-dump" ] || error "pool-vm-tools-install: run it on the VM of the test first"
        pool-vm-put-file "$vmdir" "$OUTPUT_DIR/cxl-dump" /usr/local/bin/cxl-dump
    fi
    pool-vm-command-q "$vmdir" "command -v cxl >/dev/null && command -v daxctl >/dev/null && command -v numactl >/dev/null" ||
        pool-vm-command "$vmdir" "dnf install -y /usr/bin/cxl daxctl numactl" ||
            command-error "cannot install cxl, daxctl and numactl in $(basename "$vmdir")"
}

pool-cluster-require() { # script API
    # Usage: pool-cluster-require [CLUSTER]
    #
    # Fail the test unless the VMs of CLUSTER are one Kubernetes cluster in
    # shape (vm-k8s-cluster-in-shape), printing why not and that test00-up
    # of n4-cxl-shared-2 makes it. CLUSTER is a cluster of vm-k8s-reinit,
    # by default "$POOL_VM2_DIR $POOL_VM1_DIR $POOL_VM0_DIR": VM2 the
    # control plane, VM1 and VM0 workers.
    local cluster="${1:-$POOL_VM2_DIR $POOL_VM1_DIR $POOL_VM0_DIR}" why
    why=$(vm-k8s-cluster-in-shape "$cluster") ||
        error "the cluster \"$(vm-k8s-cluster-names "$cluster")\" is not in shape: ${why:-no reason given}
run memory.test-suite/dra-driver-cxl/n4-cxl-shared-2/test00-up first"
    echo "pool-cluster-require: cluster \"$(vm-k8s-cluster-names "$cluster")\" is in shape"
}

pool-vm-reset() { # script API
    # Usage: pool-vm-reset VMDIR
    #
    # Make sure that the VM of VMDIR has no CXL memory devices, neither in
    # qemu nor in the kernel, and that hotplugged memory is not onlined
    # automatically: onlined shared memory would be system RAM of several
    # VMs at once. Restart the VM if it has devices, and wait until its
    # Kubernetes node is Ready again.
    local vmdir="$1" name plugged guest_devs
    name="$(basename "$vmdir")"
    plugged=$(pool-vm-monitor "$vmdir" "info qtree -b" | grep -c 'dev: cxl-type3')
    guest_devs=$(pool-vm-command-q "$vmdir" "ls /sys/bus/cxl/devices/" | grep -cE '^(mem|region)[0-9]')
    if [ "$plugged" != "0" ] || [ "$guest_devs" != "0" ]; then
        echo "pool-vm-reset: $name has $plugged CXL memory devices in qemu, $guest_devs CXL memory devices or regions in the kernel: restarting it"
        pool-vm-restart "$vmdir"
        plugged=$(pool-vm-monitor "$vmdir" "info qtree -b" | grep -c 'dev: cxl-type3')
        [ "$plugged" == "0" ] || error "pool-vm-reset: $name still has $plugged CXL memory devices after restart"
        # The restart keeps the shape of the cluster, but the node, or the
        # whole cluster if the VM is its control plane, needs a while.
        retry-until --timeout 300 --interval 2 --message "node $name Ready after the restart" \
            'pool-vm-command-q "$vmdir" "kubectl wait --for=condition=Ready node/$name --timeout=10s" >/dev/null 2>&1' ||
            error "pool-vm-reset: node $name is not Ready after the restart of its VM"
    fi
    pool-vm-command "$vmdir" "echo offline > /sys/devices/system/memory/auto_online_blocks && cat /sys/devices/system/memory/auto_online_blocks" ||
        command-error "cannot disable automatic onlining of hotplugged memory in $name"
}

pool-cxl-dump() { # script API
    # Usage: pool-cxl-dump VMDIR LABEL
    #
    # cxl-dump in the VM of VMDIR. The output files of other VMs than the
    # VM of the test have the short name of the VM after LABEL, for
    # instance cxl-dump.LABEL.vm1.json. cxl-assert and cxl-value work on the
    # dump afterwards.
    local vmdir="$1" label="$2" suffix
    if [ "$vmdir" == "$OUTPUT_DIR" ]; then
        cxl-dump "$label"
        return 0
    fi
    suffix="$(pool-vm-label "$vmdir")"
    pool-cxl-dump-json "$vmdir" "$label" || error "pool-cxl-dump: running cxl-dump in $(basename "$vmdir") failed"
    other-vm-command-q "$vmdir" "grep -sIr '' /sys/bus/cxl/devices/* | awk '{p=\$0; sub(/:.*/, \"\", p); n=gsub(/\//, \"/\", p); print n \"\t\" \$0}' | sort -k1,1n -k2 | cut -f2-" \
        > "$TEST_OUTPUT_DIR/cxl-sysfs.$label.$suffix.txt"
    other-vm-command-q "$vmdir" "grep -s '' /sys/devices/system/memory/block_size_bytes /sys/devices/system/memory/memory*/state; grep -H MemTotal /sys/devices/system/node/node*/meminfo" \
        > "$TEST_OUTPUT_DIR/memory.$label.$suffix.txt"
    echo "cxl-dump $label ($suffix): $(cxl-value 'summary()')"
}

pool-cxl-dump-json() {
    # Usage: pool-cxl-dump-json VMDIR LABEL
    local vmdir="$1" label="$2" json
    if [ "$vmdir" == "$OUTPUT_DIR" ]; then
        cxl-dump-json "$label"
        return
    fi
    json=$(other-vm-command-q "$vmdir" "cxl-dump -o json") || return 1
    CXL_DUMP_FILE="$TEST_OUTPUT_DIR/cxl-dump.$label.$(pool-vm-label "$vmdir").json"
    echo "$json" > "$CXL_DUMP_FILE"
}

pool-cxl-wait() { # script API
    # Usage: pool-cxl-wait VMDIR LABEL EXPRESSION [TIMEOUT]
    #
    # cxl-wait in the VM of VMDIR.
    local vmdir="$1" label="$2" expression="$3" tmo="${4:-30}"
    if [ "$vmdir" == "$OUTPUT_DIR" ]; then
        cxl-wait "$label" "$expression" "$tmo"
        return 0
    fi
    retry-until --timeout "$tmo" --message "pkg/cxl in $(pool-vm-label "$vmdir"): $expression" \
        'pool-cxl-dump-json "$vmdir" "$label" && cxl-py assert "$expression" >/dev/null' || {
        pool-cxl-dump "$vmdir" "$label"
        error "pkg/cxl in $(basename "$vmdir") did not reach the expected state in ${tmo}s: $expression"
    }
    pool-cxl-dump "$vmdir" "$label"
}

pool-port-busy() {
    # Usage: pool-port-busy [PORT]
    #
    # Return 0 if something listens on PORT (default: $POOL_PORT, the port
    # of a server without --port).
    (exec 3<>"/dev/tcp/127.0.0.1/${1:-$POOL_PORT}") 2>/dev/null
}

pool-url() { # script API
    # Usage: pool-url [NAME]
    #
    # Print the URL of the server NAME (default: the first started server)
    # on the host. Return 1 if no such server was started.
    pool-server-url "${1:-}" "127.0.0.1"
}

pool-guest-url() { # script API
    # Usage: pool-guest-url [NAME]
    #
    # Print the URL of the server NAME (default: the first started server)
    # seen from the VMs. Return 1 if no such server was started.
    pool-server-url "${1:-}" "192.168.76.2"
}

pool-server-url() {
    # Usage: pool-server-url NAME ADDRESS
    #
    # Print the URL of the server NAME at ADDRESS, "" for NAME: the first
    # started server, else POOL_URL or POOL_GUEST_URL of a server that this
    # test did not start (POOL_SERVER_PID set by the test).
    local name="$1" address="$2"
    if [ -z "$name" ]; then
        if [ "${#POOL_SERVERS[@]}" -eq 0 ]; then
            if [ "$address" == "127.0.0.1" ]; then echo "$POOL_URL"; else echo "$POOL_GUEST_URL"; fi
            return 0
        fi
        name="${POOL_SERVERS[0]}"
    fi
    if [ -z "${POOL_SERVER_PORTS[$name]:-}" ]; then
        echo "pool-url: no server $name, started: ${POOL_SERVERS[*]:-none}" >&2
        return 1
    fi
    echo "http://$address:${POOL_SERVER_PORTS[$name]}"
}

pool-server-first() {
    # Usage: pool-server-first
    #
    # Set POOL_SERVER_PID, POOL_SERVER_LOG, POOL_URL and POOL_GUEST_URL to
    # those of the first running server of POOL_SERVERS. Without servers,
    # clear POOL_SERVER_PID and keep the rest.
    local first
    if [ "${#POOL_SERVERS[@]}" -eq 0 ]; then
        POOL_SERVER_PID=""
        return 0
    fi
    first="${POOL_SERVERS[0]}"
    POOL_SERVER_PID="${POOL_SERVER_PIDS[$first]}"
    # shellcheck disable=SC2034 # the tests and dra.source.sh read it
    POOL_SERVER_LOG="${POOL_SERVER_LOGS[$first]}"
    POOL_URL="http://127.0.0.1:${POOL_SERVER_PORTS[$first]}"
    POOL_GUEST_URL="http://192.168.76.2:${POOL_SERVER_PORTS[$first]}"
}

pool-server-start() { # script API
    # Usage: pool-server-start [OPTIONS] [DEVICES]
    #
    # Build fake-cxl-pool and start a fake-cxl-pool-server on the host, a
    # pool appliance. DEVICES is the YAML list of the static devices of the
    # server, the value of "devices:" in its configuration. Serials follow
    # the scheme of the server: 0xc1ae.... for shared and 0xc1ee.... for
    # exclusive devices (0xc100.... are boot-time devices of the VMs); with
    # several servers 0xc1aeP... and 0xc1eeP..., P the pool index, so that
    # serials are unique in the cluster. Device names must be unique among
    # the servers of a VM. OPTIONS:
    #   --name NAME        server name, the DRA pool name of its controller
    #                      (default fake-cxl-pool)
    #   --port PORT        port on 127.0.0.1 (default $POOL_PORT: 9909, or
    #                      $FAKE_CXL_POOL_PORT)
    #   --hosts "VMDIR..." the VMs it is cabled to (default "$POOL_VM1_DIR
    #                      $POOL_VM2_DIR"): discovery.names, their names
    #   --index P          pool index, one hex digit: serial bases
    #                      0xc1aeP000 and 0xc1eeP000 (default: the server's
    #                      defaults 0xc1ae0000 and 0xc1ee0000)
    #   --control qmp|hmp  discovery.control, the monitor of every VM
    #                      (default: the server's choice, QMP). A VM that
    #                      another server holds over QMP needs hmp.
    #   --slots "PAT..."   discovery.slots, the CXL slots it is cabled to
    #                      (path patterns of slot names, default: all)
    #   --local-devices yes|no  discovery.localDevices (default yes)
    # The configuration, the state (removed first: every server starts
    # empty) and the log are in $TEST_OUTPUT_DIR: fake-cxl-pool.yaml,
    # fake-cxl-pool.state.json and fake-cxl-pool-server.log for the default
    # name, fake-cxl-pool-NAME.yaml, fake-cxl-pool-NAME.state.json and
    # fake-cxl-pool-server-NAME.log for others. The device backing files
    # are in $POOL_DIR, or /tmp/fake-cxl-pool-NAME.
    #
    # The server discovers only the VMs of --hosts, so that it never
    # connects to the monitors of other VMs on the host. Fail if a server
    # NAME runs already, or if the port is busy, for instance by a server
    # that someone else runs: one server at a time can use the QMP socket
    # of a VM.
    #
    # The first started server is POOL_SERVER_PID, POOL_SERVER_LOG,
    # POOL_URL and POOL_GUEST_URL; every server is in POOL_SERVERS,
    # POOL_SERVER_PIDS, POOL_SERVER_PORTS, POOL_SERVER_LOGS and
    # POOL_SERVER_HOSTS. Set an EXIT trap that detaches the devices that
    # the test left attached and stops the servers (pool-cleanup).
    local name="$POOL_DEFAULT_NAME" port="$POOL_PORT" hosts="$POOL_VM1_DIR $POOL_VM2_DIR"
    local index="" control="" slots="" local_devices=yes
    local devices config state log dir suffix="" names="" vmdir vmdirs=() pat pats=() slot_list="" pid url
    while [ $# -gt 0 ]; do
        case "$1" in
            --name) name="$2"; shift 2;;
            --port) port="$2"; shift 2;;
            --hosts) hosts="$2"; shift 2;;
            --index) index="$2"; shift 2;;
            --control) control="$2"; shift 2;;
            --slots) slots="$2"; shift 2;;
            --local-devices) local_devices="$2"; shift 2;;
            --*) error "pool-server-start: unknown option $1";;
            *) break;;
        esac
    done
    devices="${1:- []}"
    [[ "$name" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] ||
        error "pool-server-start: --name $name is not a DNS label (lower-case letters, digits, '-')"
    [[ "$port" =~ ^[0-9]+$ ]] || error "pool-server-start: --port $port is not a port number"
    [ -z "$index" ] || [[ "$index" =~ ^[0-9a-fA-F]$ ]] ||
        error "pool-server-start: --index $index is not one hex digit"
    [ -z "$control" ] || [ "$control" == qmp ] || [ "$control" == hmp ] ||
        error "pool-server-start: --control $control is not qmp or hmp"
    [ "$local_devices" == yes ] || [ "$local_devices" == no ] ||
        error "pool-server-start: --local-devices $local_devices is not yes or no"
    [ -n "$hosts" ] || error "pool-server-start: --hosts is empty"
    [ -z "${POOL_SERVER_PIDS[$name]:-}" ] ||
        error "pool-server-start: the server $name is running already, pid ${POOL_SERVER_PIDS[$name]}"
    if [ "${#POOL_SERVERS[@]}" -eq 0 ] && [ -n "$POOL_SERVER_PID" ]; then
        error "pool-server-start: the server is running already, pid $POOL_SERVER_PID"
    fi
    if [ -z "$POOL_BUILT" ]; then
        host-command "make -C \"$POOL_SRC_DIR\"" || command-error "cannot build fake-cxl-pool"
        POOL_BUILT=1
    fi
    if pool-port-busy "$port"; then
        if [ "$port" == "$POOL_PORT" ]; then
            error "port $port is busy, is another fake-cxl-pool-server running? ($(ss -ltnpH "sport = :$port" 2>/dev/null)) Stop it, or set FAKE_CXL_POOL_PORT"
        fi
        error "port $port of server $name is busy, is another fake-cxl-pool-server running? ($(ss -ltnpH "sport = :$port" 2>/dev/null)) Stop it, or give another --port"
    fi
    dir="$POOL_DIR"
    if [ "$name" != "$POOL_DEFAULT_NAME" ]; then
        suffix="-$name"
        dir="/tmp/fake-cxl-pool-$name"
    fi
    config="$TEST_OUTPUT_DIR/fake-cxl-pool$suffix.yaml"
    state="$TEST_OUTPUT_DIR/fake-cxl-pool$suffix.state.json"
    log="$TEST_OUTPUT_DIR/fake-cxl-pool-server$suffix.log"
    rm -f "$state" "$state".*
    # read splits the words without expanding them: slot patterns are
    # globs.
    read -r -a vmdirs <<< "$hosts"
    for vmdir in "${vmdirs[@]}"; do
        names+="${names:+, }\"$(basename "$vmdir")\""
    done
    read -r -a pats <<< "$slots"
    for pat in "${pats[@]}"; do
        slot_list+="${slot_list:+, }\"$pat\""
    done
    {
        echo "# fake-cxl-pool-server configuration of $(basename "$TEST_DIR"), written by pool-server-start"
        [ -z "$suffix" ] || echo "name: $name"
        echo "listen: 127.0.0.1:$port"
        if [ -n "$index" ]; then
            echo "sharedSerialBase: 0xc1ae${index,,}000"
            echo "exclusiveSerialBase: 0xc1ee${index,,}000"
        fi
        cat <<EOF
pools:
  - name: default
    dir: $dir
    capacity: 8G
    sharable: true
devices:$devices
discovery:
  qemu: true
  interval: 10s
  names: [$names]
EOF
        [ -z "$control" ] || echo "  control: $control"
        [ -z "$slot_list" ] || echo "  slots: [$slot_list]"
        if [ "$local_devices" == yes ]; then
            echo "  localDevices: true"
        else
            echo "  localDevices: false"
        fi
        echo "detachTimeout: 15s"
    } > "$config" || error "pool-server-start: cannot write $config"
    echo "pool-server-start: configuration $config:"
    cat "$config"
    "$POOL_BIN_DIR/fake-cxl-pool-server" -config "$config" -state "$state" -v \
        </dev/null >"$log" 2>&1 &
    pid=$!
    [ "${#POOL_SERVERS[@]}" -gt 0 ] || trap pool-cleanup EXIT
    POOL_SERVERS+=("$name")
    POOL_SERVER_PIDS["$name"]="$pid"
    POOL_SERVER_PORTS["$name"]="$port"
    POOL_SERVER_LOGS["$name"]="$log"
    # shellcheck disable=SC2034 # the tests read it
    POOL_SERVER_HOSTS["$name"]="$hosts"
    pool-server-first
    url="http://127.0.0.1:$port"
    echo "pool-server-start: fake-cxl-pool-server $name pid $pid, $url, log $log"
    # The server discovers the VMs and connects to their monitors before it
    # serves the first request.
    retry-until --timeout 60 --message "fake-cxl-pool-server $name on $url" \
        'kill -0 "$pid" 2>/dev/null && curl -sf --max-time 5 "$url/api/v1/status" >/dev/null' || {
        cat "$log"
        error "fake-cxl-pool-server $name did not start, see $log"
    }
    host-command "curl -sS --max-time 30 $url/api/v1/status" ||
        command-error "cannot get the status of the server $name"
}

pool-server-kill() {
    # Usage: pool-server-kill PID LABEL
    #
    # Stop the server process PID: SIGTERM, SIGKILL if it is still there
    # after 10 s.
    local pid="$1" label="$2" i
    kill -TERM "$pid" 2>/dev/null
    for i in $(seq 20); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
    done
    if kill -0 "$pid" 2>/dev/null; then
        echo "pool-server-stop: server${label:+ $label} pid $pid did not stop in 10s, killing it"
        kill -KILL "$pid" 2>/dev/null
    fi
    wait "$pid" 2>/dev/null
    echo "pool-server-stop: stopped fake-cxl-pool-server${label:+ $label} pid $pid"
}

# shellcheck disable=SC2120 # the tests give NAME
pool-server-stop() { # script API
    # Usage: pool-server-stop [NAME]
    #
    # Stop the server NAME that pool-server-start started, or every server,
    # the last started first. Without servers of pool-server-start, stop
    # the server POOL_SERVER_PID if it is set.
    local name names=() keep=() i
    if [ -n "${1:-}" ]; then
        [ -n "${POOL_SERVER_PIDS[$1]:-}" ] || return 0
        names=("$1")
    else
        if [ "${#POOL_SERVERS[@]}" -eq 0 ]; then
            [ -n "$POOL_SERVER_PID" ] || return 0
            pool-server-kill "$POOL_SERVER_PID" ""
            POOL_SERVER_PID=""
            return 0
        fi
        for (( i = ${#POOL_SERVERS[@]} - 1; i >= 0; i-- )); do
            names+=("${POOL_SERVERS[$i]}")
        done
    fi
    for name in "${names[@]}"; do
        pool-server-kill "${POOL_SERVER_PIDS[$name]}" "$name"
        unset "POOL_SERVER_PIDS[$name]" "POOL_SERVER_PORTS[$name]" "POOL_SERVER_LOGS[$name]" "POOL_SERVER_HOSTS[$name]"
    done
    for name in "${POOL_SERVERS[@]}"; do
        [ -z "${POOL_SERVER_PIDS[$name]:-}" ] || keep+=("$name")
    done
    POOL_SERVERS=("${keep[@]}")
    pool-server-first
}

pool-cleanup() {
    # Usage: pool-cleanup
    #
    # The EXIT trap of pool-server-start. If the test left devices attached
    # on a server, release them in the VMs and detach them, so that the
    # next test finds VMs without devices, delete the devices the test
    # created, and stop the servers. Without servers of pool-server-start,
    # do that on the server POOL_SERVER_PID at POOL_URL.
    local name
    if [ "${#POOL_SERVERS[@]}" -eq 0 ]; then
        if [ -n "$POOL_SERVER_PID" ] && kill -0 "$POOL_SERVER_PID" 2>/dev/null; then
            pool-cleanup-server "" "$POOL_URL"
        fi
    fi
    for name in "${POOL_SERVERS[@]}"; do
        kill -0 "${POOL_SERVER_PIDS[$name]}" 2>/dev/null || continue
        pool-cleanup-server "$name" "$(pool-url "$name")"
    done
    pool-server-stop
}

pool-cleanup-server() {
    # Usage: pool-cleanup-server NAME URL
    #
    # Release and detach what the server NAME at URL has attached, and
    # delete its dynamic devices.
    local name="$1" url="$2" atts devs lines line dev host serial vmdir pool=()
    [ -z "$name" ] || pool=(--pool "$name")
    atts=$(curl -s --max-time 30 "$url/api/v1/attachments" | python3 -c '
import json, sys
for a in json.load(sys.stdin) or []:
    if not a.get("adopted"):
        print(a["device"], a["host"], a["serial"])' 2>/dev/null)
    if [ -n "$atts" ]; then
        echo "pool-cleanup: detaching devices left attached${name:+ on $name}:"
        echo "$atts"
        mapfile -t lines <<< "$atts"
        for line in "${lines[@]}"; do
            read -r dev host serial <<< "$line"
            vmdir=$(pool-vm-dir "$host") || continue
            pool-vm-command "$vmdir" "fake-cxl-pool-client guest release $serial"
            pool-host-client "${pool[@]}" detach "$dev" --host "$host"
        done
    fi
    devs=$(curl -s --max-time 30 "$url/api/v1/devices?scope=pool" | python3 -c '
import json, sys
for d in json.load(sys.stdin) or []:
    if not d.get("static"):
        print(d["name"])' 2>/dev/null)
    for dev in $devs; do
        pool-host-client "${pool[@]}" delete "$dev" --force
    done
}

pool-client-install() { # script API
    # Usage: pool-client-install VMDIR...
    #
    # Copy fake-cxl-pool-client (built static by pool-server-start) and
    # pool-dax-rw.py into the VMs, to /usr/local/bin.
    local vmdir
    [ -x "$POOL_BIN_DIR/fake-cxl-pool-client" ] ||
        host-command "make -C \"$POOL_SRC_DIR\" bin/fake-cxl-pool-client" ||
            command-error "cannot build fake-cxl-pool-client"
    for vmdir in "$@"; do
        pool-vm-put-file "$vmdir" "$POOL_BIN_DIR/fake-cxl-pool-client" /usr/local/bin/fake-cxl-pool-client
        pool-vm-put-file "$vmdir" "$POOL_HELPER_DIR/pool-dax-rw.py" /usr/local/bin/pool-dax-rw.py
        pool-vm-command "$vmdir" "chmod 755 /usr/local/bin/fake-cxl-pool-client /usr/local/bin/pool-dax-rw.py && fake-cxl-pool-client --help | head -n 1" ||
            command-error "cannot run fake-cxl-pool-client in $(basename "$vmdir")"
    done
}

pool-client() { # script API
    # Usage: pool-client [--pool NAME] VMDIR [-o json] COMMAND [ARGS...]
    #
    # Run fake-cxl-pool-client as root in the VM of VMDIR, connected to the
    # server NAME (default: the first started server). Return its exit
    # status: 0 ok, 1 error, 2 usage, 3 conflict or timeout. COMMAND_OUTPUT
    # has what it printed.
    local url="$POOL_GUEST_URL" vmdir server=""
    if [ "$1" == "--pool" ]; then
        url=$(pool-guest-url "$2") || error "pool-client: no server $2"
        shift 2
    fi
    vmdir="$1"
    shift
    # The client's default server is the default port of the host.
    [ "$url" == "http://192.168.76.2:9909" ] || server=" --server $url"
    pool-vm-command "$vmdir" "fake-cxl-pool-client$server$(printf ' %q' "$@")"
}

pool-host-client() { # script API
    # Usage: pool-host-client [--pool NAME] [-o json] COMMAND [ARGS...]
    #
    # Run fake-cxl-pool-client on the host, connected to the server NAME
    # (default: the first started server).
    local url="$POOL_URL"
    if [ "$1" == "--pool" ]; then
        url=$(pool-url "$2") || error "pool-host-client: no server $2"
        shift 2
    fi
    host-command "$POOL_BIN_DIR/fake-cxl-pool-client --server $url$(printf ' %q' "$@")"
}

pool-attachments() { # script API
    # Usage: pool-attachments [--pool NAME] DEVICE
    #
    # Print the attachments of DEVICE on the server NAME (default: the
    # first started server) as JSON, and keep them in COMMAND_OUTPUT. Fail
    # the test if the server does not answer.
    local pool=()
    if [ "$1" == "--pool" ]; then
        pool=(--pool "$2")
        shift 2
    fi
    pool-host-client "${pool[@]}" -o json attachments --device "$1" || command-error "cannot list the attachments of $1"
}

pool-device-files() { # script API
    # Usage: pool-device-files [--pool NAME] DEVICE
    #
    # Set POOL_DEVICE_DATA to the backing file of DEVICE on the server NAME
    # (default: the first started server) on the host (path in the server's
    # JSON of the device) and POOL_DEVICE_LSA to its label storage area
    # file (lsaPath; "" for a volatile device). COMMAND_OUTPUT has the JSON
    # of the device. Fail the test if the server does not know DEVICE, or
    # if a persistent device has no LSA file.
    local pool=() dev
    if [ "$1" == "--pool" ]; then
        pool=(--pool "$2")
        shift 2
    fi
    dev="$1"
    pool-host-client "${pool[@]}" -o json devices "$dev" || command-error "cannot get $dev"
    POOL_DEVICE_DATA=$(pool-value "$COMMAND_OUTPUT" 'j.get("path") or ""')
    POOL_DEVICE_LSA=$(pool-value "$COMMAND_OUTPUT" 'j.get("lsaPath") or ""')
    [ -n "$POOL_DEVICE_DATA" ] || error "pool-device-files: $dev has no backing file"
    if [ "$(pool-value "$COMMAND_OUTPUT" 'j.get("persistent") is True')" == True ]; then
        [ -n "$POOL_DEVICE_LSA" ] || error "pool-device-files: the persistent device $dev has no lsaPath"
    fi
    echo "pool-device-files: $dev: data $POOL_DEVICE_DATA, LSA ${POOL_DEVICE_LSA:-none}"
}

pool-device-free-wait() { # script API
    # Usage: pool-device-free-wait [--pool NAME] DEVICE VMDIR...
    #
    # Wait until the VMs of VMDIRs have no CXL memory devices, 60 s at most
    # each (pool-cxl-wait, label DEVICE-released), then until DEVICE is
    # free and attached nowhere in the server NAME (default: the first
    # started server), 60 s at most. Fail the test on timeout.
    local pool=() dev vmdir
    if [ "$1" == "--pool" ]; then
        pool=(--pool "$2")
        shift 2
    fi
    dev="$1"
    shift
    for vmdir in "$@"; do
        pool-cxl-wait "$vmdir" "$dev-released" "memdevs == []" 60
    done
    retry-until --timeout 60 --message "$dev free" \
        'pool-host-client "${pool[@]}" -o json devices "$dev" >/dev/null && pool-py assert "$COMMAND_OUTPUT" "j[\"state\"] == \"free\" and j[\"attachments\"] in (None, [])"' ||
        error "$dev is not free: $COMMAND_OUTPUT"
}

pool-snapshot() { # script API
    # Usage: pool-snapshot LABEL
    #
    # Store what every server says about its hosts, devices and attachments
    # to $TEST_OUTPUT_DIR/pool.LABEL.json for the server of the default
    # name (or a server that this test did not start), and to
    # pool.LABEL.NAME.json for the server NAME of another name.
    local label="$1" name names=("") out url
    [ "${#POOL_SERVERS[@]}" -eq 0 ] || names=("${POOL_SERVERS[@]}")
    for name in "${names[@]}"; do
        out="$TEST_OUTPUT_DIR/pool.$label.json"
        url="$POOL_URL"
        if [ -n "$name" ]; then
            url=$(pool-url "$name")
            [ "$name" == "$POOL_DEFAULT_NAME" ] || out="$TEST_OUTPUT_DIR/pool.$label.$name.json"
        fi
        {
            echo '{"hosts":'
            curl -sS --max-time 30 "$url/api/v1/hosts"
            echo ',"devices":'
            curl -sS --max-time 30 "$url/api/v1/devices"
            echo ',"attachments":'
            curl -sS --max-time 30 "$url/api/v1/attachments"
            echo '}'
        } > "$out" || error "pool-snapshot: cannot query the server ${name:-at $url}"
        echo "pool-snapshot $label${name:+ ($name)}: $out"
    done
}

pool-py() {
    # Usage: pool-py assert|eval JSON EXPRESSION
    #
    # Evaluate the Python EXPRESSION with the JSON document parsed as j.
    python3 -c '
import json, sys
mode, expression = sys.argv[1], sys.argv[2]
text = sys.stdin.read()
try:
    j = json.loads(text)
except ValueError as e:
    print("pool-py: invalid JSON (%s): %s" % (e, text[:2000]), file=sys.stderr)
    sys.exit(2)
value = eval(expression)
if mode == "eval":
    print(value)
    sys.exit(0)
sys.exit(0 if value else 1)
' "$1" "$3" <<< "$2"
}

pool-assert() { # script API
    # Usage: pool-assert JSON EXPRESSION
    #
    # Fail the test unless the Python EXPRESSION is true. The JSON document,
    # for instance the output of "fake-cxl-pool-client -o json ...", is j in
    # EXPRESSION.
    pool-py assert "$1" "$2" ||
        error "fake-cxl-pool assertion failed: $2
on: $(head -c 3000 <<< "$1")"
    echo "fake-cxl-pool ok: $2"
}

pool-value() { # script API
    # Usage: pool-value JSON EXPRESSION
    #
    # Print the value of the Python EXPRESSION on the JSON document j.
    pool-py eval "$1" "$2" || error "fake-cxl-pool expression failed: $2"
}

pool-file-string() { # script API
    # Usage: pool-file-string FILE OFFSET
    #
    # Print the NUL-terminated string at byte OFFSET of the host FILE, for
    # instance of the backing file of a device.
    python3 -c '
import sys
with open(sys.argv[1], "rb") as f:
    f.seek(int(sys.argv[2], 0))
    print(f.read(4096).split(b"\0", 1)[0].decode(errors="replace"))' "$1" "$2"
}
