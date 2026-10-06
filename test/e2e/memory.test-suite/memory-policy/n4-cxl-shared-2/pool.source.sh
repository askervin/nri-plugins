# Helpers for testing CXL memory pooling and sharing with fake-cxl-pool
# (scripts/testing/fake-cxl-pool) in the VMs of n4-cxl-shared-1 and
# n4-cxl-shared-2.
#
# fake-cxl-pool-server runs on the host, next to qemu, and hotplugs CXL
# memory devices into running VMs over their QMP sockets. Tests run
# fake-cxl-pool-client in the VMs. The test runs against the VM of
# n4-cxl-shared-2 (vm-command, "VM2") and drives the VM of n4-cxl-shared-1
# ("VM1") over ssh from the host: the VMs reach the host at 192.168.76.2,
# the slirp gateway, but not each other.
#
# The helpers that work on either VM take the output directory of the VM,
# VMDIR: $OUTPUT_DIR for VM2, $POOL_VM1_DIR for VM1.

POOL_SRC_DIR="$nri_resource_policy_src/scripts/testing/fake-cxl-pool"
POOL_BIN_DIR="$POOL_SRC_DIR/bin"
POOL_HELPER_DIR="$(dirname "${BASH_SOURCE[0]}")"
POOL_DIR="/tmp/fake-cxl-pool"                   # pool of device backing files
POOL_PORT="${FAKE_CXL_POOL_PORT:-9909}"
POOL_URL="http://127.0.0.1:$POOL_PORT"          # the server, seen from the host
POOL_GUEST_URL="http://192.168.76.2:$POOL_PORT" # the server, seen from the VMs
POOL_VM2_DIR="$OUTPUT_DIR"
POOL_VM2_NAME="$VM_HOSTNAME"
# The VM of n4-cxl-shared-1 with the same distro and runtime as this one.
POOL_VM1_DIR="${POOL_VM1_DIR:-$(dirname "$OUTPUT_DIR")/n4-cxl-shared-1${VM_HOSTNAME#"$(basename "$TOPOLOGY_DIR")"}}"
POOL_VM1_NAME="$(basename "$POOL_VM1_DIR")"
POOL_SERVER_PID=""
POOL_SERVER_LOG=""

pool-vm-label() {
    # Usage: pool-vm-label VMDIR
    #
    # Print the short name of a VM in prompts and file names: vm for the
    # VM of the test, vm1 for the VM of n4-cxl-shared-1.
    case "$1" in
        "$POOL_VM2_DIR") echo "vm";;
        "$POOL_VM1_DIR") echo "vm1";;
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
        *) return 1;;
    esac
}

other-vm-command() { # script API
    # Usage: other-vm-command VMDIR COMMAND
    #
    # Execute COMMAND as root in the VM of the output directory VMDIR, which
    # is not the VM of the test, the way vm-command does in the VM of the
    # test: print the command and its output, set COMMAND_OUTPUT and
    # COMMAND_STATUS and return the exit status of COMMAND.
    local vmdir="$1" label
    label="$(pool-vm-label "$vmdir")"
    command-start "$label" "\e[38;5;13mroot@$label>\e[0m " "$2"
    ssh -F "$vmdir/.ssh-config" node sudo bash -l <<<"$COMMAND" 2>&1 | command-handle-output
    command-end "${PIPESTATUS[0]}"
    return "$COMMAND_STATUS"
}

other-vm-command-q() {
    # Usage: other-vm-command-q VMDIR COMMAND
    #
    # Execute COMMAND as root in the VM of VMDIR quietly, like vm-command-q.
    ssh -F "$1/.ssh-config" node sudo bash -l <<<"$2"
}

other-vm-put-file() { # script API
    # Usage: other-vm-put-file VMDIR SRC-HOST-FILE DST-VM-FILE
    #
    # Copy a file from the host to the VM of VMDIR, like vm-put-file.
    local vmdir="$1" src="$2" dst="$3" tmp
    tmp="vm-put-file.${src##*/}"
    host-command "scp -F \"$vmdir/.ssh-config\" \"$src\" node:\"$tmp\"" ||
        command-error "failed to copy $src to $(basename "$vmdir")"
    other-vm-command "$vmdir" "mkdir -p \"$(dirname "$dst")\" && mv \"$tmp\" \"$dst\"" ||
        command-error "failed to move $src to $dst in $(basename "$vmdir")"
}

pool-vm-command() { # script API
    # Usage: pool-vm-command VMDIR COMMAND
    #
    # vm-command in the VM of VMDIR: the VM of the test or another one.
    if [ "$1" == "$OUTPUT_DIR" ]; then
        vm-command "$2"
    else
        other-vm-command "$1" "$2"
    fi
}

pool-vm-command-q() {
    # Usage: pool-vm-command-q VMDIR COMMAND
    if [ "$1" == "$OUTPUT_DIR" ]; then
        vm-command-q "$2"
    else
        other-vm-command-q "$1" "$2"
    fi
}

pool-vm-put-file() { # script API
    # Usage: pool-vm-put-file VMDIR SRC-HOST-FILE DST-VM-FILE
    if [ "$1" == "$OUTPUT_DIR" ]; then
        vm-put-file "$2" "$3"
    else
        other-vm-put-file "$1" "$2" "$3"
    fi
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
    local vmdir="$1"
    retry-until --timeout "${2:-180}" --interval 2 --message "ssh to $(basename "$vmdir")" \
        '[ -f "$vmdir/.ssh-config" ] && command timeout 15 ssh -F "$vmdir/.ssh-config" -o ConnectTimeout=5 node true'
}

pool-vagrant-up() {
    # Usage: pool-vagrant-up VMDIR
    #
    # Start the existing VM of VMDIR without provisioning it, the way
    # vm-setup does, and wait for ssh.
    local vmdir="$1"
    ( cd "$vmdir" || exit 1
      # qemu creates the backing files of file-backed memory, not their
      # directories, and /tmp may have been emptied since VM creation.
      for mem_path in $(grep -o 'mem-path=[^,"]*' Vagrantfile | sed 's/^mem-path=//'); do
          mkdir -p "$(dirname "$mem_path")" || exit 1
      done
      vagrant up --no-provision --provider qemu || exit 1
      if [ ! -f .ssh-config ]; then
          vagrant ssh-config > .ssh-config || exit 1
          printf '  ControlMaster auto\n  ControlPersist 60\n  ControlPath /tmp/ssh-%%C\n' >> .ssh-config
          sed -i 's/^Host /Host node /' .ssh-config
      fi
    ) || error "cannot start the VM in $vmdir with vagrant up --no-provision"
    pool-vm-ssh-wait "$vmdir" || error "ssh to the VM in $vmdir does not work after vagrant up"
}

pool-host-wait() { # script API
    # Usage: pool-host-wait VMDIR HINT
    #
    # Make sure that the VM of VMDIR is up. Start it if it is not. Fail
    # with HINT, how to create the VM, if there is no VM in VMDIR.
    local vmdir="$1" hint="$2" name
    name="$(basename "$vmdir")"
    [ -f "$vmdir/Vagrantfile" ] && [ -d "$vmdir/.vagrant" ] ||
        error "no VM $name in $vmdir: $hint"
    if [ -f "$vmdir/.ssh-config" ] && command timeout 30 ssh -F "$vmdir/.ssh-config" -o ConnectTimeout=5 node true; then
        echo "pool-host-wait: $name is up"
    else
        echo "pool-host-wait: $name is not reachable, starting it"
        pool-vagrant-up "$vmdir"
    fi
    pool-vm-command "$vmdir" "hostname" || command-error "cannot run commands in $name"
    [ "$COMMAND_OUTPUT" == "$name" ] ||
        error "the VM in $vmdir calls itself $COMMAND_OUTPUT, expected $name"
}

pool-vm-restart() { # script API
    # Usage: pool-vm-restart VMDIR
    #
    # Restart qemu of the VM of VMDIR. That is the only way to get rid of a
    # CXL memory device that qemu cannot delete (a zombie device of a detach
    # without release).
    local vmdir="$1" name i
    name="$(basename "$vmdir")"
    if [ "$vmdir" == "$OUTPUT_DIR" ]; then
        timeout=300 vm-reboot || error "cannot restart $name"
        return 0
    fi
    other-vm-command "$vmdir" "sync; shutdown -h 0" || :
    for i in $(seq 60); do
        (cd "$vmdir" && vagrant status 2>/dev/null | grep -q running) || break
        sleep 2
    done
    if (cd "$vmdir" && vagrant status 2>/dev/null | grep -q running); then
        echo "pool-vm-restart: $name did not shut down, vagrant halt"
        (cd "$vmdir" && vagrant halt) || :
        for i in $(seq 30); do
            (cd "$vmdir" && vagrant status 2>/dev/null | grep -q running) || break
            sleep 2
        done
        (cd "$vmdir" && vagrant status 2>/dev/null | grep -q running) &&
            error "cannot stop $name, stop it by hand"
    fi
    echo "pool-vm-restart: $name stopped, starting it"
    pool-vagrant-up "$vmdir"
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
  qemu_bin=\$HOME/github.com/qemu/qemu/build/qemu-system-x86_64 ./run_tests.sh memory.test-suite/memory-policy/$topology/test00-up"
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

pool-vm-reset() { # script API
    # Usage: pool-vm-reset VMDIR
    #
    # Make sure that the VM of VMDIR has no CXL memory devices, neither in
    # qemu nor in the kernel, and that hotplugged memory is not onlined
    # automatically: onlined shared memory would be system RAM of several
    # VMs at once. Restart the VM if it has devices.
    local vmdir="$1" name plugged guest_devs
    name="$(basename "$vmdir")"
    plugged=$(pool-vm-monitor "$vmdir" "info qtree -b" | grep -c 'dev: cxl-type3')
    guest_devs=$(pool-vm-command-q "$vmdir" "ls /sys/bus/cxl/devices/" | grep -cE '^(mem|region)[0-9]')
    if [ "$plugged" != "0" ] || [ "$guest_devs" != "0" ]; then
        echo "pool-vm-reset: $name has $plugged CXL memory devices in qemu, $guest_devs CXL memory devices or regions in the kernel: restarting it"
        pool-vm-restart "$vmdir"
        plugged=$(pool-vm-monitor "$vmdir" "info qtree -b" | grep -c 'dev: cxl-type3')
        [ "$plugged" == "0" ] || error "pool-vm-reset: $name still has $plugged CXL memory devices after restart"
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
    # Usage: pool-port-busy
    #
    # Return 0 if something listens on the port of the server.
    (exec 3<>"/dev/tcp/127.0.0.1/$POOL_PORT") 2>/dev/null
}

pool-server-start() { # script API
    # Usage: pool-server-start [DEVICES]
    #
    # Build fake-cxl-pool and start fake-cxl-pool-server on the host, on
    # 127.0.0.1:$POOL_PORT (9909, or $FAKE_CXL_POOL_PORT). DEVICES is the
    # YAML list of the static devices of the server, the value of
    # "devices:" in its configuration. The configuration
    # (fake-cxl-pool.yaml), the state (fake-cxl-pool.state.json, removed
    # first: every server starts empty) and the log
    # (fake-cxl-pool-server.log) are in $TEST_OUTPUT_DIR.
    #
    # The server discovers only the VMs of n4-cxl-shared-1 and -2, so that
    # it never connects to the monitors of other VMs on the host. Fail if
    # the port is busy, for instance by a server that someone else runs:
    # one server at a time can use the QMP sockets of the VMs.
    #
    # Set an EXIT trap that detaches the devices that the test left attached
    # and stops the server (pool-cleanup).
    local devices="${1:- []}" config state
    [ -z "$POOL_SERVER_PID" ] || error "pool-server-start: the server is running already, pid $POOL_SERVER_PID"
    host-command "make -C \"$POOL_SRC_DIR\"" || command-error "cannot build fake-cxl-pool"
    if pool-port-busy; then
        error "port $POOL_PORT is busy, is another fake-cxl-pool-server running? ($(ss -ltnpH "sport = :$POOL_PORT" 2>/dev/null)) Stop it, or set FAKE_CXL_POOL_PORT"
    fi
    config="$TEST_OUTPUT_DIR/fake-cxl-pool.yaml"
    state="$TEST_OUTPUT_DIR/fake-cxl-pool.state.json"
    POOL_SERVER_LOG="$TEST_OUTPUT_DIR/fake-cxl-pool-server.log"
    rm -f "$state" "$state".*
    cat > "$config" <<EOF
# fake-cxl-pool-server configuration of $(basename "$TEST_DIR"), written by pool-server-start
listen: 127.0.0.1:$POOL_PORT
pools:
  - name: default
    dir: $POOL_DIR
    capacity: 8G
    sharable: true
devices:$devices
discovery:
  qemu: true
  interval: 10s
  names: ["$POOL_VM1_NAME", "$POOL_VM2_NAME"]
  localDevices: true
detachTimeout: 15s
EOF
    echo "pool-server-start: configuration $config:"
    cat "$config"
    "$POOL_BIN_DIR/fake-cxl-pool-server" -config "$config" -state "$state" -v \
        </dev/null >"$POOL_SERVER_LOG" 2>&1 &
    POOL_SERVER_PID=$!
    trap pool-cleanup EXIT
    echo "pool-server-start: fake-cxl-pool-server pid $POOL_SERVER_PID, log $POOL_SERVER_LOG"
    # The server discovers the VMs and connects to their QMP sockets before
    # it serves the first request.
    retry-until --timeout 60 --message "fake-cxl-pool-server on $POOL_URL" \
        'kill -0 "$POOL_SERVER_PID" 2>/dev/null && curl -sf --max-time 5 "$POOL_URL/api/v1/status" >/dev/null' || {
        cat "$POOL_SERVER_LOG"
        error "fake-cxl-pool-server did not start, see $POOL_SERVER_LOG"
    }
    host-command "curl -sS --max-time 30 $POOL_URL/api/v1/status" ||
        command-error "cannot get the status of the server"
}

pool-server-stop() { # script API
    # Usage: pool-server-stop
    #
    # Stop the server that pool-server-start started.
    local i
    [ -n "$POOL_SERVER_PID" ] || return 0
    kill -TERM "$POOL_SERVER_PID" 2>/dev/null
    for i in $(seq 20); do
        kill -0 "$POOL_SERVER_PID" 2>/dev/null || break
        sleep 0.5
    done
    if kill -0 "$POOL_SERVER_PID" 2>/dev/null; then
        echo "pool-server-stop: server pid $POOL_SERVER_PID did not stop in 10s, killing it"
        kill -KILL "$POOL_SERVER_PID" 2>/dev/null
    fi
    wait "$POOL_SERVER_PID" 2>/dev/null
    echo "pool-server-stop: stopped fake-cxl-pool-server pid $POOL_SERVER_PID"
    POOL_SERVER_PID=""
}

pool-cleanup() {
    # Usage: pool-cleanup
    #
    # The EXIT trap of pool-server-start. If the test left devices attached,
    # release them in the VMs and detach them, so that the next test finds
    # VMs without devices, delete the devices the test created, and stop the
    # server.
    local atts devs lines line dev host serial vmdir
    if [ -n "$POOL_SERVER_PID" ] && kill -0 "$POOL_SERVER_PID" 2>/dev/null; then
        atts=$(curl -s --max-time 30 "$POOL_URL/api/v1/attachments" | python3 -c '
import json, sys
for a in json.load(sys.stdin) or []:
    if not a.get("adopted"):
        print(a["device"], a["host"], a["serial"])' 2>/dev/null)
        if [ -n "$atts" ]; then
            echo "pool-cleanup: detaching devices left attached:"
            echo "$atts"
            mapfile -t lines <<< "$atts"
            for line in "${lines[@]}"; do
                read -r dev host serial <<< "$line"
                vmdir=$(pool-vm-dir "$host") || continue
                pool-vm-command "$vmdir" "fake-cxl-pool-client guest release $serial"
                pool-host-client detach "$dev" --host "$host"
            done
        fi
        devs=$(curl -s --max-time 30 "$POOL_URL/api/v1/devices?scope=pool" | python3 -c '
import json, sys
for d in json.load(sys.stdin) or []:
    if not d.get("static"):
        print(d["name"])' 2>/dev/null)
        for dev in $devs; do
            pool-host-client delete "$dev" --force
        done
    fi
    pool-server-stop
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
    # Usage: pool-client VMDIR [-o json] COMMAND [ARGS...]
    #
    # Run fake-cxl-pool-client as root in the VM of VMDIR, connected to the
    # server of the test. Return its exit status: 0 ok, 1 error, 2 usage,
    # 3 conflict or timeout. COMMAND_OUTPUT has what it printed.
    local vmdir="$1" server=""
    shift
    [ "$POOL_PORT" == "9909" ] || server=" --server $POOL_GUEST_URL"
    pool-vm-command "$vmdir" "fake-cxl-pool-client$server$(printf ' %q' "$@")"
}

pool-host-client() { # script API
    # Usage: pool-host-client [-o json] COMMAND [ARGS...]
    #
    # Run fake-cxl-pool-client on the host, connected to the server of the
    # test.
    host-command "$POOL_BIN_DIR/fake-cxl-pool-client --server $POOL_URL$(printf ' %q' "$@")"
}

pool-snapshot() { # script API
    # Usage: pool-snapshot LABEL
    #
    # Store what the server says about its hosts, devices and attachments
    # to $TEST_OUTPUT_DIR/pool.LABEL.json.
    local label="$1" out
    out="$TEST_OUTPUT_DIR/pool.$label.json"
    {
        echo '{"hosts":'
        curl -sS --max-time 30 "$POOL_URL/api/v1/hosts"
        echo ',"devices":'
        curl -sS --max-time 30 "$POOL_URL/api/v1/devices"
        echo ',"attachments":'
        curl -sS --max-time 30 "$POOL_URL/api/v1/attachments"
        echo '}'
    } > "$out" || error "pool-snapshot: cannot query the server"
    echo "pool-snapshot $label: $out"
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
