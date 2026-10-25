# The executor of test90-gofmbt-reliability (plan-13 of fake-cxl-pool,
# scripts/testing/fake-cxl-pool/plan-13-gofmbt/04-contract.txt): the
# actions of the model mbt-cxl on the cluster of test19-many-pools, the
# settle observation, and the line protocol with mbt-cxl, on-line (a
# coprocess) and off-line (a generated code.gen.sh).
#
# The framework sources this file for this test only (a test-level
# *.source* file), after dra.source.sh and pool.source.sh.
#
# Names (contract 1-3): the VM ids vm2 (the VM of the test, the control
# plane), vm1 and vm0; the pool ids a, b and c (servers pool-a, pool-b
# and pool-c); slots KIND@VM#I, KIND one of the kinds of contract 2, VM a
# VM id or "any"; a slot holds at most one pod, mbt-KIND-VM-I-g<gen>, with
# the label mbt.slot=KIND_VM_I and the claim c0 from the
# ResourceClaimTemplate mbt-KIND.
#
# Every action is a function mbt-act-<verb> that sets MBT_STATUS (via its
# return value), MBT_RESULT (the done JSON of contract 6.2) and MBT_NOTE
# (a word for the test output); mbt-run runs one, mbt-observe makes the
# settle observation (mbt-observe.py in each VM and on the host). Output:
# one "### mbt step N: VERB ARGS" line and one result line per step; the
# commands and their output go to $TEST_OUTPUT_DIR/mbt-exec.log, the
# observations to $TEST_OUTPUT_DIR/mbt-obs/ (the last MBT_OBS_KEEP, and
# fail-N.json of a failed step), the time of every step to
# mbt-times.tsv and of every observation to mbt-obs-times.tsv.

MBT_HELPER_DIR="$(dirname "${BASH_SOURCE[0]}")"
MBT_OBSERVER="$MBT_HELPER_DIR/mbt-observe.py"   # the observer, on the host
MBT_OBSERVER_VM=/usr/local/bin/mbt-observe.py   # and in the VMs (mbt-observer-install)
MBT_SLOT_LABEL=mbt.slot
MBT_PAUSE_IMAGE=registry.k8s.io/pause:3.10      # the image of the companion pods of leases
MBT_LOCAL_SERIAL=0xc100e2e1                     # the local memdev of every VM
MBT_LOCAL_HEX=C100E2E1
MBT_SLICE=128Mi                                 # a local claim or lease
MBT_LEASE_WAIT=60s                              # cxl-request request --wait
MBT_EXEC_TIMEOUT=150                            # seconds of a kubectl exec in a pod
MBT_EXEC_RETRY=30                               # seconds to retry a kubectl exec that cannot connect
MBT_READ_TIMEOUT="${MBT_READ_TIMEOUT:-900}"     # seconds to wait for a line of the generator
MBT_OBS_KEEP="${MBT_OBS_KEEP:-30}"              # observations kept in mbt-obs/
MBT_OBS_TIMEOUT="${MBT_OBS_TIMEOUT:-60}"        # seconds of one VM's part of an observation
MBT_NRI_RESTART_WAIT=60                         # containerd-restart: seconds to wait for the driver's restart
MBT_DRIVER_READY_WAIT="${MBT_DRIVER_READY_WAIT:-120}"   # seconds to wait for a driver to be ready (mbt-driver-ready)
MBT_LENDS_RESTORED="NRI fence: lends restored"  # the driver's log line when NRI and lending are up
MBT_POLL="${MBT_POLL:-3}"                       # seconds between settle observations
MBT_SETTLE_TIMEOUT="${MBT_SETTLE_TIMEOUT:-180}" # off-line: seconds of a settle (on-line: Go's)
MBT_VMIDS=(vm2 vm1 vm0)
MBT_POOL_IDS=(a b c)
declare -A MBT_POOL_SERVER=([a]=pool-a [b]=pool-b [c]=pool-c)
declare -A MBT_POOLED_SERIAL=([a]=0xc1ee0001 [b]=0xc1ee1001 [c]=0xc1ee2001)
declare -A MBT_SHARED_SERIAL=([a]=0xc1ae0001 [b]=0xc1ae1001 [c]=0xc1ae2001)
declare -A MBT_VMDIR=()            # VM id -> VMDIR (mbt-setup-ids)
declare -A MBT_NODE=()             # VM id -> Kubernetes node name
declare -A MBT_POOL_UNIT=()        # pool id -> systemd unit of its controller
MBT_NODES=""                       # "vm2=NODE,vm1=NODE,vm0=NODE"
MBT_UNITS=""                       # "a=UNIT,b=UNIT,c=UNIT"
MBT_POOLS=""                       # "a=pool-a,b=pool-b,c=pool-c": pool id -> DRA pool (server) name
declare -A MBT_GEN=()              # slot -> generation of its last pod, 0: none yet
declare -A MBT_DRIVER_SEEN=()      # VM id -> "POD RESTARTS" of its driver at the last observation
declare -A MBT_TRACE_REFOLLOW=()   # VM id -> time (RFC 3339) to follow the driver log from again
MBT_TMP=""                         # work files
MBT_OBS_DIR=""                     # observations
MBT_OBS_FILES=()                   # the files of the observations kept, oldest first
MBT_EXEC_LOG=""                    # the commands of every step and their output
MBT_TIMES=""                       # step, verb, args, status, seconds, observations
MBT_OBS_TIMES=""                   # step, poll, seconds of every observation
MBT_LOG=""                         # stderr of the generator (mbt-cxl.log)
MBT_BIN="${MBT_BIN:-}"            # the generator: mbt-cxl, the stub, or what the user exported
MBT_GEN_PID=""                     # the coprocess MBTGEN: its pid
MBT_RFD=""                         # and a copy of its stdout that outlives it
MBT_LINE=""                        # mbt-recv: the last line of the generator
MBT_STATUS=0                       # mbt-run: the exit status of the step,
MBT_RESULT='{}'                    # its done JSON,
MBT_NOTE=""                        # and a note for the output
MBT_OUT=""                         # mbt-sh: stdout of the command,
MBT_ERR=""                         # and its stderr
MBT_OBS=""                         # mbt-observe: the settle observation (one JSON line),
MBT_OBS_FILE=""                    # its file,
MBT_OBS_SECONDS=""                 # and how long it took
MBT_KIND="" MBT_BASE="" MBT_POOL="" MBT_SVM="" MBT_SIDX="" MBT_SLABEL="" MBT_SPOD=""  # mbt-slot
MBT_LAST_STEP="" MBT_LAST_VERB="" MBT_LAST_DONE=""   # off-line: the last mbt-step,
MBT_LAST_STATUS=0 MBT_LAST_CHECKED=1                 # its status, and whether an mbt-expect checked it

# The main process of every pod: a shell whose child is the workload. The
# shell is PID 1 of the container, which ignores SIGSEGV from outside, so a
# crash is a SIGSEGV to the child: the shell exits with its status, 139,
# and the container restarts (restartPolicy Always). SIGTERM (pod deleted)
# ends it with 0.
MBT_WORKLOAD='trap "exit 0" TERM
sleep infinity &
echo $! > /tmp/workload.pid
wait $!
exit $?'

###
### Names
###

mbt-setup-ids() { # script API
    # Usage: mbt-setup-ids VM2DIR VM1DIR VM0DIR
    #
    # Map the VM ids of the model to the VMDIRs and the Kubernetes node
    # names, the pool ids to the units of their controllers (as
    # dra-install names them for pool-a, pool-b and pool-c started in this
    # order), and create the work and output files of the executor in
    # $TEST_OUTPUT_DIR (those of an earlier run are removed).
    local vm
    MBT_VMDIR=([vm2]="$1" [vm1]="$2" [vm0]="$3")
    MBT_NODES=""
    for vm in "${MBT_VMIDS[@]}"; do
        MBT_NODE[$vm]=$(dra-vm-name "${MBT_VMDIR[$vm]}")
        MBT_NODES+="${MBT_NODES:+,}$vm=${MBT_NODE[$vm]}"
    done
    MBT_POOL_UNIT=([a]="$DRA_CONTROLLER_UNIT" [b]="$DRA_CONTROLLER_UNIT-pool-b" [c]="$DRA_CONTROLLER_UNIT-pool-c")
    MBT_UNITS="a=${MBT_POOL_UNIT[a]},b=${MBT_POOL_UNIT[b]},c=${MBT_POOL_UNIT[c]}"
    MBT_POOLS="a=${MBT_POOL_SERVER[a]},b=${MBT_POOL_SERVER[b]},c=${MBT_POOL_SERVER[c]}"
    MBT_TMP="$TEST_OUTPUT_DIR/mbt-tmp"
    MBT_OBS_DIR="$TEST_OUTPUT_DIR/mbt-obs"
    MBT_EXEC_LOG="$TEST_OUTPUT_DIR/mbt-exec.log"
    MBT_TIMES="$TEST_OUTPUT_DIR/mbt-times.tsv"
    MBT_OBS_TIMES="$TEST_OUTPUT_DIR/mbt-obs-times.tsv"
    MBT_LOG="$TEST_OUTPUT_DIR/mbt-cxl.log"
    # The output directory of a test is reused: files of an earlier run
    # would pass for this one's.
    rm -rf "$MBT_TMP" "$MBT_OBS_DIR" "$TEST_OUTPUT_DIR/mbt-fail.txt" "$TEST_OUTPUT_DIR/mbt-steps.txt" \
        "$TEST_OUTPUT_DIR/$DRA_CONTAINER".*.log
    mkdir -p "$MBT_TMP" "$MBT_OBS_DIR" || error "mbt-setup-ids: cannot create $MBT_TMP and $MBT_OBS_DIR"
    : > "$MBT_TMP/inspected"
    : > "$MBT_EXEC_LOG"
    : > "$MBT_LOG"
    printf 'step\tverb\targs\tstatus\tseconds\tobservations\n' > "$MBT_TIMES"
    printf 'step\tpoll\tseconds\n' > "$MBT_OBS_TIMES"
    MBT_GEN=() MBT_DRIVER_SEEN=() MBT_TRACE_REFOLLOW=() MBT_OBS_FILES=()
}

mbt-slot() {
    # Usage: mbt-slot SLOT
    #
    # Parse SLOT (KIND@VM#I) into MBT_KIND (sdax-a), MBT_BASE (sdax),
    # MBT_POOL (a, "" for kinds without a pool), MBT_SVM (vm1, or any),
    # MBT_SIDX (I), MBT_SLABEL (its label value, sdax-a_vm1_0) and MBT_SPOD
    # (its pod name without the generation, mbt-sdax-a-vm1-0). Return 2 if
    # SLOT is not a slot.
    local re='^((xnuma|xdax|sdax|sro|sexcl)-([abc])|lnuma|ldax|lsteer|lease|plain)@(vm[012]|any)#([0-9]+)$'
    [[ "$1" =~ $re ]] || { MBT_ERR="not a slot: '$1'"; return 2; }
    MBT_KIND=${BASH_REMATCH[1]}
    MBT_POOL=${BASH_REMATCH[3]}
    MBT_BASE=${BASH_REMATCH[2]:-$MBT_KIND}
    MBT_SVM=${BASH_REMATCH[4]}
    MBT_SIDX=${BASH_REMATCH[5]}
    MBT_SLABEL="${MBT_KIND}_${MBT_SVM}_${MBT_SIDX}"
    MBT_SPOD="mbt-$MBT_KIND-$MBT_SVM-$MBT_SIDX"
}

mbt-slot-pod() {
    # Usage: mbt-slot-pod SLOT
    #
    # mbt-slot SLOT, and print the name of the pod of its last generation.
    # Return 2 if SLOT is not a slot or has had no pod yet (in $(...) the
    # reason is lost: mbt-slot-has-pod sets MBT_ERR).
    mbt-slot-has-pod "$1" || return 2
    echo "$MBT_SPOD-g${MBT_GEN[$1]}"
}

mbt-slot-has-pod() {
    # Usage: mbt-slot-has-pod SLOT
    #
    # mbt-slot SLOT; return 2, with MBT_ERR, if it is not a slot or has had
    # no pod yet.
    mbt-slot "$1" || return 2
    [ "${MBT_GEN[$1]:-0}" -gt 0 ] || { MBT_ERR="slot $1 has had no pod"; return 2; }
}

mbt-vm-arg() {
    # Usage: mbt-vm-arg VM
    #
    # Return 2 unless VM is a VM id.
    [ -n "${MBT_VMDIR[$1]:-}" ] || { MBT_ERR="not a VM id: '$1'"; return 2; }
}

mbt-pool-arg() {
    # Usage: mbt-pool-arg POOL
    #
    # Return 2 unless POOL is a pool id.
    [ -n "${MBT_POOL_SERVER[$1]:-}" ] || { MBT_ERR="not a pool id: '$1'"; return 2; }
}

mbt-dax-key() {
    # Usage: mbt-dax-key
    #
    # Print the key of the environment of the device of the kind of the
    # last mbt-slot (CXL_<KEY>_DAX), for the kinds with a dax device.
    # Return 2 for the others.
    local serial
    case "$MBT_BASE" in
        xdax) serial=${MBT_POOLED_SERIAL[$MBT_POOL]};;
        sdax|sro|sexcl) serial=${MBT_SHARED_SERIAL[$MBT_POOL]};;
        ldax) serial=$MBT_LOCAL_SERIAL;;
        *) MBT_ERR="$MBT_KIND has no dax device"; return 2;;
    esac
    serial=${serial#0x}
    echo "${serial^^}"
}

###
### YAML
###

mbt-claim-to-template() {
    # Usage: mbt-claim-to-template NAME <<< CLAIM-YAML
    #
    # Print the ResourceClaimTemplate NAME whose claims are the
    # ResourceClaim of CLAIM-YAML (dra-shared-claim-yaml, for instance).
    awk -v name="$1" '
        /^kind: ResourceClaim$/ { print "kind: ResourceClaimTemplate"; next }
        /^metadata:$/ { meta = 1; print; next }
        meta && /^  name:/ { print "  name: " name; meta = 0; next }
        /^spec:$/ { print "spec:"; print "  spec:"; spec = 1; next }
        spec { print "  " $0; next }
        { print }'
}

mbt-template-yaml() {
    # Usage: mbt-template-yaml KIND
    #
    # Print the ResourceClaimTemplate mbt-KIND of the claim of the kind
    # KIND (contract 2): pool devices by serial, local slices of
    # $MBT_SLICE of class cxl-local, the lease claim.
    local kind="$1" pool="${1##*-}"
    case "$kind" in
        xnuma-?) dra-shared-claim-yaml x "${MBT_POOLED_SERIAL[$pool]}" "" "" cxl-pool | mbt-claim-to-template "mbt-$kind";;
        xdax-?) dra-shared-claim-yaml x "${MBT_POOLED_SERIAL[$pool]}" "" "mode: dax" cxl-pool | mbt-claim-to-template "mbt-$kind";;
        sdax-?) dra-shared-claim-yaml x "${MBT_SHARED_SERIAL[$pool]}" 1 "mode: dax" | mbt-claim-to-template "mbt-$kind";;
        sro-?) dra-shared-claim-yaml x "${MBT_SHARED_SERIAL[$pool]}" 1 "mode: dax, readOnly: true" | mbt-claim-to-template "mbt-$kind";;
        sexcl-?) dra-shared-claim-yaml x "${MBT_SHARED_SERIAL[$pool]}" "" "mode: dax" | mbt-claim-to-template "mbt-$kind";;
        lnuma) dra-claim-yaml template mbt-lnuma cxl-local "$MBT_SLICE";;
        ldax) dra-claim-yaml template mbt-ldax cxl-local "$MBT_SLICE" dax;;
        lsteer) dra-claim-yaml template mbt-lsteer cxl-local "$MBT_SLICE" "container=steering: {policy: auto}";;
        lease) dra-lease-template-yaml mbt-lease;;
        *) return 2;;
    esac
}

mbt-templates-apply() { # script API
    # Usage: mbt-templates-apply
    #
    # Create the ResourceClaimTemplates of every kind and pool in $DRA_NS
    # (19 of them, mbt-xnuma-a ... mbt-lease). Fail the test if kubectl
    # fails.
    local yaml="" kind pool base
    for pool in "${MBT_POOL_IDS[@]}"; do
        for base in xnuma xdax sdax sro sexcl; do
            yaml+="${yaml:+
---
}$(mbt-template-yaml "$base-$pool")"
        done
    done
    for kind in lnuma ldax lsteer lease; do
        yaml+="
---
$(mbt-template-yaml "$kind")"
    done
    dra-apply "$OUTPUT_DIR" <<< "$yaml"
}

# shellcheck disable=SC2001 # sed indents every line of the workload
mbt-pod-yaml() {
    # Usage: mbt-pod-yaml SLOT NAME
    #
    # Print pod NAME of SLOT (contract 2): label mbt.slot, nodeSelector of
    # the node of its VM unless the slot is "any", restartPolicy Always,
    # terminationGracePeriodSeconds 2, its claim c0 from the template of
    # its kind (none for plain), image $DRA_TOOLS_IMAGE with the tools of
    # dra-dax-tool-install in /tools, main process $MBT_WORKLOAD.
    local slot="$1" name="$2" selector="" claims="" uses=""
    mbt-slot "$slot" || return 2
    [ "$MBT_SVM" == any ] || selector="
  nodeSelector:
    kubernetes.io/hostname: ${MBT_NODE[$MBT_SVM]}"
    if [ "$MBT_KIND" != plain ]; then
        claims="
  resourceClaims:
  - name: c0
    resourceClaimTemplateName: mbt-$MBT_KIND"
        uses="
    resources:
      claims:
      - name: c0"
    fi
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
  labels:
    $MBT_SLOT_LABEL: $MBT_SLABEL
spec:$selector
  terminationGracePeriodSeconds: 2
  restartPolicy: Always$claims
  volumes:
  - name: tools
    configMap:
      name: dax-rw
  containers:
  - name: main
    image: $DRA_TOOLS_IMAGE
    imagePullPolicy: IfNotPresent
    command:
    - sh
    - -c
    - |
$(sed 's/^/      /' <<< "$MBT_WORKLOAD")
    volumeMounts:
    - name: tools
      mountPath: /tools$uses
EOF
}

###
### Commands
###

mbt-sh() {
    # Usage: mbt-sh VM COMMAND
    #
    # Run COMMAND as root in the VM of the VM id VM, quietly. MBT_OUT has
    # its stdout, MBT_ERR its stderr; both go to the executor log with the
    # command. Return its exit status.
    local vm="$1" cmd="$2" rc
    MBT_OUT=$(dra-vm-command-q "${MBT_VMDIR[$vm]}" "$cmd" 2>"$MBT_TMP/stderr")
    rc=$?
    MBT_ERR=$(<"$MBT_TMP/stderr")
    {
        echo "[$vm] \$ $cmd"
        [ -z "$MBT_OUT" ] || echo "$MBT_OUT"
        [ -z "$MBT_ERR" ] || echo "(stderr) $MBT_ERR"
        echo "(exit status $rc)"
    } >> "$MBT_EXEC_LOG"
    return "$rc"
}

mbt-exec-in() {
    # Usage: mbt-exec-in SLOT COMMAND [ARGS...]
    #
    # Run COMMAND with ARGS in container main of the pod of SLOT (kubectl
    # exec in the VM of the test, $MBT_EXEC_TIMEOUT s at most), see mbt-sh.
    # Return 2 if SLOT has no pod, else the exit status of kubectl exec.
    # A kubelet that has just restarted reports its node Ready before it
    # knows its pods again, and kubectl exec fails at the connection
    # ("unable to upgrade connection: pod does not exist"): such errors of
    # kubectl, not of COMMAND, are retried for MBT_EXEC_RETRY s.
    local pod rc deadline=$(( SECONDS + MBT_EXEC_RETRY ))
    mbt-slot-has-pod "$1" || return 2
    pod=$(mbt-slot-pod "$1") || return 2
    shift
    while :; do
        mbt-sh vm2 "timeout $MBT_EXEC_TIMEOUT kubectl exec -n $DRA_NS $pod -c main --$(printf ' %q' "$@")"
        rc=$?
        (( rc != 0 && SECONDS < deadline )) || return "$rc"
        grep -qE '^error: unable to upgrade connection|^Error from server: error dialing backend' <<< "$MBT_ERR" || return "$rc"
        sleep 2
    done
}

mbt-json() {
    # Usage: mbt-json KEY VALUE [KEY VALUE...]
    #
    # Print a JSON object of the string VALUEs; the VALUE @null is null,
    # @json:TEXT is the JSON TEXT, @200:TEXT is the first 200 bytes of TEXT.
    python3 -c '
import json, sys
a, out = sys.argv[1:], {}
for k, v in zip(a[0::2], a[1::2]):
    if v == "@null":
        out[k] = None
    elif v.startswith("@json:"):
        out[k] = json.loads(v[6:]) if v[6:].strip() else None
    elif v.startswith("@200:"):
        out[k] = v[5:].encode()[:200].decode(errors="replace")
    else:
        out[k] = v
print(json.dumps(out, sort_keys=True, separators=(",", ":")))' "$@"
}

mbt-utc() {
    # Usage: mbt-utc [SECONDS-AGO]
    #
    # Print the time SECONDS-AGO (default 0) seconds ago in UTC, RFC 3339.
    date -u -d "-${1:-0} seconds" +%Y-%m-%dT%H:%M:%SZ
}

###
### Actions (contract 4)
###

mbt-act-create() {
    # Usage: mbt-act-create SLOT
    #
    # Apply the pod of the next generation of SLOT, return at once.
    local slot="$1" gen name
    mbt-slot "$slot" || return 2
    gen=$(( ${MBT_GEN[$slot]:-0} + 1 ))
    MBT_GEN[$slot]=$gen
    name="$MBT_SPOD-g$gen"
    MBT_NOTE="pod $name"
    mbt-sh vm2 "kubectl apply -n $DRA_NS -f - <<'MBT_EOF'
$(mbt-pod-yaml "$slot" "$name")
MBT_EOF"
}

mbt-act-delete() {
    # Usage: mbt-act-delete SLOT
    #
    # Delete the pod of SLOT gracefully without waiting.
    local pod
    mbt-slot-has-pod "$1" || return 2
    pod=$(mbt-slot-pod "$1") || return 2
    MBT_NOTE="pod $pod"
    mbt-sh vm2 "kubectl delete pod -n $DRA_NS $pod --wait=false"
}

mbt-act-crash() {
    # Usage: mbt-act-crash SLOT
    #
    # Kill the workload of the pod of SLOT with SIGSEGV: the container
    # exits with 139 and restarts.
    # shellcheck disable=SC2016 # expanded by sh in the container
    mbt-exec-in "$1" sh -c 'kill -SEGV "$(cat /tmp/workload.pid)"'
}

mbt-act-write() {
    # Usage: mbt-act-write SLOT STEP
    #
    # Write "mbt-STEP" and a NUL byte at offset 0 of the dax device of the
    # claim of the pod of SLOT (dax-rw.py write).
    local key rc
    mbt-slot "$1" || return 2
    key=$(mbt-dax-key) || return 2
    # shellcheck disable=SC2016 # expanded by sh in the container
    mbt-exec-in "$1" sh -c 'exec python3 /tools/dax-rw.py write "$CXL_'"$key"'_DAX" 0 "$1"' sh "mbt-$2"
    rc=$?
    MBT_NOTE="mbt-$2"
    MBT_RESULT=$(mbt-json text @null stderr "@200:$MBT_ERR")
    return "$rc"
}

mbt-act-read() {
    # Usage: mbt-act-read SLOT
    #
    # Read the string at offset 0 of the dax device of the claim of the pod
    # of SLOT (dax-rw.py read).
    local key rc text=@null
    mbt-slot "$1" || return 2
    key=$(mbt-dax-key) || return 2
    # shellcheck disable=SC2016 # expanded by sh in the container
    mbt-exec-in "$1" sh -c 'exec python3 /tools/dax-rw.py read "$CXL_'"$key"'_DAX" 0'
    rc=$?
    if [ "$rc" == 0 ]; then
        text="$MBT_OUT"
        MBT_NOTE="read '$text'"
    fi
    MBT_RESULT=$(mbt-json text "$text" stderr "@200:$MBT_ERR")
    return "$rc"
}

mbt-forget-inspected() {
    # Usage: mbt-forget-inspected SLOT
    #
    # Inspect the pod of SLOT again at the next settle observation, for
    # instance after its leases changed (the inspect table has
    # UID:RESTARTS:SLOT entries).
    awk -F: -v slot="$1" '$3 != slot' "$MBT_TMP/inspected" > "$MBT_TMP/inspected.forget" &&
        mv "$MBT_TMP/inspected.forget" "$MBT_TMP/inspected"
}

mbt-act-lease-get() {
    # Usage: mbt-act-lease-get SLOT numa|dax
    #
    # Lease 128Mi of local memory in MODE for the container of the pod of
    # the lease kind SLOT (cxl-request request ... --wait 60s). The result
    # has the lease id (null if none) and the response of cxl-request. The
    # next settle observation inspects the pod again: its leases changed.
    local slot="$1" mode="$2" rc json
    mbt-slot "$slot" || return 2
    [ "$MBT_BASE" == lease ] || { MBT_ERR="$MBT_KIND is not the lease kind"; return 2; }
    case "$mode" in
        numa|dax) ;;
        *) MBT_ERR="lease mode '$mode' is not numa or dax"; return 2;;
    esac
    mbt-exec-in "$slot" "$DRA_REQUEST_CTR_BIN" request --source local --mode "$mode" --size "$MBT_SLICE" --wait "$MBT_LEASE_WAIT"
    rc=$?
    mbt-forget-inspected "$slot"
    json=$(dra-last-json "$MBT_OUT") || json=""
    MBT_RESULT=$(python3 -c '
import json, sys
r = json.loads(sys.argv[1]) if sys.argv[1] else None
print(json.dumps({"lease": (r or {}).get("lease"), "response": r,
                  "stderr": sys.argv[2].encode()[:200].decode(errors="replace")}, sort_keys=True, separators=(",", ":")))' "$json" "$MBT_ERR")
    MBT_NOTE="lease $(python3 -c 'import json, sys; print((json.loads(sys.argv[1]) or {}).get("lease"))' "$MBT_RESULT")"
    return "$rc"
}

mbt-act-lease-put() {
    # Usage: mbt-act-lease-put SLOT
    #
    # Release every lease of the pod of the lease kind SLOT (cxl-request
    # release --all). The next settle observation inspects the pod again.
    local rc
    mbt-slot "$1" || return 2
    [ "$MBT_BASE" == lease ] || { MBT_ERR="$MBT_KIND is not the lease kind"; return 2; }
    mbt-exec-in "$1" "$DRA_REQUEST_CTR_BIN" release --all
    rc=$?
    mbt-forget-inspected "$1"
    return "$rc"
}

mbt-act-driver-kill() {
    # Usage: mbt-act-driver-kill VM
    #
    # SIGKILL to the driver of VM in place (dra-driver-kill), return at
    # once: kubelet restarts its container.
    mbt-vm-arg "$1" || return 2
    MBT_TRACE_REFOLLOW[$1]=$(mbt-utc 2)
    dra-driver-kill "${MBT_VMDIR[$1]}" || return 1
    MBT_NOTE="$COMMAND_OUTPUT"
}

mbt-driver-ready() {
    # Usage: mbt-driver-ready VM
    #
    # Return 0 if the driver of VM is ready (amendment A15): a container of
    # it runs on the node, the log of that container (its log file, and
    # its rotated files) has "$MBT_LENDS_RESTORED" (NRI and lending are up:
    # the last step of the driver's start), both kubelet plugin sockets
    # (cxl.nri.io and cxl-pool.nri.io dra.sock) exist and the node has its
    # cxl.nri.io ResourceSlice. One ssh. MBT_ERR says what is missing.
    local vmdir=${MBT_VMDIR[$1]} name=${MBT_NODE[$1]}
    MBT_ERR=$(dra-vm-command-q "$vmdir" "id=\$(crictl ps -q --state running --namespace '^kube-system\$' --name '^$DRA_CONTAINER\$' 2>/dev/null | head -n 1)
[ -n \"\$id\" ] || { echo 'no running driver container'; exit 1; }
log=\$(crictl inspect -o go-template --template '{{.status.logPath}}' \$id 2>/dev/null)
[ -n \"\$log\" ] || { echo \"no log path of \$id\"; exit 1; }
grep -qF '$MBT_LENDS_RESTORED' \"\$log\" 2>/dev/null || zgrep -qF '$MBT_LENDS_RESTORED' \"\$log\".* 2>/dev/null ||
    { echo \"no '$MBT_LENDS_RESTORED' in the log of \${id:0:13} yet\"; exit 1; }
for d in $DRA_LOCAL_DRIVER $DRA_POOL_DRIVER; do
    test -S /var/lib/kubelet/plugins/\$d/dra.sock || { echo \"no /var/lib/kubelet/plugins/\$d/dra.sock\"; exit 1; }
done
kubectl get resourceslices -o name --field-selector spec.driver=$DRA_LOCAL_DRIVER,spec.nodeName=$name | grep -q . ||
    { echo 'no $DRA_LOCAL_DRIVER ResourceSlice of $name'; exit 1; }" 2>&1)
}

mbt-driver-ready-wait() {
    # Usage: mbt-driver-ready-wait VM
    #
    # Wait until the driver of VM is ready (mbt-driver-ready),
    # MBT_DRIVER_READY_WAIT s at most. Return non-zero on timeout, with
    # MBT_ERR saying what was missing.
    local vm="$1" why="" t0=$EPOCHREALTIME
    retry-until --timeout "$MBT_DRIVER_READY_WAIT" --interval 1 --message "$vm: the driver is ready (running, '$MBT_LENDS_RESTORED' in its log, dra.sock, its ResourceSlice)" \
        'mbt-driver-ready "$vm" || { why=$MBT_ERR; echo "$(date +%T.%N) $vm: driver not ready: $why" >> "$MBT_EXEC_LOG"; false; }' && {
        echo "$(date +%T.%N) $vm: driver ready after $(printf '%.2f' "$(echo "$EPOCHREALTIME - $t0" | bc)") s" >> "$MBT_EXEC_LOG"
        return 0
    }
    MBT_ERR="the driver of $vm is not ready after ${MBT_DRIVER_READY_WAIT}s: $why"
    return 1
}

mbt-act-driver-restart() {
    # Usage: mbt-act-driver-restart VM
    #
    # Delete the pod of the driver of VM and wait until a new pod of the
    # DaemonSet runs there and is ready (mbt-driver-ready: NRI and lending
    # up, the plugin sockets, the node's cxl.nri.io slice; the pool slices
    # are left out: a restarted controller may not have published them
    # yet). Like dra-driver-restart, but it returns non-zero instead of
    # failing the test. The log of the old pod is
    # $TEST_OUTPUT_DIR/nri-dra-driver-cxl.<vm>.<pod>.log; a running trace
    # follows the new pod.
    local vm="$1" vmdir label name old new=""
    mbt-vm-arg "$vm" || return 2
    vmdir=${MBT_VMDIR[$vm]}
    label=$(dra-vm-label "$vmdir")
    name=${MBT_NODE[$vm]}
    old=$(dra-driver-pod "$vmdir") || { MBT_ERR="no running pod of $DRA_DAEMONSET on $name"; return 1; }
    dra-vm-command-q "$vmdir" "kubectl logs -n kube-system $old -c $DRA_CONTAINER" > "$TEST_OUTPUT_DIR/$DRA_CONTAINER.$label.$old.log" 2>&1
    mbt-sh vm2 "kubectl delete pod -n kube-system $old --wait=true --timeout=60s" || return 1
    retry-until --timeout 120 --interval 1 --message "$label: a new Ready pod of $DRA_DAEMONSET" \
        'new=$(dra-driver-pod "$vmdir") && [ "$new" != "$old" ] && dra-vm-command-q "$vmdir" "kubectl wait -n kube-system --for=condition=Ready pod/$new --timeout=1s" >/dev/null 2>&1' ||
        { MBT_ERR="no new Ready pod of $DRA_DAEMONSET on $name"; return 1; }
    mbt-driver-ready-wait "$vm" || return 1
    dra-vm-command-q "$vmdir" "test -x $DRA_REQUEST_NODE_BIN" || { MBT_ERR="no $DRA_REQUEST_NODE_BIN on $name"; return 1; }
    MBT_NOTE="$old -> $new"
    MBT_DRIVER_SEEN[$vm]="$new 0"
    unset "MBT_TRACE_REFOLLOW[$vm]"
    [ -z "$DRA_TRACE_RUNNING" ] || dra-trace-driver-follow "$vmdir"
}

mbt-act-ctrl-kill() {
    # Usage: mbt-act-ctrl-kill POOL
    mbt-pool-arg "$1" || return 2
    dra-controller-kill "${MBT_POOL_UNIT[$1]}"
}

mbt-act-ctrl-start() {
    # Usage: mbt-act-ctrl-start POOL
    mbt-pool-arg "$1" || return 2
    dra-controller-start "${MBT_POOL_UNIT[$1]}"
}

mbt-act-ctrl-restart() {
    # Usage: mbt-act-ctrl-restart POOL
    mbt-pool-arg "$1" || return 2
    dra-controller-stop "${MBT_POOL_UNIT[$1]}" && dra-controller-start "${MBT_POOL_UNIT[$1]}"
}

mbt-act-server-restart() {
    # Usage: mbt-act-server-restart POOL
    mbt-pool-arg "$1" || return 2
    pool-server-restart "${MBT_POOL_SERVER[$1]}"
}

mbt-act-kubelet-restart() {
    # Usage: mbt-act-kubelet-restart VM
    #
    # Restart the kubelet of VM (dra-node-service-restart), then wait until
    # its driver is ready (mbt-driver-ready-wait, A15). The stream of the
    # trace that follows the driver log through the kubelet ends: follow
    # it again after the next observation.
    mbt-vm-arg "$1" || return 2
    local t0=$EPOCHREALTIME
    MBT_TRACE_REFOLLOW[$1]=$(mbt-utc 2)
    dra-node-service-restart "${MBT_VMDIR[$1]}" kubelet || return 1
    echo "$(date +%T.%N) $1: kubelet back after $(printf '%.2f' "$(echo "$EPOCHREALTIME - $t0" | bc)") s" >> "$MBT_EXEC_LOG"
    mbt-driver-ready-wait "$1"
}

mbt-driver-restarts() {
    # Usage: mbt-driver-restarts VM
    #
    # Print "POD RESTARTS READY" of the driver pod on the node of VM
    # (READY: True or False), quietly. Return non-zero if there is none.
    local out
    out=$(dra-vm-command-q "$OUTPUT_DIR" "kubectl get pods -n kube-system -l $DRA_POD_LABEL --field-selector spec.nodeName=${MBT_NODE[$1]} -o jsonpath='{range .items[*]}{.metadata.name} {.status.containerStatuses[?(@.name==\"$DRA_CONTAINER\")].restartCount} {.status.conditions[?(@.type==\"Ready\")].status}{\"\\n\"}{end}'" 2>/dev/null | head -n 1)
    [ -n "$out" ] || return 1
    echo "$out"
}

mbt-act-containerd-restart() {
    # Usage: mbt-act-containerd-restart VM
    #
    # Restart containerd in VM (dra-node-service-restart), then wait until
    # the driver of VM has restarted in place and is Ready again,
    # MBT_NRI_RESTART_WAIT s at most: a driver with the fix of plan-13
    # bug-01 exits when it loses its NRI connection (amendment A8). An
    # older driver does not: after the wait the step goes on, with
    # MBT_NOTE saying so. Then wait until the driver is ready
    # (mbt-driver-ready-wait, A15); return non-zero if it is not.
    local vm="$1" before after pod restarts ready rc
    mbt-vm-arg "$vm" || return 2
    MBT_TRACE_REFOLLOW[$vm]=$(mbt-utc 2)
    before=$(mbt-driver-restarts "$vm") || before=""
    dra-node-service-restart "${MBT_VMDIR[$vm]}" containerd
    rc=$?
    [ "$rc" == 0 ] && [ -n "$before" ] || return "$rc"
    read -r pod restarts ready <<< "$before"
    if retry-until --timeout "$MBT_NRI_RESTART_WAIT" --interval 1 --message "$vm: the driver $pod restarted in place (more than $restarts restarts) and Ready" \
           'after=$(mbt-driver-restarts "$vm") && read -r _ r a <<< "$after" && [ "${r:-0}" -gt "$restarts" ] && [ "$a" == True ]'; then
        MBT_NOTE="driver $pod restarted in place: $restarts -> $(read -r _ r _ <<< "$after"; echo "$r") restarts"
    else
        MBT_NOTE="driver $pod did not restart in ${MBT_NRI_RESTART_WAIT}s (a driver without the fix of bug-01): ${after:-$before}"
    fi
    mbt-driver-ready-wait "$vm"
}

mbt-run() { # script API
    # Usage: mbt-run STEP VERB ARGS...
    #
    # Execute step STEP, the action VERB ARGS (contract 4, not settle):
    # print the progress line and the result line, set MBT_STATUS (2 for
    # an unknown verb or bad arguments) and MBT_RESULT (contract 6.2).
    local step="$1" verb="$2" t0=$EPOCHREALTIME secs nargs=1
    shift 2
    echo "### mbt step $step: $verb${*:+ $*}"
    echo "=== step $step: $verb${*:+ $*} ($(date +%T.%N))" >> "$MBT_EXEC_LOG"
    MBT_RESULT='{}' MBT_NOTE="" MBT_ERR="" MBT_OUT=""
    [ "$verb" != lease-get ] || nargs=2
    case "$verb" in
        create|delete|crash|read|lease-put|lease-get|driver-kill|driver-restart|ctrl-kill|ctrl-start|ctrl-restart|server-restart|kubelet-restart|containerd-restart)
            if [ $# != "$nargs" ]; then
                MBT_ERR="$verb takes $nargs arguments, got $#: $*"
                MBT_STATUS=2
            else
                "mbt-act-$verb" "$@"
                MBT_STATUS=$?
            fi;;
        write)
            if [ $# != 1 ]; then
                MBT_ERR="write takes 1 argument, got $#: $*"
                MBT_STATUS=2
            else
                mbt-act-write "$1" "$step"
                MBT_STATUS=$?
            fi;;
        *)
            MBT_ERR="unknown verb '$verb'"
            MBT_STATUS=2;;
    esac
    secs=$(printf '%.2f' "$(echo "$EPOCHREALTIME - $t0" | bc)")
    echo "    status $MBT_STATUS, ${secs} s${MBT_NOTE:+, $MBT_NOTE}${MBT_ERR:+, stderr: $(head -c 200 <<< "$MBT_ERR" | tr '\n' ' ')}"
    printf '%s\t%s\t%s\t%s\t%s\t\n' "$step" "$verb" "$*" "$MBT_STATUS" "$secs" >> "$MBT_TIMES"
    return 0
}

###
### Observation (contract 6)
###

mbt-observer-install() { # script API
    # Usage: mbt-observer-install VMDIR...
    #
    # Copy mbt-observe.py into the VMs ($MBT_OBSERVER_VM) and run it once
    # in each. Fail the test if it does not print an observation.
    local vmdir
    for vmdir in "$@"; do
        dra-vm-put-file "$vmdir" "$MBT_OBSERVER" "$MBT_OBSERVER_VM"
        dra-vm-command "$vmdir" "chmod 755 $MBT_OBSERVER_VM && python3 $MBT_OBSERVER_VM vm --ns $DRA_NS | head -c 300; echo; exit \${PIPESTATUS[0]}" ||
            command-error "mbt-observe.py does not run in $(dra-vm-label "$vmdir")"
    done
}

mbt-observe() { # script API
    # Usage: mbt-observe STEP POLL
    #
    # Make settle observation POLL of step STEP (contract 6.1): in
    # parallel, mbt-observe.py in each VM (with the cluster parts in the
    # VM of the test) and the attachments of each pool server, then
    # mbt-observe.py assemble on the host. MBT_OBS is the observation (one
    # JSON line), MBT_OBS_FILE its file in $MBT_OBS_DIR (the last
    # $MBT_OBS_KEEP are kept). Update the table of inspected pods, and
    # follow the logs of restarted drivers (mbt-drivers-seen). A VM whose
    # part takes longer than MBT_OBS_TIMEOUT s is left out (null, with an
    # error): the observer runs under timeout in the VM, and its ssh is
    # killed on the host 10 s later. Return non-zero if the observation
    # could not be assembled: MBT_OBS is then an observation with the
    # error only.
    local step="$1" poll="$2" t0=$EPOCHREALTIME vm p pids=() cmd inspected args=() url
    inspected=$(paste -sd, "$MBT_TMP/inspected")
    for vm in "${MBT_VMIDS[@]}"; do
        cmd="timeout -k 5 $MBT_OBS_TIMEOUT python3 $MBT_OBSERVER_VM vm --ns $DRA_NS"
        [ "$vm" != vm2 ] || cmd+=" --cluster --nodes $MBT_NODES --units $MBT_UNITS --pools $MBT_POOLS --inspected '$inspected'"
        dra-vm-command-q "${MBT_VMDIR[$vm]}" "$cmd" > "$MBT_TMP/obs.$vm" 2> "$MBT_TMP/obs.$vm.err" &
        pids+=("$!")
        args+=(--vm "$vm=$MBT_TMP/obs.$vm")
    done
    for p in "${MBT_POOL_IDS[@]}"; do
        url=$(pool-url "${MBT_POOL_SERVER[$p]}") || url=""
        curl -s --max-time 10 "$url/api/v1/attachments" > "$MBT_TMP/att.$p" 2>/dev/null &
        pids+=("$!")
        args+=(--attachments "$p=$MBT_TMP/att.$p")
    done
    mbt-wait-pids $(( MBT_OBS_TIMEOUT + 10 )) "${pids[@]}"
    if MBT_OBS=$(python3 "$MBT_OBSERVER" assemble --step "$step" --poll "$poll" --nodes "$MBT_NODES" "${args[@]}" \
                     --inspected-in "$MBT_TMP/inspected" --inspected-out "$MBT_TMP/inspected.new" \
                     --summary "$MBT_TMP/summary" 2>"$MBT_TMP/assemble.err") && [ -n "$MBT_OBS" ]; then
        mv "$MBT_TMP/inspected.new" "$MBT_TMP/inspected"
    else
        MBT_OBS=$(mbt-json step "@json:$step" poll "@json:$poll" errors "@json:[$(python3 -c 'import json, sys; print(json.dumps("assemble: " + sys.argv[1][-500:]))' "$(cat "$MBT_TMP/assemble.err")")]")
        echo "    observation $poll of step $step failed: $(tail -n 3 "$MBT_TMP/assemble.err")"
    fi
    MBT_OBS_FILE="$MBT_OBS_DIR/obs-$(printf '%06d-%03d' "$step" "$poll").json"
    echo "$MBT_OBS" > "$MBT_OBS_FILE"
    MBT_OBS_FILES+=("$MBT_OBS_FILE")
    while [ "${#MBT_OBS_FILES[@]}" -gt "$MBT_OBS_KEEP" ]; do
        rm -f "${MBT_OBS_FILES[0]}"
        MBT_OBS_FILES=("${MBT_OBS_FILES[@]:1}")
    done
    MBT_OBS_SECONDS=$(printf '%.2f' "$(echo "$EPOCHREALTIME - $t0" | bc)")
    printf '%s\t%s\t%s\n' "$step" "$poll" "$MBT_OBS_SECONDS" >> "$MBT_OBS_TIMES"
    mbt-drivers-seen
}

mbt-wait-pids() {
    # Usage: mbt-wait-pids TIMEOUT PID...
    #
    # Wait until the background jobs PID of this shell have exited,
    # TIMEOUT seconds at most; then kill those that run (and their
    # children: the ssh of a dra-vm-command-q) and reap them. Return 1 if
    # some had to be killed.
    local tmo="$1" end pid alive rc=0
    shift
    end=$(( SECONDS + tmo ))
    while :; do
        alive=""
        for pid in "$@"; do
            ! kill -0 "$pid" 2>/dev/null || alive+=" $pid"
        done
        [ -n "$alive" ] && [ "$SECONDS" -lt "$end" ] || break
        sleep 0.05
    done
    for pid in $alive; do
        echo "    mbt-wait-pids: killing background job $pid after ${tmo}s"
        pkill -TERM -P "$pid" 2>/dev/null
        kill -TERM "$pid" 2>/dev/null
        rc=1
    done
    wait "$@" 2>/dev/null
    return "$rc"
}

mbt-drivers-seen() {
    # Usage: mbt-drivers-seen
    #
    # After an observation: for every driver whose container restarted in
    # its pod since the last observation, store the log of the container
    # that ended as $TEST_OUTPUT_DIR/nri-dra-driver-cxl.<vm>.<pod>.r<N>.log
    # (N: its restart count), and while a trace runs, follow the log of the
    # driver again where the stream ended (driver-kill, kubelet-restart,
    # containerd-restart and such restarts).
    local word vm pod restarts ready old_pod old_restarts label since
    [ -f "$MBT_TMP/summary" ] || return 0
    while read -r word vm pod restarts ready; do
        [ "$word" == driver ] && [ -n "${MBT_VMDIR[$vm]:-}" ] || continue
        label=$(dra-vm-label "${MBT_VMDIR[$vm]}")
        read -r old_pod old_restarts <<< "${MBT_DRIVER_SEEN[$vm]:-}"
        since=${MBT_TRACE_REFOLLOW[$vm]:-}
        if [ "$pod" == "$old_pod" ] && [ "$restarts" != "$old_restarts" ]; then
            echo "    the driver of $vm restarted in $pod: $old_restarts -> $restarts restarts"
            dra-vm-command-q "$OUTPUT_DIR" "kubectl logs -n kube-system $pod -c $DRA_CONTAINER --previous" \
                > "$TEST_OUTPUT_DIR/$DRA_CONTAINER.$label.$pod.r$(( restarts - 1 )).log" 2>&1
            [ -n "$since" ] || since=$(mbt-utc 10)
        elif [ -n "$old_pod" ] && [ "$pod" != "$old_pod" ]; then
            echo "    the driver of $vm is a new pod: $old_pod -> $pod"
            [ -n "$since" ] || since=$(mbt-utc 10)
        fi
        if [ "$ready" == ready ] && [ -n "$since" ]; then
            if [ -n "$DRA_TRACE_RUNNING" ]; then
                dra-trace-collect-vm "${MBT_VMDIR[$vm]}" "$label.driver" lines "kubectl logs -n kube-system -f --since-time=$since -c $DRA_CONTAINER $pod"
            fi
            unset "MBT_TRACE_REFOLLOW[$vm]"
        fi
        MBT_DRIVER_SEEN[$vm]="$pod $restarts"
    done < "$MBT_TMP/summary"
}

###
### The generator: on-line (coprocess) and off-line (code.gen.sh)
###

mbt-coproc-start() {
    # Usage: mbt-coproc-start ARGS...
    #
    # Start "$MBT_BIN ARGS" as the coprocess MBTGEN, its stderr appended to
    # $MBT_LOG. Its fds exist in this shell only (not in ( ... ), not in
    # external commands); MBT_RFD is a copy of its stdout that bash does not
    # close when it reaps the coprocess, so that its last lines are read.
    [ -z "$MBT_GEN_PID" ] || error "mbt-coproc-start: the generator runs already, pid $MBT_GEN_PID"
    coproc MBTGEN { exec "$MBT_BIN" "$@" 2>>"$MBT_LOG"; }
    # shellcheck disable=SC2153,SC2154 # MBTGEN_PID and MBTGEN are of coproc
    MBT_GEN_PID=$MBTGEN_PID
    exec {MBT_RFD}<&"${MBTGEN[0]}"
    echo "mbt: started $MBT_BIN $* (pid $MBT_GEN_PID), its log is $MBT_LOG"
}

mbt-coproc-stop() {
    # Usage: mbt-coproc-stop
    #
    # Close the stdin of the generator, give it 5 s to exit, then stop it
    # (SIGTERM, SIGKILL). Never fails.
    local pid="$MBT_GEN_PID" _
    [ -n "$pid" ] || return 0
    MBT_GEN_PID=""
    [ -z "${MBTGEN[1]:-}" ] || eval "exec ${MBTGEN[1]}>&-"
    for _ in $(seq 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        echo "mbt: the generator (pid $pid) did not exit, stopping it"
        kill -TERM "$pid" 2>/dev/null
        sleep 1
        kill -KILL "$pid" 2>/dev/null
    fi
    [ -z "$MBT_RFD" ] || eval "exec $MBT_RFD<&-"
    MBT_RFD=""
    wait "$pid" 2>/dev/null
    return 0
}

mbt-send() {
    # Usage: mbt-send LINE
    #
    # Send LINE to the generator. Return non-zero if it is gone: SIGPIPE is
    # ignored meanwhile, it would kill this shell without the EXIT trap.
    local rc
    [ -n "${MBTGEN[1]:-}" ] || return 1
    trap '' PIPE
    printf '%s\n' "$1" >&"${MBTGEN[1]}"
    rc=$?
    trap - PIPE
    return "$rc"
}

mbt-recv() {
    # Usage: mbt-recv
    #
    # Read the next line of the generator into MBT_LINE, $MBT_READ_TIMEOUT s
    # at most. Return non-zero on timeout or end of file.
    [ -n "$MBT_RFD" ] || return 1
    IFS= read -r -t "$MBT_READ_TIMEOUT" -u "$MBT_RFD" MBT_LINE
}

mbt-gone() {
    # Usage: mbt-gone WHAT
    #
    # Fail the test: the generator did not send WHAT.
    echo "--- the end of $MBT_LOG:"
    tail -n 20 "$MBT_LOG"
    error "mbt: no $1 from the generator in ${MBT_READ_TIMEOUT}s: it exited or hangs, see $MBT_LOG"
}

mbt-fail() { # script API
    # Usage: mbt-fail STEP MESSAGE
    #
    # Step STEP failed the oracle: print MESSAGE, keep the last observation
    # as $MBT_OBS_DIR/fail-STEP.json, show the start of the report of the
    # generator ($TEST_OUTPUT_DIR/mbt-fail.txt) and fail the test.
    local step="$1" msg="$2"
    echo "### mbt step $step FAILED: $msg"
    if [ -n "$MBT_OBS_FILE" ] && [ -f "$MBT_OBS_FILE" ]; then
        cp "$MBT_OBS_FILE" "$MBT_OBS_DIR/fail-$step.json"
        echo "the last observation: $MBT_OBS_DIR/fail-$step.json"
    fi
    if [ -f "$TEST_OUTPUT_DIR/mbt-fail.txt" ]; then
        echo "--- $TEST_OUTPUT_DIR/mbt-fail.txt (the first 80 lines):"
        head -n 80 "$TEST_OUTPUT_DIR/mbt-fail.txt"
    fi
    echo "steps: $TEST_OUTPUT_DIR/mbt-steps.txt, generator log: $MBT_LOG, executor log: $MBT_EXEC_LOG"
    error "mbt: step $step failed: $msg"
}

mbt-answer() {
    # Usage: mbt-answer STEP
    #
    # Read the answer of the generator to "done STEP ...": return on ok,
    # fail the test on fail (mbt-fail) or any other line.
    local step="$1"
    mbt-recv || mbt-gone "answer to step $step"
    case "$MBT_LINE" in
        "ok $step") return 0;;
        "fail $step"|"fail $step "*) mbt-fail "$step" "${MBT_LINE#"fail $step "}";;
        *) error "mbt: expected ok or fail of step $step from the generator, got: $MBT_LINE";;
    esac
}

mbt-settle-online() {
    # Usage: mbt-settle-online STEP
    #
    # Step STEP is settle: send observations until the generator answers
    # ok (return) or fail (mbt-fail), MBT_POLL s apart while it answers
    # wait.
    local step="$1" poll=0 t0=$EPOCHREALTIME last="" msg secs
    echo "### mbt step $step: settle"
    echo "=== step $step: settle ($(date +%T.%N))" >> "$MBT_EXEC_LOG"
    while :; do
        poll=$(( poll + 1 ))
        mbt-observe "$step" "$poll"
        mbt-send "observe $step $MBT_OBS" || mbt-gone "reader of observation $poll of step $step"
        mbt-recv || mbt-gone "answer to observation $poll of step $step"
        case "$MBT_LINE" in
            "ok $step") break;;
            "wait $step"|"wait $step "*)
                msg=${MBT_LINE#"wait $step"}
                msg=${msg# }
                [ "$msg" == "$last" ] || echo "    observation $poll (${MBT_OBS_SECONDS} s): wait: ${msg:0:300}"
                echo "observation $poll: wait: $msg" >> "$MBT_EXEC_LOG"
                last=$msg
                sleep "$MBT_POLL";;
            "fail $step"|"fail $step "*) mbt-fail "$step" "${MBT_LINE#"fail $step "}";;
            *) error "mbt: expected ok, wait or fail of step $step from the generator, got: ${MBT_LINE:0:500}";;
        esac
    done
    secs=$(printf '%.2f' "$(echo "$EPOCHREALTIME - $t0" | bc)")
    echo "    settled: $poll observations, ${secs} s"
    printf '%s\tsettle\t\t0\t%s\t%s\n' "$step" "$secs" "$poll" >> "$MBT_TIMES"
}

mbt-online() { # script API
    # Usage: mbt-online ARGS...
    #
    # The on-line run (contract 5): start the generator with ARGS
    # (mbt-coproc-start), execute the steps it sends and answer them until
    # it ends the run, then stop it.
    local words step verb
    mbt-coproc-start "$@"
    while :; do
        mbt-recv || mbt-gone "step"
        read -r -a words <<< "$MBT_LINE"
        case "${words[0]:-}" in
            step)
                step=${words[1]:-} verb=${words[2]:-}
                [[ "$step" =~ ^[0-9]+$ ]] && [ -n "$verb" ] ||
                    error "mbt: bad step line from the generator: $MBT_LINE"
                if [ "$verb" == settle ]; then
                    mbt-settle-online "$step"
                else
                    mbt-run "$step" "$verb" "${words[@]:3}"
                    mbt-send "done $step $MBT_STATUS $MBT_RESULT" || mbt-gone "reader of done $step"
                    mbt-answer "$step"
                fi;;
            end)
                echo "### mbt: the generator ended the run:${MBT_LINE#end}"
                break;;
            fail)
                # Between steps: a replay that the model cannot follow
                # (the step of the file is not enabled) fails the next step.
                step=${words[1]:-}
                mbt-fail "$step" "${MBT_LINE#"fail $step "}";;
            *) error "mbt: unexpected line from the generator: ${MBT_LINE:0:500}";;
        esac
    done
    mbt-coproc-stop
}

mbt-header-flags() { # script API
    # Usage: mbt-header-flags STEPS-FILE
    #
    # Print the model flags of the header of STEPS-FILE (an mbt-steps.txt
    # of mbt-cxl online: "# --profile P --seed S ..."), one --flag=value
    # per line: those that decide which steps are enabled and how the
    # oracle judges them (amendment A16). Not the run's budget (--steps,
    # --duration, the replay runs the file), its files (--out, --replay)
    # or what the cluster is (--local-blocks, --node-hb0/1: measured).
    # Nothing if the file has no such header.
    python3 -c '
import shlex, sys
keep = {"profile", "seed", "depth", "coverage", "randomness", "unsettled", "max-restarts", "avoid",
        "avoid-holes", "max-paths", "settle-timeout", "unblock-timeout"}
for line in open(sys.argv[1]):
    if not line.startswith("# --"):
        continue
    words = shlex.split(line[1:])
    i = 0
    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("--"):
            continue
        name, eq, value = w[2:].partition("=")
        if not eq and i < len(words) and not words[i].startswith("--"):
            value, eq = words[i], "="
            i += 1
        if name in keep:
            print("--%s=%s" % (name, value) if eq else "--" + name)
    break' "$1"
}

mbt-check() {
    # Usage: mbt-check STEP EXPECT-FILE OBSERVED-FILE [SINCE]
    #
    # Run "$MBT_BIN check" on the prediction and the observation of step
    # STEP; SINCE is the Unix time of its first observation (a settle that
    # waits longer than MBT_SETTLE_TIMEOUT fails). MBT_LINE is what it
    # printed. Return its exit status: 0 ok, 3 wait, 1 fail.
    local since=()
    [ -z "${4:-}" ] || since=(--since="$4" --settle-timeout="${MBT_SETTLE_TIMEOUT}s")
    MBT_LINE=$("$MBT_BIN" check --step="$1" --expect="$2" --observed="$3" "${since[@]}" 2>>"$MBT_LOG")
}

mbt-unchecked() {
    # Usage: mbt-unchecked
    #
    # Off-line: the last step had no mbt-expect (a code.gen.sh of a
    # generator before amendment A14, which writes one for every step):
    # fail the test if it was an action with a nonzero status, as the
    # oracle fails it on-line; a settle without one was not observed.
    [ "$MBT_LAST_CHECKED" == 1 ] && return 0
    MBT_LAST_CHECKED=1
    if [ "$MBT_LAST_VERB" == settle ]; then
        echo "    WARNING: step $MBT_LAST_STEP settle has no mbt-expect: not observed"
        return 0
    fi
    [ "$MBT_LAST_STATUS" == 0 ] ||
        mbt-fail "$MBT_LAST_STEP" "$MBT_LAST_VERB: exit status $MBT_LAST_STATUS (the step has no mbt-expect: a nonzero status fails it)"
}

mbt-step() { # script API
    # Usage: mbt-step STEP VERB ARGS...
    #
    # Off-line (a code.gen.sh): execute step STEP, and append it to
    # mbt-steps.txt. The mbt-expect that follows it checks its status and
    # result (A14), a settle is done by it. Without one, the status of an
    # action is checked here, before the next step (mbt-unchecked).
    mbt-unchecked
    MBT_LAST_STEP="$1" MBT_LAST_VERB="$2" MBT_LAST_DONE="" MBT_LAST_STATUS=0 MBT_LAST_CHECKED=""
    echo "${*:2}" >> "$TEST_OUTPUT_DIR/mbt-steps.txt"
    if [ "$2" == settle ]; then
        return 0
    fi
    mbt-run "$@"
    MBT_LAST_STATUS=$MBT_STATUS
    MBT_LAST_DONE="done $1 $MBT_STATUS $MBT_RESULT"
}

mbt-expect() { # script API
    # Usage: mbt-expect STEP <<'EOF'
    #        PREDICTION
    #        EOF
    #
    # Off-line: check the last step, STEP, against the PREDICTION of the
    # generator with "$MBT_BIN check" (mbt-check). The observed file has
    # the line that the on-line protocol would send: "done STEP STATUS
    # JSON" after an action, "observe STEP JSON" for a settle, which is
    # observed again MBT_POLL s apart while the check says wait, for
    # MBT_SETTLE_TIMEOUT s at most. Fail the test (mbt-fail) on fail or
    # timeout.
    local step="$1" expect="$MBT_TMP/expect.json" observed="$MBT_TMP/observed.txt" rc poll=0 t0=$SECONDS secs last="" since
    cat > "$expect"
    [ "$step" == "$MBT_LAST_STEP" ] || error "mbt-expect $step: the last step was $MBT_LAST_STEP"
    MBT_LAST_CHECKED=1
    if [ "$MBT_LAST_VERB" != settle ]; then
        printf '%s\n' "$MBT_LAST_DONE" > "$observed"
        mbt-check "$step" "$expect" "$observed"
        rc=$?
        case "$rc" in
            0) return 0;;
            1|3) mbt-fail "$step" "${MBT_LINE#* }";;
            *) error "mbt: $MBT_BIN check exited $rc on step $step: $MBT_LINE";;
        esac
    fi
    echo "### mbt step $step: settle"
    echo "=== step $step: settle ($(date +%T.%N))" >> "$MBT_EXEC_LOG"
    since=$(date +%s)
    while :; do
        poll=$(( poll + 1 ))
        mbt-observe "$step" "$poll"
        printf 'observe %s %s\n' "$step" "$MBT_OBS" > "$observed"
        mbt-check "$step" "$expect" "$observed" "$since"
        rc=$?
        case "$rc" in
            0) break;;
            3)
                [ "$MBT_LINE" == "$last" ] || echo "    observation $poll (${MBT_OBS_SECONDS} s): ${MBT_LINE:0:300}"
                last=$MBT_LINE
                [ $(( SECONDS - t0 )) -lt "$MBT_SETTLE_TIMEOUT" ] ||
                    mbt-fail "$step" "not settled in ${MBT_SETTLE_TIMEOUT}s: ${MBT_LINE#wait }"
                sleep "$MBT_POLL";;
            1) mbt-fail "$step" "${MBT_LINE#fail }";;
            *) error "mbt: $MBT_BIN check exited $rc on step $step: $MBT_LINE";;
        esac
    done
    secs=$(( SECONDS - t0 ))
    echo "    settled: $poll observations, ${secs} s"
    printf '%s\tsettle\t\t0\t%s\t%s\n' "$step" "$secs" "$poll" >> "$MBT_TIMES"
}

mbt-offline() { # script API
    # Usage: mbt-offline SCRIPT
    #
    # The off-line run: source SCRIPT, a code.gen.sh of "mbt-cxl generate"
    # (mbt-step and mbt-expect lines).
    [ -f "$1" ] || error "mbt-offline: no script $1"
    echo "mbt: running the steps of $1 ($(grep -c '^mbt-step ' "$1") steps)"
    echo "# off-line: the steps of $1" > "$TEST_OUTPUT_DIR/mbt-steps.txt"
    MBT_LAST_CHECKED=1
    # shellcheck source=/dev/null
    source "$1"
    mbt-unchecked
}

###
### Setup checks and teardown
###

mbt-local-blocks() { # script API
    # Usage: mbt-local-blocks
    #
    # Print the --local-blocks of the generator: vm2=N,vm1=N,vm0=N, N the
    # capacity.memory of the local memdev in the cxl.nri.io ResourceSlice
    # of the node of the VM in blocks of $MBT_SLICE. Return non-zero if a
    # node does not publish it.
    local json vm n out=""
    json=$(dra-vm-command-q "$OUTPUT_DIR" "kubectl get resourceslices -o json") || return 1
    for vm in "${MBT_VMIDS[@]}"; do
        n=$(dra-py eval "$json" "quantity(capacity(device('memdev-${MBT_LOCAL_HEX,,}', '$DRA_LOCAL_DRIVER', '${MBT_NODE[$vm]}'), 'memory') or 0) // quantity('$MBT_SLICE')") || return 1
        [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -gt 0 ] || return 1
        out+="${out:+,}$vm=$n"
    done
    echo "$out"
}

mbt-k8s-attachments() {
    # Usage: mbt-k8s-attachments POOL
    #
    # Print the attachments of the server of POOL that a pool controller
    # owns (owner k8s:...), "device@host state" each, quietly. Return
    # non-zero if the server does not answer.
    local url json
    url=$(pool-url "${MBT_POOL_SERVER[$1]}") || return 1
    json=$(curl -sf --max-time 10 "$url/api/v1/attachments") || return 1
    python3 -c '
import json, sys
for a in json.loads(sys.argv[1]) or []:
    if (a.get("owner") or "").startswith("k8s:"):
        print("%s@%s %s" % (a.get("device"), a.get("host"), a.get("state")))' "$json"
}

mbt-restore() { # script API
    # Usage: mbt-restore
    #
    # Bring back what the faults of the run took away, so that the deletes
    # of the teardown are carried out: the pool servers that do not run
    # (restarted on their state), the pool controllers that are not active
    # (started), and the driver Ready on every node (waited for, 330 s at
    # most: a container that was killed often waits for its back-off).
    # Never fails the test.
    # shellcheck disable=SC2034 # dp is set in the snippet of retry-until
    local p unit vm vmdir name dp
    [ -n "$MBT_TMP" ] || return 0
    for p in "${MBT_POOL_IDS[@]}"; do
        name=${MBT_POOL_SERVER[$p]}
        if [ -n "${POOL_SERVER_PIDS[$name]:-}" ] && ! kill -0 "${POOL_SERVER_PIDS[$name]}" 2>/dev/null; then
            echo "mbt-restore: the server $name does not run, restarting it"
            pool-server-restart "$name" || echo "mbt-restore: cannot restart the server $name"
        fi
    done
    for p in "${MBT_POOL_IDS[@]}"; do
        unit=${MBT_POOL_UNIT[$p]}
        [ -n "${DRA_CONTROLLER_URLS[$unit]:-}" ] || continue
        if ! dra-vm-command-q "$OUTPUT_DIR" "systemctl -q is-active $unit"; then
            echo "mbt-restore: $unit is not active, starting it"
            dra-controller-start "$unit" || echo "mbt-restore: cannot start $unit"
        fi
    done
    [ "${#DRA_INSTALLED_VMS[@]}" -gt 0 ] || return 0
    for vm in "${MBT_VMIDS[@]}"; do
        vmdir=${MBT_VMDIR[$vm]}
        retry-until --timeout 330 --interval 2 --message "mbt-restore: a Ready pod of $DRA_DAEMONSET on ${MBT_NODE[$vm]}" \
            'dp=$(dra-driver-pod "$vmdir") && dra-vm-command-q "$vmdir" "kubectl wait -n kube-system --for=condition=Ready pod/$dp --timeout=1s" >/dev/null 2>&1' ||
            echo "mbt-restore: the driver is not Ready on ${MBT_NODE[$vm]}"
    done
    return 0
}

mbt-teardown() { # script API
    # Usage: mbt-teardown
    #
    # The end of a run (the generator has deleted every pod and settled):
    # restore the components (mbt-restore), delete every pod of $DRA_NS
    # gracefully, and fail the test unless the pods and claims are gone,
    # no pool server has an attachment of a pool controller left, and no
    # VM has a CXL region or a memdev other than its local memdev, 120 s
    # at most each.
    local vm p left
    mbt-restore
    dra-vm-command "$OUTPUT_DIR" "kubectl delete pods --all -n $DRA_NS --grace-period=2 --wait=true --timeout=180s 2>&1 | grep -v 'No resources found'; true"
    retry-until --timeout 120 --interval 2 --message "no pods and ResourceClaims in $DRA_NS" \
        '[ -z "$(dra-vm-command-q "$OUTPUT_DIR" "kubectl get pods,resourceclaims -n $DRA_NS -o name")" ]' || {
        dra-vm-command "$OUTPUT_DIR" "kubectl get pods,resourceclaims -n $DRA_NS -o wide"
        error "mbt-teardown: pods or ResourceClaims are left in $DRA_NS"
    }
    for p in "${MBT_POOL_IDS[@]}"; do
        retry-until --timeout 120 --interval 2 --message "no attachments of the controller of pool $p" \
            'left=$(mbt-k8s-attachments "$p") && [ -z "$left" ]' ||
            error "mbt-teardown: ${MBT_POOL_SERVER[$p]} still has attachments of its controller: ${left:-the server does not answer}"
    done
    for vm in "${MBT_VMIDS[@]}"; do
        pool-cxl-wait "${MBT_VMDIR[$vm]}" mbt-released "regions == [] and [m['Serial'] for m in memdevs] == [$MBT_LOCAL_SERIAL]" 120
    done
}

mbt-exit-trap() {
    # Usage: mbt-exit-trap
    #
    # The EXIT trap of test90 (DRA_EXIT_TRAP of dra-install): stop the
    # generator, restore the components, then the cleanup of every
    # dra-driver-cxl test: dra-cleanup (deletes the pods gracefully, waits
    # for the detaches, uninstalls the driver and the controllers) and
    # pool-cleanup (releases and detaches what is left, the local memdevs
    # too, and stops the servers).
    mbt-coproc-stop
    echo "### mbt: cleanup after an error or an interruption"
    mbt-restore
    dra-cleanup
    pool-cleanup
}
