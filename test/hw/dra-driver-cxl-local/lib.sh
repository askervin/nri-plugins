# Helpers of the hardware testS of local CXL memory with nri-dra-driver-cxl.
#
# The tests run on this host and drive a single-node Kubernetes cluster
# on TARGET whose node has a local CXL memory device. Every kubectl, cxl
# and daxctl command runs on TARGET through ssh.
#
# Environment:
#   TARGET       ssh destination of the node (default root@hostname)
#   CXL_SERIAL   serial of the local memdev to test (default: the first
#                memdev of "cxl list -M" on TARGET)
#   NS           namespace of the test pods and claims (default cxl-hw)
#   TOOLS_IMAGE  image of the test containers (default python:3-alpine)

LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$LIB_DIR/../../.." && pwd)
E2E_TOOLS_DIR="$REPO_DIR/test/e2e/memory.test-suite/dra-driver-cxl/n4-cxl-shared-2"

TARGET=${TARGET:-root@hostname}
NS=${NS:-cxl-hw}
TOOLS_IMAGE=${TOOLS_IMAGE:-docker.io/library/python:3-alpine}
DRIVER=cxl.nri.io
DRA_POD_LABEL=app.kubernetes.io/name=nri-dra-driver-cxl

PASSED=0
FAILED=0
FAILURES=()

t() { # Usage: t CMD... -- run a shell command on TARGET
    ssh -o BatchMode=yes "$TARGET" "$@"
}

k() { # Usage: k ARGS... -- kubectl on TARGET
    t kubectl "$(printf '%q ' "$@")"
}

kn() { # Usage: kn ARGS... -- kubectl in namespace $NS on TARGET
    k -n "$NS" "$@"
}

kapply() { # Usage: kapply < YAML
    t kubectl apply -n "$NS" -f - >/dev/null
}

log() {
    echo "[$(date +%T)] $*"
}

pass() {
    PASSED=$((PASSED + 1))
    echo "  PASS: $*"
}

fail() {
    FAILED=$((FAILED + 1))
    FAILURES+=("${TEST_NAME:-?}: $*")
    echo "  FAIL: $*"
}

check() { # Usage: check DESCRIPTION CMD... -- pass if CMD succeeds
    local desc="$1"
    shift
    if "$@"; then pass "$desc"; else fail "$desc"; fi
}

summary() {
    echo ""
    echo "=== ${TEST_NAME:-test}: $PASSED passed, $FAILED failed"
    local f
    for f in "${FAILURES[@]}"; do
        echo "  failed: $f"
    done
    [ "$FAILED" == 0 ]
}

serial() {
    if [ -z "$CXL_SERIAL" ]; then
        CXL_SERIAL=$(t "cxl list -M | python3 -c 'import json,sys; print(hex(json.load(sys.stdin)[0][\"serial\"]))'") ||
            { echo "cannot read the serial of a memdev on $TARGET" >&2; return 1; }
    fi
    echo "$CXL_SERIAL"
}

key() { # CXL_<KEY>_, the prefix of the env variables of $CXL_SERIAL
    local s
    s=$(serial) || return 1
    s=${s#0x}
    echo "CXL_${s^^}_"
}

device_name() { # name of the device of $CXL_SERIAL in the ResourceSlice
    echo "memdev-$(serial | sed 's/^0x//')"
}

slice_json() { # the device of $CXL_SERIAL in the ResourceSlices, as JSON
    k get resourceslices -o json | python3 -c '
import json, sys
name = sys.argv[1]
for s in json.load(sys.stdin)["items"]:
    if s["spec"].get("driver") != "cxl.nri.io":
        continue
    for d in s["spec"].get("devices", []):
        if d["name"] == name:
            print(json.dumps(d))
            sys.exit(0)
sys.exit(1)' "$(device_name)"
}

jget() { # Usage: jget JSON PYEXPR -- evaluate PYEXPR on j = JSON
    python3 -c 'import json, sys; j = json.loads(sys.argv[1]); print(eval(sys.argv[2]))' "$1" "$2"
}

wait_for() { # Usage: wait_for TIMEOUT DESCRIPTION CMD... -- retry CMD every second
    local timeout="$1" desc="$2" i
    shift 2
    for ((i = 0; i < timeout; i++)); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "  timeout ($timeout s) waiting for: $desc" >&2
    return 1
}

pod_phase() {
    kn get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null
}

pod_is() { # Usage: pod_is POD PHASE
    [ "$(pod_phase "$1")" == "$2" ]
}

wait_pod() { # Usage: wait_pod POD [PHASE [TIMEOUT]] -- show the events of POD on timeout
    wait_for "${3:-180}" "pod $1 ${2:-Running}" pod_is "$1" "${2:-Running}" ||
        { pod_events "$1" | tail -n 5 | sed 's/^/    event: /' >&2; return 1; }
}

pod_events() { # Usage: pod_events POD -- the events of POD, one line each
    kn get events --field-selector "involvedObject.name=$1" -o jsonpath='{range .items[*]}{.reason}: {.message}{"\n"}{end}'
}

pexec() { # Usage: pexec POD CMD... -- run CMD in container "main" of POD
    kn exec "$1" -c main -- "${@:2}"
}

pod_env() { # Usage: pod_env POD -- the CXL_ variables of POD, sorted
    pexec "$1" sh -c 'env | grep ^CXL_ | sort'
}

pod_env_value() { # Usage: pod_env_value POD SUFFIX -- value of $(key)SUFFIX in POD
    pexec "$1" printenv "$(key)$2"
}

mems_allowed() { # Usage: mems_allowed POD -- Mems_allowed_list of the container of POD
    pexec "$1" sh -c 'grep Mems_allowed_list /proc/self/status' | awk '{print $2}'
}

in_list() { # Usage: in_list N LIST -- is node N in the node list LIST ("0-2,4")
    python3 - "$1" "$2" <<'EOF'
import sys
n, spec = int(sys.argv[1]), sys.argv[2]
nodes = set()
for part in spec.split(","):
    if "-" in part:
        lo, hi = part.split("-")
        nodes.update(range(int(lo), int(hi) + 1))
    elif part:
        nodes.add(int(part))
sys.exit(0 if n in nodes else 1)
EOF
}

node_mib() { # Usage: node_mib N -- MemTotal of NUMA node N in MiB, 0 if it has none
    t "awk '/MemTotal/ {print int(\$4/1024)}' /sys/devices/system/node/node$1/meminfo 2>/dev/null || echo 0"
}

block_bytes() { # memory block size of TARGET in bytes
    t 'echo $((0x$(cat /sys/devices/system/memory/block_size_bytes)))'
}

driver_log() { # Usage: driver_log [SINCE] -- log of the driver
    k logs -n kube-system -l "$DRA_POD_LABEL" --tail=-1 ${1:+--since=$1}
}

tools_configmap() {
    # ConfigMap "tools" with numa-touch.py and dax-rw.py (pool-dax-rw.py)
    # of the e2e tests and alloc-touch.py and dax-pattern.py, mounted at
    # /tools in the test pods.
    {
        echo "apiVersion: v1"
        echo "kind: ConfigMap"
        echo "metadata: {name: tools}"
        echo "data:"
        echo "  alloc-touch.py: |"
        sed 's/^/    /' "$LIB_DIR/alloc-touch.py"
        echo "  dax-scan.py: |"
        sed 's/^/    /' "$LIB_DIR/dax-scan.py"
        echo "  dax-pattern.py: |"
        sed 's/^/    /' "$LIB_DIR/dax-pattern.py"
        echo "  numa-touch.py: |"
        sed 's/^/    /' "$E2E_TOOLS_DIR/numa-touch.py"
        echo "  dax-rw.py: |"
        sed 's/^/    /' "$E2E_TOOLS_DIR/pool-dax-rw.py"
    } | kapply
}

reset_ns() { # delete and create namespace $NS with the tools ConfigMap
    k delete namespace "$NS" --ignore-not-found --wait=true --timeout=300s >/dev/null
    k create namespace "$NS" >/dev/null
    tools_configmap
}

claim_yaml() {
    # Usage: claim_yaml NAME CLASS [memory=SIZE] [shares=N] [mode=MODE] [readonly] [template]
    #
    # A ResourceClaim (a ResourceClaimTemplate with "template") NAME of one
    # request "mem" on DeviceClass CLASS for the device of $CXL_SERIAL.
    local name="$1" class="$2" mem="" shares="" mode="" ro="" template="" a cfg="" caps="" spec
    shift 2
    for a in "$@"; do
        case "$a" in
            memory=*) mem=${a#memory=} ;;
            shares=*) shares=${a#shares=} ;;
            mode=*) mode=${a#mode=} ;;
            readonly) ro=true ;;
            template) template=1 ;;
        esac
    done
    if [ -n "$mem" ]; then
        caps="
        capacity: {requests: {memory: $mem}}"
    elif [ -n "$shares" ]; then
        caps="
        capacity: {requests: {shares: \"$shares\"}}"
    fi
    if [ -n "$mode" ] || [ -n "$ro" ]; then
        cfg="
    config:
    - opaque:
        driver: $DRIVER
        parameters:
          apiVersion: cxl.nri.io/v1alpha1
          kind: DeviceConfig${mode:+
          mode: $mode}${ro:+
          readOnly: true}"
    fi
    spec="
  devices:
    requests:
    - name: mem
      exactly:
        deviceClassName: $class
        selectors:
        - cel: {expression: 'device.attributes[\"$DRIVER\"].serial == \"$(serial)\"'}$caps$cfg"
    if [ -n "$template" ]; then
        echo "apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata: {name: $name}
spec:
  spec:$(sed 's/^/  /' <<< "$spec")"
    else
        echo "apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata: {name: $name}
spec:$spec"
    fi
}

# The main process of the test containers: runs /tmp/run when it appears
# (see prun), so that the commands are its descendants and inherit the
# memory policy that the driver sets on it when it steers the container.
# Commands run with kubectl exec (pexec) do not.
RUNNER='trap exit TERM; while :; do if [ -f /tmp/run ]; then sh /tmp/run > /tmp/run.out 2>&1; echo $? > /tmp/run.rc; rm -f /tmp/run; fi; sleep 0.2 & wait; done'

prun() { # Usage: prun POD SCRIPT [TIMEOUT] -- run SCRIPT as a child of the main process of POD
    local i
    pexec "$1" sh -c 'rm -f /tmp/run.rc /tmp/run.out; printf "%s\n" "$1" > /tmp/run.new && mv /tmp/run.new /tmp/run' sh "$2" || return 1
    for ((i = 0; i < ${3:-300} * 5; i++)); do
        if pexec "$1" test -f /tmp/run.rc 2>/dev/null; then
            pexec "$1" cat /tmp/run.out
            return "$(pexec "$1" cat /tmp/run.rc)"
        fi
        sleep 0.2
    done
    echo "prun: $2 did not finish in ${3:-300} s" >&2
    return 124
}

pod_yaml() {
    # Usage: pod_yaml NAME [claim=CLAIM] [template=TEMPLATE] [lease] [memlimit=SIZE]
    #
    # Pod NAME with one idle container "main" of $TOOLS_IMAGE, the tools in
    # /tools, and the ResourceClaim CLAIM, a claim of TEMPLATE, or a claim
    # of the lease template cxl-lease (lease), if any.
    local name="$1" claim="" template="" lease="" memlimit="" a rc="" res=""
    shift
    for a in "$@"; do
        case "$a" in
            claim=*) claim=${a#claim=} ;;
            template=*) template=${a#template=} ;;
            lease) lease=1 ;;
            memlimit=*) memlimit=${a#memlimit=} ;;
        esac
    done
    if [ -n "$claim" ]; then
        rc="
  resourceClaims:
  - {name: cxl, resourceClaimName: $claim}"
    elif [ -n "$template" ]; then
        rc="
  resourceClaims:
  - {name: cxl, resourceClaimTemplateName: $template}"
    elif [ -n "$lease" ]; then
        rc="
  resourceClaims:
  - {name: cxl, resourceClaimTemplateName: cxl-lease}"
    fi
    if [ -n "$rc" ] || [ -n "$memlimit" ]; then
        res="
    resources:"
        [ -z "$memlimit" ] || res+="
      limits: {memory: $memlimit}"
        [ -z "$rc" ] || res+="
      claims: [{name: cxl}]"
    fi
    echo "apiVersion: v1
kind: Pod
metadata: {name: $name}
spec:
  terminationGracePeriodSeconds: 1
  restartPolicy: Never$rc
  volumes:
  - {name: tools, configMap: {name: tools}}
  containers:
  - name: main
    image: $TOOLS_IMAGE
    imagePullPolicy: IfNotPresent
    command: [sh, -c, \"$RUNNER\"]
    volumeMounts:
    - {name: tools, mountPath: /tools}$res"
}

lease_template_yaml() {
    echo "apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata: {name: cxl-lease}
spec:
  spec:
    devices:
      requests:
      - name: lease
        exactly: {deviceClassName: cxl-lease}"
}

delete_all() { # delete the pods, claims and claim templates of $NS
    kn delete pods --all --grace-period=1 --wait=true --timeout=600s >/dev/null 2>&1
    kn delete resourceclaims --all --wait=true --timeout=600s >/dev/null 2>&1
    kn delete resourceclaimtemplates --all >/dev/null 2>&1
}

region_count() { # number of CXL regions on TARGET
    t "cxl list -R 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0"
}

no_regions() { # is the memdev back in its initial state: no region on it
    [ "$(region_count)" == 0 ]
}
