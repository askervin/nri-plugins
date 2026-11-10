# The admission policies of the chart: the driver's service account may
# change only what belongs to its own node
#
# The ClusterRole of the driver lets it create and delete pods and
# ResourceClaims in every namespace (the companions of leases, test12), and
# change ResourceSlices. Two ValidatingAdmissionPolicies of the chart
# (deployment/helm/dra-driver-cxl/templates) narrow that down for the user
# system:serviceaccount:kube-system:nri-dra-driver-cxl, whose node the API
# server knows from the token of its pod (the user extra
# authentication.kubernetes.io/node-name, feature
# ServiceAccountTokenPodNodeInfo):
# - resourceslices-policy-nri-dra-driver-cxl: only the ResourceSlices of
#   its node.
# - lease-companions-policy-nri-dra-driver-cxl: creates only pods and
#   claims with the labels of a lease companion (cxl.nri.io/lease,
#   cxl.nri.io/requester-uid, cxl.nri.io/node) whose node label is its
#   node, and pods only pinned to its node by a required node affinity,
#   without volumes, host namespaces or privileged containers, running the
#   companion image of the chart; deletes only objects with its node label.
#
# The test talks to the API server as the driver of VM2 would: kubectl of
# the cluster's admin impersonates the service account with the node extra
# (--as, --as-user-extra), so the API server authorizes the requests with
# the ClusterRole of the driver and admits them with the policies. Creates
# are server-side dry runs: admission runs as for a real create, and
# nothing is left if a policy admits what it should refuse.
#
# What you will see: both policies Deny-bound and free of type-check
# warnings; a companion-shaped pod and a labelled claim of VM2 admitted;
# refused with the message of the policy: a pod labelled for VM1, a pod
# pinned to VM1, a pod with a hostPath volume, in the host network, with a
# privileged container, with another image, an unlabelled claim, a request
# of a user without a node, and the deletion of a claim of VM1; a labelled
# claim of VM2 deleted as the driver does it (foreground). Then the real
# thing: a pool lease of a running container (test12) whose companion pod
# and claim the driver creates and, at the release, deletes under the
# policy, and an orphan companion claim (a lease name, no lease) that the
# driver deletes at its next reconcile (at most 60 s).
#
# Everything happens on VM2, the VM of the test (n4-cxl-shared-2), the
# control plane of the cluster of VM2, VM1 and VM0. Run test00-up of
# n4-cxl-shared-1, -0 and -2 first: they create the VMs and make them one
# cluster. The DRA driver comes from its image, build it first:
#   make PLUGINS=nri-dra-driver-cxl SKIP_LICENSES=1 OTHER_IMAGE_TARGETS= BINARIES= images

if [[ "$distro" != *"fedora"* ]]; then
    echo "Test verdict: SKIP (this test runs only on fedora)"
    exit 0
fi

echo "### preconditions: one cluster, VM2 control plane, VM1 and VM0 workers (test00-up)"
pool-cluster-require

VM1="$POOL_VM1_DIR"    # a worker of the cluster
VM1_NAME="$POOL_VM1_NAME"
VM2="$OUTPUT_DIR"      # the VM of this test, the control plane
VM2_NAME="$POOL_VM2_NAME"
POOLED0_SERIAL=0xc1ee0001   # 0xc1ee....: exclusive pool devices
PYTHON_IMAGE=docker.io/library/python:3-alpine
PAUSE_IMAGE=registry.k8s.io/pause:3.10   # leases.companionImage of the chart
DRIVER_USER=system:serviceaccount:kube-system:nri-dra-driver-cxl
NODE_EXTRA=authentication.kubernetes.io/node-name
POLICY=lease-companions-policy-nri-dra-driver-cxl
SLICE_POLICY=resourceslices-policy-nri-dra-driver-cxl
ORPHAN=cxl-lease-0badc0de   # a companion claim without a lease

driver-kubectl() {
    # Usage: driver-kubectl NODE KUBECTL-ARGS...
    #
    # Run "kubectl KUBECTL-ARGS" in namespace $DRA_NS in VM2 as the service
    # account of the driver on node NODE ("" for a user without a node).
    # With "-f -" in KUBECTL-ARGS the YAML comes from stdin. COMMAND_OUTPUT
    # has the output, COMMAND_STATUS the exit status, which is returned.
    local node="$1" as yaml
    shift
    as="--as=$DRIVER_USER"
    [ -z "$node" ] || as+=" --as-user-extra=$NODE_EXTRA=$node"
    if [[ " $* " == *" -f - "* ]]; then
        yaml=$(cat)
        dra-vm-command "$VM2" "kubectl $as -n $DRA_NS $* <<'DRIVER_KUBECTL_EOF'
$yaml
DRIVER_KUBECTL_EOF"
    else
        dra-vm-command "$VM2" "kubectl $as -n $DRA_NS $*"
    fi
}

admitted() {
    # Usage: admitted WHAT
    #
    # Fail the test unless the last driver-kubectl succeeded.
    [ "$COMMAND_STATUS" == 0 ] ||
        error "$1: refused, expected the driver of $VM2_NAME to be allowed: $COMMAND_OUTPUT"
    echo "admitted: $1"
}

policy-denied() {
    # Usage: policy-denied WHAT MESSAGE
    #
    # Fail the test unless the last driver-kubectl failed, denied by the
    # companion policy with MESSAGE.
    [ "$COMMAND_STATUS" != 0 ] ||
        error "$1: admitted, expected $POLICY to refuse it"
    grep -qF "ValidatingAdmissionPolicy '$POLICY' with binding '$POLICY' denied request: $2" <<< "$COMMAND_OUTPUT" ||
        error "$1: not denied by $POLICY with \"$2\""
    echo "denied by $POLICY: $1"
}

companion-pod-yaml() {
    # Usage: companion-pod-yaml NODE-LABEL AFFINITY-NODE [SPEC-LINES [CONTAINER-LINES [IMAGE]]]
    #
    # Print pod fake-companion in the shape of a companion pod: the labels
    # of lease 0badc0de with node label NODE-LABEL, a required node affinity
    # to AFFINITY-NODE, no service account token, one container of IMAGE
    # (default $PAUSE_IMAGE). CONTAINER-LINES are added to the container
    # (indented by 4), SPEC-LINES to the spec (indented by 2).
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: fake-companion
  labels:
    $DRA_LEASE_LABEL: 0badc0de
    $DRA_REQUESTER_LABEL: 00000000-0000-0000-0000-00000badc0de
    $DRA_NODE_LABEL: $1
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchFields:
          - {key: metadata.name, operator: In, values: [$2]}
  automountServiceAccountToken: false
  enableServiceLinks: false
  containers:
  - name: pause
    image: ${5:-$PAUSE_IMAGE}
EOF
    [ -z "$4" ] || echo "$4"
    [ -z "$3" ] || echo "$3"
}

labelled-claim-yaml() {
    # Usage: labelled-claim-yaml NAME [NODE-LABEL]
    #
    # Print an empty ResourceClaim NAME with the labels of lease 0badc0de
    # and node label NODE-LABEL, without labels if NODE-LABEL is not given.
    # No pod uses it. The driver of the node deletes it as an orphan only
    # when NAME is $ORPHAN, the name of the companion of the lease.
    cat <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: $1
EOF
    [ -z "$2" ] || cat <<EOF
  labels:
    $DRA_LEASE_LABEL: 0badc0de
    $DRA_REQUESTER_LABEL: 00000000-0000-0000-0000-00000badc0de
    $DRA_NODE_LABEL: $2
EOF
    echo "spec: {}"
}

borrower-yaml() {
    # Usage: borrower-yaml
    #
    # Pod "borrower" on VM2 with a lease claim from a template: its
    # container main may lease memory (test12).
    dra-lease-template-yaml cxl-lease
    cat <<EOF
---
apiVersion: v1
kind: Pod
metadata:
  name: borrower
spec:
  nodeSelector:
    kubernetes.io/hostname: $VM2_NAME
  terminationGracePeriodSeconds: 2
  restartPolicy: Never
  resourceClaims:
  - name: cxl
    resourceClaimTemplateName: cxl-lease
  containers:
  - name: main
    image: $PYTHON_IMAGE
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "trap 'exit 0' TERM; sleep infinity & wait"]
    resources:
      claims:
      - name: cxl
EOF
}

echo "### preconditions: patched qemu, hdm_for_passthrough=on, kernel with CONFIG_FS_DAX"
pool-vm-require "$VM2" "$(basename "$TOPOLOGY_DIR")"

echo "### preconditions: no CXL memory devices in VM2 and VM1"
pool-vm-tools-install "$VM2"
pool-vm-reset "$VM2"
pool-vm-reset "$VM1"

echo "### preconditions: fake-cxl-pool-server on the host, one exclusive device"
pool-server-start "
  - name: pooled0
    size: 512Mi
    shared: false
    pool: default
    serial: $POOLED0_SERIAL"
pool-client-install "$VM2"

echo "### preconditions: the pool controller and the driver run in the cluster"
dra-build
dra-install
dra-pull-images "$VM2" "$PYTHON_IMAGE" "$PAUSE_IMAGE"

echo "### A: the policies of the chart"
for p in "$SLICE_POLICY" "$POLICY"; do
    # The API server type-checks a policy against the kinds it matches and
    # reports the expressions that do not fit in its status.
    dra-wait "$VM2" "policy-$p" "validatingadmissionpolicy $p" \
        "j.get('status', {}).get('observedGeneration') == j['metadata']['generation'] and not j['status'].get('typeChecking', {}).get('expressionWarnings')" 30
    dra-assert "$COMMAND_OUTPUT" "j['spec']['failurePolicy'] == 'Fail' and [c['expression'] for c in j['spec']['matchConditions']] == ['request.userInfo.username == \"$DRIVER_USER\"']"
    dra-json "$VM2" validatingadmissionpolicybinding "$p" ||
        command-error "no ValidatingAdmissionPolicyBinding $p"
    dra-assert "$COMMAND_OUTPUT" "j['spec']['policyName'] == '$p' and j['spec']['validationActions'] == ['Deny']"
done
dra-json "$VM2" validatingadmissionpolicy "$POLICY"
dra-assert "$COMMAND_OUTPUT" "sorted((r['apiGroups'], r['resources'], sorted(r['operations'])) for r in j['spec']['matchConstraints']['resourceRules']) == [([''], ['pods'], ['CREATE', 'DELETE']), (['resource.k8s.io'], ['resourceclaims'], ['CREATE', 'DELETE'])]"
# An orphan: a companion claim of VM2 without a lease. The driver of VM2
# deletes it at its next reconcile, checked in E.
dra-apply "$VM2" <<< "$(labelled-claim-yaml "$ORPHAN" "$VM2_NAME")"

echo "### B: what the driver of VM2 may create and delete"
driver-kubectl "$VM2_NAME" create --dry-run=server -f - <<< "$(companion-pod-yaml "$VM2_NAME" "$VM2_NAME")"
admitted "a companion pod of $VM2_NAME"
driver-kubectl "$VM2_NAME" create -f - <<< "$(labelled-claim-yaml own-node-object "$VM2_NAME")"
admitted "a labelled claim of $VM2_NAME"
# The driver deletes companions with foreground propagation.
driver-kubectl "$VM2_NAME" delete resourceclaim own-node-object --cascade=foreground --wait=true --timeout=30s
admitted "the deletion of a labelled claim of $VM2_NAME"

echo "### C: what the policy refuses the driver of VM2"
driver-kubectl "$VM2_NAME" create --dry-run=server -f - <<< "$(companion-pod-yaml "$VM1_NAME" "$VM1_NAME")"
policy-denied "a companion pod of $VM1_NAME" \
    "this user running on node '$VM2_NAME' may not create pods of node '$VM1_NAME'"
driver-kubectl "$VM2_NAME" create --dry-run=server -f - <<< "$(companion-pod-yaml "$VM2_NAME" "$VM1_NAME")"
policy-denied "a pod of $VM2_NAME pinned to $VM1_NAME" \
    "this user running on node '$VM2_NAME' may create only pods whose required node affinity selects that node by metadata.name in every term"
driver-kubectl "$VM2_NAME" create --dry-run=server -f - <<< "$(companion-pod-yaml "$VM2_NAME" "$VM2_NAME" "  volumes:
  - {name: root, hostPath: {path: /}}" "    volumeMounts:
    - {name: root, mountPath: /host}")"
policy-denied "a pod with a hostPath volume" \
    "this user may not create pods with volumes"
driver-kubectl "$VM2_NAME" create --dry-run=server -f - <<< "$(companion-pod-yaml "$VM2_NAME" "$VM2_NAME" "  hostNetwork: true")"
policy-denied "a pod in the host network" \
    "this user may not create pods in the host network, PID or IPC namespace"
driver-kubectl "$VM2_NAME" create --dry-run=server -f - <<< "$(companion-pod-yaml "$VM2_NAME" "$VM2_NAME" "" "    securityContext: {privileged: true}")"
policy-denied "a pod with a privileged container" \
    "this user may not create pods with privileged containers"
driver-kubectl "$VM2_NAME" create --dry-run=server -f - <<< "$(companion-pod-yaml "$VM2_NAME" "$VM2_NAME" "" "" "$PYTHON_IMAGE")"
policy-denied "a pod of another image" \
    "this user may create only pods whose containers run the companion image $PAUSE_IMAGE"
driver-kubectl "$VM2_NAME" create --dry-run=server -f - <<< "$(labelled-claim-yaml unlabelled-object)"
policy-denied "an unlabelled claim" \
    "this user may create only resourceclaims with the labels $DRA_LEASE_LABEL, $DRA_REQUESTER_LABEL and $DRA_NODE_LABEL of a lease companion"
driver-kubectl "" create --dry-run=server -f - <<< "$(companion-pod-yaml "$VM2_NAME" "$VM2_NAME")"
policy-denied "a companion pod of a user without a node" \
    "no node association found for user, this user must run in a pod on a node and ServiceAccountTokenPodNodeInfo must be enabled"
# The admin is not restricted: it creates a labelled claim of VM1, which
# the driver of VM2 may not delete.
dra-apply "$VM2" <<< "$(labelled-claim-yaml other-node-object "$VM1_NAME")"
driver-kubectl "$VM2_NAME" delete resourceclaim other-node-object
policy-denied "the deletion of a labelled claim of $VM1_NAME" \
    "this user running on node '$VM2_NAME' may not delete resourceclaims of node '$VM1_NAME'"
dra-json "$VM2" resourceclaim -n "$DRA_NS" other-node-object ||
    error "claim other-node-object is gone, the driver of $VM2_NAME deleted it"
dra-delete "$VM2" resourceclaim other-node-object

echo "### D: the companion of a real lease, created and deleted by the driver"
dra-apply "$VM2" <<< "$(borrower-yaml)"
dra-pod-wait "$VM2" borrower Running 60
dra-json "$VM2" pod -n "$DRA_NS" borrower
BORROWER_UID=$(dra-value "$COMMAND_OUTPUT" "j['metadata']['uid']")
dra-exec "$VM2" borrower/main "$DRA_REQUEST_CTR_BIN" request --source pool --size 512Mi --wait 120s ||
    command-error "cxl-request request --source pool --size 512Mi failed"
json=$(dra-last-json "$COMMAND_OUTPUT") || error "cxl-request printed no JSON response"
dra-assert "$json" "j.get('state') == 'Ready' and j.get('source') == 'pool' and j.get('serial') == '$POOLED0_SERIAL'"
LEASE=$(dra-value "$json" "j['lease']")
COMPANION="cxl-lease-$LEASE"
# The pod as the API server admitted it, after the mutating admission
# (default service account, tolerations): what the policy checked.
dra-pod-wait "$VM2" "$COMPANION" Running 30
dra-json "$VM2" pod -n "$DRA_NS" "$COMPANION"
dra-companion-meta-check "$COMMAND_OUTPUT" "$LEASE" "$BORROWER_UID" "$VM2_NAME" "$DRA_NS/borrower/main"
dra-assert "$COMMAND_OUTPUT" "j['spec']['affinity']['nodeAffinity']['requiredDuringSchedulingIgnoredDuringExecution']['nodeSelectorTerms'] == [{'matchFields': [{'key': 'metadata.name', 'operator': 'In', 'values': ['$VM2_NAME']}]}]"
dra-assert "$COMMAND_OUTPUT" "not j['spec'].get('volumes') and not any(j['spec'].get(k) for k in ('hostNetwork', 'hostPID', 'hostIPC'))"
dra-assert "$COMMAND_OUTPUT" "[(c['image'], bool(c.get('securityContext', {}).get('privileged'))) for c in j['spec']['containers'] + j['spec'].get('initContainers', [])] == [('$PAUSE_IMAGE', False)]"
dra-json "$VM2" resourceclaim -n "$DRA_NS" "$COMPANION" ||
    command-error "no companion claim $COMPANION"
dra-companion-meta-check "$COMMAND_OUTPUT" "$LEASE" "$BORROWER_UID" "$VM2_NAME" "$DRA_NS/borrower/main"
dra-exec "$VM2" borrower/main "$DRA_REQUEST_CTR_BIN" release --lease "$LEASE" ||
    command-error "cxl-request release --lease $LEASE failed"
dra-assert "$(dra-last-json "$COMMAND_OUTPUT")" "j.get('lease') == '$LEASE' and j.get('state') == 'Released'"
dra-wait "$VM2" companion-pod-deleted "pods -n $DRA_NS -l $DRA_LEASE_LABEL=$LEASE" "items == []" 90
dra-wait "$VM2" companion-claim-deleted "resourceclaims -n $DRA_NS" "'$COMPANION' not in names()" 90
dra-leases "$VM2" borrower/main
dra-assert "$DRA_LEASES" "j == []"

echo "### E: the orphan companion claim, deleted by the driver"
dra-wait "$VM2" orphan-deleted "resourceclaims -n $DRA_NS" "'$ORPHAN' not in names()" 90
dra-plugin-log "$VM2" | grep -E "lease broker: (deleting companion|lease $LEASE: created companion)" | tail -n 10

echo "### cleanup"
dra-delete "$VM2" pod borrower --grace-period=2 --wait=true --timeout=60s
dra-cleanup
pool-cleanup
trap - EXIT
pool-port-busy && error "port $POOL_PORT is still busy after stopping the server"
echo "the driver of $VM2_NAME created and deleted its companions under $POLICY"
