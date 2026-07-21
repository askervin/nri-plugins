# Test CPU affinity to devices published by device plugins and queried
# from kubelet's PodResourcesAPI.

helm-terminate
helm_config=$TEST_DIR/balloons-podresources.cfg helm-launch balloons

cleanup() {
    vm-command 'pidof fake-device-plugin && kill $(pidof fake-device-plugin) && sleep 1'
}

cleanup

# Install and (re)start fake-device-plugins
vm-command "command -v fake-device-plugin" || {
    HOST_DEVICE_PLUGIN=$OUTPUT_DIR/fake-device-plugin

    [ -f "$HOST_DEVICE_PLUGIN" ] || \
        GOARCH=amd64 go build -o "$HOST_DEVICE_PLUGIN" "${TEST_DIR%%/test/e2e/*}/scripts/testing/fake-device-plugin/fake-device-plugin.go" || \
        error "failed to build $HOST_DEVICE_PLUGIN"

    vm-put-file "$HOST_DEVICE_PLUGIN" "/usr/local/bin/$(basename "$HOST_DEVICE_PLUGIN")"
}

vm-command "cat > fake-tpu.yaml <<EOF
resourceName: tech.com/tpu
devices:
- id: tcomtpus0-numa0
  numaNodes: [0]
- id: tcomtpus0-numa1
  numaNodes: [1]
- id: tcomtpus1-numa2
  numaNodes: [2]
- id: tcomtpus1-numa3
  numaNodes: [3]
EOF
" || command-error "failed to create fake-tpu.yaml"

vm-command "fake-device-plugin -config fake-tpu.yaml >& fake-tpu.output &"

vm-command "cat > fake-nic.yaml <<EOF
resourceName: telco.com/nic
devices:
- id: telconics0-numas01
  numaNodes: [0,1]
- id: telconics1-numas23
  numaNodes: [2,3]
EOF
" || command-error "failed to create fake-nic.yaml"

vm-command "fake-device-plugin -config fake-nic.yaml >& fake-nic.output &"
sleep 1

rounds=0
while vm-command "kubectl describe node \$(hostname) | grep -E 'Capacity|Alloc|telco.com|tech.com'"; do
    ( grep -A2 Allocatable <<< "$COMMAND_OUTPUT" | grep -qE 'tech.com/tpu:.*4' ) && \
        ( grep -A2 Allocatable <<< "$COMMAND_OUTPUT" | grep -qE 'telco.com/nic:.*2' ) && \
        break
    rounds+=$(( rounds + 1 ))
    (( rounds > 10 )) && error "waiting for fake-device-plugin resources timed out"
    sleep 1
done

# burstable containers
CPUREQ=2 CPULIM=4 MEMREQ=10M MEMLIM=50M \
       EXTREQ="telco.com/nic: \"1\"" \
       EXTLIM="telco.com/nic: \"1\"" \
       POD_ANNOTATION="balloon.balloons.resource-policy.nri.io: near-nic" \
       CONTCOUNT=2 \
       create balloons-busybox
report allowed

# TODO: verify both containers received CPUs near their NICs
# Use "kubectl get pod" and jq to read containerStatuses from pod0c0 and pod0c1
# and match numas["pod0c0"] and numas["pod0c1"]


declare -a EXTREQ=( "tech.com/tpu: \"1\"" "cpuclass.balloons.nri.io/pct-hp: \"1\"" )
declare -a EXTLIM=( "tech.com/tpu: \"1\"" "cpuclass.balloons.nri.io/pct-hp: \"1\"" )
CPUREQ=1 CPULIM=1 MEMREQ=10M MEMLIM=10M \
       POD_ANNOTATION="balloon.balloons.resource-policy.nri.io: hp-near-tpu" \
       CONTCOUNT=4 \
       create balloons-busybox
report allowed
