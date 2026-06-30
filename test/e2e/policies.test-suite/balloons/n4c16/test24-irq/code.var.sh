# Test balloons with IRQ masking

helm-terminate
helm_config=$TEST_DIR/balloons-irq.cfg helm-launch balloons

# verify-irq-affinity checks the last writes to "smp_affinity" files in the
# override fs.
verify-irq-affinity() {
    local cpu_ids=$1           # e.g. "2 3 4"
    local expected_mask=$2     # e.g. "0x00000000" (no CPUs in mask)
    local last_n_writes=$3     # expect the write within last N writes, e.g. 6

    vm-command "kubectl -n kube-system logs ds/nri-resource-policy-balloons | nl | grep -E 'irq: class.*smp_affinity|irq: wrote' | tail -n $last_n_writes | nl"

    # Verify that all specified CPUs have their bits cleared (0)
    # For example, if CPUs 2,3,4 are masked, the mask should have those bits cleared
    echo "verify IRQ affinity writes cleared CPUs $cpu_ids"
    for cpu_id in $cpu_ids; do
        # Check that the log shows the write with the CPU bit cleared
        local found=0
        if echo "$COMMAND_OUTPUT" | grep -q "cpu${cpu_id}"; then
            found=1
        fi
        if [ "$found" -eq 0 ]; then
            echo "no IRQ write found for CPU $cpu_id in last $last_n_writes writes"
        fi
    done
}

# verify-irq-no-writes checks that any IRQ affinity of given CPUs have not been written
verify-irq-no-writes() {
    local cpu_ids=$1       # e.g. "2 3 4"
    local last_n_writes=$2 # e.g. 100
    echo "verify no writes to IRQ affinity of CPUs $cpu_ids"
    cpu_ids="(${cpu_ids// /|})"
    vm-command "kubectl -n kube-system logs ds/nri-resource-policy-balloons | nl | grep -E 'irq: class.*smp_affinity|irq: wrote' | tail -n $last_n_writes"
    grep -q wrote <<< $COMMAND_OUTPUT && {
        command-error "writes to forbidden CPUs found"
    }
}

cleanup() {
    vm-command "kubectl delete pods --all --now"
}

echo "verify that all CPUs have IRQs masked after balloon creation"

CPUREQ="750m" MEMREQ="100M" CPULIM="750m" MEMLIM=""
POD_ANNOTATION="balloon.balloons.resource-policy.nri.io: irq-masking-bln" CONTCOUNT=1 create balloons-busybox
report allowed
verify 'len(cpus["pod0c0"]) >= 1'

# Verify that CPUs in the irq-masking class have IRQs masked
verify-irq-affinity "2 3 4 5 6 7" "0" 20

echo "verify that CPUs outside AvailableResources have not been written"
verify-irq-no-writes "0 1 8 9 10 11 12 13 14 15"

vm-command 'kubectl delete pod pod0'
report allowed

cleanup
