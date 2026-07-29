TESTNS=repro-dup
# Triggering transient duplicates is timing sensitive. We might need to
# adjust these for our bigger nightly test machine.
PODS=16
CONTAINERS=3

setup() {
    vm-command "kubectl create namespace $TESTNS"
    helm_config=$(instantiate helm-config.yaml) helm-launch topology-aware
}

cleanup() {
    vm-command "kubectl delete pods -n $TESTNS --all --now || :"
    vm-command "kubectl delete namespace $TESTNS --now || :"
    helm-terminate
}

create-containers() {
    n=$PODS CONTCOUNT=$CONTAINERS CPUREQ=150m namespace=$TESTNS wait='' create burstable
}

kill-containers() {
    local commands=""

    commands="pkill -9 -f nri-resource-policy-topology-aware || :"
    case ${k8scri:-containerd} in
        containerd)
            vm-command 'pkill -9 -f nri-resource-policy-topology-aware || :; \
                       kill -9 $(pidof containerd) || :; \
                       pkill -9 -f "sleep inf" || :'
            ;;
        cri-o)
            vm-command 'pkill -9 -f nri-resource-policy-topology-aware || :; \
                       kill -9 $(pidof crio) || :; \
                       pkill -9 -f "sleep inf" || :'
            ;;
        *)
            error "Unknown runtime: $runtime"
            ;;
    esac
}

wait-containers-restart() {
    local statuses="" pod=""

    while ! [[ "$statuses" == "Running" ]]; do
        vm-command "kubectl get pods -A --no-headers=true | tr -s '\t' ' '| cut -d ' ' -f4 | sort -u"
        statuses=$COMMAND_OUTPUT
        [[ "$statuses" == *"Running"*"Unknown"* ]] && (
            vm-command "kubectl get pods -A -o name | grep topology-aware"
            pod=$COMMAND_OUTPUT
            if [ -n "$pod" ]; then
                vm-command "kubectl delete -n kube-system $pod"
            fi
            sleep 5
        )
    done
}

check-transient-duplicates-present() {
    # Check that we managed to trigger transient duplicate containers.
    if ! grep -q -E '(remap)|(keeping.*mapped)' <<< $COMMAND_OUTPUT; then
        echo "No remapping of containers found in the logs..."
        return 1
    fi
    return 0
}

check-remap-disambiguation() {
    # Verify that each duplicate was disambiguated by creation time.
    if grep -E '(remap)|(keeping.*mapped)' <<< $COMMAND_OUTPUT | \
            grep -v 'by creation time'; then
        grep -E '(remap)|(keeping.*mapped)' <<< $COMMAND_OUTPUT | \
            grep -v 'by creation time' | sed 's/^/INCORRECT: /g'
        error "Found some incorrectly remapped containers in the logs"
    fi

    echo "Only found correctly remapped containers in the logs..."
    grep -E '(remap)|(keeping.*mapped)' <<< $COMMAND_OUTPUT | sed 's/^/CORRECT: /g'
}

check-no-duplicate-allocations() {
    # Verify that we did not end up with duplicate allocation entries.
    if grep -q -i 'duplicate allocation entries' <<< $COMMAND_OUTPUT; then
        grep -i 'duplicate allocation entries' <<< $COMMAND_OUTPUT | sed 's/^/DUPLICATE: /g'
        error "Found duplicate allocation entries in the logs"
    fi
}

pull-logs() {
    local cnt=0
    while [ $cnt -lt 5 ]; do
        vm-command "kubectl logs -n kube-system ds/nri-resource-policy-topology-aware"
        if grep -q 'unable to retrieve container logs for' <<< $COMMAND_OUTPUT; then
            echo "Unable to retrieve policy logs, retrying..."
            sleep 3
            let cnt=$ctn+1
        else
            return 0
        fi
    done
    return 1
}

check-logs() {
    if ! pull-logs; then
        echo "Failed to pull policy logs..."
        return 1
    fi

    if ! check-transient-duplicates-present; then
        return 1
    fi

    check-remap-disambiguation
    check-no-duplicate-allocations

    return 0
}

cleanup
setup
create-containers

retries=0
while true; do
    kill-containers
    wait-containers-restart

    if check-logs; then
        break
    fi

    echo "Retrying..."
    let retries=$retries+1

    if [ $retries -ge 5 ]; then
        echo "Max retries ($retries) reached, could not reproduce the issue, giving up"
        break
    fi
done

cleanup
