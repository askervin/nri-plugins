# WS-D: realistic e2e tests, test12 onwards (plan)

Status: plan written 2026-10-06 (Fable). Implementation after test10/11
pass; each test is a separate small agent task using dra.source.sh and
pool.source.sh. All in memory.test-suite/memory-policy/n4-cxl-shared-2
unless noted. Cases are chosen to prove the acceptance criteria of
../plan/70-dra-driver-followup.md and the ordering/failure semantics of
10-contract.md section 7.

| Test | Proves | Steps and assertions |
|---|---|---|
| test12-dra-pool-exhausted | A second exclusive claim waits, it does not fail | Server: one exclusive device. Claim+pod A gets it. Claim+pod B: pod stays Pending with a scheduler event about no allocatable device; claim B has no allocation and no AttachFailed. Delete A: B gets the device within one scheduling cycle (attach, Attached, Running); the server shows exactly one attachment at any time (sample attachments every second during the switch). |
| test13-dra-controller-restart | Restart safety of the stateless reconcile | While pod A runs: `systemctl restart fake-cxl-pool-controller`; after restart no second attach (server attachment count and qemu id unchanged), claim status unchanged. Restart the controller again while a new claim B is in BindingConditionsPending (stop controller, create B, wait 10 s, start): B attaches once and runs. Delete B while the controller is stopped, start it: detach happens. |
| test14-dra-attach-failure | AttachFailed path and recovery | Variant 1: node that is not a pool host: start the server with discovery names of VM1 only (VM2 unknown) while the cluster is VM2: claim gets AttachFailed reason NoHost, pod stays Pending; scheduler deallocates (claim status.allocation cleared within a scheduling cycle), event visible; restart the server with VM2 in discovery: the next allocation succeeds without touching the pod. Variant 2: device attached manually (fake-cxl-pool-client attach pooled0 --host VM1) before the claim: AttachFailed Conflict; manual detach -> recovery. Assert the controller never detached the manual attachment (owner not k8s:). |
| test15-dra-shared-same-node | Refcount per (device, node) | Two claims for the same shared device in VM2's cluster, two pods: one attachment, one region, both pods see the same /dev/daxX.Y (the same major:minor), write in one, read in the other. Delete one claim: attachment and region stay; delete the second: released and detached. Also: one claim referenced by two pods (reservedFor 2): the second pod binds without waiting (no BindingConditionsPending for it). |
| test16-dra-driver-restart | Node plugin state file | While a pooled pod runs: `systemctl restart kubelet-cxl-plugin`; the pod keeps running, the cxl.generic slice still has no cxl-node device for the pool region (D29 from the restored set), a second pod on the same claim starts (Prepare returns the stored result); delete everything: the restarted plugin releases the device. |
| test17-dra-mixed-claim | Two drivers in one claim, memory steering | Claim with requests: dram (class dram-memory-class from the cxl.generic dram device, 64Mi) and pooled CXL (cxl-pool-memory 256Mi). Pod runs (two NodePrepare calls, one per driver). Then the steering question of D24: with DRAM in cpuset.mems the container starts; verify from the host which NUMA nodes the container's memory.numa_stat grows on when a memgrow-style workload runs. Outcome documents whether pool devices should feed NRI steering when DRAM is present (design input, not pass/fail on steering). |
| test18-dra-controller-deployment | RBAC and in-cluster deployment | Build the controller image (podman, FROM scratch + binary), `ctr -n k8s.io images import`, apply deploy/fake-cxl-pool-controller.yaml (hostNetwork), run the test10 story through it. Proves the ClusterRole (resourceclaims/driver arbitrary-node:*) is sufficient and nothing more is needed. Then remove one rule (resourceclaims/driver) and show the exact failure in the controller log (status write forbidden) to document why the rule exists. |
| test19-dra-binding-timeout | Scheduler timeout path | KubeSchedulerConfiguration with DynamicResources bindingTimeout 30s (edit /etc/kubernetes/manifests/kube-scheduler.yaml to pass --config; restore afterwards). Stop the controller, create claim+pod: after 30 s the scheduler deallocates and retries; start the controller: pod runs. Documents the default 600 s and how to lower it. |
| test20-dra-local-and-pool-preference (n4-cxl topology or shared-2 with a local beram device plugged) | Pools without binding conditions win | Plug a local device (vm-cxl-hotplug) and create its region so the node has a cxl-node device; a claim that both devices could satisfy (class selecting either driver via a union DeviceClass or two requests firstAvailable) gets the node-local device, not the pool. |

Not planned as automated tests (hazards documented in the contract):
force-deleting a pod with pooled memory (zombie device until the VM
restarts), onlining a shared device as RAM in two VMs (corruption).

Shared helpers that these tests will need beyond test10/11: `dra-unit-restart VMDIR UNIT`,
`dra-events VMDIR OBJECT` (events of a claim or pod as text),
`dra-attachment-watch` (sample server attachments in the background and
assert the maximum count), kube-scheduler config edit/restore helpers.
