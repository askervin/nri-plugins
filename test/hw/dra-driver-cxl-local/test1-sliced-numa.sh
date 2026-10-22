#!/bin/bash
# Test 1: a sliced local memdev as extra NUMA memory of several containers.
#
# Two containers claim slices of the local CXL memdev in mode numa (the
# default of DeviceClass cxl-local), a third container has no claim:
#
#   numa-a  claim numa-a, 4Gi
#   numa-b  claim numa-b, 2Gi
#   plain   no claim
#
# Checks that both slices are onlined on the same new NUMA node N, that N
# has the size of the slices, that N is in Mems_allowed of numa-a and
# numa-b but not of plain, that the memory of numa-a and numa-b lands on N
# (default policy set by the driver's steering, and an explicit
# MPOL_PREFERRED), that plain cannot use N, that a container's memory on N
# stays within its claim, and that N shrinks and goes away when the claims
# are released, leaving no region on the memdev.
#
# The workloads run as descendants of the main process of the containers
# (prun), which inherit the memory policy that the driver sets when it
# steers a container; processes of kubectl exec do not, which is shown
# separately.
#
# Needs the driver deployed with "deploy.sh sliced".
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
TEST_NAME=test1-sliced-numa
GiB=$((1 << 30))

log "$TEST_NAME: memdev $(serial) on $TARGET, memory block size $(block_bytes)"
reset_ns
check "the memdev is published as a sliced local device" \
    test "$(jget "$(slice_json)" 'j["attributes"]["shared"]["bool"]')" == False

log "creating claims numa-a (4Gi), numa-b (2Gi) and pods numa-a, numa-b, plain"
t0=$EPOCHSECONDS
{ claim_yaml numa-a cxl-local memory=4Gi; echo ---; pod_yaml numa-a claim=numa-a; } | kapply
wait_pod numa-a Running 300
log "numa-a Running after $((EPOCHSECONDS - t0)) s"
t0=$EPOCHSECONDS
{ claim_yaml numa-b cxl-local memory=2Gi; echo ---; pod_yaml numa-b claim=numa-b; echo ---; pod_yaml plain; } | kapply
wait_pod numa-b Running 300
wait_pod plain Running 300
log "numa-b and plain Running after $((EPOCHSECONDS - t0)) s"

for p in numa-a numa-b; do
    echo "  env of $p:"
    pod_env "$p" | sed 's/^/    /'
done
check "numa-a: CXL_<KEY>_MODE=numa" test "$(pod_env_value numa-a MODE)" == numa
check "numa-b: CXL_<KEY>_MODE=numa" test "$(pod_env_value numa-b MODE)" == numa
check "numa-a: CXL_<KEY>_SIZE=4Gi" test "$(pod_env_value numa-a SIZE)" == $((4 * GiB))
check "numa-b: CXL_<KEY>_SIZE=2Gi" test "$(pod_env_value numa-b SIZE)" == $((2 * GiB))
N=$(pod_env_value numa-a NODE)
NB=$(pod_env_value numa-b NODE)
check "numa-a and numa-b are on the same node ($N, $NB)" test -n "$N" -a "$N" == "$NB"
log "CXL node N=$N"
t "numactl -H | grep -E '^available|^node $N '" | sed 's/^/    /'
mib=$(node_mib "$N")
check "node $N has the memory of both slices, 6144 MiB (MemTotal $mib MiB)" \
    test "$mib" -le 6144 -a "$mib" -ge $((6144 - 256))

ma=$(mems_allowed numa-a)
mb=$(mems_allowed numa-b)
mp=$(mems_allowed plain)
log "Mems_allowed_list: numa-a=$ma numa-b=$mb plain=$mp"
check "node $N is in Mems_allowed of numa-a ($ma)" in_list "$N" "$ma"
check "node $N is in Mems_allowed of numa-b ($mb)" in_list "$N" "$mb"
check "node $N is not in Mems_allowed of plain ($mp)" eval "! in_list $N $mp"
for p in numa-a numa-b plain; do
    echo "  cpuset.mems.effective of $p: $(pexec "$p" cat /sys/fs/cgroup/cpuset.mems.effective)"
done

pages_on() { # Usage: pages_on OUTPUT NODE -- 4K pages on NODE in the last "pages" line
    grep 'pages ' <<< "$1" | tail -n 1 | tr ' ' '\n' | sed -n "s/^N$2=//p" | grep . || echo 0
}

log "numa-a: 1024 MiB with the default memory policy (the driver steers it)"
out=$(prun numa-a "python3 /tools/alloc-touch.py 1024" 2>&1)
echo "$out" | sed 's/^/    /'
p=$(pages_on "$out" "$N")
check "numa-a: >= 90% of 1024 MiB of default allocations on node $N ($p pages)" test "$p" -ge $((1024 * 256 * 9 / 10))
check "numa-a: the memory holds what was written" grep -q "verify ok" <<< "$out"
log "numa-a: 1024 MiB with the default policy in a process of kubectl exec (not a descendant of the steered process)"
for i in 1 2 3; do
    out=$(pexec numa-a python3 /tools/alloc-touch.py 1024 2>&1)
    echo "    try $i: $(grep pages <<< "$out") (informational: the policy of the steering is not inherited)"
done

log "numa-b: 1024 MiB preferring node $N (numa-touch.py)"
out=$(prun numa-b "python3 /tools/numa-touch.py 1024 $N" 2>&1)
echo "$out" | sed 's/^/    /'
p=$(pages_on "$out" "$N")
check "numa-b: >= 90% of 1024 MiB preferring node $N on it ($p pages)" test "$p" -ge $((1024 * 256 * 9 / 10))

log "plain: numa-touch.py preferring node $N must fail (not in Mems_allowed)"
out=$(prun plain "python3 /tools/numa-touch.py 64 $N" 2>&1)
rc=$?
echo "$out" | sed 's/^/    /'
check "plain: set_mempolicy(MPOL_PREFERRED, $N) is refused (exit $rc)" test "$rc" == 1
out=$(prun plain "python3 /tools/alloc-touch.py 512" 2>&1)
echo "$out" | sed 's/^/    /'
check "plain: no page of 512 MiB of default allocations on node $N" test "$(pages_on "$out" "$N")" == 0

log "numa-a and numa-b hold memory on node $N at the same time"
prun numa-a "setsid python3 /tools/alloc-touch.py --hold 2048 > /tmp/hold.log 2>&1 < /dev/null &"
prun numa-b "setsid python3 /tools/numa-touch.py --hold 1536 $N > /tmp/hold.log 2>&1 < /dev/null &"
holders_ready() { pexec numa-a grep -q ready /tmp/hold.log && pexec numa-b grep -q ready /tmp/hold.log; }
wait_for 120 "holders ready" holders_ready
ha=$(pexec numa-a cat /tmp/hold.log)
hb=$(pexec numa-b cat /tmp/hold.log)
echo "$ha" | sed 's/^/    numa-a: /'
echo "$hb" | sed 's/^/    numa-b: /'
t "grep -E 'MemTotal|MemUsed|MemFree' /sys/devices/system/node/node$N/meminfo" | sed 's/^/    /'
check "numa-a holds >= 90% of 2048 MiB on node $N" test "$(pages_on "$ha" "$N")" -ge $((2048 * 256 * 9 / 10))
check "numa-a: the held memory holds what was written" grep -q "verify ok" <<< "$ha"
check "numa-b holds >= 90% of 1536 MiB on node $N" test "$(pages_on "$hb" "$N")" -ge $((1536 * 256 * 9 / 10))

log "beyond the claim: numa-b (2Gi claim, holding 1.5 GiB) holds 2048 MiB more with the default policy"
prun numa-b "setsid python3 /tools/alloc-touch.py --hold 2048 > /tmp/more.log 2>&1 < /dev/null &"
more_ready() { pexec numa-b grep -q ready /tmp/more.log; }
wait_for 120 "numa-b holds 2048 MiB more" more_ready
pexec numa-b cat /tmp/more.log | sed 's/^/    /'
n3=$(pexec numa-b sh -c "grep '^anon ' /sys/fs/cgroup/memory.numa_stat" | tr ' ' '\n' | sed -n "s/^N$N=//p")
echo "  numa-b: anon memory on node $N $((n3 >> 20)) MiB, memory.high $(pexec numa-b cat /sys/fs/cgroup/memory.high), memory.max $(pexec numa-b cat /sys/fs/cgroup/memory.max), Mems_allowed $(mems_allowed numa-b)"
check "numa-b: its memory on node $N stays within its 2Gi claim (+64 MiB) ($((n3 >> 20)) MiB)" test "$n3" -le $(((2048 + 64) << 20))
pexec numa-b pkill -f alloc-touch.py
pexec numa-a pkill -f alloc-touch.py
pexec numa-b pkill -f numa-touch.py
sleep 2

log "releasing numa-b: node $N shrinks to the 4Gi of numa-a"
t0=$EPOCHSECONDS
kn delete pod numa-b --wait=true --timeout=300s >/dev/null
kn delete resourceclaim numa-b --wait=true --timeout=300s >/dev/null
shrunk() { [ "$(node_mib "$N")" -le 4096 ]; }
check "node $N shrinks to <= 4096 MiB in 120 s" wait_for 120 "node $N shrinks" shrunk
log "node $N has $(node_mib "$N") MiB, $((EPOCHSECONDS - t0)) s after the delete"
check "numa-a still runs with node $N in Mems_allowed" in_list "$N" "$(mems_allowed numa-a)"

log "releasing numa-a and plain: node $N goes away, no region is left"
t0=$EPOCHSECONDS
delete_all
gone() { [ "$(node_mib "$N")" == 0 ]; }
check "node $N has no memory in 120 s" wait_for 120 "node $N empty" gone
check "no CXL region is left on the memdev" wait_for 60 "no regions" no_regions
log "released in $((EPOCHSECONDS - t0)) s"

log "driver log of the steering of numa-a and numa-b"
driver_log 15m | grep -E "numa-[ab]/main: " | sed 's/^[^]]*] //; s/^/    /' | cut -c1-300 | tail -n 40

log "driver log of the slices (local:)"
driver_log 15m | grep -E "local: " | sed 's/^[^]]*] //; s/^/    /' | tail -n 30

summary
