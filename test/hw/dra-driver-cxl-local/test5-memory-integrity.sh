#!/bin/bash
# Test 5: does every byte of the local memdev hold what was written?
#
# 1. One dax claim of the whole sliced memdev: dax-scan.py writes every
#    4 KiB page and reads it back, and reports runs of pages that hold the
#    data of another offset (aliasing).
# 2. Isolation of slices: claim a (2Gi dax, the first slice of the region),
#    claim filler (126Gi dax) and claim c (2Gi dax, 128 GiB after a). a
#    writes a pattern into its slice, c writes another into its slice,
#    and a verifies its own slice: with aliasing at 128 GiB, c's writes
#    corrupt a's slice.
#
# Needs the driver deployed with "deploy.sh sliced" and an idle memdev.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
TEST_NAME=test5-memory-integrity

log "$TEST_NAME: memdev $(serial) on $TARGET"
reset_ns

log "1. the whole memdev as one dax slice"
{ claim_yaml whole cxl-local mode=dax; echo ---; pod_yaml whole claim=whole; } | kapply
wait_pod whole Running 600 || fail "pod whole is not Running"
DAX=$(pod_env_value whole DAX)
echo "  whole: $DAX, $(( $(pod_env_value whole SIZE) >> 30 )) GiB"
t "cat /sys/bus/cxl/devices/region*/resource /sys/bus/dax/devices/${DAX#/dev/}/mapping*/start /sys/bus/dax/devices/${DAX#/dev/}/mapping*/end" | tr '\n' ' ' | sed 's/^/  region, slice start, end: /'
echo
out=$(pexec whole python3 /tools/dax-scan.py 0x77 2>&1)
echo "$out" | sed 's/^/    /'
check "every page of the memdev holds what was written (no aliasing)" grep -q "^bad pages 0 " <<< "$out"
delete_all

log "2. slices a (offset 0), filler (126Gi), c (offset 128 GiB)"
{ claim_yaml a cxl-local memory=2Gi mode=dax; echo ---; pod_yaml a claim=a; } | kapply
wait_pod a Running 300
{ claim_yaml filler cxl-local memory=126Gi mode=dax; echo ---; pod_yaml filler claim=filler; } | kapply
wait_pod filler Running 600
{ claim_yaml c cxl-local memory=2Gi mode=dax; echo ---; pod_yaml c claim=c; } | kapply
wait_pod c Running 300
for p in a filler c; do
    d=$(pod_env_value "$p" DAX)
    echo "  $p: $d at $(t "cat /sys/bus/dax/devices/${d#/dev/}/mapping*/start | tr '\n' ' '")"
done
DA=$(pod_env_value a DAX)
DC=$(pod_env_value c DAX)
pexec a python3 /tools/dax-pattern.py write "$DA" 0xaaaa | sed 's/^/    a: /'
out=$(pexec a python3 /tools/dax-pattern.py verify "$DA" 0xaaaa 2>&1)
echo "    a: $out"
check "a: its slice holds its pattern before c writes" grep -q " bad 0 " <<< "$out"
pexec c python3 /tools/dax-pattern.py write "$DC" 0xcccc | sed 's/^/    c: /'
out=$(pexec a python3 /tools/dax-pattern.py verify "$DA" 0xaaaa 2>&1)
echo "    a: $out"
check "a: c's writes do not change a's slice" grep -q " bad 0 " <<< "$out"
delete_all
check "no CXL region is left on the memdev" wait_for 120 "no regions" no_regions

summary
