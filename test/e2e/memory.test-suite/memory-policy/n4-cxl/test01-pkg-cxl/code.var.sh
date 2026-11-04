# Test that pkg/cxl reads CXL hardware from sysfs correctly. Drive the CXL
# memory devices of the VM through the states below, and check after each of
# them what the cxl-dump tool, that is, pkg/cxl, makes of the result.
# - No CXL memory devices at all.
# - A memory device plugged in, enabled and disabled.
# - A region of a single memory device, enabled but without online memory,
#   with a part of its memory online, and fully online.
# - A region interleaved over two memory devices.
# - Two regions, one on each host bridge, on separate NUMA nodes.
# - Memory devices hotremoved.
#
# The CXL hardware of the n4-cxl topology: two host bridges, each with a switch
# with two hotpluggable 256M memory devices, none of them present at boot.
# cxl_memdev0 and cxl_memdev1 are behind the host bridge of NUMA node 0,
# cxl_memdev2 and cxl_memdev3 behind the one of node 1. Each host bridge has a
# memory window of its own, so memory devices can be interleaved only within a
# host bridge, and a single HDM decoder, so each host bridge can host only one
# region at a time.

if [[ "$distro" != *"fedora"* ]]; then
    echo "SKIP: this test runs only on fedora"
    exit 0
fi

# CXL needs the kernel built for this topology, and the tools to drive it.
vm-kernel-pkgs-install
cxl-tools-install

MEM_SIZE=$(( 256 * 1024 * 1024 ))

echo "### no CXL memory devices"
cxl-reset
cxl-dump no-devices
cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
cxl-assert 'len(nodes) == 2'
cxl-assert 'all(n["Size"] > 0 for n in nodes)'
cxl-assert 'd["SysfsPath"] == "/sys/bus/cxl/devices"'

echo "### cxl_memdev0 hotplugged: the kernel binds it and creates an endpoint"
cxl-hotplug cxl_memdev0
cxl-assert 'len(memdevs) == 1 and len(endpoints) == 1 and regions == []'
cxl-assert 'memdevs[0]["Name"] == "mem0"'
cxl-assert 'memdevs[0]["Serial"] == 0xc100e2e0'
cxl-assert "memdevs[0][\"RamSize\"] == $MEM_SIZE"
cxl-assert 'memdevs[0]["PmemSize"] == 0'
cxl-assert 'memdevs[0]["Enabled"] and memdevs[0]["Driver"] == "cxl_mem"'
cxl-assert 'memdevs[0]["DevName"] == "cxl/mem0"'
cxl-assert 'memdevs[0]["Major"] > 0'
# The memory device is behind the host bridge of NUMA node 0.
cxl-assert 'memdevs[0]["NodeAffinity"] == 0'
# The endpoint of the device is the one with its device numbers, and none of
# its decoders belongs to a region yet.
cxl-assert 'endpoints[0]["UportMajor"] == memdevs[0]["Major"]'
cxl-assert 'endpoints[0]["UportMinor"] == memdevs[0]["Minor"]'
cxl-assert 'endpoints[0]["UportDevName"] == "cxl/mem0"'
cxl-assert 'all(dec["Region"] == "" for dec in endpoints[0]["Decoders"].values())'
cxl-assert 'len(endpoints[0]["Decoders"]) > 0'

echo "### mem0 disabled: no driver, no endpoint"
vm-command "cxl disable-memdev mem0" || command-error "cannot disable mem0"
cxl-wait mem0-disabled 'not memdevs[0]["Enabled"]'
cxl-assert 'len(memdevs) == 1 and endpoints == []'
cxl-assert 'memdevs[0]["Driver"] == ""'
cxl-assert "memdevs[0][\"RamSize\"] == $MEM_SIZE"

echo "### region of mem0, enabled, memory offline"
vm-command "cxl enable-memdev mem0" || command-error "cannot enable mem0"
vm-command "cxl create-region -t ram -d decoder0.0 -m mem0" ||
    command-error "cannot create a region of mem0"
cxl-wait region-offline 'len(regions) == 1 and regions[0]["Enabled"]'
cxl-assert 'regions[0]["Name"] == "region0"'
cxl-assert 'regions[0]["Mode"] == "ram"'
cxl-assert "regions[0][\"Size\"] == $MEM_SIZE"
cxl-assert 'regions[0]["Resource"] > 0'
cxl-assert 'len(regions[0]["Targets"]) == 1'
cxl-assert 'names(regions[0]["Memories"]) == ["mem0"]'
# The target decoder of the region is a decoder of the endpoint of mem0, and it
# is the only decoder there that belongs to a region.
cxl-assert 'regions[0]["Targets"][0] in endpoints[0]["Decoders"]'
cxl-assert '[dec["Region"] for dec in endpoints[0]["Decoders"].values()].count("region0") == 1'
cxl-assert 'endpoints[0]["Decoders"][regions[0]["Targets"][0]]["Mode"] == "ram"'
# The node of the region comes from the dax device of the region, as there is
# no online memory to find it from. It is a new node, not one of the CPUs.
cxl-assert 'regions[0]["Node"] not in cpu_nodes()'
cxl-assert 'regions[0]["OnlineSize"] == 0'
cxl-assert 'node(regions[0]["Node"])["Size"] == 0'
REGION_NODE=$(cxl-value 'regions[0]["Node"]')
vm-command "grep . /sys/bus/cxl/devices/region0/dax_region*/dax*/target_node" ||
    command-error "cannot read the target node of region0"
grep -q "^$REGION_NODE\$" <<< "$COMMAND_OUTPUT" ||
    error "pkg/cxl reported node $REGION_NODE for region0, dax target_node says $COMMAND_OUTPUT"
vm-command "cxl list -R -u | grep -A1 region0" # region as the cxl tool sees it

echo "### last memory block of the region online"
cxl-memory-state online_movable $(cxl-region-blocks region0 last)
cxl-wait region-partially-online 'regions[0]["OnlineSize"] > 0'
# Nothing but the amount of online memory changes when only a part of the
# region is online. Now the node comes from a zone that starts in the middle
# of the region.
cxl-assert "regions[0][\"Node\"] == $REGION_NODE"
cxl-assert "regions[0][\"OnlineSize\"] == $CXL_BLOCK_SIZE"
cxl-assert "regions[0][\"OnlineSize\"] < regions[0][\"Size\"]"
cxl-assert "node($REGION_NODE)[\"Size\"] == regions[0][\"OnlineSize\"]"

echo "### all memory blocks of the region online"
cxl-memory-state online_movable $(cxl-region-blocks region0 all)
cxl-wait region-online 'regions[0]["OnlineSize"] == regions[0]["Size"]'
cxl-assert "regions[0][\"Node\"] == $REGION_NODE"
cxl-assert "regions[0][\"OnlineSize\"] == $MEM_SIZE"
cxl-assert "node($REGION_NODE)[\"Size\"] == regions[0][\"OnlineSize\"]"

echo "### region interleaved over mem0 and mem1 of the same host bridge"
cxl-memory-state offline $(cxl-region-blocks region0 all)
vm-command "cxl disable-region region0 && cxl destroy-region region0" ||
    command-error "cannot destroy region0"
cxl-hotplug cxl_memdev1
cxl-assert 'len(memdevs) == 2 and regions == []'
cxl-assert 'names(memdevs) == ["mem0", "mem1"]'
cxl-assert 'all(m["NodeAffinity"] == 0 for m in memdevs)'
vm-command "cxl create-region -t ram -d decoder0.0 -m mem0 mem1" ||
    command-error "cannot create an interleaved region of mem0 and mem1"
cxl-wait interleaved-region 'len(regions) == 1 and regions[0]["Enabled"]'
cxl-assert "regions[0][\"Size\"] == 2 * $MEM_SIZE"
cxl-assert 'len(regions[0]["Targets"]) == 2'
cxl-assert 'names(regions[0]["Memories"]) == ["mem0", "mem1"]'
cxl-assert 'len(set(regions[0]["Targets"])) == 2'
cxl-memory-state online_movable $(cxl-region-blocks region0 all)
cxl-wait interleaved-region-online 'regions[0]["OnlineSize"] == regions[0]["Size"]'
cxl-assert "regions[0][\"OnlineSize\"] == 2 * $MEM_SIZE"
cxl-assert 'node(regions[0]["Node"])["Size"] == regions[0]["OnlineSize"]'

echo "### second region on the other host bridge"
cxl-hotplug cxl_memdev2
cxl-assert 'memdevs[-1]["Serial"] == 0xc100e2e2'
# cxl_memdev2 is behind the host bridge of NUMA node 1, unlike mem0 and mem1.
cxl-assert 'by_serial(0xc100e2e2)["NodeAffinity"] == 1'
vm-command "cxl create-region -t ram -d decoder0.1 -m mem2" ||
    command-error "cannot create a region of mem2"
cxl-wait two-regions 'len(regions) == 2 and all(r["Enabled"] for r in regions)'
cxl-assert 'names(regions) == ["region0", "region1"]'
cxl-assert 'names(by_name(regions, "region1")["Memories"]) == ["mem2"]'
cxl-assert "by_name(regions, \"region1\")[\"Size\"] == $MEM_SIZE"
# Every region has a NUMA node of its own, and its own amount of online memory.
cxl-assert 'len(set(r["Node"] for r in regions)) == 2'
cxl-assert 'not set(r["Node"] for r in regions) & set(cpu_nodes())'
cxl-assert 'by_name(regions, "region1")["OnlineSize"] == 0'
cxl-assert "by_name(regions, \"region0\")[\"OnlineSize\"] == 2 * $MEM_SIZE"
cxl-memory-state online_movable $(cxl-region-blocks region1 all)
cxl-wait two-regions-online 'all(r["OnlineSize"] == r["Size"] for r in regions)'
cxl-assert "by_name(regions, \"region1\")[\"OnlineSize\"] == $MEM_SIZE"
cxl-assert "by_name(regions, \"region0\")[\"OnlineSize\"] == 2 * $MEM_SIZE"
cxl-assert 'all(node(r["Node"])["Size"] == r["OnlineSize"] for r in regions)'
cxl-assert 'len(nodes) == 4'
vm-command "numactl -H" # nodes as the kernel presents them

echo "### region1 disabled"
cxl-memory-state offline $(cxl-region-blocks region1 all)
vm-command "cxl disable-region region1" || command-error "cannot disable region1"
cxl-wait region1-disabled 'not by_name(regions, "region1")["Enabled"]'
cxl-assert 'by_name(regions, "region1")["Node"] == -1'
cxl-assert 'by_name(regions, "region1")["OnlineSize"] == 0'
# Disabling the region does not disable the memory device it uses.
cxl-assert 'by_serial(0xc100e2e2)["Enabled"]'
# ...and leaves the other region alone.
cxl-assert 'by_name(regions, "region0")["Enabled"]'
cxl-assert "by_name(regions, \"region0\")[\"OnlineSize\"] == 2 * $MEM_SIZE"

echo "### all memory devices hotremoved"
vm-command "cxl destroy-region region1" || command-error "cannot destroy region1"
cxl-memory-state offline $(cxl-region-blocks region0 all)
vm-command "cxl disable-region region0 && cxl destroy-region region0" ||
    command-error "cannot destroy region0"
vm-command "cxl disable-memdev mem0 mem1 mem2" ||
    command-error "cannot disable the memory devices"
cxl-hotremove cxl_memdev2
cxl-hotremove cxl_memdev1
cxl-hotremove cxl_memdev0
cxl-dump devices-removed
cxl-assert 'memdevs == [] and regions == [] and endpoints == []'
cxl-assert 'len(nodes) == 2'

# The CXL memory devices of this VM cannot be hotplugged again before qemu
# restarts, so leave the VM without them. cxl-reset does the restart when the
# next test needs the devices back.
