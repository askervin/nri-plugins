// Copyright The NRI Plugins Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cxl

type Devices struct {
	SysfsPath       string            // Sysfs path to the CXL bus, e.g. /sys/bus/cxl
	MemoryDevices   []*MemoryDevice   // Memory devices on this CXL bus
	RegionDevices   []*RegionDevice   // Region devices on this CXL bus
	EndpointDevices []*EndpointDevice // Endpoint devices on this CXL bus
	MemoryNodes     []*MemoryNode     // System memory node, e.g. /sys/devices/system/node/node0
}

// Memory device in sysfs:
// # grep -sr . /sys/bus/cxl/devices/mem0/* | python -c 'import sys; [print(l.count("/"), l) for l in sys.stdin]' | sort -n
// 6 /sys/bus/cxl/devices/mem0/dev:251:0
// 6 /sys/bus/cxl/devices/mem0/firmware_version:BWFW VERSION 00
// 6 /sys/bus/cxl/devices/mem0/label_storage_size:0
// 6 /sys/bus/cxl/devices/mem0/numa_node:0
// 6 /sys/bus/cxl/devices/mem0/payload_max:2048
// 6 /sys/bus/cxl/devices/mem0/serial:0xc100e2e0
// 6 /sys/bus/cxl/devices/mem0/uevent:DEVTYPE=cxl_memdev
// 6 /sys/bus/cxl/devices/mem0/uevent:DRIVER=cxl_mem
// 6 /sys/bus/cxl/devices/mem0/uevent:MAJOR=251
// 6 /sys/bus/cxl/devices/mem0/uevent:MINOR=0
// 6 /sys/bus/cxl/devices/mem0/uevent:MODALIAS=cxl:t5
// 7 /sys/bus/cxl/devices/mem0/pmem/size:0x0
// 7 /sys/bus/cxl/devices/mem0/ram/size:0x10000000
// 7 /sys/bus/cxl/devices/mem0/security/state:disabled
// 7 /sys/bus/cxl/devices/mem0/subsystem/drivers_autoprobe:1
// 7 /sys/bus/cxl/devices/mem0/uevent:DEVNAME=cxl/mem0
// 8 /sys/bus/cxl/devices/mem0/firmware/mem0/loading:0
// 8 /sys/bus/cxl/devices/mem0/firmware/mem0/remaining_size:0
// 8 /sys/bus/cxl/devices/mem0/firmware/mem0/status:idle
// 9 /sys/bus/cxl/devices/mem0/firmware/mem0/power/control:auto
// 9 /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_active_kids:0
// 9 /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_active_time:0
// 9 /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_enabled:disabled
// 9 /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_status:unsupported
// 9 /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_suspended_time:0
// 9 /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_usage:0

// MemoryDevice represents a CXL memory device
// See https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-bus-cxl
// for more details.
type MemoryDevice struct {
	SysfsPath       string // Sysfs path to the memory device, e.g. /sys/bus/cxl/devices/mem0
	Name            string // Memory device name, e.g. "mem0"
	DevName         string // uvent DEVNAME, e.g. "cxl/mem0"
	RamSize         uint64 // RAM (volatile memory) size in bytes
	PmemSize        uint64 // PMEM (persistent memory) size in bytes
	FirmwareVersion string // FirmwareVersion string
	Serial          uint64 // 64-bit PCIe device serial number
	NodeAffinity    int    // NUMA node affinity, CPU node on host, -1 if not set
	Driver          string // Driver name from uevent, e.g. "cxl_mem". Empty when memdev is disabled.
	Major           int    // Major device number from uevent
	Minor           int    // Minor device number from uevent
	Enabled         bool   // Whether the memory device is enabled (Driver != "")
}

// Memory region in sysfs (dax_regionY is a subdirectory in regionX):
// # grep -sr . /sys/bus/cxl/devices/region0 | python -c 'import sys; [print(l.count("/"), l) for l in sys.stdin]' | sort -n
// 6 /sys/bus/cxl/devices/region0/commit:1
// 6 /sys/bus/cxl/devices/region0/devtype:cxl_region
// 6 /sys/bus/cxl/devices/region0/interleave_granularity:256
// 6 /sys/bus/cxl/devices/region0/interleave_ways:1
// 6 /sys/bus/cxl/devices/region0/modalias:cxl:t6
// 6 /sys/bus/cxl/devices/region0/mode:ram
// 6 /sys/bus/cxl/devices/region0/resource:0x5d0000000
// 6 /sys/bus/cxl/devices/region0/size:0x10000000
// 6 /sys/bus/cxl/devices/region0/target0:decoder4.0
// 6 /sys/bus/cxl/devices/region0/uevent:DEVTYPE=cxl_region
// 6 /sys/bus/cxl/devices/region0/uevent:DRIVER=cxl_region
// 6 /sys/bus/cxl/devices/region0/uevent:MODALIAS=cxl:t6
// 7 /sys/bus/cxl/devices/region0/dax_region0/devtype:cxl_dax_region
// 7 /sys/bus/cxl/devices/region0/dax_region0/modalias:cxl:t8
// 7 /sys/bus/cxl/devices/region0/dax_region0/uevent:DEVTYPE=cxl_dax_region
// 7 /sys/bus/cxl/devices/region0/dax_region0/uevent:DRIVER=cxl_dax_region
// 7 /sys/bus/cxl/devices/region0/dax_region0/uevent:MODALIAS=cxl:t8
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/align:2097152
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/dev:252:0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/memmap_on_memory:1
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/modalias:dax:t0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/numa_node:-1
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/resource:0x5d0000000
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/size:268435456
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/target_node:2
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/uevent:DEVNAME=dax0.0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/uevent:DRIVER=kmem
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/uevent:MAJOR=252
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/uevent:MINOR=0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/uevent:MODALIAS=dax:t0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax_region/align:2097152
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax_region/available_size:0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax_region/id:0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax_region/size:268435456
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/end:0x5dfffffff
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/page_offset:0x0
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/start:0x5d0000000
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/control:auto
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_active_kids:0
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_active_time:0
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_enabled:disabled
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_status:unsupported
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_suspended_time:0
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_usage:0
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/control:auto
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_active_kids:0
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_active_time:0
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_enabled:disabled
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_status:unsupported
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_suspended_time:0
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_usage:0

// RegionDevice represents a memory region device in sysfs
type RegionDevice struct {
	SysfsPath  string          // Sysfs path to the region device, e.g. /sys/bus/cxl/devices/region0
	Name       string          // Region name, e.g. "region0"
	Size       uint64          // Size in bytes
	Resource   uint64          // Resource start address
	Mode       string          // Mode string, e.g. "ram"
	Node       int             // NUMA node where region memory is located, -1 if region is disabled
	OnlineSize uint64          // Size of onlined memory in bytes (may be 0 even if region is enabled)
	Targets    []string        // Target decoders, e.g. ["decoder4.0", "decoder7.0"]
	Memories   []*MemoryDevice // Memory devices associated with this region
	Enabled    bool            // Whether the region is enabled (Node != -1)
}

type EndpointDevice struct {
	SysfsPath    string                    // Sysfs path to the endpoint device, e.g. /sys/bus/cxl/devices/endpoint4
	UportMajor   int                       // Major device number of the uport
	UportMinor   int                       // Minor device number of the uport
	UportDevName string                    // Device name of the uport, e.g. "cxl/mem0"
	Decoders     map[string]*DecoderDevice // Decoders in this endpoint, key is decoder name
}

type MemoryNode struct {
	SysfsPath string // Sysfs path to the memory node, e.g. /sys/devices/system/node/node0
	ID        int    // Node ID, e.g. 0
	Name      string // Node name, e.g. "node0"
	Size      uint64 // Size in bytes
}

type DecoderDevice struct {
	SysfsPath string // Sysfs path to the decoder device, e.g. /sys/bus/cxl/devices/decoder4.0
	Name      string // Decoder name, e.g. "decoder4.0"
	Mode      string // Decoder mode, e.g. "ram"
	Region    string // Associated region name, e.g. "region0"
}

// Creating a region with the cxl tool from two memory devices:
// (requires that both memory devices are enabled and in same decoder)
// # cxl enable-memdev mem0
// # cxl enable-memdev mem1
// # cxl create-region -t ram -d decoder0.0 -m mem0,mem2
// {
//   "region":"region0",
//   "resource":"0x5d0000000",
//   "size":"512.00 MiB (536.87 MB)",
//   "type":"ram",
//   "interleave_ways":2,
//   "interleave_granularity":256,
//   "decode_state":"commit",
//   "mappings":[
//     {
//       "position":1,
//       "memdev":"mem2",
//       "decoder":"decoder7.0"
//     },
//     {
//       "position":0,
//       "memdev":"mem0",
//       "decoder":"decoder4.0"
//     }
//   ],
//   "qos_class_mismatch":true
// }
// cxl region: cmd_create_region: created 1 region
//
// The created region will then appear in sysfs under /sys/bus/cxl/devices/regionX
// # grep -sr . /sys/bus/cxl/devices/region0/* | python -c 'import sys; [print(l.count("/"), l.strip()) for l in sys.stdin]' | sort -n
// 6 /sys/bus/cxl/devices/region0/commit:1
// 6 /sys/bus/cxl/devices/region0/devtype:cxl_region
// 6 /sys/bus/cxl/devices/region0/interleave_granularity:256
// 6 /sys/bus/cxl/devices/region0/interleave_ways:2
// 6 /sys/bus/cxl/devices/region0/modalias:cxl:t6
// 6 /sys/bus/cxl/devices/region0/mode:ram
// 6 /sys/bus/cxl/devices/region0/resource:0x5d0000000
// 6 /sys/bus/cxl/devices/region0/size:0x20000000
// 6 /sys/bus/cxl/devices/region0/target0:decoder4.0
// 6 /sys/bus/cxl/devices/region0/target1:decoder7.0
// 6 /sys/bus/cxl/devices/region0/uevent:DEVTYPE=cxl_region
// 6 /sys/bus/cxl/devices/region0/uevent:DRIVER=cxl_region
// 6 /sys/bus/cxl/devices/region0/uevent:MODALIAS=cxl:t6
// 7 /sys/bus/cxl/devices/region0/dax_region0/devtype:cxl_dax_region
// 7 /sys/bus/cxl/devices/region0/dax_region0/modalias:cxl:t8
// 7 /sys/bus/cxl/devices/region0/dax_region0/uevent:DEVTYPE=cxl_dax_region
// 7 /sys/bus/cxl/devices/region0/dax_region0/uevent:DRIVER=cxl_dax_region
// 7 /sys/bus/cxl/devices/region0/dax_region0/uevent:MODALIAS=cxl:t8
// 7 /sys/bus/cxl/devices/region0/subsystem/drivers_autoprobe:1
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/align:2097152
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/dev:252:0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/memmap_on_memory:1
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/modalias:dax:t0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/numa_node:-1
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/resource:0x5d0000000
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/size:536870912
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/target_node:2
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/uevent:DEVNAME=dax0.0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/uevent:DRIVER=kmem
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/uevent:MAJOR=252
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/uevent:MINOR=0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/uevent:MODALIAS=dax:t0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax_region/align:2097152
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax_region/available_size:0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax_region/id:0
// 8 /sys/bus/cxl/devices/region0/dax_region0/dax_region/size:536870912
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/end:0x5efffffff
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/page_offset:0x0
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/start:0x5d0000000
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/control:auto
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_active_kids:0
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_active_time:0
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_enabled:disabled
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_status:unsupported
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_suspended_time:0
// 9 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/power/runtime_usage:0
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/control:auto
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_active_kids:0
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_active_time:0
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_enabled:disabled
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_status:unsupported
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_suspended_time:0
// 10 /sys/bus/cxl/devices/region0/dax_region0/dax0.0/mapping0/power/runtime_usage:0
//
//

// # Online memory as movable to prevent kernel using it:
// for f in /sys/devices/system/node/node2/memory*/state; do echo online_movable > $f; done
// # Immediately reserve pages as 2MB hugepages on node2:
// # to prevent the kernel from using them for regular allocations
// echo 256 > /sys/devices/system/node/node2/hugepages/hugepages-2048kB/nr_hugepages
// # View free pages on node2, should be zeroes now:
// grep 'Node\s*2' /proc/pagetypeinfo

// Tracing cxl memdevs behind a cxl region that combines here mem0 and mem2.
//
// Step 1: find targets of region0
//   # grep . /sys/bus/cxl/devices/region0/target*
//   /sys/bus/cxl/devices/region0/target0:decoder4.0
//   /sys/bus/cxl/devices/region0/target1:decoder7.0
//
// Step 2: find endpoints of decoders
//   # find /sys/bus/cxl/devices/endpoint*/ -name decoder4.0 -o -name decoder7.0
//   /sys/bus/cxl/devices/endpoint4/decoder4.0
//   /sys/bus/cxl/devices/endpoint7/decoder7.0
//
// Step 3: find memory devices behind endpoints by following their uports
//   # grep -sr . /sys/bus/cxl/devices/endpoint7/uport/uevent
//   MAJOR=251
//   MINOR=2
//   DEVNAME=cxl/mem2
//   DEVTYPE=cxl_memdev
//   DRIVER=cxl_mem
//   MODALIAS=cxl:t5
//
// for region in /sys/bus/cxl/devices/region*; do for decoder in $(cat $region/target*); do echo -n "# $region/target* $decoder "; for decoder_in_endpoint in $(find /sys/bus/cxl/devices/endpoint*/ -name $decoder); do endpoint=${decoder_in_endpoint%/*}; echo "found in $endpoint"; grep DEVNAME $endpoint/uport/uevent; done; done;  done

// /sys/devices/platform/ACPI0017:00/root0/port2/port3/dport1/0000:0f:00.0/mem0/uevent:DEVNAME=cxl/mem0

// ZoneInfo is read from /proc/zoneinfo
type ZoneInfo struct {
	FilePath      string // path to contents, e.g. /proc/zoneinfo
	PfnToNode     map[int64]int
	NodeToPresent map[int]uint64 // number of pages present per node
}

// NewDevices creates a new Devices instance
func NewDevices() *Devices {
	return &Devices{}
}

// NewMemoryDevice creates a new MemoryDevice instance
func NewMemoryDevice() *MemoryDevice {
	return &MemoryDevice{}
}

// NewRegionDevice creates a new RegionDevice instance
func NewRegionDevice() *RegionDevice {
	return &RegionDevice{
		Node: -1,
	}
}

// NewEndpointDevice creates a new EndpointDevice instance
func NewEndpointDevice() *EndpointDevice {
	return &EndpointDevice{
		Decoders: make(map[string]*DecoderDevice),
	}
}

// NewMemoryNode creates a new MemoryNode instance
func NewMemoryNode() *MemoryNode {
	return &MemoryNode{}
}

// NewDecoderDevice creates a new DecoderDevice instance
func NewDecoderDevice() *DecoderDevice {
	return &DecoderDevice{}
}

func NewZoneInfo() *ZoneInfo {
	return &ZoneInfo{
		PfnToNode:     make(map[int64]int),
		NodeToPresent: make(map[int]uint64),
	}
}

// Note: cxl destroy-region region0 --force
// removes the region even if memdevs are still enabled and in use.
// In a test where a process used memory (movable 2MB hugepages) from the region
// continued to work after kernel automatically moved its data to other physical memory
// (data written to the hugepages was preserved and successfully read from new hugepages on node 0).

func (ds *Devices) GetRegionDevices() []*RegionDevice {
	return ds.RegionDevices
}

func (rd *RegionDevice) GetName() string {
	return rd.Name
}

func (rd *RegionDevice) GetMode() string {
	return rd.Mode
}

func (rd *RegionDevice) GetSize() uint64 {
	return rd.Size
}

func (rd *RegionDevice) GetNode() int {
	return rd.Node
}
