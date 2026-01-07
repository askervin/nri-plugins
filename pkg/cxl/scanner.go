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

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func DevicesFromSysfs(sysfsRoot string) (*Devices, error) {
	devicesPath := sysfsRoot + "/sys/bus/cxl/devices"

	devices := NewDevices()
	devices.SysfsPath = devicesPath
	deviceEntries, err := os.ReadDir(devicesPath)
	if err != nil {
		return nil, err
	}
	for _, deviceEntry := range deviceEntries {
		switch {
		case strings.HasPrefix(deviceEntry.Name(), "mem"):
			sysfsMemdevPath := devicesPath + "/" + deviceEntry.Name()
			memdev, err := memoryDeviceFromSysfs(sysfsMemdevPath)
			if err != nil {
				return nil, err
			}
			devices.MemoryDevices = append(devices.MemoryDevices, memdev)
		case strings.HasPrefix(deviceEntry.Name(), "region"):
			sysfsRegionPath := devicesPath + "/" + deviceEntry.Name()
			region, err := regionDeviceFromSysfs(sysfsRegionPath)
			if err != nil {
				return nil, err
			}
			devices.RegionDevices = append(devices.RegionDevices, region)
		case strings.HasPrefix(deviceEntry.Name(), "endpoint"):
			sysfsEndpointPath := devicesPath + "/" + deviceEntry.Name()
			endpoint, err := endpointDeviceFromSysfs(sysfsEndpointPath)
			if err != nil {
				return nil, err
			}
			devices.EndpointDevices = append(devices.EndpointDevices, endpoint)
		}
	}

	if len(devices.RegionDevices) > 0 {
		if err := linkRegionsToMemoryDevices(devices); err != nil {
			return nil, err
		}
		if err := linkRegionsToNumaNodes(sysfsRoot, devices); err != nil {
			return nil, err
		}
	}
	return devices, nil
}

func linkRegionsToMemoryDevices(devices *Devices) error {
	devToMemdev := make(map[string]*MemoryDevice)
	for _, memdev := range devices.MemoryDevices {
		dev := fmt.Sprintf("%d:%d", memdev.Major, memdev.Minor)
		devToMemdev[dev] = memdev
	}

	// Regions have multiple target decoders, each of which may point to a memory device
	// via endpoint/decoderX/region and region/targetX.
	regionToDevs := make(map[string][]string)
	for _, endpoint := range devices.EndpointDevices {
		for _, decoder := range endpoint.Decoders {
			if decoder.Region != "" {
				dev := fmt.Sprintf("%d:%d", endpoint.UportMajor, endpoint.UportMinor)
				regionToDevs[decoder.Region] = append(regionToDevs[decoder.Region], dev)
			}
		}
	}

	for _, region := range devices.RegionDevices {
		devs := regionToDevs[region.Name]
		for _, dev := range devs {
			memdev, exists := devToMemdev[dev]
			if exists {
				region.Memories = append(region.Memories, memdev)
			}
		}
	}

	return nil
}

func linkRegionsToNumaNodes(sysfsRoot string, devices *Devices) error {
	zoneInfo := NewZoneInfo()
	err := parse(func(p *parser) error {
		data, err := p.getFileContent(sysfsRoot + "/proc/zoneinfo")
		if err != nil {
			return err
		}
		var nodeID int = -1
		var startPfn int64 = -1
		var lineNumber int
		for line := range strings.SplitSeq(data, "\n") {
			lineNumber++
			switch {
			case strings.HasPrefix(line, "Node "):
				_, err := fmt.Sscanf(line, "Node %d,", &nodeID)
				if err != nil {
					return fmt.Errorf("failed to parse Node number in /proc/zoneinfo line %d: %w", lineNumber, err)
				}
			case strings.HasPrefix(line, "  start_pfn:"):
				_, err := fmt.Sscanf(line, "  start_pfn: %d", &startPfn)
				if err != nil {
					return fmt.Errorf("failed to parse start_pfn in /proc/zoneinfo line %d: %w", lineNumber, err)
				}
				if nodeID == -1 {
					return fmt.Errorf("found start_pfn before Node in /proc/zoneinfo line %d", lineNumber)
				}
				zoneInfo.PfnToNode[startPfn] = nodeID
				nodeID = -1
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, region := range devices.RegionDevices {
		startPfn := int64(region.Resource >> 12)
		endPfn := startPfn + (int64(region.Size) >> 12) - 1
		node, ok := zoneInfo.PfnToNode[startPfn]
		if !ok {
			// not all memories are onlined, so try to find any node in the range
			for pfn := range zoneInfo.PfnToNode {
				if pfn >= startPfn && pfn <= endPfn {
					node = zoneInfo.PfnToNode[pfn]
					ok = true
					fmt.Printf("DEBUG: found NUMA node %d for region %s with resource %x at pfn %x that fits between start_pfn %x and end_pfn %x\n", node, region.Name, region.Resource, pfn, startPfn, endPfn)
					break
				}
			}
			if !ok {
				// TODO: this is not fatal error. It only means that all the memory is offline, and therefore the node cannot be determined from /proc/zoneinfo
				// that does not show start_pfn when there is no online memory in the zone.
				return fmt.Errorf("failed to find NUMA node for region %s with resource %x: missing start_pfn %d in /proc/zoneinfo", region.Name, region.Resource, startPfn)
			}
		}
		region.Node = node
	}
	return nil
}

func memoryDeviceFromSysfs(sysfsMemdevPath string) (*MemoryDevice, error) {
	memdev := NewMemoryDevice()
	memdev.SysfsPath = sysfsMemdevPath
	memdev.Name = sysfsMemdevPath[strings.LastIndex(sysfsMemdevPath, "/")+1:]

	err := parse(
		// /sys/bus/cxl/devices/mem0/uevent:
		// MAJOR=251
		// MINOR=0
		// DEVNAME=cxl/mem0
		// DEVTYPE=cxl_memdev
		// DRIVER=cxl_mem // empty or missing if memdev is disabled
		// MODALIAS=cxl:t5
		parseWithSscanf(sysfsMemdevPath+"/uevent", "MAJOR=%d", &memdev.Major),
		parseWithSscanf(sysfsMemdevPath+"/uevent", "MINOR=%d", &memdev.Minor),
		parseWithSscanf(sysfsMemdevPath+"/uevent", "DEVNAME=%s", &memdev.DevName),
		parseIgnoring(MissingLine{}), // allow missing DRIVER line
		parseWithSscanf(sysfsMemdevPath+"/uevent", "DRIVER=%s", &memdev.Driver),
		parseIgnoring(), // fail again on missing lines
		// /sys/bus/cxl/devices/mem0/numa_node:0
		parseWithSscanf(sysfsMemdevPath+"/numa_node", "%d", &memdev.NumaNode),
		// /sys/bus/cxl/devices/mem0/serial:0xc100e2e0
		parseWithSscanf(sysfsMemdevPath+"/serial", "0x%x", &memdev.Serial),
		// /sys/bus/cxl/devices/mem0/pmem/size:0x0
		parseWithSscanf(sysfsMemdevPath+"/pmem/size", "0x%x", &memdev.PmemSize),
		// /sys/bus/cxl/devices/mem0/ram/size:0x10000000
		parseWithSscanf(sysfsMemdevPath+"/ram/size", "0x%x", &memdev.RamSize),
	)
	if err != nil {
		return nil, err
	}
	memdev.Enabled = memdev.Driver != ""
	return memdev, nil
}

func regionDeviceFromSysfs(sysfsRegionPath string) (*RegionDevice, error) {
	region := NewRegionDevice()
	region.SysfsPath = sysfsRegionPath
	region.Name = sysfsRegionPath[strings.LastIndex(sysfsRegionPath, "/")+1:]

	err := parse(
		// /sys/bus/cxl/devices/region0/size:0x200000000
		parseWithSscanf(sysfsRegionPath+"/size", "0x%x", &region.Size),
		// /sys/bus/cxl/devices/region0/mode:ram
		parseWithSscanf(sysfsRegionPath+"/mode", "%s", &region.Mode),
		// /sys/bus/cxl/devices/region0/resource:0x6d0000000
		parseWithSscanf(sysfsRegionPath+"/resource", "0x%x", &region.Resource),
	)
	if err != nil {
		return nil, err
	}

	// parse decoders from regionX/targetN for N=0,1,...
	for i := 0; ; i++ {
		var targetDecoder string
		err := parse(
			parseIgnoring(MissingFile{}), // allow missing targetN files
			parseWithSscanf(fmt.Sprintf("%s/target%d", sysfsRegionPath, i), "%s", &targetDecoder),
		)
		if err != nil {
			return nil, err
		}
		if targetDecoder == "" {
			break
		}
		region.Targets = append(region.Targets, targetDecoder)
	}
	return region, nil
}

func endpointDeviceFromSysfs(sysfsEndpointPath string) (*EndpointDevice, error) {
	endpoint := NewEndpointDevice()
	endpoint.SysfsPath = sysfsEndpointPath

	err := parse(
		// /sys/bus/cxl/devices/endpoint4/uport/dev:251:0
		parseWithSscanf(sysfsEndpointPath+"/uport/dev", "%d:%d", &endpoint.UportMajor, &endpoint.UportMinor),
	)
	if err != nil {
		return nil, err
	}

	endpointEntries, err := os.ReadDir(endpoint.SysfsPath)
	if err != nil {
		return nil, err
	}
	for _, entry := range endpointEntries {
		isDecoder, _ := filepath.Match("decoder[0-9]*", entry.Name())
		switch {
		case isDecoder:
			sysfsDecoderPath := endpoint.SysfsPath + "/" + entry.Name()
			decoder, err := decoderDeviceFromSysfs(sysfsDecoderPath)
			if err != nil {
				return nil, err
			}
			endpoint.Decoders[decoder.Name] = decoder
		}
	}
	return endpoint, nil
}

func decoderDeviceFromSysfs(sysfsDecoderPath string) (*DecoderDevice, error) {
	decoder := NewDecoderDevice()
	decoder.SysfsPath = sysfsDecoderPath
	decoder.Name = sysfsDecoderPath[strings.LastIndex(sysfsDecoderPath, "/")+1:]

	err := parse(
		parseWithSscanf(sysfsDecoderPath+"/mode", "%s", &decoder.Mode),
		parseIgnoring(MissingLine{}), // region file is empty if not assigned
		parseWithSscanf(sysfsDecoderPath+"/region", "%s", &decoder.Region),
	)
	if err != nil {
		return nil, err
	}
	return decoder, nil
}
