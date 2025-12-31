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
	"strings"
)

func scanDevices(sysfsRoot string) (*Devices, error) {
	devicesPath := sysfsRoot + "/sys/bus/cxl/devices"

	devices := NewDevices(devicesPath)
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
		}
	}

	return devices, nil
}

func memoryDeviceFromSysfs(sysfsMemdevPath string) (*MemoryDevice, error) {
	var err error
	memdev := &MemoryDevice{
		SysfsPath: sysfsMemdevPath,
	}

	// /sys/bus/cxl/devices/mem0/uevent:
	// DEVTYPE=cxl_memdev
	// DRIVER=cxl_mem // empty or missing if memdev is disabled
	// MAJOR=251
	// MINOR=0
	// MODALIAS=cxl:t5
	ueventPath := sysfsMemdevPath + "/uevent"
	ueventData, err := os.ReadFile(ueventPath)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(ueventData), "\n") {
		if strings.HasPrefix(line, "MAJOR=") {
			fmt.Sscanf(line, "MAJOR=%d", &memdev.Major)
		} else if strings.HasPrefix(line, "MINOR=") {
			fmt.Sscanf(line, "MINOR=%d", &memdev.Minor)
		} else if strings.HasPrefix(line, "DRIVER=") {
			fmt.Sscanf(line, "DRIVER=%s", &memdev.Driver)
			memdev.Enabled = (memdev.Driver != "")
		}
	}
	// Parse RAM and PMEM sizes from hex values
	// /sys/bus/cxl/devices/mem0/pmem/size:0x0
	// /sys/bus/cxl/devices/mem0/ram/size:0x10000000
	ramSizePath := sysfsMemdevPath + "/ram/size"
	memdev.RAMSize, err = uint64FromHexFile(ramSizePath)
	if err != nil {
		return nil, err
	}

	pmemSizePath := sysfsMemdevPath + "/pmem/size"
	memdev.PMEMSize, err = uint64FromHexFile(pmemSizePath)
	if err != nil {
		return nil, err
	}

	// Parse serial number
	// /sys/bus/cxl/devices/mem0/serial:0xc100e2e0
	serialPath := sysfsMemdevPath + "/serial"
	memdev.Serial, err = uint64FromHexFile(serialPath)
	if err != nil {
		return nil, err
	}
	return memdev, nil
}

func uint64FromHexFile(filepath string) (uint64, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return 0, err
	}
	var value uint64
	fmt.Sscanf(string(data), "0x%x", &value)
	return value, nil
}
