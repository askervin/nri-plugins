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

package state

import (
	"github.com/containers/nri-plugins/pkg/cxl/config"
)

// The results of a prepared claim as the NRI plugin reads them: derived
// from the records by the views of the store.

// DeviceInfo is one allocation result of a prepared claim with what it got:
// a device of preparedClaimsInfo.json.
type DeviceInfo struct {
	RequestName string `json:"requestName"`
	DeviceName  string `json:"deviceName"` // device name in the pool
	// Result is the index of the allocation result of the device in the
	// claim, the n of its CDI device claim-<uid>-<n>.
	Result int `json:"result"`
	// DeviceType is device.DeviceTypeMemdev, DeviceTypeRegion,
	// DeviceTypeDRAM or DeviceTypeLease.
	DeviceType string `json:"deviceType"`
	// Mode is the api.Mode of a memory device, "" for the lease device.
	Mode           string `json:"mode,omitempty"`
	SysfsPath      string `json:"sysfsPath,omitempty"`      // sysfs path (CXL regions only)
	NUMANodes      []int  `json:"numaNodes"`                // NUMA node(s) for this device
	NodeAffinities []int  `json:"nodeAffinities,omitempty"` // CPU NUMA affinities of backing memory devices (CXL only)
	TotalBytes     uint64 `json:"totalBytes"`               // total device memory capacity (memdev: the size of the grant)
	ConsumedBytes  int64  `json:"consumedBytes"`            // allocated capacity from ConsumedCapacity

	// Serial is the serial (0x<hex>) of a memdev.
	Serial string `json:"serial,omitempty"`
	// Region is the name of the region of a region device (region0).
	Region string `json:"region,omitempty"`
	// DaxDevice is /dev/daxX.Y of mode dax, "" when the device is gone.
	DaxDevice string `json:"daxDevice,omitempty"`
	DaxMajor  int    `json:"daxMajor,omitempty"`
	DaxMinor  int    `json:"daxMinor,omitempty"`
	ReadOnly  bool   `json:"readOnly,omitempty"` // dax, block: the device node is read-only; fs: the filesystem
	// Shared is true for a shared memdev.
	Shared bool `json:"shared,omitempty"`
	// Persistent is true for a memdev in mode block or fs: Namespace is
	// the fsdax namespace of its region, BlockDevice its block device
	// (/dev/pmemK) with its numbers; fs: Access is the effective access,
	// Path the directory in the containers, NodeMount the node mount of the
	// filesystem of type FsType, LoopDevice the loop device of a cached
	// node mount.
	Persistent  bool   `json:"persistent,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	BlockDevice string `json:"blockDevice,omitempty"`
	BlockMajor  int    `json:"blockMajor,omitempty"`
	BlockMinor  int    `json:"blockMinor,omitempty"`
	Access      string `json:"access,omitempty"`
	Path        string `json:"path,omitempty"`
	NodeMount   string `json:"nodeMount,omitempty"`
	LoopDevice  string `json:"loopDevice,omitempty"`
	FsType      string `json:"fsType,omitempty"`
	// ResultSettings are the container settings of the resolved
	// MemoryConfig of the result and their origins.
	config.ResultSettings
}

// PoolResult is a prepared allocation result of a pool claim as the NRI
// plugin sees it.
type PoolResult struct {
	// Index is the index of the allocation result in the claim.
	Index    int
	Request  string
	Mode     string // api.ModeNUMA, ModeDax, ModeBlock or ModeFs
	NumaNode int    // NUMA node of the memory (numa mode), -1 if none
	Size     uint64
	// Settings are the container settings of the result.
	Settings config.ResultSettings
}
