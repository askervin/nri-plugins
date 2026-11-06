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

package dra

import (
	"encoding/json"
	"fmt"

	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/utils/cpuset"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// The results of a preparation as the readers of the claims get them,
// derived from the records by the store's views (one derivation for the
// view files, kubelet, the CDI spec, the lease broker and the NRI plugin):
// the PrepareResult of kubelet, DeviceInfo per result (the devices of
// preparedClaimsInfo.json, of either driver), PoolDevice (the devices of
// preparedPoolClaims.json).

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

// ClaimInfo is a prepared claim with its devices: a value of
// preparedClaimsInfo.json.
type ClaimInfo struct {
	ClaimName string       `json:"claimName"` // namespace/name
	Devices   []DeviceInfo `json:"devices"`
	// Lend is the lend of a companion claim.
	Lend *Lend `json:"lend,omitempty"`
	// BootID is the boot id of the kernel that the claim was prepared in.
	BootID string `json:"bootID,omitempty"`
}

// PoolDevice is one allocation result of a pool claim: a device of
// preparedPoolClaims.json.
type PoolDevice struct {
	// Result is the index of the allocation result of the device in the
	// claim, the n of its CDI device claim-<uid>-<n>.
	Result    int    `json:"result"`
	Request   string `json:"request"`
	Device    string `json:"device"`
	Pool      string `json:"pool"`
	Serial    uint64 `json:"serial"`
	Shared    bool   `json:"shared"`
	Size      uint64 `json:"size"`
	Mode      string `json:"mode"`               // api.ModeNUMA, ModeDax, ModeBlock or ModeFs
	ReadOnly  bool   `json:"readOnly,omitempty"` // dax, block: the CDI device node allows reads only; fs: the mount
	Memdev    string `json:"memdev"`
	Region    string `json:"region"`
	Dax       string `json:"dax"`
	DaxDevice string `json:"daxDevice,omitempty"` // /dev/daxX.Y (dax mode)
	DaxMajor  int    `json:"daxMajor,omitempty"`
	DaxMinor  int    `json:"daxMinor,omitempty"`
	Node      int    `json:"node"` // NUMA node of the memory (numa mode), -1 if none
	// Devices of persistent memory (modes block and fs).
	Persistent  bool   `json:"persistent,omitempty"`
	NdRegion    string `json:"ndRegion,omitempty"`    // nvdimm region of Region
	Namespace   string `json:"namespace,omitempty"`   // fsdax namespace, namespaceK.M
	BlockDevice string `json:"blockDevice,omitempty"` // its block device, /dev/pmemK
	BlockMajor  int    `json:"blockMajor,omitempty"`
	BlockMinor  int    `json:"blockMinor,omitempty"`
	Access      string `json:"access,omitempty"` // fs: api.AccessDirect or api.AccessCached ("" in a record of preparing: the default)
	// FsType is the filesystem type of mode fs: the one mounted, the
	// declared one ("": detect) in a record of preparing.
	FsType     string `json:"fsType,omitempty"`
	Path       string `json:"path,omitempty"`       // fs: the directory in the container
	NodeMount  string `json:"nodeMount,omitempty"`  // fs: the node mount of the serial and access
	LoopDevice string `json:"loopDevice,omitempty"` // fs, cached: the loop device of the node mount
	// ResultSettings are the container settings of the resolved
	// MemoryConfig of the result and their origins.
	config.ResultSettings
}

// PoolResult is a prepared allocation result of a pool claim as the NRI
// plugin sees it.
type PoolResult struct {
	// Index is the index of the allocation result in the claim.
	Index   int
	Request string
	Mode    string // api.ModeNUMA, ModeDax, ModeBlock or ModeFs
	Node    int    // NUMA node of the memory (numa mode), -1 if none
	Size    uint64
	// Settings are the container settings of the result.
	Settings config.ResultSettings
}

// claimInfoOf returns a preparation in any state as preparedClaimsInfo.json
// has its value.
func claimInfoOf(doc *store.Document, prep *state.Preparation, opts store.ViewOptions) (*ClaimInfo, error) {
	data, err := store.ClaimInfoContent(doc, prep, opts)
	if err != nil {
		return nil, err
	}
	info := &ClaimInfo{}
	if err := json.Unmarshal(data, info); err != nil {
		return nil, err
	}
	return info, nil
}

// poolDevicesOf returns the devices of a preparation in any state as
// preparedPoolClaims.json has them.
func poolDevicesOf(doc *store.Document, prep *state.Preparation, opts store.ViewOptions) ([]PoolDevice, error) {
	data, err := store.PoolDevicesContent(doc, prep, opts)
	if err != nil {
		return nil, err
	}
	var devs []PoolDevice
	if err := json.Unmarshal(data, &devs); err != nil {
		return nil, err
	}
	return devs, nil
}

// lendOf returns the lend of a companion claim as its views have it: the
// lease and its requester, the NUMA nodes lent and the lease binds; nil for
// another claim.
func lendOf(doc *store.Document, prep *state.Preparation) (*Lend, error) {
	var rec *Lend
	data, err := store.PoolLendContent(doc, prep)
	if err == nil {
		err = json.Unmarshal(data, &rec)
	}
	return rec, err
}

// prepareResult returns the PrepareResult of a preparation for kubelet,
// with the CDI devices of the CDI kind kind.
func prepareResult(prep *state.Preparation, kind string) kubeletplugin.PrepareResult {
	return store.PrepareResult(prep, kind)
}

// memory returns what a prepared memory device gives a container, with its
// env key from keys, and false for the lease device.
func (d *DeviceInfo) memory(keys envKeys) (api.Memory, bool) {
	m := api.Memory{Mode: d.Mode, Size: d.TotalBytes, Node: -1}
	if d.ConsumedBytes > 0 {
		m.Size = uint64(d.ConsumedBytes)
	}
	if len(d.NUMANodes) > 0 {
		m.Node = d.NUMANodes[0]
	}
	switch d.DeviceType {
	case device.DeviceTypeMemdev:
		serial, err := api.ParseSerial(d.Serial)
		if err != nil {
			return m, false
		}
		m.Key, m.Serial, m.Size = keys.next(api.Key(serial, 1)), d.Serial, d.TotalBytes
		m.Dax, m.ReadOnly, m.Shared = d.DaxDevice, d.ReadOnly, d.Shared
		switch {
		case d.Persistent && d.Mode == api.ModeBlock:
			m.Path = d.BlockDevice
		case d.Persistent && d.Mode == api.ModeFs:
			m.Path, m.Access, m.FsType = d.Path, d.Access, d.FsType
		}
	case device.DeviceTypeRegion:
		m.Key = keys.next(api.RegionKey(d.Region))
	case device.DeviceTypeDRAM:
		m.Key, m.Nodes = keys.next(api.DRAMKey), cpuset.New(d.NUMANodes...).String()
	default:
		return m, false
	}
	return m, true
}

// lent returns a memdev of a prepared claim of the driver of the source as
// the lease broker sees it, with the pool of its allocation result.
func (d *DeviceInfo) lent(driver, source, pool string) LentDevice {
	serial, _ := api.ParseSerial(d.Serial)
	ld := LentDevice{
		Driver:   driver,
		Source:   source,
		Request:  d.RequestName,
		Device:   d.DeviceName,
		Pool:     pool,
		Serial:   serial,
		Size:     d.TotalBytes,
		Mode:     d.Mode,
		ReadOnly: d.ReadOnly,
		Shared:   d.Shared,
		Node:     -1,
	}
	switch {
	case d.Persistent:
		ld.BlockDevice, ld.Access, ld.NodeMount, ld.FsType = d.BlockDevice, d.Access, d.NodeMount, d.FsType
	case d.Mode == api.ModeDax:
		ld.DaxDevice = d.DaxDevice
	case len(d.NUMANodes) > 0:
		ld.Node = d.NUMANodes[0]
	}
	return ld
}

// numaNode returns the NUMA node of a memdev in mode numa, -1 for another
// device.
func (d *DeviceInfo) numaNode() int {
	if d.DeviceType == device.DeviceTypeMemdev && d.Mode == api.ModeNUMA && len(d.NUMANodes) > 0 {
		return d.NUMANodes[0]
	}
	return -1
}

// errNoRecord is the error of a claim whose preparation is gone.
func errNoRecord(uid string) error {
	return fmt.Errorf("claim %s has no record", uid)
}
