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

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
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

// ClaimInfo is a prepared claim with its devices: a value of
// preparedClaimsInfo.json.
type ClaimInfo struct {
	ClaimName string             `json:"claimName"` // namespace/name
	Devices   []state.DeviceInfo `json:"devices"`
	// Lend is the lend of a companion claim.
	Lend *lend.Lend `json:"lend,omitempty"`
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
	NumaNode  int    `json:"node"` // NUMA node of the memory (numa mode), -1 if none
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
func lendOf(doc *store.Document, prep *state.Preparation) (*lend.Lend, error) {
	var rec *lend.Lend
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

// deviceMemory returns what a prepared memory device gives a container,
// with its env key from keys, and false for the lease device.
func deviceMemory(d *state.DeviceInfo, keys envKeys) (api.Memory, bool) {
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

// lentDevice returns a memdev of a prepared claim of the driver of the
// source as the lease broker sees it, with the pool of its allocation
// result.
func lentDevice(d *state.DeviceInfo, driver, source, pool string) lend.LentDevice {
	serial, _ := api.ParseSerial(d.Serial)
	ld := lend.LentDevice{
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
		NumaNode: -1,
	}
	switch {
	case d.Persistent:
		ld.BlockDevice, ld.Access, ld.NodeMount, ld.FsType = d.BlockDevice, d.Access, d.NodeMount, d.FsType
	case d.Mode == api.ModeDax:
		ld.DaxDevice = d.DaxDevice
	case len(d.NUMANodes) > 0:
		ld.NumaNode = d.NUMANodes[0]
	}
	return ld
}

// deviceNumaNode returns the NUMA node of a memdev in mode numa, -1 for
// another device.
func deviceNumaNode(d *state.DeviceInfo) int {
	if d.DeviceType == device.DeviceTypeMemdev && d.Mode == api.ModeNUMA && len(d.NUMANodes) > 0 {
		return d.NUMANodes[0]
	}
	return -1
}

// errNoRecord is the error of a claim whose preparation is gone.
func errNoRecord(uid string) error {
	return fmt.Errorf("claim %s has no record", uid)
}
