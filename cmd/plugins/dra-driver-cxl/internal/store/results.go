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

package store

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// The results of a preparation as its readers get them (kubelet, the CDI
// spec, the lease broker, the NRI plugin), derived from the records: the
// PrepareResult, a state.DeviceInfo per result, a PoolDevice per result of
// a pool claim, and the lend of a companion claim.

// ResultOptions are what the results need besides the document.
type ResultOptions struct {
	// PoolDriver is the name of the pool driver.
	PoolDriver string
	// SysRoot and DevRoot are the sysfs mount point and the directory of
	// the device nodes in the paths of the results, "/sys" and "/dev" if "".
	SysRoot, DevRoot string
}

// lendInfo is the lend of a companion claim.
type lendInfo struct {
	Lease     string       `json:"lease"`
	Pod       state.PodRef `json:"pod"`
	Container string       `json:"container"`
	NumaNodes []int        `json:"nodes,omitempty"`
	FsDir     string       `json:"fsDir,omitempty"`
	Name      string       `json:"name,omitempty"`
	Mounts    []string     `json:"mounts,omitempty"`
}

// claimInfo is a preparation of cxl.nri.io with its devices.
type claimInfo struct {
	ClaimName string             `json:"claimName"`
	Devices   []state.DeviceInfo `json:"devices"`
	Lend      *lendInfo          `json:"lend,omitempty"`
	BootID    string             `json:"bootID,omitempty"`
}

// PoolDevice is a device of a pool claim: one allocation result of the
// claim.
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

// ResultOptions returns the options of the results of the store, those of
// its Open.
func (s *Store) ResultOptions() ResultOptions {
	return ResultOptions{PoolDriver: s.opts.PoolDriver, SysRoot: s.opts.SysRoot, DevRoot: s.opts.DevRoot}
}

// withDefaults returns the options with the default roots.
func (o ResultOptions) withDefaults() ResultOptions {
	if o.SysRoot == "" {
		o.SysRoot = "/sys"
	}
	if o.DevRoot == "" {
		o.DevRoot = "/dev"
	}
	return o
}

// results returns the results of a preparation that its readers get: those
// of an allocation result (a negative index names a use of a memdev that no
// prepared result names).
func results(p *state.Preparation) []*state.Result {
	var out []*state.Result
	for i := range p.Results {
		if p.Results[i].Index >= 0 {
			out = append(out, &p.Results[i])
		}
	}
	return out
}

// PrepareResult returns the PrepareResult of a preparation with CDI
// devices of the CDI kind kind; a companion claim has no CDI devices.
func PrepareResult(p *state.Preparation, kind string) kubeletplugin.PrepareResult {
	res := kubeletplugin.PrepareResult{Devices: []kubeletplugin.Device{}}
	for _, r := range results(p) {
		d := kubeletplugin.Device{
			Requests:   []string{r.Request},
			PoolName:   r.Pool,
			DeviceName: r.Device,
		}
		if p.Lease == "" {
			d.CDIDeviceIDs = []string{kind + "=claim-" + p.UID + "-" + strconv.Itoa(r.Index)}
			if r.Kind == state.ResultLeaseClaim {
				d.CDIDeviceIDs = append(d.CDIDeviceIDs, device.CDIKind+"=lease-"+p.UID)
			}
		}
		if r.ShareID != "" {
			id := types.UID(r.ShareID)
			d.ShareID = &id
		}
		res.Devices = append(res.Devices, d)
	}
	return res
}

// deviceInfo returns a result of a preparation of cxl.nri.io as a
// state.DeviceInfo.
func deviceInfo(doc *Document, r *state.Result, opts ResultOptions) state.DeviceInfo {
	d := state.DeviceInfo{RequestName: r.Request, DeviceName: r.Device, Result: r.Index, ResultSettings: r.Settings}
	switch r.Kind {
	case state.ResultRegion:
		d.DeviceType, d.Mode = device.DeviceTypeRegion, api.ModeNUMA
		d.Region = r.Region.Name
		d.SysfsPath = regionPath(opts, r.Region.Name)
		d.NUMANodes = []int{r.Region.NumaNode}
		d.NodeAffinities = slices.Clone(r.Region.NumaAffinity)
		d.TotalBytes, d.ConsumedBytes = r.Region.Size, r.Region.Consumed
	case state.ResultDRAM:
		d.DeviceType, d.Mode = device.DeviceTypeDRAM, api.ModeNUMA
		d.NUMANodes = slices.Clone(r.DRAM.NumaNodes)
		d.TotalBytes, d.ConsumedBytes = r.DRAM.Size, r.DRAM.Consumed
	case state.ResultLeaseClaim:
		d.DeviceType = device.DeviceTypeLease
		d.ConsumedBytes = r.LeaseClaim.Consumed
	case state.ResultGrant:
		d.DeviceType = device.DeviceTypeMemdev
		if g := doc.Grant(*r.Grant); g != nil {
			grantInfo(doc, g, &d, opts)
		}
	}
	return d
}

// grantInfo sets what a grant of cxl.nri.io got in the device info of its
// result.
func grantInfo(doc *Document, g *state.Grant, d *state.DeviceInfo, opts ResultOptions) {
	d.Mode = string(g.Asked.Mode)
	d.Serial = g.Serial.String()
	d.SysfsPath = regionPath(opts, string(g.Got.Region))
	d.TotalBytes, d.ConsumedBytes = g.Got.Size, int64(g.Got.Size)
	d.NodeAffinities = numaAffinity(doc, g)
	d.Shared = sharedGrant(g)
	switch g.Asked.Mode {
	case state.ModeNUMA:
		if g.Got.NumaNode != nil {
			d.NUMANodes = []int{*g.Got.NumaNode}
		}
	case state.ModeDax:
		if g.Got.Dax != "" {
			d.DaxDevice = filepath.Join(opts.DevRoot, g.Got.Dax)
			d.DaxMajor, d.DaxMinor = daxNumbers(doc, g)
		}
		d.ReadOnly = g.Asked.ReadOnly
	case state.ModeBlock, state.ModeFs:
		d.Persistent = true
		d.ReadOnly = g.Asked.ReadOnly
		d.Namespace = g.Got.Namespace
		if bd := g.Got.BlockDevice; bd != nil {
			d.BlockDevice, d.BlockMajor, d.BlockMinor = bd.Name, bd.Dev.Major, bd.Dev.Minor
		}
		if g.Asked.Mode == state.ModeFs {
			d.Access, d.Path = string(g.Got.Mount), g.Asked.Path
			d.NodeMount, d.LoopDevice, d.FsType = mountFacts(doc, g)
		}
	}
}

// sharedGrant tells whether a grant maps its memdev shared.
func sharedGrant(g *state.Grant) bool {
	return g.Asked.Shared || g.Asked.Kind == state.KindShared
}

// numaAffinity returns the CPU NUMA nodes of the local memdev of a grant,
// nil if they are not known.
func numaAffinity(doc *Document, g *state.Grant) []int {
	if g.Asked.Source != state.SourceLocal {
		return nil
	}
	if m := doc.Memdev(g.Serial); m != nil && m.Facts.NumaAffinity != nil {
		return []int{*m.Facts.NumaAffinity}
	}
	return nil
}

// lendOf returns the lend of a companion claim, nil for another claim: the
// lease and the requester of the first grant with a lend, the lent NUMA
// nodes of its grants in their order, and their lease binds.
func lendOf(doc *Document, p *state.Preparation) *lendInfo {
	if p.Lease == "" {
		return nil
	}
	v := &lendInfo{Lease: p.Lease}
	identity := false
	for _, r := range results(p) {
		if r.Grant == nil {
			continue
		}
		g := doc.Grant(*r.Grant)
		if g == nil {
			continue
		}
		l := g.Got.Lend
		if l == nil {
			l = g.Intent.Lend
		}
		if l != nil && !identity {
			v.Pod, v.Container, v.FsDir, v.Name = l.Pod, l.Container, l.FsDir, l.Name
			identity = true
		}
		if g.Got.Lend != nil && g.Got.Lend.NumaNode != nil {
			v.NumaNodes = append(v.NumaNodes, *g.Got.Lend.NumaNode)
		}
		if b := g.Got.Bind; b != nil && (b.State == state.BindBound || b.State == state.BindStale) && !slices.Contains(v.Mounts, b.Target) {
			v.Mounts = append(v.Mounts, b.Target)
		}
	}
	return v
}

// poolDevice returns a result of a pool preparation as a PoolDevice.
func poolDevice(doc *Document, r *state.Result, opts ResultOptions) PoolDevice {
	d := PoolDevice{Result: r.Index, Request: r.Request, Device: r.Device, Pool: r.Pool, NumaNode: -1, ResultSettings: r.Settings}
	g := doc.Grant(*r.Grant)
	if g == nil {
		return d
	}
	d.Serial = uint64(g.Serial)
	d.Shared = sharedGrant(g)
	d.Size = g.Got.Size
	if d.Size == 0 {
		d.Size = g.Asked.Size
	}
	d.Mode, d.ReadOnly = string(g.Asked.Mode), g.Asked.ReadOnly
	if m := doc.Memdev(g.Serial); m != nil {
		d.Memdev = m.Name
	}
	d.Region, d.Dax = string(g.Got.Region), g.Got.Dax
	d.NumaNode = state.NumaNodeOf(g.Got.NumaNode)
	switch g.Asked.Mode {
	case state.ModeDax:
		if g.Got.Dax != "" {
			d.DaxDevice = filepath.Join(opts.DevRoot, g.Got.Dax)
			d.DaxMajor, d.DaxMinor = daxNumbers(doc, g)
		}
	case state.ModeBlock, state.ModeFs:
		poolPersistent(doc, g, &d)
	}
	return d
}

// poolPersistent sets the facts of a pool device of persistent memory.
func poolPersistent(doc *Document, g *state.Grant, d *PoolDevice) {
	d.Persistent = true
	if reg := doc.Region(g.Got.Region); reg != nil && reg.Pmem != nil {
		d.NdRegion = reg.Pmem.NdRegion
	}
	d.Namespace = g.Got.Namespace
	if bd := g.Got.BlockDevice; bd != nil {
		d.BlockDevice, d.BlockMajor, d.BlockMinor = bd.Name, bd.Dev.Major, bd.Dev.Minor
	}
	if g.Asked.Mode == state.ModeFs {
		d.Access, d.Path = string(g.Got.Mount), g.Asked.Path
		d.NodeMount, d.LoopDevice, d.FsType = mountFacts(doc, g)
	}
}

// daxNumbers returns the device numbers of the dax device of a grant in its
// region.
func daxNumbers(doc *Document, g *state.Grant) (int, int) {
	dev := doc.DaxDevOf(g)
	return dev.Major, dev.Minor
}

// mountFacts returns the path, the loop device and the filesystem type of
// the node mount of a grant in its region.
func mountFacts(doc *Document, g *state.Grant) (string, string, string) {
	if m := doc.MountOf(g); m != nil {
		return m.Path, m.Loop, m.FsType
	}
	return "", "", ""
}

// regionPath returns the sysfs path of a CXL region.
func regionPath(opts ResultOptions, name string) string {
	if name == "" {
		return ""
	}
	return filepath.Join(opts.SysRoot, "bus", "cxl", "devices", name)
}

// PoolLendContent returns the lend of a preparation of the pool driver as
// JSON, in any state: null for a claim that is not a companion.
func PoolLendContent(doc *Document, p *state.Preparation) ([]byte, error) {
	return json.Marshal(lendOf(doc, p))
}

// PoolDevicesContent returns the devices of a preparation of the pool
// driver as JSON, in any state.
func PoolDevicesContent(doc *Document, p *state.Preparation, opts ResultOptions) ([]byte, error) {
	opts = opts.withDefaults()
	devs := []PoolDevice{}
	for _, r := range results(p) {
		if r.Kind == state.ResultGrant {
			devs = append(devs, poolDevice(doc, r, opts))
		}
	}
	return json.Marshal(devs)
}

// ClaimInfoContent returns a preparation of cxl.nri.io with its devices as
// JSON, in any state.
func ClaimInfoContent(doc *Document, p *state.Preparation, opts ResultOptions) ([]byte, error) {
	opts = opts.withDefaults()
	info := claimInfo{ClaimName: p.ClaimName, Devices: []state.DeviceInfo{}, Lend: lendOf(doc, p), BootID: p.BootID}
	for _, r := range results(p) {
		info.Devices = append(info.Devices, deviceInfo(doc, r, opts))
	}
	return json.Marshal(info)
}
