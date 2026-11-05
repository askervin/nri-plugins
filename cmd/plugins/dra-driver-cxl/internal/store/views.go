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
	"bytes"
	"encoding/json"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// The views are the five files that test90's observer reads, in their
// established format, derived from the document after every commit. A
// view is marked with viewKey: at the top of an object, or in every value
// of a file that maps claim UIDs to records (whose keys the readers take as
// the claims).
const (
	viewKey = "viewOf"
	viewOf  = FileName

	ViewPreparedClaims     = "preparedClaims.json"
	ViewPreparedClaimsInfo = "preparedClaimsInfo.json"
	ViewPreparedPoolClaims = "preparedPoolClaims.json"
	ViewLocalDevices       = "localDevices.json"
	ViewLeases             = "leases.json"
)

// viewOptions are what the views need besides the document.
type viewOptions struct {
	// localDir and poolDir are the plugin data directories of cxl.nri.io
	// and of the pool driver ("": no pool view).
	localDir, poolDir string
	poolDriver        string
	// sysRoot is the sysfs mount point of region paths.
	sysRoot string
}

// viewPrepareResult is a value of preparedClaims.json.
type viewPrepareResult struct {
	kubeletplugin.PrepareResult
	ViewOf string `json:"viewOf"`
}

// viewDeviceInfo is a device of a value of preparedClaimsInfo.json.
type viewDeviceInfo struct {
	RequestName    string `json:"requestName"`
	DeviceName     string `json:"deviceName"`
	Result         int    `json:"result"`
	DeviceType     string `json:"deviceType"`
	Mode           string `json:"mode,omitempty"`
	SysfsPath      string `json:"sysfsPath,omitempty"`
	NumaNodes      []int  `json:"numaNodes"`
	NumaAffinities []int  `json:"nodeAffinities,omitempty"`
	TotalBytes     uint64 `json:"totalBytes"`
	ConsumedBytes  int64  `json:"consumedBytes"`
	Serial         string `json:"serial,omitempty"`
	Region         string `json:"region,omitempty"`
	DaxDevice      string `json:"daxDevice,omitempty"`
	DaxMajor       int    `json:"daxMajor,omitempty"`
	DaxMinor       int    `json:"daxMinor,omitempty"`
	ReadOnly       bool   `json:"readOnly,omitempty"`
	Shared         bool   `json:"shared,omitempty"`
	Persistent     bool   `json:"persistent,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	BlockDevice    string `json:"blockDevice,omitempty"`
	BlockMajor     int    `json:"blockMajor,omitempty"`
	BlockMinor     int    `json:"blockMinor,omitempty"`
	Access         string `json:"access,omitempty"`
	Path           string `json:"path,omitempty"`
	NodeMount      string `json:"nodeMount,omitempty"`
	LoopDevice     string `json:"loopDevice,omitempty"`
	FsType         string `json:"fsType,omitempty"`
	config.ResultSettings
}

// viewLend is the lend of a companion claim in preparedClaimsInfo.json and
// preparedPoolClaims.json.
type viewLend struct {
	Lease     string       `json:"lease"`
	Pod       state.PodRef `json:"pod"`
	Container string       `json:"container"`
	NumaNodes []int        `json:"nodes,omitempty"`
	FsDir     string       `json:"fsDir,omitempty"`
	Name      string       `json:"name,omitempty"`
	Mounts    []string     `json:"mounts,omitempty"`
}

// viewClaimInfo is a value of preparedClaimsInfo.json.
type viewClaimInfo struct {
	ClaimName string           `json:"claimName"`
	Devices   []viewDeviceInfo `json:"devices"`
	Lend      *viewLend        `json:"lend,omitempty"`
	BootID    string           `json:"bootID,omitempty"`
	ViewOf    string           `json:"viewOf"`
}

// viewPoolDevice is a device of a value of preparedPoolClaims.json.
type viewPoolDevice struct {
	Result      int    `json:"result"`
	Request     string `json:"request"`
	Device      string `json:"device"`
	Pool        string `json:"pool"`
	Serial      uint64 `json:"serial"`
	Shared      bool   `json:"shared"`
	Size        uint64 `json:"size"`
	Mode        string `json:"mode"`
	ReadOnly    bool   `json:"readOnly,omitempty"`
	Memdev      string `json:"memdev"`
	Region      string `json:"region"`
	Dax         string `json:"dax"`
	DaxDevice   string `json:"daxDevice,omitempty"`
	DaxMajor    int    `json:"daxMajor,omitempty"`
	DaxMinor    int    `json:"daxMinor,omitempty"`
	NumaNode    int    `json:"node"`
	Persistent  bool   `json:"persistent,omitempty"`
	NdRegion    string `json:"ndRegion,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	BlockDevice string `json:"blockDevice,omitempty"`
	BlockMajor  int    `json:"blockMajor,omitempty"`
	BlockMinor  int    `json:"blockMinor,omitempty"`
	Access      string `json:"access,omitempty"`
	FsType      string `json:"fsType,omitempty"`
	Path        string `json:"path,omitempty"`
	NodeMount   string `json:"nodeMount,omitempty"`
	LoopDevice  string `json:"loopDevice,omitempty"`
	config.ResultSettings
}

// viewPoolClaim is a value of preparedPoolClaims.json.
type viewPoolClaim struct {
	ClaimName string                      `json:"claimName"`
	Devices   []viewPoolDevice            `json:"devices"`
	Result    kubeletplugin.PrepareResult `json:"result"`
	Lend      *viewLend                   `json:"lend,omitempty"`
	BootID    string                      `json:"bootID,omitempty"`
	ViewOf    string                      `json:"viewOf"`
}

// viewLocalUse is what one grant of a claim got of a local memdev, in
// localDevices.json.
type viewLocalUse struct {
	Request    string `json:"request"`
	Result     int    `json:"result,omitempty"`
	Region     string `json:"region"`
	Mode       string `json:"mode"`
	Size       uint64 `json:"size"`
	Dax        string `json:"dax,omitempty"`
	DaxDevice  string `json:"daxDevice,omitempty"`
	Major      int    `json:"major,omitempty"`
	Minor      int    `json:"minor,omitempty"`
	ReadOnly   bool   `json:"readOnly,omitempty"`
	Access     string `json:"access,omitempty"`
	FsType     string `json:"fsType,omitempty"`
	NodeMount  string `json:"nodeMount,omitempty"`
	LoopDevice string `json:"loopDevice,omitempty"`
	Path       string `json:"path,omitempty"`
}

// viewLocalDevice is a local memdev in localDevices.json.
type viewLocalDevice struct {
	Serial      uint64                     `json:"serial"`
	SerialHex   string                     `json:"serialHex"`
	Memdev      string                     `json:"memdev"`
	Region      string                     `json:"region,omitempty"`
	Creating    string                     `json:"creating,omitempty"`
	NumaNode    int                        `json:"node"`
	Dax         string                     `json:"dax,omitempty"`
	Shared      bool                       `json:"shared,omitempty"`
	Persistent  bool                       `json:"persistent,omitempty"`
	NdRegion    string                     `json:"ndRegion,omitempty"`
	Namespace   string                     `json:"namespace,omitempty"`
	BlockDevice string                     `json:"blockDevice,omitempty"`
	BlockMajor  int                        `json:"blockMajor,omitempty"`
	BlockMinor  int                        `json:"blockMinor,omitempty"`
	Claims      map[string][]*viewLocalUse `json:"claims"`
}

// viewLocalDevices is localDevices.json.
type viewLocalDevices struct {
	BootID  string            `json:"bootID"`
	Devices []viewLocalDevice `json:"devices"`
	ViewOf  string            `json:"viewOf"`
}

// viewLeaseClaim is a lease claim in leases.json.
type viewLeaseClaim struct {
	UID       string         `json:"uid"`
	Namespace string         `json:"namespace"`
	Name      string         `json:"name"`
	Pods      []state.PodRef `json:"pods"`
	FsDir     string         `json:"fsDir,omitempty"`
}

// viewLease is a lease in leases.json.
type viewLease struct {
	ID           string       `json:"id"`
	Claim        string       `json:"claim"`
	RequestID    string       `json:"requestId,omitempty"`
	Source       string       `json:"source,omitempty"`
	Mode         string       `json:"mode"`
	Shared       bool         `json:"shared"`
	SharedDevice bool         `json:"sharedDevice,omitempty"`
	DeviceSource string       `json:"deviceSource,omitempty"`
	ReadOnly     bool         `json:"readOnly,omitempty"`
	ReadWrite    bool         `json:"readWrite,omitempty"`
	Access       string       `json:"access,omitempty"`
	FsType       string       `json:"fsType,omitempty"`
	Name         string       `json:"name,omitempty"`
	Path         string       `json:"path,omitempty"`
	Size         string       `json:"size,omitempty"`
	Serial       string       `json:"serial,omitempty"`
	Pod          state.PodRef `json:"pod"`
	Container    string       `json:"container"`
	State        string       `json:"state"`
	Error        string       `json:"error,omitempty"`
	NumaNode     int          `json:"node"`
	Bytes        uint64       `json:"bytes,omitempty"`
	Dax          string       `json:"dax,omitempty"`
	Block        string       `json:"block,omitempty"`
	Created      time.Time    `json:"created"`
}

// viewLeases is leases.json.
type viewLeases struct {
	Claims map[string]*viewLeaseClaim `json:"claims"`
	Leases map[string]*viewLease      `json:"leases"`
	BootID string                     `json:"bootID,omitempty"`
	ViewOf string                     `json:"viewOf"`
}

// leaseStateNames are the protocol's names of the lease states.
var leaseStateNames = map[state.LeaseState]string{
	state.LeaseCreating:      api.StateCreating,
	state.LeasePending:       api.StatePending,
	state.LeaseLending:       api.StateLending,
	state.LeaseReady:         api.StateReady,
	state.LeaseReleasing:     api.StateReleasing,
	state.LeaseReleasingBusy: api.StateReleasing,
	state.LeaseFailed:        api.StateFailed,
}

// views returns the content of the view files of the document by path.
func views(doc *Document, opts viewOptions) (map[string][]byte, error) {
	files := map[string]any{
		filepath.Join(opts.localDir, ViewPreparedClaims):     preparedClaimsView(doc),
		filepath.Join(opts.localDir, ViewPreparedClaimsInfo): preparedClaimsInfoView(doc, opts),
		filepath.Join(opts.localDir, ViewLocalDevices):       localDevicesView(doc),
		filepath.Join(opts.localDir, ViewLeases):             leasesView(doc),
	}
	if opts.poolDir != "" {
		files[filepath.Join(opts.poolDir, ViewPreparedPoolClaims)] = preparedPoolClaimsView(doc, opts)
	}
	out := make(map[string][]byte, len(files))
	for path, v := range files {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return nil, err
		}
		out[path] = data
	}
	return out, nil
}

// writeViews writes the views of the document that changed since they
// were last written, without syncing them. Errors are logged: the document
// is the state, the views are for readers.
func (s *Store) writeViews(doc *Document) {
	if !s.opts.CompatViews || (s.viewDoc != nil && sameViewInputs(s.viewDoc, doc)) {
		return
	}
	s.viewDoc = doc
	files, err := views(doc, viewOptions{
		localDir:   s.opts.Dir,
		poolDir:    s.opts.PoolDir,
		poolDriver: s.opts.PoolDriver,
		sysRoot:    s.opts.SysRoot,
	})
	if err != nil {
		klog.Errorf("store: views: %v", err)
		return
	}
	for _, path := range slices.Sorted(maps.Keys(files)) {
		data := files[path]
		if bytes.Equal(s.views[path], data) {
			continue
		}
		if err := writeFileAtomic(s.files, path, data, false); err != nil {
			klog.Errorf("store: view %s: %v", path, err)
			delete(s.views, path)
			s.viewDoc = nil
			continue
		}
		s.views[path] = data
	}
}

// sameViewInputs tells whether the views of the documents a and b are the
// same: the sections that they derive from are equal.
func sameViewInputs(a, b *Document) bool {
	return a.BootID == b.BootID &&
		reflect.DeepEqual(a.Preparations, b.Preparations) &&
		reflect.DeepEqual(a.Grants, b.Grants) &&
		reflect.DeepEqual(a.Memdevs, b.Memdevs) &&
		reflect.DeepEqual(a.Regions, b.Regions) &&
		reflect.DeepEqual(a.LeaseClaims, b.LeaseClaims) &&
		reflect.DeepEqual(a.Leases, b.Leases)
}

// viewed tells whether the preparation is in the views: kubelet may take
// it as prepared.
func viewed(p *state.Preparation) bool {
	return p.Prepared()
}

// preparedClaimsView returns preparedClaims.json: the PrepareResult of
// every prepared claim of cxl.nri.io by UID.
func preparedClaimsView(doc *Document) map[string]viewPrepareResult {
	out := map[string]viewPrepareResult{}
	for i := range doc.Preparations {
		p := &doc.Preparations[i]
		if p.Driver != device.DriverName || !viewed(p) {
			continue
		}
		out[p.UID] = viewPrepareResult{PrepareResult: prepareResult(p, device.CDIKind), ViewOf: viewOf}
	}
	return out
}

// prepareResult returns the PrepareResult of a preparation with CDI
// devices of the CDI kind kind; a companion claim has no CDI devices.
func prepareResult(p *state.Preparation, kind string) kubeletplugin.PrepareResult {
	res := kubeletplugin.PrepareResult{Devices: []kubeletplugin.Device{}}
	for _, r := range p.Results {
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

// preparedClaimsInfoView returns preparedClaimsInfo.json: the devices of
// every prepared claim of cxl.nri.io by UID.
func preparedClaimsInfoView(doc *Document, opts viewOptions) map[string]viewClaimInfo {
	out := map[string]viewClaimInfo{}
	for i := range doc.Preparations {
		p := &doc.Preparations[i]
		if p.Driver != device.DriverName || !viewed(p) {
			continue
		}
		info := viewClaimInfo{ClaimName: p.ClaimName, Devices: []viewDeviceInfo{}, Lend: lendView(doc, p), BootID: p.BootID, ViewOf: viewOf}
		for j := range p.Results {
			info.Devices = append(info.Devices, deviceInfoView(doc, &p.Results[j], opts))
		}
		out[p.UID] = info
	}
	return out
}

// deviceInfoView returns a result of a preparation of cxl.nri.io as a
// device of preparedClaimsInfo.json.
func deviceInfoView(doc *Document, r *state.Result, opts viewOptions) viewDeviceInfo {
	d := viewDeviceInfo{RequestName: r.Request, DeviceName: r.Device, Result: r.Index, ResultSettings: r.Settings}
	switch r.Kind {
	case state.ResultRegion:
		d.DeviceType, d.Mode = device.DeviceTypeRegion, api.ModeNUMA
		d.Region = r.Region.Name
		d.SysfsPath = regionPath(opts, r.Region.Name)
		d.NumaNodes = []int{r.Region.NumaNode}
		d.NumaAffinities = slices.Clone(r.Region.NumaAffinity)
		d.TotalBytes, d.ConsumedBytes = r.Region.Size, r.Region.Consumed
	case state.ResultDRAM:
		d.DeviceType, d.Mode = device.DeviceTypeDRAM, api.ModeNUMA
		d.NumaNodes = slices.Clone(r.DRAM.NumaNodes)
		d.TotalBytes, d.ConsumedBytes = r.DRAM.Size, r.DRAM.Consumed
	case state.ResultLeaseClaim:
		d.DeviceType = device.DeviceTypeLease
	case state.ResultGrant:
		d.DeviceType = device.DeviceTypeMemdev
		if g := doc.Grant(*r.Grant); g != nil {
			grantInfoView(doc, g, &d, opts)
		}
	}
	return d
}

// grantInfoView sets what a grant of cxl.nri.io got in the view of its
// device in preparedClaimsInfo.json.
func grantInfoView(doc *Document, g *state.Grant, d *viewDeviceInfo, opts viewOptions) {
	facts := factsOf(doc, g)
	reg := doc.Region(g.Got.Region)
	d.Mode = string(g.Asked.Mode)
	d.Serial = g.Serial.String()
	if reg != nil {
		d.SysfsPath = regionPath(opts, reg.Name)
	}
	d.TotalBytes, d.ConsumedBytes = g.Got.Size, int64(g.Got.Size)
	if facts.NumaAffinity != nil {
		d.NumaAffinities = []int{*facts.NumaAffinity}
	}
	d.Shared = facts.Shared
	switch g.Asked.Mode {
	case state.ModeNUMA:
		if g.Got.NumaNode != nil {
			d.NumaNodes = []int{*g.Got.NumaNode}
		}
	case state.ModeDax:
		if g.Got.Dax != "" {
			d.DaxDevice = "/dev/" + g.Got.Dax
			d.DaxMajor, d.DaxMinor = daxNumbers(reg, g.Got.Dax)
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
			if m := mountOf(reg, g.Got.Mount); m != nil {
				d.NodeMount, d.LoopDevice, d.FsType = m.Path, m.Loop, m.FsType
			}
		}
	}
}

// lendView returns the lend of a companion claim, nil for another claim.
func lendView(doc *Document, p *state.Preparation) *viewLend {
	if p.Lease == "" {
		return nil
	}
	v := &viewLend{Lease: p.Lease}
	identity := false
	for _, r := range p.Results {
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
		if l != nil && l.NumaNode != nil && !slices.Contains(v.NumaNodes, *l.NumaNode) {
			v.NumaNodes = append(v.NumaNodes, *l.NumaNode)
		}
		if b := g.Got.Bind; b != nil && (b.State == state.BindBound || b.State == state.BindStale) {
			v.Mounts = append(v.Mounts, b.Target)
		}
	}
	slices.Sort(v.NumaNodes)
	return v
}

// preparedPoolClaimsView returns preparedPoolClaims.json: every prepared
// claim of the pool driver by UID.
func preparedPoolClaimsView(doc *Document, opts viewOptions) map[string]viewPoolClaim {
	out := map[string]viewPoolClaim{}
	for i := range doc.Preparations {
		p := &doc.Preparations[i]
		if p.Driver != opts.poolDriver || !viewed(p) {
			continue
		}
		pc := viewPoolClaim{
			ClaimName: p.ClaimName,
			Devices:   []viewPoolDevice{},
			Result:    prepareResult(p, device.PoolCDIKind),
			Lend:      lendView(doc, p),
			BootID:    p.BootID,
			ViewOf:    viewOf,
		}
		for j := range p.Results {
			if p.Results[j].Kind == state.ResultGrant {
				pc.Devices = append(pc.Devices, poolDeviceView(doc, &p.Results[j]))
			}
		}
		out[p.UID] = pc
	}
	return out
}

// poolDeviceView returns a result of a pool preparation as a device of
// preparedPoolClaims.json.
func poolDeviceView(doc *Document, r *state.Result) viewPoolDevice {
	d := viewPoolDevice{Result: r.Index, Request: r.Request, Device: r.Device, Pool: r.Pool, NumaNode: -1, ResultSettings: r.Settings}
	g := doc.Grant(*r.Grant)
	if g == nil {
		return d
	}
	facts := factsOf(doc, g)
	reg := doc.Region(g.Got.Region)
	d.Serial = uint64(g.Serial)
	d.Shared = facts.Shared
	d.Size = g.Got.Size
	if d.Size == 0 {
		d.Size = g.Asked.Size
	}
	d.Mode, d.ReadOnly = string(g.Asked.Mode), g.Asked.ReadOnly
	if m := doc.Memdev(g.Serial); m != nil {
		d.Memdev = m.Name
	}
	if reg != nil {
		d.Region = reg.Name
	}
	d.Dax = g.Got.Dax
	d.NumaNode = state.NumaNodeOf(g.Got.NumaNode)
	switch g.Asked.Mode {
	case state.ModeDax:
		if g.Got.Dax != "" {
			d.DaxDevice = "/dev/" + g.Got.Dax
			d.DaxMajor, d.DaxMinor = daxNumbers(reg, g.Got.Dax)
		}
	case state.ModeBlock, state.ModeFs:
		d.Persistent = true
		if reg != nil && reg.Pmem != nil {
			d.NdRegion = reg.Pmem.NdRegion
		}
		d.Namespace = g.Got.Namespace
		if bd := g.Got.BlockDevice; bd != nil {
			d.BlockDevice, d.BlockMajor, d.BlockMinor = bd.Name, bd.Dev.Major, bd.Dev.Minor
		}
		if g.Asked.Mode == state.ModeFs {
			d.Access, d.Path = string(g.Got.Mount), g.Asked.Path
			if m := mountOf(reg, g.Got.Mount); m != nil {
				d.NodeMount, d.LoopDevice, d.FsType = m.Path, m.Loop, m.FsType
			}
		}
	}
	return d
}

// localDevicesView returns localDevices.json: the local memdevs with the
// uses of their claims. A claim that holds a region without a use has the
// value null; the dax devices of the memdev's regions that no grant uses
// are the uses of the claim "-".
func localDevicesView(doc *Document) viewLocalDevices {
	out := viewLocalDevices{BootID: doc.BootID, Devices: []viewLocalDevice{}, ViewOf: viewOf}
	for i := range doc.Memdevs {
		m := &doc.Memdevs[i]
		if m.Source != state.SourceLocal {
			continue
		}
		ld := viewLocalDevice{
			Serial:     uint64(m.Serial),
			SerialHex:  m.Serial.Hex(),
			Memdev:     m.Name,
			NumaNode:   -1,
			Shared:     m.Facts.Shared,
			Persistent: m.Facts.Persistent,
			Claims:     map[string][]*viewLocalUse{},
		}
		var regions []*state.Region
		for _, ref := range m.Regions {
			if reg := doc.Region(ref); reg != nil && reg.Ours() {
				regions = append(regions, reg)
			}
		}
		if len(regions) > 0 {
			localRegionView(&ld, regions[0])
		}
		localUsesView(doc, m, &ld)
		orphansView(regions, &ld)
		out.Devices = append(out.Devices, ld)
	}
	return out
}

// localRegionView sets the facts of the region of a local memdev in its
// view: the region, or its noted name while it is created; its NUMA node;
// its first dax device or nd region once it is set up; its namespace.
func localRegionView(ld *viewLocalDevice, reg *state.Region) {
	switch reg.State {
	case state.RegionOwned, state.RegionKept:
		ld.Region = reg.Name
	case state.RegionNoted, state.RegionCreating:
		ld.Creating = reg.NotedName
	}
	ld.NumaNode = state.NumaNodeOf(reg.NumaNode)
	if w := reg.WholeDevice(); reg.SetUp && w != nil {
		ld.Dax = w.Name
	}
	if p := reg.Pmem; p != nil {
		if reg.SetUp {
			ld.NdRegion = p.NdRegion
		}
		ld.Namespace = p.Namespace
		if bd := p.BlockDevice; bd != nil {
			ld.BlockDevice, ld.BlockMajor, ld.BlockMinor = bd.Name, bd.Dev.Major, bd.Dev.Minor
		}
	}
}

// localUsesView sets the uses of the claims of a local memdev in its view:
// what its realised or releasing grants got, null for a claim whose grant
// holds the region without a use yet.
func localUsesView(doc *Document, m *state.Memdev, ld *viewLocalDevice) {
	for _, ref := range m.Grants {
		g := doc.Grant(ref)
		if g == nil {
			continue
		}
		switch g.State {
		case state.GrantRealised, state.GrantUnrestored, state.GrantReleasing:
			ld.Claims[ref.Claim] = append(ld.Claims[ref.Claim], localUseView(doc, g))
		case state.GrantJournaled, state.GrantRealising:
			if _, ok := ld.Claims[ref.Claim]; !ok {
				ld.Claims[ref.Claim] = nil
			}
		}
	}
}

// orphansView sets the dax devices of the regions of a local memdev that
// no grant uses as the uses of the claim "-" in its view.
func orphansView(regions []*state.Region, ld *viewLocalDevice) {
	for _, reg := range regions {
		for _, d := range reg.DaxDevices {
			if d.Whole || d.State == state.DaxSeed || len(d.Users) > 0 {
				continue
			}
			mode := api.ModeDax
			if d.Driver == state.DriverKmem {
				mode = api.ModeNUMA
			}
			ld.Claims["-"] = append(ld.Claims["-"], &viewLocalUse{Region: reg.Name, Mode: mode, Size: d.Size, Dax: d.Name})
		}
	}
}

// localUseView returns what a grant got of a local memdev, as a use in
// localDevices.json.
func localUseView(doc *Document, g *state.Grant) *viewLocalUse {
	u := &viewLocalUse{Mode: string(g.Asked.Mode), Size: g.Got.Size, Dax: g.Got.Dax}
	if p := doc.PreparationOf(g.Ref); p != nil {
		if r := p.Result(g.Ref.Result); r != nil {
			u.Request = r.Request
		}
	}
	reg := doc.Region(g.Got.Region)
	if reg != nil {
		u.Region = reg.Name
	}
	switch g.Asked.Mode {
	case state.ModeDax:
		if g.Got.Dax != "" {
			u.DaxDevice = "/dev/" + g.Got.Dax
			u.Major, u.Minor = daxNumbers(reg, g.Got.Dax)
		}
		u.ReadOnly = g.Asked.ReadOnly
	case state.ModeBlock, state.ModeFs:
		u.Result = g.Ref.Result
		u.ReadOnly = g.Asked.ReadOnly
		if g.Asked.Mode == state.ModeFs {
			u.Access, u.Path = string(g.Got.Mount), g.Asked.Path
			if m := mountOf(reg, g.Got.Mount); m != nil {
				u.NodeMount, u.LoopDevice, u.FsType = m.Path, m.Loop, m.FsType
			}
		}
	}
	return u
}

// leasesView returns leases.json: the lease claims and the leases.
func leasesView(doc *Document) viewLeases {
	out := viewLeases{
		Claims: map[string]*viewLeaseClaim{},
		Leases: map[string]*viewLease{},
		BootID: doc.BootID,
		ViewOf: viewOf,
	}
	for _, c := range doc.LeaseClaims {
		out.Claims[c.UID] = &viewLeaseClaim{UID: c.UID, Namespace: c.Namespace, Name: c.Name, Pods: slices.Clone(c.Pods), FsDir: c.FsDir}
	}
	for i := range doc.Leases {
		l := &doc.Leases[i]
		v := &viewLease{
			ID:           l.ID,
			Claim:        l.Claim,
			RequestID:    l.RequestID,
			Source:       string(l.Asked.Source),
			Mode:         string(l.Asked.Mode),
			Shared:       l.Asked.Shared,
			SharedDevice: l.Asked.SharedDevice,
			DeviceSource: string(l.Asked.DeviceSource),
			ReadOnly:     l.Asked.ReadOnly,
			ReadWrite:    l.Asked.ReadWrite,
			Access:       string(l.Asked.Access),
			FsType:       l.Asked.FsType,
			Name:         l.Asked.Name,
			Size:         l.Asked.Size,
			Pod:          l.Pod,
			Container:    l.Container,
			State:        leaseStateNames[l.State],
			Error:        l.Error,
			NumaNode:     -1,
			Created:      l.Created,
		}
		if l.Asked.Serial != 0 {
			v.Serial = l.Asked.Serial.String()
		}
		if got := l.Got; got != nil {
			v.Source, v.Bytes, v.Dax, v.Block, v.Path = string(got.Source), got.Bytes, got.Dax, got.Block, got.Path
			v.SharedDevice = sharedDevice(l)
			if got.Access != "" {
				v.Access = string(got.Access)
			}
			if got.FsType != "" {
				v.FsType = got.FsType
			}
			if got.Serial != 0 {
				v.Serial = got.Serial.String()
			}
		}
		if l.Lend != nil {
			v.NumaNode = state.NumaNodeOf(l.Lend.NumaNode)
		}
		out.Leases[l.ID] = v
	}
	return out
}

// sharedDevice returns whether the device of a ready lease is shared: the
// prepared device's for a persistent mode, the requested or the prepared
// device's otherwise.
func sharedDevice(l *state.Lease) bool {
	if l.Asked.Mode == state.ModeBlock || l.Asked.Mode == state.ModeFs {
		return l.Got.SharedDevice
	}
	return l.Asked.SharedDevice || l.Got.SharedDevice
}

// factsOf returns the facts of the memdev of a grant, the asked sharing if
// the memdev has no record.
func factsOf(doc *Document, g *state.Grant) state.MemdevFacts {
	if m := doc.Memdev(g.Serial); m != nil {
		return m.Facts
	}
	return state.MemdevFacts{Shared: g.Asked.Shared}
}

// daxNumbers returns the device numbers of the dax device name of the
// region.
func daxNumbers(reg *state.Region, name string) (int, int) {
	if reg == nil {
		return 0, 0
	}
	if d := reg.DaxDevice(name); d != nil {
		return d.Dev.Major, d.Dev.Minor
	}
	return 0, 0
}

// mountOf returns the node mount of the region with the access, nil if
// there is none.
func mountOf(reg *state.Region, access state.Access) *state.Mount {
	if reg == nil || access == "" {
		return nil
	}
	return reg.Mount(access)
}

// regionPath returns the sysfs path of a CXL region.
func regionPath(opts viewOptions, name string) string {
	if name == "" {
		return ""
	}
	return filepath.Join(opts.sysRoot, "bus", "cxl", "devices", name)
}
