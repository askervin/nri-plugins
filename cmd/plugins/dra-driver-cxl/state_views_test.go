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

package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// The state files of the driver's file backend, in their established
// format, as the records of a document give them: the oracle of the tests
// that check the records in the shapes of those files.

// viewContent returns the state file name (preparedClaims.json,
// preparedClaimsInfo.json, preparedPoolClaims.json, localDevices.json or
// leases.json) of the records of doc.
func viewContent(doc *store.Document, name string, opts store.ResultOptions) ([]byte, error) {
	if opts.SysRoot == "" {
		opts.SysRoot = "/sys"
	}
	if opts.DevRoot == "" {
		opts.DevRoot = "/dev"
	}
	var v any
	var err error
	switch name {
	case device.PreparedClaimsFileName:
		v = preparedClaimsView(doc)
	case preparedClaimsInfoFileName:
		v, err = preparedClaimsInfoView(doc, opts)
	case poolStateFileName:
		v, err = preparedPoolClaimsView(doc, opts)
	case localStateFileName:
		v = localDevicesView(doc, opts)
	case leasesFileName:
		v = leasesView(doc)
	default:
		return nil, fmt.Errorf("no state file %s", name)
	}
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(v, "", "  ")
}

// leasesFileName is the file of the lease claims and the leases in the
// plugin data directory of cxl.nri.io.
const leasesFileName = "leases.json"

// viewed returns the preparations of the driver that kubelet may take as
// prepared, in the order of the document.
func viewed(doc *store.Document, driver string) []*state.Preparation {
	var out []*state.Preparation
	for i := range doc.Preparations {
		if p := &doc.Preparations[i]; p.Driver == driver && p.Prepared() {
			out = append(out, p)
		}
	}
	return out
}

// preparedClaimsView returns preparedClaims.json: the PrepareResult of
// every prepared claim of cxl.nri.io by UID.
func preparedClaimsView(doc *store.Document) map[string]kubeletplugin.PrepareResult {
	out := map[string]kubeletplugin.PrepareResult{}
	for _, p := range viewed(doc, device.DriverName) {
		out[p.UID] = store.PrepareResult(p, device.CDIKind)
	}
	return out
}

// preparedClaimsInfoView returns preparedClaimsInfo.json: the devices of
// every prepared claim of cxl.nri.io by UID.
func preparedClaimsInfoView(doc *store.Document, opts store.ResultOptions) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	for _, p := range viewed(doc, device.DriverName) {
		data, err := store.ClaimInfoContent(doc, p, opts)
		if err != nil {
			return nil, err
		}
		out[p.UID] = data
	}
	return out, nil
}

// viewPoolClaim is a value of preparedPoolClaims.json.
type viewPoolClaim struct {
	ClaimName string                      `json:"claimName"`
	Devices   json.RawMessage             `json:"devices"`
	Result    kubeletplugin.PrepareResult `json:"result"`
	Lend      json.RawMessage             `json:"lend,omitempty"`
	BootID    string                      `json:"bootID,omitempty"`
}

// preparedPoolClaimsView returns preparedPoolClaims.json: every prepared
// claim of the pool driver by UID.
func preparedPoolClaimsView(doc *store.Document, opts store.ResultOptions) (map[string]viewPoolClaim, error) {
	out := map[string]viewPoolClaim{}
	for _, p := range viewed(doc, opts.PoolDriver) {
		devs, err := store.PoolDevicesContent(doc, p, opts)
		if err != nil {
			return nil, err
		}
		lend, err := store.PoolLendContent(doc, p)
		if err != nil {
			return nil, err
		}
		if string(lend) == "null" {
			lend = nil
		}
		out[p.UID] = viewPoolClaim{ClaimName: p.ClaimName, Devices: devs, Result: store.PrepareResult(p, device.PoolCDIKind), Lend: lend, BootID: p.BootID}
	}
	return out, nil
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

// localDevicesView returns localDevices.json: the local memdevs with the
// uses of their claims. A claim that holds a region without a use has the
// value null; the dax devices of the memdev's regions that no grant uses
// are the uses of the claim "-".
func localDevicesView(doc *store.Document, opts store.ResultOptions) viewLocalDevices {
	out := viewLocalDevices{BootID: doc.BootID, Devices: []viewLocalDevice{}}
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
			localRegionView(&ld, regions[0], doc.RegionInMaking(m, regions[0]))
		}
		localUsesView(doc, m, &ld, opts)
		orphansView(regions, &ld)
		out.Devices = append(out.Devices, ld)
	}
	return out
}

// localRegionView sets the facts of the region of a local memdev in its
// view: the region, or its name while it is created (making: also while it
// is set up, probed and zeroed for its first Prepare); the NUMA node of a
// ram region; its first dax device or nd region once it is set up; its
// namespace.
func localRegionView(ld *viewLocalDevice, reg *state.Region, making bool) {
	switch {
	case making && reg.State == state.RegionOwned:
		ld.Creating = reg.Name
		return
	case reg.State == state.RegionOwned || reg.State == state.RegionKept:
		ld.Region = reg.Name
	case reg.State == state.RegionNoted || reg.State == state.RegionCreating:
		ld.Creating = reg.NotedName
	}
	if reg.Mode == state.RegionRam {
		ld.NumaNode = state.NumaNodeOf(reg.NumaNode)
	}
	if reg.SetUp {
		ld.Dax = reg.FirstDax()
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
func localUsesView(doc *store.Document, m *state.Memdev, ld *viewLocalDevice, opts store.ResultOptions) {
	for _, ref := range m.Grants {
		g := doc.Grant(ref)
		if g == nil {
			continue
		}
		switch g.State {
		case state.GrantRealised, state.GrantUnrestored, state.GrantReleasing:
			ld.Claims[ref.Claim] = append(ld.Claims[ref.Claim], localUseView(doc, g, opts))
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
func localUseView(doc *store.Document, g *state.Grant, opts store.ResultOptions) *viewLocalUse {
	u := &viewLocalUse{Mode: string(g.Asked.Mode), Size: g.Got.Size, Dax: g.Got.Dax, ReadOnly: g.Asked.ReadOnly, Region: string(g.Got.Region)}
	if p := doc.PreparationOf(g.Ref); p != nil {
		if r := p.Result(g.Ref.Result); r != nil {
			u.Request = r.Request
		}
	}
	switch g.Asked.Mode {
	case state.ModeDax:
		if g.Got.Dax != "" {
			u.DaxDevice = filepath.Join(opts.DevRoot, g.Got.Dax)
			u.Major, u.Minor = viewDaxNumbers(doc, g)
		}
	case state.ModeBlock, state.ModeFs:
		if g.Ref.Result > 0 {
			u.Result = g.Ref.Result
		}
		if g.Asked.Mode == state.ModeFs {
			u.Access, u.Path = string(g.Got.Mount), g.Asked.Path
			u.NodeMount, u.LoopDevice, u.FsType = viewMountFacts(doc, g)
		}
	}
	return u
}

// leasesView returns leases.json: the lease claims and the leases.
func leasesView(doc *store.Document) viewLeases {
	out := viewLeases{
		Claims: map[string]*viewLeaseClaim{},
		Leases: map[string]*viewLease{},
		BootID: doc.BootID,
	}
	for _, c := range doc.LeaseClaims {
		out.Claims[c.UID] = &viewLeaseClaim{UID: c.UID, Namespace: c.Namespace, Name: c.Name, Pods: slices.Clone(c.Pods), FsDir: c.FsDir}
	}
	for i := range doc.Leases {
		out.Leases[doc.Leases[i].ID] = leaseView(&doc.Leases[i])
	}
	return out
}

// leaseView returns a lease of leases.json: what it asked for, and for a
// lease that got its device, the device's source, serial, sharing, access
// and filesystem type over the asked ones.
func leaseView(l *state.Lease) *viewLease {
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
	if l.Asked.AsksSerial() {
		v.Serial = l.Asked.Serial.String()
	}
	if got := l.Got; got != nil {
		v.SharedDevice, v.Bytes, v.Dax, v.Block, v.Path = got.SharedDevice, got.Bytes, got.Dax, got.Block, got.Path
		if got.Source != "" {
			v.Source = string(got.Source)
		}
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
	return v
}

// viewDaxNumbers returns the device numbers of the dax device of a grant in
// its region.
func viewDaxNumbers(doc *store.Document, g *state.Grant) (int, int) {
	dev := doc.DaxDevOf(g)
	return dev.Major, dev.Minor
}

// viewMountFacts returns the path, the loop device and the filesystem type
// of the node mount of a grant in its region.
func viewMountFacts(doc *store.Document, g *state.Grant) (string, string, string) {
	if m := doc.MountOf(g); m != nil {
		return m.Path, m.Loop, m.FsType
	}
	return "", "", ""
}
