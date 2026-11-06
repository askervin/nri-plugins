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
	"maps"
	"slices"

	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

func init() {
	putLocalContent = putLocalFileContent
}

// putLocalFileContent replaces the records of cxl.nri.io in doc with those of
// the content of one of its state files and the others as doc has them.
func putLocalFileContent(doc *store.Document, opts store.ViewOptions, name string, data, preparedData []byte) error {
	view := func(n string) ([]byte, error) { return store.ViewContent(doc, n, opts) }
	var err error
	if preparedData == nil {
		if preparedData, err = view(store.ViewPreparedClaims); err != nil {
			return err
		}
	}
	infoData, localData := data, data
	if name == localStateFileName {
		infoData, err = view(store.ViewPreparedClaimsInfo)
	} else {
		localData, err = view(store.ViewLocalDevices)
	}
	if err != nil {
		return err
	}
	prepared := map[string]kubeletplugin.PrepareResult{}
	infos := PreparedClaimsInfo{}
	var local localState
	if err := json.Unmarshal(preparedData, &prepared); err != nil {
		return err
	}
	if err := json.Unmarshal(infoData, &infos); err != nil {
		return err
	}
	if err := json.Unmarshal(localData, &local); err != nil {
		// localDevices.json as a list of devices (no boot id)
		if lerr := json.Unmarshal(localData, &local.Devices); lerr != nil {
			return err
		}
	}
	putLocal(doc, prepared, infos, &local)
	return nil
}

// orphanOwner owns the uses of a memdev in localDevices.json whose release
// failed (no claim UID is "-").
const orphanOwner = "-"

// The content of localDevices.json, as the local allocator of an older
// driver wrote it: the old files that a test imports have it.

// localSlice is what one allocation result got of a local memdev.
type localSlice struct {
	Request string `json:"request"`
	// Result is the index of the allocation result in the claim (of a
	// persistent device).
	Result int    `json:"result,omitempty"`
	Region string `json:"region"`
	// Mode is api.ModeNUMA (the memory of the slice is system RAM of the
	// NUMA node of the region) or api.ModeDax (a devdax device).
	Mode string `json:"mode"`
	// Size is the slice size in bytes.
	Size uint64 `json:"size"`
	// Dax is the dax device of the slice (daxX.Y).
	Dax       string `json:"dax,omitempty"`
	DaxDevice string `json:"daxDevice,omitempty"` // dax: /dev/daxX.Y
	Major     int    `json:"major,omitempty"`
	Minor     int    `json:"minor,omitempty"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
	// The use of a persistent device by the allocation result (Mode
	// api.ModeBlock or api.ModeFs, Size the size of the block device,
	// ReadOnly effective): fs: the effective access, the type and the node
	// mount of the filesystem, the loop device of a cached node mount and
	// the directory in the containers.
	Access     string `json:"access,omitempty"`
	FsType     string `json:"fsType,omitempty"`
	NodeMount  string `json:"nodeMount,omitempty"`
	LoopDevice string `json:"loopDevice,omitempty"`
	Path       string `json:"path,omitempty"`
}

// localDevice is a local memdev that the allocator used.
type localDevice struct {
	Serial    uint64 `json:"serial"`
	SerialHex string `json:"serialHex"`
	Memdev    string `json:"memdev"`
	// Region is the region that the allocator created on the memdev, ""
	// while it is created: then the region on the memdev that Creating
	// names is the allocator's, or every region on the memdev if Creating
	// is "" (the memdev had none, checkRegions).
	Region string `json:"region,omitempty"`
	// Creating is the region that cxl create-region creates for the
	// device while Region is "", recorded before it runs (regionNote); ""
	// if its name is not known (a record of an older plugin).
	Creating string `json:"creating,omitempty"`
	Node     int    `json:"node"` // NUMA node of the memory of the region, -1 if unknown
	// Dax is the first dax device of the region, "" while the region is
	// not set up: its creation failed or was cut, or it was kept for
	// claims whose Prepare did not finish (keepRegion), until setUpRegion.
	Dax string `json:"dax,omitempty"`
	// Shared is true for a shared memdev: every claim has the whole dax
	// device Dax; of a persistent device, sharedDevices listed it when its
	// region was created.
	Shared bool `json:"shared,omitempty"`
	// Persistent is true for a memdev of persistent memory: its region is
	// a pmem region that all claims use, never sliced, zeroed or onlined.
	Persistent bool `json:"persistent,omitempty"`
	// NdRegion is the nvdimm region of the pmem region, "" while the
	// region is not set up (the role of Dax of other devices).
	NdRegion string `json:"ndRegion,omitempty"`
	// Namespace is the fsdax namespace (map mem) of NdRegion, BlockDevice
	// its block device (/dev/pmemK) and BlockMajor, BlockMinor its
	// numbers; "" while there is none.
	Namespace   string `json:"namespace,omitempty"`
	BlockDevice string `json:"blockDevice,omitempty"`
	BlockMajor  int    `json:"blockMajor,omitempty"`
	BlockMinor  int    `json:"blockMinor,omitempty"`
	// Claims are the slices of the claims that use the memdev, by claim
	// UID. A claim without slices holds the region: the claim whose
	// Acquire creates the region (recorded before it, so that a Prepare
	// cut in the creation leaves its claim), and a claim whose Prepare
	// did not finish, for its Unprepare or its Prepare again
	// (keepRegion).
	Claims map[string][]*localSlice `json:"claims"`
}

// localState is the content of the state file: the devices the allocator
// uses, and the boot of the kernel that they belong to.
type localState struct {
	BootID  string         `json:"bootID"`
	Devices []*localDevice `json:"devices"`
}

// putLocal replaces the records of cxl.nri.io in doc with those of the
// content of its state files: the prepared claims and their infos
// (preparedClaims.json and preparedClaimsInfo.json; a claim that only one
// of them has is not prepared) and the memdevs of the local allocator
// (localDevices.json). The grant of a use of a memdev is that of the
// prepared result of the claim on the memdev (matchUses); a use that no
// prepared result names is a grant with a negative result index in a
// preparation PREPARING. The uses of no claim ("-") are grants RELEASING
// of the pseudo-preparation "-" in KEPT (transitional: removed in H6
// (schema 2); 5.2 has them as dax devices of a region without users).
func putLocal(doc *store.Document, prepared claimPreparations, infos PreparedClaimsInfo, local *localState) {
	removeDriverRecords(doc, device.DriverName, state.SourceLocal)
	b := newRecordBuilder()
	for _, uid := range slices.Sorted(maps.Keys(infos)) {
		pr, ok := prepared[uid]
		if info := infos[uid]; info != nil && ok {
			addClaimInfo(b, uid, info, &pr)
		}
	}
	if local != nil {
		if local.BootID != "" {
			doc.BootID = local.BootID
		}
		for _, d := range local.Devices {
			if d != nil {
				addLocalDevice(b, d, local.BootID)
			}
		}
	}
	b.addTo(doc)
}

// addClaimInfo adds the preparation and the grants of a prepared claim.
func addClaimInfo(b *recordBuilder, uid string, info *PreparedClaimInfo, pr *kubeletplugin.PrepareResult) {
	p := b.preparation(uid, state.Preparation{
		UID:       uid,
		Driver:    device.DriverName,
		ClaimName: info.ClaimName,
		BootID:    info.BootID,
		State:     state.PreparationPrepared,
		Results:   []state.Result{},
	})
	if info.Lend != nil {
		p.Lease = info.Lend.Lease
	}
	lends := &grantLends{lend: info.Lend, prepared: true}
	for j := range info.Devices {
		d := &info.Devices[j]
		r := state.Result{Index: d.Result, Request: d.RequestName, Device: d.DeviceName, Settings: d.ResultSettings}
		if j < len(pr.Devices) {
			r.Pool = pr.Devices[j].PoolName
			if id := pr.Devices[j].ShareID; id != nil {
				r.ShareID = string(*id)
			}
		}
		switch d.DeviceType {
		case device.DeviceTypeRegion:
			node := -1
			if len(d.NUMANodes) > 0 {
				node = d.NUMANodes[0]
			}
			r.Kind = state.ResultRegion
			r.Region = &state.RegionResult{Name: d.Region, SysfsPath: d.SysfsPath, NumaNode: node, Size: d.TotalBytes,
				Consumed: d.ConsumedBytes, NumaAffinity: d.NodeAffinities}
		case device.DeviceTypeDRAM:
			r.Kind = state.ResultDRAM
			r.DRAM = &state.DRAMResult{NumaNodes: d.NUMANodes, Size: d.TotalBytes, Consumed: d.ConsumedBytes}
		case device.DeviceTypeLease:
			r.Kind = state.ResultLeaseClaim
			r.LeaseClaim = &state.LeaseClaimResult{UID: uid, Consumed: d.ConsumedBytes}
		default:
			ref := state.GrantRef{Claim: uid, Result: d.Result}
			r.Kind, r.Grant = state.ResultGrant, &ref
			r.Memdev = &state.MemdevResult{Shared: d.Shared, Persistent: d.Persistent, NumaAffinity: d.NodeAffinities}
			addDeviceGrant(b, ref, d, lends)
		}
		p.Results = append(p.Results, r)
	}
}

// addDeviceGrant adds the grant of a prepared device of a local memdev.
func addDeviceGrant(b *recordBuilder, ref state.GrantRef, d *PreparedDeviceInfo, lends *grantLends) {
	g := b.grant(ref, state.Grant{
		Serial: parseSerial(d.Serial),
		State:  state.GrantRealised,
		Asked: state.Asked{
			Source:   state.SourceLocal,
			Kind:     grantKind(d.Shared, d.Persistent),
			Mode:     state.Mode(d.Mode),
			ReadOnly: d.ReadOnly,
			Access:   state.Access(d.Access),
			FsType:   d.FsType,
			Path:     d.Path,
			Size:     d.TotalBytes,
		},
		Got: state.Got{
			Region:      state.RegionRef(baseName(d.SysfsPath)),
			Dax:         baseName(d.DaxDevice),
			DaxDev:      state.DevNumbers{Major: d.DaxMajor, Minor: d.DaxMinor},
			Size:        d.TotalBytes,
			Namespace:   d.Namespace,
			BlockDevice: blockDevice(d.BlockDevice, d.BlockMajor, d.BlockMinor),
			Mount:       state.Access(d.Access),
			MountPath:   d.NodeMount,
			Loop:        d.LoopDevice,
			FsType:      d.FsType,
		},
	})
	node := -1
	if d.Mode == api.ModeNUMA && len(d.NUMANodes) == 1 {
		node = d.NUMANodes[0]
		g.Got.NumaNode = &node
	}
	g.Intent.Region = g.Got.Region
	lends.assign(g, d.Mode, node)
}

// addLocalDevice adds the memdev record, the region and the grants of a
// memdev of the local allocator; bootID is the boot of the allocator's
// records.
func addLocalDevice(b *recordBuilder, d *localDevice, bootID string) {
	serial := state.Serial(d.Serial)
	m := b.memdev(state.Memdev{
		Serial: serial,
		Name:   d.Memdev,
		Source: state.SourceLocal,
		Facts:  state.MemdevFacts{Shared: d.Shared, Persistent: d.Persistent},
		State:  state.MemdevActive,
	})
	if len(d.Claims) == 0 {
		m.State = state.MemdevIdleKept
	}
	region := state.RegionRef(d.Region)
	if d.Region != "" || d.Creating != "" {
		region = b.region(localRegion(d), m).Ref()
	}
	for _, uid := range slices.Sorted(maps.Keys(d.Claims)) {
		uses := d.Claims[uid]
		if len(uses) == 0 {
			ref := b.newRef(uid)
			g := useGrant(b, ref, d, nil, bootID)
			g.State, g.Intent.Region = state.GrantJournaled, region
			m.Grants = append(m.Grants, ref)
			continue
		}
		for i, ref := range matchUses(b, uid, serial, uses) {
			useGrant(b, ref, d, uses[i], bootID)
			m.Grants = append(m.Grants, ref)
		}
	}
}

// localRegion returns the region record of a memdev of the local
// allocator: its region, or the region that it creates.
func localRegion(d *localDevice) state.Region {
	r := state.Region{
		Name:      d.Region,
		NotedName: d.Creating,
		Mode:      state.RegionRam,
		Targets:   []state.Serial{state.Serial(d.Serial)},
		Owner:     state.OwnerOurs,
		State:     state.RegionOwned,
		SetUp:     d.Dax != "" || d.NdRegion != "",
		NumaNode:  state.NumaNodePtr(d.Node),
	}
	if d.Region == "" {
		r.State = state.RegionNoted
	}
	if d.Persistent {
		r.Mode = state.RegionPmem
	}
	if d.Dax != "" {
		whole := state.DaxDevice{Name: d.Dax, Whole: true, State: state.DaxSeed}
		if d.Shared {
			whole.State, whole.Driver = state.DaxDeviceDax, state.DriverDeviceDax
		}
		r.DaxDevices = []state.DaxDevice{whole}
	}
	if d.Persistent || d.NdRegion != "" || d.Namespace != "" || d.BlockDevice != "" {
		r.Pmem = &state.Pmem{NdRegion: d.NdRegion, Namespace: d.Namespace, BlockDevice: blockDevice(d.BlockDevice, d.BlockMajor, d.BlockMinor)}
	}
	return r
}

// matchUses returns the grant references of the uses of a claim on a
// memdev: a persistent use is the grant of its result, a volatile one the
// prepared result of the claim on the memdev of its request and mode, else
// the next one left (the allocator appends a claim's uses in the order of
// its results); a use that no prepared result names gets a negative result
// index.
func matchUses(b *recordBuilder, uid string, serial state.Serial, uses []*localSlice) []state.GrantRef {
	free := preparedGrants(b, uid, serial)
	refs := make([]state.GrantRef, len(uses))
	taken := map[state.GrantRef]bool{}
	matchPersistent(b, uid, uses, free, refs, taken)
	matchVolatile(b, uses, free, refs, taken)
	for i := range refs {
		if refs[i] == (state.GrantRef{}) {
			refs[i] = b.newRef(uid)
		}
	}
	return refs
}

// preparedGrants returns the grants of the prepared results of the claim
// uid on the memdev, nil for a claim that is not prepared.
func preparedGrants(b *recordBuilder, uid string, serial state.Serial) []state.GrantRef {
	p := b.byUID[uid]
	if p == nil || p.State != state.PreparationPrepared {
		return nil
	}
	var free []state.GrantRef
	for _, r := range p.Results {
		if r.Grant != nil && r.Index >= 0 && b.byRef[*r.Grant] != nil && b.byRef[*r.Grant].Serial == serial {
			free = append(free, *r.Grant)
		}
	}
	return free
}

// isPersistentUse tells whether a use is of a persistent memdev.
func isPersistentUse(s *localSlice) bool {
	return s != nil && (s.Mode == api.ModeBlock || s.Mode == api.ModeFs)
}

// matchPersistent sets the grant of each persistent use, that of its
// result: one of the prepared grants free, or a new grant of a claim that
// is not prepared.
func matchPersistent(b *recordBuilder, uid string, uses []*localSlice, free []state.GrantRef, refs []state.GrantRef, taken map[state.GrantRef]bool) {
	prepared := b.byUID[uid] != nil && b.byUID[uid].State == state.PreparationPrepared
	for i, s := range uses {
		if !isPersistentUse(s) {
			continue
		}
		ref := state.GrantRef{Claim: uid, Result: s.Result}
		if !taken[ref] && ((!prepared && b.byRef[ref] == nil) || slices.Contains(free, ref)) {
			refs[i], taken[ref] = ref, true
		}
	}
}

// matchVolatile sets the grant of each volatile use: the free prepared
// grant of its request and mode first, else the next free one.
func matchVolatile(b *recordBuilder, uses []*localSlice, free []state.GrantRef, refs []state.GrantRef, taken map[state.GrantRef]bool) {
	take := func(i int, fits func(ref state.GrantRef) bool) {
		if j := slices.IndexFunc(free, func(r state.GrantRef) bool { return !taken[r] && fits(r) }); j >= 0 {
			refs[i], taken[free[j]] = free[j], true
		}
	}
	for _, sameRequest := range []bool{true, false} {
		for i, s := range uses {
			if s == nil || isPersistentUse(s) || refs[i] != (state.GrantRef{}) {
				continue
			}
			take(i, func(ref state.GrantRef) bool {
				return !sameRequest || (b.request(ref) == s.Request && string(b.byRef[ref].Asked.Mode) == s.Mode)
			})
		}
	}
}

// useGrant returns the grant ref of a use s of the memdev d (nil: the claim
// holds the region without a use), with what the use got; a grant that no
// prepared result names gets a result of its request in the preparation
// of its claim.
func useGrant(b *recordBuilder, ref state.GrantRef, d *localDevice, s *localSlice, bootID string) *state.Grant {
	g := b.byRef[ref]
	if g == nil {
		g = b.grant(ref, state.Grant{
			Serial: state.Serial(d.Serial),
			State:  state.GrantRealised,
			Asked:  state.Asked{Source: state.SourceLocal, Kind: grantKind(d.Shared, d.Persistent)},
		})
		request := ""
		if s != nil {
			request = s.Request
		}
		st := state.PreparationPreparing
		if ref.Claim == orphanOwner {
			st, g.State = state.PreparationKept, state.GrantReleasing
		}
		p := b.preparation(ref.Claim, state.Preparation{UID: ref.Claim, Driver: device.DriverName, BootID: bootID, State: st})
		p.Results = append(p.Results, state.Result{Index: ref.Result, Kind: state.ResultGrant, Request: request, Grant: &ref})
	}
	if s == nil {
		return g
	}
	g.Asked.Mode, g.Asked.ReadOnly, g.Asked.Path = state.Mode(s.Mode), s.ReadOnly, s.Path
	g.Asked.Access, g.Asked.FsType = state.Access(s.Access), s.FsType
	g.Got.Region, g.Got.Dax, g.Got.Size = state.RegionRef(s.Region), s.Dax, s.Size
	g.Got.DaxDev = state.DevNumbers{Major: s.Major, Minor: s.Minor}
	g.Got.Mount, g.Got.MountPath, g.Got.Loop, g.Got.FsType = state.Access(s.Access), s.NodeMount, s.LoopDevice, s.FsType
	if g.Intent.Region == "" {
		g.Intent.Region = g.Got.Region
	}
	return g
}
