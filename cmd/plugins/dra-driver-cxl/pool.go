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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiparser "tags.cncf.io/container-device-interface/pkg/parser"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// The pool driver is a second DRA kubelet plugin in this process. It
// prepares CXL memory devices that a pool controller has hotplugged into
// this node for a claim (contract: docs/memory/cxl/pool.md): it finds the
// memdev by the serial that the controller wrote into the claim status,
// has the device engine make a region on it (and for persistent memory an
// fsdax namespace and a node mount) and returns CDI edits; Unprepare
// releases the device so that the pool can hot-remove it. It never
// publishes ResourceSlices. Its claims are Preparations of the state store
// with driver cxl-pool.nri.io, their devices Grants of the engine.

const (
	// poolStateFileName is the view of the prepared pool claims in the
	// plugin data directory of the pool driver.
	poolStateFileName = "preparedPoolClaims.json"
	// poolPreparingFileName is the name of the records of the claims
	// whose Prepare did not finish or that a rollback kept, in the log
	// lines; the state store gives their content (preparingContent), no
	// file is written.
	poolPreparingFileName = "preparingPoolClaims.json"
	// defaultPoolPrepareTimeout is how long Prepare waits for the
	// memdev to appear.
	defaultPoolPrepareTimeout = 30 * time.Second
	// defaultMemdevProbeGrace is how long Prepare waits for the driver
	// of a memdev that is already present. A memdev disabled by an
	// earlier release is enabled again when its region is made.
	defaultMemdevProbeGrace = 2 * time.Second
	// defaultRegionRetryDelay is the pause before the one retry of a
	// region creation that failed right after hotplug ("add_dev()
	// failed").
	defaultRegionRetryDelay = 3 * time.Second
	// poolCommitTimeout bounds a commit of the pool driver's records,
	// which the end of a request does not withdraw.
	poolCommitTimeout = time.Minute
)

type poolDriver struct {
	name   string // cxl-pool.nri.io
	helper *kubeletplugin.Helper
	cdi    *cdiapi.Cache // the shared default cache, nil: no CDI spec is written
	// dataDir is the plugin data directory of the pool driver.
	dataDir string
	st      *store.Store
	engine  *engine.Engine
	// mu serializes the Prepares, Unprepares and the start.
	mu sync.Mutex
	// inflight are the serials of the Prepares in progress, by count.
	inflight map[uint64]int
	lender   *companionLender // lends companion claims
	nri      *nriPlugin       // a Prepare waits for its first Synchronize (waitNRI); nil: none
	// fence gets the NUMA nodes of devices in mode numa before their
	// memory goes online, nil for none.
	fence *nodeFence
	// bootID is the boot id of the running kernel, "" if it is unknown.
	bootID string
	// fsTypes are the filesystem types that mode fs mounts.
	fsTypes []string

	// serials is a snapshot of the serials of the devices of the pool
	// driver's records and of the Prepares in progress, for the
	// cxl.nri.io publisher, and results of the allocation results
	// of prepared claims (claim uid -> results) for the NRI plugin. They
	// have their own lock so that a rescan or an NRI event never waits
	// for a Prepare that waits for udev.
	serialsMu sync.Mutex
	serials   map[uint64]bool
	results   map[string][]poolResult
	// unfinishedNodes are the NUMA nodes of the devices in mode numa of
	// the claims whose Prepare did not finish.
	unfinishedNodes []int
}

// poolResult is a prepared allocation result of a pool claim as the NRI
// plugin sees it.
type poolResult struct {
	// Index is the index of the allocation result in the claim.
	Index   int
	Request string
	Mode    string // api.ModeNUMA, ModeDax, ModeBlock or ModeFs
	Node    int    // NUMA node of the memory (numa mode), -1 if none
	Size    uint64
	// Settings are the container settings of the result.
	Settings config.ResultSettings
}

// preparedPoolDevice is one allocation result of a pool claim as the views
// of the state store (preparedPoolClaims.json) give it.
type preparedPoolDevice struct {
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

// lent returns the device as the lease broker sees it.
func (d *preparedPoolDevice) lent(driver string) lentDevice {
	return lentDevice{
		Driver:      driver,
		Source:      api.SourcePool,
		Request:     d.Request,
		Device:      d.Device,
		Pool:        d.Pool,
		Serial:      d.Serial,
		Shared:      d.Shared,
		Size:        d.Size,
		Mode:        d.Mode,
		ReadOnly:    d.ReadOnly,
		Node:        d.Node,
		DaxDevice:   d.DaxDevice,
		BlockDevice: d.BlockDevice,
		Access:      d.Access,
		FsType:      d.FsType,
		NodeMount:   d.NodeMount,
	}
}

// memory returns what a prepared device gives a container, with the env
// key key.
func (d *preparedPoolDevice) memory(key string) api.Memory {
	return api.Memory{
		Key:      key,
		Serial:   api.FormatSerial(d.Serial),
		Shared:   d.Shared,
		Mode:     d.Mode,
		Size:     d.Size,
		Node:     d.Node,
		Dax:      d.DaxDevice,
		Path:     d.memoryPath(),
		Access:   d.Access,
		FsType:   d.FsType,
		ReadOnly: d.ReadOnly,
	}
}

// memoryPath returns the PATH of a prepared device: the block device of
// mode block, the directory in the container of mode fs.
func (d *preparedPoolDevice) memoryPath() string {
	switch d.Mode {
	case api.ModeBlock:
		return d.BlockDevice
	case api.ModeFs:
		return d.Path
	}
	return ""
}

// lentDevices returns the devices of a prepared claim as the lease
// broker sees them.
func (p *poolDriver) lentDevices(devs []preparedPoolDevice) []lentDevice {
	out := make([]lentDevice, 0, len(devs))
	for i := range devs {
		out = append(out, devs[i].lent(p.name))
	}
	return out
}

// preparedPoolClaim is a value of the view preparedPoolClaims.json.
type preparedPoolClaim struct {
	ClaimName string                      `json:"claimName"` // namespace/name
	Devices   []preparedPoolDevice        `json:"devices"`
	Result    kubeletplugin.PrepareResult `json:"result"` // what Prepare returned
	Lend      *lendRecord                 `json:"lend,omitempty"`
	// BootID is the boot id of the kernel that the claim was prepared
	// in.
	BootID string `json:"bootID,omitempty"`
}

// poolDeviceData is claim.status.devices[].data written by the pool
// controller. Serial, shared and size are required; exclusive (a shared
// device whose claim consumed all of its shares), persistent, singleHost
// (no other host has the device while the claim is allocated) and
// coherent (other hosts' writes are visible without cache maintenance) are
// false when missing.
type poolDeviceData struct {
	Serial     string  `json:"serial"`
	Shared     *bool   `json:"shared"`
	Size       *uint64 `json:"size"`
	Exclusive  bool    `json:"exclusive"`
	Persistent bool    `json:"persistent"`
	SingleHost bool    `json:"singleHost"`
	Coherent   bool    `json:"coherent"`
}

// poolDevice is the parsed poolDeviceData of an allocation result, with
// the mode, read-only setting, access, filesystem type and path of its
// device settings.
type poolDevice struct {
	Serial     uint64
	Shared     bool
	Size       uint64
	Exclusive  bool
	Persistent bool
	SingleHost bool
	Coherent   bool
	Mode       string
	ReadOnly   bool
	Access     string // fs: api.AccessDirect, api.AccessCached or "" (by type)
	FsType     string // fs: the declared type, "" to detect it
	Path       string // fs: the directory in the container
}

// facts returns the facts of the device (the contract of the pool): a
// device that is not shared has one claim at most, and no other host while
// it is allocated.
func (d *poolDevice) facts() config.DeviceFacts {
	single := d.Exclusive || !d.Shared
	return config.DeviceFacts{
		Persistent: d.Persistent,
		Shared:     d.Shared,
		Exclusive:  single,
		SingleHost: d.SingleHost || single,
		Coherent:   d.Coherent,
	}
}

// poolConfig are the settings of a pool driver.
type poolConfig struct {
	// Name is the DRA driver name, cxl-pool.nri.io.
	Name string
	// Kernel observes and changes the CXL kernel objects of the node.
	Kernel *kernel.Kernel
	// Store keeps the records.
	Store *store.Store
	// DataDir is the plugin data directory of the pool driver: its node
	// mounts are in DataDir/mounts.
	DataDir string
	// Timeout is how long Prepare waits for a memdev to appear and for
	// its persistent memory to settle (<= 0: 30 s).
	Timeout time.Duration
	// LeaseFsRoot is the directory of the lease-fs directories of the
	// lease claims, "" for none.
	LeaseFsRoot string
	// BootID is the boot id of the running kernel, "" if it is unknown.
	BootID string
	// FsTypes are the filesystem types that mode fs mounts (none:
	// config.KnownFsTypes).
	FsTypes []string
	// Fence gets the NUMA nodes of devices in mode numa before their
	// memory goes online, nil for none.
	Fence *nodeFence
	// Lock is the lock of the region creations of the process, nil for
	// none.
	Lock sync.Locker
	// Filesystems is the list of the filesystem types of the kernel, ""
	// for /proc/filesystems.
	Filesystems string
	// HolderWait, ProbeGrace, RegionRetry and OfflineSettle are the holder
	// wait of a release, the grace for the driver of a present memdev, the
	// pause before the retry of a region creation and how long memory
	// blocks stay offline before their dax device changes driver, zero for
	// the defaults.
	HolderWait, ProbeGrace, RegionRetry, OfflineSettle time.Duration
}

// newPoolDriver returns a pool driver over the engine of the records of
// its source in the store, recovered: what the store has is matched with
// the kernel (engine.Recover), the CDI spec is written by start.
func newPoolDriver(ctx context.Context, cfg poolConfig) (*poolDriver, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultPoolPrepareTimeout
	}
	if cfg.ProbeGrace <= 0 {
		cfg.ProbeGrace = defaultMemdevProbeGrace
	}
	if cfg.RegionRetry <= 0 {
		cfg.RegionRetry = defaultRegionRetryDelay
	}
	if cfg.Store == nil {
		return nil, errors.New("the pool driver needs the state store")
	}
	fsTypes := cfg.FsTypes
	if len(fsTypes) == 0 {
		fsTypes = config.KnownFsTypes
	}
	p := &poolDriver{
		name:     cfg.Name,
		dataDir:  cfg.DataDir,
		st:       cfg.Store,
		lender:   newCompanionLender(cfg.Name),
		inflight: map[uint64]int{},
		fence:    cfg.Fence,
		bootID:   cfg.BootID,
		fsTypes:  fsTypes,
	}
	opts := engine.Options{
		Kernel:      cfg.Kernel,
		Store:       cfg.Store,
		Lock:        cfg.Lock,
		Drivers:     map[state.Source]string{state.SourcePool: cfg.Name},
		MountsDirs:  map[state.Source]string{state.SourcePool: filepath.Join(cfg.DataDir, mountsDirName)},
		LeaseFsRoot: cfg.LeaseFsRoot,
		FsTypes:     p.fsTypes,
		Filesystems: cfg.Filesystems,
		Sources:     []state.Source{state.SourcePool},
		Records:     map[state.Source]string{state.SourcePool: p.preparingFile()},
		Revoke:      p.revokeLend,
		Timeouts: engine.Timeouts{Memdev: cfg.Timeout, Settle: cfg.Timeout, Holder: cfg.HolderWait,
			ProbeGrace: cfg.ProbeGrace, RegionRetry: cfg.RegionRetry, OfflineSettle: cfg.OfflineSettle},
	}
	if cfg.Fence != nil {
		opts.Fence = p.fenceNode
	}
	e, err := engine.New(opts)
	if err != nil {
		return nil, err
	}
	p.engine = e
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := cfg.Store.Lost(); err != nil {
		// nothing is released: every Prepare fails with the loss
		klog.Errorf("%s: %v: the devices of the pool driver are not recovered", p.name, err)
		return p, nil
	}
	rec, err := e.Recover(ctx)
	if err != nil {
		return nil, fmt.Errorf("recovering the pool devices: %w", err)
	}
	p.logLoaded()
	p.logRecovered(rec)
	p.updateSerials()
	return p, nil
}

// preparingFile returns the path of the records of the claims whose
// Prepare did not finish, as the log lines name them.
func (p *poolDriver) preparingFile() string {
	return filepath.Join(p.dataDir, poolPreparingFileName)
}

// fenceNode fences a NUMA node before memory of it goes online.
func (p *poolDriver) fenceNode(ctx context.Context, node int) {
	p.fence.Fence(ctx, node)
}

// revokeLend revokes the NUMA node that the grant ref of a companion claim
// lends.
func (p *poolDriver) revokeLend(ctx context.Context, ref state.GrantRef, lend state.GrantLend) error {
	claimName := ref.Claim
	if prep := p.records().Preparation(p.name, ref.Claim); prep != nil {
		claimName = prep.ClaimName
	}
	rec := &lendRecord{Lease: lend.Lease, Pod: podRef(lend.Pod), Container: lend.Container}
	if lend.NumaNode != nil {
		rec.Nodes = []int{*lend.NumaNode}
	}
	return p.lender.revoke(ctx, rec, claimName)
}

// recoverCompanions is the second phase of the recovery, once the lender
// is set up: the devices of companion claims of mode numa whose Prepare
// did not finish stay for kubelet's Unprepare (which revokes, then
// releases) and Prepare again.
func (p *poolDriver) recoverCompanions() {
	if p == nil {
		return
	}
	for _, ref := range p.engine.RecoverCompanions() {
		klog.V(3).Infof("%s: grant %s of a companion claim is kept for its Unprepare", p.name, ref)
	}
}

// logLoaded logs the prepared claims that the store has, and the devices
// of them whose memdev is gone (GONE after the recovery).
func (p *poolDriver) logLoaded() {
	r := p.records()
	n := 0
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Driver != p.name || !prep.Prepared() {
			continue
		}
		n++
		for _, res := range prep.Results {
			g := grantOf(r, &res)
			if g == nil {
				continue
			}
			if m := r.Memdev(g.Serial); m == nil || m.State == state.MemdevGone {
				klog.Warningf("%s: claim %s (%s): memdev with serial 0x%x of %s is gone, keeping it until Unprepare",
					p.name, prep.ClaimName, prep.UID, uint64(g.Serial), res.Device)
			}
		}
	}
	klog.Infof("%s: loaded %d prepared claims from %s", p.name, n, filepath.Join(p.dataDir, poolStateFileName))
}

// logRecovered logs the prepared claims without a CDI device after the
// start: those whose node mount is not mounted.
func (p *poolDriver) logRecovered(rec *engine.Recovered) {
	r := p.records()
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Driver != p.name || prep.State != state.PreparationUnrestored || prep.Lease != "" {
			continue
		}
		for _, res := range prep.Results {
			g := grantOf(r, &res)
			if g == nil || g.State != state.GrantUnrestored {
				continue
			}
			why := rec.Why[g.Ref]
			if why == nil {
				why = errors.New("not mounted again")
			}
			klog.Errorf("%s: claim %s (%s) has no CDI device: its node mount %s is not mounted (%v); a new container of it fails on its CDI device, its Prepare again tries to mount it again, its Unprepare releases the device",
				p.name, prep.ClaimName, prep.UID, unrestoredMount(r, g), why)
			break
		}
	}
}

// unrestoredMount returns the path of the node mount of a grant that the
// start did not mount again.
func unrestoredMount(r *state.Records, g *state.Grant) string {
	if reg := r.Region(g.Got.Region); reg != nil && g.Got.Mount != "" {
		if m := reg.Mount(g.Got.Mount); m != nil {
			return m.Path
		}
	}
	return g.Intent.MountPath
}

// start sets the CDI cache, rewrites the CDI spec of the prepared claims
// and starts the kubelet plugin.
func (p *poolDriver) start(ctx context.Context, cdi *cdiapi.Cache, opts ...kubeletplugin.Option) error {
	p.mu.Lock()
	p.cdi = cdi
	err := p.writeCDISpec("")
	p.mu.Unlock()
	if err != nil {
		return err
	}
	helper, err := kubeletplugin.Start(ctx, p, opts...)
	if err != nil {
		return fmt.Errorf("failed to start kubelet plugin %s: %w", p.name, err)
	}
	p.helper = helper
	klog.Infof("pool driver registered as %s", p.name)
	return nil
}

// driverName returns the DRA driver name of the pool driver, "" for a
// nil (disabled) pool driver.
func (p *poolDriver) driverName() string {
	if p == nil {
		return ""
	}
	return p.name
}

// lending returns the lender of the pool driver's companion claims, nil
// for a nil (disabled) pool driver.
func (p *poolDriver) lending() *companionLender {
	if p == nil {
		return nil
	}
	return p.lender
}

func (p *poolDriver) stop() {
	if p != nil && p.helper != nil {
		p.helper.Stop()
	}
}

// records returns the records of the store; the caller must not change
// them.
func (p *poolDriver) records() *state.Records {
	return &p.st.Snapshot().Records
}

// commit applies fn to the document in one durable commit, bounded by
// poolCommitTimeout, not by ctx.
func (p *poolDriver) commit(ctx context.Context, fn func(doc *store.Document) error) error {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), poolCommitTimeout)
	defer cancel()
	return p.st.Commit(cctx, store.Durable, fn)
}

// Serials returns the serials of the memdevs that the pool driver has
// prepared or is preparing. Nil for a nil (disabled) pool driver.
func (p *poolDriver) Serials() map[uint64]bool {
	if p == nil {
		return nil
	}
	p.serialsMu.Lock()
	defer p.serialsMu.Unlock()
	out := make(map[uint64]bool, len(p.serials))
	for s := range p.serials {
		out[s] = true
	}
	return out
}

// ClaimResults returns the prepared allocation results of a pool claim.
// Nil for a nil (disabled) pool driver.
func (p *poolDriver) ClaimResults(uid string) []poolResult {
	if p == nil {
		return nil
	}
	p.serialsMu.Lock()
	defer p.serialsMu.Unlock()
	return slices.Clone(p.results[uid])
}

// numaNodes returns the NUMA nodes of the devices in mode numa of all
// prepared claims, and of the claims whose Prepare did not finish (their
// memory may be online). Nil for a nil (disabled) pool driver.
func (p *poolDriver) numaNodes() []int {
	if p == nil {
		return nil
	}
	p.serialsMu.Lock()
	defer p.serialsMu.Unlock()
	nodes := slices.Clone(p.unfinishedNodes)
	for _, results := range p.results {
		for _, r := range results {
			if r.Mode == api.ModeNUMA && r.Node >= 0 {
				nodes = append(nodes, r.Node)
			}
		}
	}
	slices.Sort(nodes)
	return slices.Compact(nodes)
}

// updateSerials refreshes the Serials, ClaimResults and numaNodes
// snapshots from the records: the serials of every grant of the pool and
// of the Prepares in progress, the results of the prepared claims, the
// NUMA nodes of the devices in mode numa of the claims whose Prepare did
// not finish. Called with p.mu held.
func (p *poolDriver) updateSerials() {
	r := p.records()
	s := map[uint64]bool{}
	for i := range r.Grants {
		if g := &r.Grants[i]; g.Asked.Source == state.SourcePool {
			s[uint64(g.Serial)] = true
		}
	}
	for serial := range p.inflight {
		s[serial] = true
	}
	results := map[string][]poolResult{}
	var nodes []int
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		switch {
		case prep.Driver != p.name:
		case prep.Prepared():
			for _, d := range p.devicesOf(prep) {
				results[prep.UID] = append(results[prep.UID], poolResult{Index: d.Result, Request: d.Request, Mode: d.Mode,
					Node: d.Node, Size: d.Size, Settings: d.ResultSettings})
			}
		case prep.State == state.PreparationPreparing || prep.State == state.PreparationKept:
			nodes = append(nodes, unfinishedNodes(r, prep)...)
		}
	}
	p.serialsMu.Lock()
	p.serials = s
	p.results = results
	p.unfinishedNodes = nodes
	p.serialsMu.Unlock()
}

// unfinishedNodes returns the NUMA nodes of the grants of mode numa of a
// preparation whose Prepare did not finish: the node of the grant, else of
// its region.
func unfinishedNodes(r *state.Records, prep *state.Preparation) []int {
	var nodes []int
	for _, res := range prep.Results {
		g := grantOf(r, &res)
		if g == nil || g.Asked.Mode != state.ModeNUMA {
			continue
		}
		node := state.NumaNodeOf(g.Got.NumaNode)
		if node < 0 {
			region := g.Got.Region
			if region == "" {
				region = g.Intent.Region
			}
			if reg := r.Region(region); reg != nil {
				node = state.NumaNodeOf(reg.NumaNode)
			}
		}
		if node >= 0 {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// grantOf returns the grant of a result, nil if it has none.
func grantOf(r *state.Records, res *state.Result) *state.Grant {
	if res.Grant == nil {
		return nil
	}
	return r.Grant(*res.Grant)
}

// devicesOf returns the devices of a preparation of the pool driver as the
// view preparedPoolClaims.json gives them.
func (p *poolDriver) devicesOf(prep *state.Preparation) []preparedPoolDevice {
	data, err := store.PoolDevicesContent(p.st.Snapshot(), prep, p.st.ViewOptions())
	var devs []preparedPoolDevice
	if err == nil {
		err = json.Unmarshal(data, &devs)
	}
	if err != nil {
		klog.Errorf("%s: claim %s: %v", p.name, prep.ClaimName, err)
	}
	return devs
}

// lendOf returns the lend of a companion claim as the view
// preparedPoolClaims.json gives it: the lease and its requester, the NUMA
// nodes lent and the lease binds; nil for another claim.
func lendOf(doc *store.Document, prep *state.Preparation) *lendRecord {
	var rec *lendRecord
	data, err := store.PoolLendContent(doc, prep)
	if err == nil {
		err = json.Unmarshal(data, &rec)
	}
	if err != nil {
		klog.Errorf("claim %s: %v", prep.ClaimName, err)
	}
	return rec
}

func (p *poolDriver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (map[types.UID]kubeletplugin.PrepareResult, error) {
	response := map[types.UID]kubeletplugin.PrepareResult{}
	// before p.mu: the wait does not hold up the Unprepares
	if err := waitNRI(ctx, p.nri); err != nil {
		klog.Warningf("%s: preparing %d claims: %v", p.name, len(claims), err)
		for _, claim := range claims {
			response[claim.UID] = kubeletplugin.PrepareResult{Err: err}
		}
		return response, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, claim := range claims {
		response[claim.UID] = p.prepareClaim(ctx, claim)
	}
	return response, nil
}

// poolPrepare is a Prepare of a claim of the pool driver: its requests to
// the engine and its results.
type poolPrepare struct {
	uid, claimName string
	lend           *lendRecord
	reqs           []engine.GrantRequest
	results        []state.Result
}

func (p *poolDriver) prepareClaim(ctx context.Context, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	uid := string(claim.UID)
	if prep := p.records().Preparation(p.name, uid); prep != nil && prep.Prepared() {
		return p.preparedAgain(ctx, claim, prep)
	}
	pp := &poolPrepare{uid: uid, claimName: claim.Namespace + "/" + claim.Name}
	fail := func(err error) kubeletplugin.PrepareResult {
		err = fmt.Errorf("%s: preparing claim %s: %w", p.name, pp.claimName, err)
		klog.Error(err)
		return kubeletplugin.PrepareResult{Err: err}
	}
	// a Prepare that is refused before it starts leaves what an earlier
	// Prepare of the claim made with its record (kubelet retries or
	// unprepares), and retries the stale lease binds as a failed Prepare
	// does
	refuse := func(err error) kubeletplugin.PrepareResult {
		res := fail(err)
		p.retryStaleBinds(ctx)
		return res
	}
	if err := p.validate(claim, pp); err != nil {
		return refuse(err)
	}
	if err := p.commitPreparing(ctx, pp); err != nil {
		return fail(err)
	}
	p.addInflight(pp.reqs, 1)
	defer p.addInflight(pp.reqs, -1)
	p.updateSerials()
	if _, err := p.engine.PrepareGrants(ctx, pp.reqs); err != nil {
		res := fail(pp.deviceError(err))
		var be *engine.BindError
		if errors.As(err, &be) && pp.lend != nil {
			p.lender.failed(pp.lend.Lease, err)
		}
		p.failedPrepare(ctx, uid)
		return res
	}
	prep := p.records().Preparation(p.name, uid)
	devs := p.devicesOf(prep)
	p.logPrepared(pp.claimName, devs)
	if err := p.lendCompanion(ctx, pp, devs); err != nil {
		return fail(err)
	}
	result := poolPrepareResult(prep)
	if err := p.writeCDISpec(uid); err != nil {
		res := fail(err)
		p.rollbackClaim(ctx, uid, pp.claimName, nil)
		return res
	}
	if err := p.commitPrepared(ctx, uid); err != nil {
		res := fail(err)
		p.rollbackClaim(ctx, uid, pp.claimName, nil)
		if cerr := p.writeCDISpec(""); cerr != nil {
			klog.Errorf("%s: %v", p.name, cerr)
		}
		return res
	}
	if pp.lend != nil {
		lend := lendOf(p.st.Snapshot(), prep)
		klog.Infof("%s: claim %s: companion of lease %s of %s/%s/%s prepared (nodes %v, binds %v)",
			p.name, pp.claimName, lend.Lease, lend.Pod.Namespace, lend.Pod.Name, lend.Container, lend.Nodes, lend.Mounts)
		p.lender.prepared(lend.Lease, p.lentDevices(devs))
	}
	return result
}

// validate sets the lend and the requests of a Prepare of a claim, and
// returns an error if the claim cannot be prepared: its allocation or
// MemoryConfig is invalid, the companion gate refuses it, or an allocation
// result cannot be prepared (requests); a lease that cannot be bound is
// told to the broker.
func (p *poolDriver) validate(claim *resourceapi.ResourceClaim, pp *poolPrepare) error {
	resolved, err := p.checkClaim(claim)
	if err != nil {
		return err
	}
	if id := leaseOf(claim); id != "" {
		if pp.lend, err = p.lender.check(id, claim); err != nil {
			return err
		}
	}
	if err := p.requests(claim, pp, resolved); err != nil {
		var le *leaseBindError
		if errors.As(err, &le) {
			p.lender.failed(pp.lend.Lease, err)
		}
		return err
	}
	return nil
}

// retryStaleBinds unmounts the stale lease binds of the memdevs of the
// pool driver again, and releases what they held (engine.ReleaseGrants of
// no grant).
func (p *poolDriver) retryStaleBinds(ctx context.Context) {
	rctx, cancel := rollbackContext(ctx)
	defer cancel()
	if err := p.engine.ReleaseGrants(rctx, nil, engine.ReleaseRollback); err != nil {
		klog.Errorf("%s: %v", p.name, err)
	}
	p.updateSerials()
}

// deviceError returns the error of a grant of a Prepare with the device of
// its allocation result and its serial, but of a lease bind (it names the
// device itself).
func (pp *poolPrepare) deviceError(err error) error {
	var ge *engine.GrantError
	var be *engine.BindError
	if !errors.As(err, &ge) || errors.As(err, &be) {
		return err
	}
	for _, req := range pp.reqs {
		if req.Ref == ge.Ref {
			return fmt.Errorf("device %s serial 0x%x: %w", req.Device, uint64(req.Serial), ge.Err)
		}
	}
	return err
}

// preparedAgain returns the result of a claim that is prepared: a
// companion claim is announced to the broker again, the node mounts that
// the start did not mount again are mounted.
func (p *poolDriver) preparedAgain(ctx context.Context, claim *resourceapi.ResourceClaim, prep *state.Preparation) kubeletplugin.PrepareResult {
	klog.V(3).Infof("%s: claim %s (%s) was already prepared", p.name, prep.ClaimName, prep.UID)
	if prep.Lease != "" {
		p.lender.reprepared(lendOf(p.st.Snapshot(), prep), claim, p.lentDevices(p.devicesOf(prep)))
	} else if err := p.remount(ctx, prep); err != nil {
		err = fmt.Errorf("%s: preparing claim %s: %w", p.name, prep.ClaimName, err)
		klog.Error(err)
		return kubeletplugin.PrepareResult{Err: err}
	}
	return poolPrepareResult(prep)
}

// remount mounts again the node mounts of a prepared claim that the start
// could not mount, and rewrites the CDI spec when it mounted one: the
// claims of the node mount have their CDI devices again. An error names
// the node mount that stays unmounted; the claim must be unprepared to be
// prepared anew.
func (p *poolDriver) remount(ctx context.Context, prep *state.Preparation) error {
	r := p.records()
	var reqs []engine.GrantRequest
	var mounts []string
	for _, res := range prep.Results {
		g := grantOf(r, &res)
		if g == nil || g.State != state.GrantUnrestored {
			continue
		}
		reqs = append(reqs, engine.GrantRequest{Ref: g.Ref, ClaimName: prep.ClaimName, Device: res.Device, Serial: g.Serial, Asked: g.Asked})
		if mnt := unrestoredMount(r, g); !slices.Contains(mounts, mnt) {
			mounts = append(mounts, mnt)
		}
	}
	if len(reqs) == 0 {
		return nil
	}
	_, err := p.engine.PrepareGrants(ctx, reqs)
	if err == nil {
		for _, mnt := range mounts {
			klog.Infof("%s: claim %s: %s is mounted again: the claims of it have their CDI devices again", p.name, prep.ClaimName, mnt)
		}
		err = p.commit(ctx, func(doc *store.Document) error {
			cur := doc.Preparation(p.name, prep.UID)
			if cur == nil || cur.State != state.PreparationUnrestored || !allRealised(&doc.Records, cur) {
				return nil
			}
			return state.Apply(&state.PreparationTable, &cur.State, state.PreparationPrepared, state.TriggerPrepare)
		})
	}
	p.updateSerials()
	return errors.Join(err, p.writeCDISpec(""))
}

// allRealised tells whether every grant result of a preparation is
// REALISED.
func allRealised(r *state.Records, prep *state.Preparation) bool {
	for _, res := range prep.Results {
		if res.Grant == nil {
			continue
		}
		if g := r.Grant(*res.Grant); g == nil || g.State != state.GrantRealised {
			return false
		}
	}
	return true
}

// requests sets the requests to the engine and the results of a Prepare of
// a claim from the allocation results of the pool driver, the status data
// of their devices and their MemoryConfig, and returns an error for a
// result that cannot be prepared: no status data, shares that do not fit,
// a mode the device does not have, another claim's preparation of the
// device in another way, a lease of mode fs without its directory.
func (p *poolDriver) requests(claim *resourceapi.ResourceClaim, pp *poolPrepare, resolved map[int]*config.Resolved) error {
	keys := envKeys{}
	fs := 0
	for n, r := range claim.Status.Allocation.Devices.Results {
		if r.Driver != p.name {
			continue
		}
		data, err := poolDataFor(claim, &r)
		if err != nil {
			return err
		}
		if data.Shared {
			// before the device is touched: shares "0" fits next to an
			// exclusive holder
			if _, err := consumedShares(data.Serial, &r); err != nil {
				return err
			}
		}
		res := resolved[n]
		klog.V(3).Infof("%s: claim %s request %s result %d: MemoryConfig %s", p.name, pp.claimName, r.Request, n, res.Config.Compact())
		cfg := res.Config.DeviceSection()
		if data.Mode, err = cfg.PoolMode(data.facts()); err != nil {
			return fmt.Errorf("device %s serial 0x%x: %w", r.Device, data.Serial, err)
		}
		data.ReadOnly = cfg.IsReadOnly()
		// the env key of the device, as buildCDISpec counts them
		key := keys.next(api.Key(data.Serial, 1))
		if data.Mode == api.ModeFs {
			// access "": by the type of the filesystem, at its Prepare
			data.Access, data.Path, data.FsType = cfg.Access, cfg.Path, cfg.FsType
			if data.Path == "" {
				data.Path = defaultFsPath(key)
			}
		}
		if err := p.checkSamePreparation(data, pp.uid); err != nil {
			return fmt.Errorf("device %s serial 0x%x: %w", r.Device, data.Serial, err)
		}
		req := poolRequest(pp, n, &r, data)
		if data.Mode == api.ModeFs && pp.lend != nil {
			if fs++; fs > 1 {
				return &leaseBindError{fmt.Errorf("lease %s: more than one filesystem device", pp.lend.Lease)}
			}
			if req.BindTarget, err = leaseBindTarget(pp.lend); err != nil {
				return &leaseBindError{err}
			}
		}
		pp.reqs = append(pp.reqs, req)
		pp.results = append(pp.results, poolResultOf(pp.uid, n, &r, data, res.Settings()))
	}
	return nil
}

// poolRequest returns the request to the engine of the allocation result n
// of a Prepare of a claim, with its parsed status data and settings.
func poolRequest(pp *poolPrepare, n int, r *resourceapi.DeviceRequestAllocationResult, data *poolDevice) engine.GrantRequest {
	facts := data.facts()
	req := engine.GrantRequest{
		Ref:       state.GrantRef{Claim: pp.uid, Result: n},
		ClaimName: pp.claimName,
		Device:    r.Device,
		Serial:    state.Serial(data.Serial),
		Asked: state.Asked{
			Source:   state.SourcePool,
			Kind:     grantKind(data.Shared, data.Persistent),
			Mode:     state.Mode(data.Mode),
			ReadOnly: data.ReadOnly,
			Access:   state.Access(data.Access),
			FsType:   data.FsType,
			Path:     data.Path,
			Size:     data.Size,
			Shared:   data.Shared,
		},
		Facts:      state.MemdevFacts{Shared: data.Shared, Persistent: data.Persistent, Coherent: data.Coherent},
		SingleHost: facts.SingleHost,
	}
	if l := pp.lend; l != nil {
		req.Lend = &state.GrantLend{Lease: l.Lease, Pod: state.PodRef(l.Pod), Container: l.Container, FsDir: l.FsDir, Name: l.Name}
	}
	return req
}

// poolResultOf returns the result n of a Prepare of a claim: a grant of
// the device of the allocation result, with what the claim asks.
func poolResultOf(uid string, n int, r *resourceapi.DeviceRequestAllocationResult, data *poolDevice, settings config.ResultSettings) state.Result {
	res := state.Result{
		Index: n, Kind: state.ResultGrant, Request: r.Request, Pool: r.Pool, Device: r.Device, Settings: settings,
		Grant:  &state.GrantRef{Claim: uid, Result: n},
		Memdev: &state.MemdevResult{Shared: data.Shared, Persistent: data.Persistent},
	}
	if r.ShareID != nil {
		res.ShareID = string(*r.ShareID)
	}
	return res
}

// leaseBindError is the error of a companion claim whose lease of mode fs
// cannot be bound.
type leaseBindError struct {
	err error
}

// Error returns the error in words.
func (e *leaseBindError) Error() string {
	return e.err.Error()
}

// leaseBindTarget returns the lease bind of the device of mode fs of a
// companion claim, <FsDir>/<Name> of its lend.
func leaseBindTarget(lend *lendRecord) (string, error) {
	switch {
	case lend.Name == "":
		return "", fmt.Errorf("lease %s: the device is of mode %s, the lease is not", lend.Lease, api.ModeFs)
	case lend.FsDir == "":
		return "", fmt.Errorf("lease %s: its lease claim has no filesystem directory", lend.Lease)
	case !api.ValidName(lend.Name):
		return "", fmt.Errorf("lease %s: invalid name %q", lend.Lease, lend.Name)
	}
	return filepath.Join(lend.FsDir, lend.Name), nil
}

// commitPreparing commits the preparation of a Prepare PREPARING with its
// results, before the engine touches a device: a new one, a Prepare again
// of a claim whose Prepare did not finish or that its rollback kept, or of
// a claim of another boot, whose grants are dropped.
func (p *poolDriver) commitPreparing(ctx context.Context, pp *poolPrepare) error {
	return p.commit(ctx, func(doc *store.Document) error {
		prep := doc.Preparation(p.name, pp.uid)
		if prep == nil {
			doc.Preparations = append(doc.Preparations, state.Preparation{UID: pp.uid, Driver: p.name, State: state.PreparationUnknown})
			prep = &doc.Preparations[len(doc.Preparations)-1]
		}
		if prep.State == state.PreparationStale {
			// nothing of another boot is left of its grants
			for _, res := range prep.Results {
				if res.Grant != nil {
					dropGrant(&doc.Records, *res.Grant)
				}
			}
			prep.Reason = ""
		}
		prep.ClaimName, prep.BootID, prep.Results = pp.claimName, p.bootID, slices.Clone(pp.results)
		prep.Lease = ""
		if pp.lend != nil {
			prep.Lease = pp.lend.Lease
		}
		return state.Apply(&state.PreparationTable, &prep.State, state.PreparationPreparing, state.TriggerPrepare)
	})
}

// dropGrant removes the record of a grant of another boot and its
// memdev's reference to it.
func dropGrant(r *state.Records, ref state.GrantRef) {
	r.Grants = slices.DeleteFunc(r.Grants, func(g state.Grant) bool { return g.Ref == ref })
	for i := range r.Memdevs {
		r.Memdevs[i].Grants = slices.DeleteFunc(r.Memdevs[i].Grants, func(o state.GrantRef) bool { return o == ref })
	}
}

// commitPrepared commits the preparation of a Prepare whose devices are
// realised and whose CDI devices are written PREPARED.
func (p *poolDriver) commitPrepared(ctx context.Context, uid string) error {
	return p.commit(ctx, func(doc *store.Document) error {
		prep := doc.Preparation(p.name, uid)
		if prep == nil {
			return fmt.Errorf("claim %s has no record", uid)
		}
		return state.Apply(&state.PreparationTable, &prep.State, state.PreparationPrepared, state.TriggerPrepare)
	})
}

// failedPrepare commits the preparation of a Prepare that failed after the
// rollback: KEPT with the results of its grants that are left (their
// Unprepare releases them, their Prepare again reuses them), else removed.
func (p *poolDriver) failedPrepare(ctx context.Context, uid string) {
	kept, claimName := false, uid
	err := p.commit(ctx, func(doc *store.Document) error {
		prep := doc.Preparation(p.name, uid)
		if prep == nil {
			return nil
		}
		claimName = prep.ClaimName
		prep.Results = slices.DeleteFunc(prep.Results, func(res state.Result) bool {
			return res.Grant != nil && doc.Grant(*res.Grant) == nil
		})
		kept = slices.ContainsFunc(prep.Results, func(res state.Result) bool { return res.Grant != nil })
		if kept {
			return state.Apply(&state.PreparationTable, &prep.State, state.PreparationKept, state.TriggerPrepare)
		}
		if err := state.Apply(&state.PreparationTable, &prep.State, state.PreparationUnknown, state.TriggerPrepare); err != nil {
			return err
		}
		doc.Preparations = slices.DeleteFunc(doc.Preparations, func(x state.Preparation) bool { return x.Driver == p.name && x.UID == uid })
		return nil
	})
	if err != nil {
		klog.Errorf("%s: claim %s: %v", p.name, claimName, err)
	}
	if kept {
		klog.Warningf("%s: rollback: claim %s (%s): not everything was released: keeping its record in %s for its Unprepare or its next Prepare",
			p.name, claimName, uid, p.preparingFile())
	}
	p.updateSerials()
}

// rollbackClaim releases the devices of a claim whose Prepare failed after
// they were realised, or that an earlier Prepare left, as a rollback does
// (the NUMA nodes that they lend revoked first, but by failed, which is
// told between the revoke and the release), and commits its preparation
// KEPT or removes it (failedPrepare). Errors are logged.
func (p *poolDriver) rollbackClaim(ctx context.Context, uid, claimName string, failed func()) {
	rctx, cancel := rollbackContext(ctx)
	defer cancel()
	prep := p.records().Preparation(p.name, uid)
	if prep == nil || prep.State == state.PreparationStale {
		// nothing of another boot is left: its Prepare again or its
		// Unprepare goes on with it
		return
	}
	refs := grantRefs(p.records(), prep)
	if err := p.revokeLends(rctx, prep); err != nil {
		klog.Errorf("%s: rollback: claim %s: %v", p.name, claimName, err)
	}
	if failed != nil {
		failed()
	}
	if len(refs) > 0 {
		if err := p.engine.ReleaseGrants(rctx, refs, engine.ReleaseRollback); err != nil {
			klog.Errorf("%s: rollback: %v", p.name, err)
		}
	}
	p.failedPrepare(rctx, uid)
}

// grantRefs returns the refs of the grants of a preparation that the store
// has.
func grantRefs(r *state.Records, prep *state.Preparation) []state.GrantRef {
	var refs []state.GrantRef
	for _, res := range prep.Results {
		if g := grantOf(r, &res); g != nil {
			refs = append(refs, g.Ref)
		}
	}
	return refs
}

// revokeLends revokes the NUMA nodes that the grants of a companion claim
// lend.
func (p *poolDriver) revokeLends(ctx context.Context, prep *state.Preparation) error {
	if prep.Lease == "" {
		return nil
	}
	return p.lender.revoke(ctx, lendOf(p.st.Snapshot(), prep), prep.ClaimName)
}

// lendCompanion lends the NUMA nodes of the devices in mode numa of a
// companion claim to the container of its lend (each recorded before it is
// lent; the engine bound its device of mode fs). On error the claim is
// rolled back.
func (p *poolDriver) lendCompanion(ctx context.Context, pp *poolPrepare, devs []preparedPoolDevice) error {
	if pp.lend == nil {
		return nil
	}
	var err error
	for _, d := range devs {
		if d.Mode == api.ModeNUMA && d.Node >= 0 {
			if err = p.engine.RecordLend(ctx, state.GrantRef{Claim: pp.uid, Result: d.Result}, d.Node); err != nil {
				break
			}
		}
	}
	lend := *pp.lend
	if err == nil {
		err = p.lender.lend(ctx, &lend, p.lentDevices(devs))
	}
	if err != nil {
		p.rollbackClaim(ctx, pp.uid, pp.claimName, func() { p.lender.failed(lend.Lease, err) })
	}
	return err
}

// logPrepared logs the devices of a claim as prepared.
func (p *poolDriver) logPrepared(claimName string, devs []preparedPoolDevice) {
	for i := range devs {
		d := &devs[i]
		if d.Persistent {
			klog.Infof("%s: claim %s: prepared %s (serial 0x%x, shared %v, mode %s, read-only %v) as %s %s namespace %s block %s access %q fs %q mount %q loop %q",
				p.name, claimName, d.Device, d.Serial, d.Shared, d.Mode, d.ReadOnly, d.Memdev, d.Region,
				d.Namespace, d.BlockDevice, d.Access, d.FsType, d.NodeMount, d.LoopDevice)
			continue
		}
		klog.Infof("%s: claim %s: prepared %s (serial 0x%x, shared %v, mode %s, read-only %v) as %s %s dax %s node %d",
			p.name, claimName, d.Device, d.Serial, d.Shared, d.Mode, d.ReadOnly, d.Memdev, d.Region, d.Dax, d.Node)
	}
}

// addInflight adds n to the counts of the serials of reqs.
func (p *poolDriver) addInflight(reqs []engine.GrantRequest, n int) {
	for _, req := range reqs {
		serial := uint64(req.Serial)
		if p.inflight[serial] += n; p.inflight[serial] <= 0 {
			delete(p.inflight, serial)
		}
	}
	if n < 0 {
		p.updateSerials()
	}
}

// poolPrepareResult returns the PrepareResult of a preparation of the pool
// driver: a device per result, with its CDI device but for a companion
// claim (its memory belongs to the borrower, and the companion pod
// references no claim).
func poolPrepareResult(prep *state.Preparation) kubeletplugin.PrepareResult {
	res := kubeletplugin.PrepareResult{Devices: []kubeletplugin.Device{}}
	for _, r := range prep.Results {
		if r.Index < 0 {
			continue
		}
		d := kubeletplugin.Device{Requests: []string{r.Request}, PoolName: r.Pool, DeviceName: r.Device}
		if prep.Lease == "" {
			d.CDIDeviceIDs = []string{poolCDIDeviceID(prep.UID, r.Index)}
		}
		if r.ShareID != "" {
			id := types.UID(r.ShareID)
			d.ShareID = &id
		}
		res.Devices = append(res.Devices, d)
	}
	return res
}

// checkClaim returns the MemoryConfig of each allocation result of the
// pool driver in a claim by result index, and an error if the claim has no
// allocation, an opaque config entry of the pool driver that is not a
// valid MemoryConfig entry, or a result whose configuration is invalid.
func (p *poolDriver) checkClaim(claim *resourceapi.ResourceClaim) (map[int]*config.Resolved, error) {
	if claim.Status.Allocation == nil {
		return nil, errors.New("no allocation")
	}
	if err := config.CheckEntries(claim, p.name); err != nil {
		return nil, err
	}
	return resolveResults(claim, p.name, func(r *resourceapi.DeviceRequestAllocationResult) bool { return r.Driver == p.name })
}

// preparedGrant returns a grant of a prepared claim other than exceptUID
// on the serial, or nil.
func (p *poolDriver) preparedGrant(serial uint64, exceptUID string) *state.Grant {
	r := p.records()
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Driver != p.name || prep.UID == exceptUID || !prep.Prepared() {
			continue
		}
		for _, res := range prep.Results {
			if g := grantOf(r, &res); g != nil && uint64(g.Serial) == serial {
				return g
			}
		}
	}
	return nil
}

// checkSamePreparation refuses a device that another claim prepared
// differently: as shared or exclusive, or in another mode. Read-only may
// differ: it is a property of the CDI device node, not of the region.
// Modes block and fs, and fs with either access, are compatible: they
// share one pmem region.
func (p *poolDriver) checkSamePreparation(data *poolDevice, exceptUID string) error {
	other := p.preparedGrant(data.Serial, exceptUID)
	switch {
	case other == nil:
		return nil
	case other.Asked.Shared != data.Shared:
		return fmt.Errorf("shared=%v, but another claim prepared it with shared=%v", data.Shared, other.Asked.Shared)
	case string(other.Asked.Mode) != data.Mode && (!persistentMode(string(other.Asked.Mode)) || !persistentMode(data.Mode)):
		return fmt.Errorf("mode %s, but another claim prepared it in mode %s", data.Mode, other.Asked.Mode)
	}
	return nil
}

// poolDataFor parses the claim.status.devices[] entry of an allocation
// result (matched by driver, pool and device).
func poolDataFor(claim *resourceapi.ResourceClaim, r *resourceapi.DeviceRequestAllocationResult) (*poolDevice, error) {
	for _, st := range claim.Status.Devices {
		if st.Driver != r.Driver || st.Pool != r.Pool || st.Device != r.Device {
			continue
		}
		if st.Data == nil || len(st.Data.Raw) == 0 {
			return nil, fmt.Errorf("status of device %s/%s has no data (written by the pool controller with the Attached condition)", r.Pool, r.Device)
		}
		return parsePoolDeviceData(st.Data.Raw)
	}
	return nil, fmt.Errorf("claim status has no entry for device %s/%s (not attached by the pool controller yet?)", r.Pool, r.Device)
}

func parsePoolDeviceData(raw []byte) (*poolDevice, error) {
	var d poolDeviceData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("invalid device data %s: %w", string(raw), err)
	}
	if d.Serial == "" || d.Shared == nil || d.Size == nil {
		return nil, fmt.Errorf("device data %s: serial, shared and size are required", string(raw))
	}
	serial, err := api.ParseSerial(d.Serial)
	if err != nil {
		return nil, fmt.Errorf("device data: %w", err)
	}
	return &poolDevice{Serial: serial, Shared: *d.Shared, Size: *d.Size, Exclusive: d.Exclusive, Persistent: d.Persistent,
		SingleHost: d.SingleHost, Coherent: d.Coherent}, nil
}

func (p *poolDriver) UnprepareResourceClaims(ctx context.Context, claims []kubeletplugin.NamespacedObject) (map[types.UID]error, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	response := map[types.UID]error{}
	for _, claim := range claims {
		response[claim.UID] = p.unprepareClaim(ctx, string(claim.UID))
	}
	return response, nil
}

// unprepareClaim releases the devices of a claim and removes its
// preparation: a prepared claim is UNPREPARING first, the nodes that a
// companion claim lends are revoked before its memory goes offline. A
// claim that the pool driver has no record of had nothing prepared: not an
// error.
func (p *poolDriver) unprepareClaim(ctx context.Context, uid string) error {
	prep := p.records().Preparation(p.name, uid)
	if prep == nil {
		klog.V(3).Infof("%s: claim %s is not prepared, nothing to release", p.name, uid)
		return nil
	}
	claimName := prep.ClaimName
	fail := func(err error) error {
		err = fmt.Errorf("%s: unpreparing claim %s: %w", p.name, claimName, err)
		klog.Error(err)
		return err
	}
	if !prep.Prepared() {
		p.logUnfinished(prep)
	}
	if prep.Lease != "" {
		p.lender.releasing(prep.Lease)
	}
	if prep.Prepared() && prep.State != state.PreparationUnpreparing {
		if err := p.commit(ctx, func(doc *store.Document) error {
			cur := doc.Preparation(p.name, uid)
			return state.Apply(&state.PreparationTable, &cur.State, state.PreparationUnpreparing, state.TriggerUnprepare)
		}); err != nil {
			return fail(err)
		}
	}
	// Revoke before the release: offlining memory that the container
	// still has in cpuset.mems leaves a stale node there.
	if prep.State != state.PreparationStale {
		if err := p.revokeLends(ctx, prep); err != nil {
			return fail(err)
		}
	}
	err := p.engine.ReleaseGrants(ctx, grantRefs(p.records(), prep), engine.ReleaseUnprepare)
	if err == nil {
		err = p.commit(ctx, func(doc *store.Document) error {
			cur := doc.Preparation(p.name, uid)
			if cur == nil {
				return nil
			}
			if err := state.Apply(&state.PreparationTable, &cur.State, state.PreparationUnknown, state.TriggerUnprepare); err != nil {
				return err
			}
			doc.Preparations = slices.DeleteFunc(doc.Preparations, func(x state.Preparation) bool { return x.Driver == p.name && x.UID == uid })
			return nil
		})
	}
	p.updateSerials()
	if cerr := p.writeCDISpec(""); cerr != nil {
		klog.Errorf("%s: %v", p.name, cerr)
	}
	if err != nil {
		return fail(err)
	}
	klog.Infof("%s: unprepared claim %s (%s)", p.name, claimName, uid)
	return nil
}

// logUnfinished logs the Unprepare of a claim whose Prepare did not
// finish, or of another boot.
func (p *poolDriver) logUnfinished(prep *state.Preparation) {
	r := p.records()
	var serials []string
	for _, res := range prep.Results {
		if g := grantOf(r, &res); g != nil {
			serials = append(serials, api.FormatSerial(uint64(g.Serial)))
		}
	}
	what := "whose Prepare did not finish"
	if prep.State == state.PreparationStale {
		reason := prep.Reason
		if reason == "" {
			reason = "not prepared"
		}
		what = "not prepared any more (" + reason + ")"
	}
	klog.Infof("%s: unpreparing claim %s (%s), %s: releasing devices %s", p.name, prep.ClaimName, prep.UID, what, strings.Join(serials, ", "))
}

// leaseBinds returns the lease binds that the realised grants of the
// prepared claims of the pool driver list.
func (p *poolDriver) leaseBinds() map[string]bool {
	if p == nil {
		return nil
	}
	out := map[string]bool{}
	r := p.records()
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Driver != p.name || !prep.Prepared() {
			continue
		}
		for _, res := range prep.Results {
			if g := grantOf(r, &res); g != nil && g.Got.Bind != nil && (g.State == state.GrantRealised || g.State == state.GrantUnrestored) {
				out[g.Got.Bind.Target] = true
			}
		}
	}
	return out
}

// poolCDIDeviceID returns the qualified CDI device name of the allocation
// result n of a pool claim: nri.io/cxl-pool=claim-<uid>-<n>.
func poolCDIDeviceID(claimUID string, n int) string {
	return cdiparser.QualifiedName(device.CDIVendor, device.PoolCDIClass, claimCDIDeviceName(claimUID, n))
}

// buildCDISpec builds the CDI spec of the prepared pool claims, and of the
// claim uid whose Prepare is about to finish ("": none), but companion
// claims and claims with a node mount that the start could not mount again
// (unrestored): one device claim-<uid>-<n> per allocation result n with
// the result marker, the environment of the result's device (api.Env),
// the device node of a dax or block device and the bind mount of the node
// mount of an fs device.
func (p *poolDriver) buildCDISpec(uid string) *cdiSpecs.Spec {
	spec := &cdiSpecs.Spec{Kind: device.PoolCDIKind}
	r := p.records()
	byUID := map[string]*state.Preparation{}
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Driver == p.name && (prep.State == state.PreparationPrepared || prep.UID == uid) && prep.Lease == "" {
			byUID[prep.UID] = prep
		}
	}
	for _, id := range slices.Sorted(maps.Keys(byUID)) {
		devs := p.devicesOf(byUID[id])
		keys := envKeys{}
		for i := range devs {
			d := &devs[i]
			env := map[string]string{resultEnvVarName(id, d.Result): "1"}
			maps.Copy(env, api.Env(d.memory(keys.next(api.Key(d.Serial, 1)))))
			edits := cdiSpecs.ContainerEdits{Env: api.EnvList(env)}
			switch d.Mode {
			case api.ModeDax:
				edits.DeviceNodes = []*cdiSpecs.DeviceNode{daxDeviceNode(d.DaxDevice, d.DaxMajor, d.DaxMinor, d.ReadOnly)}
			case api.ModeBlock:
				edits.DeviceNodes = []*cdiSpecs.DeviceNode{blockDeviceNode(d.BlockDevice, d.BlockMajor, d.BlockMinor, d.ReadOnly)}
			case api.ModeFs:
				edits.Mounts = []*cdiSpecs.Mount{fsMount(d)}
			}
			spec.Devices = append(spec.Devices, cdiSpecs.Device{Name: claimCDIDeviceName(id, d.Result), ContainerEdits: edits})
		}
	}
	return spec
}

// writeCDISpec writes the CDI spec of the prepared devices (buildCDISpec,
// with the claim uid), or removes it when there are none.
func (p *poolDriver) writeCDISpec(uid string) error {
	if p.cdi == nil {
		return nil
	}
	spec := p.buildCDISpec(uid)
	if len(spec.Devices) == 0 {
		if err := p.cdi.RemoveSpec(device.PoolCDISpecName); err != nil {
			klog.V(5).Infof("%s: could not remove CDI spec %s (may not exist): %v", p.name, device.PoolCDISpecName, err)
		}
		return nil
	}
	v, err := cdiapi.MinimumRequiredVersion(spec)
	if err != nil {
		return fmt.Errorf("CDI spec version: %w", err)
	}
	spec.Version = v
	if err := p.cdi.WriteSpec(spec, device.PoolCDISpecName); err != nil {
		return fmt.Errorf("failed to write CDI spec %s: %w", device.PoolCDISpecName, err)
	}
	klog.V(5).Infof("%s: wrote CDI spec %s with %d devices", p.name, device.PoolCDISpecName, len(spec.Devices))
	return nil
}

// HandleError is called by the kubelet plugin helper on asynchronous
// errors (see driver.HandleError).
func (p *poolDriver) HandleError(ctx context.Context, err error, message string) {
	if errors.Is(err, kubeletplugin.ErrRecoverable) {
		klog.FromContext(ctx).Error(err, "DRAPlugin encountered an error.", "driver", p.name)
	} else {
		klog.FromContext(ctx).Error(err, "Unrecoverable error.", "driver", p.name)
	}
	runtime.HandleErrorWithContext(ctx, err, message)
}

// WatchHealthStatus: the pool driver does not report device health.
func (p *poolDriver) WatchHealthStatus(ctx context.Context, reports chan<- kubeletplugin.DeviceHealthReport) error {
	return kubeletplugin.ErrHealthNotSupported
}
