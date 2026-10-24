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
	"os"
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

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

// The pool driver is a second DRA kubelet plugin in this process. It
// prepares CXL memory devices that a pool controller has hotplugged into
// this node for a claim (contract: docs/memory/cxl/pool.md): it finds the memdev
// by the serial that the controller wrote into the claim status, creates
// a region on it (and for persistent memory an fsdax namespace and a node
// mount, see pool_persistent.go) and returns CDI edits; Unprepare releases
// the device so that the pool can hot-remove it. It never publishes
// ResourceSlices.

const (
	// poolStateFileName is the prepared pool claims file in the plugin
	// data directory of the pool driver.
	poolStateFileName = "preparedPoolClaims.json"
	// defaultPoolPrepareTimeout is how long Prepare waits for the
	// memdev to appear.
	defaultPoolPrepareTimeout = 30 * time.Second
	// defaultMemdevProbeGrace is how long Prepare waits for the driver
	// of a memdev that is already present. A memdev disabled by an
	// earlier release is enabled again by memctl.CreateRegion.
	defaultMemdevProbeGrace = 2 * time.Second
	// defaultRegionRetryDelay is the pause before the one retry of a
	// region creation that failed right after hotplug ("add_dev()
	// failed", seen in plan-3 measurement B).
	defaultRegionRetryDelay = 3 * time.Second
)

type poolDriver struct {
	name       string // cxl-pool.nri.io
	helper     *kubeletplugin.Helper
	mem        *memctl.Manager
	cdi        *cdiapi.Cache // the shared default cache, nil: no CDI spec is written
	stateFile  string        // <plugin data dir>/preparedPoolClaims.json
	timeout    time.Duration
	probeGrace time.Duration
	mu         sync.Mutex
	prepared   map[string]*preparedPoolClaim // claim uid -> ...
	inflight   map[uint64]int                // serials being prepared -> count
	lender     *companionLender              // lends companion claims
	retryDelay time.Duration
	mounter    nodeMounter   // node mounts and loop devices of mode fs
	holderWait time.Duration // how long Unprepare waits for a held block device
	// leaseFsRoot is the directory of the lease-fs directories of the
	// lease claims, where the binds of fs leases are; "": no sweep of
	// stale binds at start.
	leaseFsRoot string
	// staleBinds are lease binds of no prepared claim that could not be
	// unmounted; releaseDevices tries again.
	staleBinds []staleBind
	// fence gets the NUMA nodes of devices in mode numa before their
	// memory goes online, nil for none.
	fence *nodeFence

	// serials is a snapshot of the serials of prepared and inflight
	// devices for the cxl.nri.io publisher (D29), and results of the
	// allocation results of prepared claims (claim uid -> results) for
	// the NRI plugin. They have their own lock so that a rescan or an NRI
	// event never waits for a Prepare that waits for udev.
	serialsMu sync.Mutex
	serials   map[uint64]bool
	results   map[string][]poolResult
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
	ReadOnly  bool   `json:"readOnly,omitempty"` // dax, block: the CDI device node allows reads only; fs: always
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
	Access      string `json:"access,omitempty"`     // fs: api.AccessDirect or api.AccessCached
	Path        string `json:"path,omitempty"`       // fs: the directory in the container
	NodeMount   string `json:"nodeMount,omitempty"`  // fs: the node mount of the serial and access
	LoopDevice  string `json:"loopDevice,omitempty"` // fs, cached: the loop device of the node mount
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

type preparedPoolClaim struct {
	ClaimName string                      `json:"claimName"` // namespace/name
	Devices   []preparedPoolDevice        `json:"devices"`
	Result    kubeletplugin.PrepareResult `json:"result"` // what Prepare returned
	Lend      *lendRecord                 `json:"lend,omitempty"`
}

// poolDeviceData is claim.status.devices[].data written by the pool
// controller. Serial, shared and size are required; exclusive (a shared
// device whose claim consumed all of its shares) and persistent are false
// when missing.
type poolDeviceData struct {
	Serial     string  `json:"serial"`
	Shared     *bool   `json:"shared"`
	Size       *uint64 `json:"size"`
	Exclusive  bool    `json:"exclusive"`
	Persistent bool    `json:"persistent"`
}

// poolDevice is the parsed poolDeviceData of an allocation result, with
// the mode, read-only setting, access and path of its device settings.
type poolDevice struct {
	Serial     uint64
	Shared     bool
	Size       uint64
	Exclusive  bool
	Persistent bool
	Mode       string
	ReadOnly   bool
	Access     string // fs: api.AccessDirect or api.AccessCached
	Path       string // fs: the directory in the container
}

// newPoolDriver returns a pool driver whose prepared claims are loaded
// from stateFile, with their missing node mounts and lease binds mounted
// again, and the stale lease binds under leaseFsRoot ("": none) unmounted.
// The kubelet plugin is started separately (start).
func newPoolDriver(name string, mem *memctl.Manager, mounter nodeMounter, stateFile string, timeout time.Duration, leaseFsRoot string) (*poolDriver, error) {
	if timeout <= 0 {
		timeout = defaultPoolPrepareTimeout
	}
	p := &poolDriver{
		name:        name,
		mem:         mem,
		stateFile:   stateFile,
		timeout:     timeout,
		probeGrace:  defaultMemdevProbeGrace,
		retryDelay:  defaultRegionRetryDelay,
		mounter:     mounter,
		holderWait:  defaultHolderWait,
		lender:      newCompanionLender(name),
		leaseFsRoot: leaseFsRoot,
		prepared:    map[string]*preparedPoolClaim{},
		inflight:    map[uint64]int{},
	}
	if err := p.load(); err != nil {
		return nil, err
	}
	p.restoreMounts()
	p.updateSerials()
	return p, nil
}

// start sets the CDI cache, rewrites the CDI spec of the loaded claims
// and starts the kubelet plugin.
func (p *poolDriver) start(ctx context.Context, cdi *cdiapi.Cache, opts ...kubeletplugin.Option) error {
	p.mu.Lock()
	p.cdi = cdi
	err := p.writeCDISpec()
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
// prepared claims. Nil for a nil (disabled) pool driver.
func (p *poolDriver) numaNodes() []int {
	if p == nil {
		return nil
	}
	p.serialsMu.Lock()
	defer p.serialsMu.Unlock()
	var nodes []int
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

// updateSerials refreshes the Serials and ClaimResults snapshots. Called
// with p.mu held.
func (p *poolDriver) updateSerials() {
	s := map[uint64]bool{}
	results := map[string][]poolResult{}
	for uid, pc := range p.prepared {
		for _, d := range pc.Devices {
			s[d.Serial] = true
			results[uid] = append(results[uid], poolResult{
				Index:    d.Result,
				Request:  d.Request,
				Mode:     d.Mode,
				Node:     d.Node,
				Size:     d.Size,
				Settings: d.ResultSettings,
			})
		}
	}
	for serial := range p.inflight {
		s[serial] = true
	}
	p.serialsMu.Lock()
	p.serials = s
	p.results = results
	p.serialsMu.Unlock()
}

func (p *poolDriver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (map[types.UID]kubeletplugin.PrepareResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	response := map[types.UID]kubeletplugin.PrepareResult{}
	for _, claim := range claims {
		response[claim.UID] = p.prepareClaim(ctx, claim)
	}
	return response, nil
}

func (p *poolDriver) prepareClaim(ctx context.Context, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	uid := string(claim.UID)
	if pc, ok := p.prepared[uid]; ok {
		klog.V(3).Infof("%s: claim %s (%s) was already prepared", p.name, pc.ClaimName, uid)
		if pc.Lend != nil {
			p.lender.reprepared(pc.Lend, claim, p.lentDevices(pc.Devices))
		}
		return pc.Result
	}
	claimName := claim.Namespace + "/" + claim.Name
	resolved, err := p.checkClaim(claim)
	if err != nil {
		err = fmt.Errorf("%s: preparing claim %s: %w", p.name, claimName, err)
		klog.Error(err)
		return kubeletplugin.PrepareResult{Err: err}
	}
	var lend *lendRecord
	if id := leaseOf(claim); id != "" {
		if lend, err = p.lender.check(id, claim); err != nil {
			err = fmt.Errorf("%s: preparing claim %s: %w", p.name, claimName, err)
			klog.Error(err)
			return kubeletplugin.PrepareResult{Err: err}
		}
	}
	pc := &preparedPoolClaim{ClaimName: claimName, Result: kubeletplugin.PrepareResult{Devices: []kubeletplugin.Device{}}}
	// Serials touched by this Prepare stay inflight (hidden from the
	// cxl.nri.io publisher) until the claim is prepared or rolled back.
	var touched []uint64
	defer func() {
		for _, serial := range touched {
			if p.inflight[serial]--; p.inflight[serial] <= 0 {
				delete(p.inflight, serial)
			}
		}
		p.updateSerials()
	}()
	// the device that failed to prepare, for the holder wait of the rollback
	var failed []preparedPoolDevice
	fail := func(err error) kubeletplugin.PrepareResult {
		err = fmt.Errorf("%s: preparing claim %s: %w", p.name, claimName, err)
		klog.Error(err)
		// a lease bind left mounted would hold the device
		if uerr := p.unbindLeaseMounts(lend, uid); uerr != nil {
			klog.Errorf("%s: claim %s: %v; trying again at the next release", p.name, claimName, uerr)
			sb := staleBind{}
			if d := fsDevice(pc.Devices); d != nil {
				sb.Serial, sb.BlockDevice = d.Serial, d.BlockDevice
			}
			for _, t := range lend.Mounts {
				sb.Target = t
				p.addStaleBind(sb)
			}
		}
		p.rollback(ctx, uid, append(slices.Clone(pc.Devices), failed...), touched)
		return kubeletplugin.PrepareResult{Err: err}
	}
	keys := envKeys{}
	for n, r := range claim.Status.Allocation.Devices.Results {
		if r.Driver != p.name {
			continue
		}
		data, err := poolDataFor(claim, &r)
		if err != nil {
			return fail(err)
		}
		if data.Shared {
			// before the device is touched: shares "0" fits next to an
			// exclusive holder
			if _, err := consumedShares(data.Serial, &r); err != nil {
				return fail(err)
			}
		}
		res := resolved[n]
		klog.V(3).Infof("%s: claim %s request %s result %d: MemoryConfig %s", p.name, claimName, r.Request, n, res.Config.Compact())
		cfg := res.Config.DeviceSection()
		if data.Mode, err = cfg.PoolMode(config.PoolFacts{Persistent: data.Persistent, Shared: data.Shared, Exclusive: data.Exclusive}); err != nil {
			return fail(fmt.Errorf("device %s serial 0x%x: %w", r.Device, data.Serial, err))
		}
		data.ReadOnly = cfg.ReadOnly
		// the env key of the device, as buildCDISpec counts them
		key := keys.next(api.Key(data.Serial, 1))
		if data.Mode == api.ModeFs {
			data.Access, data.Path = cfg.Access, cfg.Path
			if data.Access == "" {
				data.Access = api.AccessDirect
			}
			if data.Path == "" {
				data.Path = defaultFsPath(key)
			}
		}
		if err := p.checkSamePreparation(data, uid); err != nil {
			return fail(fmt.Errorf("device %s serial 0x%x: %w", r.Device, data.Serial, err))
		}
		touched = append(touched, data.Serial)
		p.inflight[data.Serial]++
		p.updateSerials()
		dev, err := p.prepareDevice(ctx, &r, data)
		if err != nil && isAddDevError(err) {
			klog.Warningf("%s: claim %s: device %s: %v; retrying once in %v", p.name, claimName, r.Device, err, p.retryDelay)
			select {
			case <-ctx.Done():
			case <-time.After(p.retryDelay):
				dev, err = p.prepareDevice(ctx, &r, data)
			}
		}
		if err != nil {
			if dev != nil {
				failed = append(failed, *dev)
			}
			return fail(fmt.Errorf("device %s serial 0x%x: %w", r.Device, data.Serial, err))
		}
		dev.Result = n
		dev.ResultSettings = res.Settings()
		pc.Devices = append(pc.Devices, *dev)
		pc.Result.Devices = append(pc.Result.Devices, kubeletplugin.Device{
			Requests:     []string{r.Request},
			PoolName:     r.Pool,
			DeviceName:   r.Device,
			CDIDeviceIDs: []string{poolCDIDeviceID(uid, n)},
			ShareID:      r.ShareID,
		})
		if dev.Persistent {
			klog.Infof("%s: claim %s: prepared %s (serial 0x%x, shared %v, mode %s, read-only %v) as %s %s namespace %s block %s access %q mount %q loop %q",
				p.name, claimName, r.Device, data.Serial, data.Shared, dev.Mode, dev.ReadOnly, dev.Memdev, dev.Region,
				dev.Namespace, dev.BlockDevice, dev.Access, dev.NodeMount, dev.LoopDevice)
			continue
		}
		klog.Infof("%s: claim %s: prepared %s (serial 0x%x, shared %v, mode %s, read-only %v) as %s %s dax %s node %d",
			p.name, claimName, r.Device, data.Serial, data.Shared, dev.Mode, dev.ReadOnly, dev.Memdev, dev.Region, dev.Dax, dev.Node)
	}
	devs := p.lentDevices(pc.Devices)
	if lend != nil {
		// the bind is the lend of an fs device: in place before Ready
		if err := p.bindLeaseMounts(uid, lend, pc.Devices); err != nil {
			if uerr := p.unbindLeaseMounts(lend, uid); uerr != nil {
				klog.Errorf("%s: claim %s: %v", p.name, claimName, uerr)
			}
			if rerr := p.lender.revoke(ctx, lend, claimName); rerr != nil {
				klog.Errorf("%s: claim %s: %v", p.name, claimName, rerr)
			}
			p.lender.failed(lend.Lease, err)
			return fail(err)
		}
		if err := p.lender.lend(ctx, lend, devs); err != nil {
			if rerr := p.lender.revoke(ctx, lend, claimName); rerr != nil {
				klog.Errorf("%s: claim %s: %v", p.name, claimName, rerr)
			}
			p.lender.failed(lend.Lease, err)
			return fail(err)
		}
		pc.Lend = lend
		// The memory of a companion claim belongs to the borrower, and
		// the companion pod references no claim: no CDI devices.
		dropCDIDevices(&pc.Result)
	}
	p.prepared[uid] = pc
	if err := p.sync(); err != nil {
		delete(p.prepared, uid)
		if pc.Lend != nil {
			if rerr := p.lender.revoke(ctx, pc.Lend, claimName); rerr != nil {
				klog.Errorf("%s: claim %s: %v", p.name, claimName, rerr)
			}
		}
		res := fail(err)
		if err := p.sync(); err != nil {
			klog.Errorf("%s: %v", p.name, err)
		}
		return res
	}
	if lend != nil {
		klog.Infof("%s: claim %s: companion of lease %s of %s/%s/%s prepared (nodes %v, binds %v)",
			p.name, claimName, lend.Lease, lend.Pod.Namespace, lend.Pod.Name, lend.Container, lend.Nodes, lend.Mounts)
		p.lender.prepared(lend.Lease, devs)
	}
	return pc.Result
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

// isAddDevError matches the transient region creation failure right
// after a hotplug.
func isAddDevError(err error) bool {
	return strings.Contains(err.Error(), "add_dev")
}

// preparedDevice returns a device of a prepared claim other than
// exceptUID with the serial, or nil.
func (p *poolDriver) preparedDevice(serial uint64, exceptUID string) *preparedPoolDevice {
	for uid, pc := range p.prepared {
		if uid == exceptUID {
			continue
		}
		for i := range pc.Devices {
			if pc.Devices[i].Serial == serial {
				return &pc.Devices[i]
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
	other := p.preparedDevice(data.Serial, exceptUID)
	switch {
	case other == nil:
		return nil
	case other.Shared != data.Shared:
		return fmt.Errorf("shared=%v, but another claim prepared it with shared=%v", data.Shared, other.Shared)
	case other.Mode != data.Mode && (!persistentMode(other.Mode) || !persistentMode(data.Mode)):
		return fmt.Errorf("mode %s, but another claim prepared it in mode %s", data.Mode, other.Mode)
	}
	return nil
}

// rollback releases what a failed Prepare of a claim prepared, devs, and
// the serials that it touched, unless another prepared claim uses them.
func (p *poolDriver) rollback(ctx context.Context, uid string, devs []preparedPoolDevice, serials []uint64) {
	for _, err := range p.releaseDevices(ctx, uid, devs, serials) {
		klog.Errorf("%s: rollback: %v", p.name, err)
	}
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
	return &poolDevice{Serial: serial, Shared: *d.Shared, Size: *d.Size, Exclusive: d.Exclusive, Persistent: d.Persistent}, nil
}

// waitMemdev returns the memdev with the serial, waiting up to the
// timeout for it to appear.
func (p *poolDriver) waitMemdev(ctx context.Context, serial uint64) (string, error) {
	if name, err := p.mem.FindMemdev(serial); err == nil {
		wctx, cancel := context.WithTimeout(ctx, p.probeGrace)
		defer cancel()
		if n, err := p.mem.WaitMemdev(wctx, serial); err == nil {
			return n, nil
		}
		return name, nil
	}
	wctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return p.mem.WaitMemdev(wctx, serial)
}

// prepareDevice returns the device of an allocation result prepared as
// data says; with an error of a device of persistent memory, the device as
// far as it was prepared. The NUMA node of a device in mode numa is fenced
// before its memory goes online.
func (p *poolDriver) prepareDevice(ctx context.Context, r *resourceapi.DeviceRequestAllocationResult, data *poolDevice) (*preparedPoolDevice, error) {
	memdev, err := p.waitMemdev(ctx, data.Serial)
	if err != nil {
		return nil, err
	}
	dev := &preparedPoolDevice{
		Request:  r.Request,
		Device:   r.Device,
		Pool:     r.Pool,
		Serial:   data.Serial,
		Shared:   data.Shared,
		Size:     data.Size,
		Mode:     data.Mode,
		ReadOnly: data.ReadOnly,
		Memdev:   memdev,
		Node:     -1,
	}
	if data.Persistent {
		dev.Persistent = true
		if err := p.preparePersistent(ctx, memdev, data, dev); err != nil {
			return dev, err
		}
		return dev, nil
	}
	if data.Mode == api.ModeDax {
		// device_dax: never onlined as RAM (shared memory must never be).
		ri, err := p.mem.CreateRegion(ctx, memdev, memctl.ModeDax, "")
		if err != nil {
			return nil, err
		}
		if ri.Device == "" || ri.Driver != memctl.DriverDeviceDax {
			return nil, fmt.Errorf("%s: %s is bound to %q, not %s", memdev, ri.Dax, ri.Driver, memctl.DriverDeviceDax)
		}
		major, minor, err := p.mem.DaxDevNumbers(ri.Dax)
		if err != nil {
			return nil, err
		}
		dev.Region, dev.Dax, dev.DaxDevice, dev.DaxMajor, dev.DaxMinor = ri.Region, ri.Dax, ri.Device, major, minor
		return dev, nil
	}
	created, err := p.mem.CreateRegion(ctx, memdev, memctl.ModeNUMA, "")
	if err != nil {
		return nil, err
	}
	// the blocks of the region are offline until Online
	p.fence.Fence(ctx, created.Node)
	ri, err := p.mem.Online(memdev, true)
	if err != nil {
		return nil, err
	}
	dev.Region, dev.Dax, dev.Node = ri.Region, ri.Dax, ri.Node
	if dev.Node < 0 {
		dev.Node = p.mem.BlocksNode(ri.Blocks)
	}
	if dev.Node < 0 {
		return nil, fmt.Errorf("%s: cannot find the NUMA node of %s", memdev, ri.Region)
	}
	if p.fence != nil && dev.Node != created.Node {
		klog.V(3).Infof("%s: %s: NUMA node %d of %s known only after onlining, fencing it late", p.name, memdev, dev.Node, ri.Region)
		p.fence.Fence(ctx, dev.Node)
	}
	return dev, nil
}

// release makes the memdev with the serial removable. A memdev that is
// gone is not an error.
func (p *poolDriver) release(ctx context.Context, serial uint64) error {
	memdev, err := p.mem.FindMemdev(serial)
	if errors.Is(err, memctl.ErrNotFound) {
		klog.Infof("%s: memdev with serial 0x%x is gone, nothing to release", p.name, serial)
		return nil
	}
	if err != nil {
		return err
	}
	if err := p.mem.Release(ctx, memdev); err != nil {
		return err
	}
	klog.Infof("%s: released %s (serial 0x%x)", p.name, memdev, serial)
	return nil
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

func (p *poolDriver) unprepareClaim(ctx context.Context, uid string) error {
	pc, ok := p.prepared[uid]
	if !ok {
		return nil
	}
	if pc.Lend != nil {
		p.lender.releasing(pc.Lend.Lease)
		// Revoke before the release: offlining memory that the
		// container still has in cpuset.mems leaves a stale node there.
		if err := p.lender.revoke(ctx, pc.Lend, pc.ClaimName); err != nil {
			err = fmt.Errorf("%s: unpreparing claim %s: %w", p.name, pc.ClaimName, err)
			klog.Error(err)
			return err
		}
		// The bind holds the superblock of the device: the region is
		// released only after it is gone.
		if err := p.unbindLeaseMounts(pc.Lend, uid); err != nil {
			err = fmt.Errorf("%s: unpreparing claim %s: %w", p.name, pc.ClaimName, err)
			klog.Error(err)
			return err
		}
	}
	if errs := p.releaseDevices(ctx, uid, pc.Devices, nil); len(errs) > 0 {
		err := fmt.Errorf("%s: unpreparing claim %s: %w", p.name, pc.ClaimName, errors.Join(errs...))
		klog.Error(err)
		return err
	}
	delete(p.prepared, uid)
	klog.Infof("%s: unprepared claim %s (%s)", p.name, pc.ClaimName, uid)
	return p.sync()
}

// sync rewrites the CDI spec and the state file from the prepared map.
// Called with p.mu held.
func (p *poolDriver) sync() error {
	p.updateSerials()
	return errors.Join(p.writeCDISpec(), p.save())
}

// poolCDIDeviceID returns the qualified CDI device name of the allocation
// result n of a pool claim: nri.io/cxl-pool=claim-<uid>-<n>.
func poolCDIDeviceID(claimUID string, n int) string {
	return cdiparser.QualifiedName(device.CDIVendor, device.PoolCDIClass, claimCDIDeviceName(claimUID, n))
}

// buildCDISpec builds the CDI spec of all prepared pool claims but
// companion claims: one device claim-<uid>-<n> per allocation result n with
// the result marker, the environment of the result's device (api.Env), the
// device node of a dax or block device and the bind mount of the node
// mount of an fs device.
func (p *poolDriver) buildCDISpec() *cdiSpecs.Spec {
	spec := &cdiSpecs.Spec{Kind: device.PoolCDIKind}
	for _, uid := range slices.Sorted(maps.Keys(p.prepared)) {
		pc := p.prepared[uid]
		if pc.Lend != nil {
			continue
		}
		keys := envKeys{}
		for i := range pc.Devices {
			d := &pc.Devices[i]
			env := map[string]string{resultEnvVarName(uid, d.Result): "1"}
			maps.Copy(env, api.Env(d.memory(keys.next(api.Key(d.Serial, 1)))))
			edits := cdiSpecs.ContainerEdits{Env: api.EnvList(env)}
			switch d.Mode {
			case api.ModeDax:
				edits.DeviceNodes = []*cdiSpecs.DeviceNode{daxDeviceNode(d.DaxDevice, d.DaxMajor, d.DaxMinor, d.ReadOnly)}
			case api.ModeBlock:
				edits.DeviceNodes = []*cdiSpecs.DeviceNode{blockDeviceNode(d)}
			case api.ModeFs:
				edits.Mounts = []*cdiSpecs.Mount{fsMount(d)}
			}
			spec.Devices = append(spec.Devices, cdiSpecs.Device{Name: claimCDIDeviceName(uid, d.Result), ContainerEdits: edits})
		}
	}
	return spec
}

// writeCDISpec writes the CDI spec of the prepared devices, or removes
// it when there are none.
func (p *poolDriver) writeCDISpec() error {
	if p.cdi == nil {
		return nil
	}
	spec := p.buildCDISpec()
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

func (p *poolDriver) save() error {
	return writeJSONFile(p.stateFile, p.prepared)
}

func (p *poolDriver) load() error {
	data, err := os.ReadFile(p.stateFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", p.stateFile, err)
	}
	if err := json.Unmarshal(data, &p.prepared); err != nil {
		return fmt.Errorf("parsing %s: %w", p.stateFile, err)
	}
	if p.prepared == nil {
		p.prepared = map[string]*preparedPoolClaim{}
	}
	for uid, pc := range p.prepared {
		for _, d := range pc.Devices {
			if _, err := p.mem.FindMemdev(d.Serial); err != nil {
				klog.Warningf("%s: claim %s (%s): memdev with serial 0x%x of %s is gone, keeping it until Unprepare",
					p.name, pc.ClaimName, uid, d.Serial, d.Device)
			}
		}
	}
	klog.Infof("%s: loaded %d prepared claims from %s", p.name, len(p.prepared), p.stateFile)
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
