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
	"errors"
	"fmt"
	"slices"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/provenance"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// A claim's allocation results of a driver become the results of its
// preparation and the grant requests to the engine, every result checked
// before any device is touched: the MemoryConfig of the result (resolved
// from the claim's opaque configuration), the device section against the
// kind and the facts of the device. cxl.nri.io finds the device of a result
// in the last scan of the node (a local memdev, a region, the DRAM, the
// lease device); the pool driver takes the device's facts from the status
// data that the pool controller wrote into the claim.

// defaultFsPathDir is the directory of the default path of mode fs in
// containers, /run/cxl-fs/<KEY>.
const defaultFsPathDir = "/run/cxl-fs"

// prepare is a Prepare of a claim: its requests to the engine and its
// results.
type prepare struct {
	uid, claimName string
	lend           *Lend
	reqs           []engine.GrantRequest
	results        []state.Result
	// uses are the shares of the grants of shared memdevs, for the log
	// lines.
	uses map[state.GrantRef]string
	// lease tells whether a result is on the lease device.
	lease bool
}

// newPrepare returns the Prepare of a claim.
func newPrepare(claim *resourcev1.ResourceClaim) *prepare {
	return &prepare{uid: string(claim.UID), claimName: claim.Namespace + "/" + claim.Name, uses: map[state.GrantRef]string{}}
}

// request returns the request of the result of the grant ref.
func (pr *prepare) request(ref state.GrantRef) string {
	for _, res := range pr.results {
		if res.Index == ref.Result {
			return res.Request
		}
	}
	return ""
}

// grantLend returns the lend of a grant of the Prepare, nil for a claim that
// is not a companion.
func (pr *prepare) grantLend() *state.GrantLend {
	l := pr.lend
	if l == nil {
		return nil
	}
	return &state.GrantLend{Lease: l.Lease, Pod: l.Pod, Container: l.Container, FsDir: l.FsDir, Name: l.Name}
}

// leaseBind sets the lease bind of a request of mode fs of a companion
// claim; fs counts them: a lease has one filesystem device at most.
func (pr *prepare) leaseBind(req *engine.GrantRequest, fs *int) error {
	if req.Asked.Mode != state.ModeFs || pr.lend == nil {
		return nil
	}
	if *fs++; *fs > 1 {
		return &leaseBindError{fmt.Errorf("lease %s: more than one filesystem device", pr.lend.Lease)}
	}
	target, err := leaseBindTarget(pr.lend)
	if err != nil {
		return &leaseBindError{err}
	}
	req.BindTarget = target
	return nil
}

// resolveResults returns the MemoryConfig of each allocation result of a
// claim for driver by result index; of selects the results of the driver.
// Returns an error with the request of the first result whose configuration
// is invalid.
func resolveResults(claim *resourcev1.ResourceClaim, driver string, of func(r *resourcev1.DeviceRequestAllocationResult) bool) (map[int]*config.Resolved, error) {
	out := map[int]*config.Resolved{}
	for n := range claim.Status.Allocation.Devices.Results {
		r := &claim.Status.Allocation.Devices.Results[n]
		if !of(r) {
			continue
		}
		res, err := config.Resolve(claim, driver, r.Request)
		if err != nil {
			return nil, fmt.Errorf("request %s: %w", r.Request, err)
		}
		out[n] = res
	}
	return out, nil
}

// consumedShares returns the shares that an allocation result of the shared
// device with the serial consumed, and an error if it consumed less than one
// share or has no shares in its consumed capacity.
func consumedShares(serial uint64, r *resourcev1.DeviceRequestAllocationResult) (int64, error) {
	q, ok := r.ConsumedCapacity[device.CapacityShares]
	if !ok || q.Cmp(*resource.NewQuantity(1, resource.DecimalSI)) < 0 {
		got := ""
		if ok {
			got = q.String()
		}
		return 0, fmt.Errorf("device %s: consumed %s %q is less than 1: request %s: 1 (a share) or no %s (exclusive)",
			api.FormatSerial(serial), device.CapacityShares, got, device.CapacityShares, device.CapacityShares)
	}
	return q.Value(), nil
}

// shareUse returns how an allocation result that consumed shares of a device
// of total shares uses it: "exclusive" when it consumed all of them, else
// "1 share" or "<n> shares".
func shareUse(shares, total int64) string {
	switch {
	case shares >= total:
		return "exclusive"
	case shares == 1:
		return "1 share"
	}
	return fmt.Sprintf("%d shares", shares)
}

// defaultFsPath returns the path of mode fs of the memory with the env key
// in a container when its device settings have none.
func defaultFsPath(key string) string {
	return defaultFsPathDir + "/" + key
}

// persistentMode tells whether a mode is a mode of persistent devices.
func persistentMode(mode string) bool {
	return mode == api.ModeBlock || mode == api.ModeFs
}

// LocalConfig is what cxl.nri.io needs of the driver configuration to map
// the allocation results on local memdevs.
type LocalConfig struct {
	// Managed: the engine manages the local memdevs (manageMemdevs).
	Managed bool
	// UsableSize returns the configured usable size of a memdev (0: all of
	// it), Coherent whether it is configured coherent.
	UsableSize func(memdev string, serial uint64) uint64
	Coherent   func(memdev string, serial uint64) bool
}

// validateLocal returns the Prepare of a claim of cxl.nri.io, or an error
// when the claim cannot be prepared: no allocation, a MemoryConfig that does
// not decode or does not fit its devices, a companion claim that cannot be
// lent.
func (p *Plugin) validateLocal(claim *resourcev1.ResourceClaim) (*prepare, error) {
	if claim.Status.Allocation == nil {
		return nil, fmt.Errorf("no allocation found in claim %v/%v status", claim.Namespace, claim.Name)
	}
	if err := config.CheckEntries(claim, p.rules.Name); err != nil {
		return nil, fmt.Errorf("claim %v/%v: %w", claim.Namespace, claim.Name, err)
	}
	allocatable := p.allocatable()
	resolved, err := resolveResults(claim, p.rules.Name, func(r *resourcev1.DeviceRequestAllocationResult) bool {
		return r.Driver == p.rules.Name && r.Pool == p.nodeName
	})
	if err != nil {
		return nil, fmt.Errorf("claim %v/%v: %w", claim.Namespace, claim.Name, err)
	}
	pr := newPrepare(claim)
	if id := LeaseOf(claim); id != "" {
		local, all := p.localMemdevResults(claim, allocatable)
		if local == 0 || local != all {
			return nil, fmt.Errorf("claim %v/%v: the companion claim of lease %s needs %s devices only", claim.Namespace, claim.Name, id, device.DeviceTypeMemdev)
		}
		if pr.lend, err = p.lender.Check(id, claim); err != nil {
			return nil, fmt.Errorf("claim %v/%v: %w", claim.Namespace, claim.Name, err)
		}
	}
	err = p.localResults(claim, pr, allocatable, resolved)
	var le *leaseBindError
	if errors.As(err, &le) {
		p.lender.Failed(pr.lend.Lease, err)
		err = fmt.Errorf("claim %v/%v: %w", claim.Namespace, claim.Name, err)
	}
	return pr, err
}

// localMemdevResults returns the number of allocation results of a claim on
// local memdevs of the node, and the number of all its results on devices
// of the node.
func (p *Plugin) localMemdevResults(claim *resourcev1.ResourceClaim, allocatable device.DevicesInfo) (local, all int) {
	for _, r := range claim.Status.Allocation.Devices.Results {
		if r.Driver != p.rules.Name || r.Pool != p.nodeName {
			continue
		}
		all++
		if d := allocatable[r.Device]; d != nil {
			if _, ok := d.Dev.(*device.Memdev); ok {
				local++
			}
		}
	}
	return local, all
}

// localResults sets the requests to the engine and the results of a Prepare
// of a claim of cxl.nri.io: one for every allocation result of the driver on
// the node, as the MemoryConfig of the result (resolved) says, of the
// devices allocatable.
func (p *Plugin) localResults(claim *resourcev1.ResourceClaim, pr *prepare, allocatable device.DevicesInfo, resolved map[int]*config.Resolved) error {
	// the env keys of the memdevs, as the CDI spec counts them
	keys := envKeys{}
	fs := 0
	for n := range claim.Status.Allocation.Devices.Results {
		r := &claim.Status.Allocation.Devices.Results[n]
		if r.Driver != p.rules.Name || r.Pool != p.nodeName {
			klog.Infof("ignoring claim allocation device %+v", *r)
			continue
		}
		dev, found := allocatable[r.Device]
		if !found {
			return fmt.Errorf("could not find allocatable device %v (pool %v)", r.Device, r.Pool)
		}
		res := resolved[n]
		if res == nil {
			return pr.claimError(fmt.Errorf("request %s: internal error: no MemoryConfig of the result", r.Request))
		}
		klog.V(3).Infof("claim %s request %s result %d: MemoryConfig %s", pr.claimName, r.Request, n, res.Config.Compact())
		result := state.Result{Index: n, Request: r.Request, Pool: r.Pool, Device: r.Device, Settings: res.Settings()}
		if r.ShareID != nil {
			result.ShareID = string(*r.ShareID)
		}
		cfg := res.Config.DeviceSection()
		var err error
		switch d := dev.Dev.(type) {
		case *device.Memdev:
			key := keys.next(api.Key(d.Serial, 1))
			var req engine.GrantRequest
			if req, err = p.memdevRequest(pr, r, n, key, d, cfg); err == nil {
				if err = pr.leaseBind(&req, &fs); err != nil {
					return err
				}
				pr.reqs = append(pr.reqs, req)
				ref := req.Ref
				result.Kind, result.Grant = state.ResultGrant, &ref
				result.Memdev = &state.MemdevResult{Shared: d.Shared, Persistent: d.Persistent}
				if d.NodeAffinity >= 0 {
					result.Memdev.NumaAffinity = []int{d.NodeAffinity}
				}
			}
		default:
			if err = otherResult(&result, r, d, cfg); err != nil {
				err = pr.claimError(fmt.Errorf("request %s: %w", r.Request, err))
			}
			pr.lease = pr.lease || result.Kind == state.ResultLeaseClaim
			if result.LeaseClaim != nil {
				result.LeaseClaim.UID = pr.uid
			}
		}
		if err != nil {
			return err
		}
		pr.results = append(pr.results, result)
	}
	return nil
}

// claimError returns err of the claim of a Prepare: "claim ns/name: err".
func (pr *prepare) claimError(err error) error {
	return fmt.Errorf("claim %s: %w", pr.claimName, err)
}

// otherResult sets the result of an allocation result r of a device of the
// node that is not a local memdev (a region, the DRAM, the lease device),
// and returns an error if its device settings cfg do not fit it.
func otherResult(res *state.Result, r *resourcev1.DeviceRequestAllocationResult, dev any, cfg config.Device) error {
	var consumed int64
	if q, ok := r.ConsumedCapacity[device.CapacityMemory]; ok {
		consumed = q.Value()
	}
	switch d := dev.(type) {
	case *nricxl.RegionDevice:
		if err := cfg.NUMAOnly(device.DeviceTypeRegion); err != nil {
			return err
		}
		reg := &state.RegionResult{Name: d.Name, SysfsPath: d.SysfsPath, NumaNode: d.Node, Size: d.Size, Consumed: consumed}
		for _, mem := range d.Memories {
			if mem.NodeAffinity >= 0 {
				reg.NumaAffinity = append(reg.NumaAffinity, mem.NodeAffinity)
			}
		}
		res.Kind, res.Region = state.ResultRegion, reg
	case *device.DRAM:
		if err := cfg.NUMAOnly(device.DeviceTypeDRAM); err != nil {
			return err
		}
		res.Kind, res.DRAM = state.ResultDRAM, &state.DRAMResult{NumaNodes: slices.Clone(d.Nodes), Size: d.Size, Consumed: consumed}
	case *device.LeaseToken:
		if err := cfg.CheckLease(); err != nil {
			return err
		}
		res.Kind, res.LeaseClaim = state.ResultLeaseClaim, &state.LeaseClaimResult{Consumed: consumed}
	default:
		return fmt.Errorf("unknown device type %T for %v", dev, r.Device)
	}
	return nil
}

// memdevRequest returns the request to the engine of the allocation result
// n of a Prepare on a local memdev, by the device settings cfg: a part of a
// sliced memdev (mode numa or dax), the device of a shared one (mode dax),
// or a use of a persistent one (mode block or fs, the default path of mode
// fs by the env key of the result).
func (p *Plugin) memdevRequest(pr *prepare, r *resourcev1.DeviceRequestAllocationResult, n int, key string, dev *device.Memdev, cfg config.Device) (engine.GrantRequest, error) {
	req := engine.GrantRequest{
		Ref:       state.GrantRef{Claim: pr.uid, Result: n},
		ClaimName: pr.claimName,
		Device:    r.Device,
		Serial:    state.Serial(dev.Serial),
		Asked:     state.Asked{Source: state.SourceLocal, ReadOnly: cfg.IsReadOnly()},
		Facts: state.MemdevFacts{Shared: dev.Shared, Persistent: dev.Persistent,
			Usable: p.local.UsableSize(dev.Name, dev.Serial)},
		Lend: pr.grantLend(),
	}
	if dev.NodeAffinity >= 0 {
		req.Facts.NumaAffinity = state.NumaNodePtr(dev.NodeAffinity)
	}
	if !p.local.Managed {
		return req, pr.claimError(fmt.Errorf("device %s: %w", r.Device, errors.New("local memdevs are not managed (manageMemdevs: false)")))
	}
	if dev.Persistent {
		return req, p.persistentRequest(pr, &req, r, key, dev, cfg)
	}
	shares := int64(0)
	var err error
	if dev.Shared {
		shares, err = consumedShares(dev.Serial, r)
	}
	mode := ""
	if err == nil {
		mode, err = cfg.MemdevMode(dev.Shared)
	}
	if err != nil {
		return req, pr.claimError(fmt.Errorf("request %s: %w", r.Request, err))
	}
	req.Asked.Mode = state.Mode(mode)
	if dev.Shared {
		req.Asked.Kind, req.Asked.Shared = state.KindShared, true
		pr.uses[req.Ref] = shareUse(shares, device.SharesUnlimited)
		return req, nil
	}
	if _, ok := r.ConsumedCapacity[device.CapacityShares]; ok {
		return req, pr.claimError(fmt.Errorf("request %s: device %s: allocated as a shared device, which it is not any more", r.Request, api.FormatSerial(dev.Serial)))
	}
	size := dev.Size
	if dev.BlockSize > 0 {
		size = LocalUsableSize(dev.Size, dev.BlockSize)
	}
	if consumed, ok := r.ConsumedCapacity[device.CapacityMemory]; ok && consumed.Value() > 0 {
		size = uint64(consumed.Value())
	}
	if size == 0 {
		return req, pr.claimError(fmt.Errorf("device %s: %w", r.Device, errors.New("size 0")))
	}
	req.Asked.Kind, req.Asked.Size = state.KindExclusive, size
	return req, nil
}

// persistentRequest sets the request of an allocation result on a local
// memdev of persistent memory by the device settings cfg, its facts as the
// configuration and the allocation give them.
func (p *Plugin) persistentRequest(pr *prepare, req *engine.GrantRequest, r *resourcev1.DeviceRequestAllocationResult, key string, dev *device.Memdev, cfg config.Device) error {
	fail := func(err error) error {
		return pr.claimError(fmt.Errorf("request %s: %w", r.Request, err))
	}
	if _, ok := r.ConsumedCapacity[device.CapacityMemory]; ok {
		return fail(fmt.Errorf("device %s: allocated as a device of volatile memory, which it is not any more", api.FormatSerial(dev.Serial)))
	}
	shares, err := consumedShares(dev.Serial, r)
	if err != nil {
		return fail(err)
	}
	facts := config.DeviceFacts{
		Persistent: true,
		Shared:     dev.Shared,
		Exclusive:  shares >= device.SharesUnlimited,
		SingleHost: !dev.Shared,
		Coherent:   p.local.Coherent(dev.Name, dev.Serial),
		Local:      true,
	}
	mode, err := cfg.PersistentMode(facts)
	if err != nil {
		return fail(err)
	}
	req.Asked.Kind, req.Asked.Mode, req.Asked.Shared = state.KindPersistent, state.Mode(mode), dev.Shared
	req.Asked.Access, req.Asked.FsType = state.Access(cfg.Access), cfg.FsType
	if mode == api.ModeFs {
		if req.Asked.Path = cfg.Path; req.Asked.Path == "" {
			req.Asked.Path = defaultFsPath(key)
		}
	}
	req.Facts.Coherent, req.SingleHost = facts.Coherent, facts.SingleHost
	return nil
}

// poolDevice is the status data of an allocation result of a pool claim,
// with the mode, read-only setting, access, filesystem type and path of its
// device settings.
type poolDevice struct {
	provenance.DeviceData
	Mode     string
	ReadOnly bool
	Access   string // fs: api.AccessDirect, api.AccessCached or "" (by type)
	FsType   string // fs: the declared type, "" to detect it
	Path     string // fs: the directory in the container
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

// validatePool returns the Prepare of a claim of the pool driver, or an
// error if the claim cannot be prepared: its allocation or MemoryConfig is
// invalid, the companion gate refuses it, or an allocation result cannot be
// prepared (poolResults); a lease that cannot be bound is told to the
// broker.
func (p *Plugin) validatePool(claim *resourcev1.ResourceClaim) (*prepare, error) {
	if claim.Status.Allocation == nil {
		return nil, errors.New("no allocation")
	}
	if err := config.CheckEntries(claim, p.rules.Name); err != nil {
		return nil, err
	}
	resolved, err := resolveResults(claim, p.rules.Name, func(r *resourcev1.DeviceRequestAllocationResult) bool { return r.Driver == p.rules.Name })
	if err != nil {
		return nil, err
	}
	pr := newPrepare(claim)
	if id := LeaseOf(claim); id != "" {
		if pr.lend, err = p.lender.Check(id, claim); err != nil {
			return pr, err
		}
	}
	if err := p.poolResults(claim, pr, resolved); err != nil {
		var le *leaseBindError
		if errors.As(err, &le) {
			p.lender.Failed(pr.lend.Lease, err)
		}
		return pr, err
	}
	return pr, nil
}

// poolResults sets the requests to the engine and the results of a Prepare
// of a claim from the allocation results of the pool driver, the status
// data of their devices and their MemoryConfig, and returns an error for a
// result that cannot be prepared: no status data, shares that do not fit, a
// mode the device does not have, another claim's preparation of the device
// in another way, a lease of mode fs without its directory.
func (p *Plugin) poolResults(claim *resourcev1.ResourceClaim, pr *prepare, resolved map[int]*config.Resolved) error {
	keys := envKeys{}
	fs := 0
	for n := range claim.Status.Allocation.Devices.Results {
		r := &claim.Status.Allocation.Devices.Results[n]
		if r.Driver != p.rules.Name {
			continue
		}
		dd, err := provenance.StatusData(claim, r)
		if err != nil {
			return err
		}
		data := &poolDevice{DeviceData: *dd}
		if data.Shared {
			// before the device is touched: shares "0" fits next to an
			// exclusive holder
			if _, err := consumedShares(data.Serial, r); err != nil {
				return err
			}
		}
		res := resolved[n]
		klog.V(3).Infof("%s: claim %s request %s result %d: MemoryConfig %s", p.rules.Name, pr.claimName, r.Request, n, res.Config.Compact())
		cfg := res.Config.DeviceSection()
		if data.Mode, err = cfg.PoolMode(data.facts()); err != nil {
			return fmt.Errorf("device %s serial 0x%x: %w", r.Device, data.Serial, err)
		}
		data.ReadOnly = cfg.IsReadOnly()
		// the env key of the device, as the CDI spec counts them
		key := keys.next(api.Key(data.Serial, 1))
		if data.Mode == api.ModeFs {
			// access "": by the type of the filesystem, at its Prepare
			data.Access, data.Path, data.FsType = cfg.Access, cfg.Path, cfg.FsType
			if data.Path == "" {
				data.Path = defaultFsPath(key)
			}
		}
		if err := p.checkSamePreparation(data, pr.uid); err != nil {
			return fmt.Errorf("device %s serial 0x%x: %w", r.Device, data.Serial, err)
		}
		req := poolRequest(pr, n, r, data)
		if err := pr.leaseBind(&req, &fs); err != nil {
			return err
		}
		pr.reqs = append(pr.reqs, req)
		pr.results = append(pr.results, poolResultOf(pr.uid, n, r, data, res.Settings()))
	}
	return nil
}

// poolRequest returns the request to the engine of the allocation result n
// of a Prepare of a claim, with its parsed status data and settings.
func poolRequest(pr *prepare, n int, r *resourcev1.DeviceRequestAllocationResult, data *poolDevice) engine.GrantRequest {
	return engine.GrantRequest{
		Ref:       state.GrantRef{Claim: pr.uid, Result: n},
		ClaimName: pr.claimName,
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
		SingleHost: data.facts().SingleHost,
		Lend:       pr.grantLend(),
	}
}

// grantKind returns the kind of a grant on a memdev that is shared or of
// persistent memory.
func grantKind(shared, persistent bool) state.GrantKind {
	switch {
	case persistent:
		return state.KindPersistent
	case shared:
		return state.KindShared
	}
	return state.KindExclusive
}

// poolResultOf returns the result n of a Prepare of a claim: a grant of the
// device of the allocation result, with what the claim asks.
func poolResultOf(uid string, n int, r *resourcev1.DeviceRequestAllocationResult, data *poolDevice, settings config.ResultSettings) state.Result {
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

// preparedGrant returns a grant of a prepared claim of the driver other
// than exceptUID on the serial, or nil.
func (p *Plugin) preparedGrant(serial uint64, exceptUID string) *state.Grant {
	r := p.records()
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Driver != p.rules.Name || prep.UID == exceptUID || !prep.Prepared() {
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
// differ: it is a property of the CDI device node, not of the region. Modes
// block and fs, and fs with either access, are compatible: they share one
// pmem region.
func (p *Plugin) checkSamePreparation(data *poolDevice, exceptUID string) error {
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
