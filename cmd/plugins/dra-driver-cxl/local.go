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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// The local memdevs of cxl.nri.io: every allocation result of a claim on a
// local memdev is a grant of the device engine (a part of a sliced memdev,
// the device of a shared one, a use of a persistent one) and the claim a
// preparation in the store. This file builds the requests to the engine and
// the results of a Prepare from the allocation results and their
// MemoryConfig, commits the preparation around the engine's work, and
// derives what the publisher needs from the records. See
// docs/memory/cxl/local.md.

const (
	// cxlRegionAlign is the alignment of the physical address of a CXL
	// region in its window: a region starts at most block size -
	// cxlRegionAlign after a memory block boundary.
	cxlRegionAlign = 256 << 20
	// bootIDFile identifies the running kernel (under the sysfs root).
	bootIDFile = "proc/sys/kernel/random/boot_id"
	// rollbackTimeout bounds the cleanup after a failure.
	rollbackTimeout = time.Minute
	// localCommitTimeout bounds a commit of the records of the claims of
	// cxl.nri.io, which the end of a request does not withdraw.
	localCommitTimeout = time.Minute
)

// readBootID returns the boot id of the running kernel, "" if it cannot be
// read.
func readBootID(sysfsRoot string) string {
	b, err := os.ReadFile(filepath.Join(sysfsRoot, "/", bootIDFile))
	if err != nil {
		klog.Warningf("cannot read the boot id: %v; the claims, slices and leases of an earlier boot are taken as those of this one", err)
		return ""
	}
	return strings.TrimSpace(string(b))
}

// otherBoot tells whether a record of the boot recorded is of another boot
// than the running one, bootID. A record without a boot id, written by a
// driver that did not record it, is taken as one of this boot (a driver
// upgraded without a reboot), and so is every record when the boot id of
// the running kernel is unknown.
func otherBoot(recorded, bootID string) bool {
	return recorded != "" && bootID != "" && recorded != bootID
}

// rollbackContext returns a context for cleaning up after a failure that
// the end of ctx does not cancel.
func rollbackContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
}

// localUsableSize returns the bytes of whole memory blocks of bs bytes
// that a region on a memdev of size bytes is sure to hold, wherever in its
// window it starts.
func localUsableSize(size, bs uint64) uint64 {
	if bs == 0 {
		return 0
	}
	if bs > cxlRegionAlign {
		head := bs - cxlRegionAlign
		if size <= head {
			return 0
		}
		size -= head
	}
	return size / bs * bs
}

// localUse is how the device engine uses a local memdev.
type localUse struct {
	// Shared is true when the memdev is used as a shared device, false
	// when it is sliced; of a persistent device, whether it is shared.
	Shared bool
	// Persistent is true when the memdev is used as a persistent device.
	Persistent bool
	// Claims are the UIDs of the claims that use the memdev.
	Claims []string
}

// localSnapshot is what the publisher of local memdevs needs from the
// records of the device engine.
type localSnapshot struct {
	// Uses are the uses of the local memdevs that the engine has records
	// of, by serial.
	Uses map[uint64]localUse
	// BlockSize is the memory block size in bytes, 0 if unknown.
	BlockSize uint64
	// Probed are the usable sizes that the address line probe found, by
	// serial.
	Probed map[uint64]uint64
}

// probed returns the usable size that the address line probe found for
// the memdev with the serial, 0 if none.
func (l *localSnapshot) probed(serial uint64) uint64 {
	if l == nil {
		return 0
	}
	return l.Probed[serial]
}

// uses tells whether the engine uses the local memdev with the serial.
func (l *localSnapshot) uses(serial uint64) bool {
	if l == nil {
		return false
	}
	_, ok := l.Uses[serial]
	return ok
}

// use returns how the engine uses the local memdev with the serial, and
// whether it uses it.
func (l *localSnapshot) use(serial uint64) (localUse, bool) {
	if l == nil {
		return localUse{}, false
	}
	u, ok := l.Uses[serial]
	return u, ok
}

// localDevices are the local memdevs of cxl.nri.io on the device engine,
// and the records of the claims of cxl.nri.io in its store.
type localDevices struct {
	devices *deviceEngine
	st      *store.Store
	k       *kernel.Kernel
	bootID  string
	// managed: the engine manages the local memdevs (manageMemdevs).
	managed bool
}

// newLocalDevices returns the local memdevs of the engine devices of the
// kernel k, with the records of the store st, of the boot bootID ("":
// unknown); managed tells whether the engine manages them.
func newLocalDevices(devices *deviceEngine, st *store.Store, k *kernel.Kernel, bootID string, managed bool) *localDevices {
	l := &localDevices{devices: devices, st: st, k: k, bootID: bootID, managed: managed}
	if !managed {
		return l
	}
	if _, err := k.BlockSize(); err != nil {
		klog.Warningf("local: memory block size: %v: local memory devices are not published until the memory block size is known", err)
	}
	return l
}

// Snapshot returns the uses of the local memdevs that the engine has
// records of, the memory block size and the probed usable sizes; nil when
// the engine does not manage local memdevs.
func (l *localDevices) Snapshot() *localSnapshot {
	if l == nil || !l.managed {
		return nil
	}
	snap := &localSnapshot{Uses: map[uint64]localUse{}, Probed: map[uint64]uint64{}}
	r := &l.st.Snapshot().Records
	for i := range r.Memdevs {
		m := &r.Memdevs[i]
		if m.Source != state.SourceLocal {
			continue
		}
		u := localUse{Shared: m.Facts.Shared, Persistent: m.Facts.Persistent, Claims: []string{}}
		for _, ref := range m.Grants {
			if !slices.Contains(u.Claims, ref.Claim) {
				u.Claims = append(u.Claims, ref.Claim)
			}
		}
		slices.Sort(u.Claims)
		snap.Uses[uint64(m.Serial)] = u
	}
	for serial, p := range l.devices.Probes() {
		snap.Probed[uint64(serial)] = p.UsableSize
	}
	snap.BlockSize, _ = l.k.BlockSize()
	return snap
}

// localPrepare is a Prepare of a claim of cxl.nri.io: its requests to the
// engine and its results.
type localPrepare struct {
	uid, claimName string
	lend           *lendRecord
	reqs           []engine.GrantRequest
	results        []state.Result
	// uses are the shares of the grants of shared memdevs, for the log
	// lines.
	uses map[state.GrantRef]string
	// lease tells whether a result is on the lease device.
	lease bool
}

// claimError returns err of the claim of a Prepare: "claim ns/name: err".
func (lp *localPrepare) claimError(err error) error {
	return fmt.Errorf("claim %s: %w", lp.claimName, err)
}

// deviceError returns the error of a grant of a Prepare in the words of
// the kind of its memdev: the device of the result (a sliced or shared
// memdev), its request (a persistent one); a lease bind names the lease.
func (lp *localPrepare) deviceError(err error) error {
	var ge *engine.GrantError
	var be *engine.BindError
	if !errors.As(err, &ge) || errors.As(err, &be) {
		return lp.claimError(err)
	}
	for i := range lp.reqs {
		req := &lp.reqs[i]
		if req.Ref != ge.Ref {
			continue
		}
		if req.Asked.Kind == state.KindPersistent {
			return lp.claimError(fmt.Errorf("request %s: %w", lp.request(req.Ref), ge.Err))
		}
		return lp.claimError(fmt.Errorf("device %s: %w", req.Device, ge.Err))
	}
	return lp.claimError(err)
}

// request returns the request of the result of the grant ref.
func (lp *localPrepare) request(ref state.GrantRef) string {
	for _, res := range lp.results {
		if res.Index == ref.Result {
			return res.Request
		}
	}
	return ""
}

// requests returns the Prepare of a claim: a request to the engine and a
// result for every allocation result of cxl.nri.io on the node, as the
// MemoryConfig of the result (resolved) says, of the devices allocatable.
// Every result is checked before any device is touched.
func (s *nodeState) requests(claim *resourcev1.ResourceClaim, allocatable device.DevicesInfo, resolved map[int]*config.Resolved, lend *lendRecord) (*localPrepare, error) {
	lp := &localPrepare{uid: string(claim.UID), claimName: claim.Namespace + "/" + claim.Name, lend: lend, uses: map[state.GrantRef]string{}}
	// the env keys of the memdevs, as buildClaimsCDISpec counts them
	keys := envKeys{}
	fs := 0
	for n := range claim.Status.Allocation.Devices.Results {
		r := &claim.Status.Allocation.Devices.Results[n]
		if r.Driver != device.DriverName || r.Pool != s.NodeName {
			klog.Infof("ignoring claim allocation device %+v", *r)
			continue
		}
		dev, found := allocatable[r.Device]
		if !found {
			return nil, fmt.Errorf("could not find allocatable device %v (pool %v)", r.Device, r.Pool)
		}
		res := resolved[n]
		if res == nil {
			return nil, lp.claimError(fmt.Errorf("request %s: internal error: no MemoryConfig of the result", r.Request))
		}
		klog.V(3).Infof("claim %s request %s result %d: MemoryConfig %s", lp.claimName, r.Request, n, res.Config.Compact())
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
			if req, err = s.memdevRequest(lp, r, n, key, d, cfg); err == nil {
				if req.Asked.Mode == state.ModeFs && lend != nil {
					if fs++; fs > 1 {
						return nil, &leaseBindError{fmt.Errorf("lease %s: more than one filesystem device", lend.Lease)}
					}
					if req.BindTarget, err = leaseBindTarget(lend); err != nil {
						return nil, &leaseBindError{err}
					}
				}
				lp.reqs = append(lp.reqs, req)
				ref := req.Ref
				result.Kind, result.Grant = state.ResultGrant, &ref
				result.Memdev = &state.MemdevResult{Shared: d.Shared, Persistent: d.Persistent}
				if d.NodeAffinity >= 0 {
					result.Memdev.NumaAffinity = []int{d.NodeAffinity}
				}
			}
		default:
			if err = otherResult(&result, r, d, cfg); err != nil {
				err = lp.claimError(fmt.Errorf("request %s: %w", r.Request, err))
			}
			lp.lease = lp.lease || result.Kind == state.ResultLeaseClaim
			if result.LeaseClaim != nil {
				result.LeaseClaim.UID = lp.uid
			}
		}
		if err != nil {
			return nil, err
		}
		lp.results = append(lp.results, result)
	}
	return lp, nil
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
func (s *nodeState) memdevRequest(lp *localPrepare, r *resourcev1.DeviceRequestAllocationResult, n int, key string, dev *device.Memdev, cfg config.Device) (engine.GrantRequest, error) {
	req := engine.GrantRequest{
		Ref:       state.GrantRef{Claim: lp.uid, Result: n},
		ClaimName: lp.claimName,
		Device:    r.Device,
		Serial:    state.Serial(dev.Serial),
		Asked:     state.Asked{Source: state.SourceLocal, ReadOnly: cfg.IsReadOnly()},
		Facts: state.MemdevFacts{Shared: dev.Shared, Persistent: dev.Persistent,
			Usable: s.config.configuredUsableSize(dev.Name, dev.Serial)},
	}
	if dev.NodeAffinity >= 0 {
		req.Facts.NumaAffinity = state.NumaNodePtr(dev.NodeAffinity)
	}
	if l := lp.lend; l != nil {
		req.Lend = &state.GrantLend{Lease: l.Lease, Pod: state.PodRef(l.Pod), Container: l.Container, FsDir: l.FsDir, Name: l.Name}
	}
	if !s.local.managed {
		return req, lp.claimError(fmt.Errorf("device %s: %w", r.Device, errors.New("local memdevs are not managed (manageMemdevs: false)")))
	}
	if dev.Persistent {
		return req, s.persistentRequest(lp, &req, r, key, dev, cfg)
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
		return req, lp.claimError(fmt.Errorf("request %s: %w", r.Request, err))
	}
	req.Asked.Mode = state.Mode(mode)
	if dev.Shared {
		req.Asked.Kind, req.Asked.Shared = state.KindShared, true
		lp.uses[req.Ref] = shareUse(shares, device.SharesUnlimited)
		return req, nil
	}
	if _, ok := r.ConsumedCapacity[device.CapacityShares]; ok {
		return req, lp.claimError(fmt.Errorf("request %s: device %s: allocated as a shared device, which it is not any more", r.Request, api.FormatSerial(dev.Serial)))
	}
	size := dev.Size
	if dev.BlockSize > 0 {
		size = localUsableSize(dev.Size, dev.BlockSize)
	}
	if consumed, ok := r.ConsumedCapacity[device.CapacityMemory]; ok && consumed.Value() > 0 {
		size = uint64(consumed.Value())
	}
	if size == 0 {
		return req, lp.claimError(fmt.Errorf("device %s: %w", r.Device, errors.New("size 0")))
	}
	req.Asked.Kind, req.Asked.Size = state.KindExclusive, size
	return req, nil
}

// persistentRequest sets the request of an allocation result on a local
// memdev of persistent memory by the device settings cfg, its facts as the
// configuration and the allocation give them.
func (s *nodeState) persistentRequest(lp *localPrepare, req *engine.GrantRequest, r *resourcev1.DeviceRequestAllocationResult, key string, dev *device.Memdev, cfg config.Device) error {
	fail := func(err error) error {
		return lp.claimError(fmt.Errorf("request %s: %w", r.Request, err))
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
		Coherent:   s.config.memdevCoherent(dev.Name, dev.Serial),
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

// records returns the records of the store; the caller must not change
// them.
func (l *localDevices) records() *state.Records {
	return &l.st.Snapshot().Records
}

// commit applies fn to the document in one durable commit, bounded by
// localCommitTimeout, not by ctx.
func (l *localDevices) commit(ctx context.Context, fn func(doc *store.Document) error) error {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), localCommitTimeout)
	defer cancel()
	return l.st.Commit(cctx, store.Durable, fn)
}

// preparation returns the preparation of the claim uid of cxl.nri.io, nil
// if there is none.
func (l *localDevices) preparation(uid string) *state.Preparation {
	return l.records().Preparation(device.DriverName, uid)
}

// commitPreparing commits the preparation of a Prepare PREPARING with its
// results, before the engine touches a device: a new one, a Prepare again
// of a claim whose Prepare did not finish or that its rollback kept, or of
// a claim of another boot, whose grants are dropped.
func (l *localDevices) commitPreparing(ctx context.Context, lp *localPrepare) error {
	return l.commit(ctx, func(doc *store.Document) error {
		prep := doc.Preparation(device.DriverName, lp.uid)
		if prep == nil {
			doc.Preparations = append(doc.Preparations, state.Preparation{UID: lp.uid, Driver: device.DriverName, State: state.PreparationUnknown})
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
		prep.ClaimName, prep.BootID, prep.Results = lp.claimName, l.bootID, slices.Clone(lp.results)
		prep.Lease = ""
		if lp.lend != nil {
			prep.Lease = lp.lend.Lease
		}
		return state.Apply(&state.PreparationTable, &prep.State, state.PreparationPreparing, state.TriggerPrepare)
	})
}

// commitPrepared commits the preparation of a Prepare whose devices are
// realised PREPARED.
func (l *localDevices) commitPrepared(ctx context.Context, uid string) error {
	return l.commit(ctx, func(doc *store.Document) error {
		prep := doc.Preparation(device.DriverName, uid)
		if prep == nil {
			return fmt.Errorf("claim %s has no record", uid)
		}
		return state.Apply(&state.PreparationTable, &prep.State, state.PreparationPrepared, state.TriggerPrepare)
	})
}

// failedPrepare commits the preparation of a Prepare that failed after its
// rollback: KEPT with the results of its grants that are left (the regions
// that the rollback kept for the claim; its Unprepare releases them, its
// Prepare again reuses them), else removed.
func (l *localDevices) failedPrepare(ctx context.Context, uid string) {
	err := l.commit(ctx, func(doc *store.Document) error {
		prep := doc.Preparation(device.DriverName, uid)
		if prep == nil {
			return nil
		}
		prep.Results = slices.DeleteFunc(prep.Results, func(res state.Result) bool {
			return res.Grant == nil || doc.Grant(*res.Grant) == nil
		})
		if len(prep.Results) > 0 {
			return state.Apply(&state.PreparationTable, &prep.State, state.PreparationKept, state.TriggerPrepare)
		}
		return removePreparation(doc, uid, state.TriggerPrepare)
	})
	if err != nil {
		klog.Errorf("claim %s: rollback: %v", uid, err)
	}
}

// removePreparation removes the preparation of the claim uid of
// cxl.nri.io (-> UNKNOWN).
func removePreparation(doc *store.Document, uid string, trigger state.Trigger) error {
	prep := doc.Preparation(device.DriverName, uid)
	if prep == nil {
		return nil
	}
	if err := state.Apply(&state.PreparationTable, &prep.State, state.PreparationUnknown, trigger); err != nil {
		return err
	}
	doc.Preparations = slices.DeleteFunc(doc.Preparations, func(x state.Preparation) bool {
		return x.Driver == device.DriverName && x.UID == uid
	})
	return nil
}

// rollback releases the devices of a claim whose Prepare failed after the
// engine realised them, as a rollback does (the NUMA nodes that a companion
// claim lends revoked first, by failed, which is told between the revoke
// and the release), and commits its preparation KEPT or removes it. Errors
// are logged.
func (s *nodeState) rollback(ctx context.Context, uid, claimName string, failed func()) {
	rctx, cancel := rollbackContext(ctx)
	defer cancel()
	l := s.local
	prep := l.preparation(uid)
	if prep == nil || prep.State == state.PreparationStale {
		// nothing of another boot is left: its Prepare again or its
		// Unprepare goes on with it
		return
	}
	if prep.Lease != "" {
		if err := s.lending.revoke(rctx, l.lendOf(prep), claimName); err != nil {
			klog.Errorf("claim %s: rollback: %v", claimName, err)
		}
	}
	if failed != nil {
		failed()
	}
	if refs := grantRefs(l.records(), prep); len(refs) > 0 {
		if err := l.devices.ReleaseGrants(rctx, refs, engine.ReleaseRollback); err != nil {
			klog.Errorf("claim %s: rollback: %v", claimName, err)
		}
	}
	l.failedPrepare(rctx, uid)
}

// infoOf returns the prepared claim info of a preparation of cxl.nri.io as
// preparedClaimsInfo.json has it, in any state.
func (l *localDevices) infoOf(prep *state.Preparation) (*PreparedClaimInfo, error) {
	data, err := store.ClaimInfoContent(l.st.Snapshot(), prep, l.st.ViewOptions())
	if err != nil {
		return nil, err
	}
	info := &PreparedClaimInfo{}
	if err := json.Unmarshal(data, info); err != nil {
		return nil, err
	}
	return info, nil
}

// lendOf returns the lend of a preparation of a companion claim as
// preparedClaimsInfo.json has it, nil for another claim.
func (l *localDevices) lendOf(prep *state.Preparation) *lendRecord {
	info, err := l.infoOf(prep)
	if err != nil {
		klog.Errorf("claim %s: %v", prep.ClaimName, err)
		return nil
	}
	return info.Lend
}

// lendCompanion lends the NUMA nodes of the devices in mode numa of a
// companion claim to the container of its lend, each recorded before it is
// lent (the engine bound its device of mode fs), and returns the lend; on
// error the claim is rolled back.
func (s *nodeState) lendCompanion(ctx context.Context, lp *localPrepare, info *PreparedClaimInfo) error {
	if lp.lend == nil {
		return nil
	}
	var err error
	for _, d := range info.Devices {
		if d.DeviceType == device.DeviceTypeMemdev && d.Mode == api.ModeNUMA && len(d.NUMANodes) > 0 && d.NUMANodes[0] >= 0 {
			if err = s.local.devices.RecordLend(ctx, state.GrantRef{Claim: lp.uid, Result: d.Result}, d.NUMANodes[0]); err != nil {
				break
			}
		}
	}
	lend := *lp.lend
	if err == nil {
		err = s.lending.lend(ctx, &lend, s.lentDevices(info))
	}
	if err != nil {
		s.rollback(ctx, lp.uid, lp.claimName, func() { s.lending.failed(lend.Lease, err) })
		err = lp.claimError(err)
	}
	return err
}

// logPrepared logs what each allocation result on a local memdev of a
// Prepare got.
func (l *localDevices) logPrepared(lp *localPrepare) {
	r := l.records()
	for i := range lp.reqs {
		req := &lp.reqs[i]
		g := r.Grant(req.Ref)
		if g == nil {
			continue
		}
		memdev, region, s := "", string(g.Got.Region), uint64(g.Serial)
		if m := r.Memdev(g.Serial); m != nil {
			memdev = m.Name
		}
		request := lp.request(req.Ref)
		switch g.Asked.Kind {
		case state.KindShared:
			klog.Infof("local: memdev %s (serial 0x%x): claim %s request %s: shared %s size %d read-only %v %s",
				memdev, s, lp.uid, request, g.Got.Dax, g.Got.Size, g.Asked.ReadOnly, lp.uses[req.Ref])
		case state.KindPersistent:
			dev, access, fsType := "", string(g.Got.Mount), g.Got.FsType
			if g.Got.BlockDevice != nil {
				dev = g.Got.BlockDevice.Name
			}
			if m := mountOf(r, g); m != nil && fsType == "" {
				fsType = m.FsType
			}
			klog.Infof("local: memdev %s (serial 0x%x) %s: claim %s request %s: persistent %s mode %s read-only %v access %q fs %q",
				memdev, s, region, lp.uid, request, dev, g.Asked.Mode, g.Asked.ReadOnly, access, fsType)
		default:
			node, daxDevice := -1, ""
			if g.Asked.Mode == state.ModeNUMA {
				node = state.NumaNodeOf(g.Got.NumaNode)
			} else if g.Got.Dax != "" {
				daxDevice = filepath.Join(l.k.DevRoot, g.Got.Dax)
			}
			klog.Infof("local: memdev %s (serial 0x%x) %s: claim %s request %s: slice %s mode %s size %d node %d%s",
				memdev, s, region, lp.uid, request, g.Got.Dax, g.Asked.Mode, g.Got.Size, node, strings.TrimRight(" "+daxDevice, " "))
		}
	}
}

// mountOf returns the node mount of a grant of mode fs, nil for none.
func mountOf(r *state.Records, g *state.Grant) *state.Mount {
	if reg := r.Region(g.Got.Region); reg != nil && g.Got.Mount != "" {
		return reg.Mount(g.Got.Mount)
	}
	return nil
}

// unfinishedNodes returns the NUMA nodes of the grants of mode numa of the
// claims of cxl.nri.io whose Prepare did not finish (PREPARING, KEPT): a
// numa companion kept at a start has its memory online.
func (l *localDevices) unfinishedNodes() []int {
	if l == nil {
		return nil
	}
	r := l.records()
	var nodes []int
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Driver == device.DriverName && (prep.State == state.PreparationPreparing || prep.State == state.PreparationKept) {
			nodes = append(nodes, unfinishedNodes(r, prep)...)
		}
	}
	return nodes
}
