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
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// Plugin is one DRA driver of the process, a kubelet plugin: cxl.nri.io
// (the local memdevs, the regions, the DRAM and the lease device of the
// node; it publishes the node's ResourceSlice) or the pool driver (the
// devices that pool controllers attach to the node). They differ only in
// their SourceRules.
//
// Identity: the DRA driver name.
//
// States: the Preparation of each claim of the driver (state.Preparation,
// one per claim UID and driver; its table state.PreparationTable).
//
// Transitions: Prepare: UNKNOWN, STALE or KEPT -> PREPARING (every result
// checked before, the intent committed before the engine touches a device)
// -> PREPARED (grants realised, lend done, CDI spec written), or KEPT /
// UNKNOWN after a failure's rollback; a Prepare of a prepared claim returns
// its result (a companion announced again, unrestored node mounts mounted
// again). Unprepare: lease claims closed first (cxl.nri.io), the companion
// told and its lend revoked, PREPARED -> UNPREPARING, the grants released,
// -> UNKNOWN. See the table below in internal/state.
//
// Invariants: a PREPARED claim's grants are REALISED; the CDI spec of the
// driver has the devices of its PREPARED claims (and UNPREPARING ones when
// the rules keep them) that are not companions; a companion claim has no
// CDI device.
//
// Persistence: the preparations are records of the store, committed
// durably before kubelet gets a response; the CDI spec is derived from
// them. A Prepare or an Unprepare that committed a change of the records
// asks the publisher for a rescan when it ends.
//
// Locks and waits: the kubelet helper serializes the Prepares and
// Unprepares of the driver; a claim's lock serializes its own (and a
// test's); the CDI write lock the writes of the spec; mu guards the
// in-flight serials, the unrestored claims and the late settings. A Prepare
// waits up to 30 s for the first NRI Synchronize before any claim lock. The
// rescan is asked for with no lock of the plugin or the engine held, and
// is not waited for.
type Plugin struct {
	rules    SourceRules
	st       *store.Store
	engine   *engine.Engine
	nodeName string
	bootID   string
	devRoot  string
	lender   *Lender
	local    LocalConfig
	onShared func(serial uint64)
	// publisher publishes the node's ResourceSlice, nil for none.
	publisher *Publisher
	helper    *kubeletplugin.Helper

	locks claimLocks
	// cdiMu serializes the writes of the CDI spec: a leaf lock.
	cdiMu sync.Mutex
	cdi   *cdiapi.Cache

	// mu guards the fields below: a leaf lock.
	mu      sync.Mutex
	leases  lend.LeaseClaims
	waitNRI func(ctx context.Context) error
	// inflight are the serials of the Prepares in progress, by count.
	inflight map[uint64]int
	// unrestored are why the claims (uid) have no CDI devices since the
	// start: their node mounts did not mount again.
	unrestored map[string]error
}

// Options are the settings of a Plugin.
type Options struct {
	// Rules are those of the driver.
	Rules SourceRules
	// Store keeps the records, Engine realises the grants.
	Store  *store.Store
	Engine *engine.Engine
	// NodeName is the node of the driver, BootID the running boot ("":
	// unknown), DevRoot the directory of the device nodes.
	NodeName, BootID, DevRoot string
	// CDI is the CDI cache that the spec of the driver is written with,
	// nil for none.
	CDI *cdiapi.Cache
	// Local is the configuration of the local memdevs (cxl.nri.io).
	Local LocalConfig
	// OnShared is told the serial of a local memdev that a claim uses
	// shared, nil for none.
	OnShared func(serial uint64)
	// Publisher publishes the node's ResourceSlice: it rescans after a
	// request that changed the records; the rules that publish look the
	// devices of their claims up in its last publication.
	Publisher *Publisher
}

// New returns the plugin of the rules over the store and the engine. Its
// lender has lending disabled until it is set (Lender).
func New(opts Options) (*Plugin, error) {
	if opts.Store == nil || opts.Engine == nil {
		return nil, fmt.Errorf("%s: the plugin needs the state store and the device engine", opts.Rules.Name)
	}
	if opts.Rules.validate == nil || opts.Rules.voice == nil {
		return nil, fmt.Errorf("%s: the rules have no validation or voice: not those of LocalRules or PoolRules", opts.Rules.Name)
	}
	if opts.Rules.Publishes && opts.Publisher == nil {
		return nil, fmt.Errorf("%s: the plugin publishes and needs the publisher", opts.Rules.Name)
	}
	if opts.DevRoot == "" {
		opts.DevRoot = "/dev"
	}
	return &Plugin{
		rules:      opts.Rules,
		st:         opts.Store,
		engine:     opts.Engine,
		nodeName:   opts.NodeName,
		bootID:     opts.BootID,
		devRoot:    opts.DevRoot,
		cdi:        opts.CDI,
		local:      opts.Local,
		onShared:   opts.OnShared,
		publisher:  opts.Publisher,
		lender:     NewLender(opts.Rules.Name),
		inflight:   map[uint64]int{},
		unrestored: map[string]error{},
	}, nil
}

// Name returns the DRA driver name of the plugin, "" for nil.
func (p *Plugin) Name() string {
	if p == nil {
		return ""
	}
	return p.rules.Name
}

// Engine returns the device engine of the plugin.
func (p *Plugin) Engine() *engine.Engine {
	return p.engine
}

// Rules returns the rules of the plugin.
func (p *Plugin) Rules() SourceRules {
	return p.rules
}

// Lender returns the lender of the companion claims of the driver, nil for
// a nil plugin.
func (p *Plugin) Lender() *Lender {
	if p == nil {
		return nil
	}
	return p.lender
}

// SetLeases sets the lease broker of the claims on the lease device, nil
// when lending is disabled.
func (p *Plugin) SetLeases(leases lend.LeaseClaims) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.leases = leases
}

// SetWaitNRI sets the wait of a Prepare for the first NRI Synchronize, nil
// for no wait.
func (p *Plugin) SetWaitNRI(wait func(ctx context.Context) error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.waitNRI = wait
}

// leaseClaims returns the lease broker of the claims on the lease device.
func (p *Plugin) leaseClaims() lend.LeaseClaims {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.leases
}

// Start writes the CDI spec of the prepared claims and starts the kubelet
// plugin with the options.
func (p *Plugin) Start(ctx context.Context, opts ...kubeletplugin.Option) error {
	if err := p.writeCDI(""); err != nil {
		return err
	}
	helper, err := kubeletplugin.Start(ctx, p, opts...)
	if err := p.rules.voice.started(err); err != nil {
		return err
	}
	p.helper = helper
	return nil
}

// Stop stops the kubelet plugin; nothing for a nil plugin.
func (p *Plugin) Stop() {
	if p != nil && p.helper != nil {
		p.helper.Stop()
	}
}

// records returns the records of the store; the caller must not change
// them.
func (p *Plugin) records() *state.Records {
	return &p.st.Snapshot().Records
}

// Records returns the records of the store of the plugin; the caller must
// not change them.
func (p *Plugin) Records() *state.Records {
	return p.records()
}

// preparation returns the preparation of the claim uid of the driver, nil
// if there is none.
func (p *Plugin) preparation(uid string) *state.Preparation {
	return p.records().Preparation(p.rules.Name, uid)
}

// commit applies fn in one durable commit.
func (p *Plugin) commit(ctx context.Context, fn func(doc *store.Document) error) error {
	return commit(ctx, p.st, fn)
}

// allocatable returns the devices of the last publication of the node's
// ResourceSlice (the scheduler allocated from it), nil for a driver that
// does not publish.
func (p *Plugin) allocatable() device.DevicesInfo {
	if p.publisher == nil || !p.rules.Publishes {
		return nil
	}
	return p.publisher.Published()
}

// PrepareResourceClaims prepares the claims of kubelet: after the first NRI
// Synchronize (bounded; else every claim fails and kubelet retries), each
// claim in its turn.
func (p *Plugin) PrepareResourceClaims(ctx context.Context, claims []*resourcev1.ResourceClaim) (map[types.UID]kubeletplugin.PrepareResult, error) {
	klog.V(5).Infof("NodePrepareResource is called: request: %+v", claims)
	response := map[types.UID]kubeletplugin.PrepareResult{}
	p.mu.Lock()
	wait := p.waitNRI
	p.mu.Unlock()
	if wait != nil {
		if err := wait(ctx); err != nil {
			klog.Warningf("%s: preparing %d claims: %v", p.rules.Name, len(claims), err)
			for _, claim := range claims {
				response[claim.UID] = kubeletplugin.PrepareResult{Err: err}
			}
			return response, nil
		}
	}
	for _, claim := range claims {
		response[claim.UID] = p.prepareClaim(ctx, claim)
	}
	return response, nil
}

// prepareClaim prepares a claim with its lock held, in a request of the
// engine, and asks the publisher for a rescan when the Prepare changed the
// records.
func (p *Plugin) prepareClaim(ctx context.Context, claim *resourcev1.ResourceClaim) kubeletplugin.PrepareResult {
	// deferred first: runs after the unlock and the end of the request
	defer p.republish(ctx, p.generation())
	unlock := p.locks.lock(string(claim.UID))
	defer unlock()
	ctx, end := p.engine.Request(ctx)
	defer end()
	return p.prepare(ctx, claim)
}

// prepare prepares a claim: its preparation PREPARING with its results, the
// grants of its devices realised by the engine, the lease socket of a
// result on the lease device, the lend of a companion claim, its CDI
// devices written, PREPARED. A claim that is prepared already is not
// prepared again.
func (p *Plugin) prepare(ctx context.Context, claim *resourcev1.ResourceClaim) kubeletplugin.PrepareResult {
	uid := string(claim.UID)
	claimName := claim.Namespace + "/" + claim.Name
	if prep := p.preparation(uid); prep != nil && prep.Prepared() {
		return p.preparedAgain(ctx, claim, prep)
	}
	v := p.rules.voice
	pr, err := p.rules.validate(p, claim)
	if err != nil {
		return p.refuse(ctx, uid, claimName, err)
	}
	if err := p.commitPreparing(ctx, pr); err != nil {
		return failed(v.failure(claimName, err))
	}
	p.addInflight(pr.reqs, 1)
	defer p.addInflight(pr.reqs, -1)
	if err := p.realise(ctx, pr); err != nil {
		return failed(v.failure(claimName, err))
	}
	if err := p.openLeaseClaim(claim, pr); err != nil {
		p.rollback(ctx, uid, claimName, nil)
		return failed(v.refused(claimName, err))
	}
	v.prepared(p, pr)
	if err := p.lendCompanion(ctx, pr); err != nil {
		return failed(v.failure(claimName, err))
	}
	return p.finish(ctx, pr)
}

// commitPreparing commits the preparation of a Prepare PREPARING with its
// results.
func (p *Plugin) commitPreparing(ctx context.Context, pr *prepare) error {
	lease := ""
	if pr.lend != nil {
		lease = pr.lend.Lease
	}
	return p.commit(ctx, func(doc *store.Document) error {
		return preparing(doc, p.rules.Name, pr.uid, pr.claimName, p.bootID, lease, pr.results)
	})
}

// realise has the engine realise the grants of a Prepare; a failure is
// rolled back by the engine and the preparation committed KEPT or removed,
// a failed lease bind told to the broker.
func (p *Plugin) realise(ctx context.Context, pr *prepare) error {
	for _, req := range pr.reqs {
		if req.Asked.Kind == state.KindShared && req.Asked.Source == state.SourceLocal && p.onShared != nil {
			p.onShared(uint64(req.Serial))
		}
	}
	if len(pr.reqs) == 0 {
		return nil
	}
	_, err := p.engine.PrepareGrants(ctx, pr.reqs)
	if err == nil {
		return nil
	}
	err = p.deviceError(pr, err)
	var be *engine.BindError
	if errors.As(err, &be) && pr.lend != nil {
		p.lender.Failed(pr.lend.Lease, err)
	}
	p.failedPrepare(ctx, pr.uid)
	return err
}

// finish writes the CDI spec with the devices of a Prepare whose grants are
// realised, commits it PREPARED and tells the broker of a companion claim;
// a failure rolls the Prepare back.
func (p *Plugin) finish(ctx context.Context, pr *prepare) kubeletplugin.PrepareResult {
	v := p.rules.voice
	result := prepareResult(p.preparation(pr.uid), p.rules.CDIKind)
	err := p.writeCDI(pr.uid)
	if err == nil {
		err = p.commit(ctx, func(doc *store.Document) error { return prepared(doc, p.rules.Name, pr.uid) })
	}
	if err != nil {
		err = v.finishFailure(pr.claimName, err)
		p.rollback(ctx, pr.uid, pr.claimName, func() {
			if pr.lend != nil && p.rules.FailLeaseOnFinish {
				p.lender.Failed(pr.lend.Lease, err)
			}
		})
		if cerr := p.writeCDI(""); cerr != nil {
			v.rollbackError(rollbackCDI, pr.uid, pr.claimName, cerr)
		}
		return failed(err)
	}
	if pr.lend != nil {
		lend, devs := p.lendAndDevices(p.preparation(pr.uid))
		if lend != nil {
			v.companionPrepared(pr.claimName, lend)
		}
		p.lender.Prepared(pr.lend.Lease, p.rules.Source, devs)
	}
	klog.V(5).Infof("Created prepared claim %v allocation", pr.uid)
	return result
}

// failed returns the PrepareResult of a failed Prepare.
func failed(err error) kubeletplugin.PrepareResult {
	return kubeletplugin.PrepareResult{Err: err}
}

// refuse returns the result of a Prepare refused before any device is
// touched: nothing is rolled back, what an earlier Prepare of the claim made
// stays with its preparation for the next Prepare or the Unprepare (a KEPT,
// PREPARING or STALE record keeps its state); the rules may retry the stale
// lease binds as a failed Prepare does.
func (p *Plugin) refuse(ctx context.Context, uid, claimName string, err error) kubeletplugin.PrepareResult {
	if prep := p.preparation(uid); prep != nil {
		if serr := stays(prep, state.TriggerPrepare); serr != nil {
			klog.Errorf("%s: claim %s: %v", p.rules.Name, claimName, serr)
		}
	}
	res := failed(p.rules.voice.refused(claimName, err))
	if p.rules.RetryStaleOnRefusal {
		p.retryStaleBinds(ctx)
	}
	return res
}

// retryStaleBinds unmounts the stale lease binds of the memdevs again, and
// releases what they held (engine.ReleaseGrants of no grant).
func (p *Plugin) retryStaleBinds(ctx context.Context) {
	rctx, cancel := rollbackContext(ctx)
	defer cancel()
	if err := p.engine.ReleaseGrants(rctx, nil, engine.ReleaseRollback); err != nil {
		klog.Errorf("%s: %v", p.rules.Name, err)
	}
}

// rollbackTimeout bounds the cleanup after a failure.
const rollbackTimeout = time.Minute

// rollbackContext returns a context for cleaning up after a failure that
// the end of ctx does not cancel.
func rollbackContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
}

// deviceError returns the error of a grant of a Prepare in the words of the
// driver: the device or the request of the result; a lease bind names the
// lease itself.
func (p *Plugin) deviceError(pr *prepare, err error) error {
	var ge *engine.GrantError
	var be *engine.BindError
	if !errors.As(err, &ge) || errors.As(err, &be) {
		return err
	}
	for i := range pr.reqs {
		if req := &pr.reqs[i]; req.Ref == ge.Ref {
			return p.rules.voice.deviceError(req, pr.request(req.Ref), ge.Err)
		}
	}
	return err
}

// openLeaseClaim opens the lease socket of a claim with a result on the
// lease device.
func (p *Plugin) openLeaseClaim(claim *resourcev1.ResourceClaim, pr *prepare) error {
	if !pr.lease {
		return nil
	}
	leases := p.leaseClaims()
	if leases == nil {
		return fmt.Errorf("claim %v/%v: lending to running containers is disabled (--leases=false)", claim.Namespace, claim.Name)
	}
	if err := leases.OpenClaim(claim); err != nil {
		return fmt.Errorf("claim %v/%v: lease socket: %w", claim.Namespace, claim.Name, err)
	}
	return nil
}

// lendCompanion lends the NUMA nodes of the devices in mode numa of a
// companion claim to the container of its lend, each recorded before it is
// lent (the engine bound its device of mode fs); on error the claim is
// rolled back.
func (p *Plugin) lendCompanion(ctx context.Context, pr *prepare) error {
	if pr.lend == nil {
		return nil
	}
	info, err := claimInfoOf(p.st.Snapshot(), p.preparation(pr.uid), p.st.ResultOptions())
	if err == nil {
		for _, d := range info.Devices {
			if node := deviceNumaNode(&d); node >= 0 {
				if err = p.engine.RecordLend(ctx, state.GrantRef{Claim: pr.uid, Result: d.Result}, node); err != nil {
					break
				}
			}
		}
	}
	lend := *pr.lend
	if err == nil {
		_, devs := p.lendAndDevices(p.preparation(pr.uid))
		err = p.lender.Lend(ctx, &lend, devs)
	}
	if err != nil {
		p.rollback(ctx, pr.uid, pr.claimName, func() { p.lender.Failed(lend.Lease, err) })
	}
	return err
}

// lendAndDevices returns the lend of a preparation of a companion claim and
// its memdevs.
func (p *Plugin) lendAndDevices(prep *state.Preparation) (*lend.Lend, []state.DeviceInfo) {
	if prep == nil {
		return nil, nil
	}
	doc := p.st.Snapshot()
	lend, err := lendOf(doc, prep)
	if err != nil {
		klog.Errorf("%s: claim %s: %v", p.rules.Name, prep.ClaimName, err)
	}
	info, err := claimInfoOf(doc, prep, p.st.ResultOptions())
	if err != nil {
		klog.Errorf("%s: claim %s: %v", p.rules.Name, prep.ClaimName, err)
		return lend, nil
	}
	devs := []state.DeviceInfo{}
	for _, d := range info.Devices {
		if d.DeviceType == device.DeviceTypeMemdev {
			devs = append(devs, d)
		}
	}
	return lend, devs
}

// failedPrepare commits the preparation of a Prepare that failed after its
// rollback: KEPT with the results of its grants that are left, else
// removed.
func (p *Plugin) failedPrepare(ctx context.Context, uid string) {
	kept, claimName := false, uid
	if prep := p.preparation(uid); prep != nil {
		claimName = prep.ClaimName
	}
	err := p.commit(ctx, func(doc *store.Document) error {
		var err error
		kept, err = failedCommit(doc, p.rules.Name, uid)
		return err
	})
	if err != nil {
		p.rules.voice.rollbackError(rollbackCommit, uid, claimName, err)
	}
	if kept {
		p.rules.voice.kept(uid, claimName)
	}
}

// rollback releases the devices of a claim whose Prepare failed after the
// engine realised them, as a rollback does (the NUMA nodes that a companion
// claim lends revoked first, then failed told, then the release), and
// commits its preparation KEPT or removes it. Errors are logged.
func (p *Plugin) rollback(ctx context.Context, uid, claimName string, failed func()) {
	rctx, cancel := rollbackContext(ctx)
	defer cancel()
	prep := p.preparation(uid)
	if prep == nil || prep.State == state.PreparationStale {
		// nothing of another boot is left: its Prepare again or its
		// Unprepare goes on with it
		return
	}
	if prep.Lease != "" {
		lend, _ := lendOf(p.st.Snapshot(), prep)
		if err := p.lender.Revoke(rctx, lend, claimName); err != nil {
			p.rules.voice.rollbackError(rollbackRevoke, uid, claimName, err)
		}
	}
	if failed != nil {
		failed()
	}
	if refs := grantRefs(p.records(), prep); len(refs) > 0 {
		if err := p.engine.ReleaseGrants(rctx, refs, engine.ReleaseRollback); err != nil {
			p.rules.voice.rollbackError(rollbackRelease, uid, claimName, err)
		}
	}
	p.failedPrepare(rctx, uid)
}

// preparedAgain returns the result of a claim that is prepared (or
// UNPREPARING: kubelet's Unprepare retry has not removed it): a companion
// claim is announced to the broker again, the node mounts that the start
// did not mount again are mounted, and the claims of them have their CDI
// devices again then.
func (p *Plugin) preparedAgain(ctx context.Context, claim *resourcev1.ResourceClaim, prep *state.Preparation) kubeletplugin.PrepareResult {
	v := p.rules.voice
	v.alreadyPrepared(prep)
	if prep.State == state.PreparationPrepared || prep.State == state.PreparationUnpreparing {
		if err := stays(prep, state.TriggerPrepare); err != nil {
			klog.Errorf("%s: claim %s: %v", p.rules.Name, prep.ClaimName, err)
		}
	}
	if prep.Lease != "" {
		lend, devs := p.lendAndDevices(prep)
		p.lender.Reprepared(lend, claim, p.rules.Source, devs)
		return prepareResult(prep, p.rules.CDIKind)
	}
	if prep.State != state.PreparationUnrestored {
		return prepareResult(prep, p.rules.CDIKind)
	}
	if err := p.remount(ctx, prep); err != nil {
		if serr := stays(prep, state.TriggerPrepare); serr != nil {
			klog.Errorf("%s: claim %s: %v", p.rules.Name, prep.ClaimName, serr)
		}
		return failed(v.remountError(claim, err))
	}
	return prepareResult(p.preparation(prep.UID), p.rules.CDIKind)
}

// remount mounts again the node mounts of a prepared claim that the start
// could not mount, commits it PREPARED when every grant is REALISED again,
// and rewrites the CDI spec.
func (p *Plugin) remount(ctx context.Context, prep *state.Preparation) error {
	r := p.records()
	var reqs []engine.GrantRequest
	var mounts []string
	for _, res := range prep.Results {
		g := grantOf(r, &res)
		if g == nil || g.State != state.GrantUnrestored {
			continue
		}
		reqs = append(reqs, engine.GrantRequest{Ref: g.Ref, ClaimName: prep.ClaimName, Device: res.Device, Serial: g.Serial, Asked: g.Asked})
		if mnt := unrestoredMount(r, g); mnt != "" && !slices.Contains(mounts, mnt) {
			mounts = append(mounts, mnt)
		}
	}
	var err error
	if len(reqs) > 0 {
		_, err = p.engine.PrepareGrants(ctx, reqs)
	}
	if err == nil {
		err = p.commit(ctx, func(doc *store.Document) error { return restored(doc, p.rules.Name, prep.UID) })
	}
	if err == nil {
		p.mu.Lock()
		why := p.unrestored[prep.UID]
		delete(p.unrestored, prep.UID)
		p.mu.Unlock()
		if why == nil {
			why = errors.New("its node mount is not mounted")
		}
		p.rules.voice.remounted(prep, mounts, why)
	}
	return errors.Join(err, p.writeCDI(""))
}

// UnprepareResourceClaims unprepares the claims of kubelet, each in its
// turn.
func (p *Plugin) UnprepareResourceClaims(ctx context.Context, claims []kubeletplugin.NamespacedObject) (map[types.UID]error, error) {
	klog.V(5).Infof("NodeUnprepareResource is called: number of claims: %d", len(claims))
	response := map[types.UID]error{}
	for _, claim := range claims {
		response[claim.UID] = p.unprepareClaim(ctx, string(claim.UID))
	}
	return response, nil
}

// unprepareClaim unprepares a claim: its lease claim closed first (a claim
// on the lease device of cxl.nri.io), then its devices released with the
// claim's lock held, in a request of the engine. It asks the publisher for
// a rescan when the Unprepare changed the records.
func (p *Plugin) unprepareClaim(ctx context.Context, uid string) error {
	// deferred first: runs after the unlock and the end of the request
	defer p.republish(ctx, p.generation())
	if leases := p.leaseClaims(); leases != nil {
		// the leases of a lease claim are released first (bounded; an
		// error makes kubelet retry)
		if err := leases.CloseClaim(ctx, uid); err != nil {
			return err
		}
	}
	unlock := p.locks.lock(uid)
	defer unlock()
	ctx, end := p.engine.Request(ctx)
	defer end()
	claimName, err := p.unprepare(ctx, uid)
	return p.rules.voice.unprepared(uid, claimName, err)
}

// unprepare releases the devices of a claim and removes its preparation,
// and returns its name ("" without a record): a prepared claim is
// UNPREPARING first, the nodes
// that a companion claim lends are revoked before its memory goes offline
// (not those of another boot: nothing of it exists). A claim without a
// record had nothing prepared: not an error. The CDI spec is written after
// it; its error is the Unprepare's after the release of a prepared claim
// with the rule FailUnprepareOnCDI, logged otherwise.
func (p *Plugin) unprepare(ctx context.Context, uid string) (string, error) {
	v := p.rules.voice
	prep := p.preparation(uid)
	if prep == nil {
		v.notPrepared(uid)
		return "", nil
	}
	isPrepared := prep.Prepared()
	if !isPrepared {
		v.unfinished(prep, serialsOf(p.records(), prep))
	}
	companion := prep.Lease != ""
	if companion {
		p.lender.Releasing(prep.Lease)
	}
	if isPrepared {
		if err := p.commit(ctx, func(doc *store.Document) error { return unpreparing(doc, p.rules.Name, uid) }); err != nil {
			return prep.ClaimName, v.unprepareError(prep, isPrepared, err)
		}
	}
	err := p.release(ctx, prep, companion)
	cerr := p.writeCDI("")
	if cerr != nil && (err != nil || !isPrepared || !p.rules.FailUnprepareOnCDI) {
		klog.Errorf("%s: %v", p.rules.Name, cerr)
		cerr = nil
	}
	if err != nil {
		return prep.ClaimName, v.unprepareError(prep, isPrepared, err)
	}
	klog.V(5).Infof("Freeing devices from claim %v", uid)
	return prep.ClaimName, cerr
}

// release revokes the lend of a companion claim (companion), has the engine
// release the grants of the preparation and removes it; after a failure an
// UNPREPARING preparation stays for kubelet's retry.
func (p *Plugin) release(ctx context.Context, prep *state.Preparation, companion bool) error {
	uid := prep.UID
	err := p.revokeLends(ctx, prep, companion)
	if err == nil {
		err = p.engine.ReleaseGrants(ctx, grantRefs(p.records(), prep), engine.ReleaseUnprepare)
	}
	if err == nil {
		err = p.commit(ctx, func(doc *store.Document) error { return remove(doc, p.rules.Name, uid, state.TriggerUnprepare) })
	}
	if err == nil {
		p.mu.Lock()
		delete(p.unrestored, uid)
		p.mu.Unlock()
		return nil
	}
	if cur := p.preparation(uid); cur != nil && cur.State == state.PreparationUnpreparing {
		if serr := stays(cur, state.TriggerUnprepare); serr != nil {
			klog.Errorf("%s: claim %s: %v", p.rules.Name, prep.ClaimName, serr)
		}
	}
	return err
}

// revokeLends revokes the NUMA nodes that the grants of a companion claim
// lend (companion), but those of a claim of another boot.
func (p *Plugin) revokeLends(ctx context.Context, prep *state.Preparation, companion bool) error {
	if !companion || prep.State == state.PreparationStale {
		return nil
	}
	lend, err := lendOf(p.st.Snapshot(), prep)
	if err != nil {
		return err
	}
	return p.lender.Revoke(ctx, lend, prep.ClaimName)
}

// generation returns the generation of the document of the store: it
// grows with every commit that changes the records.
func (p *Plugin) generation() uint64 {
	return p.st.Snapshot().Generation
}

// republish asks the publisher for a rescan (Trigger, not periodic) when
// the records changed since the generation gen; nothing without a
// publisher.
func (p *Plugin) republish(ctx context.Context, gen uint64) {
	if p.publisher != nil && p.generation() != gen {
		p.publisher.Trigger(ctx, false)
	}
}

// addInflight adds n to the counts of the serials of reqs.
func (p *Plugin) addInflight(reqs []engine.GrantRequest, n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, req := range reqs {
		serial := uint64(req.Serial)
		if p.inflight[serial] += n; p.inflight[serial] <= 0 {
			delete(p.inflight, serial)
		}
	}
}

// Serials returns the serials of the memdevs of the grants of the driver's
// source and of the Prepares in progress; nil for a nil plugin.
func (p *Plugin) Serials() map[uint64]bool {
	if p == nil {
		return nil
	}
	r := p.records()
	out := map[uint64]bool{}
	for i := range r.Grants {
		if g := &r.Grants[i]; g.Asked.Source == p.rules.Source {
			out[uint64(g.Serial)] = true
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for serial := range p.inflight {
		out[serial] = true
	}
	return out
}

// Result returns the PrepareResult of a prepared claim, and false if the
// claim is not prepared.
func (p *Plugin) Result(uid string) (kubeletplugin.PrepareResult, bool) {
	prep := p.preparation(uid)
	if prep == nil || !prep.Prepared() {
		return kubeletplugin.PrepareResult{}, false
	}
	return prepareResult(prep, p.rules.CDIKind), true
}

// ClaimInfo returns a prepared claim with its devices, nil if the claim is
// not prepared.
func (p *Plugin) ClaimInfo(uid string) *ClaimInfo {
	if p == nil {
		return nil
	}
	prep := p.preparation(uid)
	if prep == nil || !prep.Prepared() {
		return nil
	}
	info, err := claimInfoOf(p.st.Snapshot(), prep, p.st.ResultOptions())
	if err != nil {
		klog.Errorf("%s: claim %s: %v", p.rules.Name, prep.ClaimName, err)
		return nil
	}
	return info
}

// PreparedResult returns the claim name and the prepared device of the
// allocation result n of a prepared claim, and false if there is none.
func (p *Plugin) PreparedResult(uid string, n int) (string, state.DeviceInfo, bool) {
	info := p.ClaimInfo(uid)
	if info == nil {
		return "", state.DeviceInfo{}, false
	}
	for _, d := range info.Devices {
		if d.Result == n {
			return info.ClaimName, d, true
		}
	}
	return "", state.DeviceInfo{}, false
}

// PoolDevices returns the devices of a preparation of the claim uid in any
// state, nil without a record.
func (p *Plugin) PoolDevices(uid string) []store.PoolDevice {
	prep := p.preparation(uid)
	if prep == nil {
		return nil
	}
	devs, err := poolDevicesOf(p.st.Snapshot(), prep, p.st.ResultOptions())
	if err != nil {
		klog.Errorf("%s: claim %s: %v", p.rules.Name, prep.ClaimName, err)
	}
	return devs
}

// ClaimResults returns the devices of a prepared claim of the pool driver
// (PoolDevices); nil for a nil plugin and a claim that is not prepared.
func (p *Plugin) ClaimResults(uid string) []store.PoolDevice {
	if p == nil {
		return nil
	}
	if prep := p.preparation(uid); prep == nil || !prep.Prepared() {
		return nil
	}
	return p.PoolDevices(uid)
}

// Recovered logs what the recovery of the engine (rec, nil for a LOST
// store) left of the driver's claims at a start: the memdevs of prepared
// claims that are gone, the count of the prepared claims (pool driver), the
// claims without CDI devices because a node mount did not mount again.
func (p *Plugin) Recovered(rec *engine.Recovered, loadedFrom string) {
	if p == nil || rec == nil {
		return
	}
	r := p.records()
	p.rules.voice.loaded(r, loadedFrom)
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Driver != p.rules.Name || prep.State != state.PreparationUnrestored {
			continue
		}
		mount, found, why := unrestoredOf(r, prep, rec)
		if why = p.rules.voice.unrestoredWhy(why); why != nil {
			p.unrestored[prep.UID] = why
		}
		if prep.Lease == "" {
			p.rules.voice.unrestored(prep, found, mount, why)
		}
	}
}

// unrestoredOf returns the node mount of the first REALISED_UNRESTORED grant
// of a preparation, whether it has one, and why the recovery rec did not
// mount it again (nil if it does not say).
func unrestoredOf(r *state.Records, prep *state.Preparation, rec *engine.Recovered) (string, bool, error) {
	var why error
	mount, found := "", false
	for _, res := range prep.Results {
		g := grantOf(r, &res)
		if g == nil || g.State != state.GrantUnrestored {
			continue
		}
		if !found {
			mount, found = unrestoredMount(r, g), true
		}
		if why == nil {
			why = rec.Why[g.Ref]
		}
	}
	return mount, found, why
}

// logLoaded logs the prepared claims of the driver name that the records r
// loaded from have, and the devices of them whose memdev is gone (GONE
// after the recovery).
func logLoaded(r *state.Records, name, from string) {
	n := 0
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Driver != name || !prep.Prepared() {
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
					name, prep.ClaimName, prep.UID, uint64(g.Serial), res.Device)
			}
		}
	}
	klog.Infof("%s: loaded %d prepared claims from %s", name, n, from)
}

// writeCDI writes the CDI spec of the prepared claims of the driver and of
// the claim pending whose Prepare is finishing ("": none), or removes it
// when there are none; nothing without a CDI cache.
func (p *Plugin) writeCDI(pending string) error {
	if p.cdi == nil {
		return nil
	}
	p.cdiMu.Lock()
	defer p.cdiMu.Unlock()
	spec, err := buildCDISpec(p.st.Snapshot(), p.rules.Name, p.rules.CDIKind, p.st.ResultOptions(), pending, p.rules.CDIUnpreparing)
	if err != nil {
		return err
	}
	return writeCDISpec(p.cdi, spec, p.rules.CDISpecName, p.rules.voice)
}

// WriteCDI writes the CDI spec of the prepared claims of the driver, or
// removes it when there are none.
func (p *Plugin) WriteCDI() error {
	return p.writeCDI("")
}

// SetCDI sets the CDI cache that the spec of the driver is written with;
// nothing for a nil plugin.
func (p *Plugin) SetCDI(cdi *cdiapi.Cache) {
	if p == nil {
		return
	}
	p.cdiMu.Lock()
	defer p.cdiMu.Unlock()
	p.cdi = cdi
}

// HandleError is called by the kubelet plugin helper on asynchronous
// errors.
func (p *Plugin) HandleError(ctx context.Context, err error, message string) {
	if errors.Is(err, kubeletplugin.ErrRecoverable) {
		klog.FromContext(ctx).Error(err, "DRAPlugin encountered an error.", "driver", p.rules.Name)
	} else {
		klog.FromContext(ctx).Error(err, "Unrecoverable error.", "driver", p.rules.Name)
	}
	runtime.HandleErrorWithContext(ctx, err, message)
}

// WatchHealthStatus declines kubelet's health stream: the driver does not
// report per-device health.
func (p *Plugin) WatchHealthStatus(ctx context.Context, reports chan<- kubeletplugin.DeviceHealthReport) error {
	return kubeletplugin.ErrHealthNotSupported
}

// claimLocks serializes the work on each claim.
type claimLocks struct {
	// mu guards claims: a leaf lock.
	mu     sync.Mutex
	claims map[string]*claimLock
}

// claimLock is the lock of one claim UID.
type claimLock struct {
	sync.Mutex
	users int
}

// lock locks the claim UID and returns the function that unlocks it.
func (l *claimLocks) lock(uid string) func() {
	l.mu.Lock()
	if l.claims == nil {
		l.claims = map[string]*claimLock{}
	}
	c := l.claims[uid]
	if c == nil {
		c = &claimLock{}
		l.claims[uid] = c
	}
	c.users++
	l.mu.Unlock()
	c.Lock()
	return func() {
		c.Unlock()
		l.mu.Lock()
		if c.users--; c.users == 0 {
			delete(l.claims, uid)
		}
		l.mu.Unlock()
	}
}

// Unrestored returns the claims of the driver without CDI devices since the
// start, with why: those that are PREPARED_UNRESTORED still (the Prepare
// again of another claim of their node mount may have restored them).
func (p *Plugin) Unrestored() map[string]error {
	r := p.records()
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]error{}
	for uid, why := range p.unrestored {
		if prep := r.Preparation(p.rules.Name, uid); prep != nil && prep.State == state.PreparationUnrestored {
			out[uid] = why
		}
	}
	return out
}
