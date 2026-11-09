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

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

const (
	poolDriver  = "cxl-pool.nri.io"
	localDriver = "cxl.nri.io"

	// serials of the memdevs of the tests: pool devices under host bridge
	// 12 (a, b), and 24 (c); a local memdev under host bridge 12 (l) and
	// one of persistent memory under 24 (p).
	serialA = 0xa1
	serialB = 0xb1
	serialC = 0xc1
	serialL = 0x11
	serialP = 0x91

	gib = uint64(1) << 30
	mib = uint64(1) << 20
)

// env is a node for the tests of the engine: a fake kernel, a store in a
// temporary directory and the engine over them, with the front-end's
// preparation records done by the test.
type env struct {
	t   *testing.T
	f   *fake.Fake
	dir string
	st  *store.Store
	e   *Engine
	// cutAt stops the process (panics with fake.ErrCut) after the n-th
	// commit from now, 0 for never.
	cutAt   int
	commits int
	// commitMu guards cutAt and commits against concurrent requests.
	commitMu sync.Mutex
	fenceMu  sync.Mutex
	fenced   []int
	// sources are the sources that the engine owns, nil for all.
	sources []state.Source
	// tune changes the options of every engine that the node starts, nil
	// for none.
	tune func(o *Options)
	// cutZero stops the process before ("before") or after ("after") the
	// next zeroing of a dax device, "" for never; onZero runs before the
	// next zeroing, nil for nothing; cutMu guards them.
	cutMu   sync.Mutex
	cutZero string
	onZero  func()
	// beforePrepared runs once in the next Prepare (prepare) between its
	// grants realised and its preparation PREPARED, nil for nothing.
	beforePrepared func()
}

// newEnv returns a node with the memdevs of specs plugged.
func newEnv(t *testing.T, specs ...fake.MemdevSpec) *env {
	t.Helper()
	v := &env{t: t, f: fake.New(t), dir: t.TempDir()}
	for _, s := range specs {
		v.f.Plug(s)
	}
	fs := filepath.Join(v.dir, "filesystems")
	if err := os.WriteFile(fs, []byte("nodev\tproc\nnodev\ttmpfs\n\text4\n\txfs\n\terofs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v.open()
	t.Cleanup(func() { _ = v.st.Close() })
	return v
}

// open opens the store and starts a new engine, as a start of the process
// does.
func (v *env) open() {
	v.t.Helper()
	st, err := store.Open(context.Background(), store.Options{Dir: filepath.Join(v.dir, "state"), BootID: v.f.BootID()})
	if err != nil {
		v.t.Fatal(err)
	}
	v.st = st
	v.startEngine()
}

// configure sets the options of the engines of the node (tune) and starts
// a new engine with them on the store, without a recovery.
func (v *env) configure(tune func(o *Options)) {
	v.t.Helper()
	v.tune = tune
	v.startEngine()
}

// startEngine starts a new engine on the store of the node.
func (v *env) startEngine() {
	v.t.Helper()
	k := v.f.Kernel()
	k.Sys = &cutSys{Sys: k.Sys, v: v}
	opts := Options{
		Kernel:  k,
		Store:   v.st,
		Drivers: map[state.Source]string{state.SourcePool: poolDriver, state.SourceLocal: localDriver},
		MountsDirs: map[state.Source]string{
			state.SourcePool:  filepath.Join(v.dir, poolDriver, "mounts"),
			state.SourceLocal: filepath.Join(v.dir, localDriver, "mounts"),
		},
		Sources:     v.sources,
		LeaseFsRoot: filepath.Join(v.dir, localDriver, "lease-fs"),
		FsTypes:     []string{config.FsTypeErofs, config.FsTypeExt4, config.FsTypeXfs},
		Filesystems: filepath.Join(v.dir, "filesystems"),
		Fence: func(_ context.Context, node int) {
			v.fenceMu.Lock()
			defer v.fenceMu.Unlock()
			if !slices.Contains(v.fenced, node) {
				v.fenced = append(v.fenced, node)
			}
		},
		Timeouts: Timeouts{Memdev: 2 * time.Second, ProbeGrace: 20 * time.Millisecond, RegionRetry: 10 * time.Millisecond,
			Settle: 5 * time.Second, LocalSettle: 5 * time.Second, Restore: time.Second, Holder: 300 * time.Millisecond,
			OfflineSettle: 20 * time.Millisecond, Offline: time.Second},
	}
	if v.tune != nil {
		v.tune(&opts)
	}
	e, err := New(opts)
	if err != nil {
		v.t.Fatal(err)
	}
	e.afterCommit = func() {
		v.commitMu.Lock()
		v.commits++
		cut := v.cutAt > 0 && v.commits == v.cutAt
		if cut {
			v.cutAt = 0
		}
		v.commitMu.Unlock()
		if cut {
			panic(fake.ErrCut)
		}
	}
	v.e = e
}

// cutSys is the system calls of the fake that stop the process at a
// zeroing (env.cutZero).
type cutSys struct {
	kernel.Sys
	v *env
}

// ZeroDax zeroes a dax device, the process stopped before or after it when
// the node says so.
func (s *cutSys) ZeroDax(ctx context.Context, major, minor int, size, align uint64) error {
	s.v.cutMu.Lock()
	when, on := s.v.cutZero, s.v.onZero
	s.v.cutZero, s.v.onZero = "", nil
	s.v.cutMu.Unlock()
	if on != nil {
		on()
	}
	if when == "before" {
		panic(fake.ErrCut)
	}
	err := s.Sys.ZeroDax(ctx, major, minor, size, align)
	if when == "after" {
		panic(fake.ErrCut)
	}
	return err
}

// cutZeroing makes the process stop before (after false) or after the next
// zeroing of a dax device.
func (v *env) cutZeroing(after bool) {
	v.cutMu.Lock()
	defer v.cutMu.Unlock()
	v.cutZero = map[bool]string{false: "before", true: "after"}[after]
}

// cutAfter makes the process stop (panic with fake.ErrCut) after the n-th
// commit of the engine from now.
func (v *env) cutAfter(n int) {
	v.cutAt = v.commits + n
}

// restart stops the process (the store closed) and starts it again: a new
// store and engine, and the first phase of the recovery.
func (v *env) restart() *Recovered {
	v.t.Helper()
	_ = v.st.Close()
	v.open()
	out, err := v.e.Recover(context.Background())
	if err != nil {
		v.t.Fatalf("recover: %v", err)
	}
	v.check("restarted")
	return out
}

// cut runs fn and reports whether the process was stopped in it.
func (v *env) cut(fn func()) (cut bool) {
	defer func() {
		if p := recover(); p != nil {
			if err, ok := p.(error); !ok || !errors.Is(err, fake.ErrCut) {
				panic(p)
			}
			cut = true
		}
	}()
	fn()
	return false
}

// records returns the records of the store.
func (v *env) records() *state.Records {
	return &v.st.Snapshot().Records
}

// check fails the test on a violation of the invariants of the records and
// the kernel now, and on a change of a kernel object that no row of its
// table has since the last check.
func (v *env) check(what string) {
	v.t.Helper()
	snap, err := v.f.Kernel().Observe(context.Background())
	if err != nil {
		v.t.Fatal(err)
	}
	v.fenceMu.Lock()
	fenced := slices.Clone(v.fenced)
	v.fenceMu.Unlock()
	if fenced == nil {
		fenced = []int{}
	}
	for _, viol := range v.e.Check(snap, v.sources, fenced) {
		v.t.Errorf("%s: %s", what, viol)
	}
	for _, line := range v.e.UnknownSeen() {
		v.t.Errorf("%s: %s%s", what, UnknownTransition, line)
	}
}

// grantResult returns a result of kind grant of the claim uid with index
// n.
func grantResult(uid string, n int) state.Result {
	return state.Result{Index: n, Kind: state.ResultGrant, Request: "mem", Grant: &state.GrantRef{Claim: uid, Result: n}}
}

// prepare does what a front-end does for a Prepare of a claim of the driver
// with the grants reqs, in a request of the engine: the preparation
// PREPARING with its results, the grants realised, then (after
// beforePrepared) PREPARED; on an error the preparation is removed, or KEPT
// when the rollback kept a grant. It returns the error of PrepareGrants.
func (v *env) prepare(driver, uid string, reqs ...GrantRequest) error {
	v.t.Helper()
	ctx, end := v.e.Request(context.Background())
	defer end()
	if err := v.st.Commit(ctx, store.Durable, func(doc *store.Document) error {
		p := doc.Preparation(driver, uid)
		if p == nil {
			doc.Preparations = append(doc.Preparations, state.Preparation{UID: uid, Driver: driver, ClaimName: "ns/" + uid,
				BootID: v.f.BootID(), State: state.PreparationUnknown})
			p = &doc.Preparations[len(doc.Preparations)-1]
		}
		if p.State == state.PreparationStale {
			// the grants of another boot are dropped with the Prepare again
			for _, res := range p.Results {
				if res.Grant != nil {
					ref := *res.Grant
					removeRecord(&doc.Grants, func(g *state.Grant) bool { return g.Ref == ref })
				}
			}
		}
		for i := range reqs {
			if p.Result(reqs[i].Ref.Result) == nil {
				p.Results = append(p.Results, grantResult(uid, reqs[i].Ref.Result))
			}
		}
		if p.State == state.PreparationPreparing {
			return state.Apply(&state.PreparationTable, &p.State, state.PreparationPreparing, state.TriggerPrepare)
		}
		return state.Apply(&state.PreparationTable, &p.State, state.PreparationPreparing, state.TriggerPrepare)
	}); err != nil {
		v.t.Fatal(err)
	}
	_, err := v.e.PrepareGrants(ctx, reqs)
	if before := v.beforePrepared; before != nil && err == nil {
		v.beforePrepared = nil
		before()
	}
	if cerr := v.st.Commit(ctx, store.Durable, func(doc *store.Document) error {
		p := doc.Preparation(driver, uid)
		if err == nil {
			return state.Apply(&state.PreparationTable, &p.State, state.PreparationPrepared, state.TriggerPrepare)
		}
		return failedPreparation(&doc.Records, p)
	}); cerr != nil {
		v.t.Fatal(cerr)
	}
	return err
}

// failedPreparation makes the preparation of a failed Prepare KEPT when a
// grant of it is left, else removes it.
func failedPreparation(r *state.Records, p *state.Preparation) error {
	left := false
	var results []state.Result
	for _, res := range p.Results {
		if res.Grant != nil && r.Grant(*res.Grant) == nil {
			continue
		}
		left = left || res.Grant != nil
		results = append(results, res)
	}
	p.Results = results
	if left {
		return state.Apply(&state.PreparationTable, &p.State, state.PreparationKept, state.TriggerPrepare)
	}
	if err := state.Apply(&state.PreparationTable, &p.State, state.PreparationUnknown, state.TriggerPrepare); err != nil {
		return err
	}
	uid, driver := p.UID, p.Driver
	removeRecord(&r.Preparations, func(x *state.Preparation) bool { return x.UID == uid && x.Driver == driver })
	return nil
}

// unprepare does what a front-end does for an Unprepare of a claim of the
// driver, in a request of the engine: UNPREPARING, the grants released, the
// preparation removed. It returns the error of ReleaseGrants (the
// preparation stays then).
func (v *env) unprepare(driver, uid string) error {
	v.t.Helper()
	ctx, end := v.e.Request(context.Background())
	defer end()
	p := v.records().Preparation(driver, uid)
	if p == nil {
		return nil
	}
	var refs []state.GrantRef
	for _, res := range p.Results {
		if res.Grant != nil {
			refs = append(refs, *res.Grant)
		}
	}
	if p.Prepared() && p.State != state.PreparationUnpreparing {
		if err := v.st.Commit(ctx, store.Durable, func(doc *store.Document) error {
			p := doc.Preparation(driver, uid)
			return state.Apply(&state.PreparationTable, &p.State, state.PreparationUnpreparing, state.TriggerUnprepare)
		}); err != nil {
			v.t.Fatal(err)
		}
	}
	if err := v.e.ReleaseGrants(ctx, refs, ReleaseUnprepare); err != nil {
		return err
	}
	if err := v.st.Commit(ctx, store.Durable, func(doc *store.Document) error {
		p := doc.Preparation(driver, uid)
		if p == nil {
			return nil
		}
		if err := state.Apply(&state.PreparationTable, &p.State, state.PreparationUnknown, state.TriggerUnprepare); err != nil {
			return err
		}
		removeRecord(&doc.Preparations, func(x *state.Preparation) bool { return x.UID == uid && x.Driver == driver })
		return nil
	}); err != nil {
		v.t.Fatal(err)
	}
	return nil
}

// mustPrepare prepares a claim and fails the test on an error.
func (v *env) mustPrepare(driver, uid string, reqs ...GrantRequest) {
	v.t.Helper()
	if err := v.prepare(driver, uid, reqs...); err != nil {
		v.t.Fatalf("prepare %s: %v", uid, err)
	}
	v.check("prepared " + uid)
}

// mustUnprepare unprepares a claim and fails the test on an error.
func (v *env) mustUnprepare(driver, uid string) {
	v.t.Helper()
	if err := v.unprepare(driver, uid); err != nil {
		v.t.Fatalf("unprepare %s: %v", uid, err)
	}
	v.check("unprepared " + uid)
}

// grant returns the record of the grant of result n of the claim uid,
// mount returns the record of the node mount that the grant n of the claim
// uid uses; the test fails if it has none.
func (v *env) mount(uid string, n int) *state.Mount {
	v.t.Helper()
	m := v.records().MountOf(v.grant(uid, n))
	if m == nil {
		v.t.Fatalf("grant %s/%d has no node mount", uid, n)
	}
	return m
}

// failing the test without one.
func (v *env) grant(uid string, n int) *state.Grant {
	v.t.Helper()
	g := v.records().Grant(state.GrantRef{Claim: uid, Result: n})
	if g == nil {
		v.t.Fatalf("no grant %s/%d", uid, n)
	}
	return g
}

// noRecords fails the test when the store has a memdev, region or grant
// record, or the kernel a region.
func (v *env) clean(what string) {
	v.t.Helper()
	r := v.records()
	if len(r.Memdevs)+len(r.Regions)+len(r.Grants) > 0 {
		v.t.Errorf("%s: records left: memdevs %+v regions %+v grants %+v", what, r.Memdevs, r.Regions, r.Grants)
	}
	snap, err := v.f.Kernel().Observe(context.Background())
	if err != nil {
		v.t.Fatal(err)
	}
	for _, ri := range snap.Regions {
		v.t.Errorf("%s: region %s (%s) left", what, ri.Name, ri.State)
	}
}

// poolReq returns the grant request of result n of the claim uid on a pool
// device.
func poolReq(uid string, n int, serial uint64, mode state.Mode, kind state.GrantKind) GrantRequest {
	return GrantRequest{
		Ref:    state.GrantRef{Claim: uid, Result: n},
		Serial: state.Serial(serial),
		Asked:  state.Asked{Source: state.SourcePool, Kind: kind, Mode: mode, Size: 256 * mib, Shared: kind == state.KindShared},
		Facts:  state.MemdevFacts{Shared: kind == state.KindShared, Persistent: kind == state.KindPersistent},
	}
}

// localReq returns the grant request of result n of the claim uid on a
// local memdev.
func localReq(uid string, n int, serial uint64, mode state.Mode, kind state.GrantKind, size uint64) GrantRequest {
	return GrantRequest{
		Ref:    state.GrantRef{Claim: uid, Result: n},
		Serial: state.Serial(serial),
		Asked:  state.Asked{Source: state.SourceLocal, Kind: kind, Mode: mode, Size: size, Shared: kind == state.KindShared},
		Facts:  state.MemdevFacts{Shared: kind == state.KindShared, Persistent: kind == state.KindPersistent},
	}
}

// fsReq returns the request of a grant of mode fs on a persistent device.
func fsReq(req GrantRequest, readOnly bool, access state.Access) GrantRequest {
	req.Asked.Mode, req.Asked.ReadOnly, req.Asked.Access = state.ModeFs, readOnly, access
	req.Asked.Path = "/mnt/data"
	req.SingleHost = true
	return req
}

// formatPmem makes the fsdax namespace of the persistent memdev with the
// serial (memdev memdev) and a filesystem of the type on it, as a writer
// on another host would, leaving no region.
func (v *env) formatPmem(memdev string, typ string) {
	v.t.Helper()
	k := v.f.Kernel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := k.RootDecoder(memdev, kernel.RegionPmem)
	if err != nil {
		v.t.Fatal(err)
	}
	region, err := k.CreateRegion(ctx, kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionPmem})
	if err != nil {
		v.t.Fatal(err)
	}
	nd, err := k.WaitNdRegion(ctx, region)
	if err != nil {
		v.t.Fatal(err)
	}
	ns, err := k.CreateFsdaxNamespace(ctx, nd, "")
	if err != nil {
		v.t.Fatal(err)
	}
	v.f.SetImage(ns.BlockDevice, fsImage(typ))
	if err := k.ReleaseRegion(ctx, region); err != nil {
		v.t.Fatal(err)
	}
}

// fsImage returns the head of a block device with the signature of a
// filesystem type.
func fsImage(typ string) []byte {
	img := make([]byte, kernel.FsProbeBytes)
	switch typ {
	case "erofs":
		binary.LittleEndian.PutUint32(img[1024:], 0xE0F5E1E2)
	case "ext4":
		binary.LittleEndian.PutUint16(img[1080:], 0xEF53)
		binary.LittleEndian.PutUint32(img[1024+0x60:], 0x2)
	case "xfs":
		copy(img, "XFSB")
	}
	return img
}

// errBusy is the error of a busy device.
var errBusy = syscall.EBUSY

// blockState returns the sysfs attribute of the state of memory block n.
func blockState(n int) string {
	return fmt.Sprintf("devices/system/memory/memory%d/state", n)
}

// storeDocument is the document of the store.
type storeDocument = store.Document

// mountInfo is a mount of the kernel.
type mountInfo = kernel.MountInfo
