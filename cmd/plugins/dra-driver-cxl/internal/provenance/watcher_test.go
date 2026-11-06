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

package provenance

import (
	"context"
	"errors"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// TestPoolSlicesSerials pins Serials: only the slices of the pool driver
// count, unqualified or qualified serial attributes, invalid ones skipped;
// another pool driver name; a failed list keeps the serials of the last
// one, known and failing; a nil watcher knows that there are none.
func TestPoolSlicesSerials(t *testing.T) {
	client := fake.NewClientset(
		slice("pool", device.PoolDriverName, serialAttr("serial", "0xC1EE0001"), serialAttr("serial", "bogus"), nil),
		slice("other", "other.example.com", serialAttr("other.example.com/serial", "3238060770")),
		slice("node1", device.DriverName, serialAttr("serial", "0xc100e2e1")),
	)
	list, claims := ClientLists(client, "")
	w := New(Options{List: list, Claims: claims, NodeName: testNode})
	ctx := context.Background()
	serials, known := w.Serials(ctx)
	if !known || w.Failing() || !maps.Equal(serials, map[uint64]bool{0xc1ee0001: true}) {
		t.Fatalf("serials %v known %v failing %v", serials, known, w.Failing())
	}
	// another pool driver name
	list, claims = ClientLists(client, "other.example.com")
	other := New(Options{List: list, Claims: claims, Driver: "other.example.com", NodeName: testNode})
	if serials, _ := other.Serials(ctx); !maps.Equal(serials, map[uint64]bool{3238060770: true}) {
		t.Fatalf("serials of other.example.com %v", serials)
	}

	// an API failure keeps the serials of the last list
	logs := captureKlog(t)
	client.PrependReactor("list", "resourceslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	serials, known = w.Serials(ctx)
	if !known || !w.Failing() || !serials[0xc1ee0001] {
		t.Fatalf("after a failed list: serials %v known %v failing %v", serials, known, w.Failing())
	}
	wantLogLine(t, logs(), "listing the ResourceSlices of pool controllers: apiserver unavailable; using the serials of the last list")

	var none *Watcher
	if serials, known := none.Serials(ctx); serials != nil || !known || none.Failing() || none.Holding() {
		t.Fatalf("nil watcher: serials %v known %v", serials, known)
	}
	none.NotePrepared(map[uint64]bool{1: true})
	if pool, held := none.Gate(ctx, &nricxl.Devices{}, map[uint64]bool{1: true}, nil); !pool[1] || held != nil {
		t.Fatalf("nil watcher: pool %v held %v", pool, held)
	}
}

// TestPoolSlicesFirstListFails pins the watcher before the first
// successful list: not known, failing, only the remembered pool serials;
// a new memdev is held without expiry; after a list it is known.
func TestPoolSlicesFirstListFails(t *testing.T) {
	logs := captureKlog(t)
	e := newWatchEnv(t)
	e.publish("0xc1ee0001")
	fail := true
	e.client.PrependReactor("list", "resourceslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		if fail {
			return true, nil, errors.New("apiserver unavailable")
		}
		return false, nil, nil
	})
	serials, known := e.w.Serials(t.Context())
	if known || !e.w.Failing() || len(serials) != 0 {
		t.Fatalf("serials %v known %v failing %v before the first successful list", serials, known, e.w.Failing())
	}
	wantLogLine(t, logs(), "listing the ResourceSlices of pool controllers: apiserver unavailable; no local memory device is published "+
		"until a list succeeds")
	e.plug(localSerial)
	e.wantHeld("never listed", localSerial)
	wantLogLine(t, logs(), compat.LogPoolSerialsHoldingBackNewMemdev+" mem0 (serial 0xc100e2e1): it may be a pool device: the ResourceSlices "+
		"of pool controllers were never listed")
	e.advance(2 * HoldBack)
	e.wantHeld("never listed, later", localSerial)
	fail = false
	serials, known = e.w.Serials(t.Context())
	if !known || e.w.Failing() || !maps.Equal(serials, map[uint64]bool{0xc1ee0001: true}) {
		t.Fatalf("serials %v known %v failing %v after the first successful list", serials, known, e.w.Failing())
	}
}

// TestHeldUntilPoolBack pins a new memdev held while a remembered pool has
// no slices: UNKNOWN to HELD, HELD again at the next scan with its hold
// time kept, and LOCAL when the pool is back without it.
func TestHeldUntilPoolBack(t *testing.T) {
	logs := captureKlog(t)
	e := newWatchEnv(t)
	e.publish("0xc1ee2001")
	e.wantHeld("pool-c listed")
	e.publish()
	e.plug(otherLocalSerial)
	e.wantHeld("pool-c missing", otherLocalSerial)
	wantLogLine(t, logs(), compat.LogPoolSerialsHoldingBackNewMemdev+" mem0 (serial 0xa1): it may be a pool device: pools without "+
		"ResourceSlices: "+poolC)
	since := e.held(otherLocalSerial)
	e.advance(time.Minute)
	e.wantHeld("a minute later", otherLocalSerial)
	if got := e.held(otherLocalSerial); !got.Equal(since) {
		t.Fatalf("held since %v, expected %v", got, since)
	}
	if n := countLogLines(logs(), compat.LogPoolSerialsHoldingBackNewMemdev+" mem0"); n != 1 {
		t.Fatalf("%d lines of the hold, expected 1", n)
	}
	e.publish("0xc1ee2001")
	e.wantHeld("pool-c back")
	e.wantState(otherLocalSerial, state.ProvenanceLocal)
	wantLogLine(t, logs(), "pool serials: publishing memdev mem0 (serial 0xa1) as a local memory device: no pool is missing now")
	wantLogLine(t, logs(), "pool serials: memdev mem0 (serial 0xa1) is a local memory device")
	if r := e.record(otherLocalSerial); r == nil || r.State != state.ProvenanceLocal || r.Pool != "" || !r.LastSeen.Equal(e.now()) {
		t.Fatalf("record %+v", r)
	}
}

// held returns when the memdev of the serial was first held, failing the
// test if it is not held.
func (e *watchEnv) held(serial uint64) time.Time {
	e.t.Helper()
	e.w.mu.Lock()
	defer e.w.mu.Unlock()
	en := e.w.entries[serial]
	if en == nil || !en.held() || en.rec.HeldSince.IsZero() {
		e.t.Fatalf("serial %#x is not held: %+v", serial, en)
	}
	return en.rec.HeldSince
}

// TestHeldGone pins a held memdev that is detached before its hold ended:
// its hold is forgotten, nothing is committed for it.
func TestHeldGone(t *testing.T) {
	e := newWatchEnv(t)
	e.publish("0xc1ee2001")
	e.wantHeld("pool-c listed")
	e.publish()
	e.plug(otherLocalSerial)
	e.wantHeld("held", otherLocalSerial)
	e.unplug(otherLocalSerial)
	e.wantHeld("detached")
	e.wantState(otherLocalSerial, state.ProvenanceUnknown)
	if e.w.Holding() || e.record(otherLocalSerial) != nil {
		t.Fatal("the hold of a detached memdev is kept")
	}
}

// TestHeldBecomesPool pins a held memdev that the returning pool lists: it
// is POOL, durably, with the pool, and no longer held.
func TestHeldBecomesPool(t *testing.T) {
	e := newWatchEnv(t)
	e.publish("0xc1ee2001")
	e.wantHeld("pool-c listed")
	e.publish()
	e.plug(sharedPoolSerial)
	e.wantHeld("held", sharedPoolSerial)
	e.publish("0xc1ee2001", "0xc1ae2001")
	_, _ = e.w.Serials(t.Context())
	if r := e.st.Snapshot().ProvenanceOf(sharedPoolSerial); r == nil || r.State != state.ProvenancePool || r.Pool != poolC {
		t.Fatalf("record %+v", r)
	}
	e.wantHeld("listed")
	e.w.mu.Lock()
	rec := e.w.entries[sharedPoolSerial].rec
	e.w.mu.Unlock()
	if rec.State != state.ProvenancePool || !rec.HeldSince.IsZero() || rec.HeldReason != "" {
		t.Fatalf("entry %+v", rec)
	}
}

// TestLocalBecomesPool pins a LOCAL memdev that a pool slice lists later,
// and a serial that the pool driver prepares: both POOL with their line,
// and POOL stays POOL when it is seen again.
func TestLocalBecomesPool(t *testing.T) {
	logs := captureKlog(t)
	e := newWatchEnv(t)
	e.plug(localSerial)
	e.plug(otherLocalSerial)
	e.wantHeld("local")
	e.wantState(localSerial, state.ProvenanceLocal)
	e.publish("0xc100e2e1")
	e.wantHeld("listed by pool-c")
	e.wantState(localSerial, state.ProvenancePool)
	wantLogLine(t, logs(), "pool serials: memdev serial 0xc100e2e1 is a pool device now (in a ResourceSlice of "+poolC+")")
	if r := e.record(localSerial); r == nil || r.State != state.ProvenancePool || r.Pool != poolC {
		t.Fatalf("record %+v", r)
	}
	e.w.NotePrepared(map[uint64]bool{otherLocalSerial: true, 0xa2: true})
	wantLogLine(t, logs(), "pool serials: memdev serial 0xa1 is a pool device now (prepared by the pool driver)")
	e.wantState(otherLocalSerial, state.ProvenancePool)
	e.wantState(0xa2, state.ProvenancePool)
	if r := e.st.Snapshot().ProvenanceOf(0xa2); r == nil || r.State != state.ProvenancePool || r.Pool != "" {
		t.Fatalf("record of a prepared serial %+v", r)
	}
	// seen again
	e.advance(time.Minute)
	e.wantHeld("seen again")
	e.wantState(localSerial, state.ProvenancePool)
	e.w.mu.Lock()
	seen := e.w.entries[localSerial].rec.LastSeen
	e.w.mu.Unlock()
	if !seen.Equal(e.now()) {
		t.Fatalf("last seen %v, expected %v", seen, e.now())
	}
	e.w.NotePrepared(nil)
	if e.w.prepared != nil {
		t.Fatalf("prepared %v", e.w.prepared)
	}
}

// TestAbsenceExpires pins the observed absence: POOL and LOCAL serials are
// forgotten, and so is a pool, after Retention of observations at most
// ObservationGap apart; a longer gap starts the absence again.
func TestAbsenceExpires(t *testing.T) {
	logs := captureKlog(t)
	e := newWatchEnv(t)
	e.publish("0xc1ee2001")
	e.plug(localSerial)
	e.wantHeld("first scan")
	e.publish()
	e.unplug(localSerial)
	// a day without observations, then one: the absence starts there
	e.advance(Retention + time.Hour)
	e.wantHeld("a day later")
	e.wantState(0xc1ee2001, state.ProvenancePool)
	e.wantState(localSerial, state.ProvenanceLocal)
	// observed, but with a gap
	e.advance(ObservationGap + time.Second)
	e.wantHeld("after a gap")
	e.idle(Retention - time.Minute)
	e.wantState(0xc1ee2001, state.ProvenancePool)
	e.wantState(localSerial, state.ProvenanceLocal)
	e.idle(2 * time.Minute)
	e.wantState(0xc1ee2001, state.ProvenanceUnknown)
	e.wantState(localSerial, state.ProvenanceUnknown)
	out := logs()
	wantLogLine(t, out, "pool serials: forgetting serial 0xc1ee2001 (pool true, observed absent since ")
	wantLogLine(t, out, "pool serials: forgetting serial 0xc100e2e1 (pool false, observed absent since ")
	wantLogLine(t, out, "pool serials: forgetting pool "+poolC+" (observed without ResourceSlices since ")
	recs, pools := e.records()
	if len(recs) != 0 || len(pools) != 0 {
		t.Fatalf("records %+v, pools %+v", recs, pools)
	}
}

// TestClaimEvidence pins the pool claims of the node: the serial of an
// attached one is POOL with its pool, an attaching one holds new memdevs
// without expiry, failed attaches and claims of other nodes do not count,
// and claims that cannot be listed hold new memdevs for HoldBack.
func TestClaimEvidence(t *testing.T) {
	logs := captureKlog(t)
	e := newWatchEnv(t)
	e.claim("attached", testNode, "c-shared0", "0xc1ae2001")
	e.claim("failed", testNode, "c-pooled1", "failed")
	e.claim("elsewhere", "node2", "c-pooled2", "")
	e.plug(localSerial)
	e.plug(sharedPoolSerial)
	e.wantHeld("first start")
	e.wantState(localSerial, state.ProvenanceLocal)
	if r := e.record(sharedPoolSerial); r == nil || r.State != state.ProvenancePool || r.Pool != poolC {
		t.Fatalf("record %+v", r)
	}
	e.claim("attaching", testNode, "c-pooled0", "")
	e.plug(otherLocalSerial)
	e.wantHeld("attach in flight", otherLocalSerial)
	wantLogLine(t, logs(), compat.LogPoolSerialsHoldingBackNewMemdev+" mem2 (serial 0xa1): it may be a pool device: pool claims of the "+
		"node are not attached yet: "+testNS+"/attaching")
	e.advance(2 * HoldBack)
	e.wantHeld("attach in flight, later", otherLocalSerial)
	e.claim("attaching", testNode, "c-pooled0", "0xc1ee2001")
	e.wantHeld("attached")
	e.wantState(otherLocalSerial, state.ProvenanceLocal)

	// the claims cannot be listed
	e.client.PrependReactor("list", "resourceclaims", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	e.plug(0xa2)
	e.wantHeld("claims not listable", 0xa2)
	out := logs()
	wantLogLine(t, out, "pool serials: listing the pool claims of the node: apiserver unavailable")
	wantLogLine(t, out, compat.LogPoolSerialsHoldingBackNewMemdev+" mem3 (serial 0xa2): it may be a pool device: the pool claims of the "+
		"node cannot be listed")
	e.advance(HoldBack)
	e.wantHeld("claims not listable, held for long enough")
	e.wantState(0xa2, state.ProvenanceLocal)
	// no new memdev: the claims are not listed
	e.wantHeld("nothing new")
}

// TestPoolDeviceUsedByLocalClaims pins the error, once, about a pool
// device that local claims use: it is a pool serial of the gate.
func TestPoolDeviceUsedByLocalClaims(t *testing.T) {
	logs := captureKlog(t)
	e := newWatchEnv(t)
	e.publish("0xc100e2e1")
	e.plug(localSerial)
	serials, _ := e.w.Serials(t.Context())
	local := map[uint64][]string{localSerial: {"u1"}}
	for range 2 {
		pool, held := e.w.Gate(t.Context(), e.devices(), serials, local)
		if !pool[localSerial] || len(held) != 0 {
			t.Fatalf("pool %v held %v", pool, held)
		}
	}
	const text = "pool serials: memdev mem0 (serial 0xc100e2e1) is a pool device, but local claims use it: it is no longer " +
		"published, and no local claim is prepared on it; release the local claims ([u1]) and check its memory"
	if n := countLogLines(logs(), text); n != 1 {
		t.Fatalf("%d lines %q:\n%s", n, text, logs())
	}
	// a memdev that local claims use is local, also while a pool is missing
	e.publish()
	e.plug(otherLocalSerial)
	_, held := e.w.Gate(t.Context(), e.devices(), nil, map[uint64][]string{otherLocalSerial: {"u2"}})
	if len(held) != 0 {
		t.Fatalf("held %v", held)
	}
	e.wantState(otherLocalSerial, state.ProvenanceLocal)
}

// TestCheckLocalRefusals pins the two refusals of CheckLocal, with a fresh
// list: a pool device (of its pool, if known) and a held memdev; a local
// memdev and a nil watcher are accepted.
func TestCheckLocalRefusals(t *testing.T) {
	e := newWatchEnv(t)
	ctx := t.Context()
	e.publish("0xc1ee2001")
	e.plug(localSerial)
	e.wantHeld("local")
	noErr(t, e.w.CheckLocal(ctx, localSerial))
	// pool-c lists it now, before any scan
	e.publish("0xc1ee2001", "0xc100e2e1")
	wantErr(t, e.w.CheckLocal(ctx, localSerial),
		"memory device serial 0xc100e2e1 is a pool device of "+poolC+": it is not used as a local memory device")
	e.publish()
	wantErr(t, e.w.CheckLocal(ctx, localSerial),
		"memory device serial 0xc100e2e1 is a pool device of "+poolC+": it is not used as a local memory device")
	// prepared by the pool driver: no pool
	e.w.NotePrepared(map[uint64]bool{0xa2: true})
	wantErr(t, e.w.CheckLocal(ctx, 0xa2), "memory device serial 0xa2 is a pool device: it is not used as a local memory device")
	e.plug(otherLocalSerial)
	e.wantHeld("held", otherLocalSerial)
	wantErr(t, e.w.CheckLocal(ctx, otherLocalSerial),
		"memory device serial 0xa1 is held back as a possible pool device: it is not used as a local memory device yet")
	if err := (*Watcher)(nil).CheckLocal(ctx, localSerial); err != nil {
		t.Fatal(err)
	}
	// not listed by a watcher without the records
	list, claims := ClientLists(e.client, "")
	fresh := New(Options{List: list, Claims: claims, NodeName: testNode})
	noErr(t, fresh.CheckLocal(ctx, localSerial))
}

// TestWatch pins the ticks of Watch: a rescan (not periodic) at every
// ListRetry while the list fails or a memdev is held, none while neither
// and the node was scanned, a periodic one after Poll without a scan, and
// the end with ctx.
func TestWatch(t *testing.T) {
	oldRetry, oldPoll := ListRetry, Poll
	t.Cleanup(func() { ListRetry, Poll = oldRetry, oldPoll })
	ListRetry = 5 * time.Millisecond

	var failing atomic.Bool
	listErr := errors.New("apiserver unavailable")
	var holding atomic.Bool
	w := New(Options{
		List: func(context.Context) ([]resourcev1.ResourceSlice, error) {
			if failing.Load() {
				return nil, listErr
			}
			return nil, nil
		},
		Claims: func(context.Context) ([]resourcev1.ResourceClaim, error) {
			if holding.Load() {
				return []resourcev1.ResourceClaim{*poolClaim("attaching", testNode, "c-pooled0", "")}, nil
			}
			return nil, nil
		},
		NodeName: testNode,
	})
	ctx := t.Context()
	var mu sync.Mutex
	var calls []bool
	last := time.Now()
	scan := func() {
		serials, _ := w.Serials(ctx)
		w.Gate(ctx, &nricxl.Devices{MemoryDevices: []*nricxl.MemoryDevice{{Name: "mem0", Serial: otherLocalSerial}}}, serials, nil)
	}
	rescan := func(_ context.Context, periodic bool) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, periodic)
	}
	lastScan := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(calls)
	}
	// watch runs Watch until it rescanned twice (want: periodic), or for
	// 20 ticks if it must not rescan (no want).
	watch := func(what string, want ...bool) {
		t.Helper()
		mu.Lock()
		calls = nil
		mu.Unlock()
		ctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); w.Watch(ctx, rescan, lastScan) }()
		if len(want) == 0 {
			time.Sleep(20 * ListRetry)
		}
		for end := time.Now().Add(5 * time.Second); len(want) > 0 && count() < 2 && time.Now().Before(end); {
			time.Sleep(time.Millisecond)
		}
		cancel()
		<-done
		mu.Lock()
		defer mu.Unlock()
		if len(want) == 0 && len(calls) != 0 {
			t.Fatalf("%s: rescans %v, expected none", what, calls)
		}
		if len(want) > 0 && len(calls) < 2 {
			t.Fatalf("%s: rescans %v, expected one at every tick", what, calls)
		}
		for _, periodic := range calls {
			if periodic != want[0] {
				t.Fatalf("%s: rescans %v, expected periodic %v", what, calls, want[0])
			}
		}
	}

	// the list fails
	Poll = time.Hour
	failing.Store(true)
	scan()
	watch("list failing", false)
	// a memdev is held
	failing.Store(false)
	holding.Store(true)
	scan()
	if !w.Holding() {
		t.Fatal("not holding")
	}
	watch("held", false)
	// neither, scanned
	holding.Store(false)
	scan()
	if w.Holding() || w.Failing() {
		t.Fatal("holding or failing")
	}
	watch("idle")
	// not scanned for Poll
	Poll = 20 * time.Millisecond
	mu.Lock()
	last = time.Now().Add(-time.Second)
	mu.Unlock()
	watch("not scanned for Poll", true)
}
