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
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// Two Prepares of one claim serialize on its lock, the Prepare of another
// claim does not wait for them.
func TestClaimLock(t *testing.T) {
	e := lendEnv(t)
	_, hooks := e.lending()
	block := make(chan struct{})
	entered := make(chan string, 4)
	hooks.mu.Lock()
	hooks.block = map[string]chan struct{}{"cxl-lease-l1": block}
	hooks.entered = entered
	hooks.mu.Unlock()
	ctx := context.Background()
	prepare := func(c *resourcev1.ResourceClaim, out chan<- kubeletplugin.PrepareResult) {
		res, err := e.local.PrepareResourceClaims(ctx, []*resourcev1.ResourceClaim{c})
		if err != nil {
			out <- kubeletplugin.PrepareResult{Err: err}
			return
		}
		out <- res[c.UID]
	}
	first, second := make(chan kubeletplugin.PrepareResult, 1), make(chan kubeletplugin.PrepareResult, 1)
	go prepare(e.companionOf(e.local), first)
	if name := <-entered; name != "cxl-lease-l1" {
		t.Fatalf("entered %s", name)
	}
	go prepare(e.companionOf(e.local), second)
	// another claim of the driver meanwhile
	e.mustPrepare(e.local, localClaim("u2", device.DRAMDeviceName, 64*mib))
	select {
	case name := <-entered:
		t.Fatalf("the second Prepare of the claim entered the gate of %s while the first one is in it", name)
	case res := <-second:
		t.Fatalf("the second Prepare of the claim returned %+v while the first one runs", res)
	case <-time.After(100 * time.Millisecond):
	}
	close(block)
	a, b := <-first, <-second
	mustOK(t, a.Err)
	mustOK(t, b.Err)
	e.wantEvents("two Prepares of one claim", "lending l1 cxl-lease-l1", "lend pod-uid-1/app 2 l1", "prepared l1",
		"lending l1 cxl-lease-l1", "prepared l1")
	e.check("after the Prepares")
	e.mustUnprepare(e.local, "c1")
	e.mustUnprepare(e.local, "u2")
	e.wantClean()
}

// A Prepare waits for the first NRI Synchronize: an error of the wait
// fails every claim of the call, with a warning, before any device or
// record.
func TestWaitNRI(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()}, poolSpec(serialPoolX))
	errWait := errors.New("NRI has not synchronized")
	waited := 0
	wait := func(ctx context.Context) error {
		waited++
		if ctx == nil {
			return errors.New("no context")
		}
		return errWait
	}
	logs := klogCapture(t)
	for _, p := range []*Plugin{e.local, e.pool} {
		e.mark()
		p.SetWaitNRI(wait)
		claims := []*resourcev1.ResourceClaim{localClaim("u1", localDev, envBlockSize), localClaim("u2", device.DRAMDeviceName, 64*mib)}
		if p == e.pool {
			claims = []*resourcev1.ResourceClaim{poolClaim("u1", "pooled0", poolExclusiveData), poolClaim("u2", "pooled0", poolExclusiveData)}
		}
		res, err := p.PrepareResourceClaims(context.Background(), claims)
		mustOK(t, err)
		for _, c := range claims {
			if !errors.Is(res[c.UID].Err, errWait) || len(res[c.UID].Devices) != 0 {
				t.Fatalf("%s: claim %s: %+v", p.Name(), c.UID, res[c.UID])
			}
			e.wantState(p, string(c.UID), state.PreparationUnknown)
		}
		wantLogText(t, logs(), fmt.Sprintf("%s: preparing 2 claims: %v", p.Name(), errWait))
		e.wantNoCommands("a Prepare before NRI")
		p.SetWaitNRI(func(context.Context) error { return nil })
		e.mustPrepare(p, claims[0])
		p.SetWaitNRI(nil)
		e.mustUnprepare(p, "u1")
	}
	if waited != 2 {
		t.Fatalf("waited %d times", waited)
	}
	var none *Plugin
	none.SetWaitNRI(wait)
	none.Stop()
	none.Recovered(nil, "")
	e.wantClean()
}

// Prepares and Unprepares of cxl.nri.io neither scan nor publish: the
// table of the publisher and its generation stay as they are.
func TestPrepareDoesNotPublish(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec(), pmemSpec()})
	gen, scanned, devs := e.pub.Generation(), e.pub.LastScan(), e.pub.Devices()
	e.mustPrepare(e.local, localClaim("u1", localDev, envBlockSize))
	e.mustPrepare(e.local, localClaim("u2", pmemDev, -device.SharesUnlimited, cfgBlock))
	e.mustPrepare(e.local, localClaim("u3", device.DRAMDeviceName, 64*mib))
	e.mustUnprepare(e.local, "u1")
	e.mustUnprepare(e.local, "u2")
	e.mustUnprepare(e.local, "u3")
	if g := e.pub.Generation(); g != gen || !e.pub.LastScan().Equal(scanned) || len(e.pub.Devices()) != len(devs) {
		t.Fatalf("generation %d (was %d), last scan %v (was %v)", g, gen, e.pub.LastScan(), scanned)
	}
	e.rescan()
	if g := e.pub.Generation(); g != gen {
		t.Fatalf("a rescan after the claims changed the generation %d -> %d", gen, g)
	}
}

// HandleError logs the errors of the kubelet plugin helper as recoverable
// or not with the driver; the drivers report no device health.
func TestHandleErrorAndHealth(t *testing.T) {
	e := newDriverEnv(t, nil)
	logs := klogCapture(t)
	ctx := context.Background()
	e.pool.HandleError(ctx, fmt.Errorf("slice: %w", kubeletplugin.ErrRecoverable), "publishing")
	e.local.HandleError(ctx, errors.New("lost"), "registering")
	log := logs()
	wantLogText(t, log, `"DRAPlugin encountered an error." err="slice: recoverable error" driver="cxl-pool.nri.io"`)
	wantLogText(t, log, `"Unrecoverable error." err="lost" driver="cxl.nri.io"`)
	for _, p := range []*Plugin{e.local, e.pool} {
		if err := p.WatchHealthStatus(ctx, make(chan kubeletplugin.DeviceHealthReport)); !errors.Is(err, kubeletplugin.ErrHealthNotSupported) {
			t.Fatalf("%s: %v", p.Name(), err)
		}
	}
}

// New refuses a plugin without the store or the engine, one of rules that
// are not those of LocalRules or PoolRules, and one that publishes without
// the publisher; NewPublisher refuses a publisher without the store or the
// scan.
func TestNew(t *testing.T) {
	e := newDriverEnv(t, nil)
	if _, err := New(Options{Rules: PoolRules(device.PoolDriverName, "", ""), Store: e.st}); err == nil {
		t.Fatal("a plugin without the engine")
	}
	_, err := New(Options{Rules: SourceRules{Name: "zero.nri.io", Source: state.SourcePool}, Store: e.st, Engine: e.eng})
	wantErrText(t, err, "zero.nri.io: the rules have no validation or voice")
	_, err = New(Options{Rules: LocalRules(""), Store: e.st, Engine: e.eng})
	wantErrText(t, err, "cxl.nri.io: the plugin publishes and needs the publisher")
	for _, opts := range []PublishOptions{{Scan: pubNoScan}, {Store: e.st}} {
		_, err = NewPublisher(opts)
		wantErrText(t, err, "the publisher needs the state store and the scan of the devices")
	}
	p, err := New(Options{Rules: PoolRules("other.nri.io", "", ""), Store: e.st, Engine: e.eng})
	mustOK(t, err)
	if p.Name() != "other.nri.io" || p.Engine() != e.eng || p.devRoot != "/dev" || p.Records() == nil || p.Rules().Source != state.SourcePool {
		t.Fatalf("plugin %+v", p)
	}
}
