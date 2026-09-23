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

package leases

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// A companion that cannot be created fails the lease and releases it: the
// client gets Failed with the error; a claim created before the pod failed
// is deleted by the release.
func TestCompanionCreateFails(t *testing.T) {
	e := brokerEnv(t)
	var podFails atomic.Bool
	e.client.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if podFails.Load() {
			return true, nil, errors.New("quota exceeded")
		}
		return false, nil, nil
	})
	e.openClaim()
	e.start()
	// a claim of the name exists already
	_, err := e.client.ResourceV1().ResourceClaims(envNS).Create(context.Background(), companionClaim("000000a1"), metav1.CreateOptions{})
	mustOK(t, err)
	r, _ := e.call(api.Request{Op: api.OpRequest, Size: "64Mi"})
	if r.State != api.StateFailed || !strings.HasPrefix(r.Error, "creating companion claim demo/cxl-lease-000000a1: ") {
		t.Fatalf("response %+v", r)
	}
	e.waitState(r.Lease, state.LeaseNone)

	podFails.Store(true)
	r, _ = e.call(api.Request{Op: api.OpRequest, Size: "64Mi"})
	if r.State != api.StateFailed || r.Error != "creating companion pod demo/cxl-lease-000000a2: quota exceeded" || r.Lease != "000000a2" {
		t.Fatalf("response %+v", r)
	}
	e.waitState(r.Lease, state.LeaseNone)
	e.wantGone(CompanionName("000000a2"))
}

// A restart keeps a READY lease and its companion: kubelet prepares the
// prepared companion again, the lease stays READY with the same response;
// a lease whose companion's Prepare was cut after the gate (LENDING) is
// READY by kubelet's Prepare after the restart.
func TestRestartAnnounceAgain(t *testing.T) {
	e := newLeaseEnv(t, nil, fake.MemdevSpec{Serial: serialPoolX}, fake.MemdevSpec{Serial: 0xc1ee0002, HostBridge: 24})
	e.openClaim()
	e.start()
	claim, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Source: "pool", Size: "256Mi", Wait: "5s"}, "pooled0", poolExclusiveData)
	ready := r.resp
	// the second lease: its companion passes the gate, then the driver stops
	e.call(api.Request{Op: api.OpRequest, Source: "pool", Size: "256Mi", Wait: "0s"})
	second := e.waitClaim("cxl-lease-000000a2")
	_, err := e.b.OnLending("000000a2", second)
	mustOK(t, err)

	e.restart()
	e.ctrs.forget()
	e.start()
	if l := e.lease("000000a1"); l == nil || l.State != state.LeaseReady {
		t.Fatalf("READY lease after a restart %+v", l)
	}
	if l := e.lease("000000a2"); l == nil || l.State != state.LeaseLending {
		t.Fatalf("LENDING lease after a restart %+v", l)
	}
	mustOK(t, e.prepare(e.pool, allocatedPool(claim, "pooled0", poolExclusiveData)).Err)
	if l := e.lease("000000a1"); l == nil || l.State != state.LeaseReady {
		t.Fatalf("READY lease after the Prepare again %+v", l)
	}
	again, _ := e.call(api.Request{Op: api.OpEnv, Lease: "000000a1"})
	if !reflect.DeepEqual(again, ready) {
		t.Fatalf("response after the Prepare again\n%+v\nexpected\n%+v", again, ready)
	}
	data := strings.ReplaceAll(poolExclusiveData, "0xc1ee0001", "0xc1ee0002")
	mustOK(t, e.prepare(e.pool, allocatedPool(second, "pooled1", data)).Err)
	if l := e.lease("000000a2"); l == nil || l.State != state.LeaseReady || got(l).Serial != 0xc1ee0002 {
		t.Fatalf("cut lease after kubelet's Prepare %+v", l)
	}
	e.wantReleaseAll(2)
	e.wantNoRegions()
}

// A READY fs lease whose companion's node mount does not mount again at a
// start (its preparation PREPARED_UNRESTORED) fails at the start and is
// released in place: the list shows it Failed with why, its companion is
// deleted and unprepared, the lease removed.
func TestUnrestoredCompanionFails(t *testing.T) {
	e := newLeaseEnv(t, nil, fake.MemdevSpec{Serial: serialPoolP, Pmem: 512 << 20})
	dev := e.formatPmem(serialPoolP, "erofs")
	e.addSlices(persistentPoolSlice())
	e.openClaim()
	e.start()
	_, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Shared: true, Mode: "fs", Wait: "5s"}, "llm0", poolPmemData)
	if r.resp.State != api.StateReady {
		t.Fatalf("response %+v", r.resp)
	}
	var stay atomic.Bool
	stay.Store(true)
	for _, resource := range []string{"pods", "resourceclaims"} {
		e.client.PrependReactor("delete", resource, func(a k8stesting.Action) (bool, runtime.Object, error) {
			return stay.Load(), nil, nil
		})
	}
	e.b.Stop()
	_ = e.st.Close()
	mustOK(t, e.k.Kernel().Unmount(filepath.Join(e.poolDir, "mounts", "c1af0001-direct")))
	e.k.SetMountError(dev, syscall.EIO, "")
	e.boot()
	if p := e.st.Snapshot().Preparation(e.pool.Name(), "uid-cxl-lease-000000a1"); p == nil || p.State != state.PreparationUnrestored {
		t.Fatalf("companion %+v", p)
	}
	l := e.stored("000000a1")
	if l == nil || l.State != state.LeaseFailed || l.Error != "the device of companion claim demo/cxl-lease-000000a1 was not restored at the start of the driver" {
		t.Fatalf("lease %+v", l)
	}
	e.start()
	list, _ := e.call(api.Request{Op: api.OpList})
	if list.Leases == nil || len(*list.Leases) != 1 || (*list.Leases)[0].State != api.StateFailed || (*list.Leases)[0].Error != l.Error {
		t.Fatalf("list %+v", list)
	}
	e.waitStored("000000a1", func(l *state.Lease) bool { return l.ReleaseRequested && l.State == state.LeaseFailed })
	stay.Store(false)
	e.k.SetMountError(dev, nil, "")
	e.waitState("000000a1", state.LeaseNone)
	e.wantGone(CompanionName("000000a1"))
	e.wantNoRegions()
}

// A LENDING lease whose companion claim the start did not restore (a stop
// between the companion's PREPARED and OnPrepared) fails and is released in
// place as a READY one.
func TestUnrestoredLendingCompanionFails(t *testing.T) {
	e := newLeaseEnv(t, nil, fake.MemdevSpec{Serial: serialPoolP, Pmem: 512 << 20})
	dev := e.formatPmem(serialPoolP, "erofs")
	e.addSlices(persistentPoolSlice())
	e.openClaim()
	e.start()
	_, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Shared: true, Mode: "fs", Wait: "5s"}, "llm0", poolPmemData)
	if r.resp.State != api.StateReady {
		t.Fatalf("response %+v", r.resp)
	}
	var stay atomic.Bool
	stay.Store(true)
	for _, resource := range []string{"pods", "resourceclaims"} {
		e.client.PrependReactor("delete", resource, func(a k8stesting.Action) (bool, runtime.Object, error) {
			return stay.Load(), nil, nil
		})
	}
	e.b.Stop()
	mustOK(t, e.st.Commit(context.Background(), store.Durable, func(doc *store.Document) error {
		doc.Lease("000000a1").State = state.LeaseLending
		return nil
	}))
	_ = e.st.Close()
	mustOK(t, e.k.Kernel().Unmount(filepath.Join(e.poolDir, "mounts", "c1af0001-direct")))
	e.k.SetMountError(dev, syscall.EIO, "")
	e.boot()
	if p := e.st.Snapshot().Preparation(e.pool.Name(), "uid-cxl-lease-000000a1"); p == nil || p.State != state.PreparationUnrestored {
		t.Fatalf("companion %+v", p)
	}
	l := e.stored("000000a1")
	if l == nil || l.State != state.LeaseFailed || l.Error != "the device of companion claim demo/cxl-lease-000000a1 was not restored at the start of the driver" {
		t.Fatalf("lease %+v", l)
	}
	e.start()
	list, _ := e.call(api.Request{Op: api.OpList})
	if list.Leases == nil || len(*list.Leases) != 1 || (*list.Leases)[0].State != api.StateFailed || (*list.Leases)[0].Error != l.Error {
		t.Fatalf("list %+v", list)
	}
	e.waitStored("000000a1", func(l *state.Lease) bool { return l.ReleaseRequested && l.State == state.LeaseFailed })
	stay.Store(false)
	e.k.SetMountError(dev, nil, "")
	e.waitState("000000a1", state.LeaseNone)
	e.wantGone(CompanionName("000000a1"))
	e.wantNoRegions()
}

// waitStored waits until the stored lease satisfies cond.
func (e *leaseEnv) waitStored(id string, cond func(l *state.Lease) bool) {
	e.t.Helper()
	for i := 0; i < 1000; i++ {
		if l := e.stored(id); l != nil && cond(l) {
			return
		}
		e.sleep()
	}
	e.t.Fatalf("lease %s: %+v", id, e.stored(id))
}

// A lease claim whose socket does not start at a start is OPEN_NO_LISTENER;
// its Prepare again or the reconcile starts it.
func TestRelistenFails(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.b.Stop()
	_ = e.st.Close()
	dir := filepath.Dir(e.sock())
	mustOK(t, os.RemoveAll(dir))
	mustOK(t, os.WriteFile(dir, []byte("x"), 0o600))
	e.boot()
	if c := e.st.Snapshot().LeaseClaim(envLeaseClaim); c == nil || c.State != state.LeaseClaimOpenNoListener {
		t.Fatalf("lease claim %+v", c)
	}
	e.start()
	mustOK(t, os.Remove(dir))
	e.openClaim()
	if c := e.st.Snapshot().LeaseClaim(envLeaseClaim); c == nil || c.State != state.LeaseClaimOpen {
		t.Fatalf("lease claim %+v", c)
	}
	if resp, _ := e.call(api.Request{Op: api.OpList}); resp.Error != "" {
		t.Fatalf("list %+v", resp)
	}
	// a start whose listen fails again
	e.b.Stop()
	_ = e.st.Close()
	mustOK(t, os.RemoveAll(dir))
	mustOK(t, os.WriteFile(dir, []byte("x"), 0o600))
	e.boot()
	e.b.Stop()
	_ = e.st.Close()
	e.boot()
	if c := e.st.Snapshot().LeaseClaim(envLeaseClaim); c == nil || c.State != state.LeaseClaimOpenNoListener {
		t.Fatalf("lease claim %+v", c)
	}
	// the reconcile listens again once it can
	e.b.reconcile()
	if c := e.st.Snapshot().LeaseClaim(envLeaseClaim); c == nil || c.State != state.LeaseClaimOpenNoListener {
		t.Fatalf("lease claim after a failed listen of the reconcile %+v", c)
	}
	mustOK(t, os.Remove(dir))
	e.b.reconcile()
	if c := e.st.Snapshot().LeaseClaim(envLeaseClaim); c == nil || c.State != state.LeaseClaimOpen {
		t.Fatalf("lease claim after the reconcile %+v", c)
	}
	e.start()
	if resp, _ := e.call(api.Request{Op: api.OpList}); resp.Error != "" {
		t.Fatalf("list %+v", resp)
	}
}

// A lend that fails at the companion's Prepare through the pool driver: the
// Prepare fails and is rolled back, the lease fails (OnLendFailed) and is
// released; the client gets Failed with the lend error.
func TestPoolLendFailure(t *testing.T) {
	e := newLeaseEnv(t, nil, fake.MemdevSpec{Serial: serialPoolX})
	e.openClaim()
	e.start()
	e.ctrs.setLendErr(errors.New("container is memory-steered"))
	ch := e.async(api.Request{Op: api.OpRequest, Source: "pool", Size: "256Mi"})
	claim := e.waitClaim("cxl-lease-000000a1")
	wantErrText(t, e.prepare(e.pool, allocatedPool(claim, "pooled0", poolExclusiveData)).Err, "memory-steered")
	e.wantNoRegions()
	resp := <-ch
	if resp.State != api.StateFailed || resp.Error != "lease 000000a1: lending node 2 to demo/borrower/app: container is memory-steered" {
		t.Fatalf("lend failure response %+v", resp)
	}
	e.waitState("000000a1", state.LeaseNone)
	e.wantGone("cxl-lease-000000a1")
}

// The companion unprepared behind the broker (its pod deleted by someone):
// the driver tells the broker, the lease fails, the reconcile releases it.
func TestCompanionUnpreparedBehind(t *testing.T) {
	e := newLeaseEnv(t, nil, fake.MemdevSpec{Serial: serialPoolX})
	e.openClaim()
	e.start()
	_, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Source: "pool", Size: "256Mi", Wait: "5s"}, "pooled0", poolExclusiveData)
	if r.resp.State != api.StateReady {
		t.Fatalf("response %+v", r.resp)
	}
	mustOK(t, e.client.CoreV1().Pods(envNS).Delete(context.Background(), CompanionName("000000a1"), metav1.DeleteOptions{}))
	mustOK(t, e.unprepare(e.pool, "uid-"+CompanionName("000000a1")))
	if l := e.lease("000000a1"); l == nil || l.State != state.LeaseFailed || l.Error != "companion claim unprepared (companion pod deleted or evicted)" {
		t.Fatalf("lease %+v", l)
	}
	if got := e.ctrs.lentNodes(envPodUID, envCtr); len(got) != 0 {
		t.Fatalf("lent %v after the companion's Unprepare", got)
	}
	e.b.reconcile()
	e.waitState("000000a1", state.LeaseNone)
	_, err := e.client.ResourceV1().ResourceClaims(envNS).Get(context.Background(), CompanionName("000000a1"), metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("companion claim left: %v", err)
	}
	e.wantNoRegions()
}

// The lease device is published with --leases only; a claim on it is
// prepared by cxl.nri.io through the broker: its CDI devices claim-<uid>-0
// and lease-<uid>, its socket; its Unprepare closes the lease claim first.
func TestLeaseClaimPrepare(t *testing.T) {
	if devs := dra.BuildDevices(dra.PublishConfig{IgnoreDRAMNodes: true, PublishLeaseDevice: true}, &kernel.Snapshot{}, nil, nil, nil); devs["lease"] == nil {
		t.Fatalf("no lease device in %v", devs)
	}
	if devs := dra.BuildDevices(dra.PublishConfig{IgnoreDRAMNodes: true}, &kernel.Snapshot{}, nil, nil, nil); len(devs) != 0 {
		t.Fatalf("lease device published without --leases: %v", devs)
	}
	e := brokerEnv(t)
	e.start()
	r := e.prepare(e.local, leaseClaimObj())
	mustOK(t, r.Err)
	if len(r.Devices) != 1 || !slices.Equal(r.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl=claim-lc1-0", "nri.io/cxl=lease-lc1"}) {
		t.Fatalf("prepared %+v", r.Devices)
	}
	if info := e.local.ClaimInfo(envLeaseClaim); info == nil || info.Devices[0].DeviceType != device.DeviceTypeLease || info.Devices[0].Mode != "" {
		t.Fatalf("claim info %+v", info)
	}
	if _, err := os.Stat(e.sock()); err != nil {
		t.Fatalf("no lease socket: %v", err)
	}
	resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "64Mi", Wait: "0s"})
	mustOK(t, e.unprepare(e.local, envLeaseClaim))
	if _, err := os.Stat(e.sock()); !os.IsNotExist(err) || e.claim(envLeaseClaim) != nil {
		t.Fatalf("lease claim left: %v", err)
	}
	e.waitState(resp.Lease, state.LeaseNone)
}
