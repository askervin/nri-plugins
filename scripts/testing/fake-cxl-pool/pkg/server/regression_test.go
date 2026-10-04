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

package server

// Regression tests for the findings of the code review in
// plan/51-code-review.md (H1, M2-M5, L1-L3, L6, L7).

import (
	"context"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/qemu"
)

// gatedMon blocks the first QueryTree after arm() until release(), after it
// has taken its snapshot: a refresh with a stale tree.
type gatedMon struct {
	*qemu.Fake
	mu    sync.Mutex
	armed bool
	snap  chan struct{}
	gate  chan struct{}
}

func newGatedMon(f *qemu.Fake) *gatedMon {
	return &gatedMon{Fake: f, snap: make(chan struct{}), gate: make(chan struct{})}
}

func (g *gatedMon) arm() {
	g.mu.Lock()
	g.armed = true
	g.mu.Unlock()
}

func (g *gatedMon) QueryTree(ctx context.Context) (*qemu.Tree, error) {
	t, err := g.Fake.QueryTree(ctx)
	g.mu.Lock()
	armed := g.armed
	g.armed = false
	g.mu.Unlock()
	if armed {
		close(g.snap)
		<-g.gate
	}
	return t, err
}

// newServerWith starts a server for the config whose hosts vm1 (and vm2)
// use the given monitors.
func newServerWith(t *testing.T, cfgText string, mons map[string]qemu.Monitor) *Server {
	t.Helper()
	cfg, err := ParseConfig([]byte(cfgText))
	if err != nil {
		t.Fatal(err)
	}
	var procs []*qemu.Process
	for i, n := range []string{"vm1", "vm2"} {
		if mons[n] != nil {
			procs = append(procs, vmCmdline(n, 101+i, "-object", "memory-backend-ram,id="+localObj+",share=on,size=256M"))
		}
	}
	srv, err := New(cfg, Options{
		Logger:       log.New(testWriter{t}, "", 0),
		Verbose:      true,
		Discover:     func() ([]*qemu.Process, error) { return procs, nil },
		ProcessAlive: func(int, uint64) bool { return true },
		NewMonitor: func(proto, path string) qemu.Monitor {
			for n, m := range mons {
				if strings.Contains(path, "/"+n+"/") {
					return m
				}
			}
			f := qemu.NewFake(nil, nil)
			f.Unreachable = true
			return f
		},
		SocketExists:   func(p string) bool { return strings.HasSuffix(p, "qmp.sock") },
		BackgroundPoll: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Start()
	t.Cleanup(srv.Stop)
	return srv
}

func poolConfig(dir, extra string) string {
	return "pools:\n  - name: default\n    dir: " + filepath.Join(dir, "pool") + "\n" + extra
}

const pooled0 = "devices:\n  - name: pooled0\n    size: 256M\n"

// H1: a refresh whose tree was read before an attach completed must not
// drop the new attachment.
func TestStaleTreeKeepsNewAttachment(t *testing.T) {
	f := newVMFake()
	g := newGatedMon(f)
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(t.TempDir(), pooled0), map[string]qemu.Monitor{"vm1": g})
	g.arm()
	done := make(chan struct{})
	go func() { srv.Hosts(ctx, false); close(done) }() // GET /hosts
	<-g.snap
	a, _, err := srv.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	if err != nil {
		t.Fatal(err)
	}
	close(g.gate)
	<-done
	cur, err := srv.DeviceAttachment("pooled0", "vm1")
	if err != nil || cur.State != api.AttachmentAttached {
		t.Fatalf("attachment dropped by a reconcile with a stale tree: %+v %v (qemu has %s: %v)",
			cur, err, a.QemuDeviceID, f.HasDevice(a.QemuDeviceID))
	}
	if d, _ := srv.Device("pooled0"); d.State != api.DeviceAttached {
		t.Fatalf("device state %s", d.State)
	}
}

// H1: the stale tree must not open a window for attaching an exclusive
// device to a second host.
func TestStaleTreeNoDoubleExclusiveAttach(t *testing.T) {
	g1 := newGatedMon(newVMFake())
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(t.TempDir(), pooled0),
		map[string]qemu.Monitor{"vm1": g1, "vm2": newVMFake()})
	g1.arm()
	done := make(chan struct{})
	go func() { srv.refreshTrees(ctx, "vm1"); close(done) }()
	<-g1.snap
	if _, _, err := srv.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"}); err != nil {
		t.Fatal(err)
	}
	close(g1.gate)
	<-done
	_, _, err := srv.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm2"})
	mustCode(t, err, api.CodeConflict)
	srv.refreshTrees(ctx)
	as, _ := srv.Attachments(AttachmentFilter{Device: "pooled0"})
	if len(as) != 1 || as[0].Host != "vm1" || as[0].Adopted {
		t.Fatalf("exclusive device pooled0 has attachments %+v", as)
	}
}

// H1: adoption respects the exclusive rule.
func TestAdoptionRespectsExclusive(t *testing.T) {
	dir := t.TempDir()
	f1, f2 := newVMFake(), newVMFake()
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(dir, pooled0), map[string]qemu.Monitor{"vm1": f1, "vm2": f2})
	if _, _, err := srv.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm2"}); err != nil {
		t.Fatal(err)
	}
	// someone plugs the same exclusive device into vm1 behind the server
	obj := "fcp_pooled0.hp7"
	f1.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: obj, Size: 256 << 20, MemPath: filepath.Join(dir, "pool", "pooled0.raw"), Share: true})
	if err := f1.PlugDevice(qemu.CXLType3{ID: obj, Bus: "ds0_hb0", VolatileMemdev: obj, Serial: 0xc1f00001}); err != nil {
		t.Fatal(err)
	}
	srv.refreshTrees(ctx)
	as, _ := srv.Attachments(AttachmentFilter{Device: "pooled0"})
	if len(as) != 1 || as[0].Host != "vm2" {
		t.Fatalf("exclusive device adopted twice: %+v", as)
	}
	// a shared device may be adopted on another host
	sh := "devices:\n  - name: s0\n    size: 256M\n    shared: true\n"
	f3, f4 := newVMFake(), newVMFake()
	dir2 := t.TempDir()
	srv2 := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(dir2, sh), map[string]qemu.Monitor{"vm1": f3, "vm2": f4})
	if _, _, err := srv2.Attach(ctx, "s0", api.AttachRequest{Host: "vm2"}); err != nil {
		t.Fatal(err)
	}
	obj = "fcp_s0.hp9"
	f3.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: obj, Size: 256 << 20, MemPath: filepath.Join(dir2, "pool", "s0.raw"), Share: true})
	if err := f3.PlugDevice(qemu.CXLType3{ID: obj, Bus: "ds0_hb0", VolatileMemdev: obj, Serial: 0xc1f00001}); err != nil {
		t.Fatal(err)
	}
	srv2.refreshTrees(ctx)
	if as, _ := srv2.Attachments(AttachmentFilter{Device: "s0"}); len(as) != 2 {
		t.Fatalf("shared device not adopted: %+v", as)
	}
}

// M2: a client that gives up does not turn the detach into a timeout.
func TestDetachIgnoresClientCancel(t *testing.T) {
	f := newVMFake()
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(t.TempDir(), pooled0), map[string]qemu.Monitor{"vm1": f})
	a, _, err := srv.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	if err != nil {
		t.Fatal(err)
	}
	f.Hold(a.QemuDeviceID)
	go func() {
		time.Sleep(300 * time.Millisecond)
		f.Release(a.QemuDeviceID)
	}()
	cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	da, res, err := srv.Detach(cctx, "pooled0", "vm1", DetachOptions{Wait: true, Timeout: 5 * time.Second})
	if err != nil || res != DetachDone || da.State != api.AttachmentDetached {
		t.Fatalf("detach after client cancel: %v %v %+v", res, err, da)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Fatalf("detach returned before the guest released the device")
	}
	if f.HasObject(a.QemuObjectID) {
		t.Fatalf("object-del skipped")
	}
}

// M3: concurrent attach/detach of an attaching device (run with -race).
type slowAddMon struct{ *qemu.Fake }

func (s slowAddMon) DeviceAdd(ctx context.Context, d qemu.CXLType3) error {
	time.Sleep(30 * time.Millisecond)
	return s.Fake.DeviceAdd(ctx, d)
}

func TestConcurrentAttachDetachNoRace(t *testing.T) {
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(t.TempDir(), pooled0), map[string]qemu.Monitor{"vm1": slowAddMon{newVMFake()}})
	no := false
	if _, _, err := srv.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1", Wait: &no}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		_, _, _ = srv.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1", Wait: &no})
		_, _, _ = srv.Detach(ctx, "pooled0", "vm1", DetachOptions{Wait: true, Timeout: time.Second})
		time.Sleep(3 * time.Millisecond)
	}
}

// M4: the config wins over the state file for shared and labels of config
// devices, and a non-sharable pool is respected.
func TestConfigWinsOverState(t *testing.T) {
	dir := t.TempDir()
	base := "stateFile: " + filepath.Join(dir, "state.json") + "\n" + poolConfig(dir, "devices:\n  - name: cfg0\n    size: 256M\n    labels: {a: b}\n    shared: ")
	mons := map[string]qemu.Monitor{"vm1": newVMFake()}
	srv := newServerWith(t, base+"true\n", mons)
	if _, err := srv.PatchDevice("cfg0", api.DevicePatch{Labels: map[string]string{"x": "y"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Allocate("cfg0", api.AllocationRequest{Owner: "claim-1"}); err != nil {
		t.Fatal(err)
	}
	srv.Stop()
	srv2 := newServerWith(t, base+"false\n", mons)
	d, _ := srv2.Device("cfg0")
	if d.Shared || d.Labels["a"] != "b" || d.Labels["x"] != "" {
		t.Fatalf("state file overrides the config: shared=%v labels=%v", d.Shared, d.Labels)
	}
	if d.Allocation == nil || d.Allocation.Owner != "claim-1" {
		t.Fatalf("allocation not restored: %+v", d.Allocation)
	}
}

// M5: config devices without a serial do not take the serials of dynamic
// devices in the state file, and keep their serials across restarts.
func TestStateSerials(t *testing.T) {
	dir := t.TempDir()
	base := "stateFile: " + filepath.Join(dir, "state.json") + "\n" + poolConfig(dir, "")
	mons := map[string]qemu.Monitor{"vm1": newVMFake()}
	srv := newServerWith(t, base, mons)
	d, err := srv.CreateDevice(api.DeviceCreate{Name: "dyn0", Size: api.Size(256 << 20)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.Attach(ctx, "dyn0", api.AttachRequest{Host: "vm1"}); err != nil {
		t.Fatal(err)
	}
	srv.Stop()
	two := "devices:\n  - name: cfg0\n    size: 256M\n  - name: cfg1\n    size: 256M\n"
	srv2 := newServerWith(t, base+two, mons)
	d2, err := srv2.Device("dyn0")
	if err != nil || d2.Serial != d.Serial || len(d2.Attachments) != 1 {
		t.Fatalf("dynamic device lost or changed: %+v %v", d2, err)
	}
	c0, _ := srv2.Device("cfg0")
	c1, _ := srv2.Device("cfg1")
	if c0.Serial == d.Serial || c1.Serial == d.Serial || c0.Serial == c1.Serial {
		t.Fatalf("serial collision: dyn0 %s cfg0 %s cfg1 %s", d.Serial, c0.Serial, c1.Serial)
	}
	srv2.Stop()
	// reordered config devices keep their serials
	srv3 := newServerWith(t, base+"devices:\n  - name: cfg1\n    size: 256M\n  - name: cfg0\n    size: 256M\n", mons)
	r0, _ := srv3.Device("cfg0")
	r1, _ := srv3.Device("cfg1")
	if r0.Serial != c0.Serial || r1.Serial != c1.Serial {
		t.Fatalf("config serials changed: cfg0 %s->%s cfg1 %s->%s", c0.Serial, r0.Serial, c1.Serial, r1.Serial)
	}
}

// M5: a device with attachments is never dropped from the state silently.
func TestStateKeepsAttachedDeviceOfRemovedPool(t *testing.T) {
	dir := t.TempDir()
	mons := map[string]qemu.Monitor{"vm1": newVMFake()}
	two := "pools:\n  - name: default\n    dir: " + filepath.Join(dir, "p0") + "\n  - name: other\n    dir: " + filepath.Join(dir, "p1") + "\n"
	sf := "stateFile: " + filepath.Join(dir, "state.json") + "\n"
	srv := newServerWith(t, sf+two, mons)
	if _, err := srv.CreateDevice(api.DeviceCreate{Name: "d1", Size: api.Size(256 << 20), Pool: "other"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.Attach(ctx, "d1", api.AttachRequest{Host: "vm1"}); err != nil {
		t.Fatal(err)
	}
	srv.Stop()
	srv2 := newServerWith(t, sf+"pools:\n  - name: default\n    dir: "+filepath.Join(dir, "p0")+"\n", mons)
	d, err := srv2.Device("d1")
	if err != nil || len(d.Attachments) != 1 {
		t.Fatalf("attached device of a removed pool dropped: %+v %v", d, err)
	}
	if _, _, err := srv2.Detach(ctx, "d1", "vm1", DetachOptions{Wait: true}); err != nil {
		t.Fatal(err)
	}
	if err := srv2.DeleteDevice(ctx, "d1", false); err != nil {
		t.Fatal(err)
	}
}

// L1: the hotplug counter is seeded from the device ids qemu already has.
func TestHotplugCounterSeededFromQemu(t *testing.T) {
	dir := t.TempDir()
	f := newVMFake()
	// leftovers of a previous server run without a state file: a device
	// of an unknown device and an object whose object-del failed
	obj := "fcp_gone.hp3"
	f.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: obj, Size: 256 << 20, MemPath: filepath.Join(dir, "x.raw"), Share: true})
	if err := f.PlugDevice(qemu.CXLType3{ID: obj, Bus: "ds0_hb0", VolatileMemdev: obj, Serial: 1}); err != nil {
		t.Fatal(err)
	}
	f.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: "fcp_pooled0.hp5", Size: 256 << 20, MemPath: filepath.Join(dir, "y.raw")})
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(dir, pooled0), map[string]qemu.Monitor{"vm1": f})
	a, _, err := srv.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	if err != nil || a.QemuDeviceID != "fcp_pooled0.hp6" {
		t.Fatalf("attach: %+v %v", a, err)
	}
}

// L2: device_del "not found" still checks whether the backend leaked.
func TestDeviceDelNotFoundChecksLeak(t *testing.T) {
	f := newVMFake()
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(t.TempDir(), pooled0), map[string]qemu.Monitor{"vm1": f})
	a, _, err := srv.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	if err != nil {
		t.Fatal(err)
	}
	// surprise removal behind the server, memory kept online in the guest
	f.LeakOnRelease = true
	f.Hold(a.QemuDeviceID)
	if err := f.DeviceDel(ctx, a.QemuDeviceID); err != nil {
		t.Fatal(err)
	}
	f.Release(a.QemuDeviceID)
	da, _, err := srv.Detach(ctx, "pooled0", "vm1", DetachOptions{Wait: true, Timeout: time.Second})
	mustCode(t, err, api.CodeConflict)
	if da.State != api.AttachmentFailed || !strings.Contains(da.Error, "leaked") {
		t.Fatalf("leak not detected: %+v", da)
	}
}

// L3: an interleaved window is shared by its targets.
func TestInterleavedFMW(t *testing.T) {
	f := newVMFake()
	f.FMW = []qemu.FMWWindow{{Targets: []string{"cxlhb0", "cxlhb1"}, Size: 1 << 30}}
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(t.TempDir(), ""), map[string]qemu.Monitor{"vm1": f})
	h, _ := srv.Host(ctx, "vm1", true)
	if h.HostBridges[0].FMWSize != 512<<20 || h.HostBridges[1].FMWSize != 512<<20 {
		t.Fatalf("interleaved fmw counted per target: %+v", h.HostBridges)
	}
}

// L6: a pool device must not have the serial of a local device of the host
// it is attached to.
func TestSerialCollisionWithLocalDevice(t *testing.T) {
	cfg := "devices:\n  - name: cfg0\n    size: 256M\n    serial: 0xc100e2e0\n"
	f1, f2 := newVMFake(), newVMFake()
	for _, f := range []*qemu.Fake{f1, f2} {
		f.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendRAM, ID: localObj, Size: 256 << 20, Share: true})
	}
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(t.TempDir(), cfg), map[string]qemu.Monitor{"vm1": f1, "vm2": f2})
	_, err := srv.CreateDevice(api.DeviceCreate{Name: "d1", Size: api.Size(256 << 20), Serial: "0xc100e2e0"})
	mustCode(t, err, api.CodeConflict)
	// vm1 and vm2 both have the local device with serial 0xc100e2e0
	_, _, err = srv.Attach(ctx, "cfg0", api.AttachRequest{Host: "vm1"})
	mustCode(t, err, api.CodeConflict)
	// local devices of different hosts may share a serial
	for _, h := range []string{"vm1", "vm2"} {
		if _, _, err := srv.Attach(ctx, h+".memdev0", api.AttachRequest{Host: h}); err != nil {
			t.Fatal(err)
		}
	}
}

// L7: a slot reserved for a local device is used only when no other slot
// is free, even if it is on the requested NUMA node.
func TestReservedSlotBeforeNuma(t *testing.T) {
	f := newVMFake()
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(t.TempDir(), "devices:\n  - name: a\n    size: 256M\n  - name: b\n    size: 256M\n"), map[string]qemu.Monitor{"vm1": f})
	a, _, err := srv.Attach(ctx, "a", api.AttachRequest{Host: "vm1", NumaNode: ptr(1)})
	if err != nil || a.Slot.Bus != "ds0_hb1" {
		t.Fatalf("attach a: %+v %v", a, err)
	}
	// only ds1_hb1 (reserved for vm1.memdev0) is left on node 1
	b, _, err := srv.Attach(ctx, "b", api.AttachRequest{Host: "vm1", NumaNode: ptr(1)})
	if err != nil || b.Slot.NumaNode != 0 {
		t.Fatalf("attach b took the reserved slot: %+v %v", b, err)
	}
}

// L10: an allocated device is not deleted without force.
func TestDeleteAllocatedDevice(t *testing.T) {
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(t.TempDir(), ""), map[string]qemu.Monitor{"vm1": newVMFake()})
	if _, err := srv.CreateDevice(api.DeviceCreate{Name: "d1", Size: api.Size(256 << 20)}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Allocate("d1", api.AllocationRequest{Owner: "claim-1"}); err != nil {
		t.Fatal(err)
	}
	mustCode(t, srv.DeleteDevice(ctx, "d1", false), api.CodeConflict)
	if err := srv.DeleteDevice(ctx, "d1", true); err != nil {
		t.Fatal(err)
	}
}
