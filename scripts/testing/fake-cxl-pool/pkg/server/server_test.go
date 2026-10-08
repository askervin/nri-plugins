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

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/client"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/qemu"
)

type testEnv struct {
	t      *testing.T
	dir    string
	cfg    *Config
	srv    *Server
	hs     *httptest.Server
	c      *client.Client
	mu     sync.Mutex
	fakes  map[string]*qemu.Fake // by monitor socket path
	procs  []*qemu.Process
	alive  map[int]bool
	logbuf *strings.Builder
}

func vmCmdline(name string, pid int, extra ...string) *qemu.Process {
	args := []string{"/usr/bin/qemu-system-x86_64",
		"-drive", "if=none,id=disk0,format=qcow2,file=/e2e/" + name + "/.vagrant/machines/" + name + "/qemu/vq_x/linked-box.img",
		"-qmp", "unix:qmp.sock,server,nowait",
		"-monitor", "unix:monitor.sock,server,nowait",
		"-device", "pxb-cxl,bus_nr=12,bus=pcie.0,id=cxlhb0,numa_node=0",
		"-device", "pxb-cxl,bus_nr=24,bus=pcie.0,id=cxlhb1,numa_node=1",
		"-M", "cxl-fmw.0.targets.0=cxlhb0,cxl-fmw.0.size=4G,cxl-fmw.1.targets.0=cxlhb1,cxl-fmw.1.size=4G",
	}
	args = append(args, extra...)
	p := qemu.ParseCmdline(args)
	p.PID = pid
	p.StartTime = uint64(1000 + pid)
	p.Cwd = "/"
	for i, s := range p.QMPSockets {
		p.QMPSockets[i] = p.ResolvePath(s, nil)
	}
	for i, s := range p.HMPSockets {
		p.HMPSockets[i] = p.ResolvePath(s, nil)
	}
	return p
}

func newVMFake() *qemu.Fake {
	return qemu.NewFake(map[string]int{"cxlhb0": 0, "cxlhb1": 1}, map[string]string{
		"ds0_hb0": "cxlhb0", "ds1_hb0": "cxlhb0",
		"ds0_hb1": "cxlhb1", "ds1_hb1": "cxlhb1",
	})
}

const localObj = "beram_cxl_memdev0__bus_ds1_hb1__sn_0xc100e2e0"

func newTestEnv(t *testing.T, extraConfig string) *testEnv {
	t.Helper()
	dir := t.TempDir()
	e := &testEnv{t: t, dir: dir, fakes: map[string]*qemu.Fake{}, alive: map[int]bool{}, logbuf: &strings.Builder{}}
	vm1 := vmCmdline("vm1", 101, "-uuid", "6BA7B810-9DAD-11D1-80B4-00C04FD430C8",
		"-object", "memory-backend-ram,id="+localObj+",share=on,size=256M")
	vm2 := vmCmdline("vm2", 102)
	e.procs = []*qemu.Process{vm1, vm2}
	e.alive[101], e.alive[102] = true, true
	f1, f2 := newVMFake(), newVMFake()
	f1.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendRAM, ID: localObj, Size: 256 << 20, Share: true})
	e.fakes["/e2e/vm1/qmp.sock"] = f1
	e.fakes["/e2e/vm2/qmp.sock"] = f2
	cfgText := `
listen: 127.0.0.1:0
exclusiveSerialBase: 0xc1ee0000
stateFile: ` + filepath.Join(dir, "state.json") + `
pools:
  - name: default
    dir: ` + filepath.Join(dir, "pool") + `
    capacity: 2G
    sharable: true
devices:
  - name: shared0
    size: 256M
    shared: true
    serial: 0xc1ae0000
  - name: pooled0
    size: 512M
` + extraConfig
	cfg, err := ParseConfig([]byte(cfgText))
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	e.start()
	return e
}

func (e *testEnv) start() {
	e.t.Helper()
	opts := Options{
		Logger:  log.New(io.MultiWriter(testWriter{e.t}), "", 0),
		Verbose: true,
		Discover: func() ([]*qemu.Process, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return append([]*qemu.Process(nil), e.procs...), nil
		},
		ProcessAlive: func(pid int, st uint64) bool {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.alive[pid]
		},
		NewMonitor: func(proto, path string) qemu.Monitor {
			e.mu.Lock()
			defer e.mu.Unlock()
			if f, ok := e.fakes[path]; ok {
				return f
			}
			f := qemu.NewFake(nil, nil)
			f.Unreachable = true
			return f
		},
		SocketExists:   func(path string) bool { return strings.HasSuffix(path, "qmp.sock") },
		BackgroundPoll: 20 * time.Millisecond,
	}
	srv, err := New(e.cfg, opts)
	if err != nil {
		e.t.Fatal(err)
	}
	srv.Start()
	e.srv = srv
	e.hs = httptest.NewServer(srv.Handler())
	e.c = client.New(e.hs.URL)
	e.t.Cleanup(e.stop)
}

func (e *testEnv) stop() {
	if e.hs != nil {
		e.hs.Close()
		e.hs = nil
	}
	if e.srv != nil {
		e.srv.Stop()
		e.srv = nil
	}
}

func (e *testEnv) fake(host string) *qemu.Fake { return e.fakes["/e2e/"+host+"/qmp.sock"] }

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(b), "\n"))
	return len(b), nil
}

var ctx = context.Background()

func ptr[T any](v T) *T { return &v }

func mustCode(t *testing.T, err error, code string) {
	t.Helper()
	if !api.IsCode(err, code) {
		t.Fatalf("expected %s error, got %v", code, err)
	}
}

func TestHostsAndResolve(t *testing.T) {
	e := newTestEnv(t, "")
	hs, err := e.c.Hosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != 2 || hs[0].Name != "vm1" || hs[1].Name != "vm2" {
		t.Fatalf("unexpected hosts %+v", hs)
	}
	h := hs[0]
	if h.State != api.HostRunning || h.Control != "qmp" || h.QMP != "/e2e/vm1/qmp.sock" || h.PID != 101 ||
		h.UUID != "6ba7b810-9dad-11d1-80b4-00c04fd430c8" || h.Source != api.SourceDiscovered {
		t.Fatalf("unexpected host %+v", h)
	}
	if len(h.Slots) != 4 || h.Slots[0].Bus != "ds0_hb0" || h.Slots[2].NumaNode != 1 {
		t.Fatalf("unexpected slots %+v", h.Slots)
	}
	if len(h.HostBridges) != 2 || h.HostBridges[1].FMWSize != 4<<30 || h.HostBridges[1].NumaNode != 1 {
		t.Fatalf("unexpected host bridges %+v", h.HostBridges)
	}
	if len(h.LocalDevices) != 1 || h.LocalDevices[0] != "vm1.memdev0" {
		t.Fatalf("unexpected local devices %+v", h.LocalDevices)
	}
	r, err := e.c.Resolve(ctx, "vm2.example.com", "")
	if err != nil || r.Name != "vm2" {
		t.Fatalf("resolve by first label: %+v %v", r, err)
	}
	r, err = e.c.Resolve(ctx, "wrong-hostname", "6BA7B810-9DAD-11D1-80B4-00C04FD430C8")
	if err != nil || r.Name != "vm1" {
		t.Fatalf("resolve by uuid: %+v %v", r, err)
	}
	_, err = e.c.Resolve(ctx, "nosuch", "")
	mustCode(t, err, api.CodeNotFound)
	h2, err := e.c.Host(ctx, "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if err != nil || h2.Name != "vm1" {
		t.Fatalf("host by uuid: %+v %v", h2, err)
	}
	st, err := e.c.Status(ctx)
	if err != nil || st.Hosts != 2 || st.Devices != 3 || st.Qemu.Versions["vm1"] != "11.1.1 fake" {
		t.Fatalf("unexpected status %+v %v", st, err)
	}
	ps, err := e.c.Pools(ctx)
	if err != nil || len(ps) != 1 || ps[0].Used != 768<<20 || ps[0].Free != 2<<30-768<<20 {
		t.Fatalf("unexpected pools %+v %v", ps, err)
	}
}

func TestCreateDevice(t *testing.T) {
	e := newTestEnv(t, "")
	_, err := e.c.CreateDevice(ctx, api.DeviceCreate{Size: 100 << 20})
	mustCode(t, err, api.CodeInvalidArgument)
	d, err := e.c.CreateDevice(ctx, api.DeviceCreate{Size: 256 << 20, Labels: map[string]string{"a": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "dev0" || d.Serial != "0xc1ee0002" || d.State != api.DeviceFree || d.Scope != api.ScopePool {
		// pooled0 got 0xc1ee0001 at startup
		t.Fatalf("unexpected device %+v", d)
	}
	if st, err := os.Stat(d.Path); err != nil || st.Size() != 256<<20 {
		t.Fatalf("backing file: %v %v", st, err)
	}
	_, err = e.c.CreateDevice(ctx, api.DeviceCreate{Name: "dev0", Size: 256 << 20})
	mustCode(t, err, api.CodeConflict)
	_, err = e.c.CreateDevice(ctx, api.DeviceCreate{Name: "big", Size: 2 << 30})
	mustCode(t, err, api.CodeConflict)
	_, err = e.c.CreateDevice(ctx, api.DeviceCreate{Name: "x", Size: 256 << 20, Serial: "0xc1ae0000"})
	mustCode(t, err, api.CodeConflict)
	d2, err := e.c.CreateDevice(ctx, api.DeviceCreate{Name: "s1", Size: 256 << 20, Shared: true, Serial: "0xabc"})
	if err != nil || d2.Serial != "0xabc" || !d2.Shared {
		t.Fatalf("unexpected device %+v %v", d2, err)
	}
	// a shared device without a serial gets one from the shared base
	d3, err := e.c.CreateDevice(ctx, api.DeviceCreate{Name: "s2", Size: 256 << 20, Shared: true})
	if err != nil || d3.Serial != "0xc1ae0001" || !d3.Shared {
		t.Fatalf("unexpected device %+v %v", d3, err)
	}
	if err := e.c.DeleteDevice(ctx, "s2", false); err != nil {
		t.Fatal(err)
	}
	ds, err := e.c.Devices(ctx, client.DeviceListOptions{Shared: ptr(true)})
	if err != nil || len(ds) != 2 || ds[0].Name != "s1" || ds[1].Name != "shared0" {
		t.Fatalf("unexpected shared devices %+v %v", ds, err)
	}
	p, err := e.c.PatchDevice(ctx, "dev0", api.DevicePatch{Shared: ptr(true), Labels: map[string]string{"x": "y"}})
	if err != nil || !p.Shared || p.Labels["x"] != "y" || p.Labels["a"] != "" {
		t.Fatalf("unexpected patched device %+v %v", p, err)
	}
	if err := e.c.DeleteDevice(ctx, "dev0", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.Path); !os.IsNotExist(err) {
		t.Fatalf("backing file not removed: %v", err)
	}
	mustCode(t, e.c.DeleteDevice(ctx, "shared0", false), api.CodeConflict)
	mustCode(t, e.c.DeleteDevice(ctx, "vm1.memdev0", false), api.CodeConflict)
	mustCode(t, e.c.DeleteDevice(ctx, "nosuch", false), api.CodeNotFound)
}

func TestAttachDetachExclusive(t *testing.T) {
	e := newTestEnv(t, "")
	a, status, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	if err != nil || status != 201 {
		t.Fatalf("attach: %d %v", status, err)
	}
	// prefers a slot that is not reserved for the local device (ds1_hb1)
	if a.State != api.AttachmentAttached || a.Slot.Bus != "ds0_hb0" || a.QemuDeviceID != "fcp_pooled0.hp1" ||
		a.QemuObjectID != "fcp_pooled0.hp1" || a.Serial != "0xc1ee0001" || a.ID != "pooled0@vm1" {
		t.Fatalf("unexpected attachment %+v", a)
	}
	f1 := e.fake("vm1")
	cmds := strings.Join(f1.Commands(), "\n")
	if !strings.Contains(cmds, "object_add memory-backend-file,id=fcp_pooled0.hp1,size=536870912,share=on,mem-path="+filepath.Join(e.dir, "pool", "pooled0.raw")) ||
		!strings.Contains(cmds, "device_add cxl-type3,bus=ds0_hb0,volatile-memdev=fcp_pooled0.hp1,id=fcp_pooled0.hp1,sn=0xc1ee0001") {
		t.Fatalf("unexpected qemu commands:\n%s", cmds)
	}
	// idempotent
	a2, status, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	if err != nil || status != 200 || a2.QemuDeviceID != a.QemuDeviceID {
		t.Fatalf("second attach: %d %v %+v", status, err, a2)
	}
	// exclusive
	_, _, err = e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm2"})
	mustCode(t, err, api.CodeConflict)
	d, _ := e.c.Device(ctx, "pooled0")
	if d.State != api.DeviceAttached || len(d.Attachments) != 1 {
		t.Fatalf("unexpected device %+v", d)
	}
	h, _ := e.c.Host(ctx, "vm1")
	if h.Slots[0].Attachment != "pooled0@vm1" || h.Slots[0].Device != "fcp_pooled0.hp1" || h.HostBridges[0].AttachedBytes != 512<<20 {
		t.Fatalf("unexpected host %+v", h)
	}
	mustCode(t, e.c.DeleteDevice(ctx, "pooled0", false), api.CodeConflict)
	// detach: the guest has nothing to release in the fake
	da, status, err := e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{})
	if err != nil || status != 200 || da.State != api.AttachmentDetached {
		t.Fatalf("detach: %d %v %+v", status, err, da)
	}
	if f1.HasDevice("fcp_pooled0.hp1") || f1.HasObject("fcp_pooled0.hp1") {
		t.Fatalf("device or object left in qemu: %s", f1)
	}
	_, _, err = e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{})
	mustCode(t, err, api.CodeNotFound)
	// attach again: a new qemu id
	a3, status, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm2", NumaNode: ptr(1)})
	if err != nil || status != 201 || a3.QemuDeviceID != "fcp_pooled0.hp1" || a3.Slot.NumaNode != 1 || a3.Slot.Bus != "ds0_hb1" {
		t.Fatalf("attach to vm2: %d %v %+v", status, err, a3)
	}
	_, _, err = e.c.Detach(ctx, "pooled0", "vm2", client.DetachOptions{})
	if err != nil {
		t.Fatal(err)
	}
	a4, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm2"})
	if err != nil || a4.QemuDeviceID != "fcp_pooled0.hp2" {
		t.Fatalf("hotplug counter not used: %+v %v", a4, err)
	}
}

func TestAttachShared(t *testing.T) {
	e := newTestEnv(t, "")
	a1, _, err := e.c.Attach(ctx, "shared0", api.AttachRequest{Host: "vm1"})
	if err != nil {
		t.Fatal(err)
	}
	// host by uuid
	a2, _, err := e.c.Attach(ctx, "shared0", api.AttachRequest{Host: "vm2"})
	if err != nil {
		t.Fatal(err)
	}
	if a1.Serial != "0xc1ae0000" || a2.Serial != a1.Serial {
		t.Fatalf("serials differ: %s %s", a1.Serial, a2.Serial)
	}
	d, _ := e.c.Device(ctx, "shared0")
	if len(d.Attachments) != 2 || d.State != api.DeviceAttached {
		t.Fatalf("unexpected device %+v", d)
	}
	as, err := e.c.Attachments(ctx, "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "")
	if err != nil || len(as) != 1 || as[0].Host != "vm1" {
		t.Fatalf("attachments by uuid: %+v %v", as, err)
	}
	// detach from vm1 by uuid
	if _, _, err := e.c.Detach(ctx, "shared0", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", client.DetachOptions{}); err != nil {
		t.Fatal(err)
	}
	d, _ = e.c.Device(ctx, "shared0")
	if len(d.Attachments) != 1 || d.Attachments[0].Host != "vm2" {
		t.Fatalf("unexpected device %+v", d)
	}
	// delete with force detaches first; config devices cannot be deleted,
	// so test with a dynamic shared device
	if _, err := e.c.CreateDevice(ctx, api.DeviceCreate{Name: "s1", Size: 256 << 20, Shared: true}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"vm1", "vm2"} {
		if _, _, err := e.c.Attach(ctx, "s1", api.AttachRequest{Host: h}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.c.DeleteDevice(ctx, "s1", true); err != nil {
		t.Fatal(err)
	}
	_, err = e.c.Device(ctx, "s1")
	mustCode(t, err, api.CodeNotFound)
}

func TestDetachGuestHolds(t *testing.T) {
	e := newTestEnv(t, "")
	a, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	if err != nil {
		t.Fatal(err)
	}
	f1 := e.fake("vm1")
	f1.Hold(a.QemuDeviceID)
	da, _, err := e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{Timeout: 100 * time.Millisecond})
	mustCode(t, err, api.CodeConflict)
	if da.State != api.AttachmentFailed || !strings.Contains(da.Error, "did not release") {
		t.Fatalf("unexpected attachment %+v", da)
	}
	d, _ := e.c.Device(ctx, "pooled0")
	if d.State != api.DeviceError {
		t.Fatalf("unexpected device state %s", d.State)
	}
	// attaching meanwhile is a conflict, here and elsewhere
	_, _, err = e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	mustCode(t, err, api.CodeConflict)
	_, _, err = e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm2"})
	mustCode(t, err, api.CodeConflict)
	// a repeated detach is a conflict and sends no second device_del
	_, _, err = e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{Timeout: 50 * time.Millisecond})
	mustCode(t, err, api.CodeConflict)
	n := 0
	for _, c := range f1.Commands() {
		if strings.HasPrefix(c, "device_del") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected one device_del, got %d: %v", n, f1.Commands())
	}
	// the guest releases: the background waiter finalizes
	f1.Release(a.QemuDeviceID)
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := e.c.WaitDetached(wctx, "pooled0", "vm1", 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if f1.HasObject(a.QemuObjectID) {
		t.Fatalf("object not deleted")
	}
}

func TestDetachNoWait(t *testing.T) {
	e := newTestEnv(t, "")
	a, status, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1", Wait: ptr(false)})
	if err != nil || status != 202 || a.State != api.AttachmentAttaching {
		t.Fatalf("attach no-wait: %d %v %+v", status, err, a)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		cur, err := e.c.DeviceAttachment(ctx, "pooled0", "vm1")
		if err == nil && cur.State == api.AttachmentAttached {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not attached: %+v %v", cur, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.fake("vm1").Hold(a.QemuDeviceID)
	da, status, err := e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{NoWait: true})
	if err != nil || status != 202 || da.State != api.AttachmentDetaching {
		t.Fatalf("detach no-wait: %d %v %+v", status, err, da)
	}
	e.fake("vm1").Release(a.QemuDeviceID)
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := e.c.WaitDetached(wctx, "pooled0", "vm1", 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestStockQemuZombie(t *testing.T) {
	e := newTestEnv(t, "")
	f1 := e.fake("vm1")
	f1.Stock = true
	if _, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"}); err != nil {
		t.Fatal(err)
	}
	da, _, err := e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{Timeout: 100 * time.Millisecond})
	mustCode(t, err, api.CodeConflict)
	if da.State != api.AttachmentFailed {
		t.Fatalf("unexpected attachment %+v", da)
	}
	// reconcile keeps it: the device is still in qemu
	e.srv.Refresh(ctx, true)
	cur, err := e.c.DeviceAttachment(ctx, "pooled0", "vm1")
	if err != nil || cur.State != api.AttachmentFailed {
		t.Fatalf("unexpected attachment %+v %v", cur, err)
	}
	// the slot stays occupied by the zombie
	h, _ := e.c.Host(ctx, "vm1")
	if h.Slots[0].Device != "fcp_pooled0.hp1" {
		t.Fatalf("zombie slot looks free: %+v", h.Slots[0])
	}
}

func TestAllocationOwnership(t *testing.T) {
	e := newTestEnv(t, "")
	if _, err := e.c.Allocate(ctx, "pooled0", "claim-a", "test"); err != nil {
		t.Fatal(err)
	}
	_, err := e.c.Allocate(ctx, "pooled0", "claim-b", "")
	mustCode(t, err, api.CodeConflict)
	al, err := e.c.Allocate(ctx, "pooled0", "claim-a", "again")
	if err != nil || al.Note != "again" {
		t.Fatalf("re-allocate: %+v %v", al, err)
	}
	_, _, err = e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	mustCode(t, err, api.CodeConflict)
	_, _, err = e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1", Owner: "claim-b"})
	mustCode(t, err, api.CodeConflict)
	if _, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1", Owner: "claim-a"}); err != nil {
		t.Fatal(err)
	}
	_, _, err = e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{})
	mustCode(t, err, api.CodeConflict)
	if _, _, err := e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{Owner: "claim-a"}); err != nil {
		t.Fatal(err)
	}
	mustCode(t, e.c.Release(ctx, "pooled0", "claim-b", false), api.CodeConflict)
	if err := e.c.Release(ctx, "pooled0", "claim-a", false); err != nil {
		t.Fatal(err)
	}
	d, _ := e.c.Device(ctx, "pooled0")
	if d.Allocation != nil {
		t.Fatalf("allocation not released")
	}
	// force
	if _, err := e.c.Allocate(ctx, "pooled0", "claim-a", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1", Force: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
}

func TestSlotSelection(t *testing.T) {
	e := newTestEnv(t, "")
	_, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1", Slot: "nosuch"})
	mustCode(t, err, api.CodeInvalidArgument)
	a, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1", Slot: "ds1_hb0"})
	if err != nil || a.Slot.Bus != "ds1_hb0" || a.Slot.HostBridge != "cxlhb0" || a.Slot.Kind != api.SlotDownstream {
		t.Fatalf("explicit slot: %+v %v", a, err)
	}
	_, _, err = e.c.Attach(ctx, "shared0", api.AttachRequest{Host: "vm1", Slot: "ds1_hb0"})
	mustCode(t, err, api.CodeConflict)
	// a slot occupied by a device someone else plugged
	f1 := e.fake("vm1")
	f1.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendRAM, ID: "other", Size: 256 << 20})
	if err := f1.PlugDevice(qemu.CXLType3{ID: "foreign", Bus: "ds0_hb0", VolatileMemdev: "other", Serial: 7}); err != nil {
		t.Fatal(err)
	}
	_, _, err = e.c.Attach(ctx, "shared0", api.AttachRequest{Host: "vm1", Slot: "ds0_hb0"})
	mustCode(t, err, api.CodeConflict)
	// numa 0 is full now: falls back to numa 1, avoiding the local device slot
	a, _, err = e.c.Attach(ctx, "shared0", api.AttachRequest{Host: "vm1", NumaNode: ptr(0)})
	if err != nil || a.Slot.Bus != "ds0_hb1" {
		t.Fatalf("fallback slot: %+v %v", a, err)
	}
	h, _ := e.c.Host(ctx, "vm1")
	if h.Slots[0].Device != "foreign" || h.Slots[0].Attachment != "" {
		t.Fatalf("unexpected foreign slot %+v", h.Slots[0])
	}
	// the last free slot is the local device's slot: a pool device takes it
	if _, err := e.c.CreateDevice(ctx, api.DeviceCreate{Name: "d3", Size: 256 << 20}); err != nil {
		t.Fatal(err)
	}
	a, _, err = e.c.Attach(ctx, "d3", api.AttachRequest{Host: "vm1"})
	if err != nil || a.Slot.Bus != "ds1_hb1" {
		t.Fatalf("last slot: %+v %v", a, err)
	}
	if _, err := e.c.CreateDevice(ctx, api.DeviceCreate{Name: "d4", Size: 256 << 20}); err != nil {
		t.Fatal(err)
	}
	_, _, err = e.c.Attach(ctx, "d4", api.AttachRequest{Host: "vm1"})
	mustCode(t, err, api.CodeConflict)
}

func TestLocalDevice(t *testing.T) {
	e := newTestEnv(t, "")
	d, err := e.c.Device(ctx, "vm1.memdev0")
	if err != nil || d.Scope != api.ScopeLocal || d.LocalHost != "vm1" || d.Serial != "0xc100e2e0" || d.Size != 256<<20 || d.Backend != api.BackendRAM {
		t.Fatalf("unexpected local device %+v %v", d, err)
	}
	_, _, err = e.c.Attach(ctx, "vm1.memdev0", api.AttachRequest{Host: "vm2"})
	mustCode(t, err, api.CodeInvalidArgument)
	a, _, err := e.c.Attach(ctx, "vm1.memdev0", api.AttachRequest{Host: "vm1"})
	if err != nil || a.Slot.Bus != "ds1_hb1" || a.QemuObjectID != localObj || a.Serial != "0xc100e2e0" {
		t.Fatalf("unexpected attachment %+v %v", a, err)
	}
	f1 := e.fake("vm1")
	for _, c := range f1.Commands() {
		if strings.HasPrefix(c, "object_add") {
			t.Fatalf("object_add for a local device: %s", c)
		}
	}
	if _, _, err := e.c.Detach(ctx, "vm1.memdev0", "vm1", client.DetachOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range f1.Commands() {
		if strings.HasPrefix(c, "object_del") {
			t.Fatalf("object_del for a local device: %s", c)
		}
	}
	if !f1.HasObject(localObj) {
		t.Fatalf("local backend deleted")
	}
	ds, err := e.c.Devices(ctx, client.DeviceListOptions{Host: "vm1"})
	if err != nil || len(ds) != 1 || ds[0].Name != "vm1.memdev0" {
		t.Fatalf("devices of vm1: %+v %v", ds, err)
	}
}

func TestDeviceAddFailure(t *testing.T) {
	e := newTestEnv(t, "")
	f1 := e.fake("vm1")
	f1.FailDeviceAdd = &qemu.Error{Command: "device_add", Desc: "something broke"}
	a, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	mustCode(t, err, api.CodeUnavailable)
	if !strings.Contains(err.Error(), "something broke") || a.State != api.AttachmentFailed {
		t.Fatalf("unexpected error %v %+v", err, a)
	}
	if f1.HasObject("fcp_pooled0.hp1") {
		t.Fatalf("object not deleted after failed device_add")
	}
	d, _ := e.c.Device(ctx, "pooled0")
	if d.State != api.DeviceFree || len(d.Attachments) != 0 {
		t.Fatalf("unexpected device %+v", d)
	}
	if _, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"}); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestAdoptAndReconcile(t *testing.T) {
	e := newTestEnv(t, "")
	f1 := e.fake("vm1")
	// someone (vm-cxl-hotplug) plugs the local device
	if err := f1.PlugDevice(qemu.CXLType3{ID: "cxl_memdev0.hp1", Bus: "ds1_hb1", VolatileMemdev: localObj, Serial: 0xc100e2e0}); err != nil {
		t.Fatal(err)
	}
	e.srv.Refresh(ctx, true)
	a, err := e.c.DeviceAttachment(ctx, "vm1.memdev0", "vm1")
	if err != nil || !a.Adopted || a.QemuDeviceID != "cxl_memdev0.hp1" || a.State != api.AttachmentAttached {
		t.Fatalf("not adopted: %+v %v", a, err)
	}
	// someone removes it behind the server's back
	if err := f1.DeviceDel(ctx, "cxl_memdev0.hp1"); err != nil {
		t.Fatal(err)
	}
	e.srv.Refresh(ctx, true)
	_, err = e.c.DeviceAttachment(ctx, "vm1.memdev0", "vm1")
	mustCode(t, err, api.CodeNotFound)
}

func TestPersistenceAndRestart(t *testing.T) {
	e := newTestEnv(t, "")
	if _, err := e.c.CreateDevice(ctx, api.DeviceCreate{Name: "dyn", Size: 256 << 20, Shared: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.Allocate(ctx, "vm1.memdev0", "claim-x", ""); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"vm1", "vm2"} {
		if _, _, err := e.c.Attach(ctx, "dyn", api.AttachRequest{Host: h, Owner: "k8s:" + h}); err != nil {
			t.Fatal(err)
		}
	}
	e.stop()
	// server restart: same qemus
	e.start()
	d, err := e.c.Device(ctx, "dyn")
	if err != nil || len(d.Attachments) != 2 || d.Serial != "0xc1ae0001" {
		t.Fatalf("device not restored: %+v %v", d, err)
	}
	// attachment owners survive
	if d.Attachments[0].Owner != "k8s:"+d.Attachments[0].Host || d.Attachments[1].Owner != "k8s:"+d.Attachments[1].Host {
		t.Fatalf("attachment owners not restored: %+v", d.Attachments)
	}
	l, err := e.c.Device(ctx, "vm1.memdev0")
	if err != nil || l.Allocation == nil || l.Allocation.Owner != "claim-x" {
		t.Fatalf("local allocation not restored: %+v %v", l, err)
	}
	// hotplug counters survive
	if _, _, err := e.c.Detach(ctx, "dyn", "vm1", client.DetachOptions{}); err != nil {
		t.Fatal(err)
	}
	a, _, err := e.c.Attach(ctx, "dyn", api.AttachRequest{Host: "vm1"})
	if err != nil || a.QemuDeviceID != "fcp_dyn.hp2" {
		t.Fatalf("counter not restored: %+v %v", a, err)
	}
	// qemu of vm2 restarts: its attachments are dropped
	e.stop()
	e.mu.Lock()
	e.procs[1] = vmCmdline("vm2", 202)
	e.alive[202] = true
	delete(e.alive, 102)
	e.fakes["/e2e/vm2/qmp.sock"] = newVMFake()
	e.mu.Unlock()
	e.start()
	as, err := e.c.Attachments(ctx, "", "dyn")
	if err != nil || len(as) != 1 || as[0].Host != "vm1" {
		t.Fatalf("unexpected attachments after qemu restart: %+v %v", as, err)
	}
	h, _ := e.c.Host(ctx, "vm2")
	if h.PID != 202 || h.State != api.HostRunning {
		t.Fatalf("unexpected host %+v", h)
	}
	// vm1 stops
	e.mu.Lock()
	e.procs = e.procs[1:]
	delete(e.alive, 101)
	e.mu.Unlock()
	if _, err := e.c.Rescan(ctx); err != nil {
		t.Fatal(err)
	}
	h, _ = e.c.Host(ctx, "vm1")
	if h.State != api.HostStopped || len(h.Attachments) != 0 {
		t.Fatalf("unexpected stopped host %+v", h)
	}
	_, _, err = e.c.Attach(ctx, "dyn", api.AttachRequest{Host: "vm1"})
	mustCode(t, err, api.CodeUnavailable)
}

func TestEvents(t *testing.T) {
	e := newTestEnv(t, "")
	ectx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	got := make(chan client.Event, 100)
	go func() {
		_ = e.c.Events(ectx, func(ev client.Event) error {
			got <- ev
			return nil
		})
	}()
	time.Sleep(100 * time.Millisecond)
	if _, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"}); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case ev := <-got:
			if ev.Type == api.EventAttachmentUpdated && strings.Contains(string(ev.Object), `"state":"attached"`) {
				return
			}
		case <-ectx.Done():
			t.Fatal("no attachment.updated event")
		}
	}
}

func TestConfigErrors(t *testing.T) {
	for _, bad := range []string{
		"pools: [{name: a}, {name: a}]",
		"devices: [{name: x}]",
		"unknownKey: 1",
		"hosts: [{qmp: /x}]",
		"discovery: {interval: -1s}",
		"detachTimeout: -5s",
	} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	cfg := DefaultConfig()
	if cfg.Listen != "127.0.0.1:9909" || cfg.Pools[0].Dir != "/tmp/fake-cxl-pool" || cfg.StateFile != "/tmp/fake-cxl-pool.state.json" ||
		uint64(*cfg.ExclusiveSerialBase) != 0xc1ee0000 || uint64(*cfg.SharedSerialBase) != 0xc1ae0000 || !cfg.Discovery.QemuEnabled() {
		t.Fatalf("unexpected defaults %+v", cfg)
	}
}

func TestStaticFileBackendBinding(t *testing.T) {
	// two VMs pre-declare the same file as befile_ backends: the config
	// device with that file is bound to both, and attach reuses the object
	dir := t.TempDir()
	file := filepath.Join(dir, "pool", "static0.raw")
	e := &testEnv{t: t, dir: dir, fakes: map[string]*qemu.Fake{}, alive: map[int]bool{101: true, 102: true}}
	obj := "befile_cxl_memdev0__bus_ds0_hb0__sn_0xc1ae0000"
	for i, n := range []string{"vm1", "vm2"} {
		e.procs = append(e.procs, vmCmdline(n, 101+i, "-object", "memory-backend-file,id="+obj+",share=on,mem-path="+file+",size=256M"))
		f := newVMFake()
		f.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: obj, Size: 256 << 20, MemPath: file, Share: true})
		e.fakes["/e2e/"+n+"/qmp.sock"] = f
	}
	cfg, err := ParseConfig([]byte(`
stateFile: "-"
pools: [{name: default, dir: ` + filepath.Join(dir, "pool") + `}]
devices: [{name: static0, size: 256M, shared: true, file: ` + file + `, serial: 0xc1ae0000}]
`))
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	e.start()
	d, _ := e.c.Device(ctx, "static0")
	if d.Scope != api.ScopePool || d.Path != file {
		t.Fatalf("unexpected device %+v", d)
	}
	for _, n := range []string{"vm1", "vm2"} {
		a, _, err := e.c.Attach(ctx, "static0", api.AttachRequest{Host: n})
		if err != nil || a.QemuObjectID != obj || a.Slot.Bus != "ds0_hb0" || a.Serial != "0xc1ae0000" {
			t.Fatalf("attach to %s: %+v %v", n, a, err)
		}
	}
	h, _ := e.c.Host(ctx, "vm2")
	if len(h.LocalDevices) != 1 || h.LocalDevices[0] != "static0" {
		t.Fatalf("unexpected local devices %+v", h.LocalDevices)
	}
	// without a config device, the file backend becomes a shared local device
	e.stop()
	cfg2, _ := ParseConfig([]byte(`
stateFile: "-"
pools: [{name: default, dir: ` + filepath.Join(dir, "pool2") + `}]
`))
	e.cfg = cfg2
	for _, n := range []string{"vm1", "vm2"} {
		f := newVMFake()
		f.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: obj, Size: 256 << 20, MemPath: file, Share: true})
		e.fakes["/e2e/"+n+"/qmp.sock"] = f
	}
	e.start()
	d, err = e.c.Device(ctx, "static0")
	if err != nil || d.Scope != api.ScopeLocal || !d.Shared || len(d.LocalHosts) != 2 || d.Backend != api.BackendFile {
		t.Fatalf("unexpected local file device %+v %v", d, err)
	}
	for _, n := range []string{"vm1", "vm2"} {
		if _, _, err := e.c.Attach(ctx, "static0", api.AttachRequest{Host: n}); err != nil {
			t.Fatalf("attach to %s: %v", n, err)
		}
	}
}

func TestLeakedDetach(t *testing.T) {
	e := newTestEnv(t, "")
	a, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	if err != nil {
		t.Fatal(err)
	}
	f1 := e.fake("vm1")
	f1.LeakOnRelease = true
	f1.Hold(a.QemuDeviceID)
	_, _, err = e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{Timeout: 50 * time.Millisecond})
	mustCode(t, err, api.CodeConflict)
	// the guest removes the device with its memory still online
	f1.Release(a.QemuDeviceID)
	deadline := time.Now().Add(5 * time.Second)
	var cur *api.Attachment
	for {
		cur, err = e.c.DeviceAttachment(ctx, "pooled0", "vm1")
		if err == nil && cur.State == api.AttachmentFailed && strings.Contains(cur.Error, "leaked") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not marked leaked: %+v %v", cur, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(cur.Error, "leaked") {
		t.Fatalf("unexpected error %q", cur.Error)
	}
	d, _ := e.c.Device(ctx, "pooled0")
	if d.State != api.DeviceError {
		t.Fatalf("unexpected device state %s", d.State)
	}
	// not handed to another host, the slot is free for others
	_, _, err = e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm2"})
	mustCode(t, err, api.CodeConflict)
	a2, _, err := e.c.Attach(ctx, "shared0", api.AttachRequest{Host: "vm1", Slot: a.Slot.Bus})
	if err != nil || a2.Slot.Bus != a.Slot.Bus {
		t.Fatalf("slot of a leaked device not reusable: %+v %v", a2, err)
	}
	// forget with force
	_, _, err = e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{})
	mustCode(t, err, api.CodeConflict)
	if _, _, err := e.c.Detach(ctx, "pooled0", "vm1", client.DetachOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	if d, _ := e.c.Device(ctx, "pooled0"); d.State != api.DeviceFree {
		t.Fatalf("unexpected device state %s", d.State)
	}
}

func TestUUIDWithoutDashesAndFilters(t *testing.T) {
	e := newTestEnv(t, "")
	r, err := e.c.Resolve(ctx, "", "6ba7b8109dad11d180b400c04fd430c8")
	if err != nil || r.Name != "vm1" {
		t.Fatalf("resolve by machine-id: %+v %v", r, err)
	}
	if _, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "6BA7B8109DAD11D180B400C04FD430C8"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.c.Detach(ctx, "pooled0", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", client.DetachOptions{}); err != nil {
		t.Fatal(err)
	}
	e.stop()
	e.cfg.Discovery.Names = []string{"vm2*"}
	e.start()
	hs, err := e.c.Hosts(ctx)
	if err != nil || len(hs) != 1 || hs[0].Name != "vm2" {
		t.Fatalf("discovery filter: %+v %v", hs, err)
	}
}

func TestReservedSocketSkipped(t *testing.T) {
	e := newTestEnv(t, "")
	e.stop()
	e.mu.Lock()
	p := vmCmdline("vm3", 103)
	// qmp-e2e.sock first: it must not be used
	p.QMPSockets = append([]string{"/e2e/vm3/qmp-e2e.sock"}, p.QMPSockets...)
	e.procs = append(e.procs, p)
	e.alive[103] = true
	e.fakes["/e2e/vm3/qmp.sock"] = newVMFake()
	e.fakes["/e2e/vm3/qmp-e2e.sock"] = newVMFake()
	e.mu.Unlock()
	e.start()
	h, err := e.c.Host(ctx, "vm3")
	if err != nil || h.QMP != "/e2e/vm3/qmp.sock" || h.State != api.HostRunning {
		t.Fatalf("unexpected host %+v %v", h, err)
	}
}

func TestFMWCapacityAndHotRemove(t *testing.T) {
	e := newTestEnv(t, "")
	e.stop()
	f1 := e.fake("vm1")
	// 512M window on cxlhb0, 256M on cxlhb1 (as reported by qemu)
	f1.FMW = []qemu.FMWWindow{{Targets: []string{"cxlhb0"}, Size: 512 << 20}, {Targets: []string{"cxlhb1"}, Size: 256 << 20}}
	e.fake("vm2").Stock = true
	e.start()
	h1, _ := e.c.Host(ctx, "vm1")
	h2, _ := e.c.Host(ctx, "vm2")
	if !h1.HotRemoveCapable || h2.HotRemoveCapable {
		t.Fatalf("unexpected hotRemoveCapable %v %v", h1.HotRemoveCapable, h2.HotRemoveCapable)
	}
	if h1.HostBridges[0].FMWSize != 512<<20 {
		t.Fatalf("fmw from qemu not used: %+v", h1.HostBridges)
	}
	// pooled0 (512M) fills cxlhb0
	a, _, err := e.c.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1", NumaNode: ptr(0)})
	if err != nil || a.Slot.HostBridge != "cxlhb0" {
		t.Fatalf("attach: %+v %v", a, err)
	}
	// shared0 (256M) does not fit under cxlhb0 any more
	_, _, err = e.c.Attach(ctx, "shared0", api.AttachRequest{Host: "vm1", Slot: "ds1_hb0"})
	mustCode(t, err, api.CodeConflict)
	a, _, err = e.c.Attach(ctx, "shared0", api.AttachRequest{Host: "vm1", NumaNode: ptr(0)})
	if err != nil || a.Slot.HostBridge != "cxlhb1" {
		t.Fatalf("attach falls back to cxlhb1: %+v %v", a, err)
	}
	if _, err := e.c.CreateDevice(ctx, api.DeviceCreate{Name: "d1", Size: 256 << 20}); err != nil {
		t.Fatal(err)
	}
	_, _, err = e.c.Attach(ctx, "d1", api.AttachRequest{Host: "vm1"})
	mustCode(t, err, api.CodeConflict)
	if !strings.Contains(err.Error(), "room") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestZombieNotAdopted(t *testing.T) {
	e := newTestEnv(t, "")
	f1 := e.fake("vm1")
	f1.Stock = true
	a, _, err := e.c.Attach(ctx, "vm1.memdev0", api.AttachRequest{Host: "vm1"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = e.c.Detach(ctx, "vm1.memdev0", "vm1", client.DetachOptions{Timeout: 50 * time.Millisecond})
	mustCode(t, err, api.CodeConflict)
	if _, _, err := e.c.Detach(ctx, "vm1.memdev0", "vm1", client.DetachOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	// the zombie is still in qemu: it must not come back as attached,
	// neither now nor after a server restart
	for i := 0; i < 2; i++ {
		e.srv.Refresh(ctx, true)
		if _, err := e.c.DeviceAttachment(ctx, "vm1.memdev0", "vm1"); !api.IsCode(err, api.CodeNotFound) {
			t.Fatalf("zombie %s adopted (round %d): %v", a.QemuDeviceID, i, err)
		}
		h, _ := e.c.Host(ctx, "vm1")
		if h.Slots[3].Device != a.QemuDeviceID {
			t.Fatalf("zombie slot looks free: %+v", h.Slots[3])
		}
		e.stop()
		e.start()
	}
}
