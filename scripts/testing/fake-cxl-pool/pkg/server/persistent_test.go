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
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/client"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/pool"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/qemu"
)

const llm0Config = `  - name: llm0
    size: 512Mi
    shared: true
    persistent: true
    serial: 0xc1ae0001
`

// rawDevice returns the JSON object of a device as the server sends it.
func (e *testEnv) rawDevice(name string) map[string]any {
	e.t.Helper()
	resp, err := http.Get(e.hs.URL + "/api/v1/devices/" + name)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		e.t.Fatalf("device %s: %v: %s", name, err, b)
	}
	return m
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

func TestPersistentConfig(t *testing.T) {
	cfg, err := ParseConfig([]byte("pools: [{name: default, dir: /p}]\ndevices:\n" + llm0Config +
		"  - name: vol0\n    size: 256Mi\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Devices[0].Persistent || cfg.Devices[1].Persistent {
		t.Fatalf("unexpected persistent flags %+v", cfg.Devices)
	}
	for bad, want := range map[string]string{
		// the LSA of a file with extension .lsa would be the file itself
		"devices: [{name: a, size: 256Mi, persistent: true, file: /p/a.lsa}]": "would be the data file itself",
		// two persistent devices with the same LSA
		"devices: [{name: a, size: 256Mi, persistent: true, file: /p/x.raw}, {name: b, size: 256Mi, persistent: true, file: /p/x.img}]": `is also a file of device "a"`,
		// an LSA that is the data file of another device
		"devices: [{name: b, size: 256Mi, file: /p/a.lsa}, {name: a, size: 256Mi, persistent: true}]": `label storage area file /p/a.lsa is also a file of device "b"`,
		"devices: [{name: a, size: 256Mi, persistent: yes-please}]":                                   "invalid config",
	} {
		_, err := ParseConfig([]byte("pools: [{name: default, dir: /p}]\n" + bad))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: expected %q, got %v", bad, want, err)
		}
	}
	// a volatile device may have any file name
	if _, err := ParseConfig([]byte("pools: [{name: default, dir: /p}]\ndevices: [{name: a, size: 256Mi, file: /p/a.lsa}]")); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentAttachDetach(t *testing.T) {
	e := newTestEnv(t, llm0Config)
	data := filepath.Join(e.dir, "pool", "llm0.raw")
	lsa := filepath.Join(e.dir, "pool", "llm0.lsa")
	if fileSize(t, data) != 512<<20 || fileSize(t, lsa) != 262144 {
		t.Fatalf("backing files: data %d lsa %d", fileSize(t, data), fileSize(t, lsa))
	}
	d, err := e.c.Device(ctx, "llm0")
	if err != nil || !d.Persistent || d.LSAPath != lsa || d.Path != data {
		t.Fatalf("unexpected device %+v %v", d, err)
	}
	raw := e.rawDevice("llm0")
	if raw["persistent"] != true || raw["lsaPath"] != lsa {
		t.Fatalf("unexpected JSON %v", raw)
	}
	raw = e.rawDevice("pooled0")
	if v, ok := raw["persistent"]; !ok || v != false {
		t.Fatalf("volatile device JSON without persistent false: %v", raw)
	}
	if _, ok := raw["lsaPath"]; ok {
		t.Fatalf("volatile device JSON with lsaPath: %v", raw)
	}
	for _, h := range []string{"vm1", "vm2"} {
		a, _, err := e.c.Attach(ctx, "llm0", api.AttachRequest{Host: h})
		if err != nil || a.QemuDeviceID != "fcp_llm0.hp1" || a.QemuObjectID != "fcp_llm0.hp1" ||
			a.QemuLSAObjectID != "fcp_llm0.hp1-lsa" || a.Serial != "0xc1ae0001" {
			t.Fatalf("attach to %s: %+v %v", h, a, err)
		}
		// every qemu maps the same two files
		want := []string{
			"object_add memory-backend-file,id=fcp_llm0.hp1,size=536870912,share=on,mem-path=" + data,
			"object_add memory-backend-file,id=fcp_llm0.hp1-lsa,size=262144,share=on,mem-path=" + lsa,
			"device_add cxl-type3,bus=" + a.Slot.Bus + ",persistent-memdev=fcp_llm0.hp1,lsa=fcp_llm0.hp1-lsa,id=fcp_llm0.hp1,sn=0xc1ae0001",
		}
		if got := e.fake(h).Commands(); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: qemu commands:\n%s\nwant:\n%s", h, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
	if _, _, err := e.c.Detach(ctx, "llm0", "vm1", client.DetachOptions{}); err != nil {
		t.Fatal(err)
	}
	f1 := e.fake("vm1")
	if got := f1.Commands()[3:]; !reflect.DeepEqual(got, []string{"device_del fcp_llm0.hp1", "object_del fcp_llm0.hp1", "object_del fcp_llm0.hp1-lsa"}) {
		t.Fatalf("detach commands %v", got)
	}
	if f1.HasDevice("fcp_llm0.hp1") || f1.HasObject("fcp_llm0.hp1") || f1.HasObject("fcp_llm0.hp1-lsa") {
		t.Fatalf("left in qemu: %s", f1)
	}
	// a static device keeps its files
	if fileSize(t, data) != 512<<20 || fileSize(t, lsa) != 262144 {
		t.Fatal("backing files changed")
	}
	// a re-attach uses new ids for both backends
	a, _, err := e.c.Attach(ctx, "llm0", api.AttachRequest{Host: "vm1"})
	if err != nil || a.QemuDeviceID != "fcp_llm0.hp2" || !f1.HasObject("fcp_llm0.hp2-lsa") {
		t.Fatalf("re-attach: %+v %v", a, err)
	}
}

func TestPersistentDeviceAddFailure(t *testing.T) {
	e := newTestEnv(t, llm0Config)
	f1 := e.fake("vm1")
	f1.FailDeviceAdd = &qemu.Error{Command: "device_add", Desc: "something broke"}
	_, _, err := e.c.Attach(ctx, "llm0", api.AttachRequest{Host: "vm1"})
	mustCode(t, err, api.CodeUnavailable)
	got := f1.Commands()
	if len(got) != 5 || !strings.HasPrefix(got[2], "device_add ") ||
		!reflect.DeepEqual(got[3:], []string{"object_del fcp_llm0.hp1", "object_del fcp_llm0.hp1-lsa"}) {
		t.Fatalf("qemu commands:\n%s", strings.Join(got, "\n"))
	}
	if f1.HasObject("fcp_llm0.hp1") || f1.HasObject("fcp_llm0.hp1-lsa") {
		t.Fatalf("objects left after failed device_add: %s", f1)
	}
	if d, _ := e.c.Device(ctx, "llm0"); d.State != api.DeviceFree {
		t.Fatalf("unexpected device %+v", d)
	}
	if _, _, err := e.c.Attach(ctx, "llm0", api.AttachRequest{Host: "vm1"}); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestPersistentCreateDelete(t *testing.T) {
	e := newTestEnv(t, "")
	poolDir := filepath.Join(e.dir, "pool")
	d, err := e.c.CreateDevice(ctx, api.DeviceCreate{Name: "p0", Size: 256 << 20, Shared: true, Persistent: true})
	if err != nil || !d.Persistent || d.LSAPath != filepath.Join(poolDir, "p0.lsa") || d.Path != filepath.Join(poolDir, "p0.raw") {
		t.Fatalf("create: %+v %v", d, err)
	}
	if fileSize(t, d.Path) != 256<<20 || fileSize(t, d.LSAPath) != 262144 {
		t.Fatal("backing files not created")
	}
	v, err := e.c.CreateDevice(ctx, api.DeviceCreate{Name: "v0", Size: 256 << 20})
	if err != nil || v.Persistent || v.LSAPath != "" {
		t.Fatalf("volatile create: %+v %v", v, err)
	}
	if _, err := os.Stat(filepath.Join(poolDir, "v0.lsa")); !os.IsNotExist(err) {
		t.Fatalf("volatile device has an LSA file: %v", err)
	}
	// the server restarts: the device stays persistent, a missing LSA file
	// is created again
	e.stop()
	if err := os.Remove(d.LSAPath); err != nil {
		t.Fatal(err)
	}
	e.start()
	r, err := e.c.Device(ctx, "p0")
	if err != nil || !r.Persistent || r.LSAPath != d.LSAPath || fileSize(t, d.LSAPath) != 262144 {
		t.Fatalf("after restart: %+v %v", r, err)
	}
	if err := e.c.DeleteDevice(ctx, "p0", false); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{d.Path, d.LSAPath} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("%s not removed: %v", f, err)
		}
	}
}

func TestPersistentCreateFileClash(t *testing.T) {
	dir := t.TempDir()
	// a config device whose data file is the LSA file that a new
	// persistent device p1 would get
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(dir, "devices:\n  - name: clash\n    size: 256Mi\n    file: "+
		filepath.Join(dir, "pool", "p1.lsa")+"\n"), map[string]qemu.Monitor{"vm1": newVMFake()})
	_, err := srv.CreateDevice(api.DeviceCreate{Name: "p1", Size: 256 << 20, Persistent: true})
	mustCode(t, err, api.CodeConflict)
	if !strings.Contains(err.Error(), `device "clash"`) {
		t.Fatalf("unexpected error %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pool", "p1.raw")); !os.IsNotExist(err) {
		t.Fatalf("data file created for a refused device: %v", err)
	}
	// the name, the serial and the capacity are free again
	if _, err := srv.CreateDevice(api.DeviceCreate{Name: "p1", Size: 256 << 20}); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentAdopt(t *testing.T) {
	e := newTestEnv(t, llm0Config)
	f1 := e.fake("vm1")
	data := filepath.Join(e.dir, "pool", "llm0.raw")
	lsa := filepath.Join(e.dir, "pool", "llm0.lsa")
	// a previous server run (state lost) attached llm0
	f1.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: "fcp_llm0.hp7", Size: 512 << 20, MemPath: data, Share: true})
	f1.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: "fcp_llm0.hp7-lsa", Size: pool.LSASize, MemPath: lsa, Share: true})
	if err := f1.PlugDevice(qemu.CXLType3{ID: "fcp_llm0.hp7", Bus: "ds0_hb0", PersistentMemdev: "fcp_llm0.hp7", LSA: "fcp_llm0.hp7-lsa", Serial: 0xc1ae0001}); err != nil {
		t.Fatal(err)
	}
	e.srv.Refresh(ctx, true)
	a, err := e.c.DeviceAttachment(ctx, "llm0", "vm1")
	if err != nil || !a.Adopted || a.QemuDeviceID != "fcp_llm0.hp7" || a.QemuObjectID != "fcp_llm0.hp7" || a.Serial != "0xc1ae0001" {
		t.Fatalf("not adopted: %+v %v", a, err)
	}
	if a.QemuLSAObjectID != "fcp_llm0.hp7-lsa" {
		t.Fatalf("LSA backend not recorded: %+v", a)
	}
	if _, _, err := e.c.Detach(ctx, "llm0", "vm1", client.DetachOptions{}); err != nil {
		t.Fatal(err)
	}
	cmds := f1.Commands()
	if got := cmds[len(cmds)-3:]; !reflect.DeepEqual(got, []string{"device_del fcp_llm0.hp7", "object_del fcp_llm0.hp7", "object_del fcp_llm0.hp7-lsa"}) {
		t.Fatalf("detach commands %v", got)
	}
	// the counter is above the adopted ids
	a, _, err = e.c.Attach(ctx, "llm0", api.AttachRequest{Host: "vm1"})
	if err != nil || a.QemuDeviceID != "fcp_llm0.hp8" {
		t.Fatalf("attach: %+v %v", a, err)
	}
}

func TestHotplugCounterSeededFromLSA(t *testing.T) {
	dir := t.TempDir()
	f := newVMFake()
	// only the LSA backend of an earlier attach is left (its object-del
	// failed)
	f.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: "fcp_pooled0.hp4-lsa", Size: pool.LSASize, MemPath: filepath.Join(dir, "y.lsa")})
	srv := newServerWith(t, "stateFile: \"-\"\n"+poolConfig(dir, pooled0), map[string]qemu.Monitor{"vm1": f})
	a, _, err := srv.Attach(ctx, "pooled0", api.AttachRequest{Host: "vm1"})
	if err != nil || a.QemuDeviceID != "fcp_pooled0.hp5" {
		t.Fatalf("attach: %+v %v", a, err)
	}
}

func TestPersistentPreDeclaredBackendRefused(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pool", "static0.raw")
	e := &testEnv{t: t, dir: dir, fakes: map[string]*qemu.Fake{}, alive: map[int]bool{101: true}}
	obj := "befile_cxl_memdev0__bus_ds0_hb0__sn_0xc1ae0000"
	e.procs = append(e.procs, vmCmdline("vm1", 101, "-object", "memory-backend-file,id="+obj+",share=on,mem-path="+file+",size=256M"))
	f := newVMFake()
	f.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: obj, Size: 256 << 20, MemPath: file, Share: true})
	e.fakes["/e2e/vm1/qmp.sock"] = f
	cfg, err := ParseConfig([]byte(`
stateFile: "-"
pools: [{name: default, dir: ` + filepath.Join(dir, "pool") + `}]
devices: [{name: static0, size: 256M, shared: true, persistent: true, file: ` + file + `, serial: 0xc1ae0000}]
`))
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	e.start()
	_, _, err = e.c.Attach(ctx, "static0", api.AttachRequest{Host: "vm1"})
	mustCode(t, err, api.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "has no label storage area") || len(f.Commands()) != 0 {
		t.Fatalf("unexpected error %v, qemu commands %v", err, f.Commands())
	}
}

func TestPersistentAdoptOtherLSAName(t *testing.T) {
	e := newTestEnv(t, llm0Config)
	f1 := e.fake("vm1")
	data := filepath.Join(e.dir, "pool", "llm0.raw")
	lsa := filepath.Join(e.dir, "pool", "llm0.lsa")
	// a hand hotplug whose LSA backend does not follow the -lsa naming
	f1.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: "fcp_llm0.hp3", Size: 512 << 20, MemPath: data, Share: true})
	f1.AddObject(qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: "fcp_llm0.labels", Size: pool.LSASize, MemPath: lsa, Share: true})
	if err := f1.PlugDevice(qemu.CXLType3{ID: "fcp_llm0.hp3", Bus: "ds0_hb0", PersistentMemdev: "fcp_llm0.hp3", LSA: "fcp_llm0.labels", Serial: 0xc1ae0001}); err != nil {
		t.Fatal(err)
	}
	e.srv.Refresh(ctx, true)
	a, err := e.c.DeviceAttachment(ctx, "llm0", "vm1")
	if err != nil || !a.Adopted || a.QemuLSAObjectID != "fcp_llm0.labels" {
		t.Fatalf("not adopted with its LSA backend: %+v %v", a, err)
	}
	if _, _, err := e.c.Detach(ctx, "llm0", "vm1", client.DetachOptions{}); err != nil {
		t.Fatal(err)
	}
	cmds := f1.Commands()
	if got := cmds[len(cmds)-2:]; !reflect.DeepEqual(got, []string{"object_del fcp_llm0.hp3", "object_del fcp_llm0.labels"}) {
		t.Fatalf("detach commands %v", cmds)
	}
	if f1.HasObject("fcp_llm0.labels") {
		t.Fatalf("LSA backend left in qemu: %s", f1)
	}
}

func TestPersistentFinalizeWithoutDevice(t *testing.T) {
	e := newTestEnv(t, "")
	if _, err := e.c.CreateDevice(ctx, api.DeviceCreate{Name: "p0", Size: 256 << 20, Persistent: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.c.Attach(ctx, "p0", api.AttachRequest{Host: "vm1"}); err != nil {
		t.Fatal(err)
	}
	// the device record is gone (config reload), then qemu deletes the
	// device: finalize deletes the recorded backends all the same
	e.srv.mu.Lock()
	delete(e.srv.devices, "p0")
	e.srv.mu.Unlock()
	f1 := e.fake("vm1")
	if err := f1.DeviceDel(ctx, "fcp_p0.hp1"); err != nil {
		t.Fatal(err)
	}
	e.srv.Refresh(ctx, true)
	if f1.HasObject("fcp_p0.hp1") || f1.HasObject("fcp_p0.hp1-lsa") {
		t.Fatalf("backends left in qemu: %v", f1.Commands())
	}
}
