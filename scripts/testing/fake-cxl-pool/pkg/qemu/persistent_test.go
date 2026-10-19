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

package qemu

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	pmemData = MemoryBackend{QomType: MemoryBackendFile, ID: "fcp_llm0.hp1", Size: 512 << 20, MemPath: "/pool/llm0.raw", Share: true}
	pmemLSA  = MemoryBackend{QomType: MemoryBackendFile, ID: "fcp_llm0.hp1-lsa", Size: 256 << 10, MemPath: "/pool/llm0.lsa", Share: true}
	pmemDev  = CXLType3{ID: "fcp_llm0.hp1", Bus: "ds0", PersistentMemdev: "fcp_llm0.hp1", LSA: "fcp_llm0.hp1-lsa", Serial: 0xc1ae0001}
)

func TestPersistentCommandLines(t *testing.T) {
	if LSAObjectID("fcp_llm0.hp1") != "fcp_llm0.hp1-lsa" {
		t.Fatalf("LSA id %q", LSAObjectID("fcp_llm0.hp1"))
	}
	if got := HMPObjectAdd(pmemLSA); got != "object_add memory-backend-file,id=fcp_llm0.hp1-lsa,size=262144,share=on,mem-path=/pool/llm0.lsa" {
		t.Fatalf("HMP object_add of the LSA: %s", got)
	}
	if got := HMPDeviceAdd(pmemDev); got != "device_add cxl-type3,bus=ds0,persistent-memdev=fcp_llm0.hp1,lsa=fcp_llm0.hp1-lsa,id=fcp_llm0.hp1,sn=0xc1ae0001" {
		t.Fatalf("HMP device_add: %s", got)
	}
	want := map[string]any{"driver": "cxl-type3", "bus": "ds0", "persistent-memdev": "fcp_llm0.hp1",
		"lsa": "fcp_llm0.hp1-lsa", "id": "fcp_llm0.hp1", "sn": uint64(0xc1ae0001)}
	if got := QMPDeviceAddArgs(pmemDev); !reflect.DeepEqual(got, want) {
		t.Fatalf("QMP device_add: %v", got)
	}
	vol := CXLType3{ID: "fcp_d0.hp1", Bus: "ds0", VolatileMemdev: "fcp_d0.hp1", Serial: 1}
	if _, ok := QMPDeviceAddArgs(vol)["lsa"]; ok {
		t.Fatal("volatile device_add has lsa")
	}
	if got := HMPDeviceAdd(vol); got != "device_add cxl-type3,bus=ds0,volatile-memdev=fcp_d0.hp1,id=fcp_d0.hp1,sn=0x1" {
		t.Fatalf("volatile HMP device_add: %s", got)
	}
	if pmemDev.Memdev() != "fcp_llm0.hp1" || vol.Memdev() != "fcp_d0.hp1" {
		t.Fatal("wrong Memdev")
	}
}

func TestFakePersistentChecks(t *testing.T) {
	ctx := context.Background()
	f := NewFake(map[string]int{"hb0": 0}, map[string]string{"ds0": "hb0", "ds1": "hb0"})
	for _, b := range []MemoryBackend{pmemData, pmemLSA, {QomType: MemoryBackendFile, ID: "other", Size: 1 << 28, MemPath: "/x", Share: true}} {
		if err := f.ObjectAdd(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		d    CXLType3
		want string
	}{
		{CXLType3{ID: "a", Bus: "ds0", Serial: 1}, "at least one memdev property must be set"},
		{CXLType3{ID: "b", Bus: "ds0", PersistentMemdev: "fcp_llm0.hp1", Serial: 1}, "lsa property must be set for persistent devices"},
		{CXLType3{ID: "c", Bus: "ds0", PersistentMemdev: "nosuch", LSA: "fcp_llm0.hp1-lsa", Serial: 1}, "Property 'cxl-type3.persistent-memdev' can't find value 'nosuch'"},
		{CXLType3{ID: "d", Bus: "ds0", PersistentMemdev: "fcp_llm0.hp1", LSA: "nosuch", Serial: 1}, "Property 'cxl-type3.lsa' can't find value 'nosuch'"},
		{CXLType3{ID: "e", Bus: "ds0", PersistentMemdev: "fcp_llm0.hp1", LSA: "fcp_llm0.hp1", Serial: 1}, "memory backend fcp_llm0.hp1 can't be used multiple times."},
	} {
		if err := f.DeviceAdd(ctx, tc.d); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("device_add %+v: expected %q, got %v", tc.d, tc.want, err)
		}
	}
	if err := f.DeviceAdd(ctx, pmemDev); err != nil {
		t.Fatal(err)
	}
	// both backends are in use now
	for _, d := range []CXLType3{
		{ID: "f", Bus: "ds1", PersistentMemdev: "other", LSA: "fcp_llm0.hp1-lsa", Serial: 2},
		{ID: "g", Bus: "ds1", VolatileMemdev: "fcp_llm0.hp1", Serial: 2},
	} {
		if err := f.DeviceAdd(ctx, d); err == nil || !strings.Contains(err.Error(), "can't be used multiple times") {
			t.Fatalf("device_add %+v of a busy backend: %v", d, err)
		}
	}
	for _, id := range []string{pmemData.ID, pmemLSA.ID} {
		if err := f.ObjectDel(ctx, id); err == nil || !strings.Contains(err.Error(), "is in use") {
			t.Fatalf("object_del %s of a busy backend: %v", id, err)
		}
	}
	tree, err := f.QueryTree(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d := tree.Device("fcp_llm0.hp1"); d == nil || d.PersistentMemdev != "fcp_llm0.hp1" || d.LSA != "fcp_llm0.hp1-lsa" ||
		d.VolatileMemdev != "" || d.Memdev() != "fcp_llm0.hp1" {
		t.Fatalf("unexpected tree device %+v", d)
	}
	if err := f.DeviceDel(ctx, pmemDev.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{pmemData.ID, pmemLSA.ID} {
		if err := f.ObjectDel(ctx, id); err != nil {
			t.Fatalf("object_del %s after device_del: %v", id, err)
		}
	}
}

func TestParseQtreePersistent(t *testing.T) {
	text := CleanHMPOutput(rawSession(t, "hmp-raw-info-qtree-full-crio.txt"))
	old := `                    memdev = ""
                    persistent-memdev = ""
                    volatile-memdev = "/objects/beram_cxl_memdev2__bus_cxlsw_ds0_usrp0hb1__sn_0xc100e2e2"
                    lsa = ""`
	if !strings.Contains(text, old) {
		t.Fatal("test data changed: cxl_memdev2.hp3 properties not found")
	}
	text = strings.Replace(text, old, `                    memdev = ""
                    persistent-memdev = "/objects/fcp_llm0.hp1"
                    volatile-memdev = ""
                    lsa = "/objects/fcp_llm0.hp1-lsa"`, 1)
	tree := ParseQtree(text)
	d := tree.Device("cxl_memdev2.hp3")
	if d == nil || d.PersistentMemdev != "fcp_llm0.hp1" || d.LSA != "fcp_llm0.hp1-lsa" || d.VolatileMemdev != "" ||
		d.Memdev() != "fcp_llm0.hp1" {
		t.Fatalf("unexpected persistent device %+v", d)
	}
	v := tree.Device("cxl_memdev1.hp2")
	if v == nil || v.PersistentMemdev != "" || v.LSA != "" || v.Memdev() != "beram_cxl_memdev1__bus_cxlsw_ds1_usrp0hb0__sn_0xc100e2e1" {
		t.Fatalf("unexpected volatile device %+v", v)
	}
}

func TestQMPPersistent(t *testing.T) {
	srv := newFakeQMPServer(t)
	srv.qom = true
	q := NewQMP(srv.path, t.Logf)
	q.IdleTimeout = 0
	defer q.Close()
	ctx := context.Background()
	for _, b := range []MemoryBackend{pmemData, pmemLSA} {
		if err := q.ObjectAdd(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	d := pmemDev
	d.Bus = "ds1"
	if err := q.DeviceAdd(ctx, d); err != nil {
		t.Fatal(err)
	}
	var oa []map[string]any
	for _, r := range srv.requests("object-add") {
		var args map[string]any
		_ = json.Unmarshal(r["arguments"], &args)
		oa = append(oa, args)
	}
	if len(oa) != 2 || oa[1]["id"] != "fcp_llm0.hp1-lsa" || oa[1]["mem-path"] != "/pool/llm0.lsa" ||
		oa[1]["size"] != float64(262144) || oa[1]["share"] != true || oa[1]["qom-type"] != MemoryBackendFile {
		t.Fatalf("unexpected object-add requests %v", oa)
	}
	da := srv.requests("device_add")
	var args map[string]any
	if len(da) != 1 || json.Unmarshal(da[0]["arguments"], &args) != nil {
		t.Fatalf("unexpected device_add requests %v", da)
	}
	if args["persistent-memdev"] != "fcp_llm0.hp1" || args["lsa"] != "fcp_llm0.hp1-lsa" || args["volatile-memdev"] != nil {
		t.Fatalf("unexpected device_add arguments %v", args)
	}
	tree, err := q.QueryTree(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if td := tree.Device("fcp_llm0.hp1"); td == nil || td.PersistentMemdev != "fcp_llm0.hp1" || td.LSA != "fcp_llm0.hp1-lsa" || td.VolatileMemdev != "" {
		t.Fatalf("unexpected QOM tree device %+v", td)
	}
	if err := q.DeviceDel(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := q.WaitDeviceDeleted(wctx, d.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{pmemData.ID, pmemLSA.ID} {
		if err := q.ObjectDel(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	var seq []string
	srv.mu.Lock()
	reqs := append([]map[string]json.RawMessage(nil), srv.reqs...)
	srv.mu.Unlock()
	for _, r := range reqs {
		var c string
		_ = json.Unmarshal(r["execute"], &c)
		if c == "object-add" || c == "device_add" || c == "device_del" || c == "object-del" {
			var a map[string]any
			_ = json.Unmarshal(r["arguments"], &a)
			seq = append(seq, c+" "+a["id"].(string))
		}
	}
	want := []string{"object-add fcp_llm0.hp1", "object-add fcp_llm0.hp1-lsa", "device_add fcp_llm0.hp1",
		"device_del fcp_llm0.hp1", "object-del fcp_llm0.hp1", "object-del fcp_llm0.hp1-lsa"}
	if !reflect.DeepEqual(seq, want) {
		t.Fatalf("QMP sequence %v, want %v", seq, want)
	}
}

func TestHMPPersistent(t *testing.T) {
	srv := newFakeHMPServer(t, func(cmd string) string {
		if strings.HasPrefix(cmd, "device_add") || strings.HasPrefix(cmd, "object_add") ||
			strings.HasPrefix(cmd, "device_del") || strings.HasPrefix(cmd, "object_del") {
			return ""
		}
		return "unknown command: '" + cmd + "'"
	})
	h := NewHMP(srv.path, t.Logf)
	ctx := context.Background()
	for _, b := range []MemoryBackend{pmemData, pmemLSA} {
		if err := h.ObjectAdd(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.DeviceAdd(ctx, pmemDev); err != nil {
		t.Fatal(err)
	}
	if err := h.DeviceDel(ctx, pmemDev.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{pmemData.ID, pmemLSA.ID} {
		if err := h.ObjectDel(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"object_add memory-backend-file,id=fcp_llm0.hp1,size=536870912,share=on,mem-path=/pool/llm0.raw",
		"object_add memory-backend-file,id=fcp_llm0.hp1-lsa,size=262144,share=on,mem-path=/pool/llm0.lsa",
		"device_add cxl-type3,bus=ds0,persistent-memdev=fcp_llm0.hp1,lsa=fcp_llm0.hp1-lsa,id=fcp_llm0.hp1,sn=0xc1ae0001",
		"device_del fcp_llm0.hp1",
		"object_del fcp_llm0.hp1",
		"object_del fcp_llm0.hp1-lsa",
	}
	if got := srv.commands(); !reflect.DeepEqual(got, want) {
		t.Fatalf("HMP commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
