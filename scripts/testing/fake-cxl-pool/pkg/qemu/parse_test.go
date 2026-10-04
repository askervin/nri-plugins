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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rawSession returns the bytes that a client sees after sending the
// command line in a raw socat capture: everything after the first prompt.
func rawSession(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, hmpPrompt)
	if i < 0 {
		t.Fatalf("%s: no prompt", name)
	}
	return s[i+len(hmpPrompt):]
}

func TestCleanHMPOutput(t *testing.T) {
	out := CleanHMPOutput(rawSession(t, "hmp-raw-info-version.txt"))
	if out != "11.1.1openSUSE Slowroll" {
		t.Fatalf("unexpected version output %q", out)
	}
	if v := NormalizeVersion(out); v != "11.1.1 openSUSE Slowroll" {
		t.Fatalf("unexpected normalized version %q", v)
	}
	if v := NormalizeVersion("10.1.50 v10.1.0-1234-gff076b1e6c"); v != "10.1.50 v10.1.0-1234-gff076b1e6c" {
		t.Fatalf("unexpected normalized version %q", v)
	}
	if out := CleanHMPOutput("device_del x\x1b[K\r\n(qemu) "); out != "" {
		t.Fatalf("expected empty output, got %q", out)
	}
}

func TestParseQtreeBrief(t *testing.T) {
	tree := ParseQtree(CleanHMPOutput(rawSession(t, "hmp-raw-info-qtree.txt")))
	if len(tree.HostBridges) != 2 {
		t.Fatalf("expected 2 host bridges, got %+v", tree.HostBridges)
	}
	if tree.HostBridge("cxlhb0") == nil || tree.HostBridge("cxlhb1") == nil {
		t.Fatalf("missing host bridges: %+v", tree.HostBridges)
	}
	slots := 0
	for _, p := range tree.Ports {
		if p.IsSlot() {
			slots++
		}
	}
	// 2 downstream ports under hb0, 8 under hb1; root ports have switches
	if slots != 10 {
		t.Fatalf("expected 10 slots, got %d: %+v", slots, tree.Ports)
	}
	if rp := tree.Port("cxlrp0hb0"); rp == nil || rp.IsSlot() || rp.Kind != PortRootPort {
		t.Fatalf("root port with a switch must not be a slot: %+v", rp)
	}
	p := tree.Port("cxlsw_ds0_usrp0hb1")
	if p == nil || p.HostBridge != "cxlhb1" || p.Occupant() != "cxl_memdev2.hp3" {
		t.Fatalf("unexpected port: %+v", p)
	}
	if p := tree.Port("cxlsw_ds7_usrp0hb1"); p == nil || p.Occupant() != "" {
		t.Fatalf("expected free port: %+v", p)
	}
	if len(tree.Type3) != 3 {
		t.Fatalf("expected 3 cxl-type3 devices, got %+v", tree.Type3)
	}
	d := tree.Device("cxl_memdev0.hp1")
	if d == nil || d.Bus != "cxlsw_ds0_usrp0hb0" || d.HasSerial {
		t.Fatalf("unexpected device %+v", d)
	}
}

func TestParseQtreeFull(t *testing.T) {
	tree := ParseQtree(CleanHMPOutput(rawSession(t, "hmp-raw-info-qtree-full-crio.txt")))
	if hb := tree.HostBridge("cxlhb1"); hb == nil || hb.NumaNode != 1 {
		t.Fatalf("expected cxlhb1 on numa node 1: %+v", tree.HostBridges)
	}
	if hb := tree.HostBridge("cxlhb0"); hb == nil || hb.NumaNode != 0 {
		t.Fatalf("expected cxlhb0 on numa node 0: %+v", tree.HostBridges)
	}
	d := tree.Device("cxl_memdev2.hp3")
	if d == nil {
		t.Fatalf("cxl_memdev2.hp3 not found: %+v", tree.Type3)
	}
	if d.VolatileMemdev != "beram_cxl_memdev2__bus_cxlsw_ds0_usrp0hb1__sn_0xc100e2e2" ||
		!d.HasSerial || d.Serial != 0xc100e2e2 || d.Bus != "cxlsw_ds0_usrp0hb1" {
		t.Fatalf("unexpected device %+v", d)
	}
	slots := 0
	for _, p := range tree.Ports {
		if p.IsSlot() {
			slots++
		}
	}
	if slots != 4 {
		t.Fatalf("expected 4 slots in crio VM, got %d", slots)
	}
}

func TestParseQtreeRootPortSlot(t *testing.T) {
	text := `bus: main-system-bus
  type System
  dev: pxb-cxl-host, id ""
    bus: cxlhb0
      type pxb-cxl-bus
      dev: cxl-rp, id "cxlrp0hb0"
        bus: cxlrp0hb0
          type CXL
      dev: cxl-rp, id "cxlrp1hb0"
        bus: cxlrp1hb0
          type CXL
          dev: cxl-type3, id "x.hp1"
            volatile-memdev = "/objects/fcp_x.hp1"
            sn = 3253731329 (0xc1f00001)
  dev: q35-pcihost, id ""
    bus: pcie.0
      type PCIE
      dev: pxb-cxl, id "cxlhb0"
        numa_node = 0 (0x0)
`
	tree := ParseQtree(text)
	if len(tree.Ports) != 2 || !tree.Ports[0].IsSlot() || !tree.Ports[1].IsSlot() {
		t.Fatalf("expected 2 root port slots: %+v", tree.Ports)
	}
	if tree.Port("cxlrp1hb0").Occupant() != "x.hp1" {
		t.Fatalf("unexpected occupant")
	}
	d := tree.Device("x.hp1")
	if d == nil || d.VolatileMemdev != "fcp_x.hp1" || d.Serial != 0xc1f00001 || d.Bus != "cxlrp1hb0" {
		t.Fatalf("unexpected device %+v", d)
	}
	if tree.HostBridges[0].NumaNode != 0 {
		t.Fatalf("unexpected numa %+v", tree.HostBridges)
	}
}

func TestParseInfoMemdev(t *testing.T) {
	mds := ParseInfoMemdev(CleanHMPOutput(rawSession(t, "hmp-raw-info-memdev.txt")))
	if len(mds) != 12 {
		t.Fatalf("expected 12 memdevs, got %d", len(mds))
	}
	found := false
	for _, m := range mds {
		if m.ID == "beram_cxl_memdev6__bus_cxlsw_ds4_usrp0hb1__sn_0xc100e2e6" {
			found = true
			if m.Size != 256<<20 || !m.Share {
				t.Fatalf("unexpected memdev %+v", m)
			}
		}
		if m.ID == "membuiltin_0_node_0" && (m.Size != 4<<30 || m.Share) {
			t.Fatalf("unexpected memdev %+v", m)
		}
	}
	if !found {
		t.Fatalf("memdev6 not found")
	}
}

func readCmdline(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func TestParseCmdline(t *testing.T) {
	p := ParseCmdline(readCmdline(t, "cmdline-n4-cxl-containerd.txt"))
	if p.Name != "n4-cxl-fedora-43-containerd" {
		t.Fatalf("unexpected name %q", p.Name)
	}
	if p.ProjectDir != "/home/akervine/github.com/containers/nri-plugins/test/e2e/n4-cxl-fedora-43-containerd" {
		t.Fatalf("unexpected project dir %q", p.ProjectDir)
	}
	if len(p.QMPSockets) != 0 {
		t.Fatalf("unexpected qmp sockets %v", p.QMPSockets)
	}
	if len(p.HMPSockets) != 2 || p.HMPSockets[0] != "monitor.sock" ||
		!strings.HasSuffix(p.HMPSockets[1], "/qemu_socket") {
		t.Fatalf("unexpected hmp sockets %v", p.HMPSockets)
	}
	if len(p.HostBridges) != 2 || p.HostBridgeNuma("cxlhb1") != 1 || p.HostBridges[1].BusNr != 24 {
		t.Fatalf("unexpected host bridges %+v", p.HostBridges)
	}
	if p.FMWSize("cxlhb0") != 4<<30 || p.FMWSize("cxlhb1") != 4<<30 {
		t.Fatalf("unexpected fmws %+v", p.FMWs)
	}
	lbs := p.LocalBackends()
	if len(lbs) != 10 {
		t.Fatalf("expected 10 local backends, got %d", len(lbs))
	}
	lb := lbs[3]
	if lb.Memdev != "cxl_memdev3" || lb.Bus != "cxlsw_ds1_usrp0hb1" || lb.Serial != 0xc100e2e3 ||
		lb.Size != 256<<20 || lb.QomType != MemoryBackendRAM || !lb.Share {
		t.Fatalf("unexpected local backend %+v", lb)
	}
	// daemonized qemu: cwd is "/", sockets are in the project dir
	p.Cwd = "/"
	exists := func(path string) bool { return path == p.ProjectDir+"/monitor.sock" }
	if got := p.ResolvePath("monitor.sock", exists); got != p.ProjectDir+"/monitor.sock" {
		t.Fatalf("unexpected resolved path %q", got)
	}
	p.Cwd = "/some/dir"
	if got := p.ResolvePath("monitor.sock", func(string) bool { return false }); got != "/some/dir/monitor.sock" {
		t.Fatalf("unexpected resolved path %q", got)
	}
}

func TestParseCmdlineQMPAndUUID(t *testing.T) {
	args := []string{"/opt/qemu/bin/qemu-system-x86_64",
		"-name", "guest=vm1,debug-threads=on",
		"-uuid", "6BA7B810-9DAD-11D1-80B4-00C04FD430C8",
		"-qmp", "unix:qmp.sock,server=on,wait=off",
		"-chardev", "socket,id=qmp1,path=/run/vm1.qmp,server=on,wait=off",
		"-mon", "chardev=qmp1,mode=control",
		"-chardev", "socket,id=c2,path=/run/client.sock",
		"-mon", "chardev=c2",
		"-object", `{"qom-type":"memory-backend-file","id":"befile_cxl_memdev0__bus_ds0__sn_0xc1f0ee00","mem-path":"/tmp/fake-cxl-pool/s0.raw","size":268435456,"share":true}`,
		"-device", "cxl-type3,bus=ds0,volatile-memdev=befile_cxl_memdev0__bus_ds0__sn_0xc1f0ee00,id=cxl_memdev0,sn=0xc1f0ee00",
		"-M", "q35,cxl=on,cxl-fmw.0.targets.0=cxlhb0,cxl-fmw.0.targets.1=cxlhb1,cxl-fmw.0.size=8G",
		"-daemonize",
	}
	p := ParseCmdline(args)
	if p.Name != "vm1" || p.UUID != "6ba7b810-9dad-11d1-80b4-00c04fd430c8" {
		t.Fatalf("unexpected name/uuid %q %q", p.Name, p.UUID)
	}
	if len(p.QMPSockets) != 2 || p.QMPSockets[0] != "qmp.sock" || p.QMPSockets[1] != "/run/vm1.qmp" {
		t.Fatalf("unexpected qmp sockets %v", p.QMPSockets)
	}
	if len(p.HMPSockets) != 0 {
		t.Fatalf("client chardev must not be a monitor: %v", p.HMPSockets)
	}
	lbs := p.LocalBackends()
	if len(lbs) != 1 || lbs[0].QomType != MemoryBackendFile || lbs[0].MemPath != "/tmp/fake-cxl-pool/s0.raw" ||
		lbs[0].Size != 256<<20 || !lbs[0].Share || lbs[0].Serial != 0xc1f0ee00 {
		t.Fatalf("unexpected local backends %+v", lbs)
	}
	if p.FMWSize("cxlhb1") != 4<<30 { // 8G interleaved over two host bridges
		t.Fatalf("unexpected fmw %+v", p.FMWs)
	}
}

func TestParseOpts(t *testing.T) {
	o := ParseOpts("memory-backend-file,id=a,mem-path=/tmp/a,,b.raw,share=on,size=1G", "qom-type")
	if o.First != "memory-backend-file" || o.Get("mem-path") != "/tmp/a,b.raw" || o.Get("size") != "1G" {
		t.Fatalf("unexpected opts %+v", o)
	}
	if EscapeOptValue("a,b") != "a,,b" {
		t.Fatalf("bad escape")
	}
	o = ParseOpts("driver=cxl-type3,id=x", "driver")
	if o.First != "cxl-type3" || o.Get("id") != "x" {
		t.Fatalf("unexpected opts %+v", o)
	}
}

func TestDiscoverSelf(t *testing.T) {
	// Discover must not fail on a real /proc, whether or not qemus run.
	if _, err := os.Stat("/proc/self/cmdline"); err != nil {
		t.Skip("no /proc")
	}
	if _, err := Discover("/proc"); err != nil {
		t.Fatal(err)
	}
	if !ProcessAlive("/proc", os.Getpid(), 0) {
		t.Fatal("own process not alive")
	}
}

func TestCommandLines(t *testing.T) {
	b := MemoryBackend{QomType: MemoryBackendFile, ID: "fcp_d0.hp1", Size: 256 << 20, MemPath: "/tmp/p/d0.raw", Share: true}
	if s := HMPObjectAdd(b); s != "object_add memory-backend-file,id=fcp_d0.hp1,size=268435456,share=on,mem-path=/tmp/p/d0.raw" {
		t.Fatalf("unexpected object_add %q", s)
	}
	d := CXLType3{ID: "fcp_d0.hp1", Bus: "ds0", VolatileMemdev: "fcp_d0.hp1", Serial: 0xc1f00001}
	if s := HMPDeviceAdd(d); s != "device_add cxl-type3,bus=ds0,volatile-memdev=fcp_d0.hp1,id=fcp_d0.hp1,sn=0xc1f00001" {
		t.Fatalf("unexpected device_add %q", s)
	}
}

// Review L3, L4: unassigned NUMA nodes (qemu MAX_NODES = 128) are -1, and
// interleaved windows are shared by their targets.
func TestNumaUnassignedAndInterleave(t *testing.T) {
	tree := ParseQtree(`bus: main-system-bus
  dev: q35-pcihost, id ""
    bus: pcie.0
      dev: pxb-cxl, id "cxlhb0"
        numa_node = 128 (0x80)
  dev: pxb-cxl-host, id ""
    bus: cxlhb0
`)
	if len(tree.HostBridges) != 1 || tree.HostBridges[0].NumaNode != -1 {
		t.Fatalf("unexpected host bridges %+v", tree.HostBridges)
	}
	p := ParseCmdline([]string{"qemu-system-x86_64", "-device", "pxb-cxl,id=cxlhb0,bus_nr=12,numa_node=128",
		"-M", "cxl-fmw.0.targets.0=cxlhb0,cxl-fmw.0.targets.1=cxlhb1,cxl-fmw.0.size=4G,cxl-fmw.1.targets.0=cxlhb1,cxl-fmw.1.size=1G"})
	if p.HostBridgeNuma("cxlhb0") != -1 || p.FMWSize("cxlhb0") != 2<<30 || p.FMWSize("cxlhb1") != 3<<30 {
		t.Fatalf("numa %d fmw %d %d", p.HostBridgeNuma("cxlhb0"), p.FMWSize("cxlhb0"), p.FMWSize("cxlhb1"))
	}
}
