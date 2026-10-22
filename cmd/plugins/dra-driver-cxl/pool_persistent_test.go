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

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"golang.org/x/sys/unix"
)

// fakeMounter is the mount table and the loop devices of a node. Like the
// kernel it gives a second mount of a source the superblock (and the
// super options) of the first one, and removes an autoclear loop device
// with its last mount.
type fakeMounter struct {
	mu        sync.Mutex
	mounts    []mountInfo
	calls     []string
	loops     map[string]string // loop device -> backing
	nextLoop  int
	mountErr  map[string]error    // source -> error of Mount
	superOpts map[string][]string // source -> super options of a new superblock
	busy      map[string]bool     // targets whose Unmount fails with EBUSY
	bindRoot  string              // the root of a new bind, "": that of its source
	holders   map[string]string   // block device -> holder, like a container's bind mount
	holderErr error               // error of Holder
	detachErr error               // error of Release(true) of a loop device
	bindFlags []string            // the per-mount flags of a new bind, nil: those of its source
}

func newFakeMounter() *fakeMounter {
	return &fakeMounter{
		loops:     map[string]string{},
		mountErr:  map[string]error{},
		superOpts: map[string][]string{},
		busy:      map[string]bool{},
		holders:   map[string]string{},
	}
}

func (m *fakeMounter) call(format string, args ...any) {
	m.calls = append(m.calls, fmt.Sprintf(format, args...))
}

func (m *fakeMounter) Mount(source, target, fstype string, flags uintptr, data string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call("mount %s %s %s 0x%x %s", source, target, fstype, flags, data)
	if err := m.mountErr[source]; err != nil {
		return err
	}
	if _, err := os.Stat(target); err != nil {
		return err
	}
	if flags&unix.MS_BIND != 0 {
		// a bind has the superblock and the per-mount flags of its source
		src := findMount(m.mounts, source)
		if src == nil {
			return unix.EINVAL
		}
		bind := *src
		bind.Target = filepath.Clean(target)
		if m.bindFlags != nil {
			bind.MountFlags = slices.Clone(m.bindFlags)
		}
		if m.bindRoot != "" {
			bind.Root = m.bindRoot
		}
		m.mounts = append(m.mounts, bind)
		return nil
	}
	opts := []string{"ro", data}
	if o, ok := m.superOpts[source]; ok {
		opts = o
	}
	for _, mi := range m.mounts {
		if mi.Source == source {
			opts = mi.SuperOpts
		}
	}
	m.mounts = append(m.mounts, mountInfo{Root: "/", Target: target, FsType: fstype, Source: source, SuperOpts: opts, MountFlags: []string{"ro", "nosuid", "nodev"}})
	return nil
}

func (m *fakeMounter) Unmount(target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call("umount %s", target)
	if m.busy[target] {
		return unix.EBUSY
	}
	mi := findMount(m.mounts, target)
	if mi == nil {
		return unix.EINVAL
	}
	source := mi.Source
	m.mounts = slices.DeleteFunc(m.mounts, func(x mountInfo) bool { return x.Target == target })
	m.autoclear(source)
	return nil
}

// autoclear removes an autoclear loop device without mounts.
func (m *fakeMounter) autoclear(loop string) {
	if _, ok := m.loops[loop]; !ok {
		return
	}
	for _, mi := range m.mounts {
		if mi.Source == loop {
			return
		}
	}
	delete(m.loops, loop)
}

func (m *fakeMounter) Mounts() ([]mountInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.mounts), nil
}

func (m *fakeMounter) Mounted(target string) (*mountInfo, error) {
	mounts, _ := m.Mounts()
	return findMount(mounts, target), nil
}

type fakeLoop struct {
	m    *fakeMounter
	path string
}

func (l *fakeLoop) Path() string { return l.path }

func (l *fakeLoop) Release(detach bool) error {
	l.m.mu.Lock()
	defer l.m.mu.Unlock()
	l.m.call("loop-release %s detach=%v", l.path, detach)
	if detach && l.m.detachErr != nil {
		return l.m.detachErr
	}
	if detach {
		delete(l.m.loops, l.path)
	} else {
		l.m.autoclear(l.path)
	}
	return nil
}

func (m *fakeMounter) AttachLoop(backing string) (loopDevice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path := fmt.Sprintf("/dev/loop%d", m.nextLoop)
	m.nextLoop++
	m.call("loop %s %s", path, backing)
	m.loops[path] = backing
	return &fakeLoop{m: m, path: path}, nil
}

func (m *fakeMounter) LoopBackingFile(loop string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loops[loop], nil
}

func (m *fakeMounter) Holder(dev string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.holderErr != nil {
		return "", m.holderErr
	}
	if h := m.holders[dev]; h != "" {
		return h, nil
	}
	for loop, backing := range m.loops {
		if backing == dev {
			return filepath.Base(loop), nil
		}
	}
	for _, mi := range m.mounts {
		if mi.Source == dev {
			return "in use", nil
		}
	}
	return "", nil
}

// setBusy makes the Unmount of target fail with EBUSY, or not.
func (m *fakeMounter) setBusy(target string, busy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.busy[target] = busy
}

func (m *fakeMounter) callsOf(prefix string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, c := range m.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// The nvdimm region of a pmem region0 of mem0, as the kernel of the e2e
// VMs shows it (see pkg/cxl/memctl/pmem_test.go).
const (
	fakeNdRegionPath = "devices/platform/ACPI0017:00/root0/nvdimm-bridge0/ndbus0/region0"
	fakeNsBytes      = 536870912
	fakePmemBytes    = 534773760
)

// plugPersistent makes mem0 appear with persistent memory.
func (f *fakePoolSys) plugPersistent(serial string) {
	f.plug(serial)
	f.write(fakeMemPath+"/ram/size", "0x0")
	f.write(fakeMemPath+"/pmem/size", "0x20000000")
}

// fsdax gives region0 the fsdax namespace0.0 with map mem and /dev/pmem0.
func (f *fakePoolSys) fsdax() {
	ns := fakeNdRegionPath + "/namespace0.0"
	f.write(ns+"/size", fmt.Sprint(fakeNsBytes))
	f.write(ns+"/holder", "pfn0.0")
	pd := fakeNdRegionPath + "/pfn0.0"
	f.write(pd+"/mode", "ram")
	f.link("bus/nd/devices/pfn0.0", "../../../"+pd)
	f.link(pd+"/driver", f.p("bus/nd/drivers/nd_pmem"))
	f.write(pd+"/block/pmem0/dev", "259:0")
	f.write(pd+"/block/pmem0/size", fmt.Sprint(fakePmemBytes/512))
	f.link("class/block/pmem0", "../../"+pd+"/block/pmem0")
}

// execPmem fakes cxl create-region -t pmem (the nvdimm region with the
// namespace of the labels, or the seed) and ndctl create-namespace.
func (f *fakePoolSys) execPmem(name string, args ...string) (string, bool) {
	cmd := name + " " + strings.Join(args, " ")
	switch {
	case strings.HasPrefix(cmd, "cxl create-region -t pmem "):
		f.write("bus/cxl/devices/region0/target0", "decoder4.0")
		f.write("bus/cxl/devices/region0/pmem_region0/uevent", "")
		f.mkdir("bus/nd/drivers/nd_region")
		f.mkdir("bus/nd/drivers/nd_pmem")
		f.link("bus/nd/devices/region0", "../../../"+fakeNdRegionPath)
		f.write(fakeNdRegionPath+"/init_namespaces", "1/1")
		f.link(fakeNdRegionPath+"/driver", f.p("bus/nd/drivers/nd_region"))
		ns := fakeNdRegionPath + "/namespace0.0"
		f.write(ns+"/size", "0")
		f.write(ns+"/holder", "")
		f.link("bus/nd/devices/namespace0.0", "../../../"+ns)
		if f.labels {
			f.fsdax()
		}
		return `{"region":"region0","size":"512.00 MiB","type":"pmem"}`, true
	case strings.HasPrefix(cmd, "ndctl create-namespace "):
		f.labels = true
		f.fsdax()
		return `{"dev":"namespace0.0","mode":"fsdax","map":"mem","size":534773760,"blockdev":"pmem0"}`, true
	}
	return "", false
}

// removeNdRegion removes the nvdimm region with region0; the labels stay.
func (f *fakePoolSys) removeNdRegion() {
	_ = os.RemoveAll(f.p(fakeNdRegionPath))
	for _, l := range []string{"bus/nd/devices/region0", "bus/nd/devices/namespace0.0", "bus/nd/devices/pfn0.0", "class/block/pmem0"} {
		_ = os.Remove(f.p(l))
	}
}

const (
	persistentSerial = "0xc1ae0001"
	// a shared persistent device with one share, and exclusive
	persistentData = `{"serial":"0xc1ae0001","shared":true,"size":536870912,"persistent":true}`
	writerData     = `{"serial":"0xc1ae0001","shared":true,"size":536870912,"persistent":true,"exclusive":true}`
	blockConfig    = `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"block"}`
	blockROConfig  = `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"block","readOnly":true}`
)

// fsConfig returns a DeviceConfig of mode fs with the access and path.
func fsConfig(access, path string) string {
	return fmt.Sprintf(`{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"fs","readOnly":true,"access":%q,"path":%q}`, access, path)
}

func persistentClaim(uid, data, config string) *resourceapi.ResourceClaim {
	return withConfig(poolClaim(uid, "c-"+uid, "llm0", data), resourceapi.AllocationConfigSourceClaim, nil, config)
}

func TestPoolModeFor(t *testing.T) {
	volatile := &poolDevice{}
	shared := &poolDevice{Shared: true}
	reader := &poolDevice{Shared: true, Persistent: true}
	writer := &poolDevice{Shared: true, Persistent: true, Exclusive: true}
	private := &poolDevice{Persistent: true}
	for _, tc := range []struct {
		cfg  deviceConfig
		dev  *poolDevice
		want string
		err  string
	}{
		{dev: volatile, want: api.ModeNUMA},
		{dev: shared, want: api.ModeDax},
		{cfg: deviceConfig{ReadOnly: true}, dev: shared, want: api.ModeDax},
		{cfg: deviceConfig{Mode: "block"}, dev: writer, want: api.ModeBlock},
		{cfg: deviceConfig{Mode: "block"}, dev: private, want: api.ModeBlock},
		{cfg: deviceConfig{Mode: "block", ReadOnly: true}, dev: reader, want: api.ModeBlock},
		{cfg: deviceConfig{Mode: "fs", ReadOnly: true}, dev: reader, want: api.ModeFs},
		{cfg: deviceConfig{Mode: "fs", ReadOnly: true, Access: "cached", Path: "/models"}, dev: writer, want: api.ModeFs},
		// T1-T7: the config alone, in this order
		{cfg: deviceConfig{Mode: "ext4", Access: "bogus"}, dev: reader, err: `DeviceConfig: invalid mode "ext4" (numa, dax, block or fs)`},
		{cfg: deviceConfig{Mode: "block", Access: "bogus", Path: "rel"}, dev: reader, err: "DeviceConfig: access needs mode fs"},
		{cfg: deviceConfig{Access: "direct"}, dev: volatile, err: "DeviceConfig: access needs mode fs"},
		{cfg: deviceConfig{Mode: "dax", Path: "rel"}, dev: reader, err: "DeviceConfig: path needs mode fs"},
		{cfg: deviceConfig{Mode: "fs", Access: "dax", Path: "rel"}, dev: volatile, err: `DeviceConfig: invalid access "dax" (direct or cached)`},
		{cfg: deviceConfig{Mode: "fs", Path: "/run/cxl/fs"}, dev: volatile,
			err: `DeviceConfig: invalid path "/run/cxl/fs" (an absolute path outside /dev, /proc, /sys, /run/cxl and /var/run/cxl)`},
		{cfg: deviceConfig{Mode: "fs", Access: "cached"}, dev: volatile, err: "DeviceConfig: mode fs is read-only: set readOnly: true (write the device with mode block)"},
		{cfg: deviceConfig{Mode: "numa", ReadOnly: true}, dev: reader, err: "DeviceConfig: readOnly needs mode dax, block or fs"},
		// T8-T10: with the status data
		{cfg: deviceConfig{Mode: "block"}, dev: shared, err: "DeviceConfig: mode block needs a persistent device"},
		{cfg: deviceConfig{Mode: "fs", ReadOnly: true}, dev: volatile, err: "DeviceConfig: mode fs needs a persistent device"},
		{dev: reader, err: "DeviceConfig: a persistent device needs mode block or fs"},
		{cfg: deviceConfig{ReadOnly: true}, dev: private, err: "DeviceConfig: a persistent device needs mode block or fs"},
		{cfg: deviceConfig{Mode: "dax"}, dev: writer, err: "DeviceConfig: a persistent device needs mode block or fs"},
		{cfg: deviceConfig{Mode: "numa"}, dev: private, err: "DeviceConfig: a persistent device needs mode block or fs"},
		{cfg: deviceConfig{Mode: "block"}, dev: reader, err: "DeviceConfig: mode block: a shared device is writable only exclusively (no shares request)"},
		// volatile devices as before
		{cfg: deviceConfig{Mode: "numa"}, dev: shared, err: "DeviceConfig: mode numa: a shared device is used as dax only"},
		{cfg: deviceConfig{ReadOnly: true}, dev: volatile, err: "DeviceConfig: readOnly needs mode dax, block or fs"},
	} {
		got, err := tc.cfg.poolModeFor(tc.dev)
		if (tc.err == "" && (err != nil || got != tc.want)) || (tc.err != "" && (err == nil || err.Error() != tc.err)) {
			t.Errorf("%+v %+v: got %q %v, expected %q %q", tc.cfg, *tc.dev, got, err, tc.want, tc.err)
		}
	}
}

func TestValidFsPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/models": true, "/run/cxl-fs/C1AE0001": true, "/run/cxl-fs": true, "/devices": true, "/run/cxlfs": true, "/a/b": true,
		"": false, "/": false, "models": false, "/models/": false, "/a/../b": false, "/a//b": false,
		"/dev": false, "/dev/pmem0": false, "/proc/1": false, "/sys": false, "/run/cxl": false, "/run/cxl/fs/x": false,
		"/var/run/cxl": false, "/var/run/cxl/fs": false, "/var/run/cxl-fs": true,
	} {
		if got := validFsPath(p); got != want {
			t.Errorf("validFsPath(%q) = %v", p, got)
		}
	}
}

// wantNoMounts checks that the node has no mounts, loop devices and mount
// directories left.
func (e *poolTestEnv) wantNoMounts(t *testing.T, p *poolDriver) {
	t.Helper()
	mounts, _ := e.m.Mounts()
	entries, _ := os.ReadDir(p.mountsDir())
	if len(mounts) != 0 || len(e.m.loops) != 0 || len(entries) != 0 {
		t.Fatalf("mounts %+v, loops %v, mount directories %v left", mounts, e.m.loops, entries)
	}
}

func TestPoolPersistentWriter(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plugPersistent(persistentSerial)
	p := e.driver(t)

	res := prepare(t, p, persistentClaim("w1", writerData, blockConfig))
	noErr(t, res.Err)
	e.f.wantCommand(t, "cxl create-region -t pmem -d decoder0.0 -m mem0")
	e.f.wantCommand(t, "ndctl create-namespace -f -r region0 -m fsdax -M mem")
	cd := e.wantCDIDevice(t, "claim-w1-0", []string{"CXL_C1AE0001_MODE=block", "CXL_C1AE0001_PATH=/dev/pmem0", "CXL_C1AE0001_READONLY=0",
		"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=534773760", "CXL_CLAIM_w1=1"})
	if want := []*cdiSpecs.DeviceNode{{Path: "/dev/pmem0", Type: "b", Major: 259, Minor: 0}}; !reflect.DeepEqual(cd.ContainerEdits.DeviceNodes, want) ||
		len(cd.ContainerEdits.Mounts) != 0 {
		t.Fatalf("CDI device %+v", cd.ContainerEdits)
	}
	data, _ := os.ReadFile(e.stateFile)
	for _, want := range []string{`"persistent": true`, `"ndRegion": "region0"`, `"namespace": "namespace0.0"`, `"blockDevice": "/dev/pmem0"`,
		`"blockMajor": 259`, `"mode": "block"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("state file lacks %s:\n%s", want, data)
		}
	}
	noErr(t, unprepare(t, p, "w1"))
	e.f.wantReleased(t)
	e.wantClean(t, p)

	// a second writer reuses the namespace of the labels
	noErr(t, prepare(t, p, persistentClaim("w2", writerData, blockConfig)).Err)
	if n := strings.Count(e.f.commands(), "ndctl"); n != 1 {
		t.Fatalf("ndctl ran %d times:\n%s", n, e.f.commands())
	}
	noErr(t, unprepare(t, p, "w2"))

	// a read-only block claim: device node "r", never creates a namespace
	noErr(t, prepare(t, p, persistentClaim("r1", persistentData, blockROConfig)).Err)
	cd = e.wantCDIDevice(t, "claim-r1-0", []string{"CXL_C1AE0001_MODE=block", "CXL_C1AE0001_PATH=/dev/pmem0", "CXL_C1AE0001_READONLY=1",
		"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=534773760", "CXL_CLAIM_r1=1"})
	if cd.ContainerEdits.DeviceNodes[0].Permissions != "r" {
		t.Fatalf("read-only device node %+v", cd.ContainerEdits.DeviceNodes[0])
	}
	noErr(t, unprepare(t, p, "r1"))
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
	if strings.Contains(e.f.commands(), "destroy-namespace") {
		t.Fatalf("a namespace was destroyed:\n%s", e.f.commands())
	}
}

func TestPoolPersistentReaders(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plugPersistent(persistentSerial)
	e.f.labels = true // written by a writer earlier
	p := e.driver(t)
	direct := p.nodeMountPath(0xc1ae0001, "direct")
	cached := p.nodeMountPath(0xc1ae0001, "cached")
	if want := filepath.Join(filepath.Dir(e.stateFile), "mounts", "c1ae0001-direct"); direct != want {
		t.Fatalf("node mount %s, expected %s", direct, want)
	}

	noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("", ""))).Err)
	noErr(t, prepare(t, p, persistentClaim("d2", persistentData, fsConfig("direct", "/models"))).Err)
	noErr(t, prepare(t, p, persistentClaim("c1", persistentData, fsConfig("cached", ""))).Err)
	noErr(t, prepare(t, p, persistentClaim("c2", persistentData, fsConfig("cached", ""))).Err)
	if n := strings.Count(e.f.commands(), "create-region"); n != 1 || strings.Contains(e.f.commands(), "ndctl") {
		t.Fatalf("unexpected commands:\n%s", e.f.commands())
	}
	// one mount per access, shared by the claims
	wantCalls := []string{
		fmt.Sprintf("mount /dev/pmem0 %s erofs 0x%x dax=always", direct, fsMountFlags),
		"loop /dev/loop0 /dev/pmem0",
		fmt.Sprintf("mount /dev/loop0 %s erofs 0x%x dax=never", cached, fsMountFlags),
		"loop-release /dev/loop0 detach=false",
	}
	if got := slices.Concat(e.m.callsOf("mount"), e.m.callsOf("loop")); !reflect.DeepEqual(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(wantCalls))) {
		t.Fatalf("mount calls %q, expected %q", got, wantCalls)
	}
	if fsMountFlags != unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV {
		t.Fatalf("mount flags 0x%x", fsMountFlags)
	}
	mount := func(host, ctr string) []*cdiSpecs.Mount {
		return []*cdiSpecs.Mount{{HostPath: host, ContainerPath: ctr, Type: "bind", Options: []string{"bind", "ro", "nosuid", "nodev"}}}
	}
	env := func(uid, path, access string) []string {
		return []string{"CXL_C1AE0001_ACCESS=" + access, "CXL_C1AE0001_MODE=fs", "CXL_C1AE0001_PATH=" + path, "CXL_C1AE0001_READONLY=1",
			"CXL_C1AE0001_SERIAL=0xc1ae0001", "CXL_C1AE0001_SHARED=1", "CXL_C1AE0001_SIZE=534773760", "CXL_CLAIM_" + uid + "=1"}
	}
	for _, c := range []struct{ uid, host, path, access string }{
		{"d1", direct, "/run/cxl-fs/C1AE0001", "direct"},
		{"d2", direct, "/models", "direct"},
		{"c1", cached, "/run/cxl-fs/C1AE0001", "cached"},
	} {
		cd := e.wantCDIDevice(t, "claim-"+c.uid+"-0", env(c.uid, c.path, c.access))
		if !reflect.DeepEqual(cd.ContainerEdits.Mounts, mount(c.host, c.path)) || len(cd.ContainerEdits.DeviceNodes) != 0 {
			t.Fatalf("%s: CDI device %+v", c.uid, cd.ContainerEdits)
		}
	}
	if d := p.prepared["c1"].Devices[0]; d.Access != "cached" || d.NodeMount != cached || d.LoopDevice != "/dev/loop0" || d.Path != "/run/cxl-fs/C1AE0001" {
		t.Fatalf("prepared device %+v", d)
	}

	// the last claim of an access unmounts it, the other access stays
	noErr(t, unprepare(t, p, "d1"))
	noErr(t, unprepare(t, p, "c1"))
	if len(e.m.callsOf("umount")) != 0 {
		t.Fatalf("unmounted while in use: %q", e.m.calls)
	}
	noErr(t, unprepare(t, p, "d2"))
	if got := e.m.callsOf("umount"); !slices.Equal(got, []string{"umount " + direct}) || strings.Contains(e.f.commands(), "disable-region") {
		t.Fatalf("after the last direct claim: %q\n%s", got, e.f.commands())
	}
	// a busy mount fails the Unprepare, the claim stays prepared
	e.m.busy[cached] = true
	wantErr(t, unprepare(t, p, "c2"), "device 0xc1ae0001: unmounting "+cached+": device or resource busy")
	if p.prepared["c2"] == nil || strings.Contains(e.f.commands(), "disable-region") {
		t.Fatalf("busy Unprepare released the device:\n%s", e.f.commands())
	}
	// a holder of the block device (a container's bind mount) fails it too
	e.m.busy[cached] = false
	e.m.holders["/dev/pmem0"] = "in use"
	wantErr(t, unprepare(t, p, "c2"), "device 0xc1ae0001: /dev/pmem0 is still in use")
	if p.prepared["c2"] == nil || strings.Contains(e.f.commands(), "disable-region") || len(e.m.loops) != 0 {
		t.Fatalf("held device released:\n%s\nloops %v", e.f.commands(), e.m.loops)
	}
	delete(e.m.holders, "/dev/pmem0")
	noErr(t, unprepare(t, p, "c2"))
	e.f.wantReleased(t)
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

func TestPoolPersistentSamePreparation(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plugPersistent(persistentSerial)
	e.f.labels = true
	p := e.driver(t)
	noErr(t, prepare(t, p, persistentClaim("r1", persistentData, blockROConfig)).Err)
	noErr(t, prepare(t, p, persistentClaim("r2", persistentData, fsConfig("cached", "/models"))).Err)
	// a volatile preparation of the serial never meets them
	wantErr(t, prepare(t, p, poolClaim("v1", "c-v1", "llm0", sharedPersistentAsVolatile)).Err, "mode dax, but another claim prepared it in mode ")
	// two results of one claim on the serial: one mount, unmounted with it
	claim := persistentClaim("r3", persistentData, fsConfig("direct", ""))
	claim.Status.Allocation.Devices.Results = append(claim.Status.Allocation.Devices.Results,
		resourceapi.DeviceRequestAllocationResult{Request: "mem2", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: "llm0", ConsumedCapacity: poolConsumed(persistentData)})
	noErr(t, prepare(t, p, claim).Err)
	e.wantCDIDevice(t, "claim-r3-2", []string{"CXL_C1AE0001_2_ACCESS=direct", "CXL_C1AE0001_2_MODE=fs", "CXL_C1AE0001_2_PATH=/run/cxl-fs/C1AE0001_2",
		"CXL_C1AE0001_2_READONLY=1", "CXL_C1AE0001_2_SERIAL=0xc1ae0001", "CXL_C1AE0001_2_SHARED=1", "CXL_C1AE0001_2_SIZE=534773760", "CXL_CLAIM_r3=1"})
	if n := len(e.m.callsOf("mount ")); n != 2 {
		t.Fatalf("%d mounts: %q", n, e.m.calls)
	}
	for _, uid := range []string{"r3", "r2", "r1"} {
		noErr(t, unprepare(t, p, uid))
	}
	e.f.wantReleased(t)
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

const sharedPersistentAsVolatile = `{"serial":"0xc1ae0001","shared":true,"size":536870912}`

func TestPoolPersistentErrors(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plugPersistent(persistentSerial)
	p := e.driver(t)
	checkClean := func(what string) {
		t.Helper()
		e.wantClean(t, p)
		e.wantNoMounts(t, p)
		if strings.Count(e.f.commands(), "create-region") != strings.Count(e.f.commands(), "destroy-region") {
			t.Fatalf("%s: region left:\n%s", what, e.f.commands())
		}
	}

	// T12: readers before a writer
	wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig("", ""))).Err,
		"device 0xc1ae0001: no fsdax namespace in region0: has a writer written the device?")
	checkClean("T12 fs")
	wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, blockROConfig)).Err,
		"device 0xc1ae0001: no fsdax namespace in region0: has a writer written the device?")
	checkClean("T12 block")
	if strings.Contains(e.f.commands(), "ndctl") {
		t.Fatalf("a reader created a namespace:\n%s", e.f.commands())
	}

	// T13: no erofs, direct and cached (the loop device is detached)
	e.f.labels = true
	e.m.mountErr["/dev/pmem0"] = unix.EINVAL
	wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig("direct", ""))).Err,
		"device 0xc1ae0001: /dev/pmem0 has no erofs filesystem: invalid argument")
	checkClean("T13 direct")
	e.m.mountErr["/dev/loop0"] = unix.EINVAL
	wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig("cached", ""))).Err,
		"device 0xc1ae0001: /dev/pmem0 has no erofs filesystem: invalid argument")
	if !slices.Contains(e.m.calls, "loop-release /dev/loop0 detach=true") {
		t.Fatalf("loop device not detached: %q", e.m.calls)
	}
	checkClean("T13 cached")

	// T14: another mount of the block device has its superblock without DAX
	delete(e.m.mountErr, "/dev/pmem0")
	e.m.superOpts["/dev/pmem0"] = []string{"ro", "user_xattr", "acl", "dax=never"}
	wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig("direct", ""))).Err,
		"device 0xc1ae0001: erofs on /dev/pmem0 was mounted without DAX")
	checkClean("T14")
	delete(e.m.superOpts, "/dev/pmem0")

	// T11: the status data says persistent, the memdev has no pmem
	e.f.write(fakeMemPath+"/pmem/size", "0x0")
	wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig("direct", ""))).Err,
		"device 0xc1ae0001: mem0 has no persistent memory")
	checkClean("T11")
}

func TestPoolPersistentRestart(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plugPersistent(persistentSerial)
	e.f.labels = true
	p := e.driver(t)
	noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", ""))).Err)
	noErr(t, prepare(t, p, persistentClaim("c1", persistentData, fsConfig("cached", ""))).Err)
	noErr(t, prepare(t, p, persistentClaim("c2", persistentData, fsConfig("cached", ""))).Err)
	nmounts := len(e.m.callsOf("mount "))

	// a restart keeps the mounts
	p = e.driver(t)
	if len(e.m.callsOf("mount ")) != nmounts || len(e.m.callsOf("umount")) != 0 {
		t.Fatalf("restart touched the mounts: %q", e.m.calls)
	}
	// missing mounts are mounted again, a mount of no claim is unmounted
	direct, cached := p.nodeMountPath(0xc1ae0001, "direct"), p.nodeMountPath(0xc1ae0001, "cached")
	e.m.mounts = nil
	e.m.loops = map[string]string{}
	stale := p.nodeMountPath(0xc1ee0002, "direct")
	noErr(t, os.MkdirAll(stale, 0o755))
	noErr(t, e.m.Mount("/dev/pmem7", stale, "erofs", fsMountFlags, "dax=always"))
	p = e.driver(t)
	for _, mnt := range []string{direct, cached} {
		if mi, _ := e.m.Mounted(mnt); mi == nil {
			t.Fatalf("%s not mounted again", mnt)
		}
	}
	if mi, _ := e.m.Mounted(stale); mi != nil || !slices.Contains(e.m.calls, "umount "+stale) {
		t.Fatalf("stale mount left: %q", e.m.calls)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale mount directory left: %v", err)
	}
	// the new loop device is in the state
	if d := p.prepared["c2"].Devices[0]; d.LoopDevice != "/dev/loop1" {
		t.Fatalf("loop device %q after the restart", d.LoopDevice)
	}
	p = e.driver(t)
	if d := p.prepared["c1"].Devices[0]; d.LoopDevice != "/dev/loop1" {
		t.Fatalf("loop device %q not saved", d.LoopDevice)
	}
	for _, uid := range []string{"d1", "c1", "c2"} {
		noErr(t, unprepare(t, p, uid))
	}
	e.f.wantReleased(t)
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

// wantRegion checks whether region0 of the fake sysfs exists.
func (e *poolTestEnv) wantRegion(t *testing.T, exists bool) {
	t.Helper()
	_, err := os.Stat(e.f.p("bus/cxl/devices/region0"))
	if (err == nil) != exists {
		t.Fatalf("region0 exists %v, expected %v:\n%s", err == nil, exists, e.f.commands())
	}
}

func TestPoolPersistentRollbackMultiDevice(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plugPersistent(persistentSerial)
	e.f.labels = true
	p := e.driver(t)
	direct, cached := p.nodeMountPath(0xc1ae0001, "direct"), p.nodeMountPath(0xc1ae0001, "cached")
	// result 0 direct, result 1 (request mem2) cached, whose mount fails
	twoResults := func(uid string) *resourceapi.ResourceClaim {
		c := persistentClaim(uid, persistentData, fsConfig("direct", ""))
		c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
			resourceapi.DeviceRequestAllocationResult{Request: "mem2", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: "llm0", ConsumedCapacity: poolConsumed(persistentData)})
		return withConfig(c, resourceapi.AllocationConfigSourceClaim, []string{"mem2"}, fsConfig("cached", "/cache"))
	}
	e.m.mountErr["/dev/loop0"] = unix.EINVAL
	wantErr(t, prepare(t, p, twoResults("m1")).Err, "device 0xc1ae0001: /dev/pmem0 has no erofs filesystem: invalid argument")
	// the mount of the first result is gone with the region
	e.wantNoMounts(t, p)
	e.wantRegion(t, false)
	e.wantClean(t, p)

	// the mount of the first result is shared with another claim: it stays
	noErr(t, prepare(t, p, persistentClaim("o1", persistentData, fsConfig("direct", ""))).Err)
	e.m.mountErr["/dev/loop1"] = unix.EINVAL
	wantErr(t, prepare(t, p, twoResults("m2")).Err, "has no erofs filesystem")
	if mi, _ := e.m.Mounted(direct); mi == nil {
		t.Fatal("the mount of another claim was unmounted")
	}
	if mi, _ := e.m.Mounted(cached); mi != nil || len(e.m.loops) != 0 {
		t.Fatalf("cached mount %+v, loops %v left", mi, e.m.loops)
	}
	e.wantRegion(t, true)
	noErr(t, unprepare(t, p, "o1"))
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

func TestPoolPersistentRollbackHolder(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plugPersistent(persistentSerial)
	e.f.labels = true
	p := e.driver(t)
	direct := p.nodeMountPath(0xc1ae0001, "direct")

	// T14 under a foreign non-DAX user of the block device: the region
	// stays
	e.m.superOpts["/dev/pmem0"] = []string{"ro", "dax=never"}
	e.m.holders["/dev/pmem0"] = "foreign mount"
	wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig("direct", ""))).Err, "was mounted without DAX")
	e.wantRegion(t, true)
	if strings.Contains(e.f.commands(), "disable-region") {
		t.Fatalf("region released under a holder:\n%s", e.f.commands())
	}
	delete(e.m.holders, "/dev/pmem0")

	// T14 whose unmount fails: the plugin's own mount holds the device
	e.m.busy[direct] = true
	wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig("direct", ""))).Err, "was mounted without DAX")
	e.wantRegion(t, true)
	if mi, _ := e.m.Mounted(direct); mi == nil || strings.Contains(e.f.commands(), "disable-region") {
		t.Fatalf("mount %+v, commands:\n%s", mi, e.f.commands())
	}
	e.m.busy[direct] = false
	noErr(t, e.m.Unmount(direct))
	delete(e.m.superOpts, "/dev/pmem0")

	// T13 cached whose loop device cannot be detached: the loop holds it
	e.m.mountErr["/dev/loop0"] = unix.EINVAL
	e.m.detachErr = errors.New("detach failed")
	wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig("cached", ""))).Err, "has no erofs filesystem")
	e.wantRegion(t, true)
	if len(e.m.loops) != 1 || strings.Contains(e.f.commands(), "disable-region") {
		t.Fatalf("loops %v, commands:\n%s", e.m.loops, e.f.commands())
	}
	e.m.detachErr = nil
	e.m.loops = map[string]string{}
	delete(e.m.mountErr, "/dev/loop0")

	// with nothing left, the next failure releases the region
	e.m.mountErr["/dev/pmem0"] = unix.EINVAL
	wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig("direct", ""))).Err, "has no erofs filesystem")
	e.f.wantReleased(t)
	e.wantClean(t, p)
}

func TestPoolPersistentForeignNodeMount(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plugPersistent(persistentSerial)
	e.f.labels = true
	p := e.driver(t)
	direct, cached := p.nodeMountPath(0xc1ae0001, "direct"), p.nodeMountPath(0xc1ae0001, "cached")
	noErr(t, os.MkdirAll(direct, 0o755))
	noErr(t, os.MkdirAll(cached, 0o755))
	for _, tc := range []struct {
		source, target, fstype, data, access, err string
	}{
		{"tmpfs", direct, "tmpfs", "", "direct", "device 0xc1ae0001: " + direct + " is a tmpfs mount of tmpfs, not of /dev/pmem0"},
		{"/dev/pmem7", direct, "erofs", "dax=always", "direct", "device 0xc1ae0001: " + direct + " is a erofs mount of /dev/pmem7, not of /dev/pmem0"},
		{"/dev/pmem0", direct, "erofs", "dax=never", "direct", "device 0xc1ae0001: erofs on /dev/pmem0 was mounted without DAX"},
		{"/dev/pmem0", cached, "erofs", "dax=never", "cached", "device 0xc1ae0001: " + cached + " is a erofs mount of /dev/pmem0, not of a loop device over /dev/pmem0"},
		{"/dev/loop5", cached, "erofs", "dax=never", "cached", "device 0xc1ae0001: " + cached + " is a erofs mount of /dev/loop5, not of a loop device over /dev/pmem0"},
	} {
		if tc.source == "/dev/loop5" {
			e.m.loops["/dev/loop5"] = "/dev/pmem3"
		}
		noErr(t, e.m.Mount(tc.source, tc.target, tc.fstype, 0, tc.data))
		wantErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig(tc.access, ""))).Err, tc.err)
		// never used, never unmounted
		if mi, _ := e.m.Mounted(tc.target); mi == nil || mi.Source != tc.source || len(e.m.callsOf("umount")) != 0 {
			t.Fatalf("%s: foreign mount touched: %+v %q", tc.source, mi, e.m.calls)
		}
		e.m.mounts = nil
		delete(e.m.loops, "/dev/loop5")
		e.wantClean(t, p)
	}
	// an erofs of the device over a loop device over it is reused
	e.m.loops["/dev/loop5"] = "/dev/pmem0"
	noErr(t, e.m.Mount("/dev/loop5", cached, "erofs", 0, "dax=never"))
	noErr(t, prepare(t, p, persistentClaim("r1", persistentData, fsConfig("cached", ""))).Err)
	if d := p.prepared["r1"].Devices[0]; d.LoopDevice != "/dev/loop5" || len(e.m.callsOf("loop /dev")) != 0 {
		t.Fatalf("prepared %+v, calls %q", d, e.m.calls)
	}
	noErr(t, unprepare(t, p, "r1"))
	e.wantClean(t, p)
}

func TestPoolPersistentRestoreChecks(t *testing.T) {
	e := newPoolTestEnv(t)
	e.f.plugPersistent(persistentSerial)
	e.f.labels = true
	p := e.driver(t)
	noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", ""))).Err)
	direct := p.nodeMountPath(0xc1ae0001, "direct")
	state, _ := os.ReadFile(e.stateFile)
	nmounts := len(e.m.callsOf("mount "))

	// another block device is the namespace's now: not mounted, logged
	e.m.mounts = nil
	e.f.write(fakeNdRegionPath+"/pfn0.0/block/pmem0/dev", "259:4")
	e.driver(t)
	if mi, _ := e.m.Mounted(direct); mi != nil || len(e.m.callsOf("mount ")) != nmounts {
		t.Fatalf("mounted a changed device: %q", e.m.calls)
	}
	if _, err := os.Stat(direct); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mount directory left: %v", err)
	}
	if now, _ := os.ReadFile(e.stateFile); string(now) != string(state) {
		t.Fatalf("state changed:\n%s", now)
	}
	// the region is gone (a reboot): not mounted
	e.f.removeNdRegion()
	_ = os.RemoveAll(e.f.p("bus/cxl/devices/region0"))
	p = e.driver(t)
	if len(e.m.callsOf("mount ")) != nmounts || p.prepared["d1"] == nil {
		t.Fatalf("mounted without a region: %q", e.m.calls)
	}
	noErr(t, unprepare(t, p, "d1"))
	e.wantClean(t, p)
}

func TestWaitNoHolder(t *testing.T) {
	e := newPoolTestEnv(t)
	p := e.driver(t)
	e.m.holders["/dev/pmem0"] = "in use"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantErr(t, p.waitNoHolder(ctx, 0xc1ae0001, "/dev/pmem0", time.Now().Add(time.Minute)),
		"device 0xc1ae0001: /dev/pmem0 is still in use: context canceled")
	// a deadline that has passed: one check, no wait
	start := time.Now()
	wantErr(t, p.waitNoHolder(context.Background(), 0xc1ae0001, "/dev/pmem0", start), "device 0xc1ae0001: /dev/pmem0 is still in use")
	if d := time.Since(start); d > holderPoll {
		t.Fatalf("waited %v after the deadline", d)
	}
	e.m.holderErr = errors.New("sysfs gone")
	wantErr(t, p.waitNoHolder(context.Background(), 0xc1ae0001, "/dev/pmem0", start), "sysfs gone")
	e.m.holderErr = nil
	delete(e.m.holders, "/dev/pmem0")
	noErr(t, p.waitNoHolder(context.Background(), 0xc1ae0001, "/dev/pmem0", start))
}

func TestPoolPersistentSyncFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	e := newPoolTestEnv(t)
	e.f.plugPersistent(persistentSerial)
	e.f.labels = true
	p := e.driver(t)
	dir := filepath.Dir(e.stateFile)
	noErr(t, os.MkdirAll(p.mountsDir(), 0o755))
	noErr(t, os.Chmod(dir, 0o555))
	defer func() { _ = os.Chmod(dir, 0o755) }()
	wantErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", ""))).Err, poolStateFileName)
	e.wantNoMounts(t, p)
	e.f.wantReleased(t)
	if len(p.prepared) != 0 {
		t.Fatalf("prepared %v", p.prepared)
	}
}

// newPoolLeaseEnv returns a pool test env with the persistent device of
// persistentData written by a writer, a pool driver with a lease-fs root,
// and fake hooks that give the lend records of companion claims the
// lease-fs directory of the lease claim lc1 and the name models.
func newPoolLeaseEnv(t *testing.T) (*poolTestEnv, *poolDriver, *fakeHooks) {
	t.Helper()
	e := newPoolTestEnv(t)
	e.leaseFsRoot = filepath.Join(filepath.Dir(e.stateFile), "lease-fs")
	e.f.plugPersistent(persistentSerial)
	e.f.labels = true
	hooks := &fakeHooks{fsDir: filepath.Join(e.leaseFsRoot, "lc1"), name: "models"}
	noErr(t, os.MkdirAll(hooks.fsDir, 0o755))
	return e, e.leaseDriver(t, hooks), hooks
}

// leaseDriver returns a new pool driver, as after a restart, that lends
// companion claims with the hooks.
func (e *poolTestEnv) leaseDriver(t *testing.T, hooks *fakeHooks) *poolDriver {
	t.Helper()
	p := e.driver(t)
	p.lender.set(newFakeLender(testRef), hooks)
	return p
}

// fsCompanion returns the companion claim of lease id of mode fs with the
// access on the persistent device, as the broker writes its DeviceConfig.
func fsCompanion(id, access string) *resourceapi.ResourceClaim {
	cfg := fmt.Sprintf(`{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"fs","readOnly":true,"access":%q}`, access)
	c := persistentClaim("uid-"+companionName(id), persistentData, cfg)
	c.ObjectMeta = companionClaim(id).ObjectMeta
	return c
}

// bindCall returns the call of the fake mounter of a lease bind.
func bindCall(nodeMount, target string) string {
	return fmt.Sprintf("mount %s %s  0x%x ", nodeMount, target, unix.MS_BIND)
}

// TestPoolLeaseBind prepares the companion claim of an fs lease: the node
// mount, then its bind in the lease-fs directory before the broker hears
// of it; the Unprepare unmounts the bind before the node mount and the
// region, and fails while the bind is busy.
func TestPoolLeaseBind(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	direct := p.nodeMountPath(0xc1ae0001, "direct")
	target := filepath.Join(hooks.fsDir, "models")
	uid := "uid-cxl-lease-l1"
	bound := false
	hooks.onPrepared = func(string) {
		mi, _ := e.m.Mounted(target)
		bound = mi != nil
	}
	r := prepare(t, p, fsCompanion("l1", "direct"))
	noErr(t, r.Err)
	e.wantNoCDIDevices(t, r)
	if !bound {
		t.Fatal("the bind did not exist when the broker was told that the companion is prepared")
	}
	// a plain bind of the node mount, which inherits its flags
	wantCalls := []string{fmt.Sprintf("mount /dev/pmem0 %s erofs 0x%x dax=always", direct, fsMountFlags), bindCall(direct, target)}
	if got := e.m.callsOf("mount"); !slices.Equal(got, wantCalls) {
		t.Fatalf("mount calls %q, expected %q", got, wantCalls)
	}
	if mi, _ := e.m.Mounted(target); mi == nil || mi.FsType != "erofs" || mi.Source != "/dev/pmem0" || !slices.Equal(mi.MountFlags, []string{"ro", "nosuid", "nodev"}) {
		t.Fatalf("bind %+v", mi)
	}
	// recorded in the lend and the state file
	if rec := p.prepared[uid].Lend; rec.FsDir != hooks.fsDir || rec.Name != "models" || !slices.Equal(rec.Mounts, []string{target}) {
		t.Fatalf("lend record %+v", rec)
	}
	data, _ := os.ReadFile(e.stateFile)
	for _, want := range []string{`"fsDir": "` + hooks.fsDir + `"`, `"name": "models"`, `"mounts": [`, `"` + target + `"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("state file lacks %s:\n%s", want, data)
		}
	}
	// the broker gets the access and the node mount
	if d := hooks.devs[0]; d.Mode != api.ModeFs || d.Access != api.AccessDirect || d.NodeMount != direct || d.BlockDevice != "/dev/pmem0" || d.Serial != 0xc1ae0001 ||
		d.Size != fakePmemBytes || !d.ReadOnly || d.Node != -1 {
		t.Fatalf("lent device %+v", d)
	}
	if log := hooks.log(); log != "lending l1 cxl-lease-l1\nprepared l1" {
		t.Fatalf("hooks:\n%s", log)
	}

	// the borrower has files of the bind open: the Unprepare fails, the
	// claim, the node mount and the region stay
	e.m.busy[target] = true
	wantErr(t, unprepare(t, p, uid), "cxl-pool.nri.io: unpreparing claim demo/cxl-lease-l1: lease l1: unmounting "+target+": device or resource busy")
	if p.prepared[uid] == nil || strings.Contains(e.f.commands(), "disable-region") {
		t.Fatalf("busy bind: claim %v, commands:\n%s", p.prepared[uid], e.f.commands())
	}
	for _, mnt := range []string{target, direct} {
		if mi, _ := e.m.Mounted(mnt); mi == nil {
			t.Fatalf("%s unmounted while the bind is busy", mnt)
		}
	}
	// kubelet retries: the bind, then the node mount, then the region
	e.m.busy[target] = false
	noErr(t, unprepare(t, p, uid))
	if got := e.m.callsOf("umount"); !slices.Equal(got, []string{"umount " + target, "umount " + target, "umount " + direct}) {
		t.Fatalf("umount calls %q", got)
	}
	e.f.wantReleased(t)
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bind directory left: %v", err)
	}
	if _, err := os.Stat(hooks.fsDir); err != nil {
		t.Fatalf("the lease-fs directory of the lease claim is the broker's: %v", err)
	}
	if log := hooks.log(); !strings.HasSuffix(log, "releasing l1\nreleasing l1") {
		t.Fatalf("hooks:\n%s", log)
	}
	// unbinding again is a no-op
	noErr(t, p.unbindLeaseMounts(&lendRecord{Lease: "l1", Mounts: []string{target}}, ""))
	noErr(t, p.unbindLeaseMounts(nil, ""))

	// a static claim of the same device and access keeps the node mount
	// and the region when the companion is unprepared
	noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", ""))).Err)
	noErr(t, prepare(t, p, fsCompanion("l2", "direct")).Err)
	noErr(t, unprepare(t, p, "uid-cxl-lease-l2"))
	if mi, _ := e.m.Mounted(target); mi != nil {
		t.Fatalf("bind left %+v", mi)
	}
	if mi, _ := e.m.Mounted(direct); mi == nil || strings.Count(e.f.commands(), "disable-region") != 1 {
		t.Fatalf("the static claim lost its node mount or region:\n%s", e.f.commands())
	}
	noErr(t, unprepare(t, p, "d1"))
	e.f.wantReleased(t)
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

// TestPoolLeaseBlock prepares the companion claims of block leases: the
// writer creates the fsdax namespace, a reader of a share finds it; the
// broker gets the block device, nothing is mounted or bound, and the
// companion has no CDI device.
func TestPoolLeaseBlock(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	e.f.labels = false // a fresh device
	for _, c := range []struct {
		data, config string
		readOnly     bool
	}{
		{writerData, blockConfig, false},
		{persistentData, blockROConfig, true},
	} {
		claim := persistentClaim("uid-"+companionName("l1"), c.data, c.config)
		claim.ObjectMeta = companionClaim("l1").ObjectMeta
		r := prepare(t, p, claim)
		noErr(t, r.Err)
		e.wantNoCDIDevices(t, r)
		if d := hooks.devs[0]; d.Mode != api.ModeBlock || d.BlockDevice != "/dev/pmem0" || d.ReadOnly != c.readOnly || d.Size != fakePmemBytes ||
			d.Node != -1 || d.DaxDevice != "" || d.NodeMount != "" || d.Access != "" {
			t.Fatalf("lent device %+v", d)
		}
		if rec := p.prepared["uid-cxl-lease-l1"].Lend; len(rec.Mounts) != 0 || len(rec.Nodes) != 0 {
			t.Fatalf("lend record %+v", rec)
		}
		if calls := e.m.callsOf("mount"); len(calls) != 0 {
			t.Fatalf("mount calls %q", calls)
		}
		noErr(t, unprepare(t, p, "uid-cxl-lease-l1"))
		e.f.wantReleased(t)
		e.wantClean(t, p)
	}
	if n := strings.Count(e.f.commands(), "ndctl create-namespace"); n != 1 {
		t.Fatalf("ndctl create-namespace ran %d times:\n%s", n, e.f.commands())
	}
	e.wantNoMounts(t, p)
}

// TestPoolLeaseBindErrors fails the Prepare of companion claims of fs
// leases whose bind cannot be made, and rolls back everything.
func TestPoolLeaseBindErrors(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	direct := p.nodeMountPath(0xc1ae0001, "direct")
	target := filepath.Join(hooks.fsDir, "models")
	checkClean := func(what string) {
		t.Helper()
		e.wantClean(t, p)
		e.wantNoMounts(t, p)
		e.f.wantReleased(t)
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: bind directory left: %v", what, err)
		}
	}

	// E1: a lease claim of an older driver
	hooks.fsDir = ""
	wantErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err,
		"cxl-pool.nri.io: preparing claim demo/cxl-lease-l1: lease l1: its lease claim has no filesystem directory")
	if !strings.Contains(hooks.log(), "failed l1: lease l1: its lease claim has no filesystem directory") {
		t.Fatalf("lend failure not told:\n%s", hooks.log())
	}
	checkClean("E1")
	hooks.fsDir = filepath.Join(e.leaseFsRoot, "lc1")

	// E2: two fs devices, the first bind is unmounted again
	c := fsCompanion("l2", "direct")
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourceapi.DeviceRequestAllocationResult{Request: "mem2", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: "llm0", ConsumedCapacity: poolConsumed(persistentData)})
	wantErr(t, prepare(t, p, c).Err, "lease l2: more than one filesystem device")
	if !slices.Contains(e.m.calls, "umount "+target) {
		t.Fatalf("first bind not unmounted: %q", e.m.calls)
	}
	checkClean("E2")

	// E3: a foreign mount at the target is neither used nor unmounted
	noErr(t, os.MkdirAll(target, 0o755))
	noErr(t, e.m.Mount("tmpfs", target, "tmpfs", 0, ""))
	n := len(e.m.callsOf("umount " + target))
	wantErr(t, prepare(t, p, fsCompanion("l3", "direct")).Err, "device 0xc1ae0001: "+target+" is a tmpfs mount of tmpfs, not of "+direct)
	if mi, _ := e.m.Mounted(target); mi == nil || mi.Source != "tmpfs" || len(e.m.callsOf("umount "+target)) != n {
		t.Fatalf("foreign mount touched: %+v %q", mi, e.m.calls)
	}
	e.m.mounts = slices.DeleteFunc(e.m.mounts, func(mi mountInfo) bool { return mi.Target == target })
	noErr(t, os.Remove(target))
	checkClean("E3")

	// a bind of the node mount at the target (a Prepare again after a
	// crash before the state was written) is used
	noErr(t, prepare(t, p, fsCompanion("l4", "direct")).Err)
	n = len(e.m.callsOf("mount "))
	delete(p.prepared, "uid-cxl-lease-l4")
	noErr(t, prepare(t, p, fsCompanion("l4", "direct")).Err)
	if len(e.m.callsOf("mount ")) != n || !slices.Equal(p.prepared["uid-cxl-lease-l4"].Lend.Mounts, []string{target}) {
		t.Fatalf("existing bind not used: %q %+v", e.m.calls, p.prepared["uid-cxl-lease-l4"].Lend)
	}
	noErr(t, unprepare(t, p, "uid-cxl-lease-l4"))
	checkClean("existing bind")

	// E4: a bind without the flags of the node mount is unmounted again
	e.m.bindFlags = []string{"ro", "relatime"}
	wantErr(t, prepare(t, p, fsCompanion("l5", "cached")).Err,
		"device 0xc1ae0001: the bind of "+p.nodeMountPath(0xc1ae0001, "cached")+" at "+target+" is not a read-only nosuid nodev erofs mount")
	e.m.bindFlags = nil
	checkClean("E4")

	// a bad name
	hooks.name = ".."
	wantErr(t, prepare(t, p, fsCompanion("l6", "direct")).Err, `lease l6: invalid name ".."`)
	hooks.name = "models"
	checkClean("name")

	// a bind of a failed Prepare that cannot be unmounted holds the
	// region; the next release unmounts it
	c = fsCompanion("l7", "direct")
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourceapi.DeviceRequestAllocationResult{Request: "mem2", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: "llm0", ConsumedCapacity: poolConsumed(persistentData)})
	e.m.setBusy(target, true)
	wantErr(t, prepare(t, p, c).Err, "lease l7: more than one filesystem device")
	if mi, _ := e.m.Mounted(target); mi == nil || !slices.Equal(p.staleBinds, []staleBind{{Target: target, Serial: 0xc1ae0001, BlockDevice: "/dev/pmem0"}}) {
		t.Fatalf("busy bind %+v, stale %v", mi, p.staleBinds)
	}
	e.wantRegion(t, true)
	e.m.setBusy(target, false)
	noErr(t, prepare(t, p, persistentClaim("d1", persistentData, fsConfig("direct", ""))).Err)
	noErr(t, unprepare(t, p, "d1"))
	if len(p.staleBinds) != 0 {
		t.Fatalf("stale binds %v", p.staleBinds)
	}
	checkClean("stale bind")
}

// TestPoolLeaseBindSyncFailure unmounts the bind of a companion claim whose
// state cannot be written.
func TestPoolLeaseBindSyncFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	e, p, hooks := newPoolLeaseEnv(t)
	dir := filepath.Dir(e.stateFile)
	noErr(t, os.MkdirAll(p.mountsDir(), 0o755))
	noErr(t, os.Chmod(dir, 0o555))
	defer func() { _ = os.Chmod(dir, 0o755) }()
	wantErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err, poolStateFileName)
	e.wantNoMounts(t, p)
	e.f.wantReleased(t)
	if len(p.prepared) != 0 || !slices.Contains(e.m.calls, "umount "+filepath.Join(hooks.fsDir, "models")) {
		t.Fatalf("prepared %v, calls %q", p.prepared, e.m.calls)
	}
}

// TestPoolLeaseBindRestart binds missing lease binds again at start and
// unmounts the binds of no prepared claim.
func TestPoolLeaseBindRestart(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	cached := p.nodeMountPath(0xc1ae0001, "cached")
	target := filepath.Join(hooks.fsDir, "models")
	uid := "uid-cxl-lease-l1"
	noErr(t, prepare(t, p, fsCompanion("l1", "cached")).Err)
	if mi, _ := e.m.Mounted(target); mi == nil || mi.Source != "/dev/loop0" {
		t.Fatalf("bind of the cached node mount %+v", mi)
	}
	nmounts := len(e.m.callsOf("mount "))

	// a restart keeps the bind
	e.leaseDriver(t, hooks)
	if len(e.m.callsOf("mount ")) != nmounts || len(e.m.callsOf("umount")) != 0 {
		t.Fatalf("restart touched the mounts: %q", e.m.calls)
	}
	// a missing bind is bound again after its node mount
	e.m.mounts = nil
	e.m.loops = map[string]string{}
	e.leaseDriver(t, hooks)
	if got, want := e.m.callsOf("mount ")[nmounts:], []string{fmt.Sprintf("mount /dev/loop1 %s erofs 0x%x dax=never", cached, fsMountFlags),
		bindCall(cached, target)}; !slices.Equal(got, want) {
		t.Fatalf("mounts after the restart %q, expected %q", got, want)
	}
	if mi, _ := e.m.Mounted(target); mi == nil || mi.Source != "/dev/loop1" {
		t.Fatalf("bind %+v", mi)
	}
	// a bind of no prepared claim (a crash between the bind and the
	// state write) is unmounted, its directory removed
	stale := filepath.Join(e.leaseFsRoot, "lc2", "x")
	noErr(t, os.MkdirAll(stale, 0o755))
	noErr(t, e.m.Mount(cached, stale, "", unix.MS_BIND, ""))
	e.leaseDriver(t, hooks)
	if mi, _ := e.m.Mounted(stale); mi != nil || !slices.Contains(e.m.calls, "umount "+stale) {
		t.Fatalf("stale bind left: %q", e.m.calls)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale bind directory left: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(stale)); err != nil {
		t.Fatalf("the lease-fs directory of a lease claim is the broker's: %v", err)
	}
	if mi, _ := e.m.Mounted(target); mi == nil {
		t.Fatal("the bind of the prepared claim was unmounted")
	}
	// without a lease-fs root nothing is swept
	noErr(t, os.MkdirAll(stale, 0o755))
	noErr(t, e.m.Mount(cached, stale, "", unix.MS_BIND, ""))
	root := e.leaseFsRoot
	e.leaseFsRoot = ""
	e.driver(t)
	if mi, _ := e.m.Mounted(stale); mi == nil {
		t.Fatal("swept without a lease-fs root")
	}
	e.leaseFsRoot = root
	e.leaseDriver(t, hooks)
	if mi, _ := e.m.Mounted(stale); mi != nil {
		t.Fatal("stale bind not swept")
	}
	// without its node mount a bind is not bound again
	e.m.mounts = nil
	e.m.loops = map[string]string{}
	e.f.write(fakeNdRegionPath+"/pfn0.0/block/pmem0/dev", "259:4")
	e.leaseDriver(t, hooks)
	if mi, _ := e.m.Mounted(target); mi != nil {
		t.Fatalf("bound without a node mount: %+v", mi)
	}
	e.f.write(fakeNdRegionPath+"/pfn0.0/block/pmem0/dev", "259:0")
	p = e.leaseDriver(t, hooks)
	if mi, _ := e.m.Mounted(target); mi == nil {
		t.Fatal("not bound again")
	}
	noErr(t, unprepare(t, p, uid))
	e.f.wantReleased(t)
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bind directory left: %v", err)
	}
}

// badConfigClaim is a claim of the persistent device whose DeviceConfig
// fails before any device is touched; its rollback runs releaseDevices.
func badConfigClaim(uid string) *resourceapi.ResourceClaim {
	return persistentClaim(uid, persistentData, `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"ext4"}`)
}

// TestPoolLeaseBindChecks covers the abnormal cases of lease binds: a
// device of mode fs for a lease of another mode, a bind that another
// prepared claim lists, a bind of another root of the erofs, a foreign
// mount stacked on a bind.
func TestPoolLeaseBindChecks(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	target := filepath.Join(hooks.fsDir, "models")

	// the lease is not in mode fs: OnLending gives it no name
	hooks.name = ""
	wantErr(t, prepare(t, p, fsCompanion("l0", "direct")).Err, "lease l0: the device is of mode fs, the lease is not")
	hooks.name = "models"
	e.wantClean(t, p)
	e.wantNoMounts(t, p)

	// a bind that another prepared claim lists is not adopted
	noErr(t, prepare(t, p, fsCompanion("l1", "direct")).Err)
	wantErr(t, prepare(t, p, fsCompanion("l2", "direct")).Err, "device 0xc1ae0001: "+target+" is the bind of another lease")
	if mi, _ := e.m.Mounted(target); mi == nil || len(e.m.callsOf("umount "+target)) != 0 {
		t.Fatalf("the bind of l1 was touched: %+v %q", mi, e.m.calls)
	}
	// nor unmounted by another claim that lists it too
	p.prepared["dup"] = &preparedPoolClaim{ClaimName: "demo/dup", Lend: &lendRecord{Lease: "l9", Mounts: []string{target}}}
	noErr(t, unprepare(t, p, "dup"))
	if mi, _ := e.m.Mounted(target); mi == nil || len(e.m.callsOf("umount "+target)) != 0 {
		t.Fatalf("the bind of l1 was unmounted by another claim: %+v %q", mi, e.m.calls)
	}

	// a foreign mount stacked on the bind stops the unbind
	noErr(t, e.m.Mount("tmpfs", target, "tmpfs", 0, ""))
	releases := strings.Count(e.f.commands(), "disable-region")
	wantErr(t, unprepare(t, p, "uid-cxl-lease-l1"), "lease l1: "+target+" is a tmpfs mount of tmpfs, not a lease bind")
	if p.prepared["uid-cxl-lease-l1"] == nil || len(e.m.callsOf("umount "+target)) != 0 || strings.Count(e.f.commands(), "disable-region") != releases {
		t.Fatalf("unbind went on under a foreign mount: %q\n%s", e.m.calls, e.f.commands())
	}
	e.m.mounts = slices.DeleteFunc(e.m.mounts, func(mi mountInfo) bool { return mi.FsType == "tmpfs" })
	noErr(t, unprepare(t, p, "uid-cxl-lease-l1"))
	e.f.wantReleased(t)
	e.wantClean(t, p)
	e.wantNoMounts(t, p)

	// a bind of another directory of the erofs than the root of the node
	// mount is no lease bind
	e.m.bindRoot = "/sub"
	wantErr(t, prepare(t, p, fsCompanion("l3", "direct")).Err, "is not a read-only nosuid nodev erofs mount")
	e.m.bindRoot = ""
	e.f.wantReleased(t)
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}

// TestPoolLeaseStaleBinds checks that lease binds of no prepared claim
// that cannot be unmounted are unmounted at a later release, and that the
// region of their device is released then when no claim has it.
func TestPoolLeaseStaleBinds(t *testing.T) {
	e, p, hooks := newPoolLeaseEnv(t)
	target := filepath.Join(hooks.fsDir, "models")
	stale := []staleBind{{Target: target, Serial: 0xc1ae0001, BlockDevice: "/dev/pmem0"}}
	// releaseLater runs a release of an unrelated failed Prepare, unbusies
	// the bind before that if unbusy, and checks the result
	releaseLater := func(what string) {
		t.Helper()
		e.wantRegion(t, true)
		e.m.setBusy(target, false)
		wantErr(t, prepare(t, p, badConfigClaim("x-"+what)).Err, `invalid mode "ext4"`)
		if len(p.staleBinds) != 0 {
			t.Fatalf("%s: stale binds %v left", what, p.staleBinds)
		}
		e.f.wantReleased(t)
		e.wantClean(t, p)
		e.wantNoMounts(t, p)
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: bind directory left: %v", what, err)
		}
	}

	// R4: a failed Prepare whose bind is busy; no later claim of the serial
	c := fsCompanion("l1", "direct")
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results,
		resourceapi.DeviceRequestAllocationResult{Request: "mem2", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: "llm0", ConsumedCapacity: poolConsumed(persistentData)})
	e.m.setBusy(target, true)
	wantErr(t, prepare(t, p, c).Err, "lease l1: more than one filesystem device")
	if !slices.Equal(p.staleBinds, stale) {
		t.Fatalf("stale binds %+v", p.staleBinds)
	}
	// a release while the bind is still busy keeps it and the region
	wantErr(t, prepare(t, p, badConfigClaim("x0")).Err, `invalid mode "ext4"`)
	if !slices.Equal(p.staleBinds, stale) || strings.Contains(e.f.commands(), "disable-region") {
		t.Fatalf("stale binds %+v, commands:\n%s", p.staleBinds, e.f.commands())
	}
	releaseLater("failed prepare")

	// R3: a bind that fails its check and cannot be unmounted
	e.m.bindFlags = []string{"ro", "relatime"}
	e.m.setBusy(target, true)
	wantErr(t, prepare(t, p, fsCompanion("l2", "direct")).Err, "is not a read-only nosuid nodev erofs mount")
	e.m.bindFlags = nil
	if !slices.Equal(p.staleBinds, stale) {
		t.Fatalf("stale binds %+v", p.staleBinds)
	}
	releaseLater("failed check")

	// R2: a bind of no prepared claim at start (a crash before the state
	// write) that is busy, of a cached node mount: its block device is the
	// backing device of the loop device
	noErr(t, prepare(t, p, fsCompanion("l3", "cached")).Err)
	delete(p.prepared, "uid-cxl-lease-l3")
	noErr(t, p.save())
	e.m.setBusy(target, true)
	p = e.leaseDriver(t, hooks)
	if !slices.Equal(p.staleBinds, stale) {
		t.Fatalf("stale binds after the restart %+v", p.staleBinds)
	}
	if mi, _ := e.m.Mounted(p.nodeMountPath(0xc1ae0001, "cached")); mi != nil {
		t.Fatalf("node mount of no claim left: %+v", mi)
	}
	releaseLater("restart")

	// a stale bind that a Prepare again adopts is forgotten, not unmounted
	noErr(t, prepare(t, p, fsCompanion("l4", "direct")).Err)
	delete(p.prepared, "uid-cxl-lease-l4")
	p.addStaleBind(staleBind{Target: target, Serial: 0xc1ae0001, BlockDevice: "/dev/pmem0"})
	noErr(t, prepare(t, p, fsCompanion("l4", "direct")).Err)
	wantErr(t, prepare(t, p, badConfigClaim("x1")).Err, `invalid mode "ext4"`)
	if mi, _ := e.m.Mounted(target); mi == nil || len(p.staleBinds) != 0 {
		t.Fatalf("adopted bind %+v, stale binds %v", mi, p.staleBinds)
	}
	noErr(t, unprepare(t, p, "uid-cxl-lease-l4"))
	e.f.wantReleased(t)
	e.wantClean(t, p)
	e.wantNoMounts(t, p)
}
