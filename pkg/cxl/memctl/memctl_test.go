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

package memctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeSys builds a sysfs tree like the one of an e2e VM with one hotplugged
// CXL memory device, and fakes the cxl and daxctl tools and the dax bus
// attributes on top of it.
type fakeSys struct {
	t       *testing.T
	root    string
	mu      sync.Mutex
	cmds    []string
	writes  []string // dax bus driver attributes written
	nextDax int      // id of the next dax device that dax_region/create makes
}

func (f *fakeSys) p(rel string) string { return filepath.Join(f.root, rel) }

func (f *fakeSys) write(rel, val string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(f.p(rel)), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.p(rel), []byte(val+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeSys) link(rel, target string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(f.p(rel)), 0o755); err != nil {
		f.t.Fatal(err)
	}
	_ = os.Remove(f.p(rel))
	if err := os.Symlink(target, f.p(rel)); err != nil {
		f.t.Fatal(err)
	}
}

const memPath = "devices/pci0000:0c/0000:0c:00.0/0000:0d:00.0/0000:0e:00.0/0000:0f:00.0/mem0"

func newFakeSys(t *testing.T) *fakeSys {
	f := &fakeSys{t: t, root: t.TempDir()}
	f.write("devices/system/memory/block_size_bytes", "8000000")
	for _, b := range []int{74, 75} {
		f.write("devices/system/memory/memory"+itoa(b)+"/state", "offline")
	}
	f.write("bus/cxl/devices/decoder0.0/devtype", "cxl_decoder_root")
	f.write("bus/cxl/devices/decoder0.0/target_list", "12")
	f.write("bus/cxl/devices/decoder0.1/devtype", "cxl_decoder_root")
	f.write("bus/cxl/devices/decoder0.1/target_list", "24")
	_ = os.MkdirAll(f.p("bus/cxl/drivers/cxl_mem"), 0o755)
	_ = os.MkdirAll(f.p("bus/dax/drivers/kmem"), 0o755)
	_ = os.MkdirAll(f.p("bus/dax/drivers/device_dax"), 0o755)
	return f
}

func itoa(i int) string { return strconv.Itoa(i) }

// plug makes mem0 with the serial appear, with its endpoint and driver.
func (f *fakeSys) plug(serial string) {
	f.write(memPath+"/serial", serial)
	f.link("bus/cxl/devices/mem0", "../../../"+memPath)
	f.link(memPath+"/driver", "../../../../../../../bus/cxl/drivers/cxl_mem")
	_ = os.MkdirAll(f.p("bus/cxl/devices/endpoint4"), 0o755)
	f.link("bus/cxl/devices/endpoint4/uport", "../../../../"+memPath)
}

const (
	daxRegionPath = "bus/cxl/devices/region0/dax_region0"
	daxAttrsPath  = daxRegionPath + "/dax_region"
	regionBytes   = 0x10000000
	daxAlign      = 2 << 20
)

// addDax makes a dax device of region0 appear, unbound.
func (f *fakeSys) addDax(name string, size uint64) {
	d := daxRegionPath + "/" + name
	_, id, _ := strings.Cut(name, ".")
	f.write(d+"/size", strconv.FormatUint(size, 10))
	f.write(d+"/target_node", "2")
	f.write(d+"/dev", "252:"+id)
	f.write(d+"/resource", "0x250000000")
	f.link("bus/dax/devices/"+name, "../../../"+d)
}

func (f *fakeSys) daxSize(name string) uint64 {
	v, _ := readUint(f.p(daxRegionPath + "/" + name + "/size"))
	return v
}

func (f *fakeSys) daxBound(name string) bool {
	_, err := os.Lstat(f.p(daxRegionPath + "/" + name + "/driver"))
	return err == nil
}

func (f *fakeSys) bindDax(name, driver string) {
	f.link(daxRegionPath+"/"+name+"/driver", "../../../../../dax/drivers/"+driver)
}

// available returns the bytes of region0 that no dax device holds, and
// writes it to dax_region/available_size.
func (f *fakeSys) available() uint64 {
	free := uint64(regionBytes)
	m, _ := filepath.Glob(f.p(daxRegionPath + "/dax0.*"))
	for _, d := range m {
		free -= f.daxSize(filepath.Base(d))
	}
	f.write(daxAttrsPath+"/available_size", strconv.FormatUint(free, 10))
	return free
}

// writeAttr writes a sysfs attribute, doing what the kernel does for the
// attributes of the dax bus.
func (f *fakeSys) writeAttr(path, val string) error {
	rel, err := filepath.Rel(f.root, path)
	if err != nil {
		return err
	}
	dir, attr := filepath.Dir(rel), filepath.Base(rel)
	switch {
	case dir == daxAttrsPath && attr == "create":
		if val != "1" {
			return syscall.EINVAL
		}
		if f.available() == 0 {
			return syscall.ENOSPC
		}
		name := "dax0." + itoa(f.nextDax)
		f.nextDax++
		f.addDax(name, 0)
		f.write(daxAttrsPath+"/create", name)
		return nil
	case dir == daxAttrsPath && attr == "delete":
		if _, err := os.Stat(f.p(daxRegionPath + "/" + val)); err != nil {
			return syscall.ENXIO
		}
		if f.daxBound(val) || f.daxSize(val) != 0 || strings.HasSuffix(val, ".0") {
			return syscall.EBUSY
		}
		_ = os.RemoveAll(f.p(daxRegionPath + "/" + val))
		_ = os.Remove(f.p("bus/dax/devices/" + val))
		f.available()
		return nil
	case filepath.Dir(dir) == "bus/dax/devices" && attr == "mapping":
		return f.mapDax(filepath.Base(dir), val)
	case filepath.Dir(dir) == "bus/dax/devices" && attr == "size":
		name := filepath.Base(dir)
		size, err := strconv.ParseUint(val, 0, 64)
		switch {
		case err != nil || size%daxAlign != 0:
			return syscall.EINVAL
		case f.daxBound(name):
			return syscall.EBUSY
		case size > f.daxSize(name) && size-f.daxSize(name) > f.available():
			return syscall.ENOSPC
		}
		f.write(daxRegionPath+"/"+name+"/size", val)
		f.available()
		return nil
	case filepath.Dir(dir) == "bus/dax/drivers":
		f.writes = append(f.writes, rel)
		driver := filepath.Base(dir)
		switch attr {
		case "unbind":
			t, err := os.Readlink(f.p(daxRegionPath + "/" + val + "/driver"))
			if err != nil || filepath.Base(t) != driver {
				return syscall.ENODEV
			}
			_ = os.Remove(f.p(daxRegionPath + "/" + val + "/driver"))
		case "new_id", "bind":
			switch {
			case f.daxBound(val):
				return syscall.EBUSY
			case f.daxSize(val) == 0 && attr == "bind":
				return syscall.ENXIO
			case f.daxSize(val) > 0:
				f.bindDax(val, driver)
			}
		}
		return nil
	}
	return os.WriteFile(path, []byte(val), 0o644)
}

// daxRanges returns the memory of the dax devices of region0: their
// mappingN, or resource and size.
func (f *fakeSys) daxRanges() []Range {
	var out []Range
	devs, _ := filepath.Glob(f.p(daxRegionPath + "/dax0.*"))
	for _, d := range devs {
		maps, _ := filepath.Glob(d + "/mapping[0-9]*")
		for _, m := range maps {
			start, _ := readUint(m + "/start")
			end, _ := readUint(m + "/end")
			out = append(out, Range{Start: start, End: end})
		}
		if size := f.daxSize(filepath.Base(d)); len(maps) == 0 && size > 0 {
			start, _ := readUint(d + "/resource")
			out = append(out, Range{Start: start, End: start + size - 1})
		}
	}
	return out
}

// mapDax adds the memory "start-end" (hex) to an unbound dax device, as
// the kernel's mapping attribute does: a range that is taken fails with
// ENOMEM, a length that is not a multiple of the align is ignored.
func (f *fakeSys) mapDax(name, val string) error {
	s, e, ok := strings.Cut(val, "-")
	start, err1 := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	end, err2 := strconv.ParseUint(strings.TrimPrefix(e, "0x"), 16, 64)
	switch {
	case !ok || err1 != nil || err2 != nil || end < start:
		return syscall.EINVAL
	case f.daxBound(name):
		return syscall.EBUSY
	case (end-start+1)%daxAlign != 0:
		return nil
	}
	for _, r := range f.daxRanges() {
		if start <= r.End && r.Start <= end {
			return syscall.ENOMEM
		}
	}
	d := daxRegionPath + "/" + name
	maps, _ := filepath.Glob(f.p(d + "/mapping[0-9]*"))
	m := d + "/mapping" + itoa(len(maps))
	f.write(m+"/start", "0x"+strconv.FormatUint(start, 16))
	f.write(m+"/end", "0x"+strconv.FormatUint(end, 16))
	if len(maps) == 0 {
		f.write(d+"/resource", "0x"+strconv.FormatUint(start, 16))
	}
	f.write(d+"/size", strconv.FormatUint(f.daxSize(name)+end-start+1, 10))
	f.available()
	return nil
}

func (f *fakeSys) exec(ctx context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	f.mu.Unlock()
	switch name + " " + args[0] {
	case "cxl create-region":
		f.write("bus/cxl/devices/region0/target0", "decoder4.0")
		f.write("bus/cxl/devices/region0/resource", "0x250000000")
		f.write("bus/cxl/devices/region0/size", "0x10000000")
		f.write(daxAttrsPath+"/align", itoa(daxAlign))
		f.write(daxAttrsPath+"/create", "")
		f.addDax("dax0.0", regionBytes)
		f.available()
		f.bindDax("dax0.0", "kmem")
		f.nextDax = 1
		return `[{"region":"region0","resource":"0x250000000","size":"256.00 MiB"}]` + "\ncxl region: cmd_create_region: created 1 region\n", nil
	case "cxl disable-region", "cxl enable-memdev":
		if args[0] == "enable-memdev" {
			f.link(memPath+"/driver", "../../../../../../../bus/cxl/drivers/cxl_mem")
		}
		return "", nil
	case "cxl destroy-region":
		_ = os.RemoveAll(f.p("bus/cxl/devices/region0"))
		m, _ := filepath.Glob(f.p("bus/dax/devices/dax0.*"))
		for _, d := range m {
			_ = os.Remove(d)
		}
		return "", nil
	case "cxl disable-memdev":
		_ = os.Remove(f.p(memPath + "/driver"))
		return "", nil
	case "daxctl reconfigure-device":
		drv := "kmem"
		if strings.Contains(strings.Join(args, " "), "--mode=devdax") {
			drv = "device_dax"
		}
		f.bindDax(args[len(args)-1], drv)
		return "", nil
	}
	return "", errors.New("unexpected command " + name + " " + strings.Join(args, " "))
}

func (f *fakeSys) manager() *Manager {
	return &Manager{
		SysRoot:      f.root,
		DevRoot:      "/dev",
		Exec:         f.exec,
		LookPath:     func(string) (string, error) { return "/usr/bin/daxctl", nil },
		PollInterval: 5 * time.Millisecond,
		Logf:         f.t.Logf,
		WriteFile:    f.writeAttr,
	}
}

func (f *fakeSys) commands() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.cmds, "\n")
}

func TestFindAndWait(t *testing.T) {
	f := newFakeSys(t)
	g := f.manager()
	if _, err := g.FindMemdev(0xc1f00001); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		f.plug("0xc1f00001")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := g.WaitMemdev(ctx, 0xc1f00001)
	if err != nil || m != "mem0" {
		t.Fatalf("wait: %q %v", m, err)
	}
	tctx, tcancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer tcancel()
	if _, err := g.WaitMemdev(tctx, 0x1234); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout, got %v", err)
	}
	if ep, err := g.endpoint("mem0"); err != nil || ep != "endpoint4" {
		t.Fatalf("endpoint %q %v", ep, err)
	}
	if uid, err := g.hostBridgeUID("mem0"); err != nil || uid != 12 {
		t.Fatalf("uid %d %v", uid, err)
	}
	if d, err := g.RootDecoder("mem0", RegionRAM); err != nil || d != "decoder0.0" {
		t.Fatalf("root decoder %q %v", d, err)
	}
}

func TestRegionNUMAOnlineRelease(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc1f00001")
	g := f.manager()
	ctx := context.Background()
	ri, err := g.CreateRegion(ctx, "mem0", ModeNUMA, "")
	if err != nil {
		t.Fatal(err)
	}
	if ri.Region != "region0" || ri.Dax != "dax0.0" || ri.Driver != DriverKmem || ri.Mode != ModeNUMA || ri.Node != 2 ||
		len(ri.Blocks) != 2 || ri.Blocks[0] != 74 {
		t.Fatalf("unexpected region info %+v", ri)
	}
	if !strings.Contains(f.commands(), "cxl create-region -t ram -d decoder0.0 -m mem0") {
		t.Fatalf("unexpected commands:\n%s", f.commands())
	}
	// idempotent
	if _, err := g.CreateRegion(ctx, "mem0", ModeNUMA, ""); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(f.commands(), "create-region"); n != 1 {
		t.Fatalf("region created %d times", n)
	}
	if _, err := g.Online("mem0", true); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"74", "75"} {
		if st, _ := readTrim(f.p("devices/system/memory/memory" + b + "/state")); st != "online_movable" {
			t.Fatalf("memory%s state %q", b, st)
		}
		// the kernel shows "online" for online_movable blocks
		f.write("devices/system/memory/memory"+b+"/state", "online")
	}
	// review L5: a block onlined in another zone is not "online movable"
	f.write("devices/system/memory/memory75/valid_zones", "Normal")
	if _, err := g.Online("mem0", true); err == nil || !strings.Contains(err.Error(), "zone Normal") {
		t.Fatalf("online --movable accepted a Normal block: %v", err)
	}
	f.write("devices/system/memory/memory75/valid_zones", "Movable")
	if _, err := g.Online("mem0", true); err != nil {
		t.Fatal(err)
	}
	if err := g.Release(ctx, "mem0"); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"74", "75"} {
		if st, _ := readTrim(f.p("devices/system/memory/memory" + b + "/state")); st != "offline" {
			t.Fatalf("memory%s state %q after release", b, st)
		}
	}
	want := "cxl disable-region region0\ncxl destroy-region region0\ncxl disable-memdev mem0"
	if !strings.HasSuffix(f.commands(), want) {
		t.Fatalf("unexpected commands:\n%s", f.commands())
	}
	// releasing again, or a missing device, is fine
	if err := g.Release(ctx, "mem0"); err != nil {
		t.Fatal(err)
	}
	if err := g.Release(ctx, "mem7"); err != nil {
		t.Fatal(err)
	}
}

func TestRegionDax(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc1f00001")
	_ = os.Remove(f.p(memPath + "/driver")) // disabled memdev gets enabled
	g := f.manager()
	ri, err := g.CreateRegion(context.Background(), "mem0", ModeDax, "decoder0.0")
	if err != nil {
		t.Fatal(err)
	}
	if ri.Driver != DriverDeviceDax || ri.Mode != ModeDax || ri.Device != "/dev/dax0.0" {
		t.Fatalf("unexpected region info %+v", ri)
	}
	_ = os.Remove(f.p(daxRegionPath + "/dax0.0/dev"))
	if _, _, err := g.DaxDevNumbers("dax0.0"); err == nil {
		t.Fatal("expected an error for a missing dev file")
	}
	f.write("bus/cxl/devices/region0/dax_region0/dax0.0/dev", "251:3")
	if ma, mi, err := g.DaxDevNumbers("dax0.0"); err != nil || ma != 251 || mi != 3 {
		t.Fatalf("dax device numbers %d:%d %v", ma, mi, err)
	}
	f.write("bus/cxl/devices/region0/dax_region0/dax0.0/dev", "bogus")
	if _, _, err := g.DaxDevNumbers("dax0.0"); err == nil {
		t.Fatal("expected a parse error")
	}
	cmds := f.commands()
	if !strings.HasPrefix(cmds, "cxl enable-memdev mem0\n") || !strings.Contains(cmds, "daxctl reconfigure-device --mode=devdax --force dax0.0") {
		t.Fatalf("unexpected commands:\n%s", cmds)
	}
	if _, err := g.Online("mem0", true); err == nil {
		t.Fatal("online must fail in mode dax")
	}
	for _, mode := range []string{"bogus", "devdax", "ram", ""} {
		want := `invalid mode "` + mode + `" (numa or dax)`
		if err := ValidMode(mode); err == nil || err.Error() != want {
			t.Fatalf("ValidMode(%q): expected %q, got %v", mode, want, err)
		}
		if _, err := g.CreateRegion(context.Background(), "mem0", mode, ""); err == nil || err.Error() != want {
			t.Fatalf("mode %q: expected %q, got %v", mode, want, err)
		}
	}
	for _, mode := range []string{ModeNUMA, ModeDax} {
		if err := ValidMode(mode); err != nil {
			t.Fatalf("ValidMode(%q): %v", mode, err)
		}
	}
}

// The kernel binds the dax device of a volatile region to kmem by itself, and
// its driver link exists before dev_dax_kmem_probe has added the memory
// blocks: CreateRegion must wait for the blocks (e2e test10-dra-pooling
// failed its first NodePrepare with "no memory blocks found").
func TestRegionNUMAWaitsForBlocks(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc1ee0001")
	for _, b := range []int{74, 75} {
		_ = os.RemoveAll(f.p("devices/system/memory/memory" + itoa(b)))
	}
	g := f.manager()
	go func() {
		time.Sleep(30 * time.Millisecond)
		for _, b := range []int{74, 75} {
			f.write("devices/system/memory/memory"+itoa(b)+"/state", "offline")
		}
	}()
	ri, err := g.CreateRegion(context.Background(), "mem0", ModeNUMA, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ri.Blocks) != 2 {
		t.Fatalf("CreateRegion returned before the memory blocks appeared: %+v", ri)
	}
	if _, err := g.Online("mem0", true); err != nil {
		t.Fatal(err)
	}
	// Without blocks, the wait ends with the context.
	_ = os.RemoveAll(f.p("devices/system/memory/memory75"))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := g.waitRegionBlocks(ctx, "region0"); err == nil || !strings.Contains(err.Error(), "1 of 2 memory blocks") {
		t.Fatalf("expected a timeout with 1 of 2 blocks, got %v", err)
	}
}

// The same race for a region in mode dax: the switch from the kernel's
// kmem binding to device_dax must wait for the kmem probe.
func TestRegionDaxWaitsForKmemProbe(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc1ae0001")
	for _, b := range []int{74, 75} {
		_ = os.RemoveAll(f.p("devices/system/memory/memory" + itoa(b)))
	}
	g := f.manager()
	go func() {
		time.Sleep(30 * time.Millisecond)
		for _, b := range []int{74, 75} {
			f.write("devices/system/memory/memory"+itoa(b)+"/state", "offline")
		}
	}()
	start := time.Now()
	ri, err := g.CreateRegion(context.Background(), "mem0", ModeDax, "")
	if err != nil {
		t.Fatal(err)
	}
	if ri.Driver != DriverDeviceDax {
		t.Fatalf("unexpected region info %+v", ri)
	}
	if time.Since(start) < 30*time.Millisecond {
		t.Fatalf("CreateRegion switched drivers before the kmem probe finished")
	}
}

// A region in mode dax is sliced into dax devices and released without
// disabling the memdev.
func TestDaxSlices(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc100e2e1")
	g := f.manager()
	ctx := context.Background()
	if _, err := g.CreateRegion(ctx, "mem0", ModeDax, ""); err != nil {
		t.Fatal(err)
	}
	if dir := g.daxRegionDir("region0"); dir != f.p(daxAttrsPath) {
		t.Fatalf("dax region directory %q", dir)
	}
	avail, align, devs, err := g.DaxRegionInfo("region0")
	if err != nil || avail != 0 || align != daxAlign || strings.Join(devs, ",") != "dax0.0" {
		t.Fatalf("dax region info %d %d %v %v", avail, align, devs, err)
	}
	if _, _, _, err := g.DaxRegionInfo("region7"); err == nil {
		t.Fatal("expected an error for a missing region")
	}
	if a, err := g.daxDeviceResource("dax0.0"); err != nil || a != 0x250000000 {
		t.Fatalf("resource %x %v", a, err)
	}

	// the first slice: dax0.0 shrinks
	if err := g.ResizeDaxDevice(ctx, "dax0.0", 64<<20); err != nil {
		t.Fatal(err)
	}
	if f.daxBound("dax0.0") || f.daxSize("dax0.0") != 64<<20 {
		t.Fatalf("dax0.0 bound %v size %d", f.daxBound("dax0.0"), f.daxSize("dax0.0"))
	}
	if err := g.ResizeDaxDevice(ctx, "dax0.0", 1<<20); err == nil {
		t.Fatal("a misaligned size was accepted")
	}
	if err := g.SetDaxDriver(ctx, "dax0.0", DriverDeviceDax); err != nil {
		t.Fatal(err)
	}

	// more slices
	dax, err := g.CreateDaxDevice(ctx, "region0", 32<<20)
	if err != nil || dax != "dax0.1" || f.daxBound(dax) || f.daxSize(dax) != 32<<20 {
		t.Fatalf("created %q %v (bound %v, size %d)", dax, err, f.daxBound(dax), f.daxSize(dax))
	}
	if err := g.SetDaxDriver(ctx, dax, DriverDeviceDax); err != nil {
		t.Fatal(err)
	}
	if ma, mi, err := g.DaxDevNumbers(dax); err != nil || ma != 252 || mi != 1 || g.TargetNode(dax) != 2 {
		t.Fatalf("%s: %d:%d %v node %d", dax, ma, mi, err, g.TargetNode(dax))
	}
	if sz, err := g.DaxDeviceSize(dax); err != nil || sz != 32<<20 {
		t.Fatalf("%s size %d %v", dax, sz, err)
	}
	if avail, _, devs, _ := g.DaxRegionInfo("region0"); avail != regionBytes-96<<20 || len(devs) != 2 {
		t.Fatalf("available %d, devices %v", avail, devs)
	}
	// no room: the new device is deleted again
	if _, err := g.CreateDaxDevice(ctx, "region0", 512<<20); err == nil {
		t.Fatal("a slice larger than the free space was created")
	}
	if _, _, devs, _ := g.DaxRegionInfo("region0"); len(devs) != 2 {
		t.Fatalf("failed creation left devices %v", devs)
	}

	// deletion, of a missing device too
	if err := g.DeleteDaxDevice(ctx, "region0", dax); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(f.p("bus/dax/devices/" + dax)); err == nil {
		t.Fatalf("%s not deleted", dax)
	}
	if err := g.DeleteDaxDevice(ctx, "region0", dax); err != nil {
		t.Fatal(err)
	}
	// dax0.0 is kept with size 0
	if err := g.DeleteDaxDevice(ctx, "region0", "dax0.0"); err != nil {
		t.Fatal(err)
	}
	if f.daxBound("dax0.0") || f.daxSize("dax0.0") != 0 {
		t.Fatalf("dax0.0 bound %v size %d", f.daxBound("dax0.0"), f.daxSize("dax0.0"))
	}
	if avail, _, _, _ := g.DaxRegionInfo("region0"); avail != regionBytes {
		t.Fatalf("available %d after deleting all slices", avail)
	}

	// the regions go, the memdev stays enabled
	if err := g.ReleaseRegions(ctx, "mem0"); err != nil {
		t.Fatal(err)
	}
	cmds := f.commands()
	if !strings.HasSuffix(cmds, "cxl disable-region region0\ncxl destroy-region region0") {
		t.Fatalf("unexpected commands:\n%s", cmds)
	}
	if _, err := os.Stat(f.p(memPath + "/driver")); err != nil {
		t.Fatal("ReleaseRegions disabled the memdev")
	}
	if len(g.Regions("mem0")) != 0 {
		t.Fatalf("regions left: %v", g.Regions("mem0"))
	}
	if err := g.ReleaseRegions(ctx, "mem7"); err != nil {
		t.Fatal(err)
	}
}

// Without daxctl, dax devices are bound and unbound through sysfs.
func TestDaxDriverSysfs(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc100e2e1")
	g := f.manager()
	g.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	ctx := context.Background()
	if _, err := g.CreateRegion(ctx, "mem0", ModeDax, ""); err != nil {
		t.Fatal(err)
	}
	if g.DaxDriver("dax0.0") != DriverDeviceDax {
		t.Fatalf("dax0.0 is bound to %q", g.DaxDriver("dax0.0"))
	}
	if err := g.ResizeDaxDevice(ctx, "dax0.0", 128<<20); err != nil {
		t.Fatal(err)
	}
	dax, err := g.CreateDaxDevice(ctx, "region0", 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"dax0.0", dax} {
		if err := g.SetDaxDriver(ctx, d, DriverDeviceDax); err != nil {
			t.Fatal(err)
		}
	}
	// a full region has no room for another device
	if _, err := g.CreateDaxDevice(ctx, "region0", daxAlign); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("expected ENOSPC, got %v", err)
	}
	// a device of size 0 cannot be bound
	if err := g.DeleteDaxDevice(ctx, "region0", "dax0.0"); err != nil {
		t.Fatal(err)
	}
	if err := g.SetDaxDriver(ctx, "dax0.0", DriverDeviceDax); err == nil {
		t.Fatal("a device of size 0 was bound")
	}
	if err := g.UnbindDax(ctx, dax); err != nil || f.daxBound(dax) {
		t.Fatalf("unbind %s: %v (bound %v)", dax, err, f.daxBound(dax))
	}
	// unbinding an unbound device is fine
	if err := g.UnbindDax(ctx, dax); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.commands(), "daxctl") {
		t.Fatalf("daxctl used:\n%s", f.commands())
	}
	// kmem is bound with bind only: a new_id would make it take every
	// unbound dax device of the CXL regions
	if err := g.SetDaxDriver(ctx, dax, DriverDeviceDax); err != nil {
		t.Fatal(err)
	}
	f.writes = nil
	if err := g.SetDaxDriver(ctx, dax, DriverKmem); err != nil || g.DaxDriver(dax) != DriverKmem {
		t.Fatalf("kmem bind: %v, driver %q", err, g.DaxDriver(dax))
	}
	if w := strings.Join(f.writes, ","); w != "bus/dax/drivers/device_dax/unbind,bus/dax/drivers/kmem/bind" {
		t.Fatalf("kmem bind writes %s", w)
	}
}

func TestBlocksNodeAndReleaseRegion(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc100e2e1")
	g := f.manager()
	ctx := context.Background()
	if n := g.BlocksNode([]int{74, 75}); n != -1 {
		t.Fatalf("node %d of blocks without a node link", n)
	}
	f.write("devices/system/memory/memory75/node3/x", "")
	if n := g.BlocksNode([]int{74, 75}); n != 3 {
		t.Fatalf("node %d, expected 3", n)
	}
	if _, err := g.CreateRegion(ctx, "mem0", ModeNUMA, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Online("mem0", true); err != nil {
		t.Fatal(err)
	}
	if err := g.ReleaseRegion(ctx, "region0"); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"74", "75"} {
		if st, _ := readTrim(f.p("devices/system/memory/memory" + b + "/state")); st != "offline" {
			t.Fatalf("memory%s state %q after release", b, st)
		}
	}
	if !strings.HasSuffix(f.commands(), "cxl disable-region region0\ncxl destroy-region region0") {
		t.Fatalf("unexpected commands:\n%s", f.commands())
	}
	if err := g.ReleaseRegion(ctx, "region0"); err != nil {
		t.Fatal(err)
	}
}

// block_size_bytes is hex without 0x: "8000000" is 128 MiB.
func TestMemoryBlockSize(t *testing.T) {
	f := newFakeSys(t)
	g := f.manager()
	for _, tc := range []struct {
		val  string
		want uint64
	}{
		{"8000000", 134217728},
		{"0x8000000", 134217728},
		{"80000000", 2 << 30},
	} {
		f.write("devices/system/memory/block_size_bytes", tc.val)
		if bs, err := g.MemoryBlockSize(); err != nil || bs != tc.want {
			t.Fatalf("block size %q: %d %v, expected %d", tc.val, bs, err, tc.want)
		}
	}
	for _, bad := range []string{"0", "bogus", ""} {
		f.write("devices/system/memory/block_size_bytes", bad)
		if _, err := g.MemoryBlockSize(); err == nil {
			t.Fatalf("block size %q accepted", bad)
		}
	}
	_ = os.Remove(f.p("devices/system/memory/block_size_bytes"))
	if _, err := g.MemoryBlockSize(); err == nil {
		t.Fatal("a missing block size accepted")
	}
}

func TestRange(t *testing.T) {
	bs := uint64(128 << 20)
	r := Range{Start: 0x250000000, End: 0x257ffffff}
	if r.Size() != bs || !r.Aligned(bs) || r.String() != "0x250000000-0x257ffffff" {
		t.Fatalf("range %v size %d aligned %v", r, r.Size(), r.Aligned(bs))
	}
	if got := r.blocks(bs); len(got) != 1 || got[0] != 74 {
		t.Fatalf("blocks %v", got)
	}
	// a range that starts 2 MiB into a block holds no whole block
	r = Range{Start: 0x250200000, End: 0x2581fffff}
	if r.Aligned(bs) || r.Aligned(0) || len(r.blocks(bs)) != 0 || !r.Aligned(daxAlign) {
		t.Fatalf("misaligned range %v: blocks %v", r, r.blocks(bs))
	}
	r = Range{Start: 0x250200000, End: 0x25fffffff}
	if got := r.blocks(bs); len(got) != 1 || got[0] != 75 {
		t.Fatalf("blocks %v", got)
	}
}

// The memory of dax devices: mappings, resource and size without them,
// memory blocks and the free gaps of the region.
func TestDaxDeviceRanges(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc100e2e1")
	g := f.manager()
	ctx := context.Background()
	if _, err := g.CreateRegion(ctx, "mem0", ModeDax, ""); err != nil {
		t.Fatal(err)
	}
	if r, err := g.RegionRange("region0"); err != nil || r != (Range{Start: 0x250000000, End: 0x25fffffff}) {
		t.Fatalf("region range %v %v", r, err)
	}
	// no mappings: resource and size
	ranges, err := g.DaxDeviceRanges("dax0.0")
	if err != nil || len(ranges) != 1 || ranges[0] != (Range{Start: 0x250000000, End: 0x25fffffff}) {
		t.Fatalf("ranges %v %v", ranges, err)
	}
	bs, err := g.MemoryBlockSize()
	if err != nil {
		t.Fatal(err)
	}
	if blocks, err := g.DaxDeviceBlocks("dax0.0", bs); err != nil || len(blocks) != 2 || blocks[0] != 74 || blocks[1] != 75 {
		t.Fatalf("blocks %v %v", blocks, err)
	}
	if _, err := g.DaxDeviceBlocks("dax0.0", 0); err == nil {
		t.Fatal("block size 0 accepted")
	}
	if gaps, err := g.RegionFreeGaps("region0"); err != nil || len(gaps) != 0 {
		t.Fatalf("gaps of a full region %v %v", gaps, err)
	}
	if err := g.ResizeDaxDevice(ctx, "dax0.0", 0); err != nil {
		t.Fatal(err)
	}
	if ranges, err := g.DaxDeviceRanges("dax0.0"); err != nil || len(ranges) != 0 {
		t.Fatalf("ranges of an empty device %v %v", ranges, err)
	}
	if gaps, err := g.RegionFreeGaps("region0"); err != nil || len(gaps) != 1 || gaps[0] != (Range{Start: 0x250000000, End: 0x25fffffff}) {
		t.Fatalf("gaps of an empty region %v %v", gaps, err)
	}

	// a device of two ranges, listed in address order
	f.addDax("dax0.1", 130<<20)
	f.write(daxRegionPath+"/dax0.1/mapping0/start", "0x258000000")
	f.write(daxRegionPath+"/dax0.1/mapping0/end", "0x25fffffff")
	f.write(daxRegionPath+"/dax0.1/mapping1/start", "0x250000000")
	f.write(daxRegionPath+"/dax0.1/mapping1/end", "0x2501fffff")
	ranges, err = g.DaxDeviceRanges("dax0.1")
	if err != nil || len(ranges) != 2 || ranges[0] != (Range{Start: 0x250000000, End: 0x2501fffff}) || ranges[1] != (Range{Start: 0x258000000, End: 0x25fffffff}) {
		t.Fatalf("ranges %v %v", ranges, err)
	}
	if ranges[0].Aligned(bs) || !ranges[1].Aligned(bs) {
		t.Fatalf("alignment of %v", ranges)
	}
	// only memory75 lies wholly in its memory
	if blocks, err := g.DaxDeviceBlocks("dax0.1", bs); err != nil || len(blocks) != 1 || blocks[0] != 75 {
		t.Fatalf("blocks %v %v", blocks, err)
	}
	gaps, err := g.RegionFreeGaps("region0")
	if err != nil || len(gaps) != 1 || gaps[0] != (Range{Start: 0x250200000, End: 0x257ffffff}) {
		t.Fatalf("gaps %v %v", gaps, err)
	}
	if err := g.WaitDaxBlocks(ctx, "dax0.1"); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(f.p("devices/system/memory/memory75"))
	tctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if err := g.WaitDaxBlocks(tctx, "dax0.1"); err == nil || !strings.Contains(err.Error(), "0 of 1 memory blocks") {
		t.Fatalf("expected a timeout with 0 of 1 blocks, got %v", err)
	}
	if err := g.WaitDaxBlocks(ctx, "dax0.0"); err == nil || !strings.Contains(err.Error(), "dax0.0 has no whole memory block") {
		t.Fatalf("expected no blocks for an empty device, got %v", err)
	}
	f.write(daxRegionPath+"/dax0.1/mapping0/end", "bogus")
	if _, err := g.DaxDeviceRanges("dax0.1"); err == nil {
		t.Fatal("a bad mapping accepted")
	}
	if _, err := g.RegionFreeGaps("region0"); err == nil {
		t.Fatal("gaps with a bad mapping")
	}
	if _, err := g.RegionRange("region7"); err == nil {
		t.Fatal("range of a missing region")
	}
}

// A dax device is placed explicitly, and the placement checked.
func TestCreateDaxDeviceRanges(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc100e2e1")
	g := f.manager()
	ctx := context.Background()
	if _, err := g.CreateRegion(ctx, "mem0", ModeDax, ""); err != nil {
		t.Fatal(err)
	}
	if err := g.ResizeDaxDevice(ctx, "dax0.0", 64<<20); err != nil {
		t.Fatal(err)
	}
	// the block-aligned second half of the region
	dax, err := g.CreateDaxDeviceRanges(ctx, "region0", []Range{{Start: 0x258000000, End: 0x25fffffff}})
	if err != nil || dax != "dax0.1" || f.daxBound(dax) || f.daxSize(dax) != 128<<20 {
		t.Fatalf("created %q %v (bound %v, size %d)", dax, err, f.daxBound(dax), f.daxSize(dax))
	}
	if ranges, _ := g.DaxDeviceRanges(dax); len(ranges) != 1 || ranges[0] != (Range{Start: 0x258000000, End: 0x25fffffff}) {
		t.Fatalf("ranges %v", ranges)
	}
	gaps, err := g.RegionFreeGaps("region0")
	if err != nil || len(gaps) != 1 || gaps[0] != (Range{Start: 0x254000000, End: 0x257ffffff}) {
		t.Fatalf("gaps %v %v", gaps, err)
	}
	// a taken range, a length the kernel ignores: no device left
	for _, tc := range []struct {
		start, size uint64
		err         string
	}{
		{0x258000000, 64 << 20, "cannot allocate memory"},
		{0x254000000, 1 << 20, "memory [] after mapping [0x254000000-0x2540fffff]"},
	} {
		r := []Range{{Start: tc.start, End: tc.start + tc.size - 1}}
		if _, err := g.CreateDaxDeviceRanges(ctx, "region0", r); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("placing %d bytes at 0x%x: %v, expected %q", tc.size, tc.start, err, tc.err)
		}
	}
	if devs := g.DaxDevices("region0"); len(devs) != 2 {
		t.Fatalf("failed placements left devices %v", devs)
	}

	// two ranges, listed in any order; a second range that the kernel
	// ignores deletes the device
	if err := g.DeleteDaxDevice(ctx, "region0", dax); err != nil {
		t.Fatal(err)
	}
	two := []Range{{Start: 0x25c000000, End: 0x25fffffff}, {Start: 0x254000000, End: 0x255ffffff}}
	dax, err = g.CreateDaxDeviceRanges(ctx, "region0", two)
	if err != nil || f.daxSize(dax) != 96<<20 {
		t.Fatalf("created %q %v (size %d)", dax, err, f.daxSize(dax))
	}
	if ranges, _ := g.DaxDeviceRanges(dax); len(ranges) != 2 || ranges[0] != two[1] || ranges[1] != two[0] {
		t.Fatalf("ranges %v", ranges)
	}
	if err := g.DeleteDaxDevice(ctx, "region0", dax); err != nil {
		t.Fatal(err)
	}
	bad := []Range{two[0], {Start: 0x254000000, End: 0x2540fffff}}
	if _, err := g.CreateDaxDeviceRanges(ctx, "region0", bad); err == nil || !strings.Contains(err.Error(), "after mapping") {
		t.Fatalf("expected a mismatch, got %v", err)
	}
	if _, err := g.CreateDaxDeviceRanges(ctx, "region0", nil); err == nil {
		t.Fatal("a device without memory")
	}
	if devs := g.DaxDevices("region0"); len(devs) != 1 {
		t.Fatalf("failed placements left devices %v", devs)
	}
}

// kmem is never unbound from memory that is online: the kernel could not
// remove it.
func TestUnbindKmemOnline(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc100e2e1")
	g := f.manager()
	g.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	ctx := context.Background()
	if _, err := g.CreateRegion(ctx, "mem0", ModeNUMA, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Online("mem0", true); err != nil {
		t.Fatal(err)
	}
	f.write("devices/system/memory/memory74/state", "offline")
	err := g.UnbindDax(ctx, "dax0.0")
	if err == nil || !strings.Contains(err.Error(), "dax0.0: memory blocks [75] are not offline") || !f.daxBound("dax0.0") {
		t.Fatalf("unbind of online kmem memory: %v (bound %v)", err, f.daxBound("dax0.0"))
	}
	if err := g.SetDaxDriver(ctx, "dax0.0", DriverDeviceDax); err == nil || g.DaxDriver("dax0.0") != DriverKmem {
		t.Fatalf("switch from online kmem memory: %v", err)
	}
	if err := g.ResizeDaxDevice(ctx, "dax0.0", 0); err == nil || f.daxSize("dax0.0") != regionBytes {
		t.Fatalf("resize of online kmem memory: %v", err)
	}
	f.write("devices/system/memory/memory75/state", "offline")
	if err := g.UnbindDax(ctx, "dax0.0"); err != nil || f.daxBound("dax0.0") {
		t.Fatalf("unbind of offline kmem memory: %v", err)
	}
	// without a block size nothing can be checked: kmem stays
	if err := g.SetDaxDriverSysfs(ctx, "dax0.0", DriverKmem); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(f.p("devices/system/memory/block_size_bytes"))
	if err := g.UnbindDax(ctx, "dax0.0"); err == nil || !f.daxBound("dax0.0") {
		t.Fatalf("unbind without a block size: %v", err)
	}
}

// SetDaxDriverSysfs binds through sysfs although daxctl is installed.
func TestSetDaxDriverSysfs(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc100e2e1")
	g := f.manager()
	ctx := context.Background()
	if _, err := g.CreateRegion(ctx, "mem0", ModeDax, ""); err != nil {
		t.Fatal(err)
	}
	ncmds := len(f.commands())
	if err := g.ResizeDaxDevice(ctx, "dax0.0", 128<<20); err != nil {
		t.Fatal(err)
	}
	f.writes = nil
	if err := g.SetDaxDriverSysfs(ctx, "dax0.0", DriverKmem); err != nil || g.DaxDriver("dax0.0") != DriverKmem {
		t.Fatalf("kmem bind: %v, driver %q", err, g.DaxDriver("dax0.0"))
	}
	if w := strings.Join(f.writes, ","); w != "bus/dax/drivers/kmem/bind" {
		t.Fatalf("kmem bind writes %s", w)
	}
	if err := g.SetDaxDriverSysfs(ctx, "dax0.0", DriverKmem); err != nil {
		t.Fatal(err)
	}
	if len(f.commands()) != ncmds {
		t.Fatalf("daxctl used:\n%s", f.commands()[ncmds:])
	}
}

// A region that does not start at a block boundary has only the blocks
// that lie wholly in it: CreateRegion waits for those only.
func TestRegionBlocksMisaligned(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc100e2e1")
	g := f.manager()
	ctx := context.Background()
	if _, err := g.CreateRegion(ctx, "mem0", ModeNUMA, ""); err != nil {
		t.Fatal(err)
	}
	f.write("bus/cxl/devices/region0/resource", "0x24c000000")
	_ = os.RemoveAll(f.p("devices/system/memory/memory75"))
	if blocks, err := g.RegionBlocks("region0"); err != nil || len(blocks) != 1 || blocks[0] != 74 {
		t.Fatalf("blocks %v %v", blocks, err)
	}
	tctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := g.waitRegionBlocks(tctx, "region0"); err != nil {
		t.Fatal(err)
	}
	// no whole block: nothing to wait for
	f.write("bus/cxl/devices/region0/size", "0x8000000")
	if err := g.waitRegionBlocks(tctx, "region0"); err != nil {
		t.Fatal(err)
	}
	f.write("bus/cxl/devices/region0/size", "bogus")
	if _, err := g.RegionBlocks("region0"); err == nil {
		t.Fatal("a bad region size accepted")
	}
}
