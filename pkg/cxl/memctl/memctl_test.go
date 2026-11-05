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
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// The tests of the flows that memctl composes from package kernel, on the
// fake of package kernel; the steps themselves are tested in package
// kernel.

const (
	serial0 = 0xc1f00001
	serial1 = 0xc1f00002
	mib     = 1 << 20
)

// newFake returns a fake with mem0 plugged under host bridge 12 and a
// Manager on it.
func newFake(t *testing.T, spec fake.MemdevSpec) (*fake.Fake, *Manager) {
	t.Helper()
	f := fake.New(t)
	if spec.Serial == 0 {
		spec.Serial = serial0
	}
	f.Plug(spec)
	return f, manager(f)
}

// manager returns a Manager on the fake. Its LookPath finds daxctl, which
// memctl must not run: the fake fails every command but cxl and ndctl.
func manager(f *fake.Fake) *Manager {
	k := f.Kernel()
	return &Manager{
		SysRoot:      k.SysRoot,
		DevRoot:      k.DevRoot,
		Exec:         k.Exec,
		LookPath:     func(string) (string, error) { return "/usr/bin/daxctl", nil },
		PollInterval: 2 * time.Millisecond,
		Logf:         k.Logf,
		WriteFile:    k.WriteFile,
	}
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestFindAndWait(t *testing.T) {
	f := fake.New(t)
	g := manager(f)
	if _, err := g.FindMemdev(serial0); !errors.Is(err, ErrNotFound) || err.Error() != "no CXL memory device with the serial 0xc1f00001" {
		t.Fatalf("expected not found, got %v", err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		f.Plug(fake.MemdevSpec{Serial: serial0})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if m, err := g.WaitMemdev(ctx, serial0); err != nil || m != "mem0" {
		t.Fatalf("wait: %q %v", m, err)
	}
	tctx, tcancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer tcancel()
	if _, err := g.WaitMemdev(tctx, 0x1234); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout, got %v", err)
	}
	if ms := g.Memdevs(); !reflect.DeepEqual(ms, []Memdev{{Name: "mem0", Serial: serial0}}) {
		t.Fatalf("memdevs %+v", ms)
	}
	if d, err := g.RootDecoder("mem0", RegionRAM); err != nil || d != "decoder0.0" {
		t.Fatalf("root decoder %q %v", d, err)
	}
}

// A region in mode numa: kmem, its memory onlined movable and released
// with the memdev (TestRegionNUMAOnlineRelease of before).
func TestRegionNUMAOnlineRelease(t *testing.T) {
	f, g := newFake(t, fake.MemdevSpec{})
	ctx := context.Background()
	ri, err := g.CreateRegion(ctx, "mem0", ModeNUMA, "")
	noErr(t, err)
	want := &RegionInfo{Memdev: "mem0", Region: "region0", Dax: "dax0.0", Driver: DriverKmem, Mode: ModeNUMA, Node: 2, Blocks: []int{74, 75}}
	if !reflect.DeepEqual(ri, want) {
		t.Fatalf("region info %+v", ri)
	}
	if !strings.Contains(f.Commands(), "cxl create-region -t ram -d decoder0.0 -m mem0") {
		t.Fatalf("commands:\n%s", f.Commands())
	}
	// idempotent
	_, err = g.CreateRegion(ctx, "mem0", ModeNUMA, "")
	noErr(t, err)
	if n := strings.Count(f.Commands(), "create-region"); n != 1 {
		t.Fatalf("region created %d times", n)
	}
	_, err = g.Online("mem0", true)
	noErr(t, err)
	f.Write("devices/system/memory/memory75/valid_zones", "Normal")
	if _, err := g.Online("mem0", true); err == nil || !strings.Contains(err.Error(), "zone Normal") {
		t.Fatalf("online movable accepted a Normal block: %v", err)
	}
	f.Write("devices/system/memory/memory75/valid_zones", "Movable")
	_, err = g.Online("mem0", true)
	noErr(t, err)
	noErr(t, g.Release(ctx, "mem0"))
	want2 := "cxl disable-region region0\ncxl destroy-region region0\ncxl disable-memdev mem0"
	if !strings.HasSuffix(f.Commands(), want2) {
		t.Fatalf("commands:\n%s", f.Commands())
	}
	// releasing again, or a missing device, is fine
	noErr(t, g.Release(ctx, "mem0"))
	noErr(t, g.Release(ctx, "mem7"))
	noErr(t, g.ReleaseRegions(ctx, "mem7"))
}

// A region in mode dax: the disabled memdev is enabled, device_dax bound
// through sysfs; modes are validated (TestRegionDax of before).
func TestRegionDax(t *testing.T) {
	f, g := newFake(t, fake.MemdevSpec{Disabled: true})
	ctx := context.Background()
	ri, err := g.CreateRegion(ctx, "mem0", ModeDax, "decoder0.0")
	noErr(t, err)
	if ri.Driver != DriverDeviceDax || ri.Mode != ModeDax || ri.Device != f.DevRoot()+"/dax0.0" {
		t.Fatalf("region info %+v", ri)
	}
	cmds := f.Commands()
	if !strings.HasPrefix(cmds, "cxl enable-memdev mem0\n") || strings.Contains(cmds, "daxctl") {
		t.Fatalf("commands:\n%s", cmds)
	}
	if ma, mi, err := g.DaxDevNumbers("dax0.0"); err != nil || ma != 252 || mi != 0 {
		t.Fatalf("dax device numbers %d:%d %v", ma, mi, err)
	}
	if _, err := g.Online("mem0", true); err == nil {
		t.Fatal("online must fail in mode dax")
	}
	if f.HasDaxID(DriverDeviceDax, "dax0.0") {
		t.Fatal("an id of dax0.0 left in device_dax")
	}
	for _, mode := range []string{"bogus", "devdax", "ram", ""} {
		want := `invalid mode "` + mode + `" (numa or dax)`
		if err := ValidMode(mode); err == nil || err.Error() != want {
			t.Fatalf("ValidMode(%q): expected %q, got %v", mode, want, err)
		}
		if _, err := g.CreateRegion(ctx, "mem0", mode, ""); err == nil || err.Error() != want {
			t.Fatalf("mode %q: expected %q, got %v", mode, want, err)
		}
	}
	for _, mode := range []string{ModeNUMA, ModeDax} {
		noErr(t, ValidMode(mode))
	}
}

// The kernel binds the dax device of a volatile region to kmem by itself,
// and its driver link exists before kmem added the memory blocks:
// CreateRegion waits for the blocks, in mode numa and before the switch to
// device_dax (TestRegionNUMAWaitsForBlocks, TestRegionDaxWaitsForKmemProbe).
func TestRegionWaitsForKmemProbe(t *testing.T) {
	for _, mode := range []string{ModeNUMA, ModeDax} {
		f, g := newFake(t, fake.MemdevSpec{})
		f.NoKmemBlocks = true
		go func() {
			time.Sleep(30 * time.Millisecond)
			f.AddBlocks(74, 75)
		}()
		start := time.Now()
		ri, err := g.CreateRegion(context.Background(), "mem0", mode, "")
		noErr(t, err)
		// device_dax has no memory blocks
		if (mode == ModeNUMA && len(ri.Blocks) != 2) || time.Since(start) < 30*time.Millisecond {
			t.Fatalf("%s: CreateRegion returned before the memory blocks appeared: %+v", mode, ri)
		}
	}
}

// A udev rule onlines the blocks that kmem adds for a new region, also
// after they were offlined: they stay offline before the switch to
// device_dax (TestRegionDaxReofflinesAutoOnlined).
func TestRegionDaxReofflinesAutoOnlined(t *testing.T) {
	defer func(d time.Duration) { settleOffline = d }(settleOffline)
	settleOffline = 50 * time.Millisecond
	f, g := newFake(t, fake.MemdevSpec{})
	f.AutoOnline = 2
	f.Before("write bus/dax/drivers/kmem/unbind", func() {
		for _, b := range []int{74, 75} {
			if st := f.BlockState(b); st != kernel.BlockStateOffline {
				t.Errorf("kmem unbound with memory%d %s", b, st)
			}
		}
	})
	ri, err := g.CreateRegion(context.Background(), "mem0", ModeDax, "")
	if err != nil || ri.Driver != DriverDeviceDax {
		t.Fatalf("region %+v, %v", ri, err)
	}
}

// bug-21: SetDaxDriver leaves no id after a bind, and an id that another
// tool left is removed by the unbind of a resize (TestDaxIDsNotLeft).
func TestDaxIDsNotLeft(t *testing.T) {
	for _, tc := range []struct {
		name string
		left bool
	}{
		{name: "sysfs"},
		{name: "left by another tool", left: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, g := newFake(t, fake.MemdevSpec{})
			ctx := context.Background()
			_, err := g.CreateRegion(ctx, "mem0", ModeDax, "")
			noErr(t, err)
			noErr(t, g.ResizeDaxDevice(ctx, "dax0.0", 128*mib))
			other, err := g.CreateDaxDevice(ctx, "region0", 64*mib)
			noErr(t, err)
			noErr(t, g.SetDaxDriver(ctx, "dax0.0", DriverDeviceDax))
			if tc.left {
				f.SetDaxID(DriverDeviceDax, "dax0.0")
			}
			f.Before("write bus/dax/devices/dax0.0/size", func() {
				if err := manager(f).SetDaxDriver(ctx, other, DriverDeviceDax); err != nil {
					t.Errorf("the other bind: %v", err)
				}
			})
			noErr(t, g.ResizeDaxDevice(ctx, "dax0.0", 64*mib))
			if f.DaxDriver("dax0.0") != "" || f.DaxSize("dax0.0") != 64*mib || f.DaxDriver(other) != DriverDeviceDax {
				t.Fatalf("dax0.0 %q %d; %s %q", f.DaxDriver("dax0.0"), f.DaxSize("dax0.0"), other, f.DaxDriver(other))
			}
			if f.HasDaxID(DriverDeviceDax, other) || f.HasDaxID(DriverDeviceDax, "dax0.0") {
				t.Fatal("an id left")
			}
			// a failed bind leaves no id either
			noErr(t, g.ResizeDaxDevice(ctx, "dax0.0", 0))
			if err := g.SetDaxDriver(ctx, "dax0.0", DriverDeviceDax); err == nil {
				t.Fatal("a device of size 0 was bound")
			}
			if f.HasDaxID(DriverDeviceDax, "dax0.0") {
				t.Fatal("an id left after a failed bind")
			}
		})
	}
}

// kmem is bound with bind only, device_dax with new_id and bind, also when
// daxctl is installed (TestDaxDriverSysfs, TestSetDaxDriverSysfs).
func TestSetDaxDriverSysfs(t *testing.T) {
	f, g := newFake(t, fake.MemdevSpec{})
	ctx := context.Background()
	_, err := g.CreateRegion(ctx, "mem0", ModeDax, "")
	noErr(t, err)
	ncmds := len(f.Commands())
	f.Writes()
	noErr(t, g.SetDaxDriverSysfs(ctx, "dax0.0", DriverKmem))
	if w := strings.Join(f.Writes(), ","); w != "bus/dax/drivers/device_dax/remove_id,bus/dax/drivers/device_dax/unbind,bus/dax/drivers/kmem/bind,bus/dax/drivers/kmem/remove_id" {
		t.Fatalf("kmem bind writes %s", w)
	}
	noErr(t, g.SetDaxDriverSysfs(ctx, "dax0.0", DriverKmem))
	if len(f.Commands()) != ncmds {
		t.Fatalf("daxctl used:\n%s", f.Commands()[ncmds:])
	}
	noErr(t, g.UnbindDax(ctx, "dax0.0"))
	f.Writes()
	noErr(t, g.SetDaxDriver(ctx, "dax0.0", DriverDeviceDax))
	if w := strings.Join(f.Writes(), ","); w != "bus/dax/drivers/device_dax/new_id,bus/dax/drivers/device_dax/remove_id" {
		t.Fatalf("device_dax bind writes %s", w)
	}
	if len(f.Commands()) != ncmds {
		t.Fatalf("commands:\n%s", f.Commands()[ncmds:])
	}
	// a bind that fails leaves no id, kmem's neither
	noErr(t, g.ResizeDaxDevice(ctx, "dax0.0", 0))
	f.SetDaxID(DriverKmem, "dax0.0")
	if err := g.SetDaxDriver(ctx, "dax0.0", DriverKmem); err == nil || f.HasDaxID(DriverKmem, "dax0.0") {
		t.Fatalf("a failed bind: %v, id left %v", err, f.HasDaxID(DriverKmem, "dax0.0"))
	}
	if !strings.Contains(err2text(g.SetDaxDriver(ctx, "dax0.0", DriverDeviceDax)), "bind dax0.0 to device_dax: ") {
		t.Fatal("the text of a failed bind changed")
	}
}

// err2text returns the text of err, "" for nil.
func err2text(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// The dax devices of a region are listed in lexical order, the first one
// is that of Info.
func TestDaxDevicesLexical(t *testing.T) {
	_, g := newFake(t, fake.MemdevSpec{Ram: 1 << 30})
	ctx := context.Background()
	_, err := g.CreateRegion(ctx, "mem0", ModeDax, "")
	noErr(t, err)
	noErr(t, g.ResizeDaxDevice(ctx, "dax0.0", 2*mib))
	for i := 1; i <= 10; i++ {
		_, err := g.CreateDaxDevice(ctx, "region0", 2*mib)
		noErr(t, err)
	}
	devs := g.DaxDevices("region0")
	if devs[1] != "dax0.1" || devs[2] != "dax0.10" || devs[3] != "dax0.2" {
		t.Fatalf("dax devices %v", devs)
	}
	if _, _, d, err := g.DaxRegionInfo("region0"); err != nil || !reflect.DeepEqual(d, devs) {
		t.Fatalf("dax region devices %v %v", d, err)
	}
}

// The name of the next region of the root decoder is noted before cxl
// create-region runs, under the creation lock, and the name it created
// after it; an error of the first note creates nothing
// (TestCreateRegionNoted).
func TestCreateRegionNoted(t *testing.T) {
	f, g := newFake(t, fake.MemdevSpec{})
	var notes []string
	note := func(region, decoder string, created bool) error {
		if regionCreateMu.TryLock() {
			regionCreateMu.Unlock()
			if !created {
				t.Error("the note before the creation without the lock")
			}
		}
		notes = append(notes, fmt.Sprintf("%s %s %v", region, decoder, created))
		return nil
	}
	ctx := context.Background()
	_, err := g.CreateRegionNoted(ctx, "mem0", ModeDax, "", 0, note)
	noErr(t, err)
	if want := []string{"region0 decoder0.0 false", "region0 decoder0.0 true"}; !reflect.DeepEqual(notes, want) {
		t.Fatalf("notes %q, expected %q", notes, want)
	}
	// a region that exists is reused without a note
	notes = nil
	if _, err := g.CreateRegionNoted(ctx, "mem0", ModeDax, "", 0, note); err != nil || notes != nil {
		t.Fatalf("reuse: %v, notes %q", err, notes)
	}
	// a note that fails: no create-region
	noErr(t, g.Release(ctx, "mem0"))
	ncmds := strings.Count(f.Commands(), "create-region")
	_, err = g.CreateRegionNoted(ctx, "mem0", ModeDax, "", 0, func(string, string, bool) error { return errors.New("no room") })
	if err == nil || err.Error() != "no room" || strings.Count(f.Commands(), "create-region") != ncmds {
		t.Fatalf("a failed note: %v\n%s", err, f.Commands())
	}
}

// The last check of ReleaseRegionInOrder and cxl destroy-region, and the
// deletion of a hollow region, hold regionCreateMu.
func TestCreationLock(t *testing.T) {
	f, g := newFake(t, fake.MemdevSpec{})
	f.Plug(fake.MemdevSpec{Serial: serial1})
	ctx := context.Background()
	_, err := g.CreateRegion(ctx, "mem0", ModeNUMA, "")
	noErr(t, err)
	locked := func(what string) func() {
		return func() {
			if regionCreateMu.TryLock() {
				regionCreateMu.Unlock()
				t.Errorf("%s without regionCreateMu", what)
			}
		}
	}
	f.Before("cxl destroy-region", locked("cxl destroy-region"))
	above, err := g.ReleaseRegionInOrder(ctx, "mem0", "region0")
	if err != nil || above != nil {
		t.Fatalf("release: %v %v", above, err)
	}
	// a region of another memdev above: kept
	_, err = g.CreateRegion(ctx, "mem0", ModeNUMA, "")
	noErr(t, err)
	_, err = g.CreateRegion(ctx, "mem1", ModeNUMA, "")
	noErr(t, err)
	if above, err := g.ReleaseRegionInOrder(ctx, "mem0", "region0"); err != nil || !reflect.DeepEqual(above, []string{"region1"}) {
		t.Fatalf("release below region1: %v %v", above, err)
	}
	if !g.HollowRegion(f.HollowRegion("decoder0.1", 256*mib)) {
		t.Fatal("not hollow")
	}
	f.Before("write devices/platform/ACPI0017:00/root0/decoder0.1/delete_region", locked("delete_region"))
	noErr(t, g.DeleteHollowRegion("region2"))
	if d, err := g.RegionRootDecoder("region1"); err != nil || d != "decoder0.0" {
		t.Fatalf("root decoder %q %v", d, err)
	}
	if h := g.DecoderHoles("mem0"); h != nil {
		t.Fatalf("holes %+v", h)
	}
	if a := g.RegionsAbove("mem1"); a != nil {
		t.Fatalf("above mem1 %v", a)
	}
	// decoders that cannot be read count as a region above
	f.Write("devices/platform/ACPI0017:00/root0/port1/decoders_committed", "bogus")
	if a := g.RegionsAbove("mem0"); len(a) != 1 || !strings.HasPrefix(a[0], "(the decoders of port1: ") {
		t.Fatalf("above with unreadable decoders %v", a)
	}
	if h := g.DecoderHoles("mem0"); h != nil {
		t.Fatalf("holes with unreadable decoders %v", h)
	}
}

// A writer creates the fsdax namespace in a new region of persistent
// memory, which is reused; a reader finds it from the labels
// (TestPmemWriterThenReader, TestCreatePmemRegionErrors).
func TestPmemWriterThenReader(t *testing.T) {
	f, g := newFake(t, fake.MemdevSpec{Pmem: 512 * mib})
	f.PmemDelay = 5 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pr, err := g.CreatePmemRegion(ctx, "mem0", "")
	noErr(t, err)
	if pr.Memdev != "mem0" || pr.Region != "region0" || pr.NdRegion != "region0" || len(pr.Namespaces) != 0 || FsdaxNamespace(pr.Namespaces) != nil {
		t.Fatalf("new region %+v", pr)
	}
	ns, err := g.CreateFsdaxNamespace(ctx, pr.NdRegion, "")
	noErr(t, err)
	want := Namespace{Name: "namespace0.0", Mode: NamespaceFsdax, Map: MapMem, Size: 510 * mib, BlockDevice: f.DevRoot() + "/pmem0", Major: 259, Minor: 0}
	if !reflect.DeepEqual(*ns, want) {
		t.Fatalf("namespace %+v, expected %+v", *ns, want)
	}
	// the region is reused
	pr, err = g.CreatePmemRegion(ctx, "mem0", "")
	if err != nil || !reflect.DeepEqual(pr.Namespaces, []Namespace{want}) || strings.Count(f.Commands(), "create-region") != 1 {
		t.Fatalf("reused region %+v %v\n%s", pr, err, f.Commands())
	}
	noErr(t, g.Release(ctx, "mem0"))
	// the reader
	pr, err = g.CreatePmemRegion(ctx, "mem0", "")
	noErr(t, err)
	want.Minor = 1
	if got := FsdaxNamespace(pr.Namespaces); got == nil || !reflect.DeepEqual(*got, want) {
		t.Fatalf("reader namespaces %+v", pr.Namespaces)
	}
	if strings.Count(f.Commands(), "ndctl") != 1 || !strings.Contains(f.Commands(), "cxl enable-memdev mem0") {
		t.Fatalf("commands:\n%s", f.Commands())
	}
	if p, err := g.Persistent("mem0"); err != nil || !p {
		t.Fatalf("persistent %v %v", p, err)
	}
	if _, _, size, err := g.BlockDeviceInfo("pmem0"); err != nil || size != 510*mib {
		t.Fatalf("block device %d %v", size, err)
	}
	if nd, err := g.NdRegion("region0"); err != nil || nd != "region0" {
		t.Fatalf("nd region %q %v", nd, err)
	}

	// a region of volatile memory of the memdev is not reused
	f, g = newFake(t, fake.MemdevSpec{Ram: 256 * mib, Pmem: 512 * mib})
	_, err = g.CreateRegion(ctx, "mem0", ModeDax, "")
	noErr(t, err)
	if _, err := g.CreatePmemRegion(ctx, "mem0", ""); err == nil || !strings.Contains(err.Error(), "mem0: region0 is not a region of persistent memory") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	// no nvdimm region appears
	f.Write("bus/cxl/devices/region0/pmem_region0/uevent", "")
	tctx, tcancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer tcancel()
	if _, err := g.CreatePmemRegion(tctx, "mem0", ""); err == nil || !strings.Contains(err.Error(), "region0: no nvdimm region appeared") {
		t.Fatalf("expected a timeout, got %v", err)
	}
}

// The errors of the probe are those of package kernel.
func TestProbeUnsupported(t *testing.T) {
	if !errors.Is(ErrProbeUnsupported, kernel.ErrProbeUnsupported) {
		t.Fatal("ErrProbeUnsupported is not the one of package kernel")
	}
}
