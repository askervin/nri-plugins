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

package kernel_test

import (
	"context"
	"encoding/json"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// mixedNode is a node with every kind of object: mem0 (RAM, 1 GiB) with
// region0 sliced into a numa slice (kmem, online) and a dax slice
// (device_dax); mem1 (persistent) with region1, an fsdax namespace, a
// direct node mount and a cached one on a loop device, and a container's
// copy of the direct one; mem2 disabled; and a hollow region of a memdev
// that was removed.
func mixedNode(t *testing.T) (*fake.Fake, *kernel.Kernel, string) {
	t.Helper()
	f := fake.New(t)
	f.Plug(fake.MemdevSpec{Serial: serial0, Ram: gib})
	f.Plug(fake.MemdevSpec{Serial: serial1, Pmem: pmemNsBytes, HostBridge: 24})
	f.Plug(fake.MemdevSpec{Serial: serial2, HostBridge: 24, Disabled: true})
	k := f.Kernel()
	ctx := ctxTimeout(t, 5*time.Second)
	createRegion(t, k, "mem0", kernel.RegionRAM, 0)
	noErr(t, k.UnbindDax(ctx, "dax0.0"))
	noErr(t, k.ResizeDaxDevice(ctx, "dax0.0", bs))
	noErr(t, k.BindDax(ctx, "dax0.0", kernel.DriverKmem))
	noErr(t, k.WaitDaxBlocks(ctx, "dax0.0"))
	noErr(t, k.OnlineBlocks([]int{74}, true))
	dax, err := k.CreateDaxDevice(ctx, "region0", bs)
	noErr(t, err)
	noErr(t, k.BindDax(ctx, dax, kernel.DriverDeviceDax))
	createRegion(t, k, "mem1", kernel.RegionPmem, 0)
	ns, err := k.CreateFsdaxNamespace(ctx, "region1", "")
	noErr(t, err)
	dev := ns.BlockDevice
	direct := mountPoint(t, "direct")
	noErr(t, k.FsMount(dev, direct, "ext4", true, []string{"dax=always"}))
	loop, err := k.AttachLoop(dev, false)
	noErr(t, err)
	noErr(t, k.Mount(loop.Path(), mountPoint(t, "cached"), "erofs", syscall.MS_RDONLY, "dax=never"))
	noErr(t, loop.Release(false))
	f.AddForeign(300, dev, "/run/cxl/fs/x", "ext4", false)
	h := f.HollowRegion("decoder0.0", 256*mib)
	if h != "region2" {
		t.Fatalf("hollow region %s", h)
	}
	return f, k, dev
}

// One observation of every object, with one definition each of hollow,
// enabled, online and the node of a region: the snapshot agrees with the
// readers of the objects.
func TestObserve(t *testing.T) {
	f, k, dev := mixedNode(t)
	s := observe(t, k)
	if len(s.Errors) != 0 {
		t.Fatalf("errors %v", s.Errors)
	}
	if s.BootID != f.BootID() || s.BlockSize != bs {
		t.Fatalf("boot %q block size %d", s.BootID, s.BlockSize)
	}
	for serial, want := range map[uint64]kernel.MemdevState{serial0: kernel.MemdevReady, serial1: kernel.MemdevReady,
		serial2: kernel.MemdevUnbound, 0x99: kernel.MemdevAbsent} {
		if m := s.Memdev(serial); m.State != want || !reflect.DeepEqual(m, k.Memdev(serial)) {
			t.Errorf("memdev %x: %+v, want %v (reader %+v)", serial, m, want, k.Memdev(serial))
		}
	}
	for name, want := range map[string]kernel.RegionState{"region0": kernel.RegionEnabled, "region1": kernel.RegionEnabled,
		"region2": kernel.RegionHollow, "region9": kernel.RegionAbsent} {
		r := s.Region(name)
		if r.State != want {
			t.Errorf("%s: %v, want %v", name, r.State, want)
		}
		if want != kernel.RegionAbsent {
			if got, _ := k.Region(name); !reflect.DeepEqual(r, got) {
				t.Errorf("%s: snapshot %+v, reader %+v", name, r, got)
			}
		}
	}
	if r := s.Region("region0"); r.NumaNode != 2 || r.Mode != kernel.RegionRAM || !reflect.DeepEqual(r.Serials, []uint64{serial0}) {
		t.Errorf("region0 %+v", r)
	}
	if r := s.Region("region1"); r.NdRegion != "region1" || r.Mode != kernel.RegionPmem || r.NumaNode != -1 {
		t.Errorf("region1 %+v", r)
	}
	if rs := s.RegionsOf(serial0); len(rs) != 1 || rs[0].Name != "region0" {
		t.Errorf("regions of mem0 %+v", rs)
	}
	for name, want := range map[string]kernel.DaxState{"dax0.0": kernel.DaxKmem, "dax0.1": kernel.DaxDeviceDax, "dax0.9": kernel.DaxAbsent} {
		d := s.DaxDevice(name)
		if d.State != want {
			t.Errorf("%s: %v, want %v", name, d.State, want)
		}
		if want != kernel.DaxAbsent {
			if got, _ := k.DaxDevice(name); !reflect.DeepEqual(d, got) {
				t.Errorf("%s: snapshot %+v, reader %+v", name, d, got)
			}
		}
	}
	if ds := s.DaxDevicesOf("region0"); len(ds) != 2 || len(s.DaxRegions) != 1 || s.DaxRegions[0].Available != gib-2*bs {
		t.Errorf("dax devices %+v, regions %+v", ds, s.DaxRegions)
	}
	if b := s.Block(74); b.State != kernel.BlockOnline || b.NumaNode != 2 || b.Zones != "Movable" {
		t.Errorf("memory74 %+v", b)
	}
	if b := s.Block(75); b.State != kernel.BlockAbsent {
		t.Errorf("memory75 %+v", b)
	}
	if online := s.OnlineBlocks([]int{74, 75}); !reflect.DeepEqual(online, []int{74}) {
		t.Errorf("online %v", online)
	}
	if n, ok := s.NumaNode(2); !ok || !n.HasMemory || n.MemTotal != bs {
		t.Errorf("node 2 %+v", n)
	}
	if p, ok := s.Port("port2"); !ok || p.Committed != 1 || p.Decoders[0].Region != "region1" {
		t.Errorf("port2 %+v", p)
	}
	if _, ok := s.Port("port9"); ok {
		t.Error("port9 found")
	}
	nd := s.NdRegionOf("region1")
	if nd.State != kernel.NdSettled || len(nd.Namespaces) != 1 || nd.Namespaces[0].State != kernel.NsFsdax {
		t.Errorf("nd region %+v", nd)
	}
	if nd := s.NdRegionOf("region0"); nd.State != kernel.NdAbsent {
		t.Errorf("nd region of a ram region %+v", nd)
	}
	if d, ok := s.BlockDevice(dev); !ok || d.Namespace != "namespace1.0" || d.Major != 259 || d.ReadOnly {
		t.Errorf("block device %+v", d)
	}
	loop := f.DevRoot() + "/loop0"
	if d, ok := s.BlockDevice(loop); !ok || d.Backing != dev || !d.ReadOnly || len(s.Loops) != 1 {
		t.Errorf("loop device %+v, loops %+v", d, s.Loops)
	}
	if sbs := s.SuperblocksOf(dev); len(sbs) != 2 || sbs[0].ReadOnly || !sbs[1].ReadOnly || sbs[1].Device != loop {
		t.Errorf("superblocks %+v", sbs)
	}
	if len(s.Mounts) != 2 {
		t.Errorf("mounts %+v", s.Mounts)
	}
	if _, err := json.Marshal(s); err != nil {
		t.Fatal(err)
	}
}

// A memdev or a region of a snapshot that cannot be read is named in
// Errors; the others are observed.
func TestObservePartial(t *testing.T) {
	f, k, _ := mixedNode(t)
	f.Write("bus/cxl/devices/mem2/serial", "bogus")
	f.Remove("devices/system/memory/block_size_bytes")
	s := observe(t, k)
	if len(s.Errors) != 2 || len(s.Memdevs) != 2 || len(s.Regions) != 3 || s.BlockSize != 0 {
		t.Fatalf("errors %v, %d memdevs, %d regions", s.Errors, len(s.Memdevs), len(s.Regions))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := k.Observe(ctx); err == nil {
		t.Fatal("an observation without its context")
	}
	// a node without CXL
	empty := &kernel.Kernel{SysRoot: t.TempDir(), ProcRoot: t.TempDir(), DevRoot: t.TempDir(), Sys: f.Kernel().Sys}
	s, err := empty.Observe(context.Background())
	if err != nil || len(s.Memdevs) != 0 || len(s.Regions) != 0 {
		t.Fatalf("empty node %+v %v", s, err)
	}
}

// The waits are woken by the events of the kernel: a wait whose polls are
// an hour apart ends at once when the memdev appears.
func TestWaitWokenByEvents(t *testing.T) {
	f := fake.New(t)
	k := f.Kernel()
	k.PollInterval = time.Hour
	go func() {
		time.Sleep(20 * time.Millisecond)
		f.Plug(fake.MemdevSpec{Serial: serial0})
	}()
	start := time.Now()
	if _, err := k.WaitMemdev(ctxTimeout(t, 10*time.Second), serial0, kernel.MemdevReady); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the wait took %v", d)
	}
}

// Changes closes every channel taken before a Notify, and only those.
func TestChanges(t *testing.T) {
	var c kernel.Changes
	a, b := c.Changed(), c.Changed()
	if a != b {
		t.Fatal("two channels before a change")
	}
	c.Notify()
	for _, ch := range []<-chan struct{}{a, b} {
		select {
		case <-ch:
		default:
			t.Fatal("not closed by Notify")
		}
	}
	next := c.Changed()
	select {
	case <-next:
		t.Fatal("closed before the next Notify")
	default:
	}
	c.Notify()
	<-next
}

// The address line probe and the zeroing of a dax device go to the memory
// of its character device: its numbers, its size and the align of its
// region; a device of size 0 has no aliasing.
func TestProbeAndZero(t *testing.T) {
	f, k := sliceNode(t)
	ctx := context.Background()
	noErr(t, k.ResizeDaxDevice(ctx, "dax0.0", 256*mib))
	noErr(t, k.BindDax(ctx, "dax0.0", kernel.DriverDeviceDax))
	f.Aliasing = &kernel.Aliasing{Offset: 64 * mib, Garbage: -1}
	a, err := k.ProbeAliasing("dax0.0")
	if err != nil || a.Offset != 64*mib {
		t.Fatalf("probe %s %v", a, err)
	}
	if a, err := k.ProbeAliasing("dax0.0"); err != nil || a.Offset != 0 || a.String() != "no aliasing" {
		t.Fatalf("second probe %s %v", a, err)
	}
	noErr(t, k.Zero(ctx, "dax0.0"))
	if z := f.Zeroed(); !reflect.DeepEqual(z, []string{"252:0 268435456 2097152"}) {
		t.Fatalf("zeroed %v", z)
	}
	if p := f.Probed(); len(p) != 2 || p[0] != "252:0 268435456" {
		t.Fatalf("probed %v", p)
	}
	d, err := k.CreateDaxDevice(ctx, "region0", 2*mib)
	noErr(t, err)
	noErr(t, k.ResizeDaxDevice(ctx, d, 0))
	if a, err := k.ProbeAliasing(d); err != nil || a.Offset != 0 || len(f.Probed()) != 2 {
		t.Fatalf("probe of an empty device %s %v", a, err)
	}
	f.ZeroErr = syscall.EIO
	wantErr(t, k.Zero(ctx, "dax0.0"), syscall.EIO, "zeroing dax0.0")
	// a stop in the probe
	f.CutProbe()
	func() {
		defer func() {
			if r := recover(); r != fake.ErrCut {
				t.Fatalf("recovered %v", r)
			}
		}()
		_, _ = k.ProbeAliasing("dax0.0")
	}()
	if _, err := k.ProbeAliasing("dax9.9"); err == nil {
		t.Fatal("probe of a missing device")
	}
}
