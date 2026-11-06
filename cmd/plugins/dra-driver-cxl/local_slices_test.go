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
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

const (
	// largeSerial is the serial of the memdev of 2 GiB of the tests with
	// memory blocks of largeBlockSize: its region starts 256 MiB after a
	// block boundary, with whole blocks 19, 20 and 21.
	largeSerial    = 0xc100e2e2
	largeBlockSize = 512 * mib
)

// sliceTestEnv is a localTestEnv with the checks of the slices of local
// memdevs in the fake kernel.
type sliceTestEnv struct {
	*localTestEnv
}

// newSliceTestEnv returns a node with the local memdev localSerial and the
// memdevs of specs plugged.
func newSliceTestEnv(t *testing.T, specs ...fake.MemdevSpec) *sliceTestEnv {
	t.Helper()
	return &sliceTestEnv{newLocalTestEnv(t, specs...)}
}

// newLargeBlocksEnv returns a node with memory blocks of largeBlockSize
// and the memdev largeSerial plugged besides localSerial, started.
func newLargeBlocksEnv(t *testing.T) *sliceTestEnv {
	t.Helper()
	e := newSliceTestEnv(t)
	e.k.SetBlockSize(largeBlockSize)
	e.plug(fake.MemdevSpec{Serial: largeSerial, Ram: 2 << 30})
	e.base = e.k.Commands()
	e.start()
	return e
}

// largeClaim returns a claim of bytes of the memdev largeSerial.
func largeClaim(uid string, bytes int64, configs ...string) *resourcev1.ResourceClaim {
	return memdevClaim(uid, memdevDeviceName(largeSerial), bytes, configs...)
}

// claimOfTwo returns a claim of the local memdev with the results of
// requests "mem" and "mem2", consuming bytes and bytes2 of it.
func claimOfTwo(uid string, bytes, bytes2 int64, configs ...string) *resourcev1.ResourceClaim {
	c := localClaim(uid, bytes, configs...)
	r := c.Status.Allocation.Devices.Results[0]
	r.Request = "mem2"
	r.ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityMemory: *resource.NewQuantity(bytes2, resource.BinarySI)}
	c.Status.Allocation.Devices.Results = append(c.Status.Allocation.Devices.Results, r)
	return c
}

// dax returns the dax device of result n of the claim uid.
func (e *sliceTestEnv) dax(uid string, n int) string {
	e.t.Helper()
	g := e.grant(uid, n)
	if g == nil {
		e.t.Fatalf("claim %s has no grant %d", uid, n)
	}
	return g.Got.Dax
}

// prepareFails prepares a claim that must fail with an error that
// contains substr, and returns the error.
func (e *sliceTestEnv) prepareFails(claim *resourcev1.ResourceClaim, substr string) error {
	e.t.Helper()
	err := e.prepare(claim)
	wantErr(e.t, err, substr)
	return err
}

// wantDax checks the size and the driver of a dax device.
func (e *sliceTestEnv) wantDax(dax string, size uint64, driver string) {
	e.t.Helper()
	if !e.k.DaxExists(dax) || e.k.DaxSize(dax) != size || e.k.DaxDriver(dax) != driver {
		e.t.Fatalf("%s: exists %v, size %d, driver %q; expected size %d, driver %q", dax, e.k.DaxExists(dax), e.k.DaxSize(dax), e.k.DaxDriver(dax), size, driver)
	}
}

// wantGone checks that the dax devices do not exist.
func (e *sliceTestEnv) wantGone(daxes ...string) {
	e.t.Helper()
	for _, dax := range daxes {
		if e.k.DaxExists(dax) {
			e.t.Fatalf("%s exists (size %d, driver %q)", dax, e.k.DaxSize(dax), e.k.DaxDriver(dax))
		}
	}
}

// wantRanges checks the memory of a dax device.
func (e *sliceTestEnv) wantRanges(dax string, want ...kernel.Range) {
	e.t.Helper()
	if got := e.k.DaxRanges(dax); !slices.Equal(got, want) {
		e.t.Fatalf("%s: memory %v, expected %v", dax, got, want)
	}
}

// blockRange returns the memory of n memory blocks of the fake from block
// b.
func (e *sliceTestEnv) blockRange(b, n uint64) kernel.Range {
	bs, err := e.k.Kernel().BlockSize()
	noErr(e.t, err)
	return kernel.Range{Start: b * bs, End: (b+n)*bs - 1}
}

// wantMemoryBlocks checks that exactly the memory blocks listed exist, and
// that they are online movable.
func (e *sliceTestEnv) wantMemoryBlocks(blocks ...int) {
	e.t.Helper()
	m, _ := filepath.Glob(e.k.P("devices/system/memory/memory[0-9]*"))
	got := []string{}
	for _, d := range m {
		rel := "devices/system/memory/" + filepath.Base(d)
		got = append(got, filepath.Base(d)+" "+e.k.Read(rel+"/state")+" "+e.k.Read(rel+"/valid_zones"))
	}
	want := []string{}
	for _, b := range blocks {
		want = append(want, fmt.Sprintf("memory%d online Movable", b))
	}
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		e.t.Fatalf("memory blocks %v, expected %v", got, want)
	}
}

// wantUsed checks whether the engine has a record of the local memdev.
func (e *sliceTestEnv) wantUsed(used bool) {
	e.t.Helper()
	if got := e.inUse(); got != used {
		e.t.Fatalf("memdev used %v, expected %v", got, used)
	}
}

// wantRegionReleased checks that the region was released last, and the
// memdev not disabled.
func (e *sliceTestEnv) wantRegionReleased(region string) {
	e.t.Helper()
	cmds := e.commands()
	if !strings.HasSuffix(cmds, "cxl disable-region "+region+"\ncxl destroy-region "+region) || strings.Contains(cmds, "disable-memdev") {
		e.t.Fatalf("%s not released:\n%s", region, cmds)
	}
}

// availableSize returns the free memory of the dax region of a region.
func (e *sliceTestEnv) availableSize(region string) string {
	return e.k.Read("bus/cxl/devices/" + region + "/dax_" + region + "/dax_region/available_size")
}

// The memory block size is read as hex, and again for every slice and
// every snapshot of the publisher.
func TestLocalBlockSize(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	// "8000000" is hex
	if bs := e.s.local.Snapshot().BlockSize; bs != 134217728 {
		t.Fatalf("block size %d of %q", bs, e.k.Read("devices/system/memory/block_size_bytes"))
	}
	// 2 GiB blocks: a 128 MiB claim needs a 2 GiB slice
	e.k.SetBlockSize(2 << 30)
	if err := e.prepareFails(localClaim("u1", 128*mib), "the slice needs 2147483648"); !errors.Is(err, kernel.ErrNoRoom) {
		t.Fatalf("expected no room, got %v", err)
	}
	e.wantRegionReleased("region0")
	if bs := e.s.local.Snapshot().BlockSize; bs != 2<<30 {
		t.Fatalf("block size %d after the change", bs)
	}
	e.wantUsed(false)
	e.k.Write("devices/system/memory/block_size_bytes", "bogus")
	_ = e.prepareFails(localClaim("u1", 128*mib, localDaxConfig), "memory block size")
	e.wantUsed(false)
	// unknown at start: the snapshot reads it again
	e.k.Remove("devices/system/memory/block_size_bytes")
	e.restart()
	if bs := e.s.local.Snapshot().BlockSize; bs != 0 {
		t.Fatalf("block size %d without block_size_bytes", bs)
	}
	e.k.SetBlockSize(localBlockSize)
	if bs := e.s.local.Snapshot().BlockSize; bs != localBlockSize {
		t.Fatalf("block size %d", bs)
	}
	var none *localDevices
	if none.Snapshot() != nil {
		t.Fatal("snapshot of no local devices")
	}
	if off := newLocalDevices(e.devices, e.st, e.k.Kernel(), e.k.BootID(), false); off.Snapshot() != nil {
		t.Fatal("snapshot of unmanaged local devices")
	}
}

// Dax and numa slices share a region on whole blocks, numa blocks go online
// and offline with their slice, the region goes with the last slice.
func TestLocalMixedSlices(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()

	// a dax slice of 64 MiB is rounded up to a block: dax0.0 is reused
	e.mustPrepare(localClaim("u1", 64*mib, localDaxConfig))
	g := e.grant("u1", 0)
	if g.Got.Region != "region0" || g.Got.Dax != "dax0.0" || g.Got.Size != localBlockSize || g.Got.DaxDev.Major != 252 || g.Got.DaxDev.Minor != 0 {
		t.Fatalf("dax slice %+v", g.Got)
	}
	if info := e.s.GetClaimInfo("u1").Devices[0]; info.Mode != api.ModeDax || info.DaxDevice != filepath.Join(e.k.DevRoot(), "dax0.0") || info.DaxMajor != 252 || info.TotalBytes != localBlockSize {
		t.Fatalf("device info %+v", info)
	}
	if !strings.Contains(e.commands(), "cxl create-region -t ram -d decoder0.0 -m mem0") {
		t.Fatalf("commands:\n%s", e.commands())
	}
	e.wantDax("dax0.0", localBlockSize, kernel.DriverDeviceDax)
	e.wantRanges("dax0.0", e.blockRange(74, 1))
	e.wantMemoryBlocks()
	e.wantUsed(true)

	// a numa slice: the next block, onlined movable
	e.mustPrepare(localClaim("u2", localBlockSize))
	if g := e.grant("u2", 0); g.Got.Dax != "dax0.1" || g.Got.Size != localBlockSize || g.Got.NumaNode == nil || *g.Got.NumaNode != 2 {
		t.Fatalf("numa slice %+v", g.Got)
	}
	e.wantDax("dax0.1", localBlockSize, kernel.DriverKmem)
	e.wantRanges("dax0.1", e.blockRange(75, 1))
	e.wantMemoryBlocks(75)

	// a dax slice of two blocks, and a numa slice of two blocks
	e.mustPrepare(localClaim("u3", 2*localBlockSize, localDaxConfig))
	e.wantRanges("dax0.2", e.blockRange(76, 2))
	e.mustPrepare(localClaim("u4", 2*localBlockSize-mib))
	e.wantDax("dax0.3", 2*localBlockSize, kernel.DriverKmem)
	e.wantRanges("dax0.3", e.blockRange(78, 2))
	e.wantMemoryBlocks(75, 78, 79)
	if n := strings.Count(e.commands(), "create-region"); n != 1 {
		t.Fatalf("region created %d times", n)
	}
	if avail := e.availableSize("region0"); avail != fmt.Sprint(localRegionSize-6*localBlockSize) {
		t.Fatalf("available %s", avail)
	}

	// a numa release offlines its blocks only, and first-fit fills the gap
	e.mustUnprepare("u2")
	e.wantGone("dax0.1")
	e.wantMemoryBlocks(78, 79)
	e.wantUsed(true)
	e.mustPrepare(localClaim("u5", localBlockSize))
	e.wantRanges(e.dax("u5", 0), e.blockRange(75, 1))
	e.wantMemoryBlocks(75, 78, 79)

	// a dax release keeps dax0.0 with size 0
	e.mustUnprepare("u1")
	e.wantDax("dax0.0", 0, "")
	e.mustUnprepare("u4")
	e.mustUnprepare("u5")
	e.wantMemoryBlocks()
	e.wantUsed(true)
	if strings.Contains(e.commands(), "destroy-region") {
		t.Fatalf("region released while a slice exists:\n%s", e.commands())
	}
	// the last slice takes the region with it, the memdev stays enabled
	e.mustUnprepare("u3")
	e.wantRegionReleased("region0")
	if !e.k.Exists("bus/cxl/devices/mem0/driver") {
		t.Fatal("memdev disabled")
	}
	e.wantUsed(false)
	e.mustUnprepare("u3")
	e.wantClean()

	// only dax slices are zeroed, after they are bound
	want := "252:0 134217728 2097152,252:2 268435456 2097152"
	if got := strings.Join(e.k.Zeroed(), ","); got != want {
		t.Fatalf("zeroed %s, expected %s", got, want)
	}
	// numa slices are bound to kmem through sysfs
	if strings.Contains(e.commands(), "daxctl") {
		t.Fatalf("daxctl bound kmem:\n%s", e.commands())
	}
}

// Dax slices, read-only or not, of one claim or two: a slice that does not
// fit fails without a new dax device; a released dax0.0 is reused.
func TestLocalDaxSlices(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()

	e.mustPrepare(localClaim("u1", localBlockSize, localDaxConfig))
	if g := e.grant("u1", 0); g.Got.Dax != "dax0.0" || g.Got.Size != localBlockSize || g.Got.DaxDev.Major != 252 || g.Got.DaxDev.Minor != 0 {
		t.Fatalf("slice %+v", g.Got)
	}
	e.mustPrepare(localClaim("u2", 3*mib, localROConfig))
	if g := e.grant("u2", 0); g.Got.Dax != "dax0.1" || g.Got.Size != localBlockSize || g.Got.DaxDev.Minor != 1 || !g.Asked.ReadOnly {
		t.Fatalf("read-only slice %+v %+v", g.Asked, g.Got)
	}
	if info := e.s.GetClaimInfo("u2").Devices[0]; !info.ReadOnly || info.DaxDevice != filepath.Join(e.k.DevRoot(), "dax0.1") || info.DaxMinor != 1 {
		t.Fatalf("read-only device info %+v", info)
	}
	// a slice larger than the free space
	if err := e.prepareFails(localClaim("u3", localRegionSize, localDaxConfig), "the slice needs 1073741824"); !errors.Is(err, kernel.ErrNoRoom) {
		t.Fatalf("expected no room, got %v", err)
	}
	e.wantGone("dax0.2")
	if p := e.preparation("u3"); p != nil {
		t.Fatalf("preparation of a failed claim %+v", p)
	}
	// releasing the first slice keeps dax0.0 with size 0 for the next
	e.mustUnprepare("u1")
	e.wantDax("dax0.0", 0, "")
	// a claim of two slices, each of them rounded up to a memory block:
	// the first gets dax0.0
	e.mustPrepare(claimOfTwo("u3", 16*mib, 2*mib, localDaxConfig))
	if g := e.grant("u3", 0); g.Got.Dax != "dax0.0" || g.Got.Size != localBlockSize || g.Got.Region != "region0" ||
		g.Got.DaxDev.Major != 252 || g.Got.DaxDev.Minor != 0 {
		t.Fatalf("first slice %+v", g.Got)
	}
	if g := e.grant("u3", 1); g.Got.Dax != "dax0.2" || g.Got.Size != localBlockSize {
		t.Fatalf("second slice %+v", g.Got)
	}
	if info := e.s.GetClaimInfo("u3"); len(info.Devices) != 2 {
		t.Fatalf("device info %+v", info)
	}
	e.mustUnprepare("u2")
	e.mustUnprepare("u3")
	e.wantGone("dax0.1", "dax0.2")
	e.wantRegionReleased("region0")
	e.wantUsed(false)
	e.wantClean()
}

// Slices of both modes are bound through the sysfs attributes of the dax
// drivers, never with daxctl.
func TestLocalSlicesSysfs(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	e.mustPrepare(localClaim("u1", 8*mib, localDaxConfig))
	e.wantDax("dax0.0", localBlockSize, kernel.DriverDeviceDax)
	if w := e.k.Writes(); !slices.Contains(w, "bus/dax/drivers/device_dax/new_id") {
		t.Fatalf("writes %v", w)
	}
	e.mustPrepare(localClaim("u2", 8*mib))
	e.wantDax("dax0.1", localBlockSize, kernel.DriverKmem)
	if w := e.k.Writes(); !slices.Contains(w, "bus/dax/drivers/kmem/bind") {
		t.Fatalf("writes %v", w)
	}
	e.wantMemoryBlocks(75)
	e.mustUnprepare("u2")
	e.mustUnprepare("u1")
	e.wantRegionReleased("region0")
	if strings.Contains(e.commands(), "daxctl") {
		t.Fatalf("daxctl used:\n%s", e.commands())
	}
}

// A slice that first-fit places across a block boundary goes on the first
// whole free blocks, combining free ranges (512 MiB blocks: blocks 19-21).
func TestLocalPlacement(t *testing.T) {
	e := newLargeBlocksEnv(t)

	// first-fit would give dax0.0 the head of the region
	e.mustPrepare(largeClaim("u1", largeBlockSize))
	e.wantDax("dax0.0", 0, "")
	u1 := e.dax("u1", 0)
	e.wantDax(u1, largeBlockSize, kernel.DriverKmem)
	e.wantRanges(u1, e.blockRange(19, 1))
	e.wantMemoryBlocks(19)
	// dax slices too: never the head, never half a block
	e.mustPrepare(largeClaim("u2", largeBlockSize, localDaxConfig))
	e.wantRanges(e.dax("u2", 0), e.blockRange(20, 1))
	e.mustPrepare(largeClaim("u3", largeBlockSize))
	e.wantRanges(e.dax("u3", 0), e.blockRange(21, 1))
	e.wantMemoryBlocks(19, 21)
	// a block is free, in the head and the tail: no whole block
	_ = e.prepareFails(largeClaim("u4", largeBlockSize, localDaxConfig), "no 536870912 bytes of whole free memory blocks in region0")
	if devs := e.k.Kernel().DaxDevices("region0"); !slices.Equal(devs, []string{"dax0.0", "dax0.1", "dax0.2", "dax0.3"}) {
		t.Fatalf("dax devices %v", devs)
	}
	e.wantDax("dax0.0", 0, "")

	// two free blocks apart: a numa slice of two ranges, onlined and
	// offlined
	e.mustUnprepare("u1")
	e.mustUnprepare("u3")
	e.wantMemoryBlocks()
	e.mustPrepare(largeClaim("u5", 2*largeBlockSize))
	u5 := e.dax("u5", 0)
	e.wantRanges(u5, e.blockRange(19, 1), e.blockRange(21, 1))
	e.wantDax(u5, 2*largeBlockSize, kernel.DriverKmem)
	e.wantMemoryBlocks(19, 21)
	e.mustUnprepare("u5")
	e.wantMemoryBlocks()
	e.mustUnprepare("u2")
	e.wantRegionReleased("region0")
	e.wantClean()
}

// With blocks larger than the region alignment the memdev publishes the
// whole blocks it is sure to have and serves both modes in any order.
func TestLocalLargeBlocks(t *testing.T) {
	e := newLargeBlocksEnv(t)
	bs := uint64(largeBlockSize)
	dev := e.s.Allocatable.(device.DevicesInfo)[memdevDeviceName(largeSerial)]
	if dev == nil {
		t.Fatalf("not published: %v", e.s.Allocatable)
	}
	if p := localMemdevDevice(dev.Name, dev.Dev.(*device.Memdev)).Capacity[device.CapacityMemory].RequestPolicy; p == nil ||
		p.Default.String() != "1536Mi" || p.ValidRange.Step.String() != "512Mi" {
		t.Fatalf("request policy %+v", p)
	}
	e.mustPrepare(largeClaim("u1", int64(bs), localDaxConfig))
	e.mustPrepare(largeClaim("u2", int64(bs)))
	e.mustPrepare(largeClaim("u3", int64(bs), localDaxConfig))
	if r, err := e.k.Kernel().RegionRange("region0"); err != nil || r.Start%bs != 256*mib {
		t.Fatalf("region at %v: %v", r, err)
	}
	e.wantRanges(e.dax("u1", 0), e.blockRange(19, 1))
	e.wantRanges(e.dax("u2", 0), e.blockRange(20, 1))
	e.wantRanges(e.dax("u3", 0), e.blockRange(21, 1))
	e.wantMemoryBlocks(20)
	// no fourth block
	_ = e.prepareFails(largeClaim("u4", int64(bs)), "no room")
	// the released blocks serve the other mode
	e.mustUnprepare("u2")
	e.mustUnprepare("u1")
	e.mustPrepare(largeClaim("u5", int64(bs), localDaxConfig))
	e.mustPrepare(largeClaim("u6", int64(bs)))
	e.wantRanges(e.dax("u5", 0), e.blockRange(19, 1))
	e.wantRanges(e.dax("u6", 0), e.blockRange(20, 1))
	e.wantMemoryBlocks(20)
	for _, uid := range []string{"u3", "u5", "u6"} {
		e.mustUnprepare(uid)
	}
	e.wantRegionReleased("region0")
	e.wantMemoryBlocks()
	e.wantClean()
}

// Failures while a slice is placed on whole blocks, bound or onlined leave
// nothing behind (the layout of TestLocalPlacement).
func TestLocalPlacementFailures(t *testing.T) {
	e := newLargeBlocksEnv(t)
	bs := int64(largeBlockSize)

	// the misplaced first-fit device cannot be deleted
	e.k.FailWrite("bus/dax/devices/dax0.0/size", nil, syscall.EIO)
	_ = e.prepareFails(largeClaim("u1", bs), "dax0.0: set size 0: input/output error")
	e.wantRegionReleased("region0")
	if e.s.local.Snapshot().uses(largeSerial) {
		t.Fatal("memdev used after a failed slice")
	}

	e.mustPrepare(largeClaim("u1", bs, localDaxConfig))
	e.wantRanges(e.dax("u1", 0), e.blockRange(19, 1))
	// the placed device cannot be mapped
	e.k.FailWrite("bus/dax/devices/dax0.2/mapping", syscall.EIO)
	_ = e.prepareFails(largeClaim("u2", bs), "dax0.2: map 0x280000000-0x29fffffff: input/output error")
	e.wantGone("dax0.2")
	// the placed device cannot be bound to kmem: it goes, dax0.0 stays
	e.k.FailWrite("bus/dax/drivers/kmem/bind", syscall.EIO)
	_ = e.prepareFails(largeClaim("u2", bs), "bind dax0.2 to kmem: input/output error")
	e.wantGone("dax0.2")
	e.wantDax("dax0.0", 0, "")
	e.wantDax(e.dax("u1", 0), largeBlockSize, kernel.DriverDeviceDax)
	// the free memory of the region cannot be read when the misplaced
	// first-fit device is deleted
	size := e.k.Read("bus/cxl/devices/region0/size")
	e.k.Before("write bus/dax/devices/dax0.0/size 0", func() { e.k.Write("bus/cxl/devices/region0/size", "bogus") })
	err := e.s.Prepare(context.Background(), largeClaim("u2", bs, localDaxConfig))
	e.k.Write("bus/cxl/devices/region0/size", size)
	// the available size that the fake wrote while the size was bogus
	free := uint64(0)
	for _, g := range e.k.Gaps("region0") {
		free += g.Size()
	}
	e.k.Write("bus/cxl/devices/region0/dax_region0/dax_region/available_size", fmt.Sprint(free))
	e.check("prepared u2")
	wantErr(t, err, "cannot parse region region0")
	e.wantDax("dax0.0", 0, "")
	if devs := e.k.Kernel().DaxDevices("region0"); len(devs) != 2 {
		t.Fatalf("dax devices %v", devs)
	}
	if n := len(e.records().Grants); n != 1 {
		t.Fatalf("grants %+v", e.records().Grants)
	}
	e.wantMemoryBlocks()

	// the memory blocks of kmem never appear
	e.k.NoKmemBlocks = true
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = e.s.Prepare(ctx, largeClaim("u2", bs))
	e.k.NoKmemBlocks = false
	e.check("prepared u2")
	wantErr(t, err, "0 of 1 memory blocks appeared: context deadline exceeded")
	if devs := e.k.Kernel().DaxDevices("region0"); len(devs) != 2 {
		t.Fatalf("dax devices %v", devs)
	}
	e.mustUnprepare("u1")
	e.wantRegionReleased("region0")
	e.wantClean()
}

// A slice whose release failed is never handed out again and keeps the
// region: its grant stays RELEASING until its claim's next Unprepare.
func TestLocalFailedReleases(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	e.mustPrepare(localClaim("u1", localBlockSize))
	e.mustPrepare(localClaim("u2", localBlockSize, localDaxConfig))
	e.wantDax("dax0.0", localBlockSize, kernel.DriverKmem)
	e.wantMemoryBlocks(74)

	// the memory of u1 cannot be offlined
	e.k.FailWrite("devices/system/memory/memory74/state", syscall.EBUSY)
	wantErr(t, e.unprepare("u1"), "releasing slice dax0.0: cannot offline its memory (in use?)")
	if g := e.grant("u1", 0); g == nil || g.State != state.GrantReleasing || g.Got.Dax != "dax0.0" {
		t.Fatalf("grant of the failed release %+v", g)
	}
	// the next slice does not get it
	e.mustPrepare(localClaim("u3", localBlockSize, localDaxConfig))
	if d := e.dax("u3", 0); d == "dax0.0" {
		t.Fatalf("slice %s of a failed release handed out", d)
	}
	e.wantDax("dax0.0", localBlockSize, kernel.DriverKmem)
	e.wantMemoryBlocks(74)
	// kubelet's retry releases it
	e.mustUnprepare("u1")
	e.wantDax("dax0.0", 0, "")
	e.wantMemoryBlocks()

	// a numa slice whose rollback cannot offline it: dax0.0 again, on the
	// free blocks 74 and 77
	e.k.FailWrite("devices/system/memory/memory77/state", syscall.EIO)
	e.k.FailWrite("devices/system/memory/memory74/state", nil, syscall.EBUSY)
	_ = e.prepareFails(localClaim("u4", 2*localBlockSize), "memory77: online_movable: input/output error")
	g := e.grant("u4", 0)
	if g == nil || g.State != state.GrantReleasing || g.Got.Dax != "dax0.0" {
		t.Fatalf("grant of the failed rollback %+v", g)
	}
	e.wantDax("dax0.0", 2*localBlockSize, kernel.DriverKmem)
	e.wantRanges("dax0.0", e.blockRange(74, 1), e.blockRange(77, 1))
	if online := e.onlineBlocks(); !slices.Equal(online, []int{74}) {
		t.Fatalf("blocks %v online", online)
	}
	if p := e.preparation("u4"); p == nil || p.State != state.PreparationKept {
		t.Fatalf("preparation of the failed rollback %+v", p)
	}
	// the last claim keeps the region for it; the Unprepare of its claim
	// releases it
	e.mustUnprepare("u2")
	e.mustUnprepare("u3")
	if strings.Contains(e.commands(), "destroy-region") {
		t.Fatalf("region released with the slice of a failed release:\n%s", e.commands())
	}
	e.wantUsed(true)
	e.mustUnprepare("u4")
	e.wantRegionReleased("region0")
	e.wantMemoryBlocks()
	e.wantClean()

	// restart: u1 is not prepared (its Prepare was cut after its memory
	// went online), and its memory cannot be offlined: its grant keeps the
	// part for its Unprepare
	e.mustPrepare(localClaim("u2", localBlockSize, localDaxConfig))
	e.k.CutAfter("write devices/system/memory/memory75/state online_movable")
	if !e.cut(func() { _ = e.s.Prepare(context.Background(), localClaim("u1", localBlockSize)) }) {
		t.Fatal("the Prepare was not cut")
	}
	e.k.FailWrite("devices/system/memory/memory75/state", syscall.EBUSY)
	e.restart()
	if g := e.grant("u1", 0); g == nil || g.State != state.GrantRealising || g.Got.Dax != "dax0.1" {
		t.Fatalf("grant after the restart %+v", g)
	}
	if p := e.preparation("u1"); p == nil || p.State != state.PreparationKept {
		t.Fatalf("preparation after the restart %+v", p)
	}
	e.mustPrepare(localClaim("u3", localBlockSize, localDaxConfig))
	if d := e.dax("u3", 0); d == "dax0.1" {
		t.Fatalf("slice %s of a failed release handed out", d)
	}
	e.wantMemoryBlocks(75)
	e.mustUnprepare("u1")
	e.wantGone("dax0.1")
	e.mustUnprepare("u2")
	e.mustUnprepare("u3")
	e.wantClean()
}

// A kmem device with online memory that no record names is not reused nor
// unbound; a restart offlines and deletes it.
func TestLocalUntrackedKmem(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	ctx := context.Background()
	e.mustPrepare(localClaim("u1", localBlockSize))
	e.mustPrepare(localClaim("u2", localBlockSize, localDaxConfig))
	k := e.k.Kernel()
	stray, err := k.CreateDaxDevice(ctx, "region0", localBlockSize)
	noErr(t, err)
	noErr(t, k.BindDax(ctx, stray, kernel.DriverKmem))
	noErr(t, k.WaitDaxBlocks(ctx, stray))
	noErr(t, k.OnlineBlocks([]int{76}, true))
	// the records do not name it: a Prepare without the check of the
	// invariants
	noErr(t, e.s.Prepare(ctx, localClaim("u3", localBlockSize, localDaxConfig)))
	if d := e.dax("u3", 0); d == stray {
		t.Fatalf("%s with online memory reused", d)
	}
	e.wantDax(stray, localBlockSize, kernel.DriverKmem)
	e.wantMemoryBlocks(74, 76)
	wantErr(t, k.ResizeDaxDevice(ctx, stray, 0), stray+": memory blocks [76] are not offline")
	e.restart()
	e.wantGone(stray)
	e.wantMemoryBlocks(74)
	for _, uid := range []string{"u1", "u2", "u3"} {
		e.mustUnprepare(uid)
	}
	e.wantClean()
}

// A numa slice that fails to offline keeps its grant RELEASING until the
// Unprepare is retried; other claims are not affected.
func TestLocalNUMAReleaseFailure(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	e.mustPrepare(localClaim("u1", 2*localBlockSize))
	e.k.FailWrite("devices/system/memory/memory75/state", syscall.EBUSY)
	err := e.unprepare("u1")
	wantErr(t, err, "releasing slice dax0.0: cannot offline its memory (in use?)")
	wantErr(t, err, "device or resource busy")
	if e.k.BlockState(74) != kernel.BlockStateOffline || e.k.BlockState(75) != kernel.BlockStateOnline {
		t.Fatalf("memory74 %q, memory75 %q", e.k.BlockState(74), e.k.BlockState(75))
	}
	e.wantDax("dax0.0", 2*localBlockSize, kernel.DriverKmem)
	if g := e.grant("u1", 0); g == nil || g.State != state.GrantReleasing || g.Got.Dax != "dax0.0" {
		t.Fatalf("grant %+v", g)
	}
	if p := e.preparation("u1"); p == nil || p.State != state.PreparationUnpreparing {
		t.Fatalf("preparation %+v", p)
	}
	// another numa claim gets a slice of its own meanwhile
	e.mustPrepare(localClaim("u2", localBlockSize))
	e.wantRanges(e.dax("u2", 0), e.blockRange(76, 1))
	e.mustUnprepare("u1")
	e.wantMemoryBlocks(76)
	if strings.Contains(e.commands(), "destroy-region") {
		t.Fatalf("region destroyed while u2 uses it:\n%s", e.commands())
	}
	// a slice that fails to delete after the offline
	u2 := e.dax("u2", 0)
	e.k.FailWrite("bus/dax/devices/"+u2+"/size", syscall.EBUSY)
	wantErr(t, e.unprepare("u2"), "releasing slice "+u2)
	e.wantMemoryBlocks()
	e.wantDax(u2, localBlockSize, "")
	e.mustUnprepare("u2")
	e.wantRegionReleased("region0")
	e.wantClean()
}

// A region creation before the endpoint port is retried once, a foreign
// region is refused; claims that cannot be served fail without commands.
func TestLocalRegionErrors(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	ctx := context.Background()

	// a transient region creation failure is retried once
	e.k.FailCommand("cxl create-region", fake.ErrAddDev)
	e.mustPrepare(localClaim("u1", localBlockSize))
	if n := strings.Count(e.commands(), "create-region"); n != 2 {
		t.Fatalf("region created %d times:\n%s", n, e.commands())
	}
	e.mustUnprepare("u1")

	// two failures make the claim fail and leave nothing
	e.k.FailCommand("cxl create-region", fake.ErrAddDev, fake.ErrAddDev)
	_ = e.prepareFails(localClaim("u1", localBlockSize), "add_dev")
	e.wantUsed(false)
	e.wantClean()

	// a region that the plugin did not create
	_, err := e.k.Exec(ctx, "cxl", "create-region", "-t", "ram", "-d", "decoder0.0", "-m", "mem0")
	noErr(t, err)
	e.base = e.k.Commands()
	_ = e.prepareFails(localClaim("u1", localBlockSize, localDaxConfig), "memdev mem0 has region region0 that the plugin did not create")
	e.wantUsed(false)
	if cmds := e.commands(); cmds != "" {
		t.Fatalf("the region of another was touched:\n%s", cmds)
	}
	noErr(t, e.k.Kernel().ReleaseRegion(ctx, "region0"))
	e.base = e.k.Commands()

	// a memdev that is gone, an invalid mode or size
	e.k.Unplug(localSerial)
	if err := e.prepareFails(localClaim("u1", localBlockSize), "no CXL memory device with the serial 0xc100e2e1"); !errors.Is(err, kernel.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
	e.k.Plug(fake.MemdevSpec{Serial: localSerial, Ram: localRegionSize})
	_ = e.prepareFails(localClaim("u1", localBlockSize, memoryConfig("ram", false, "")), `invalid mode "ram"`)
	devs := e.s.Allocatable.(device.DevicesInfo)
	info := *devs[localDeviceName]
	memdev := *info.Dev.(*device.Memdev)
	memdev.Size = 0
	info.Dev = &memdev
	e.s.Allocatable = device.DevicesInfo{localDeviceName: &info}
	_ = e.prepareFails(localClaim("u1", 0), "size 0")
	e.s.Allocatable = devs
	// local memdevs not managed
	e.s.local = newLocalDevices(e.devices, e.st, e.k.Kernel(), e.k.BootID(), false)
	_ = e.prepareFails(localClaim("u1", localBlockSize), "manageMemdevs: false")
	e.mustUnprepare("u1")
	if cmds := e.commands(); cmds != "" {
		t.Fatalf("commands of refused claims:\n%s", cmds)
	}
	e.wantClean()
}

// localDevices.json has the slices of the claims; a start releases cut
// Prepares, unnamed dax devices, gone slices, idle regions, another boot's.
func TestLocalStateAndReconcile(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	ctx := context.Background()
	e.mustPrepare(localClaim("u1", localBlockSize, localDaxConfig))
	e.mustPrepare(localClaim("u2", localBlockSize))
	e.mustPrepare(localClaim("u3", localBlockSize, localDaxConfig))
	path := filepath.Join(e.dir, "localDevices.json")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("localDevices.json: %v %v", st, err)
	}
	data, _ := os.ReadFile(path)
	for _, want := range []string{`"serialHex": "c100e2e1"`, `"region": "region0"`, `"mode": "dax"`, `"mode": "numa"`, `"dax": "dax0.1"`,
		`"daxDevice": "` + filepath.Join(e.k.DevRoot(), "dax0.2") + `"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("localDevices.json lacks %s:\n%s", want, data)
		}
	}
	if d := e.localDevice(localSerial); d == nil || len(d.Claims) != 3 || d.Claims["u2"][0].Mode != api.ModeNUMA || d.Claims["u2"][0].Dax != "dax0.1" {
		t.Fatalf("view %+v", d)
	}

	// restart: the numa claim u4 is not prepared (its Prepare was cut after
	// its memory went online): its memory is offlined and its slice
	// deleted
	e.k.CutAfter("write devices/system/memory/memory77/state online_movable")
	if !e.cut(func() { _ = e.s.Prepare(ctx, localClaim("u4", localBlockSize)) }) {
		t.Fatal("the Prepare was not cut")
	}
	u4 := e.dax("u4", 0)
	e.restart()
	e.wantGone(u4)
	if d := e.localDevice(localSerial); d == nil || len(d.Claims) != 3 || e.grant("u4", 0) != nil {
		t.Fatalf("after the restart: %+v, u4 %+v", d, e.grant("u4", 0))
	}
	// its preparation stays for kubelet's retry
	if p := e.preparation("u4"); p == nil || p.State != state.PreparationPreparing {
		t.Fatalf("preparation of the cut Prepare %+v", p)
	}
	e.mustUnprepare("u4")
	e.wantMemoryBlocks(75)
	e.wantUsed(true)

	// restart: a dax device that belongs to no claim is deleted, a kmem
	// one offlined first
	k := e.k.Kernel()
	stray, err := k.CreateDaxDevice(ctx, "region0", localBlockSize)
	noErr(t, err)
	noErr(t, k.BindDax(ctx, stray, kernel.DriverKmem))
	noErr(t, k.WaitDaxBlocks(ctx, stray))
	blocks, err := k.DaxDeviceBlocks(stray, localBlockSize)
	noErr(t, err)
	noErr(t, k.OnlineBlocks(blocks, true))
	e.restart()
	e.wantGone(stray)
	e.wantMemoryBlocks(75)
	e.wantDax("dax0.2", localBlockSize, kernel.DriverDeviceDax)

	// restart: the slice of u1 is gone (size changed): it is forgotten
	noErr(t, k.ResizeDaxDevice(ctx, "dax0.0", 2*localBlockSize))
	e.restart()
	if g := e.grant("u1", 0); g == nil || g.Got.Dax != "" {
		t.Fatalf("grant of the gone slice %+v", g)
	}
	e.wantDax("dax0.0", 0, "")
	e.mustUnprepare("u2")
	e.mustUnprepare("u3")
	e.mustUnprepare("u1")
	e.wantUsed(false)
	e.wantRegionReleased("region0")

	// restart: a region without claims (a Prepare cut after the region
	// was created) is destroyed
	e.k.CutAfter("cxl create-region")
	if !e.cut(func() { _ = e.s.Prepare(ctx, localClaim("u1", localBlockSize)) }) {
		t.Fatal("the Prepare was not cut")
	}
	e.restart()
	e.wantUsed(false)
	e.wantRegionReleased("region0")
	e.wantMemoryBlocks()
	e.mustUnprepare("u1")

	// restart: the region is gone (destroyed by another, or a reboot)
	e.mustPrepare(localClaim("u1", localBlockSize))
	noErr(t, k.OfflineBlocks(ctx, []int{74}, 0, 0))
	noErr(t, k.ReleaseRegion(ctx, "region0"))
	e.restart()
	if r := e.records().Region("region0"); r != nil || len(e.regions(localSerial)) != 0 {
		t.Fatalf("record of a gone region %+v", r)
	}
	e.mustUnprepare("u1")
	e.wantUsed(false)
	e.mustPrepare(localClaim("u1", localBlockSize))
	e.reboot()
	e.wantUsed(false)
	e.wantClean()

	// restart: the memdev is gone: its records stay for kubelet's
	// Unprepare
	e.mustPrepare(localClaim("u1", localBlockSize, localDaxConfig))
	e.k.Unplug(localSerial)
	e.restart()
	if m := e.records().Memdev(localSerial); m == nil || m.State != state.MemdevGone {
		t.Fatalf("memdev record %+v", m)
	}
	e.mustUnprepare("u1")
	e.wantUsed(false)
}

// A failed set-up of the region or a slice leaves nothing of it; a slice
// that fails to delete stays with its claim until a retry.
func TestLocalSliceFailures(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	enable := errors.New("device_dax: enable failed")

	// the region does not come up in devdax mode
	e.k.FailWrite("bus/dax/drivers/device_dax/new_id", enable)
	e.k.FailWrite("bus/dax/drivers/device_dax/bind", enable)
	_ = e.prepareFails(localClaim("u1", 8*mib, localDaxConfig), "enable failed")
	e.wantRegionReleased("region0")
	e.wantUsed(false)

	// zeroing fails: the same
	e.k.ZeroErr = errors.New("mmap: no such device")
	if err := e.prepareFails(localClaim("u1", 8*mib, localDaxConfig), "zeroing dax0.0: mmap: no such device"); strings.Count(err.Error(), "zeroing") != 1 {
		t.Fatalf("the zeroing is named more than once: %v", err)
	}
	e.wantRegionReleased("region0")
	e.wantUsed(false)
	e.k.ZeroErr = nil

	// kmem cannot be bound, or the memory not onlined: the same, no memory
	// is left online
	e.k.FailWrite("bus/dax/drivers/kmem/bind", syscall.EIO)
	_ = e.prepareFails(localClaim("u1", 8*mib), "bind dax0.0 to kmem: input/output error")
	e.wantRegionReleased("region0")
	e.k.FailWrite("devices/system/memory/memory75/state", syscall.EIO)
	_ = e.prepareFails(localClaim("u1", 2*localBlockSize), "memory75: online_movable: input/output error")
	e.wantRegionReleased("region0")
	e.wantMemoryBlocks()
	e.wantUsed(false)

	// a later slice fails to resize, to bind or to online: only that slice
	// goes
	e.mustPrepare(localClaim("u1", 8*mib, localDaxConfig))
	e.k.FailWrite("bus/dax/devices/dax0.1/size", syscall.EIO)
	_ = e.prepareFails(localClaim("u2", 8*mib, localDaxConfig), "input/output error")
	e.wantGone("dax0.1")
	e.k.FailWrite("bus/dax/drivers/device_dax/new_id", enable)
	e.k.FailWrite("bus/dax/drivers/device_dax/bind", enable)
	_ = e.prepareFails(localClaim("u2", 8*mib, localDaxConfig), "enable failed")
	e.wantGone("dax0.1")
	e.k.FailWrite("devices/system/memory/memory76/state", syscall.EIO)
	_ = e.prepareFails(localClaim("u2", 2*localBlockSize), "memory76: online_movable")
	e.wantGone("dax0.1")
	e.wantMemoryBlocks()
	e.wantDax("dax0.0", localBlockSize, kernel.DriverDeviceDax)
	if n := len(e.records().Grants); n != 1 {
		t.Fatalf("grants %+v", e.records().Grants)
	}
	e.wantUsed(true)

	// a slice that fails to delete stays with its claim until a retry
	e.k.FailWrite("bus/cxl/devices/region0/dax_region0/dax_region/delete", syscall.EBUSY)
	e.mustPrepare(localClaim("u3", 8*mib, localDaxConfig))
	u3 := e.dax("u3", 0)
	wantErr(t, e.unprepare("u3"), "releasing slice "+u3)
	if g := e.grant("u3", 0); !e.k.DaxExists(u3) || g == nil || g.State != state.GrantReleasing {
		t.Fatalf("after a failed release: %s exists %v, grant %+v", u3, e.k.DaxExists(u3), g)
	}
	e.mustUnprepare("u3")
	e.wantGone(u3)
	e.mustUnprepare("u1")
	e.wantClean()
}

// The records of another boot and a memdev whose cut creation left no
// region are dropped without commands; an unknown boot keeps them.
func TestLocalStateOfAnotherBoot(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	ctx := context.Background()
	e.mustPrepare(localClaim("u1", localBlockSize))
	if v := e.localView(); v.BootID != e.k.BootID() || v.BootID == "" {
		t.Fatalf("localDevices.json of boot %q, expected %q", v.BootID, e.k.BootID())
	}
	cmds := e.k.Commands()

	// an unknown boot keeps the records, another boot forgets them
	bootID := filepath.Join(e.k.ProcRoot(), "sys/kernel/random/boot_id")
	boot := e.k.BootID()
	noErr(t, os.WriteFile(bootID, []byte("\n"), 0o644))
	e.restart()
	e.wantUsed(true)
	noErr(t, os.WriteFile(bootID, []byte(boot+"\n"), 0o644))
	e.reboot()
	e.wantUsed(false)
	if now := e.k.Commands(); now != cmds {
		t.Fatalf("the records of another boot touched the memdev:\n%s", strings.TrimPrefix(now, cmds))
	}

	// a memdev without a region, whose creation was cut before it made one
	e.k.CutBefore("cxl create-region")
	if !e.cut(func() { _ = e.s.Prepare(ctx, localClaim("u2", localBlockSize)) }) {
		t.Fatal("the Prepare was not cut")
	}
	e.wantUsed(true)
	cmds = e.k.Commands()
	e.restart()
	e.wantUsed(false)
	if now := e.k.Commands(); now != cmds {
		t.Fatalf("a memdev without a region touched:\n%s", strings.TrimPrefix(now, cmds))
	}
	e.mustUnprepare("u2")
	e.wantClean()
}

// A new region whose memory aliases is made again with its distinct bytes
// only; that usable size is published and kept across restarts.
func TestLocalAliasedRegion(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	half := uint64(localRegionSize / 2)
	e.k.Aliasing = &kernel.Aliasing{Offset: half, Base: 0, Garbage: -1}
	// the device numbers of dax0.0 of each region that the Prepare makes
	var seeds []string
	var seed func()
	seed = func() {
		major, minor, err := e.k.Kernel().DaxDevNumbers("dax0.0")
		noErr(t, err)
		seeds = append(seeds, fmt.Sprintf("%d:%d", major, minor))
		e.k.After("cxl create-region -t ram -d decoder0.0 -m mem0", seed)
	}
	e.k.After("cxl create-region -t ram -d decoder0.0 -m mem0", seed)
	e.mustPrepare(localClaim("u1", 8*mib, localDaxConfig))
	if n := strings.Count(e.commands(), "create-region"); n != 2 {
		t.Fatalf("expected the region to be created twice, got %d:\n%s", n, e.commands())
	}
	if !strings.Contains(e.commands(), fmt.Sprintf("cxl create-region -t ram -d decoder0.0 -m mem0 -s %d", half)) {
		t.Fatalf("commands:\n%s", e.commands())
	}
	// both probes are of dax0.0: over all of the first region, then over
	// all of the region made again
	if len(seeds) != 2 {
		t.Fatalf("dax0.0 of %d regions, expected 2: %v", len(seeds), seeds)
	}
	probes := []string{fmt.Sprintf("%s %d", seeds[0], localRegionSize), fmt.Sprintf("%s %d", seeds[1], half)}
	if p := e.k.Probed(); !slices.Equal(p, probes) {
		t.Fatalf("expected the probes %v of dax0.0, got %v", probes, p)
	}
	if got := e.s.local.Snapshot().probed(localSerial); got != half {
		t.Fatalf("probed usable size %d, expected %d", got, half)
	}
	if r, err := e.k.Kernel().RegionRange("region0"); err != nil || r.Size() != half {
		t.Fatalf("region %v: %v", r, err)
	}
	e.rescan()
	if d := e.s.Allocatable.(device.DevicesInfo)[localDeviceName]; d == nil || d.Dev.(*device.Memdev).Size != half {
		t.Fatalf("published %+v", d)
	}
	e.restart()
	if got := e.s.local.Snapshot().probed(localSerial); got != half {
		t.Fatalf("probed usable size after a restart %d, expected %d", got, half)
	}
	e.mustUnprepare("u1")
	e.wantClean()
}

// The configured usable size limits the regions of the memdev; a probe
// that is turned off is not run.
func TestLocalConfiguredUsableSize(t *testing.T) {
	e := newSliceTestEnv(t)
	limit := uint64(localRegionSize / 2)
	e.config.MemdevSettings = []MemdevSetting{{Device: "0xc100e2e1", UsableSize: fmt.Sprint(limit + 4096)}}
	e.config.VerifyAddressing = ptr(false)
	e.start()
	e.mustPrepare(localClaim("u1", 8*mib, localDaxConfig))
	if !strings.Contains(e.commands(), fmt.Sprintf("cxl create-region -t ram -d decoder0.0 -m mem0 -s %d", limit)) {
		t.Fatalf("commands:\n%s", e.commands())
	}
	if p := e.k.Probed(); len(p) != 0 {
		t.Fatalf("probed although verifyAddressing is off: %v", p)
	}
	e.mustUnprepare("u1")
	e.wantClean()
}
