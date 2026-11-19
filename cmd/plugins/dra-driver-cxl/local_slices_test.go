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
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
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

// The memory block size is read as hex, and again for every slice and
// every snapshot of the publisher.
func TestLocalBlockSize(t *testing.T) {
	e := newSliceTestEnv(t)
	e.start()
	// "8000000" is hex
	if bs := e.localSnapshot().BlockSize; bs != 134217728 {
		t.Fatalf("block size %d of %q", bs, e.k.Read("devices/system/memory/block_size_bytes"))
	}
	// 2 GiB blocks: a 128 MiB claim needs a 2 GiB slice
	e.k.SetBlockSize(2 << 30)
	if err := e.prepareFails(localClaim("u1", 128*mib), "the slice needs 2147483648"); !errors.Is(err, kernel.ErrNoRoom) {
		t.Fatalf("expected no room, got %v", err)
	}
	e.wantRegionReleased("region0")
	if bs := e.localSnapshot().BlockSize; bs != 2<<30 {
		t.Fatalf("block size %d after the change", bs)
	}
	e.wantUsed(false)
	e.k.Write("devices/system/memory/block_size_bytes", "bogus")
	_ = e.prepareFails(localClaim("u1", 128*mib, localDaxConfig), "memory block size")
	e.wantUsed(false)
	// unknown at start: the snapshot reads it again
	e.k.Remove("devices/system/memory/block_size_bytes")
	e.restart()
	if bs := e.localSnapshot().BlockSize; bs != 0 {
		t.Fatalf("block size %d without block_size_bytes", bs)
	}
	e.k.SetBlockSize(localBlockSize)
	if bs := e.localSnapshot().BlockSize; bs != localBlockSize {
		t.Fatalf("block size %d", bs)
	}
	off, err := dra.NewPublisher(dra.PublishOptions{Store: e.st, NodeName: "node1", Scan: func(context.Context) (*kernel.Snapshot, error) { return &kernel.Snapshot{}, nil }})
	noErr(t, err)
	if off.LocalSnapshot() != nil {
		t.Fatal("snapshot of unmanaged local devices")
	}
}

// With blocks larger than the region alignment the memdev publishes the
// whole blocks it is sure to have and serves both modes in any order.
func TestLocalLargeBlocks(t *testing.T) {
	e := newLargeBlocksEnv(t)
	bs := uint64(largeBlockSize)
	dev := e.publisher.Devices()[memdevDeviceName(largeSerial)]
	if dev == nil {
		t.Fatalf("not published: %v", e.publisher.Devices())
	}
	if p := localMemdevDevice(dev.Name, dev.Dev.(*dra.Memdev)).Capacity[device.CapacityMemory].RequestPolicy; p == nil ||
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
	noErr(t, prepareOn(ctx, e.s, localClaim("u3", localBlockSize, localDaxConfig)))
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
	if got := e.localSnapshot().ProbedSize(localSerial); got != half {
		t.Fatalf("probed usable size %d, expected %d", got, half)
	}
	if r, err := e.k.Kernel().RegionRange("region0"); err != nil || r.Size() != half {
		t.Fatalf("region %v: %v", r, err)
	}
	e.rescan()
	if d := e.publisher.Devices()[localDeviceName]; d == nil || d.Dev.(*dra.Memdev).Size != half {
		t.Fatalf("published %+v", d)
	}
	e.restart()
	if got := e.localSnapshot().ProbedSize(localSerial); got != half {
		t.Fatalf("probed usable size after a restart %d, expected %d", got, half)
	}
	e.mustUnprepare("u1")
	e.wantClean()
}
