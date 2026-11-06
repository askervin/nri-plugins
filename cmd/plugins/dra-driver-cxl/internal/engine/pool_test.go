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

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// A pool device in mode numa: its region with daxN.0 bound to kmem and its
// memory online movable on the node of its window, fenced first; its
// Unprepare destroys the region and disables the memdev.
func TestPoolNuma(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.mustPrepare(poolDriver, "c1", poolReq("c1", 0, serialA, state.ModeNUMA, state.KindExclusive))
	g := v.grant("c1", 0)
	if g.State != state.GrantRealised || g.Got.Region != "region0" || g.Got.Dax != "dax0.0" || state.NumaNodeOf(g.Got.NumaNode) != 2 {
		t.Fatalf("grant %+v", g)
	}
	reg := v.records().Region("region0")
	if reg == nil || reg.State != state.RegionOwned || !reg.SetUp || reg.DaxDevices[0].State != state.DaxKmemOnline ||
		len(reg.DaxDevices[0].Users) != 1 {
		t.Fatalf("region %+v", reg)
	}
	if len(v.fenced) != 1 || v.fenced[0] != 2 {
		t.Fatalf("fenced %v", v.fenced)
	}
	snap, _ := v.f.Kernel().Observe(context.Background())
	if online := snap.OnlineBlocks(snap.Region("region0").Range.Blocks(snap.BlockSize)); len(online) == 0 {
		t.Fatal("no memory online")
	}
	// Prepare again: the realised grant verifies and is reused
	before := v.f.Commands()
	if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{poolReq("c1", 0, serialA, state.ModeNUMA, state.KindExclusive)}); err != nil {
		t.Fatal(err)
	}
	if cmds := v.f.CommandsSince(before); cmds != "" {
		t.Fatalf("a Prepare again ran %q", cmds)
	}
	v.mustUnprepare(poolDriver, "c1")
	v.clean("unprepared")
	if !strings.Contains(v.f.Commands(), "disable-memdev mem0") {
		t.Fatalf("memdev not disabled: %s", v.f.Commands())
	}
}

// A pool device in mode dax: device_dax over the whole region, never
// online; a shared device is the region of every claim of it until the
// last one goes.
func TestPoolDax(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.mustPrepare(poolDriver, "c1", poolReq("c1", 0, serialA, state.ModeDax, state.KindExclusive))
	g := v.grant("c1", 0)
	if g.Got.Dax != "dax0.0" || g.Got.DaxDev.IsZero() || v.f.DaxDriver("dax0.0") != kernel.DriverDeviceDax {
		t.Fatalf("grant %+v, driver %s", g, v.f.DaxDriver("dax0.0"))
	}
	if len(v.fenced) != 0 {
		t.Fatalf("fenced %v", v.fenced)
	}
	v.mustUnprepare(poolDriver, "c1")
	v.clean("unprepared")
}

func TestPoolSharedDax(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.mustPrepare(poolDriver, "c1", poolReq("c1", 0, serialA, state.ModeDax, state.KindShared))
	v.mustPrepare(poolDriver, "c2", poolReq("c2", 1, serialA, state.ModeDax, state.KindShared))
	d := v.records().Region("region0").DaxDevice("dax0.0")
	if len(d.Users) != 2 {
		t.Fatalf("users %v", d.Users)
	}
	v.mustUnprepare(poolDriver, "c1")
	if v.records().Region("region0") == nil || strings.Contains(v.f.Commands(), "destroy-region") {
		t.Fatal("the region went with its first claim")
	}
	v.mustUnprepare(poolDriver, "c2")
	v.clean("unprepared")
}

// A pool Prepare waits for its memdev to appear; one that does not appear
// fails with the deadline and leaves nothing.
func TestPoolWaitsForMemdev(t *testing.T) {
	v := newEnv(t)
	go func() {
		time.Sleep(50 * time.Millisecond)
		v.f.Plug(fake.MemdevSpec{Serial: serialA})
	}()
	v.mustPrepare(poolDriver, "c1", poolReq("c1", 0, serialA, state.ModeDax, state.KindExclusive))
	v.mustUnprepare(poolDriver, "c1")

	v.e.opts.Timeouts.Memdev = 100 * time.Millisecond
	before := v.f.Commands()
	start := time.Now()
	err := v.prepare(poolDriver, "c2", poolReq("c2", 0, serialB, state.ModeDax, state.KindExclusive))
	took := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "0xb1") || took < 100*time.Millisecond || took > 2*time.Second {
		t.Fatalf("error %v after %v", err, took)
	}
	if cmds := v.f.CommandsSince(before); cmds != "" {
		t.Fatalf("commands %q", cmds)
	}
	v.check("timed out")
	v.clean("timed out")
	if v.records().Preparation(poolDriver, "c2") != nil {
		t.Fatal("the preparation of the failed Prepare stays")
	}
}

// A region on a pool memdev that no record names is never reused: the
// memdev is refused.
func TestPoolForeignRegion(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	k := v.f.Kernel()
	d, _ := k.RootDecoder("mem0", kernel.RegionRAM)
	if _, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: "mem0", Decoder: d, Type: kernel.RegionRAM}); err != nil {
		t.Fatal(err)
	}
	before := v.f.Commands()
	err := v.prepare(poolDriver, "c1", poolReq("c1", 0, serialA, state.ModeDax, state.KindExclusive))
	if !errors.Is(err, ErrForeignRegion) || !strings.Contains(err.Error(), "memdev mem0 has region region0 that the plugin did not create") {
		t.Fatalf("error %v", err)
	}
	if cmds := v.f.CommandsSince(before); strings.Contains(cmds, "region0") {
		t.Fatalf("the foreign region was touched: %s", cmds)
	}
	if r := v.records(); len(r.Grants) > 0 || len(r.Regions) > 0 {
		t.Fatalf("records %+v", r)
	}
}

// A memdev whose endpoint port is not there yet: the region creation is
// tried once more.
func TestPoolEndpointRetry(t *testing.T) {
	v := newEnv(t)
	v.f.EndpointDelay = 60 * time.Millisecond
	v.f.Plug(fake.MemdevSpec{Serial: serialA})
	v.e.opts.Timeouts.ProbeGrace = time.Millisecond
	v.e.opts.Timeouts.RegionRetry = 200 * time.Millisecond
	v.mustPrepare(poolDriver, "c1", poolReq("c1", 0, serialA, state.ModeDax, state.KindExclusive))
	v.mustUnprepare(poolDriver, "c1")
	v.clean("unprepared")
}

// A release whose memory cannot be offlined (EBUSY) fails and keeps the
// records; the retry releases.
func TestPoolReleaseBusy(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.mustPrepare(poolDriver, "c1", poolReq("c1", 0, serialA, state.ModeNUMA, state.KindExclusive))
	snap, _ := v.f.Kernel().Observe(context.Background())
	blocks := snap.Region("region0").Range.Blocks(snap.BlockSize)
	v.f.FailWrite(blockState(blocks[0]), errBusy)
	if err := v.unprepare(poolDriver, "c1"); err == nil {
		t.Fatal("a busy release succeeded")
	}
	if g := v.grant("c1", 0); g.State != state.GrantReleasing {
		t.Fatalf("grant %s", g.State)
	}
	v.mustUnprepare(poolDriver, "c1")
	v.clean("released at the retry")
}

// A new region whose daxN.0 device_dax takes by an id that another tool
// left: recorded as found, used in mode dax.
func TestPoolLeftDeviceDaxID(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.f.SetDaxID(kernel.DriverDeviceDax, "dax0.0")
	v.mustPrepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeDax, state.KindExclusive))
	if d := v.records().Region("region0").DaxDevice("dax0.0"); d.State != state.DaxDeviceDax {
		t.Fatalf("dax device %+v", d)
	}
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}

// The numa twin: daxN.0 found bound to device_dax is switched to kmem
// (DEVICE_DAX -> SIZED -> KMEM_OFFLINE) and onlined.
func TestPoolLeftDeviceDaxIDNuma(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.f.SetDaxID(kernel.DriverDeviceDax, "dax0.0")
	v.mustPrepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeNUMA, state.KindExclusive))
	if d := v.records().Region("region0").DaxDevice("dax0.0"); d.State != state.DaxKmemOnline {
		t.Fatalf("dax device %+v", d)
	}
	v.mustUnprepare(poolDriver, "c")
	v.clean("unprepared")
}

// A timeout of 0 or less is the default.
func TestTimeoutDefaults(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		got := Timeouts{Memdev: d, Holder: d}.withDefaults()
		if got.Memdev != 30*time.Second || got.Holder != 10*time.Second || got.Rollback != time.Minute {
			t.Errorf("%v: %+v", d, got)
		}
	}
}

// A fence that does not finish in time: the memory goes online anyway.
func TestFenceDeadline(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.e.opts.Timeouts.Fence = 20 * time.Millisecond
	// the fence holds the node, its pass does not finish
	v.e.opts.Fence = func(ctx context.Context, node int) {
		v.fenceMu.Lock()
		v.fenced = append(v.fenced, node)
		v.fenceMu.Unlock()
		<-ctx.Done()
	}
	logs := captureKlogV(t, "0")
	v.mustPrepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeNUMA, state.KindExclusive))
	if !strings.Contains(logs(), "fencing NUMA node 2 did not finish in 20ms: its memory goes online anyway") {
		t.Fatalf("logs %s", logs())
	}
	v.mustUnprepare(poolDriver, "c")
}

// A cxl create-region that fails with add_dev is tried once more, logged
// with the claim and the DRA device.
func TestPoolAddDevRetry(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	v.f.FailCommand("cxl create-region", fake.ErrAddDev)
	req := poolReq("c1", 0, serialA, state.ModeDax, state.KindExclusive)
	req.ClaimName, req.Device = "ns/c1", "pooled0"
	logs := captureKlog(t)
	v.mustPrepare(poolDriver, "c1", req)
	if out := logs(); !strings.Contains(out, "cxl-pool.nri.io: claim ns/c1: device pooled0: ") || !strings.Contains(out, "retrying once in") {
		t.Fatalf("no retry line in\n%s", out)
	}
	v.mustUnprepare(poolDriver, "c1")
	v.clean("unprepared")
}

// A failed Prepare returns the grants that its rollback kept with the
// error: the second grant of the claim finds a foreign region, the
// rollback cannot disable the memdev of the first one.
func TestPoolRollbackReturnsKept(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA}, fake.MemdevSpec{Serial: serialB})
	k := v.f.Kernel()
	d, _ := k.RootDecoder("mem1", kernel.RegionRAM)
	if _, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: "mem1", Decoder: d, Type: kernel.RegionRAM}); err != nil {
		t.Fatal(err)
	}
	v.f.FailCommand("cxl disable-memdev", errBusy)
	b := poolReq("c", 1, serialB, state.ModeDax, state.KindExclusive)
	kept, err := v.e.PrepareGrants(context.Background(), []GrantRequest{poolReq("c", 0, serialA, state.ModeDax, state.KindExclusive), b})
	if !errors.Is(err, ErrForeignRegion) {
		t.Fatalf("error %v", err)
	}
	if len(kept) != 1 || kept[0].Ref != (state.GrantRef{Claim: "c"}) || kept[0].State != state.GrantReleasing {
		t.Fatalf("kept %+v", kept)
	}
}
