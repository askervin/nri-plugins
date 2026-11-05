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

package fake_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// cut runs fn and tells whether it stopped with ErrCut.
func cut(t *testing.T, fn func()) (stopped bool) {
	t.Helper()
	defer func() {
		switch r := recover(); r {
		case nil:
		case fake.ErrCut:
			stopped = true
		default:
			panic(r)
		}
	}()
	fn()
	return false
}

// The hooks of the tests: a stop before or after a command or a write, a
// command or a write that fails, functions before and after one; each is
// used once.
func TestHooks(t *testing.T) {
	f := fake.New(t)
	f.Plug(fake.MemdevSpec{Serial: 0xc1}) // mem0
	k := f.Kernel()
	ctx := context.Background()
	req := kernel.CreateRegionRequest{Memdev: "mem0", Decoder: "decoder0.0", Type: kernel.RegionRAM}

	f.CutBefore("cxl create-region")
	if !cut(t, func() { _, _ = k.CreateRegion(ctx, req) }) || strings.Contains(f.Commands(), "create-region") {
		t.Fatalf("not stopped before:\n%s", f.Commands())
	}
	f.CutAfter("cxl create-region")
	if !cut(t, func() { _, _ = k.CreateRegion(ctx, req) }) || !f.Exists("bus/cxl/devices/region0") {
		t.Fatalf("not stopped after:\n%s", f.Commands())
	}
	f.FailCommand("cxl disable-region", fake.ErrAddDev, nil)
	if err := k.DisableRegion(ctx, "region0"); !errors.Is(err, fake.ErrAddDev) {
		t.Fatalf("expected the failure, got %v", err)
	}
	if err := k.DisableRegion(ctx, "region0"); err != nil {
		t.Fatalf("the second disable-region failed: %v", err)
	}
	noErr(t, k.EnableRegion(ctx, "region0"))
	f.FailWrite("bus/dax/devices/dax0.0/size", syscall.EIO)
	noErr(t, k.UnbindDax(ctx, "dax0.0"))
	if err := k.ResizeDaxDevice(ctx, "dax0.0", 2<<20); !errors.Is(err, syscall.EIO) {
		t.Fatalf("expected the write failure, got %v", err)
	}
	var order []string
	f.Before("write bus/dax/devices/dax0.0/size", func() { order = append(order, "before") })
	f.After("write bus/dax/devices/dax0.0/size", func() { order = append(order, "after") })
	noErr(t, k.ResizeDaxDevice(ctx, "dax0.0", 2<<20))
	noErr(t, k.ResizeDaxDevice(ctx, "dax0.0", 4<<20))
	if strings.Join(order, ",") != "before,after" {
		t.Fatalf("hooks %v", order)
	}
	f.CutAfter("write bus/dax/devices/dax0.0/size 0")
	if !cut(t, func() { _ = k.ResizeDaxDevice(ctx, "dax0.0", 0) }) || f.DaxSize("dax0.0") != 0 {
		t.Fatalf("not stopped after the write: size %d", f.DaxSize("dax0.0"))
	}
	// a stop after a mount at a target
	dir := filepath.Join(t.TempDir(), "m")
	noErr(t, os.MkdirAll(dir, 0o755))
	f.CutMount(dir)
	if !cut(t, func() { _ = k.Mount("tmpfs", dir, "tmpfs", 0, "") }) || len(f.MountTable()) != 1 {
		t.Fatalf("not stopped after the mount: %+v", f.MountTable())
	}
}

// A reboot: a new boot id, nothing of the regions, dax devices, memory
// blocks and mounts of the old boot, the memdevs enabled again.
func TestReboot(t *testing.T) {
	f := fake.New(t)
	f.Plug(fake.MemdevSpec{Serial: 0xc1})
	k := f.Kernel()
	ctx := context.Background()
	d, err := k.RootDecoder("mem0", kernel.RegionRAM)
	noErr(t, err)
	_, err = k.CreateRegion(ctx, kernel.CreateRegionRequest{Memdev: "mem0", Decoder: d, Type: kernel.RegionRAM})
	noErr(t, err)
	noErr(t, k.OnlineBlocks([]int{74}, true))
	boot := f.BootID()
	f.Reboot()
	s, err := k.Observe(ctx)
	noErr(t, err)
	if s.BootID == boot || len(s.Regions) != 0 || len(s.DaxDevices) != 0 || f.BlockState(74) != "" || len(s.Memdevs) != 1 || s.Memdevs[0].State != kernel.MemdevReady {
		t.Fatalf("after the reboot: %+v", s)
	}
	if p, ok := s.Port("port1"); !ok || p.Committed != 0 {
		t.Fatalf("port after the reboot %+v", p)
	}
	if n, _ := s.NumaNode(2); n.HasMemory {
		t.Fatalf("node 2 has memory after the reboot")
	}
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
