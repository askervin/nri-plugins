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

package guest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSys builds a sysfs tree like the one of an e2e VM with one hotplugged
// CXL memory device, and fakes the cxl and daxctl tools on top of it.
type fakeSys struct {
	t    *testing.T
	root string
	mu   sync.Mutex
	cmds []string
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
	os.Remove(f.p(rel))
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
	os.MkdirAll(f.p("bus/cxl/drivers/cxl_mem"), 0o755)
	os.MkdirAll(f.p("bus/dax/drivers/kmem"), 0o755)
	os.MkdirAll(f.p("bus/dax/drivers/device_dax"), 0o755)
	return f
}

func itoa(i int) string { return strconv.Itoa(i) }

// plug makes mem0 with the serial appear, with its endpoint and driver.
func (f *fakeSys) plug(serial string) {
	f.write(memPath+"/serial", serial)
	f.link("bus/cxl/devices/mem0", "../../../"+memPath)
	f.link(memPath+"/driver", "../../../../../../../bus/cxl/drivers/cxl_mem")
	os.MkdirAll(f.p("bus/cxl/devices/endpoint4"), 0o755)
	f.link("bus/cxl/devices/endpoint4/uport", "../../../../"+memPath)
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
		os.MkdirAll(f.p("bus/cxl/devices/region0/dax_region0/dax0.0"), 0o755)
		os.MkdirAll(f.p("bus/dax/devices"), 0o755)
		f.link("bus/dax/devices/dax0.0", "../../../bus/cxl/devices/region0/dax_region0/dax0.0")
		f.write("bus/cxl/devices/region0/dax_region0/dax0.0/target_node", "2")
		f.link("bus/cxl/devices/region0/dax_region0/dax0.0/driver", "../../../../../dax/drivers/kmem")
		return `[{"region":"region0","resource":"0x250000000","size":"256.00 MiB"}]` + "\ncxl region: cmd_create_region: created 1 region\n", nil
	case "cxl disable-region", "cxl enable-memdev":
		if args[0] == "enable-memdev" {
			f.link(memPath+"/driver", "../../../../../../../bus/cxl/drivers/cxl_mem")
		}
		return "", nil
	case "cxl destroy-region":
		os.RemoveAll(f.p("bus/cxl/devices/region0"))
		os.Remove(f.p("bus/dax/devices/dax0.0"))
		return "", nil
	case "cxl disable-memdev":
		os.Remove(f.p(memPath + "/driver"))
		return "", nil
	case "daxctl reconfigure-device":
		drv := "kmem"
		if strings.Contains(strings.Join(args, " "), "--mode=devdax") {
			drv = "device_dax"
		}
		f.link("bus/cxl/devices/region0/dax_region0/dax0.0/driver", "../../../../../dax/drivers/"+drv)
		return "", nil
	}
	return "", errors.New("unexpected command " + name + " " + strings.Join(args, " "))
}

func (f *fakeSys) guest() *Guest {
	return &Guest{
		SysRoot:      f.root,
		DevRoot:      "/dev",
		Exec:         f.exec,
		LookPath:     func(string) (string, error) { return "/usr/bin/daxctl", nil },
		PollInterval: 5 * time.Millisecond,
		Logf:         f.t.Logf,
	}
}

func (f *fakeSys) commands() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.cmds, "\n")
}

func TestFindAndWait(t *testing.T) {
	f := newFakeSys(t)
	g := f.guest()
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
	if ep, err := g.Endpoint("mem0"); err != nil || ep != "endpoint4" {
		t.Fatalf("endpoint %q %v", ep, err)
	}
	if uid, err := g.HostBridgeUID("mem0"); err != nil || uid != 12 {
		t.Fatalf("uid %d %v", uid, err)
	}
	if d, err := g.RootDecoder("mem0"); err != nil || d != "decoder0.0" {
		t.Fatalf("root decoder %q %v", d, err)
	}
}

func TestRegionRAMOnlineRelease(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc1f00001")
	g := f.guest()
	ctx := context.Background()
	ri, err := g.CreateRegion(ctx, "mem0", ModeRAM, "")
	if err != nil {
		t.Fatal(err)
	}
	if ri.Region != "region0" || ri.Dax != "dax0.0" || ri.Driver != DriverKmem || ri.Mode != ModeRAM || ri.Node != 2 ||
		len(ri.Blocks) != 2 || ri.Blocks[0] != 74 {
		t.Fatalf("unexpected region info %+v", ri)
	}
	if !strings.Contains(f.commands(), "cxl create-region -t ram -d decoder0.0 -m mem0") {
		t.Fatalf("unexpected commands:\n%s", f.commands())
	}
	// idempotent
	if _, err := g.CreateRegion(ctx, "mem0", ModeRAM, ""); err != nil {
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

func TestRegionDevDax(t *testing.T) {
	f := newFakeSys(t)
	f.plug("0xc1f00001")
	os.Remove(f.p(memPath + "/driver")) // disabled memdev gets enabled
	g := f.guest()
	ri, err := g.CreateRegion(context.Background(), "mem0", ModeDevDax, "decoder0.0")
	if err != nil {
		t.Fatal(err)
	}
	if ri.Driver != DriverDeviceDax || ri.Mode != ModeDevDax || ri.Device != "/dev/dax0.0" {
		t.Fatalf("unexpected region info %+v", ri)
	}
	cmds := f.commands()
	if !strings.HasPrefix(cmds, "cxl enable-memdev mem0\n") || !strings.Contains(cmds, "daxctl reconfigure-device --mode=devdax --force dax0.0") {
		t.Fatalf("unexpected commands:\n%s", cmds)
	}
	if _, err := g.Online("mem0", true); err == nil {
		t.Fatal("online must fail in devdax mode")
	}
	if _, err := g.CreateRegion(context.Background(), "mem0", "bogus", ""); err == nil {
		t.Fatal("expected invalid mode error")
	}
}
