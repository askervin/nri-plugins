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
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

// fakePoolSys is a sysfs tree with one hotplugged CXL memdev (mem0) under
// host bridge 12, with the cxl CLI and the attributes of the dax drivers
// faked on top of it, like the tests of nri-plugins pkg/cxl/memctl.
type fakePoolSys struct {
	t      *testing.T
	root   string
	mu     sync.Mutex
	cmds   []string
	labels bool // the LSA of a persistent mem0 has an fsdax namespace
	// cutAfter is the beginning of a command after which the plugin is
	// killed (cutPrepare), "" for none.
	cutAfter string
	// failCmd is the beginning of a command that fails, "" for none.
	failCmd string
	// daxDev is the dev of dax0.0 that cxl create-region makes, "" for
	// 251:3; pmemDev that of pmem0 of the fsdax namespace, "" for 259:0
	// (a reboot gives the devices other numbers).
	daxDev, pmemDev string
}

const fakeMemPath = "devices/pci0000:0c/0000:0c:00.0/0000:0d:00.0/0000:0e:00.0/0000:0f:00.0/mem0"

func newFakePoolSys(t *testing.T) *fakePoolSys {
	f := &fakePoolSys{t: t, root: t.TempDir()}
	f.write("devices/system/memory/block_size_bytes", "8000000")
	for _, b := range []string{"74", "75"} {
		f.write("devices/system/memory/memory"+b+"/state", "offline")
	}
	f.write("bus/cxl/devices/decoder0.0/devtype", "cxl_decoder_root")
	f.write("bus/cxl/devices/decoder0.0/target_list", "12")
	// the name of the next region, which the fake cxl create-region
	// always creates
	f.write("bus/cxl/devices/decoder0.0/create_ram_region", "region0")
	f.write("bus/cxl/devices/decoder0.0/create_pmem_region", "region0")
	f.mkdir("bus/cxl/drivers/cxl_mem")
	f.mkdir("bus/dax/drivers/kmem")
	f.mkdir("bus/dax/drivers/device_dax")
	f.mkdir("bus/dax/devices")
	return f
}

func (f *fakePoolSys) p(rel string) string { return filepath.Join(f.root, rel) }

func (f *fakePoolSys) mkdir(rel string) {
	f.t.Helper()
	if err := os.MkdirAll(f.p(rel), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakePoolSys) write(rel, val string) {
	f.t.Helper()
	f.mkdir(filepath.Dir(rel))
	if err := os.WriteFile(f.p(rel), []byte(val+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakePoolSys) read(rel string) string {
	b, _ := os.ReadFile(f.p(rel))
	return strings.TrimSpace(string(b))
}

func (f *fakePoolSys) link(rel, target string) {
	f.t.Helper()
	f.mkdir(filepath.Dir(rel))
	_ = os.Remove(f.p(rel))
	if err := os.Symlink(target, f.p(rel)); err != nil {
		f.t.Fatal(err)
	}
}

// plug makes mem0 with the serial appear with its endpoint and driver.
func (f *fakePoolSys) plug(serial string) {
	f.write(fakeMemPath+"/serial", serial)
	f.link("bus/cxl/devices/mem0", "../../../"+fakeMemPath)
	f.link(fakeMemPath+"/driver", "../../../../../../../bus/cxl/drivers/cxl_mem")
	f.mkdir("bus/cxl/devices/endpoint4")
	f.link("bus/cxl/devices/endpoint4/uport", "../../../../"+fakeMemPath)
}

// unplug removes mem0 (hot-remove by the pool).
func (f *fakePoolSys) unplug() {
	_ = os.Remove(f.p("bus/cxl/devices/mem0"))
	_ = os.RemoveAll(f.p("bus/cxl/devices/endpoint4"))
	_ = os.RemoveAll(f.p("devices/pci0000:0c"))
}

const daxPath = "bus/cxl/devices/region0/dax_region0/dax0.0"

// exec runs a faked command, and kills the plugin after it if it is the
// command of cutAfter.
func (f *fakePoolSys) exec(ctx context.Context, name string, args ...string) (string, error) {
	out, err := f.run(ctx, name, args...)
	cmd := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	cut := f.cutAfter != "" && strings.HasPrefix(cmd, f.cutAfter)
	if cut {
		f.cutAfter = ""
	}
	f.mu.Unlock()
	if cut {
		panic(errCut)
	}
	return out, err
}

func (f *fakePoolSys) run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.cmds = append(f.cmds, cmd)
	fail := f.failCmd != "" && strings.HasPrefix(cmd, f.failCmd)
	f.mu.Unlock()
	if fail {
		return "", errors.New(cmd + ": exit status 1")
	}
	if out, ok := f.execPmem(name, args...); ok {
		return out, nil
	}
	switch name + " " + args[0] {
	case "cxl create-region":
		f.write("bus/cxl/devices/region0/target0", "decoder4.0")
		f.write("bus/cxl/devices/region0/resource", "0x250000000")
		f.write("bus/cxl/devices/region0/size", "0x10000000")
		f.mkdir(daxPath)
		f.link("bus/dax/devices/dax0.0", "../../../"+daxPath)
		f.write(daxPath+"/target_node", "2")
		f.write(daxPath+"/size", "268435456")
		f.write(daxPath+"/resource", "0x250000000")
		f.write(daxPath+"/dev", cmp.Or(f.daxDev, "251:3"))
		f.link(daxPath+"/driver", "../../../../../dax/drivers/kmem")
		return `[{"region":"region0","resource":"0x250000000","size":"256.00 MiB"}]`, nil
	case "cxl enable-memdev":
		f.link(fakeMemPath+"/driver", "../../../../../../../bus/cxl/drivers/cxl_mem")
		return "", nil
	case "cxl disable-region":
		return "", nil
	case "cxl destroy-region":
		_ = os.RemoveAll(f.p("bus/cxl/devices/region0"))
		_ = os.Remove(f.p("bus/dax/devices/dax0.0"))
		f.removeNdRegion()
		return "", nil
	case "cxl disable-memdev":
		_ = os.Remove(f.p(fakeMemPath + "/driver"))
		return "", nil
	}
	return "", errors.New("unexpected command " + name + " " + strings.Join(args, " "))
}

func (f *fakePoolSys) commands() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.cmds, "\n")
}

// commandsSince returns the commands run after those of before, an earlier
// commands().
func (f *fakePoolSys) commandsSince(before string) string {
	return strings.TrimPrefix(strings.TrimPrefix(f.commands(), before), "\n")
}

func (f *fakePoolSys) manager() *memctl.Manager {
	return &memctl.Manager{
		SysRoot:      f.root,
		DevRoot:      "/dev",
		Exec:         f.exec,
		PollInterval: 2 * time.Millisecond,
		Logf:         f.t.Logf,
		WriteFile:    f.writeAttr,
	}
}

// writeAttr writes a sysfs attribute; delete_region of a root decoder
// deletes the region under it, and the attributes of a dax driver bind and
// unbind dax0.0, as the kernel does. The writes of dax driver attributes
// are commands ("write bus/dax/drivers/device_dax/new_id dax0.0"); the
// plugin is killed after the one of cutAfter.
func (f *fakePoolSys) writeAttr(path, val string) error {
	if rel, _ := filepath.Rel(f.root, path); filepath.Dir(filepath.Dir(rel)) == "bus/dax/drivers" {
		cmd := "write " + rel + " " + val
		f.mu.Lock()
		f.cmds = append(f.cmds, cmd)
		cut := f.cutAfter != "" && strings.HasPrefix(cmd, f.cutAfter)
		if cut {
			f.cutAfter = ""
		}
		f.mu.Unlock()
		err := f.daxDriverAttr(filepath.Base(filepath.Dir(rel)), filepath.Base(rel), val)
		if cut {
			panic(errCut)
		}
		return err
	}
	if filepath.Base(path) != "delete_region" {
		return os.WriteFile(path, []byte(val), 0o644)
	}
	f.mu.Lock()
	f.cmds = append(f.cmds, "delete_region "+filepath.Base(filepath.Dir(path))+" "+val)
	f.mu.Unlock()
	dir := filepath.Join(filepath.Dir(path), val)
	if _, err := os.Stat(dir); err != nil {
		return err
	}
	_ = os.RemoveAll(dir)
	_ = os.Remove(f.p("bus/cxl/devices/" + val))
	return nil
}

// daxDriverAttr binds dax0.0 to the driver (bind, new_id) or unbinds it
// (unbind), as the dax bus does; remove_id does nothing that sysfs shows.
func (f *fakePoolSys) daxDriverAttr(driver, attr, dax string) error {
	if dax != "dax0.0" {
		return syscall.ENODEV
	}
	cur := ""
	if t, err := os.Readlink(f.p(daxPath + "/driver")); err == nil {
		cur = filepath.Base(t)
	}
	switch attr {
	case "unbind":
		if cur != driver {
			return syscall.ENODEV
		}
		_ = os.Remove(f.p(daxPath + "/driver"))
	case "bind", "new_id":
		switch {
		case cur != "" && attr == "bind":
			return syscall.EBUSY
		case cur == "":
			f.link(daxPath+"/driver", "../../../../../dax/drivers/"+driver)
		}
	}
	return nil
}

// hollowRegion makes the region under root decoder decoder0.0 hollow, as
// the kernel leaves a region whose memdev was removed before it was
// destroyed (plan-13 bug-12): commit 0, target0 empty, the address range
// kept. A plain region directory of the fake is replaced.
func (f *fakePoolSys) hollowRegion(region, mode string) {
	_ = os.RemoveAll(f.p("bus/cxl/devices/" + region))
	dir := "bus/cxl/devices/decoder0.0/" + region
	for file, value := range map[string]string{
		"commit": "0", "devtype": "cxl_region", "interleave_ways": "1", "mode": mode,
		"resource": "0x850000000", "size": "0x10000000", "target0": "", "uuid": "675e71d7-179f-4beb-ab43-55f82e02b39a",
	} {
		f.write(dir+"/"+file, value)
	}
	f.link("bus/cxl/devices/"+region, "decoder0.0/"+region)
}

// stackPorts puts the endpoint of mem0 under the host bridge port1 and
// the switch port6, whose committed decoders have the regions in commit
// order ("" for a decoder without a region), as the decoder stacks of
// plan-13 bug-02 (memctl.DecoderHole).
func (f *fakePoolSys) stackPorts(regions ...string) {
	const ep = "devices/platform/ACPI0017:00/root0/port1/port6/endpoint4"
	_ = os.RemoveAll(f.p("bus/cxl/devices/endpoint4"))
	f.link(ep+"/uport", "../../../../../../../"+fakeMemPath)
	f.link("bus/cxl/devices/endpoint4", "../../../"+ep)
	for _, port := range []string{"devices/platform/ACPI0017:00/root0/port1", "devices/platform/ACPI0017:00/root0/port1/port6"} {
		id := strings.TrimPrefix(filepath.Base(port), "port")
		f.write(port+"/decoders_committed", fmt.Sprint(len(regions)))
		for i, r := range regions {
			f.write(fmt.Sprintf("%s/decoder%s.%d/region", port, id, i), r)
		}
	}
}

func (f *fakePoolSys) wantCommand(t *testing.T, cmd string) {
	t.Helper()
	if !strings.Contains(f.commands(), cmd) {
		t.Fatalf("command %q not run:\n%s", cmd, f.commands())
	}
}

const releaseCommands = "cxl disable-region region0\ncxl destroy-region region0\ncxl disable-memdev mem0"

func (f *fakePoolSys) wantReleased(t *testing.T) {
	t.Helper()
	if !strings.HasSuffix(f.commands(), releaseCommands) {
		t.Fatalf("device not released:\n%s", f.commands())
	}
}

func (f *fakePoolSys) wantBlocks(t *testing.T, state string) {
	t.Helper()
	for _, b := range []string{"74", "75"} {
		if st := f.read("devices/system/memory/memory" + b + "/state"); st != state {
			t.Fatalf("memory%s is %q, expected %q", b, st, state)
		}
	}
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
	f.write(pd+"/block/pmem0/dev", cmp.Or(f.pmemDev, "259:0"))
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

// renamePmem gives the fsdax namespace of region0 the block device name
// with the numbers dev, as the next boot or a new probe may.
func (f *fakePoolSys) renamePmem(name, dev string) {
	pd := fakeNdRegionPath + "/pfn0.0"
	_ = os.RemoveAll(f.p(pd + "/block/pmem0"))
	_ = os.Remove(f.p("class/block/pmem0"))
	f.write(pd+"/block/"+name+"/dev", dev)
	f.write(pd+"/block/"+name+"/size", fmt.Sprint(fakePmemBytes/512))
	f.link("class/block/"+name, "../../"+pd+"/block/"+name)
}
