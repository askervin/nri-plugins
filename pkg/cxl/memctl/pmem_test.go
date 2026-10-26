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
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// The sysfs layout of a CXL region of persistent memory, as 7.3.0-rc4
// shows it in the e2e VMs: regionN/pmem_regionN, the nvdimm region
// regionN (same id) on the nvdimm bus of the nvdimm bridge, its namespaces
// namespaceN.M, an fsdax namespace held by a pfn device pfnN.M (mode
// "ram" for map mem) with the block device pmemK.
const (
	ndBusPath      = "devices/platform/ACPI0017:00/root0/nvdimm-bridge0/ndbus0"
	ndRegionPath   = ndBusPath + "/region0"
	pmemNsBytes    = 536870912
	pmemBlockBytes = 534773760 // ndctl list: 510 MiB with map mem
	fsdaxJSON      = `{"dev":"namespace0.0","mode":"fsdax","map":"mem","size":534773760,` +
		`"uuid":"ac26f016-7aa3-446c-8719-78f2d546ebed","sector_size":512,"align":2097152,"blockdev":"pmem0"}`
)

// pmemSys is a fakeSys with a persistent memdev: cxl create-region -t pmem
// and ndctl create-namespace, labels that outlive the region (the LSA), and
// a kernel that probes the nvdimm region and its namespaces after delay.
type pmemSys struct {
	*fakeSys
	labels bool          // the LSA has the label of an fsdax namespace
	delay  time.Duration // until the nvdimm region and namespaces are probed
	probes sync.WaitGroup
}

func newPmemSys(t *testing.T) *pmemSys {
	f := &pmemSys{fakeSys: newFakeSys(t)}
	// a probe outliving a failed test must not write into its removed
	// temporary directory
	t.Cleanup(f.probes.Wait)
	f.write("bus/cxl/devices/decoder0.0/cap_ram", "1")
	f.write("bus/cxl/devices/decoder0.0/cap_pmem", "0")
	f.write("bus/cxl/devices/decoder0.2/devtype", "cxl_decoder_root")
	f.write("bus/cxl/devices/decoder0.2/target_list", "12")
	f.write("bus/cxl/devices/decoder0.2/cap_ram", "0")
	f.write("bus/cxl/devices/decoder0.2/cap_pmem", "1")
	_ = os.MkdirAll(f.p("bus/nd/drivers/nd_region"), 0o755)
	_ = os.MkdirAll(f.p("bus/nd/drivers/nd_pmem"), 0o755)
	return f
}

// plugPmem makes mem0 appear with persistent memory only.
func (f *pmemSys) plugPmem(serial string) {
	f.plug(serial)
	f.write(memPath+"/ram/size", "0x0")
	f.write(memPath+"/pmem/size", "0x20000000")
}

// fsdax gives namespace0.0 the size of the labels, held by pfn, with its
// block device pmem0.
func (f *pmemSys) fsdax(pfn string) {
	ns := ndRegionPath + "/namespace0.0"
	f.write(ns+"/size", itoa(pmemNsBytes))
	f.write(ns+"/holder", pfn)
	f.write(ns+"/mode", "memory")
	_ = os.Remove(f.p(ns + "/driver"))
	pd := ndRegionPath + "/" + pfn
	f.write(pd+"/mode", "ram")
	f.link("bus/nd/devices/"+pfn, "../../../"+pd)
	f.link(pd+"/driver", f.p("bus/nd/drivers/nd_pmem"))
	f.write(pd+"/block/pmem0/dev", "259:0")
	f.write(pd+"/block/pmem0/size", itoa(pmemBlockBytes/512))
	f.link("class/block/pmem0", "../../"+pd+"/block/pmem0")
}

// probe makes the nvdimm region and its namespaces appear as the kernel
// does: the region bound, then namespace0.0 (from the labels, else the
// seed), then the pfn device and the block device of an fsdax namespace.
func (f *pmemSys) probe() {
	time.Sleep(f.delay)
	f.write(ndRegionPath+"/init_namespaces", "1/1")
	f.link(ndRegionPath+"/driver", f.p("bus/nd/drivers/nd_region"))
	time.Sleep(f.delay)
	ns := ndRegionPath + "/namespace0.0"
	f.link("bus/nd/devices/namespace0.0", "../../../"+ns)
	f.write(ns+"/holder", "")
	f.write(ns+"/mode", "raw")
	if !f.labels {
		f.write(ns+"/size", "0")
		return
	}
	// nd_pmem probes the namespace before the pfn device claims it
	f.write(ns+"/size", itoa(pmemNsBytes))
	f.link(ns+"/driver", f.p("bus/nd/drivers/nd_pmem"))
	time.Sleep(f.delay)
	f.fsdax("pfn0.1")
}

func (f *pmemSys) exec(ctx context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	switch {
	case strings.HasPrefix(cmd, "cxl create-region -t pmem "):
		f.mu.Lock()
		f.cmds = append(f.cmds, cmd)
		f.mu.Unlock()
		f.write("bus/cxl/devices/region0/target0", "decoder4.0")
		f.write("bus/cxl/devices/region0/resource", "0x250000000")
		f.write("bus/cxl/devices/region0/size", "0x20000000")
		f.write("bus/cxl/devices/region0/pmem_region0/uevent", "")
		f.write(ndRegionPath+"/size", itoa(pmemNsBytes))
		f.link("bus/nd/devices/region0", "../../../"+ndRegionPath)
		f.probes.Add(1)
		go func() {
			defer f.probes.Done()
			f.probe()
		}()
		return `{"region":"region0","resource":"0x250000000","size":"512.00 MiB","type":"pmem"}` + "\ncxl region: cmd_create_region: created 1 region\n", nil
	case strings.HasPrefix(cmd, "ndctl create-namespace "):
		f.mu.Lock()
		f.cmds = append(f.cmds, cmd)
		f.mu.Unlock()
		f.labels = true
		f.fsdax("pfn0.0")
		return fsdaxJSON + "\n", nil
	case cmd == "cxl destroy-region region0":
		_ = os.RemoveAll(f.p(ndRegionPath))
		for _, l := range []string{"bus/nd/devices/region0", "bus/nd/devices/namespace0.0", "bus/nd/devices/pfn0.0",
			"bus/nd/devices/pfn0.1", "class/block/pmem0"} {
			_ = os.Remove(f.p(l))
		}
	}
	return f.fakeSys.exec(ctx, name, args...)
}

func (f *pmemSys) manager() *Manager {
	m := f.fakeSys.manager()
	m.Exec = f.exec
	return m
}

func TestPersistent(t *testing.T) {
	f := newPmemSys(t)
	f.plugPmem("0xc1ae0001")
	g := f.manager()
	if p, err := g.Persistent("mem0"); err != nil || !p {
		t.Fatalf("persistent memdev: %v %v", p, err)
	}
	f.write(memPath+"/pmem/size", "0x0")
	if p, err := g.Persistent("mem0"); err != nil || p {
		t.Fatalf("memdev without pmem: %v %v", p, err)
	}
	_ = os.RemoveAll(f.p(memPath + "/pmem"))
	if p, err := g.Persistent("mem0"); err != nil || p {
		t.Fatalf("memdev without a pmem directory: %v %v", p, err)
	}
	f.write(memPath+"/pmem/size", "bogus")
	if _, err := g.Persistent("mem0"); err == nil {
		t.Fatal("bogus pmem size accepted")
	}
}

func TestRootDecoderByType(t *testing.T) {
	f := newPmemSys(t)
	f.plugPmem("0xc1ae0001")
	g := f.manager()
	for typ, want := range map[string]string{RegionRAM: "decoder0.0", RegionPmem: "decoder0.2"} {
		if d, err := g.RootDecoder("mem0", typ); err != nil || d != want {
			t.Errorf("%s: %q %v, expected %s", typ, d, err, want)
		}
	}
	f.write("bus/cxl/devices/decoder0.2/cap_pmem", "0")
	if _, err := g.RootDecoder("mem0", RegionPmem); err == nil || !strings.Contains(err.Error(), "no root decoder for pmem regions targets host bridge 12 of mem0") {
		t.Fatalf("expected no decoder, got %v", err)
	}
	if _, err := g.RootDecoder("mem0", "volatile"); err == nil {
		t.Fatal("invalid region type accepted")
	}
}

func TestPmemWriterThenReader(t *testing.T) {
	f := newPmemSys(t)
	f.delay = 20 * time.Millisecond
	f.plugPmem("0xc1ae0001")
	g := f.manager()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// writer: a new region has only the seed namespace
	pr, err := g.CreatePmemRegion(ctx, "mem0", "")
	if err != nil {
		t.Fatal(err)
	}
	if pr.Memdev != "mem0" || pr.Region != "region0" || pr.NdRegion != "region0" || len(pr.Namespaces) != 0 {
		t.Fatalf("new region %+v", pr)
	}
	if !strings.Contains(f.commands(), "cxl create-region -t pmem -d decoder0.2 -m mem0") {
		t.Fatalf("unexpected commands:\n%s", f.commands())
	}
	if FsdaxNamespace(pr.Namespaces) != nil {
		t.Fatal("fsdax namespace in a new region")
	}
	ns, err := g.CreateFsdaxNamespace(ctx, pr.NdRegion, "")
	if err != nil {
		t.Fatal(err)
	}
	want := Namespace{Name: "namespace0.0", Mode: NamespaceFsdax, Map: MapMem, Size: pmemBlockBytes, BlockDevice: "/dev/pmem0", Major: 259, Minor: 0}
	if !reflect.DeepEqual(*ns, want) {
		t.Fatalf("namespace %+v, expected %+v", *ns, want)
	}
	if !strings.Contains(f.commands(), "ndctl create-namespace -f -r region0 -m fsdax -M mem") {
		t.Fatalf("unexpected commands:\n%s", f.commands())
	}
	// the region is reused
	pr, err = g.CreatePmemRegion(ctx, "mem0", "")
	if err != nil || !reflect.DeepEqual(pr.Namespaces, []Namespace{want}) || strings.Count(f.commands(), "create-region") != 1 {
		t.Fatalf("reused region %+v %v\n%s", pr, err, f.commands())
	}
	if err := g.Release(ctx, "mem0"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(f.commands(), "cxl disable-region region0\ncxl destroy-region region0\ncxl disable-memdev mem0") {
		t.Fatalf("unexpected commands:\n%s", f.commands())
	}

	// reader: the namespace comes from the labels, after the probe of the
	// region, the namespace and its pfn device
	pr, err = g.CreatePmemRegion(ctx, "mem0", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := FsdaxNamespace(pr.Namespaces); got == nil || !reflect.DeepEqual(*got, want) {
		t.Fatalf("reader namespaces %+v", pr.Namespaces)
	}
	if strings.Count(f.commands(), "ndctl") != 1 || !strings.Contains(f.commands(), "cxl enable-memdev mem0") {
		t.Fatalf("unexpected commands:\n%s", f.commands())
	}
	if strings.Contains(f.commands(), "destroy-namespace") || strings.Contains(f.commands(), "labels") {
		t.Fatalf("a namespace or label operation:\n%s", f.commands())
	}
}

func TestNamespacesWaitForProbe(t *testing.T) {
	f := newPmemSys(t)
	f.plugPmem("0xc1ae0001")
	f.labels = true
	g := f.manager()
	f.write(ndRegionPath+"/size", itoa(pmemNsBytes))
	f.link("bus/nd/devices/region0", "../../../"+ndRegionPath)
	poll := func() ([]Namespace, bool) {
		t.Helper()
		ns, settled, err := g.namespaces("region0")
		if err != nil {
			t.Fatal(err)
		}
		return ns, settled
	}
	// region not bound
	if _, settled := poll(); settled {
		t.Fatal("unbound region settled")
	}
	// bound, its namespace not registered yet
	f.write(ndRegionPath+"/init_namespaces", "1/1")
	f.link(ndRegionPath+"/driver", f.p("bus/nd/drivers/nd_region"))
	if _, settled := poll(); settled {
		t.Fatal("settled before the namespace was registered")
	}
	// nd_pmem probing the namespace: not raw yet
	ns := ndRegionPath + "/namespace0.0"
	f.link("bus/nd/devices/namespace0.0", "../../../"+ns)
	f.write(ns+"/size", itoa(pmemNsBytes))
	f.write(ns+"/holder", "")
	f.link(ns+"/driver", f.p("bus/nd/drivers/nd_pmem"))
	if _, settled := poll(); settled {
		t.Fatal("settled while the namespace was probed")
	}
	// claimed by a pfn device without its driver yet
	f.fsdax("pfn0.1")
	_ = os.Remove(f.p(ndRegionPath + "/pfn0.1/driver"))
	if _, settled := poll(); settled {
		t.Fatal("settled before the pfn device was probed")
	}
	// the driver bound, its probe adding the disk: the disk directory
	// is there, its class link and dev attribute not yet
	f.link(ndRegionPath+"/pfn0.1/driver", f.p("bus/nd/drivers/nd_pmem"))
	_ = os.Remove(f.p("class/block/pmem0"))
	if _, settled := poll(); settled {
		t.Fatal("settled before the class link of the disk appeared")
	}
	f.link("class/block/pmem0", "../../"+ndRegionPath+"/pfn0.1/block/pmem0")
	_ = os.Remove(f.p(ndRegionPath + "/pfn0.1/block/pmem0/dev"))
	if _, settled := poll(); settled {
		t.Fatal("settled before the dev attribute of the disk appeared")
	}
	f.write(ndRegionPath+"/pfn0.1/block/pmem0/dev", "259:0")
	// the disk complete, the mode of the pfn device not readable (or
	// unknown): not settled, whatever the order of the reads (bug-10 C)
	_ = os.Remove(f.p(ndRegionPath + "/pfn0.1/mode"))
	if got, settled := poll(); settled {
		t.Fatalf("settled without the mode of the pfn device: %+v", got)
	}
	f.write(ndRegionPath+"/pfn0.1/mode", "bogus")
	if got, settled := poll(); settled {
		t.Fatalf("settled with an unknown mode of the pfn device: %+v", got)
	}
	f.write(ndRegionPath+"/pfn0.1/mode", "ram")
	got, settled := poll()
	if !settled || len(got) != 1 || got[0].Mode != NamespaceFsdax || got[0].Map != MapMem || got[0].BlockDevice != "/dev/pmem0" {
		t.Fatalf("settled %v namespaces %+v", settled, got)
	}
	// map dev
	f.write(ndRegionPath+"/pfn0.1/mode", "pmem")
	if got, _ := poll(); got[0].Map != MapDev || FsdaxNamespace(got) != nil {
		t.Fatalf("map dev namespace %+v", got)
	}
	// a raw namespace with its own block device
	_ = os.RemoveAll(f.p(ndRegionPath + "/pfn0.1"))
	f.write(ns+"/holder", "")
	f.link(ns+"/driver", f.p("bus/nd/drivers/nd_pmem"))
	f.write(ns+"/block/pmem0/dev", "259:0")
	f.write(ns+"/block/pmem0/size", itoa(pmemNsBytes/512))
	f.link("class/block/pmem0", "../../"+ns+"/block/pmem0")
	if got, settled := poll(); !settled || got[0].Mode != NamespaceRaw || got[0].Size != pmemNsBytes || got[0].BlockDevice != "/dev/pmem0" {
		t.Fatalf("raw namespace %v %+v", settled, got)
	}
	// devdax
	f.write(ns+"/holder", "dax0.1")
	f.write(ndRegionPath+"/dax0.1/uevent", "")
	f.link("bus/nd/devices/dax0.1", "../../../"+ndRegionPath+"/dax0.1")
	f.link(ndRegionPath+"/dax0.1/driver", f.p("bus/nd/drivers/nd_pmem"))
	if got, settled := poll(); !settled || got[0].Mode != NamespaceDevdax || got[0].BlockDevice != "" || FsdaxNamespace(got) != nil {
		t.Fatalf("devdax namespace %v %+v", settled, got)
	}
	// Namespaces gives up with the context
	_ = os.Remove(f.p(ndRegionPath + "/dax0.1/driver"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := g.Namespaces(ctx, "region0"); err == nil || !strings.Contains(err.Error(), "region0: namespaces still probing (namespace0.0: no ") ||
		!strings.Contains(err.Error(), "bus/nd/devices/dax0.1/driver): context deadline exceeded") {
		t.Fatalf("expected a timeout naming the missing file, got %v", err)
	}
}

// A pfn device that is probed, with its disk complete, but whose mode
// cannot be read is not settled: an fsdax namespace with an unknown map is
// not taken for no fsdax namespace (review DRV2 E11).
func TestNamespacesPfnModeUnreadable(t *testing.T) {
	f := newPmemSys(t)
	f.plugPmem("0xc1ae0001")
	g := f.manager()
	f.write(ndRegionPath+"/size", itoa(pmemNsBytes))
	f.link("bus/nd/devices/region0", "../../../"+ndRegionPath)
	f.write(ndRegionPath+"/init_namespaces", "1/1")
	f.link(ndRegionPath+"/driver", f.p("bus/nd/drivers/nd_region"))
	f.link("bus/nd/devices/namespace0.0", "../../../"+ndRegionPath+"/namespace0.0")
	f.fsdax("pfn0.1")
	_ = os.Remove(f.p(ndRegionPath + "/pfn0.1/mode"))
	got, settled, err := g.namespaces("region0")
	if err != nil || settled {
		t.Fatalf("settled %v err %v namespaces %+v", settled, err, got)
	}
}

// ndctl create-namespace -f is never run over a region that is probing
// or has an fsdax namespace: it would destroy what a writer formatted.
func TestCreateFsdaxNamespaceRefuses(t *testing.T) {
	f := newPmemSys(t)
	f.plugPmem("0xc1ae0001")
	g := f.manager()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pr, err := g.CreatePmemRegion(ctx, "mem0", "")
	if err != nil {
		t.Fatal(err)
	}
	// a writer formatted the device meanwhile, with map dev
	f.fsdax("pfn0.1")
	f.write(ndRegionPath+"/pfn0.1/mode", "pmem")
	if _, err := g.CreateFsdaxNamespace(ctx, pr.NdRegion, "namespace0.0"); err == nil || !strings.Contains(err.Error(), `region0: not creating an fsdax namespace: namespace0.0 is one already (map "dev")`) {
		t.Fatalf("expected a refusal, got %v", err)
	}
	// its mode cannot be read
	_ = os.Remove(f.p(ndRegionPath + "/pfn0.1/mode"))
	if _, err := g.CreateFsdaxNamespace(ctx, pr.NdRegion, "namespace0.0"); err == nil || !strings.Contains(err.Error(), "region0: not creating an fsdax namespace: the namespaces are still probing (namespace0.0: cannot read ") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if strings.Contains(f.commands(), "ndctl") {
		t.Fatalf("ndctl ran:\n%s", f.commands())
	}
}

func TestCreatePmemRegionErrors(t *testing.T) {
	f := newPmemSys(t)
	f.plugPmem("0xc1ae0001")
	g := f.manager()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// a region of volatile memory of the memdev is not reused
	f.write("bus/cxl/devices/region0/target0", "decoder4.0")
	if _, err := g.CreatePmemRegion(ctx, "mem0", ""); err == nil || !strings.Contains(err.Error(), "mem0: region0 is not a region of persistent memory") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	// a pmem region without an nvdimm region
	f.write("bus/cxl/devices/region0/pmem_region0/uevent", "")
	if _, err := g.CreatePmemRegion(ctx, "mem0", ""); err == nil || !strings.Contains(err.Error(), "region0: no nvdimm region appeared") {
		t.Fatalf("expected a timeout, got %v", err)
	}
	if _, err := g.NdRegion("pmem_region0"); err == nil {
		t.Fatal("invalid region name accepted")
	}
	// no namespace is created in a region that is probing
	if _, err := g.CreateFsdaxNamespace(ctx, "region0", "namespace0.0"); err == nil || !strings.Contains(err.Error(), "region0: not creating an fsdax namespace: the namespaces are still probing") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if strings.Contains(f.commands(), "ndctl") {
		t.Fatalf("ndctl ran:\n%s", f.commands())
	}
	// ndctl output without a namespace
	f.write(ndRegionPath+"/init_namespaces", "0/0")
	f.link("bus/nd/devices/region0", "../../../"+ndRegionPath)
	f.link(ndRegionPath+"/driver", f.p("bus/nd/drivers/nd_region"))
	g.Exec = func(ctx context.Context, name string, args ...string) (string, error) { return "{}", nil }
	if _, err := g.CreateFsdaxNamespace(ctx, "region0", "namespace0.0"); err == nil || !strings.Contains(err.Error(), "did not report a namespace") {
		t.Fatalf("expected an error, got %v", err)
	}
}

func TestCreateFsdaxNamespaceReconfigures(t *testing.T) {
	f := newPmemSys(t)
	f.plugPmem("0xc1ae0001")
	g := f.manager()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pr, err := g.CreatePmemRegion(ctx, "mem0", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.CreateFsdaxNamespace(ctx, pr.NdRegion, "namespace0.0"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.commands(), "ndctl create-namespace -f -r region0 -m fsdax -M mem -e namespace0.0") {
		t.Fatalf("unexpected commands:\n%s", f.commands())
	}
}
