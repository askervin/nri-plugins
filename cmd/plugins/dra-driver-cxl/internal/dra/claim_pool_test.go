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

package dra

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// cutPrepare runs a Prepare of the claim on the plugin that the process
// does not finish: it stops at a cut point of the fake (fake.ErrCut).
func (e *driverEnv) cutPrepare(p *Plugin, claim *resourcev1.ResourceClaim) {
	e.t.Helper()
	defer func() {
		r := recover()
		if err, ok := r.(error); ok && errors.Is(err, fake.ErrCut) {
			return
		}
		if r == nil {
			e.t.Fatal("the Prepare was not cut")
		}
		panic(r)
	}()
	_, _ = p.PrepareResourceClaims(context.Background(), []*resourcev1.ResourceClaim{claim})
}

// wantPoolLine fails the test unless the log has the line of the pool
// driver's prepared device pooled0 that test10 waits for.
func wantPoolLine(t *testing.T, log string) {
	t.Helper()
	for _, line := range strings.Split(log, "\n") {
		ok, err := compat.MatchesRegexp(compat.LogDRAPoolDriverClaimPreparedPooled0, line)
		mustOK(t, err)
		if ok {
			return
		}
	}
	t.Fatalf("no line %q in\n%s", compat.LogDRAPoolDriverClaimPreparedPooled0, log)
}

// A pool device of volatile memory in mode numa: its region onlined, the
// line of test10, its CDI device; the result of the claim has the pool
// driver's devices only; the Unprepare releases the device.
func TestPoolNUMA(t *testing.T) {
	e := newDriverEnv(t, nil, poolSpec(serialPoolX))
	logs := klogCapture(t)
	res := e.mustPrepare(e.pool, poolClaim("u1", "pooled0", poolExclusiveData))
	wantResult(t, res, resultDevice("mem", envPool, "pooled0", "nri.io/cxl-pool=claim-u1-0"))
	wantPoolLine(t, logs())
	if !strings.Contains(e.commands(), "cxl create-region -t ram -d decoder0.0 -m mem0") {
		t.Fatalf("commands:\n%s", e.commands())
	}
	if spec := e.cdiSpec(e.pool.Rules().CDISpecName); spec == nil || spec.Kind != "nri.io/cxl-pool" {
		t.Fatalf("CDI spec %+v", spec)
	}
	cd := e.cdiDevice(e.pool, "claim-u1-0")
	want := []string{"CXL_C1EE0001_MODE=numa", "CXL_C1EE0001_NODE=2", "CXL_C1EE0001_SERIAL=0xc1ee0001", "CXL_C1EE0001_SHARED=0",
		"CXL_C1EE0001_SIZE=268435456", "CXL_CLAIM_u1_0=1"}
	if cd == nil || !slices.Equal(cd.ContainerEdits.Env, want) || len(cd.ContainerEdits.DeviceNodes) != 0 {
		t.Fatalf("CDI device %+v, expected env %v", cd, want)
	}
	if got := NumaNodes(e.records(), e.pool.Name()); !slices.Equal(got, []int{2}) {
		t.Fatalf("NUMA nodes %v", got)
	}
	e.mustUnprepare(e.pool, "u1")
	if !strings.Contains(e.commands(), "cxl destroy-region region0\ncxl disable-memdev mem0") {
		t.Fatalf("not released:\n%s", e.commands())
	}
	wantLogText(t, logs(), "cxl-pool.nri.io: unprepared claim demo/claim-u1 (u1)")
	// the lines of the release that test10 looks for
	released := false
	for _, line := range strings.Split(logs(), "\n") {
		ok, err := compat.MatchesRegexp(compat.LogUnpreparReleas, line)
		mustOK(t, err)
		released = released || ok
	}
	if !released {
		t.Fatalf("no line %q in\n%s", compat.LogUnpreparReleas, logs())
	}
	e.wantClean()
	// an unknown claim is not an error
	e.mustUnprepare(e.pool, "u1")
}

// A pool device of volatile memory in mode dax, and a shared one used by
// two claims: devdax devices as CDI device nodes, read-only by the
// configuration.
func TestPoolDaxAndShared(t *testing.T) {
	e := newDriverEnv(t, nil, poolSpec(serialPoolX), fake.MemdevSpec{Serial: serialPoolS, HostBridge: 24})
	e.mustPrepare(e.pool, poolClaim("x1", "pooled0", poolExclusiveData, cfgDax))
	x := e.pool.PoolDevices("x1")[0]
	cd := e.cdiDevice(e.pool, "claim-x1-0")
	if x.Mode != api.ModeDax || x.DaxDevice == "" || x.NumaNode != -1 || cd == nil ||
		!reflect.DeepEqual(cd.ContainerEdits.DeviceNodes, []*cdiSpecs.DeviceNode{DaxDeviceNode(x.DaxDevice, x.DaxMajor, x.DaxMinor, false)}) {
		t.Fatalf("device %+v, CDI device %+v", x, cd)
	}
	e.mustPrepare(e.pool, poolClaim("s1", "shared0", poolSharedData))
	e.mustPrepare(e.pool, poolClaim("s2", "shared0", poolSharedData, cfgDaxRO))
	s1, s2 := e.pool.PoolDevices("s1")[0], e.pool.PoolDevices("s2")[0]
	if !s1.Shared || s1.Mode != api.ModeDax || s1.DaxDevice != s2.DaxDevice || s1.ReadOnly || !s2.ReadOnly {
		t.Fatalf("shared devices %+v %+v", s1, s2)
	}
	if cd := e.cdiDevice(e.pool, "claim-s2-0"); cd == nil || cd.ContainerEdits.DeviceNodes[0].Permissions != "r" {
		t.Fatalf("read-only CDI device %+v", cd)
	}
	// a claim of the shared device in another mode is refused before the
	// device is touched
	e.mark()
	res := e.prepare(e.pool, poolClaim("s3", "shared0", poolSharedData, cfgNUMA))
	wantErrText(t, res.Err, "cxl-pool.nri.io: preparing claim demo/claim-s3: device shared0 serial 0xc1ae0001: ")
	e.wantNoCommands("a refused claim")
	for _, uid := range []string{"x1", "s1", "s2"} {
		e.mustUnprepare(e.pool, uid)
	}
	e.wantClean()
}

// Pool devices of persistent memory: an exclusive writer in mode block
// makes the namespace; readers in mode fs share the node mount of the
// access.
func TestPoolPersistent(t *testing.T) {
	e := newDriverEnv(t, nil, poolPmemSpec(serialPoolP))
	e.mustPrepare(e.pool, poolClaim("w1", "llm0", poolWriterData, cfgBlock))
	if !strings.Contains(e.commands(), "ndctl create-namespace") {
		t.Fatalf("no namespace made:\n%s", e.commands())
	}
	w := e.pool.PoolDevices("w1")[0]
	cd := e.cdiDevice(e.pool, "claim-w1-0")
	if !w.Persistent || w.Mode != api.ModeBlock || w.BlockDevice == "" || w.NdRegion == "" || cd == nil ||
		!reflect.DeepEqual(cd.ContainerEdits.DeviceNodes, []*cdiSpecs.DeviceNode{BlockDeviceNode(w.BlockDevice, w.BlockMajor, w.BlockMinor, false)}) {
		t.Fatalf("device %+v, CDI device %+v", w, cd)
	}
	hasEnv(t, cd, "CXL_C1AF0001_MODE=block", "CXL_C1AF0001_PATH="+w.BlockDevice, "CXL_C1AF0001_SHARED=1")
	e.mustUnprepare(e.pool, "w1")
	// the writer of another host leaves a filesystem
	e.formatPmemAgain(serialPoolP, "erofs")
	e.mustPrepare(e.pool, poolClaim("r1", "llm0", poolPmemData, cfgFsRO))
	e.mustPrepare(e.pool, poolClaim("r2", "llm0", poolPmemData, cfgFsRO))
	r1, r2 := e.pool.PoolDevices("r1")[0], e.pool.PoolDevices("r2")[0]
	mnt := filepath.Join(e.poolDir, "mounts", "c1af0001-direct")
	if r1.Mode != api.ModeFs || r1.NodeMount != mnt || r2.NodeMount != mnt || r1.FsType != "erofs" || r1.Access != api.AccessDirect ||
		r1.Path != "/run/cxl-fs/C1AF0001" || !r1.ReadOnly {
		t.Fatalf("devices %+v %+v", r1, r2)
	}
	cd = e.cdiDevice(e.pool, "claim-r1-0")
	if want := []*cdiSpecs.Mount{FsCDIMount(mnt, "/run/cxl-fs/C1AF0001", true)}; cd == nil || !reflect.DeepEqual(cd.ContainerEdits.Mounts, want) {
		t.Fatalf("CDI device %+v", cd)
	}
	e.mustUnprepare(e.pool, "r1")
	if mi, _ := e.k.Kernel().Mounted(mnt); mi == nil {
		t.Fatal("the node mount went with a claim of it left")
	}
	e.mustUnprepare(e.pool, "r2")
	if mi, _ := e.k.Kernel().Mounted(mnt); mi != nil {
		t.Fatalf("node mount left %+v", mi)
	}
	e.wantClean()
}

// formatPmemAgain writes a filesystem of the type on the fsdax namespace of
// the persistent memdev, which has no region of the drivers, as a writer
// on another host does.
func (e *driverEnv) formatPmemAgain(serial uint64, typ string) {
	e.t.Helper()
	k := e.k.Kernel()
	ctx := context.Background()
	memdev := e.k.Memdev(serial)
	// the release of the driver disabled it
	mustOK(e.t, k.EnableMemdev(ctx, memdev))
	d, err := k.RootDecoder(memdev, kernel.RegionPmem)
	mustOK(e.t, err)
	region, err := k.CreateRegion(ctx, kernel.CreateRegionRequest{Memdev: memdev, Decoder: d, Type: kernel.RegionPmem})
	mustOK(e.t, err)
	nd, err := k.WaitNdRegion(ctx, region)
	mustOK(e.t, err)
	nss, err := k.Namespaces(ctx, nd)
	mustOK(e.t, err)
	ns := kernel.FsdaxNamespace(nss)
	if ns == nil {
		e.t.Fatalf("%s has no fsdax namespace", memdev)
	}
	e.k.SetImage(ns.BlockDevice, fsImage(typ))
	mustOK(e.t, k.ReleaseRegion(ctx, region))
	e.mark()
}

// A rollback that cannot release everything keeps the claim's record
// (KEPT) with the grants left and says so in the pool driver's words; its
// Unprepare releases them.
func TestPoolRollbackKept(t *testing.T) {
	e := newDriverEnv(t, nil, poolSpec(serialPoolX), poolSpec(0xc1ee0002))
	k := e.k.Kernel()
	foreign := e.k.Memdev(0xc1ee0002)
	d, err := k.RootDecoder(foreign, kernel.RegionRAM)
	mustOK(t, err)
	region, err := k.CreateRegion(context.Background(), kernel.CreateRegionRequest{Memdev: foreign, Decoder: d, Type: kernel.RegionRAM})
	mustOK(t, err)
	e.mark()
	// the second device has a region that the driver did not make; the
	// rollback of the first one cannot disable its memdev
	e.k.FailCommand("cxl disable-memdev", syscall.EBUSY)
	claim := addPoolResult(poolClaim("u1", "pooled0", poolExclusiveData), "mem2", "pooled1",
		`{"serial":"0xc1ee0002","shared":false,"size":268435456}`)
	logs := klogCapture(t)
	wantErrText(t, e.prepare(e.pool, claim).Err, "that the plugin did not create")
	wantLogText(t, logs(), "cxl-pool.nri.io: rollback: claim demo/claim-u1 (u1): not everything was released: keeping its record in "+
		e.preparingFile()+" for its Unprepare or its next Prepare")
	prep := e.preparation(e.pool, "u1")
	if prep == nil || prep.State != state.PreparationKept || len(prep.Results) != 1 || prep.Results[0].Index != 0 {
		t.Fatalf("preparation %+v", prep)
	}
	if devs := e.pool.PoolDevices("u1"); len(devs) != 1 || devs[0].Serial != serialPoolX {
		t.Fatalf("devices %+v", devs)
	}
	if e.pool.ClaimResults("u1") != nil || e.pool.ClaimInfo("u1") != nil {
		t.Fatal("results of a KEPT claim")
	}
	// the foreign region goes; the Unprepare forgets its record
	mustOK(t, k.ReleaseRegion(context.Background(), region))
	e.mustUnprepare(e.pool, "u1")
	e.wantClean()
}

// The scheduler holds a pool device for a claim that waits for its attach
// (the pool controller is down, no status data): its Prepare is refused
// without touching anything, its pod is deleted (the Unprepare of a claim
// without a record is nil), and another claim on the same device is then
// prepared once it is attached.
func TestPoolSchedulerHold(t *testing.T) {
	e := newDriverEnv(t, nil, poolSpec(serialPoolX))
	logs := klogCapture(t)
	xnuma := poolClaim("xnuma", "pooled0", "")
	res := e.prepare(e.pool, xnuma)
	wantErrText(t, res.Err, "cxl-pool.nri.io: preparing claim demo/claim-xnuma: ")
	e.wantNoCommands("a Prepare without status data")
	e.wantState(e.pool, "xnuma", state.PreparationUnknown)
	if s := e.pool.Serials(); len(s) != 0 {
		t.Fatalf("serials %v", s)
	}
	mustOK(t, e.unprepare(e.pool, "xnuma"))
	wantLogText(t, logs(), "cxl-pool.nri.io: claim xnuma is not prepared, nothing to release")
	if strings.Contains(logs(), "cxl-pool.nri.io: unprepared claim") {
		t.Fatalf("an Unprepare without a record logged as unprepared:\n%s", logs())
	}
	e.wantNoCommands("an Unprepare without a record")
	xdax := poolClaim("xdax", "pooled0", "", cfgDax)
	wantErrText(t, e.prepare(e.pool, xdax).Err, "cxl-pool.nri.io: preparing claim demo/claim-xdax: ")
	e.wantNoCommands("a Prepare without status data")
	e.mustPrepare(e.pool, setPoolData(xdax, "pooled0", poolExclusiveData))
	if d := e.pool.PoolDevices("xdax"); len(d) != 1 || d[0].Mode != api.ModeDax {
		t.Fatalf("devices %+v", d)
	}
	e.mustUnprepare(e.pool, "xdax")
	e.wantClean()
}

// A Prepare whose context ends after cxl create-region and whose CDI spec
// cannot be written fails, and its rollback still releases everything: the
// cleanup is not bound to the context of the request.
func TestPoolRollbackOutlivesContext(t *testing.T) {
	e := newDriverEnv(t, nil, poolSpec(serialPoolX))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.k.After("cxl create-region", func() {
		cancel()
		mustOK(t, os.RemoveAll(e.cdiDir))
		mustOK(t, os.WriteFile(e.cdiDir, nil, 0o644))
	})
	claim := poolClaim("u1", "pooled0", poolExclusiveData)
	res, err := e.pool.PrepareResourceClaims(ctx, []*resourcev1.ResourceClaim{claim})
	mustOK(t, err)
	wantErrText(t, res[claim.UID].Err, "failed to write CDI spec")
	mustOK(t, os.Remove(e.cdiDir))
	mustOK(t, os.MkdirAll(e.cdiDir, 0o755))
	e.check("rolled back")
	e.wantState(e.pool, "u1", state.PreparationUnknown)
	e.wantClean()
}
