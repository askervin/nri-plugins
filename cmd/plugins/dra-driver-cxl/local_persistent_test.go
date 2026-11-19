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
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

const (
	localPmemSerial     = 0xc100f5e1
	localPmemDeviceName = "memdev-c100f5e1"
	localPmemBlockRW    = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block"}}`
	localPmemBlockRO    = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"block","readOnly":true}}`
	localPmemFsRW       = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":false}}`
	localPmemFsRO       = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs"}}`
	// the shares of an exclusive claim and of a share
	localPmemAll, localPmemShare = "1M", "1"
	// localPmemPath is the default path of mode fs of the memdev.
	localPmemPath = "/run/cxl-fs/C100F5E1"
)

// pmemTestEnv is a localTestEnv with the local memdev localPmemSerial of
// 512 MiB of persistent memory, every filesystem type that the plugin
// knows allowed.
type pmemTestEnv struct {
	*localTestEnv
}

// newPmemTestEnv returns a pmemTestEnv, not started.
func newPmemTestEnv(t *testing.T) *pmemTestEnv {
	t.Helper()
	e := &pmemTestEnv{localTestEnv: newLocalTestEnv(t, fakeMemdevSpecPmem(localPmemSerial))}
	e.config.FsTypes = slices.Clone(api.KnownFsTypes)
	return e
}

// memdev returns the name of the memdev in the kernel.
func (e *pmemTestEnv) memdev() string {
	return e.k.Memdev(localPmemSerial)
}

// region returns the region of the memdev, "" for none.
func (e *pmemTestEnv) region() string {
	if rs := e.regions(localPmemSerial); len(rs) > 0 {
		return rs[0]
	}
	return ""
}

// namespace returns the fsdax namespace of the region of the memdev in the
// kernel, nil if there is none.
func (e *pmemTestEnv) namespace() *kernel.Namespace {
	k := e.k.Kernel()
	nd, err := k.NdRegionOf(e.region())
	if err != nil {
		return nil
	}
	nss, _, err := k.ProbeNamespaces(nd)
	if err != nil {
		return nil
	}
	return kernel.FsdaxNamespace(nss)
}

// nodeMount returns the node mount of the memdev with the access.
func (e *pmemTestEnv) nodeMount(access string) string {
	return filepath.Join(e.dir, mountsDirName, "c100f5e1-"+access)
}

// mounted returns the mount at target in the mount namespace of the
// driver, nil if there is none.
func (e *pmemTestEnv) mounted(target string) *kernel.MountInfo {
	e.t.Helper()
	mi, err := e.k.Kernel().Mounted(target)
	noErr(e.t, err)
	return mi
}

// used tells whether the engine has a record of the memdev.
func (e *pmemTestEnv) used() bool {
	return e.localSnapshot().InUse(localPmemSerial)
}

// published returns the memdev as a scan publishes it now, nil if it does
// not.
func (e *pmemTestEnv) published() *resourcev1.Device {
	e.t.Helper()
	e.rescan()
	for _, d := range e.publisher.Resources().Pools[testNode].Slices[0].Devices {
		if d.Name == localPmemDeviceName {
			return &d
		}
	}
	return nil
}

// wantPmemCDIDevice checks the env, the device nodes and the mounts of a
// CDI device of the claims spec.
func (e *pmemTestEnv) wantPmemCDIDevice(name string, env []string, nodes []*cdiSpecs.DeviceNode, mounts []*cdiSpecs.Mount) {
	e.t.Helper()
	d := cdiDeviceByName(e.cdiSpec(), name)
	same := func(a, b any, n int) bool { return n == 0 || reflect.DeepEqual(a, b) }
	if d == nil || !slices.Equal(d.ContainerEdits.Env, env) ||
		len(d.ContainerEdits.DeviceNodes) != len(nodes) || !same(d.ContainerEdits.DeviceNodes, nodes, len(nodes)) ||
		len(d.ContainerEdits.Mounts) != len(mounts) || !same(d.ContainerEdits.Mounts, mounts, len(mounts)) {
		var got any = d
		if d != nil {
			got = d.ContainerEdits
		}
		e.t.Fatalf("CDI device %s: %+v, expected env %v nodes %+v mounts %+v", name, got, env, nodes, mounts)
	}
}

// wantRegions checks how many times the driver created a region of the
// memdev and destroyed one, and that it never disabled a memdev.
func (e *pmemTestEnv) wantRegions(created, destroyed int) {
	e.t.Helper()
	cmds := e.commands()
	c, d := 0, 0
	for _, l := range strings.Split(cmds, "\n") {
		switch {
		case strings.HasPrefix(l, "cxl create-region ") && strings.HasSuffix(l, " -m "+e.memdev()):
			c++
		case strings.HasPrefix(l, "cxl destroy-region "):
			d++
		}
	}
	if c != created || d != destroyed {
		e.t.Fatalf("region created %d and destroyed %d times, expected %d and %d:\n%s", c, d, created, destroyed, cmds)
	}
	if strings.Contains(cmds, "disable-memdev") {
		e.t.Fatalf("a memdev was disabled:\n%s", cmds)
	}
}

// wantNoViolations fails the test on a violation of the rules of
// persistent devices in the kernel.
func (e *pmemTestEnv) wantNoViolations() {
	e.t.Helper()
	if v := e.k.Violations(); len(v) > 0 {
		e.t.Fatalf("violations %v", v)
	}
}

// infoOf returns the info of the first device of a prepared claim.
func (e *pmemTestEnv) infoOf(uid string) PreparedDeviceInfo {
	e.t.Helper()
	info := e.s.ClaimInfo(uid)
	if info == nil || len(info.Devices) == 0 {
		e.t.Fatalf("claim %s is not prepared", uid)
	}
	return info.Devices[0]
}

// pmemClaim returns a claim allocated the persistent memdev for request
// "mem" with the consumed shares ("": none), and opaque cxl.nri.io claim
// configs.
func pmemClaim(uid, shares string, configs ...string) *resourcev1.ResourceClaim {
	c := memdevClaim(uid, localPmemDeviceName, 0, configs...)
	if shares != "" {
		c.Status.Allocation.Devices.Results[0].ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse(shares)}
	}
	return c
}

// pmemEnv returns the env of a CDI device of the persistent memdev.
func pmemEnv(uid string, kv ...string) []string {
	env := []string{"CXL_CLAIM_" + uid + "_0=1"}
	for _, s := range kv {
		env = append(env, "CXL_C100F5E1_"+s)
	}
	slices.Sort(env)
	return env
}

// The life cycle of a persistent local memdev: readers refused before a
// block writer makes the namespace, fs writers and readers of one node mount.
func TestLocalPersistentLifeCycle(t *testing.T) {
	e := newPmemTestEnv(t)
	e.start()
	if d := e.published(); d == nil || !*d.Attributes["persistent"].BoolValue || *d.Attributes["shared"].BoolValue {
		t.Fatalf("published %+v", d)
	}

	// readers before a writer: refused, the region goes again
	wantErr(t, e.prepare(pmemClaim("r1", localPmemShare, localPmemFsRO)),
		"cxl.nri.io: claim demo/claim-r1: device memdev-c100f5e1 serial 0xc100f5e1: device 0xc100f5e1: no fsdax namespace in region0: has a writer written the device?")
	wantErr(t, e.prepare(pmemClaim("r1", localPmemShare, localPmemBlockRO)), "no fsdax namespace in region0")
	e.wantRegions(2, 2)
	if strings.Contains(e.commands(), "ndctl") || e.used() {
		t.Fatalf("a reader made a namespace or holds the device:\n%s", e.commands())
	}

	// the configuration rules, before the device is touched
	before := e.commands()
	wantErr(t, e.prepare(pmemClaim("w0", localPmemShare, localPmemBlockRW)),
		"claim demo/claim-w0: request mem: MemoryConfig: device.mode block: the device is writable only exclusively (no shares request)")
	wantErr(t, e.prepare(pmemClaim("w0", localPmemShare)), "MemoryConfig: device: a persistent device needs mode block or fs")
	wantErr(t, e.prepare(pmemClaim("w0", "0", localPmemBlockRW)), "device 0xc100f5e1: consumed shares \"0\" is less than 1")
	claim := pmemClaim("w0", "", localPmemBlockRW)
	claim.Status.Allocation.Devices.Results[0].ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityMemory: resource.MustParse("1Gi")}
	wantErr(t, e.prepare(claim), "claim demo/claim-w0: request mem: device 0xc100f5e1: allocated as a device of volatile memory, which it is not any more")
	if e.commands() != before {
		t.Fatalf("a refused claim touched the device:\n%s", strings.TrimPrefix(e.commands(), before))
	}

	// the block writer has the device alone and makes the namespace
	e.mustPrepare(pmemClaim("w1", localPmemAll, localPmemBlockRW))
	if !strings.Contains(e.commands(), "ndctl create-namespace -f -r region0 -m fsdax -M mem") {
		t.Fatalf("no namespace made:\n%s", e.commands())
	}
	ns := e.namespace()
	if ns == nil {
		t.Fatal("no fsdax namespace")
	}
	pmem := ns.BlockDevice
	e.wantPmemCDIDevice("claim-w1-0",
		pmemEnv("w1", "MODE=block", "PATH="+pmem, "READONLY=0", "SERIAL=0xc100f5e1", "SHARED=0", "SIZE=534773760"),
		[]*cdiSpecs.DeviceNode{{Path: pmem, Type: "b", Major: int64(ns.Major), Minor: int64(ns.Minor)}}, nil)
	if e.k.IsReadOnly(pmem) {
		t.Fatal("the block device of a writer is read-only")
	}
	info := e.infoOf("w1")
	if !info.Persistent || info.Mode != api.ModeBlock || info.BlockDevice != pmem || e.grant("w1", 0).Got.Namespace != "namespace0.0" || info.TotalBytes != fakePmemBytes || info.ReadOnly {
		t.Fatalf("prepared %+v", info)
	}
	// the writer writes an ext4
	e.k.SetImage(pmem, fake.FsImage("ext4"))
	e.mustUnprepare("w1")
	e.wantRegions(3, 3)
	if e.used() || e.published() == nil {
		t.Fatal("the idle device is used or not published")
	}

	// fs writers and a reader of one node mount
	e.mustPrepare(pmemClaim("rw1", localPmemShare, localPmemFsRW))
	e.mustPrepare(pmemClaim("rw2", localPmemShare, localPmemFsRW))
	e.mustPrepare(pmemClaim("ro1", localPmemShare, localPmemFsRO))
	e.wantRegions(4, 3)
	pmem = e.namespace().BlockDevice
	mnt := e.nodeMount("direct")
	for uid, ro := range map[string]bool{"rw1": false, "rw2": false, "ro1": true} {
		readOnly, opts := "0", []string{"bind", "nosuid", "nodev"}
		if ro {
			readOnly, opts = "1", []string{"bind", "ro", "nosuid", "nodev"}
		}
		e.wantPmemCDIDevice("claim-"+uid+"-0",
			pmemEnv(uid, "ACCESS=direct", "FSTYPE=ext4", "MODE=fs", "PATH="+localPmemPath, "READONLY="+readOnly, "SERIAL=0xc100f5e1", "SHARED=0", "SIZE=534773760"),
			nil, []*cdiSpecs.Mount{{HostPath: mnt, ContainerPath: localPmemPath, Type: "bind", Options: opts}})
	}
	if mi := e.mounted(mnt); mi == nil || mi.FsType != "ext4" || mi.SuperReadOnly() || len(e.k.MountTable()) != 1 {
		t.Fatalf("node mount %+v of mounts %+v", mi, e.k.MountTable())
	}
	// the last writer goes: the superblock and the block device turn
	// read-only, the reader stays
	e.mustUnprepare("rw1")
	if mi := e.mounted(mnt); mi == nil || mi.SuperReadOnly() {
		t.Fatalf("after one writer: %+v", mi)
	}
	e.mustUnprepare("rw2")
	if mi := e.mounted(mnt); mi == nil || !mi.SuperReadOnly() || !e.k.IsReadOnly(pmem) {
		t.Fatalf("after the writers: %+v, read-only %v", mi, e.k.IsReadOnly(pmem))
	}
	// a held block device keeps the region and the claim for kubelet's
	// retry
	e.k.SetHolder(pmem, "in use")
	wantErr(t, e.unprepare("ro1"), "device 0xc100f5e1: "+pmem+" is still in use")
	e.wantRegions(4, 3)
	if e.preparation("ro1") == nil {
		t.Fatal("the claim is gone after a failed release")
	}
	e.k.SetHolder(pmem, "")
	e.mustUnprepare("ro1")
	e.wantRegions(4, 4)
	if len(e.k.MountTable()) != 0 || e.cdiSpec() != nil || e.used() {
		t.Fatalf("left: mounts %+v", e.k.MountTable())
	}
	e.wantClean()
	e.wantNoViolations()
}
