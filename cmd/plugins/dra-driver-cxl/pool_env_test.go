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
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// poolTestEnv is a node for the tests of the pool driver: the fake kernel
// of pkg/cxl/kernel/fake (sysfs, commands, mounts), a state store and a CDI
// directory in a temporary directory, and the pool driver over them. The
// kernel and the files outlive a restart of the driver (driver).
type poolTestEnv struct {
	t  *testing.T
	k  *fake.Fake
	st *store.Store
	// dir is the plugin data directory of the pool driver and of the
	// store.
	dir        string
	cdiDir     string
	timeout    time.Duration
	holderWait time.Duration
	// base are the commands of the fake before those of the driver.
	base string
}

func newPoolTestEnv(t *testing.T) *poolTestEnv {
	dir := t.TempDir()
	e := &poolTestEnv{
		t:          t,
		k:          fake.New(t),
		dir:        filepath.Join(dir, device.PoolDriverName),
		cdiDir:     filepath.Join(dir, "cdi"),
		timeout:    200 * time.Millisecond,
		holderWait: 50 * time.Millisecond,
	}
	noErr(t, os.MkdirAll(e.dir, 0o755))
	t.Cleanup(func() {
		if e.st != nil {
			_ = e.st.Close()
		}
	})
	return e
}

// plug hot-adds the pool device with the serial (volatile memory) and
// returns its memdev.
func (e *poolTestEnv) plug(serial uint64) string {
	return e.k.Plug(fake.MemdevSpec{Serial: serial})
}

// driver returns a new pool driver on the env's store, as after a restart
// (the store opened again, the recovery of dra.NewNode), without a kubelet
// plugin. cxl.nri.io manages no local memdevs. A driver returned before
// must not be used after.
func (e *poolTestEnv) driver(t *testing.T) *dra.Plugin {
	t.Helper()
	noErr(t, os.MkdirAll(e.cdiDir, 0o755))
	if e.st != nil {
		_ = e.st.Close()
	}
	var err error
	e.st, err = store.Open(context.Background(), store.Options{Dir: e.dir, BootID: e.k.BootID()})
	noErr(t, err)
	node, err := dra.NewNode(dra.NodeOptions{
		Kernel:     e.k.Kernel(),
		Store:      e.st,
		Dir:        filepath.Join(filepath.Dir(e.dir), device.DriverName),
		PoolDriver: device.PoolDriverName,
		CDIDir:     e.cdiDir,
		NodeName:   testNode,
		FsTypes:    api.KnownFsTypes,
		Timeouts: engine.Timeouts{Memdev: e.timeout, Settle: e.timeout, Holder: e.holderWait,
			ProbeGrace: 20 * time.Millisecond, RegionRetry: 10 * time.Millisecond, OfflineSettle: 20 * time.Millisecond},
	})
	noErr(t, err)
	_, err = node.Recover(context.Background())
	noErr(t, err)
	noErr(t, node.WriteCDI())
	checkPool(t, node.Pool, "started")
	return node.Pool
}

// records returns the records of the env's store.
func (e *poolTestEnv) records() *state.Records {
	return &e.st.Snapshot().Records
}

// preparation returns the preparation of the claim uid of the pool driver,
// nil if there is none.
func (e *poolTestEnv) preparation(uid string) *state.Preparation {
	return e.records().Preparation(device.PoolDriverName, uid)
}

// cdiSpec returns the pool CDI spec on disk, nil if there is none.
func (e *poolTestEnv) cdiSpec(t *testing.T) *cdiSpecs.Spec {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.cdiDir, device.PoolCDISpecName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	noErr(t, err)
	spec := &cdiSpecs.Spec{}
	noErr(t, json.Unmarshal(data, spec))
	return spec
}

// wantClean checks that nothing is prepared: no CDI spec, no serials, no
// record of the pool driver in the store, no region in the kernel.
func (e *poolTestEnv) wantClean(t *testing.T, p *dra.Plugin) {
	t.Helper()
	r := e.records()
	var left []string
	for i := range r.Preparations {
		if r.Preparations[i].Driver == device.PoolDriverName {
			left = append(left, "preparation "+r.Preparations[i].UID+" "+string(r.Preparations[i].State))
		}
	}
	for i := range r.Grants {
		left = append(left, "grant "+r.Grants[i].Ref.String()+" "+string(r.Grants[i].State))
	}
	for i := range r.Memdevs {
		left = append(left, "memdev "+r.Memdevs[i].Serial.String())
	}
	for i := range r.Regions {
		left = append(left, "region "+string(r.Regions[i].Ref()))
	}
	snap, err := e.k.Kernel().Observe(context.Background())
	noErr(t, err)
	for _, ri := range snap.Regions {
		left = append(left, "kernel "+ri.Name)
	}
	if e.cdiSpec(t) != nil || len(p.Serials()) != 0 || len(left) > 0 {
		t.Fatalf("not clean: CDI spec %+v, serials %v, records and regions %v", e.cdiSpec(t), p.Serials(), left)
	}
}

// commands returns the commands that the fake ran for the driver.
func (e *poolTestEnv) commands() string {
	return e.k.CommandsSince(e.base)
}

// poolConsumed returns the consumed capacity of an allocation result of
// a pool device with the status data: of a shared device all of its
// shares (exclusive) or one, nil otherwise.
func poolConsumed(data string) map[resourceapi.QualifiedName]resource.Quantity {
	d, err := device.ParsePoolStatusData([]byte(data))
	switch {
	case err != nil || !d.Shared:
		return nil
	case d.Exclusive:
		return map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: *resource.NewQuantity(device.SharesUnlimited, resource.DecimalSI)}
	}
	return map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse("1")}
}

// exclusiveData is the status data of the pool device of an exclusive
// claim.
const exclusiveData = `{"serial":"0xc1ee0001","shared":false,"size":268435456,"host":"n1"}`

// poolClaim returns a claim allocated a pool device, with the status
// entry written by the pool controller (data "" for none) and the shares
// that the scheduler counts for a shared device (poolConsumed).
func poolClaim(uid, name, dev, data string) *resourceapi.ResourceClaim {
	c := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), Name: name, Namespace: "default"},
		Status: resourceapi.ResourceClaimStatus{
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{
					Results: []resourceapi.DeviceRequestAllocationResult{
						{Request: "mem", Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: dev, ConsumedCapacity: poolConsumed(data)},
						{Request: "local", Driver: device.DriverName, Pool: "node1", Device: "dram"},
					},
				},
			},
		},
	}
	if data != "" {
		c.Status.Devices = []resourceapi.AllocatedDeviceStatus{
			{Driver: device.DriverName, Pool: "node1", Device: "dram"},
			{Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: dev, Data: &runtime.RawExtension{Raw: []byte(data)}},
		}
	}
	return c
}

func prepare(t *testing.T, p *dra.Plugin, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	t.Helper()
	res, err := p.PrepareResourceClaims(context.Background(), []*resourceapi.ResourceClaim{claim})
	if err != nil {
		t.Fatal(err)
	}
	checkPool(t, p, "prepared "+string(claim.UID))
	return res[claim.UID]
}

// kubeletClaim returns the claim uid as kubelet unprepares it: with the
// namespace and the name of a prepared claim.
func kubeletClaim(p *dra.Plugin, uid string) kubeletplugin.NamespacedObject {
	claim := kubeletplugin.NamespacedObject{UID: types.UID(uid)}
	if info := p.ClaimInfo(uid); info != nil {
		claim.Namespace, claim.Name, _ = strings.Cut(info.ClaimName, "/")
	}
	return claim
}

func unprepare(t *testing.T, p *dra.Plugin, uid string) error {
	t.Helper()
	res, err := p.UnprepareResourceClaims(context.Background(), []kubeletplugin.NamespacedObject{kubeletClaim(p, uid)})
	if err != nil {
		t.Fatal(err)
	}
	checkPool(t, p, "unprepared "+uid)
	return res[types.UID(uid)]
}

// checkPool fails the test on a violation of the invariants of the records
// of the pool driver and the kernel now: the document's (state.Check) and
// the engine's; and on a change of a kernel object that no row of its
// table has since the last check.
func checkPool(t *testing.T, p *dra.Plugin, what string) {
	t.Helper()
	snap, err := p.Engine().Observe(context.Background())
	noErr(t, err)
	for _, v := range p.Engine().Check(snap, []state.Source{state.SourcePool}, nil) {
		t.Errorf("%s: %s", what, v)
	}
	for _, line := range p.Engine().UnknownSeen() {
		t.Errorf("%s: %s%s", what, engine.UnknownTransition, line)
	}
}

func wantErr(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), substr) {
		t.Fatalf("expected an error with %q, got %v", substr, err)
	}
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// kernelAt returns the kernel of the node with its sysfs in root/sys.
func kernelAt(root string) *kernel.Kernel {
	k := kernel.New()
	k.SysRoot = filepath.Join(root, "sys")
	return k
}
