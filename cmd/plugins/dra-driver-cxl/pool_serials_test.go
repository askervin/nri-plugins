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
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// The serials of bug-09 (plan-13 run L6): c-shared0 of pool-c (c-pooled0
// is 0xc1ee2001), and a local memdev other than that of the e2e VMs
// (localSerial).
const (
	sharedPoolSerial = 0xc1ae2001
	otherLocalSerial = 0xa1
)

// serialsEnv is a node with memdevs, the ResourceSlices and
// ResourceClaims of a fake API server and the driver's poolSlices, scanned
// as rescanAndPublish does.
type serialsEnv struct {
	t       *testing.T
	client  *fake.Clientset
	file    string
	mu      sync.Mutex
	clock   time.Time
	ps      *poolSlices
	devs    map[uint64]*nricxl.MemoryDevice // on the node
	regions map[uint64]bool                 // memdevs with a region
	plugged int
	local   *localSnapshot
}

func newSerialsEnv(t *testing.T) *serialsEnv {
	e := &serialsEnv{
		t:       t,
		client:  fake.NewClientset(),
		file:    filepath.Join(t.TempDir(), poolSerialsFileName),
		clock:   time.Date(2026, 10, 26, 9, 35, 0, 0, time.UTC),
		devs:    map[uint64]*nricxl.MemoryDevice{},
		regions: map[uint64]bool{},
		local:   &localSnapshot{BlockSize: localBlockSize},
	}
	e.restart()
	return e
}

// restart starts the driver again: a new poolSlices from the file.
func (e *serialsEnv) restart() {
	e.ps = newPoolSlices(e.client, testNode, "", e.file)
	e.ps.now = e.now
}

func (e *serialsEnv) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

// advance moves the clock forward without a scan.
func (e *serialsEnv) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clock = e.clock.Add(d)
}

// idle lets d pass with a scan every poolSlicesPoll, as the pool watch
// does on a node without udev events.
func (e *serialsEnv) idle(d time.Duration) {
	e.t.Helper()
	for end := e.now().Add(d); e.now().Before(end); {
		e.advance(min(poolSlicesPoll, end.Sub(e.now())))
		e.scan()
	}
}

// publish makes pool-c publish devices with the serials, unpublish (no
// serials) deletes its ResourceSlice as its graceful stop does.
func (e *serialsEnv) publish(serials ...string) {
	e.t.Helper()
	ctx := context.Background()
	_ = e.client.ResourceV1().ResourceSlices().Delete(ctx, "pool-c", metav1.DeleteOptions{})
	if len(serials) == 0 {
		return
	}
	var attrs []map[resourceapi.QualifiedName]resourceapi.DeviceAttribute
	for _, s := range serials {
		attrs = append(attrs, serialAttr("serial", s))
	}
	_, err := e.client.ResourceV1().ResourceSlices().Create(ctx, slice("pool-c", device.PoolDriverName, attrs...), metav1.CreateOptions{})
	noErr(e.t, err)
}

// plug attaches a memdev with the serial to the node, unplug detaches it.
func (e *serialsEnv) plug(serial uint64) {
	m := localMemdev()
	m.Serial = serial
	m.Name = fmt.Sprintf("mem%d", e.plugged)
	e.plugged++
	e.devs[serial] = m
}

func (e *serialsEnv) unplug(serial uint64) { delete(e.devs, serial) }

// devices returns the devices on the node: the memdevs, and region<N> of
// node 2+N on the memdevs with a region.
func (e *serialsEnv) devices() *nricxl.Devices {
	devs := &nricxl.Devices{}
	for _, s := range slices.Sorted(maps.Keys(e.devs)) {
		m := e.devs[s]
		devs.MemoryDevices = append(devs.MemoryDevices, m)
		if e.regions[s] {
			n := len(devs.RegionDevices)
			devs.RegionDevices = append(devs.RegionDevices, &nricxl.RegionDevice{
				Name: fmt.Sprintf("region%d", n), Size: 1 << 30, Mode: "ram", Node: 2 + n, Enabled: true, Memories: []*nricxl.MemoryDevice{m},
			})
		}
	}
	return devs
}

// scan returns the memdev devices that a rescan publishes.
func (e *serialsEnv) scan() []string {
	e.t.Helper()
	cfg := &DriverConfig{IgnoreDRAMNodes: true}
	ctx := context.Background()
	scanConfig, serials := scanInput(ctx, cfg, nil, e.ps)
	infos, err := scanDetected(ctx, scanConfig, e.devices(), serials, e.ps, e.local)
	noErr(e.t, err)
	return slices.Sorted(maps.Keys(infos))
}

// claim makes a pool claim of pool-c's device dev allocated to node, with
// the serial in its status ("" for none, "failed" for a failed attach).
func (e *serialsEnv) claim(name, node, dev, serial string) {
	e.t.Helper()
	r := resourceapi.DeviceRequestAllocationResult{Request: "mem", Driver: device.PoolDriverName, Pool: "pool-c", Device: dev}
	c := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS},
		Status: resourceapi.ResourceClaimStatus{
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{Results: []resourceapi.DeviceRequestAllocationResult{r}},
				NodeSelector: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{node}}},
				}}},
			},
		},
	}
	st := resourceapi.AllocatedDeviceStatus{Driver: r.Driver, Pool: r.Pool, Device: r.Device}
	switch serial {
	case "":
	case "failed":
		st.Conditions = []metav1.Condition{{Type: device.PoolDriverName + "/AttachFailed", Status: metav1.ConditionTrue, Reason: "NoHost"}}
		c.Status.Devices = append(c.Status.Devices, st)
	default:
		st.Conditions = []metav1.Condition{{Type: device.PoolDriverName + "/Attached", Status: metav1.ConditionTrue, Reason: "Attached"}}
		st.Data = &runtime.RawExtension{Raw: []byte(`{"serial":"` + serial + `","shared":true,"size":268435456}`)}
		c.Status.Devices = append(c.Status.Devices, st)
	}
	ctx := context.Background()
	claims := e.client.ResourceV1().ResourceClaims(testNS)
	_ = claims.Delete(ctx, name, metav1.DeleteOptions{})
	_, err := claims.Create(ctx, c, metav1.CreateOptions{})
	noErr(e.t, err)
}

func (e *serialsEnv) wantScan(what string, want ...string) {
	e.t.Helper()
	if got := e.scan(); !slices.Equal(got, want) {
		e.t.Fatalf("%s: published %v, expected %v", what, got, want)
	}
}

// The sequence of bug-09: a shared pool device is in pool-c's slice and is
// attached to the node for a claim that is not prepared; pool-c's
// controller stops gracefully and deletes its slice; a rescan, and a
// driver restart while the slice is absent, must not publish it.
func TestPoolSerialsSliceDeleted(t *testing.T) {
	e := newSerialsEnv(t)
	e.plug(localSerial)
	e.publish("0xc1ee2001", "0xc1ae2001")
	e.wantScan("local device", localDeviceName)
	e.plug(sharedPoolSerial)
	e.wantScan("pool device attached", localDeviceName)
	e.publish()
	e.wantScan("slice deleted", localDeviceName)
	e.restart()
	e.wantScan("driver restarted without the slice", localDeviceName)
	if e.ps.Holding() {
		t.Fatal("a remembered pool device is held back as a new memdev")
	}
	// the file has the pool serials and the local memdev
	data, err := os.ReadFile(e.file)
	noErr(t, err)
	var f poolSerialsFile
	noErr(t, json.Unmarshal(data, &f))
	got := map[string]bool{}
	for _, r := range f.Serials {
		got[r.Serial] = r.Local
	}
	if !maps.Equal(got, map[string]bool{"0xc100e2e1": true, "0xc1ae2001": false, "0xc1ee2001": false}) || f.Pools[device.PoolDriverName+"/pool-c"].IsZero() {
		t.Fatalf("file %s", data)
	}
	// the controller is back
	e.publish("0xc1ee2001", "0xc1ae2001")
	e.wantScan("slice back", localDeviceName)
}

// As in run L6: the pool device is detached while the slice lists it, the
// slice is deleted and the device is attached again (hot-add) before the
// controller publishes again.
func TestPoolSerialsHotAddWhileSliceDeleted(t *testing.T) {
	e := newSerialsEnv(t)
	e.plug(localSerial)
	e.plug(sharedPoolSerial)
	e.publish("0xc1ee2001", "0xc1ae2001")
	e.wantScan("pool device attached", localDeviceName)
	e.unplug(sharedPoolSerial)
	e.wantScan("pool device detached", localDeviceName)
	e.publish()
	e.advance(13 * time.Second)
	e.plug(sharedPoolSerial)
	e.wantScan("pool device attached without the slice", localDeviceName)
	e.advance(3 * time.Minute)
	e.wantScan("3 minutes later", localDeviceName)
	e.restart()
	e.wantScan("driver restarted", localDeviceName)
}

// A pool device whose serial the driver never saw in a slice (the slice
// was published and deleted between two scans) is attached while pool-c
// has no slice: it is held back, and is a pool device once pool-c lists
// it.
func TestPoolSerialsNewMemdevHeldBack(t *testing.T) {
	e := newSerialsEnv(t)
	e.plug(localSerial)
	e.publish("0xc1ee2001")
	e.wantScan("local device", localDeviceName)
	e.publish()
	e.plug(sharedPoolSerial)
	e.wantScan("new memdev while pool-c is missing", localDeviceName)
	if !e.ps.Holding() {
		t.Fatal("the new memdev is not held back")
	}
	e.advance(newMemdevHoldBack / 2)
	e.wantScan("half the hold back time later", localDeviceName)
	e.publish("0xc1ee2001", "0xc1ae2001")
	e.wantScan("pool-c lists it", localDeviceName)
	if e.ps.Holding() {
		t.Fatal("a pool device is held back")
	}
	e.publish()
	e.advance(2 * newMemdevHoldBack)
	e.wantScan("pool-c missing again", localDeviceName)
}

// A new memdev that is held back while a pool is missing is published as
// a local one after newMemdevHoldBack, and at once when the pool is back
// without it.
func TestPoolSerialsHoldBackEnds(t *testing.T) {
	e := newSerialsEnv(t)
	e.publish("0xc1ee2001")
	e.wantScan("no memdevs")
	e.publish()
	e.plug(localSerial)
	e.wantScan("held back")
	e.advance(newMemdevHoldBack)
	e.wantScan("after the hold back time", localDeviceName)
	if e.ps.Holding() {
		t.Fatal("still holding")
	}
	// another new memdev, and pool-c comes back without it
	e.plug(otherLocalSerial)
	e.wantScan("second new memdev held back", localDeviceName)
	e.publish("0xc1ee2001")
	e.wantScan("pool-c back", "memdev-a1", localDeviceName)
	// a pool observed missing for longer than poolMissingWindow holds
	// back nothing
	e.publish()
	e.unplug(otherLocalSerial)
	e.wantScan("detached", localDeviceName)
	e.idle(poolMissingWindow + time.Minute)
	e.plug(0xa2)
	e.wantScan("pool-c gone for long", "memdev-a2", localDeviceName)
	// but only when its absence was observed: after a driver restart it
	// starts again
	e.restart()
	e.plug(0xa3)
	e.wantScan("pool-c gone for long, restarted", "memdev-a2", localDeviceName)
	if !e.ps.Holding() {
		t.Fatal("not holding after the restart")
	}
}

// The local memdev of the e2e VMs is hot-added while every pool has its
// slices and was never in a pool slice: it is published at once, also
// after a restart while the pool slices are absent.
func TestPoolSerialsLocalDevice(t *testing.T) {
	e := newSerialsEnv(t)
	e.wantScan("no memdevs, no pools")
	e.plug(localSerial)
	e.wantScan("first run, no pools", localDeviceName)
	e.publish("0xc1ee2001")
	e.unplug(localSerial)
	e.wantScan("detached")
	e.plug(localSerial)
	e.wantScan("attached again", localDeviceName)
	e.publish()
	e.restart()
	e.wantScan("restart without the pool slices", localDeviceName)
	e.unplug(localSerial)
	e.wantScan("detached without the pool slices")
	e.plug(localSerial)
	e.wantScan("attached again without the pool slices", localDeviceName)
}

// A pool device is detached; later a genuinely local device with another
// serial is attached. The pool serial is forgotten after
// poolSerialRetention without being seen.
func TestPoolSerialsPoolDeviceRemoved(t *testing.T) {
	e := newSerialsEnv(t)
	e.publish("0xc1ee2001", "0xc1ae2001")
	e.plug(sharedPoolSerial)
	e.wantScan("pool device attached")
	e.unplug(sharedPoolSerial)
	e.wantScan("pool device detached")
	e.plug(otherLocalSerial)
	e.wantScan("local device attached", "memdev-a1")
	// the controller stops: the pool device stays a pool device
	e.publish()
	e.plug(sharedPoolSerial)
	e.wantScan("pool device attached without the slice", "memdev-a1")
	e.unplug(sharedPoolSerial)
	// a day without a scan, then one scan: its absence was not observed
	e.advance(poolSerialRetention + time.Hour)
	e.wantScan("a day later", "memdev-a1")
	if _, ok := e.ps.records[sharedPoolSerial]; !ok {
		t.Fatal("pool serial forgotten without observing its absence")
	}
	// a day of scans
	e.idle(poolSerialRetention + time.Hour)
	e.wantScan("a day of observed absence later", "memdev-a1")
	if _, ok := e.ps.records[sharedPoolSerial]; ok {
		t.Fatal("pool serial not forgotten")
	}
	if _, ok := e.ps.records[otherLocalSerial]; !ok {
		t.Fatal("present local memdev forgotten")
	}
}

// A memdev that the local allocator uses is local, also when it is new
// while a pool is missing (a restart with a lost file).
func TestPoolSerialsLocalAllocatorUses(t *testing.T) {
	e := newSerialsEnv(t)
	e.publish("0xc1ee2001")
	e.wantScan("no memdevs")
	e.publish()
	e.plug(localSerial)
	e.local.Uses = map[uint64]localUse{localSerial: {}}
	e.wantScan("used by the local allocator", localDeviceName)
}

// The memdevs that the pool driver prepares are remembered as pool
// serials.
func TestPoolSerialsPrepared(t *testing.T) {
	e := newSerialsEnv(t)
	e.publish("0xc1ee2001")
	e.plug(localSerial)
	e.wantScan("local", localDeviceName)
	// once prepared, the local memdev's serial is a pool device's
	e.ps.NotePrepared(map[uint64]bool{localSerial: true})
	e.wantScan("prepared")
	e.restart()
	e.wantScan("restarted")
}

// A file that cannot be parsed has lost the remembered serials: a new
// memdev is held back as while a pool is missing, for poolMissingWindow
// (review DRV2 E4). The next write replaces the file.
func TestPoolSerialsBadFile(t *testing.T) {
	e := newSerialsEnv(t)
	noErr(t, os.WriteFile(e.file, []byte("{bogus"), 0o600))
	e.restart()
	e.plug(localSerial)
	e.wantScan("bad file")
	e.advance(newMemdevHoldBack)
	e.wantScan("bad file, held back for long enough", localDeviceName)
	e.idle(poolMissingWindow)
	e.plug(otherLocalSerial)
	e.wantScan("an hour later", "memdev-a1", localDeviceName)
	data, err := os.ReadFile(e.file)
	noErr(t, err)
	var f poolSerialsFile
	noErr(t, json.Unmarshal(data, &f))
}

// R5 of review DRV2: the file is truncated (a power loss before the
// write was durable, which writeJSONFile now prevents) while pool-c's
// slices are gone: the pool device is not published at once; neither is
// the local memdev, which is new again.
func TestPoolSerialsTruncatedFile(t *testing.T) {
	e := newSerialsEnv(t)
	e.plug(localSerial)
	e.publish("0xc1ee2001", "0xc1ae2001")
	e.wantScan("local", localDeviceName)
	e.publish()
	noErr(t, os.WriteFile(e.file, nil, 0o600))
	e.restart()
	e.plug(sharedPoolSerial)
	e.wantScan("truncated file, controller down")
	if !e.ps.Holding() {
		t.Fatal("not holding")
	}
}

// R3 of review DRV2: a hand-edited file with a null record is loaded
// without it.
func TestPoolSerialsNullRecord(t *testing.T) {
	e := newSerialsEnv(t)
	noErr(t, os.WriteFile(e.file, []byte(`{"serials":[null,{"serial":"0xc1ae2001","seen":"2026-10-26T09:00:00Z"}]}`), 0o600))
	e.restart()
	if len(e.ps.records) != 1 || e.ps.records[sharedPoolSerial] == nil || e.ps.lost != "" {
		t.Fatalf("records %v lost %q", e.ps.records, e.ps.lost)
	}
	e.plug(sharedPoolSerial)
	e.wantScan("pool serial of the file")
}

// R1 of review DRV2: pool-c was listed at the last scan 2 h ago, the node
// had no udev event since, and a pool device that the node never saw in a
// slice is attached while pool-c's slices are gone. Its absence is
// observed from that scan on: the new memdev is held back.
func TestPoolSerialsQuietNodeWindow(t *testing.T) {
	e := newSerialsEnv(t)
	e.plug(localSerial)
	e.publish("0xc1ee2001")
	e.wantScan("local", localDeviceName)
	e.advance(2 * time.Hour)
	e.publish()
	e.plug(sharedPoolSerial)
	e.wantScan("never-listed pool device on a quiet node", localDeviceName)
	if !e.ps.Holding() {
		t.Fatal("not holding")
	}
	// with the pool watch, an hour of observed absence holds back nothing
	e.unplug(sharedPoolSerial)
	e.idle(poolMissingWindow + time.Minute)
	e.plug(otherLocalSerial)
	e.wantScan("after an hour of observed absence", "memdev-a1", localDeviceName)
}

// R2 of review DRV2: a pool serial listed at a scan 25 h ago, no scan
// since; the controller stops gracefully, an unrelated rescan runs, and
// the device is attached: it is still a pool serial.
func TestPoolSerialsQuietNodeForget(t *testing.T) {
	e := newSerialsEnv(t)
	e.plug(localSerial)
	e.publish("0xc1ee2001", "0xc1ae2001")
	e.wantScan("local", localDeviceName)
	e.advance(25 * time.Hour)
	e.publish()
	e.wantScan("unrelated udev scan", localDeviceName)
	e.advance(time.Second)
	e.plug(sharedPoolSerial)
	e.wantScan("pool device attached", localDeviceName)
	if e.ps.Holding() {
		t.Fatal("a remembered pool serial is held back")
	}
}

// R7 of review DRV2: an established local memdev that a pool slice lists
// later is a pool device from then on, also after the slice is gone.
func TestPoolSerialsLocalBecomesPool(t *testing.T) {
	e := newSerialsEnv(t)
	e.plug(localSerial)
	e.wantScan("local", localDeviceName)
	e.publish("0xc100e2e1")
	e.wantScan("listed by pool-c")
	e.publish()
	e.wantScan("slice gone")
	e.restart()
	e.wantScan("restarted")
}

// A first start without the file while pool-c's controller is down (no
// pool known): the status of the pool claims of the node tells pool
// devices, and a pool claim of the node that is not attached yet holds
// back new memdevs for as long as it is not (review DRV2 E5).
func TestPoolSerialsClaimEvidence(t *testing.T) {
	e := newSerialsEnv(t)
	e.claim("attached", testNode, "c-shared0", "0xc1ae2001")
	e.claim("failed", testNode, "c-pooled1", "failed")
	e.claim("elsewhere", "node2", "c-pooled2", "")
	e.plug(localSerial)
	e.plug(sharedPoolSerial)
	e.wantScan("first start", localDeviceName)
	if r := e.ps.records[sharedPoolSerial]; r == nil || r.Local || r.Pool != device.PoolDriverName+"/pool-c" {
		t.Fatalf("record %+v", r)
	}
	// a claim of the node is being attached: a new memdev waits for it
	e.claim("attaching", testNode, "c-pooled0", "")
	e.plug(otherLocalSerial)
	e.wantScan("attach in flight", localDeviceName)
	e.advance(2 * newMemdevHoldBack)
	e.wantScan("attach in flight, later", localDeviceName)
	// its status tells another serial
	e.claim("attaching", testNode, "c-pooled0", "0xc1ee2001")
	e.wantScan("attached", "memdev-a1", localDeviceName)
	// or it tells this one
	e.claim("attaching2", testNode, "c-pooled3", "")
	e.plug(0xc1ee2003)
	e.wantScan("second attach in flight", "memdev-a1", localDeviceName)
	e.claim("attaching2", testNode, "c-pooled3", "0xc1ee2003")
	e.wantScan("second attached", "memdev-a1", localDeviceName)
	if e.ps.Holding() || e.ps.records[0xc1ee2003].Local {
		t.Fatalf("holding %v record %+v", e.ps.Holding(), e.ps.records[0xc1ee2003])
	}
}

// While no list of the pool slices has succeeded, a new memdev is held
// back without the hold-back time running: it counts from the first
// successful list on (review DRV2 E6).
func TestPoolSerialsHoldWhileNotListed(t *testing.T) {
	e := newSerialsEnv(t)
	e.publish("0xc1ee2001")
	e.wantScan("pool-c listed")
	e.publish()
	fail := true
	e.client.PrependReactor("list", "resourceslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		if fail {
			return true, nil, errors.New("apiserver unavailable")
		}
		return false, nil, nil
	})
	e.restart()
	e.plug(localSerial)
	e.wantScan("not listed")
	e.advance(2 * newMemdevHoldBack)
	e.wantScan("not listed, later")
	if !e.ps.Holding() {
		t.Fatal("not holding")
	}
	fail = false
	e.wantScan("listed, pool-c missing")
	e.advance(newMemdevHoldBack)
	e.wantScan("held back for long enough", localDeviceName)
}

// The regions of a memdev that is held back are not published either, and
// the reason is not "pool device" (review DRV2 E8).
func TestPoolSerialsHeldRegion(t *testing.T) {
	e := newSerialsEnv(t)
	e.publish("0xc1ee2001")
	e.wantScan("no memdevs")
	e.publish()
	e.plug(otherLocalSerial)
	e.regions[otherLocalSerial] = true
	e.wantScan("held back")
	devs := e.devices()
	if r := poolIgnoreReason(devs.RegionDevices[0], nil, map[uint64]bool{otherLocalSerial: true}); !strings.Contains(r, "held back") {
		t.Fatalf("reason %q", r)
	}
	e.advance(newMemdevHoldBack)
	e.wantScan("published", "region0-node2")
}

// CheckLocal refuses a remembered pool serial, a serial of a current pool
// slice and a held memdev; the local allocator checks it before it uses a
// memdev (review DRV2 E2).
func TestPoolSerialsCheckLocal(t *testing.T) {
	e := newSerialsEnv(t)
	ctx := context.Background()
	e.plug(localSerial)
	e.publish("0xc1ee2001")
	e.wantScan("local", localDeviceName)
	noErr(t, e.ps.CheckLocal(ctx, localSerial))
	// pool-c lists it now, before any rescan
	e.publish("0xc1ee2001", "0xc100e2e1")
	if err := e.ps.CheckLocal(ctx, localSerial); err == nil || !strings.Contains(err.Error(), "memory device serial 0xc100e2e1 is a pool device of "+device.PoolDriverName+"/pool-c") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	e.publish()
	if err := e.ps.CheckLocal(ctx, localSerial); err == nil {
		t.Fatal("a remembered pool serial accepted")
	}
	e.plug(otherLocalSerial)
	e.wantScan("held")
	if err := e.ps.CheckLocal(ctx, otherLocalSerial); err == nil || !strings.Contains(err.Error(), "held back") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if err := (*poolSlices)(nil).CheckLocal(ctx, localSerial); err != nil {
		t.Fatal(err)
	}
}

// driver returns a driver that rescans the memdevs of e (not
// started: it does not publish).
func (e *serialsEnv) driver(detect func(string) (*nricxl.Devices, error)) *driver {
	e.t.Helper()
	old := detectDevices
	detectDevices = detect
	e.t.Cleanup(func() { detectDevices = old })
	local := newFakeLocalSys(e.t).allocator(e.t, e.t.TempDir())
	return &driver{
		sysfsRoot:  e.t.TempDir(),
		config:     &DriverConfig{IgnoreDRAMNodes: true},
		state:      nodeState{baseState: &baseState{NodeName: testNode}, local: local},
		poolSlices: e.ps,
	}
}

// allocatableNames returns the names of the devices that d would publish.
func (d *driver) allocatableNames() []string {
	d.state.Lock()
	defer d.state.Unlock()
	devs, _ := d.state.Allocatable.(device.DevicesInfo)
	return slices.Sorted(maps.Keys(devs))
}

// Two rescans (an udev event and a tick of the pool watch) never run at
// the same time: the later one stores and publishes last (R8 of review
// DRV2: a rescan that took a memdev as local at the end of its hold-back
// stored its result after a rescan that had found it in the returning
// pool slice).
func TestRescanSerialized(t *testing.T) {
	e := newSerialsEnv(t)
	e.plug(localSerial)
	devs := e.devices()
	entered := make(chan int32, 2)
	release := make(chan struct{})
	var n atomic.Int32
	d := e.driver(func(string) (*nricxl.Devices, error) {
		i := n.Add(1)
		entered <- i
		if i == 1 {
			<-release
		}
		return devs, nil
	})
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); d.rescanAndPublish(ctx) }()
	<-entered
	go func() { defer wg.Done(); d.rescan(ctx, true) }()
	select {
	case i := <-entered:
		t.Errorf("rescan %d ran while rescan 1 was running", i)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if n.Load() != 2 || !slices.Equal(d.allocatableNames(), []string{localDeviceName}) {
		t.Fatalf("%d rescans, devices %v", n.Load(), d.allocatableNames())
	}
}

// The pool watch rescans while a memdev is held back, and also without
// udev events every poolSlicesPoll: a local memdev that a returning pool
// slice lists is withdrawn (review DRV2 E1, E2).
func TestPoolWatch(t *testing.T) {
	oldRetry, oldPoll := poolListRetry, poolSlicesPoll
	t.Cleanup(func() { poolListRetry, poolSlicesPoll = oldRetry, oldPoll })
	e := newSerialsEnv(t)
	e.plug(localSerial)
	e.publish("0xc1ee2001")
	e.wantScan("local", localDeviceName)
	e.publish()
	e.plug(otherLocalSerial)
	var mu sync.Mutex
	devs := e.devices()
	d := e.driver(func(string) (*nricxl.Devices, error) {
		mu.Lock()
		defer mu.Unlock()
		return devs, nil
	})
	ctx := context.Background()
	d.rescanAndPublish(ctx)
	if got := d.allocatableNames(); !slices.Equal(got, []string{localDeviceName}) {
		t.Fatalf("devices %v", got)
	}
	watch := func(want ...string) {
		t.Helper()
		ctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); d.poolWatch(ctx) }()
		defer func() { cancel(); <-done }()
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			if slices.Equal(d.allocatableNames(), want) {
				return
			}
		}
		t.Fatalf("devices %v, expected %v", d.allocatableNames(), want)
	}
	// held back: the ticks rescan, it is published after the hold-back
	poolListRetry, poolSlicesPoll = 5*time.Millisecond, time.Hour
	e.advance(newMemdevHoldBack)
	watch("memdev-a1", localDeviceName)
	// pool-c is back and lists the local memdev: a periodic rescan
	// withdraws it
	poolSlicesPoll = 20 * time.Millisecond
	e.publish("0xc1ee2001", "0xc100e2e1")
	watch("memdev-a1")
}

// The local allocator refuses a pool device before it creates a region on
// it or onlines its memory: a local claim allocated on a memdev that a
// pool slice lists by now fails (review DRV2 E2).
func TestPrepareLocalPoolDevice(t *testing.T) {
	e := newLocalTestState(t)
	env := newSerialsEnv(t)
	env.publish("0xc1ee2001", "0xc100e2e1")
	e.local.poolGuard = localPoolGuard(nil, env.ps)
	ctx := context.Background()
	err := e.Prepare(ctx, localClaim("u1", 64*mib))
	if err == nil || !strings.Contains(err.Error(), "memory device serial 0xc100e2e1 is a pool device of "+device.PoolDriverName+"/pool-c: it is not used as a local memory device") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if _, err := e.local.AcquireShared(ctx, "u2", "mem", localSerial, false, "exclusive"); err == nil || !strings.Contains(err.Error(), "is a pool device") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if e.inUse() || strings.Contains(e.f.commands(), "create-region") {
		t.Fatalf("the pool device was used:\n%s", e.f.commands())
	}
	// not listed: prepared
	env.publish("0xc1ee2001")
	env.ps = newPoolSlices(env.client, testNode, "", "")
	e.local.poolGuard = localPoolGuard(nil, env.ps)
	noErr(t, e.Prepare(ctx, localClaim("u1", 64*mib)))
}
