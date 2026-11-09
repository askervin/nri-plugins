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

package provenance

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

const (
	testNode = "node1"
	testNS   = "demo"
	// poolC is the pool of the ResourceSlice of the tests.
	poolC = device.PoolDriverName + "/pool-c"
	// localSerial is a local memdev, sharedPoolSerial c-shared0 of pool-c
	// (c-pooled0 is 0xc1ee2001), otherLocalSerial another local memdev.
	localSerial      = 0xc100e2e1
	sharedPoolSerial = 0xc1ae2001
	otherLocalSerial = 0xa1
)

// watchEnv is a node with memdevs, the ResourceSlices and ResourceClaims
// of a fake API server, a state store and the Watcher over them, scanned
// as the publisher does.
type watchEnv struct {
	t      *testing.T
	client *fake.Clientset
	dir    string
	st     *store.Store
	w      *Watcher
	// forget are the serials of --forget-pool-serial of the next restart.
	forget []uint64

	mu      sync.Mutex
	clock   time.Time
	devs    map[uint64]*nricxl.MemoryDevice // on the node
	plugged int
}

// newWatchEnv returns the env of a first start: an empty store.
func newWatchEnv(t *testing.T) *watchEnv {
	e := &watchEnv{
		t:      t,
		client: fake.NewClientset(),
		dir:    t.TempDir(),
		clock:  time.Date(2026, 10, 26, 9, 35, 0, 0, time.UTC),
		devs:   map[uint64]*nricxl.MemoryDevice{},
	}
	t.Cleanup(e.closeStore)
	e.restart()
	return e
}

// name is the name of the records in the log lines.
func (e *watchEnv) name() string {
	return filepath.Join(e.dir, "poolSerials.json")
}

// closeStore closes the store, writing its pending commits.
func (e *watchEnv) closeStore() {
	if e.st != nil {
		noErr(e.t, e.st.Close())
		e.st = nil
	}
}

// restart starts the driver again: the store reopened, a new Watcher.
func (e *watchEnv) restart() {
	e.t.Helper()
	e.closeStore()
	st, err := store.Open(context.Background(), store.Options{Dir: e.dir, BootID: "boot-1"})
	noErr(e.t, err)
	e.st = st
	list, claims := ClientLists(e.client, "")
	e.w = New(Options{Store: e.st, List: list, Claims: claims, NodeName: testNode, Name: e.name(), Forget: e.forget, Now: e.now})
}

// lose makes state.json content and removes state.json.prev, so that the
// store opens LOST at the restart.
func (e *watchEnv) lose(content string) {
	e.t.Helper()
	e.closeStore()
	noErr(e.t, os.WriteFile(filepath.Join(e.dir, store.FileName), []byte(content), 0o600))
	if err := os.Remove(filepath.Join(e.dir, store.PrevName)); err != nil && !os.IsNotExist(err) {
		e.t.Fatal(err)
	}
	e.restart()
	if e.st.Lost() == nil {
		e.t.Fatal("the store is not LOST")
	}
}

func (e *watchEnv) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

// advance moves the clock forward without a scan.
func (e *watchEnv) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clock = e.clock.Add(d)
}

// idle lets d pass with a scan every Poll, as the watch does on a node
// without udev events.
func (e *watchEnv) idle(d time.Duration) {
	e.t.Helper()
	for end := e.now().Add(d); e.now().Before(end); {
		e.advance(min(Poll, end.Sub(e.now())))
		e.scan()
	}
}

// publish makes pool-c publish devices with the serials; without serials
// it deletes its ResourceSlice as its graceful stop does.
func (e *watchEnv) publish(serials ...string) {
	e.t.Helper()
	ctx := context.Background()
	_ = e.client.ResourceV1().ResourceSlices().Delete(ctx, "pool-c", metav1.DeleteOptions{})
	if len(serials) == 0 {
		return
	}
	var attrs []map[resourcev1.QualifiedName]resourcev1.DeviceAttribute
	for _, s := range serials {
		attrs = append(attrs, serialAttr("serial", s))
	}
	_, err := e.client.ResourceV1().ResourceSlices().Create(ctx, slice("pool-c", device.PoolDriverName, attrs...), metav1.CreateOptions{})
	noErr(e.t, err)
}

// plug attaches a memdev with the serial to the node, unplug detaches it.
func (e *watchEnv) plug(serial uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.devs[serial] = &nricxl.MemoryDevice{Name: fmt.Sprintf("mem%d", e.plugged), DevName: fmt.Sprintf("cxl/mem%d", e.plugged),
		RamSize: 1 << 30, Serial: serial, NodeAffinity: 0, Enabled: true}
	e.plugged++
}

func (e *watchEnv) unplug(serial uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.devs, serial)
}

// devices returns the memdevs on the node.
func (e *watchEnv) devices() *nricxl.Devices {
	e.mu.Lock()
	defer e.mu.Unlock()
	devs := &nricxl.Devices{}
	for _, s := range slices.Sorted(maps.Keys(e.devs)) {
		devs.MemoryDevices = append(devs.MemoryDevices, e.devs[s])
	}
	return devs
}

// scan observes the node as a scan of the publisher does without a pool
// driver: the list of the pool slices, then the gate of the memdevs. It
// returns the serials of the held memdevs.
func (e *watchEnv) scan() []uint64 {
	e.t.Helper()
	ctx := context.Background()
	serials, _ := e.w.Serials(ctx)
	_, held := e.w.Gate(ctx, e.devices(), serials, nil)
	return slices.Sorted(maps.Keys(held))
}

// wantHeld scans and fails unless the held memdevs are the serials.
func (e *watchEnv) wantHeld(what string, want ...uint64) {
	e.t.Helper()
	if got := e.scan(); !slices.Equal(got, want) {
		e.t.Fatalf("%s: held %#x, expected %#x", what, got, want)
	}
}

// stateOf returns the state of the serial in the watcher, UNKNOWN for
// none.
func (e *watchEnv) stateOf(serial uint64) state.ProvenanceState {
	e.w.mu.Lock()
	defer e.w.mu.Unlock()
	if en := e.w.entries[serial]; en != nil {
		return en.rec.State
	}
	return state.ProvenanceUnknown
}

// wantState fails unless the serial is in the state.
func (e *watchEnv) wantState(serial uint64, want state.ProvenanceState) {
	e.t.Helper()
	if got := e.stateOf(serial); got != want {
		e.t.Fatalf("serial %#x: state %s, expected %s", serial, got, want)
	}
}

// flush waits until the lazy commits so far are written.
func (e *watchEnv) flush() {
	e.t.Helper()
	noErr(e.t, e.st.Commit(context.Background(), store.Durable, func(*store.Document) error { return nil }))
}

// records returns the Provenance records and the listed pools of the
// store once the commits so far are written.
func (e *watchEnv) records() ([]state.Provenance, []state.ListedPool) {
	e.t.Helper()
	e.flush()
	doc := e.st.Snapshot()
	return doc.Provenance, doc.ListedPools
}

// record returns the record of the serial in the store, nil for none.
func (e *watchEnv) record(serial uint64) *state.Provenance {
	e.t.Helper()
	recs, _ := e.records()
	for i := range recs {
		if uint64(recs[i].Serial) == serial {
			return &recs[i]
		}
	}
	return nil
}

// claim makes a pool claim of pool-c's device dev allocated to node, with
// the serial in its status ("" for none, "failed" for a failed attach).
func (e *watchEnv) claim(name, node, dev, serial string) {
	e.t.Helper()
	c := poolClaim(name, node, dev, serial)
	ctx := context.Background()
	claims := e.client.ResourceV1().ResourceClaims(testNS)
	_ = claims.Delete(ctx, name, metav1.DeleteOptions{})
	_, err := claims.Create(ctx, c, metav1.CreateOptions{})
	noErr(e.t, err)
}

// poolClaim returns a pool claim of pool-c's device dev allocated to node,
// with the serial in its status ("" for none, "failed" for a failed
// attach).
func poolClaim(name, node, dev, serial string) *resourcev1.ResourceClaim {
	r := resourcev1.DeviceRequestAllocationResult{Request: "mem", Driver: device.PoolDriverName, Pool: "pool-c", Device: dev}
	c := &resourcev1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS},
		Status: resourcev1.ResourceClaimStatus{
			Allocation: &resourcev1.AllocationResult{
				Devices: resourcev1.DeviceAllocationResult{Results: []resourcev1.DeviceRequestAllocationResult{r}},
				NodeSelector: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{node}}},
				}}},
			},
		},
	}
	st := resourcev1.AllocatedDeviceStatus{Driver: r.Driver, Pool: r.Pool, Device: r.Device}
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
	return c
}

// slice returns a ResourceSlice of the driver whose devices have the
// attributes.
func slice(name, driver string, attrs ...map[resourcev1.QualifiedName]resourcev1.DeviceAttribute) *resourcev1.ResourceSlice {
	rs := &resourcev1.ResourceSlice{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       resourcev1.ResourceSliceSpec{Driver: driver, Pool: resourcev1.ResourcePool{Name: name, ResourceSliceCount: 1}},
	}
	for i, a := range attrs {
		rs.Spec.Devices = append(rs.Spec.Devices, resourcev1.Device{Name: name + "-" + string(rune('a'+i)), Attributes: a})
	}
	return rs
}

// serialAttr returns the attributes of a device with the serial under key.
func serialAttr(key, serial string) map[resourcev1.QualifiedName]resourcev1.DeviceAttribute {
	return map[resourcev1.QualifiedName]resourcev1.DeviceAttribute{resourcev1.QualifiedName(key): {StringValue: &serial}}
}

// captureKlog makes klog write to a buffer at verbosity 4 for the test and
// returns a function that returns the output so far.
func captureKlog(t *testing.T) func() string {
	t.Helper()
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	noErr(t, fs.Set("logtostderr", "false"))
	noErr(t, fs.Set("alsologtostderr", "false"))
	noErr(t, fs.Set("v", "4"))
	// each line once, not also in the outputs of the lower severities
	noErr(t, fs.Set("one_output", "true"))
	var mu sync.Mutex
	var buf bytes.Buffer
	klog.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	t.Cleanup(func() {
		klog.Flush()
		_ = fs.Set("logtostderr", "true")
		_ = fs.Set("one_output", "false")
		_ = fs.Set("v", "0")
	})
	return func() string {
		klog.Flush()
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// wantLogLine fails the test unless a line of the log contains text.
func wantLogLine(t *testing.T, log, text string) {
	t.Helper()
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, text) {
			return
		}
	}
	t.Fatalf("no log line with %q:\n%s", text, log)
}

// countLogLines returns the number of lines of the log with text.
func countLogLines(log, text string) int {
	n := 0
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, text) {
			n++
		}
	}
	return n
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err error, text string) {
	t.Helper()
	if err == nil || err.Error() != text {
		t.Fatalf("error %v, expected %q", err, text)
	}
}
