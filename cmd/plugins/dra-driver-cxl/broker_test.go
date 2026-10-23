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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	"tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
)

// fakeLender is a nodeLender with a fixed container table.
type fakeLender struct {
	mu      sync.Mutex
	byPid   *containerRef               // returned for any pid, nil: unknown
	ctrs    map[string]*containerRef    // podUID/name
	lent    map[string]map[int][]string // podUID/name -> node -> holders
	calls   []string
	lendErr error
	gone    []func(containerRef)
	started []func(containerRef)
}

func newFakeLender(refs ...containerRef) *fakeLender {
	f := &fakeLender{ctrs: map[string]*containerRef{}, lent: map[string]map[int][]string{}}
	for i := range refs {
		r := refs[i]
		f.ctrs[r.PodUID+"/"+r.Name] = &r
	}
	if len(refs) > 0 {
		r := refs[0]
		f.byPid = &r
	}
	return f
}

func (f *fakeLender) ContainerByPid(pid int) (*containerRef, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.byPid == nil {
		return nil, false
	}
	r := *f.byPid
	return &r, true
}

func (f *fakeLender) Container(podUID, name string) (*containerRef, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.ctrs[podUID+"/"+name]
	if !ok {
		return nil, false
	}
	c := *r
	return &c, true
}

func (f *fakeLender) LendNode(ctx context.Context, podUID, name string, node int, holder string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("lend %s/%s %d", podUID, name, node))
	if f.lendErr != nil {
		return f.lendErr
	}
	k := podUID + "/" + name
	if f.lent[k] == nil {
		f.lent[k] = map[int][]string{}
	}
	if !slices.Contains(f.lent[k][node], holder) {
		f.lent[k][node] = append(f.lent[k][node], holder)
	}
	return nil
}

func (f *fakeLender) RevokeNode(ctx context.Context, podUID, name string, node int, holder string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("revoke %s/%s %d", podUID, name, node))
	k := podUID + "/" + name
	if h := slices.DeleteFunc(f.lent[k][node], func(s string) bool { return s == holder }); len(h) > 0 {
		f.lent[k][node] = h
	} else {
		delete(f.lent[k], node)
	}
	return nil
}

func (f *fakeLender) LentNodes(podUID, name string) []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	var nodes []int
	for n := range f.lent[podUID+"/"+name] {
		nodes = append(nodes, n)
	}
	slices.Sort(nodes)
	return nodes
}

// holders returns the holders of a node lent to a container.
func (f *fakeLender) holders(podUID, name string, node int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.lent[podUID+"/"+name][node])
}

func (f *fakeLender) OnContainerGone(fn func(ref containerRef)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gone = append(f.gone, fn)
}

func (f *fakeLender) OnContainerStarted(fn func(ref containerRef)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, fn)
}

func (f *fakeLender) callLog() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

func (f *fakeLender) setPeer(r *containerRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byPid = r
}

func (f *fakeLender) remove(podUID, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ctrs, podUID+"/"+name)
}

var _ nodeLender = (*fakeLender)(nil)

const (
	testNode          = "node1"
	testNS            = "demo"
	testPod           = "borrower"
	testPodUID        = "pod-uid-1"
	testCtr           = "app"
	testLeaseClaimUID = "lc1"
)

var testRef = containerRef{PodUID: testPodUID, PodNamespace: testNS, PodName: testPod, Name: testCtr, ID: "c1", Pid: 42}

type brokerEnv struct {
	t      *testing.T
	dir    string
	cdiDir string
	cli    string
	client *fake.Clientset
	lender *fakeLender
	b      *broker
	mounts func() ([]mountInfo, error) // brokerConfig.Mounts of restart
}

func requesterPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: testPod, Namespace: testNS, UID: types.UID(testPodUID)},
		Spec:       corev1.PodSpec{RestartPolicy: corev1.RestartPolicyAlways, NodeName: testNode},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// leaseClaimObj is a prepared claim on the lease device of the requester
// pod.
func leaseClaimObj() *resourceapi.ResourceClaim {
	return &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "lease", Namespace: testNS, UID: types.UID(testLeaseClaimUID)},
		Status: resourceapi.ResourceClaimStatus{
			Allocation: &resourceapi.AllocationResult{Devices: resourceapi.DeviceAllocationResult{
				Results: []resourceapi.DeviceRequestAllocationResult{{Request: "lease", Driver: device.DriverName, Pool: testNode, Device: device.LeaseDeviceName}},
			}},
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{{Resource: "pods", Name: testPod, UID: types.UID(testPodUID)}},
		},
	}
}

func newBrokerEnv(t *testing.T) *brokerEnv {
	t.Helper()
	dir, err := os.MkdirTemp("", "lease")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e := &brokerEnv{
		t:      t,
		dir:    filepath.Join(dir, "cxl.nri.io"),
		cdiDir: filepath.Join(dir, "cdi"),
		cli:    filepath.Join(dir, "cxl-request"),
		client: fake.NewClientset(requesterPod(), leaseClaimObj()),
		lender: newFakeLender(testRef),
	}
	noErr(t, os.MkdirAll(e.cdiDir, 0o755))
	noErr(t, os.WriteFile(e.cli, []byte("#!/bin/true\n"), 0o755))
	e.restart()
	return e
}

// restart creates a new broker on the same data directory, as after a
// plugin restart.
func (e *brokerEnv) restart() {
	e.t.Helper()
	if e.b != nil {
		e.b.stop()
	}
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(e.cdiDir), cdiapi.WithAutoRefresh(false))
	noErr(e.t, err)
	b, err := newBroker(brokerConfig{
		Client:      e.client,
		NodeName:    testNode,
		DataDir:     e.dir,
		CDI:         cache,
		CLI:         e.cli,
		WaitDefault: 5 * time.Second,
		PoolDriver:  device.PoolDriverName,
		Mounts:      e.mounts,
	})
	noErr(e.t, err)
	b.pollInterval = 5 * time.Millisecond
	b.reconcileEvery = time.Hour // the tests call reconcile()
	b.closeTimeout = 2 * time.Second
	n := 0
	b.newID = func() string { n++; return fmt.Sprintf("%08x", 0xa0+n) }
	e.b = b
	e.t.Cleanup(b.stop)
}

func (e *brokerEnv) start() {
	e.b.start(e.lender)
}

func (e *brokerEnv) sock() string {
	return filepath.Join(e.dir, leaseDirName, testLeaseClaimUID, leaseSocketName)
}

// call sends one request and returns the response and the received fd
// (-1 for none).
func (e *brokerEnv) call(req api.Request) (api.Response, int) {
	e.t.Helper()
	data, _ := json.Marshal(req)
	return e.callRaw(string(data))
}

// callRaw sends one request line and returns the response and the
// received fd (-1 for none).
func (e *brokerEnv) callRaw(req string) (api.Response, int) {
	e.t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: e.sock(), Net: "unix"})
	noErr(e.t, err)
	defer func() { _ = c.Close() }()
	_, err = c.Write([]byte(req + "\n"))
	noErr(e.t, err)
	buf := make([]byte, 64*1024)
	oob := make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	noErr(e.t, err)
	fd := -1
	if oobn > 0 {
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		noErr(e.t, err)
		fds, err := syscall.ParseUnixRights(&msgs[0])
		noErr(e.t, err)
		fd = fds[0]
	}
	line := buf[:n]
	if !strings.Contains(string(line), "\n") {
		rest, err := bufio.NewReader(c).ReadBytes('\n')
		noErr(e.t, err)
		line = append(line, rest...)
	}
	var resp api.Response
	noErr(e.t, json.Unmarshal(line, &resp))
	return resp, fd
}

// async runs call in the background.
func (e *brokerEnv) async(req api.Request) chan api.Response {
	ch := make(chan api.Response, 1)
	go func() {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: e.sock(), Net: "unix"})
		if err != nil {
			ch <- api.Response{Error: err.Error()}
			return
		}
		defer func() { _ = c.Close() }()
		data, _ := json.Marshal(req)
		_, _ = c.Write(append(data, '\n'))
		line, err := bufio.NewReader(c).ReadBytes('\n')
		var resp api.Response
		if err == nil {
			err = json.Unmarshal(line, &resp)
		}
		if err != nil {
			resp.Error = err.Error()
		}
		ch <- resp
	}()
	return ch
}

func (e *brokerEnv) waitClaim(name string) *resourceapi.ResourceClaim {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := e.client.ResourceV1().ResourceClaims(testNS).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil {
			// the pod is created right after the claim
			if _, err := e.client.CoreV1().Pods(testNS).Get(context.Background(), name, metav1.GetOptions{}); err == nil {
				return c
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("claim %s not created", name)
	return nil
}

func (e *brokerEnv) wantGone(name string) {
	e.t.Helper()
	_, err := e.client.CoreV1().Pods(testNS).Get(context.Background(), name, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		e.t.Fatalf("companion pod %s still exists (%v)", name, err)
	}
	_, err = e.client.ResourceV1().ResourceClaims(testNS).Get(context.Background(), name, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		e.t.Fatalf("companion claim %s still exists (%v)", name, err)
	}
}

func (e *brokerEnv) lease(id string) *lease {
	e.b.mu.Lock()
	defer e.b.mu.Unlock()
	if l := e.b.store.Leases[id]; l != nil {
		c := *l
		return &c
	}
	return nil
}

func (e *brokerEnv) waitState(id, state string) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l := e.lease(id)
		if (l == nil && state == api.StateReleased) || (l != nil && l.State == state) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("lease %s not %s: %+v", id, state, e.lease(id))
}

// wantNoCDIDevices checks that a prepared claim of one device has no CDI
// device, and that the CDI spec of the pool driver has none.
func (e *poolTestEnv) wantNoCDIDevices(t *testing.T, r kubeletplugin.PrepareResult) {
	t.Helper()
	if len(r.Devices) != 1 || len(r.Devices[0].CDIDeviceIDs) != 0 || e.cdiSpec(t) != nil {
		t.Fatalf("CDI devices of a companion claim: %+v, spec %+v", r.Devices, e.cdiSpec(t))
	}
}

// allocated returns the companion claim as the scheduler and the pool
// controller leave it: allocated a pool device, config copied from the
// spec, device data in the status.
func allocated(c *resourceapi.ResourceClaim, dev, data string) *resourceapi.ResourceClaim {
	c = c.DeepCopy()
	c.UID = types.UID("uid-" + c.Name)
	var cfgs []resourceapi.DeviceAllocationConfiguration
	for _, sc := range c.Spec.Devices.Config {
		cfgs = append(cfgs, resourceapi.DeviceAllocationConfiguration{Source: resourceapi.AllocationConfigSourceClaim, Requests: sc.Requests, DeviceConfiguration: sc.DeviceConfiguration})
	}
	request := companionClaimRef
	if len(c.Spec.Devices.Requests) > 0 && len(c.Spec.Devices.Requests[0].FirstAvailable) > 0 {
		request += "/" + api.SourcePool
	}
	c.Status.Allocation = &resourceapi.AllocationResult{Devices: resourceapi.DeviceAllocationResult{
		Results: []resourceapi.DeviceRequestAllocationResult{{Request: request, Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: dev, ConsumedCapacity: poolConsumed(data)}},
		Config:  cfgs,
	}}
	c.Status.Devices = []resourceapi.AllocatedDeviceStatus{{Driver: device.PoolDriverName, Pool: "fake-cxl-pool", Device: dev, Data: &runtime.RawExtension{Raw: []byte(data)}}}
	return c
}

func TestBrokerLeaseClaimSocketAndCDI(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	noErr(t, e.b.OpenClaim(leaseClaimObj())) // idempotent

	st, err := os.Stat(e.sock())
	noErr(t, err)
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode %v", st.Mode())
	}
	if st, _ := os.Stat(filepath.Dir(e.sock())); st.Mode().Perm() != 0o755 {
		t.Fatalf("directory mode %v", st.Mode())
	}

	// the CDI device of the claim
	m, _ := filepath.Glob(filepath.Join(e.cdiDir, device.LeasesCDISpecName+".*"))
	if len(m) != 1 {
		t.Fatalf("no CDI spec in %s", e.cdiDir)
	}
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(e.cdiDir), cdiapi.WithAutoRefresh(false))
	noErr(t, err)
	dev := cache.GetDevice(leaseCDIDeviceID(testLeaseClaimUID))
	if dev == nil {
		t.Fatalf("CDI device %s missing: %v", leaseCDIDeviceID(testLeaseClaimUID), cache.ListDevices())
	}
	if leaseCDIDeviceID(testLeaseClaimUID) != "nri.io/cxl=lease-lc1" {
		t.Fatalf("CDI id %s", leaseCDIDeviceID(testLeaseClaimUID))
	}
	fsDir := filepath.Join(e.dir, "lease-fs", testLeaseClaimUID)
	wantMounts := []*specs.Mount{
		{HostPath: filepath.Dir(e.sock()), ContainerPath: "/run/cxl", Type: "bind", Options: []string{"rbind", "rw"}},
		{HostPath: fsDir, ContainerPath: "/run/cxl/fs", Type: "bind", Options: []string{"rbind", "ro", "rslave"}},
		{HostPath: e.cli, ContainerPath: "/usr/local/bin/cxl-request", Type: "bind", Options: []string{"bind", "ro"}},
	}
	if !reflect.DeepEqual(dev.ContainerEdits.Mounts, wantMounts) {
		t.Fatalf("mounts %s", toJSON(dev.ContainerEdits.Mounts))
	}
	// the lease-fs directory and the mount point in the socket directory
	for _, d := range []string{fsDir, filepath.Join(filepath.Dir(e.sock()), "fs")} {
		if st, err := os.Stat(d); err != nil || !st.IsDir() || st.Mode().Perm() != 0o755 {
			t.Fatalf("directory %s: %v %v", d, st, err)
		}
	}
	if tc := e.b.store.Claims[testLeaseClaimUID]; tc.FsDir != fsDir {
		t.Fatalf("lease claim %+v", tc)
	}
	if !slices.Equal(dev.ContainerEdits.Env, []string{"CXL_LEASE_SOCKET=/run/cxl/cxl.sock"}) {
		t.Fatalf("env %v", dev.ContainerEdits.Env)
	}
	if leaseContainerDir+"/"+leaseSocketName != api.DefaultSocket {
		t.Fatalf("the socket is mounted at %s/%s, not at %s", leaseContainerDir, leaseSocketName, api.DefaultSocket)
	}

	// without a lender: lending unavailable
	resp, _ := e.call(api.Request{Op: "list"})
	wantErr(t, errors.New(resp.Error), "lending unavailable: NRI not connected")

	// restart: the socket is re-created
	e.restart()
	e.start()
	resp, _ = e.call(api.Request{Op: "list"})
	if resp.Error != "" || resp.Leases == nil || len(*resp.Leases) != 0 {
		t.Fatalf("list after restart: %+v", resp)
	}

	// close: socket, directories and CDI device gone
	noErr(t, e.b.CloseClaim(context.Background(), testLeaseClaimUID))
	for _, d := range []string{filepath.Dir(e.sock()), fsDir} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("directory %s not removed: %v", d, err)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(e.cdiDir, device.LeasesCDISpecName+".*")); len(m) != 0 {
		t.Fatalf("CDI spec not removed: %v", m)
	}
	noErr(t, e.b.CloseClaim(context.Background(), testLeaseClaimUID)) // unknown: fine
}

func TestBrokerAuthRejection(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.lender.setPeer(&containerRef{PodUID: "other-pod", PodNamespace: testNS, PodName: "intruder", Name: "x"})
	e.start()
	resp, _ := e.call(api.Request{Op: "request", Size: "512Mi"})
	wantErr(t, errors.New(resp.Error), "not a container of the claim's pod")
	e.lender.setPeer(nil)
	resp, _ = e.call(api.Request{Op: "list"})
	wantErr(t, errors.New(resp.Error), "not a container of the claim's pod")
	if l, _ := e.client.ResourceV1().ResourceClaims(testNS).List(context.Background(), metav1.ListOptions{}); len(l.Items) != 1 {
		t.Fatalf("objects created for a rejected request: %d claims", len(l.Items))
	}

	// a pod added to a shared lease claim later is found by re-reading
	// the claim's reservedFor
	tc := leaseClaimObj()
	tc.Status.ReservedFor = append(tc.Status.ReservedFor, resourceapi.ResourceClaimConsumerReference{Resource: "pods", Name: "second", UID: "pod-uid-2"})
	_, err := e.client.ResourceV1().ResourceClaims(testNS).Update(context.Background(), tc, metav1.UpdateOptions{})
	noErr(t, err)
	e.lender.setPeer(&containerRef{PodUID: "pod-uid-2", PodNamespace: testNS, PodName: "second", Name: "x"})
	resp, _ = e.call(api.Request{Op: "list"})
	if resp.Error != "" {
		t.Fatalf("second pod rejected: %+v", resp)
	}

	// bad requests: validation errors (docs/memory/cxl/leases.md), sizes, ops,
	// unknown leases
	e.lender.setPeer(&testRef)
	for _, c := range []struct {
		req api.Request
		err string
	}{
		{api.Request{Op: "request", Size: "1Gi", Source: "any"}, `invalid source "any" (local or pool)`},
		{api.Request{Op: "request", Size: "1Gi", Mode: "devdax"}, `invalid mode "devdax" (numa, dax, fs or block)`},
		{api.Request{Op: "request", Shared: true, Mode: "numa"}, "shared memory is never onlined as RAM: use mode dax"},
		{api.Request{Op: "request", Size: "1Gi", ReadOnly: true}, "readOnly needs mode dax, fs or block"},
		{api.Request{Op: "request", Size: "64Mi", Mode: "fs", ReadOnly: true, Access: "slow"}, `invalid access "slow" (direct or cached)`},
		{api.Request{Op: "request", Size: "64Mi", Access: "cached"}, "access needs mode fs"},
		{api.Request{Op: "request", Size: "64Mi", Name: "x"}, "name needs mode fs"},
		{api.Request{Op: "request", Size: "64Mi", Mode: "fs", ReadOnly: true, Name: "a/b"}, `invalid name "a/b" (letters, digits, ".", "_" and "-", not "." or "..")`},
		{api.Request{Op: "request", Size: "64Mi", Mode: "fs"}, "mode fs needs readOnly"},
		{api.Request{Op: "request", Size: "64Mi", Mode: "fs", ReadOnly: true, Source: "local"}, "mode fs needs source pool"},
		{api.Request{Op: "request"}, "size or serial is required"},
		{api.Request{Op: "request", Serial: "xyz"}, `invalid serial "xyz"`},
		{api.Request{Op: "release"}, "release takes --lease ID or --all"},
		{api.Request{Op: "request", Size: "1Gi", Wait: "-1s"}, `invalid wait "-1s"`},
		{api.Request{Op: "request", Size: "lots"}, `invalid size "lots"`},
		{api.Request{Op: "request", Size: "0"}, `invalid size "0"`},
		{api.Request{Op: "lease"}, `unknown op "lease"`},
		{api.Request{Op: "release", Lease: "nope"}, "no such lease"},
		{api.Request{Op: "fd", Lease: "nope"}, "no such lease of this container"},
		{api.Request{Op: "env", Lease: "nope"}, "no such lease of this container"},
	} {
		resp, _ := e.call(c.req)
		if resp.Error != c.err && !strings.HasPrefix(resp.Error, c.err) {
			t.Errorf("%+v: error %q, expected %q", c.req, resp.Error, c.err)
		}
	}
	for _, line := range []string{`{"op":"request","kind":"memory","size":"1Gi"}`, `{"op":"request","exclusive":true}`, `[]`} {
		resp, _ := e.callRaw(line)
		wantErr(t, errors.New(resp.Error), "invalid request: ")
	}
	if resp, _ := e.callRaw(`{"op":"request","kind":"memory"}`); resp.Error != `invalid request: json: unknown field "kind"` {
		t.Fatalf("old protocol: %+v", resp)
	}
}

// TestBrokerPoolNumaLease runs a pool lease through the real pool driver
// (fake sysfs) and the fake lender: request -> companion objects ->
// prepare (lend) -> Ready -> release (revoke, objects deleted) ->
// unprepare.
func TestBrokerPoolNumaLease(t *testing.T) {
	pe := newPoolTestEnv(t)
	pe.f.plug("0xc1ee0001")
	p := pe.driver(t)
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	p.lender.set(e.lender, e.b)

	ch := e.async(api.Request{Op: "request", Source: "pool", Size: "256Mi", Wait: "5s", RequestID: "r1"})
	name := "cxl-lease-000000a1"
	claim := e.waitClaim(name)
	e.waitState("000000a1", api.StatePending)

	// the companion claim, exactly
	params := `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"numa"}`
	wantSpec := resourceapi.ResourceClaimSpec{Devices: resourceapi.DeviceClaim{
		Requests: []resourceapi.DeviceRequest{{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
			DeviceClassName: "cxl-pool",
			Capacity:        &resourceapi.CapacityRequirements{Requests: map[resourceapi.QualifiedName]resource.Quantity{"memory": resource.MustParse("256Mi")}},
		}}},
		Config: []resourceapi.DeviceClaimConfiguration{{DeviceConfiguration: resourceapi.DeviceConfiguration{Opaque: &resourceapi.OpaqueDeviceConfiguration{
			Driver: "cxl-pool.nri.io", Parameters: runtime.RawExtension{Raw: []byte(params)},
		}}}},
	}}
	if !reflect.DeepEqual(claim.Spec, wantSpec) {
		got, _ := json.Marshal(claim.Spec)
		t.Fatalf("claim spec:\n%s", got)
	}
	wantOwner := []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: testPod, UID: testPodUID, Controller: ptr(true)}}
	if !reflect.DeepEqual(claim.OwnerReferences, wantOwner) {
		t.Fatalf("claim owners %+v", claim.OwnerReferences)
	}
	wantLabels := map[string]string{"cxl.nri.io/lease": "000000a1", "cxl.nri.io/requester-uid": testPodUID, "cxl.nri.io/node": testNode}
	if !reflect.DeepEqual(claim.Labels, wantLabels) {
		t.Fatalf("claim labels %v", claim.Labels)
	}
	if !reflect.DeepEqual(claim.Annotations, map[string]string{"cxl.nri.io/requester": "demo/borrower/app"}) {
		t.Fatalf("claim annotations %v", claim.Annotations)
	}

	// the companion pod, exactly
	pod, err := e.client.CoreV1().Pods(testNS).Get(context.Background(), name, metav1.GetOptions{})
	noErr(t, err)
	if !reflect.DeepEqual(pod.Labels, wantLabels) {
		t.Fatalf("pod labels %v", pod.Labels)
	}
	if !reflect.DeepEqual(pod.OwnerReferences, []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: testPod, UID: testPodUID}}) {
		t.Fatalf("pod owners %+v", pod.OwnerReferences)
	}
	res := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("16Mi")}
	wantPodSpec := corev1.PodSpec{
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{testNode}}}}},
		}}},
		Tolerations:                   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
		RestartPolicy:                 corev1.RestartPolicyAlways,
		AutomountServiceAccountToken:  ptr(false),
		EnableServiceLinks:            ptr(false),
		TerminationGracePeriodSeconds: ptr(int64(1)),
		ResourceClaims:                []corev1.PodResourceClaim{{Name: "lease", ResourceClaimName: ptr(name)}},
		Containers: []corev1.Container{{
			Name: "pause", Image: "registry.k8s.io/pause:3.10",
			Resources: corev1.ResourceRequirements{Requests: res, Limits: res},
		}},
	}
	if !reflect.DeepEqual(pod.Spec, wantPodSpec) {
		got, _ := json.Marshal(pod.Spec)
		t.Fatalf("pod spec:\n%s", got)
	}

	// kubelet prepares the companion claim: region, online, lend
	alloc := allocated(claim, "pooled0", exclusiveData)
	r := prepare(t, p, alloc)
	noErr(t, r.Err)
	if got := e.lender.LentNodes(testPodUID, testCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("lent nodes %v", got)
	}
	// the companion pod references no claim: no CDI device
	pe.wantNoCDIDevices(t, r)
	wantResponse(t, <-ch, api.Response{State: api.StateReady, Source: "pool", Mode: "numa", Node: ptr(2), Size: 268435456, Serial: "0xc1ee0001",
		Env: map[string]string{"CXL_C1EE0001_MODE": "numa", "CXL_C1EE0001_NODE": "2", "CXL_C1EE0001_SERIAL": "0xc1ee0001",
			"CXL_C1EE0001_SHARED": "0", "CXL_C1EE0001_SIZE": "268435456"}})
	data, _ := os.ReadFile(pe.stateFile)
	if !strings.Contains(string(data), `"lease": "000000a1"`) || !strings.Contains(string(data), `"nodes": [`) {
		t.Fatalf("lend not persisted in the pool state:\n%s", data)
	}

	// the same requestId returns the same lease
	again, _ := e.call(api.Request{Op: "request", Source: "pool", Size: "256Mi", RequestID: "r1"})
	if again.Lease != "000000a1" || again.State != api.StateReady {
		t.Fatalf("retry with requestId: %+v", again)
	}
	list, _ := e.call(api.Request{Op: "list"})
	if list.Leases == nil || len(*list.Leases) != 1 || (*list.Leases)[0].Lease != "000000a1" || (*list.Leases)[0].Env["CXL_C1EE0001_NODE"] != "2" {
		t.Fatalf("list %+v", list)
	}
	// env: the same environment, no fd
	env, fd := e.call(api.Request{Op: "env", Lease: "000000a1"})
	if fd >= 0 || env.State != api.StateReady || !reflect.DeepEqual(env.Env, again.Env) {
		t.Fatalf("env %+v fd %d", env, fd)
	}
	// fd: not a dax or block lease
	resp, fd := e.call(api.Request{Op: "fd", Lease: "000000a1"})
	if fd >= 0 || resp.Error != "lease 000000a1 is not a dax or block lease; use env" || resp.Mode != "numa" {
		t.Fatalf("fd of a numa lease %+v fd %d", resp, fd)
	}

	// a restarted container gets the node again
	e.lender.mu.Lock()
	e.lender.lent = map[string]map[int][]string{}
	started := e.lender.started[0]
	e.lender.mu.Unlock()
	started(testRef)
	if got := e.lender.LentNodes(testPodUID, testCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("not re-lent after restart: %v", got)
	}

	// release: revoke, companion objects deleted, lease dropped
	rel, _ := e.call(api.Request{Op: "release", Lease: "000000a1"})
	if rel.State != api.StateReleased {
		t.Fatalf("release %+v", rel)
	}
	e.wantGone(name)
	if !strings.Contains(e.lender.callLog(), "revoke pod-uid-1/app 2") {
		t.Fatalf("not revoked:\n%s", e.lender.callLog())
	}
	// kubelet unprepares the companion claim: revoke again, release
	noErr(t, unprepare(t, p, string(alloc.UID)))
	pe.f.wantReleased(t)
	if l := e.lender.LentNodes(testPodUID, testCtr); len(l) != 0 {
		t.Fatalf("still lent %v", l)
	}
}

func TestBrokerSharedLeaseFd(t *testing.T) {
	e := newLeaseFdEnv(t, "0xc1ae0001")
	claim, resp, fd := e.prepareLease(api.Request{Op: "request", Serial: "0xC1AE0001", Shared: true, Source: "pool"}, "shared0", sharedData)
	want := resourceapi.ExactDeviceRequest{
		DeviceClassName: "cxl-pool-shared",
		Selectors:       []resourceapi.DeviceSelector{{CEL: &resourceapi.CELDeviceSelector{Expression: `device.attributes["cxl-pool.nri.io"].serial == "0xc1ae0001"`}}},
		Capacity:        &resourceapi.CapacityRequirements{Requests: map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse("1")}},
	}
	if !reflect.DeepEqual(*claim.Spec.Devices.Requests[0].Exactly, want) {
		t.Fatalf("shared request %+v", claim.Spec.Devices.Requests[0].Exactly)
	}
	if dc := deviceConfigOf(t, claim, device.PoolDriverName); dc == nil || dc.Mode != api.ModeDax || dc.ReadOnly {
		t.Fatalf("companion DeviceConfig %+v", dc)
	}
	sharedEnv := map[string]string{"CXL_C1AE0001_DAX": "/dev/dax0.0", "CXL_C1AE0001_MODE": "dax", "CXL_C1AE0001_READONLY": "0",
		"CXL_C1AE0001_SERIAL": "0xc1ae0001", "CXL_C1AE0001_SHARED": "1", "CXL_C1AE0001_SIZE": "268435456"}
	e.wantDaxFd(resp, fd)
	wantResponse(t, resp, api.Response{State: api.StateReady, Source: "pool", Mode: "dax", Shared: true, Size: 268435456, Serial: "0xc1ae0001",
		Dax: "/dev/dax0.0", Env: sharedEnv})
	if calls := e.lender.callLog(); strings.Contains(calls, "lend") {
		t.Fatalf("shared device lent as a node:\n%s", calls)
	}

	// the fd again, and the env without it
	resp, fd = e.call(api.Request{Op: "fd", Lease: "000000a1", Wait: "1s"})
	e.wantDaxFd(resp, fd)
	resp, fd = e.call(api.Request{Op: "env", Lease: "000000a1"})
	if fd >= 0 || !reflect.DeepEqual(resp.Env, sharedEnv) {
		t.Fatalf("env %+v fd %d", resp, fd)
	}
	if got := e.opened(); !slices.Equal(got, []bool{false, false}) {
		t.Fatalf("dax opened read-only: %v", got)
	}
	e.wantReleaseAll(1)
	e.wantGone("cxl-lease-000000a1")
}

func TestBrokerTimeoutReleases(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	resp, _ := e.call(api.Request{Op: "request", Size: "1Gi", Wait: "50ms"})
	if resp.State != api.StateFailed || resp.Error != "timeout: not Ready after 50ms" {
		t.Fatalf("timeout response %+v", resp)
	}
	e.waitState(resp.Lease, api.StateReleased)
	e.wantGone(companionName(resp.Lease))

	// wait 0 returns Pending at once and keeps the lease
	resp, _ = e.call(api.Request{Op: "request", Size: "1Gi", Mode: "dax", Wait: "0s"})
	if resp.State != api.StatePending || resp.Error != "" || resp.Size != 1<<30 || resp.Env != nil {
		t.Fatalf("wait 0 response %+v", resp)
	}
	// fd and env wait for Ready, and keep a lease that is not Ready
	for _, op := range []string{"fd", "env"} {
		r, fd := e.call(api.Request{Op: op, Lease: resp.Lease, Wait: "20ms"})
		if fd >= 0 || r.State != api.StatePending || r.Error != "" {
			t.Fatalf("%s of a pending lease %+v fd %d", op, r, fd)
		}
	}
	if l := e.lease(resp.Lease); l == nil || l.State != api.StatePending {
		t.Fatalf("lease after fd and env %+v", l)
	}
}

func TestBrokerLendFailure(t *testing.T) {
	pe := newPoolTestEnv(t)
	pe.f.plug("0xc1ee0001")
	p := pe.driver(t)
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	p.lender.set(e.lender, e.b)
	e.lender.mu.Lock()
	e.lender.lendErr = errSteered
	e.lender.mu.Unlock()

	ch := e.async(api.Request{Op: "request", Source: "pool", Size: "256Mi"})
	claim := e.waitClaim("cxl-lease-000000a1")
	r := prepare(t, p, allocated(claim, "pooled0", exclusiveData))
	wantErr(t, r.Err, "memory-steered")
	pe.f.wantReleased(t) // rolled back
	resp := <-ch
	if resp.State != api.StateFailed || !strings.Contains(resp.Error, "memory-steered") {
		t.Fatalf("lend failure response %+v", resp)
	}
	e.waitState("000000a1", api.StateReleased)
	e.wantGone("cxl-lease-000000a1")
}

// TestBrokerOnLending checks that only the companion claim of a lease is
// lent: its name, namespace and owner.
func TestBrokerOnLending(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	resp, _ := e.call(api.Request{Op: "request", Size: "256Mi", Wait: "0s"})
	id := resp.Lease
	wrongName, wrongNS, wrongOwner, noOwner := companionClaim(id), companionClaim(id), companionClaim(id), companionClaim(id)
	wrongName.Name = "cxl-lease-ffffffff"
	wrongNS.Namespace = "other"
	wrongOwner.OwnerReferences[0].UID = "pod-uid-2"
	noOwner.OwnerReferences = nil
	for _, c := range []struct {
		id    string
		claim *resourceapi.ResourceClaim
	}{
		{"ffffffff", companionClaim("ffffffff")},
		{id, wrongName},
		{id, wrongNS},
		{id, wrongOwner},
		{id, noOwner},
	} {
		_, err := e.b.OnLending(c.id, c.claim)
		if err == nil || err.Error() != fmt.Sprintf("claim %s/%s: not the companion of lease %s", c.claim.Namespace, c.claim.Name, c.id) {
			t.Errorf("lease %s claim %s/%s owners %v: %v", c.id, c.claim.Namespace, c.claim.Name, c.claim.OwnerReferences, err)
		}
	}
	if l := e.lease(id); l.State != api.StatePending {
		t.Fatalf("refused companions changed the lease: %+v", l)
	}
	rec, err := e.b.OnLending(id, companionClaim(id))
	noErr(t, err)
	if !reflect.DeepEqual(rec, &lendRecord{Lease: id, Pod: podRef{Namespace: testNS, Name: testPod, UID: testPodUID}, Container: testCtr}) {
		t.Fatalf("lend record %+v", rec)
	}
	if l := e.lease(id); l.State != api.StateLending {
		t.Fatalf("lease %+v", l)
	}
	// a failed lease is not lent again
	e.b.OnLendFailed(id, errors.New("boom"))
	_, err = e.b.OnLending(id, companionClaim(id))
	wantErr(t, err, "lease "+id+" is ")
}

func TestBrokerRestartAndReconcile(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	resp, _ := e.call(api.Request{Op: "request", Size: "256Mi", Wait: "0s"})
	id := resp.Lease
	_, err := e.b.OnLending(id, companionClaim(id))
	noErr(t, err)
	e.b.OnPrepared(id, []lentDevice{{Source: api.SourcePool, Serial: 0xc1ee0001, Size: 1 << 28, Mode: api.ModeNUMA, Node: 2}})
	e.waitState(id, api.StateReady)

	// restart: lease and socket are back, the lend is re-applied
	e.restart()
	e.lender.mu.Lock()
	e.lender.lent = map[string]map[int][]string{}
	e.lender.mu.Unlock()
	e.start()
	if l := e.lease(id); l == nil || l.State != api.StateReady || l.Node != 2 {
		t.Fatalf("lease after restart %+v", l)
	}
	list, _ := e.call(api.Request{Op: "list"})
	if list.Leases == nil || len(*list.Leases) != 1 {
		t.Fatalf("list after restart %+v", list)
	}
	e.b.reconcile()
	if got := e.lender.LentNodes(testPodUID, testCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("lend not re-applied by reconcile: %v", got)
	}

	// an orphaned companion (no lease) is deleted; objects with only the
	// node label, or not named after their lease label, are not
	others := []metav1.ObjectMeta{
		{Name: "cxl-lease-0badf00e", Namespace: testNS, Labels: map[string]string{device.NodeLabel: testNode}},
		{Name: "workload", Namespace: testNS, Labels: map[string]string{device.LeaseLabel: "0badf00f", device.NodeLabel: testNode}},
	}
	for _, meta := range append(others, metav1.ObjectMeta{Name: "cxl-lease-0badf00d", Namespace: testNS,
		Labels: map[string]string{device.LeaseLabel: "0badf00d", device.NodeLabel: testNode}}) {
		_, err = e.client.CoreV1().Pods(testNS).Create(context.Background(), &corev1.Pod{ObjectMeta: meta}, metav1.CreateOptions{})
		noErr(t, err)
		_, err = e.client.ResourceV1().ResourceClaims(testNS).Create(context.Background(), &resourceapi.ResourceClaim{ObjectMeta: meta}, metav1.CreateOptions{})
		noErr(t, err)
	}
	e.b.reconcile()
	e.wantGone("cxl-lease-0badf00d")
	for _, meta := range others {
		_, perr := e.client.CoreV1().Pods(testNS).Get(context.Background(), meta.Name, metav1.GetOptions{})
		_, cerr := e.client.ResourceV1().ResourceClaims(testNS).Get(context.Background(), meta.Name, metav1.GetOptions{})
		if perr != nil || cerr != nil {
			t.Fatalf("%s deleted: %v %v", meta.Name, perr, cerr)
		}
	}
	if e.lease(id) == nil {
		t.Fatal("live lease dropped by reconcile")
	}

	// the requester container stopped but the pod restarts it: kept
	e.lender.remove(testPodUID, testCtr)
	e.b.reconcile()
	if e.lease(id) == nil {
		t.Fatal("lease of a restarting container dropped")
	}
	// the requester pod is deleted: the lease is released
	noErr(t, e.client.CoreV1().Pods(testNS).Delete(context.Background(), testPod, metav1.DeleteOptions{}))
	e.b.reconcile()
	e.waitState(id, api.StateReleased)
	e.wantGone(companionName(id))
	if !strings.Contains(e.lender.callLog(), "revoke pod-uid-1/app 2") {
		t.Fatalf("not revoked:\n%s", e.lender.callLog())
	}
}

func TestBrokerCompanionGoneAndContainerGone(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	r1, _ := e.call(api.Request{Op: "request", Size: "256Mi", Wait: "0s"})
	r2, _ := e.call(api.Request{Op: "request", Serial: "0xc1ae0001", Shared: true, Wait: "0s"})

	// companion deleted behind the broker's back: unprepare -> Failed,
	// reconcile drops it
	e.b.OnReleasing(r1.Lease)
	if l := e.lease(r1.Lease); l.State != api.StateFailed {
		t.Fatalf("lease %+v", l)
	}
	noErr(t, e.client.CoreV1().Pods(testNS).Delete(context.Background(), companionName(r1.Lease), metav1.DeleteOptions{}))
	e.b.reconcile()
	e.waitState(r1.Lease, api.StateReleased)

	// the requester pod has restartPolicy Never: its stopped container
	// releases its leases
	pod := requesterPod()
	pod.Spec.RestartPolicy = corev1.RestartPolicyNever
	_, err := e.client.CoreV1().Pods(testNS).Update(context.Background(), pod, metav1.UpdateOptions{})
	noErr(t, err)
	e.lender.remove(testPodUID, testCtr)
	e.b.containerGone(testRef)
	e.waitState(r2.Lease, api.StateReleased)
	e.wantGone(companionName(r2.Lease))
}

func TestBrokerCloseClaimReleasesLeases(t *testing.T) {
	e := newBrokerEnv(t)
	ctx := context.Background()
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	r, _ := e.call(api.Request{Op: "request", Size: "256Mi", Wait: "0s"})
	noErr(t, e.b.CloseClaim(ctx, testLeaseClaimUID))
	e.waitState(r.Lease, api.StateReleased)
	e.wantGone(companionName(r.Lease))
}

// TestBrokerCloseClaimDoesNotWaitForCompanions closes a lease claim whose
// lease has a companion that stays Terminating, as the companion of a
// local lease does while the Unprepare of the lease claim runs: kubelet
// unprepares the companion's claim through the same driver, after it.
func TestBrokerCloseClaimDoesNotWaitForCompanions(t *testing.T) {
	e := newBrokerEnv(t)
	ctx := context.Background()
	// reactors are added before the broker uses the client: the fake
	// client does not lock its reactor chain
	var stay atomic.Bool
	e.client.PrependReactor("delete", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return stay.Load(), nil, nil // accepted, but the pod stays (Terminating)
	})
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	r, _ := e.call(api.Request{Op: "request", Size: "64Mi", Source: "local", Wait: "0s"})
	_, err := e.b.OnLending(r.Lease, companionClaim(r.Lease))
	noErr(t, err)
	e.b.OnPrepared(r.Lease, []lentDevice{{Source: api.SourceLocal, Serial: 0xc100e2e1, Size: 64 << 20, Mode: api.ModeNUMA, Node: 2}})
	noErr(t, e.lender.LendNode(ctx, testPodUID, testCtr, 2, r.Lease))
	stay.Store(true)

	start := time.Now()
	noErr(t, e.b.CloseClaim(ctx, testLeaseClaimUID))
	if d := time.Since(start); d > time.Second {
		t.Fatalf("CloseClaim waited %v for the companion", d)
	}
	if got := e.lender.LentNodes(testPodUID, testCtr); len(got) != 0 {
		t.Fatalf("CloseClaim returned before the revoke: %v lent", got)
	}
	if _, err := os.Stat(e.sock()); !os.IsNotExist(err) {
		t.Fatalf("socket left after CloseClaim: %v", err)
	}
	if l := e.lease(r.Lease); l == nil || l.State != api.StateReleasing {
		t.Fatalf("lease with a terminating companion %+v", l)
	}

	// a plugin restart meanwhile: the reconcile continues the release of
	// the lease, whose lease claim is gone
	e.restart()
	e.start()
	if l := e.lease(r.Lease); l == nil {
		t.Fatal("lease dropped before its companion is gone")
	}
	stay.Store(false)
	e.waitState(r.Lease, api.StateReleased)
	e.wantGone(companionName(r.Lease))
}

// TestBrokerCloseClaimRetry fails the Unprepare of a lease claim while the
// deletion of a companion cannot be requested; kubelet retries.
func TestBrokerCloseClaimRetry(t *testing.T) {
	e := newBrokerEnv(t)
	ctx := context.Background()
	var fail atomic.Bool
	e.client.PrependReactor("delete", "resourceclaims", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if fail.Load() {
			return true, nil, errors.New("apiserver unavailable")
		}
		return false, nil, nil
	})
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	r, _ := e.call(api.Request{Op: "request", Size: "256Mi", Wait: "0s"})
	fail.Store(true)
	e.b.closeTimeout = 50 * time.Millisecond
	wantErr(t, e.b.CloseClaim(ctx, testLeaseClaimUID), "still releasing 1 leases, retry")
	if _, err := os.Stat(e.sock()); err != nil {
		t.Fatalf("socket closed too early: %v", err)
	}
	fail.Store(false)
	e.b.closeTimeout = 5 * time.Second
	noErr(t, e.b.CloseClaim(ctx, testLeaseClaimUID))
	e.waitState(r.Lease, api.StateReleased)
	e.wantGone(companionName(r.Lease))
}

// TestLeaseDevice publishes the lease device and prepares a claim on it
// through nodeState: claim marker + lease CDI device, socket opened.
func TestLeaseDevice(t *testing.T) {
	devs, err := buildDevInfos(&DriverConfig{IgnoreDRAMNodes: true, PublishLeaseDevice: true}, &nricxl.Devices{}, nil, nil)
	noErr(t, err)
	if d := devs["lease"]; d == nil || d.Name != "lease" {
		t.Fatalf("no lease device in %v", devs)
	} else if _, ok := d.Dev.(*device.LeaseToken); !ok {
		t.Fatalf("lease Dev %T", d.Dev)
	}
	none, _ := buildDevInfos(&DriverConfig{IgnoreDRAMNodes: true}, &nricxl.Devices{}, nil, nil)
	if len(none) != 0 {
		t.Fatalf("lease device published without --leases: %v", none)
	}

	e := newBrokerEnv(t)
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(e.cdiDir), cdiapi.WithAutoRefresh(false))
	noErr(t, err)
	s := &nodeState{
		baseState: &baseState{
			CdiCache:               cache,
			Allocatable:            devs,
			Prepared:               claimPreparations{},
			PreparedClaimsFilePath: filepath.Join(e.dir, "preparedClaims.json"),
			NodeName:               testNode,
		},
		config:         &DriverConfig{},
		preparedClaims: PreparedClaimsInfo{},
		claimsFilePath: filepath.Join(e.dir, "preparedClaimsInfo.json"),
		podClaims:      map[string]map[string]bool{},
	}

	r := s.GetResources()
	got := r.Pools[testNode].Slices[0].Devices
	want := []resourceapi.Device{{
		Name: "lease",
		Attributes: map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
			"type": {StringValue: ptr("lease")},
		},
		AllowMultipleAllocations: ptr(true),
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("published %+v", got)
	}

	// lending disabled: Prepare fails
	wantErr(t, s.Prepare(context.Background(), leaseClaimObj()), "claim demo/lease: lending to running containers is disabled (--leases=false)")

	s.leases = e.b
	noErr(t, s.Prepare(context.Background(), leaseClaimObj()))
	res := s.Prepared[testLeaseClaimUID]
	if len(res.Devices) != 1 || !slices.Equal(res.Devices[0].CDIDeviceIDs, []string{"nri.io/cxl=claim-lc1-0", "nri.io/cxl=lease-lc1"}) {
		t.Fatalf("prepared %+v", res.Devices)
	}
	if info := s.preparedClaims[testLeaseClaimUID]; info == nil || info.Devices[0].DeviceType != "lease" || info.Devices[0].Mode != "" {
		t.Fatalf("claim info %+v", info)
	}
	if _, err := os.Stat(e.sock()); err != nil {
		t.Fatalf("no lease socket: %v", err)
	}
}

// poolSlice is the pool controller's ResourceSlice with an exclusive
// device pooled0 and the shared devices shared0 and shared1.
func poolSlice() *resourceapi.ResourceSlice {
	attrs := func(serial string, shared bool) map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
		return map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
			"type": {StringValue: ptr("memdev")}, "source": {StringValue: ptr("pool")}, "serial": {StringValue: &serial},
			"shared": {BoolValue: ptr(shared)}, "size": {IntValue: ptr(int64(1 << 28))},
		}
	}
	return &resourceapi.ResourceSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "fake-cxl-pool"},
		Spec: resourceapi.ResourceSliceSpec{
			Driver:   device.PoolDriverName,
			Pool:     resourceapi.ResourcePool{Name: "fake-cxl-pool", ResourceSliceCount: 1},
			AllNodes: ptr(true),
			Devices: []resourceapi.Device{
				{Name: "pooled0", Attributes: attrs("0xc1ee0001", false),
					Capacity: map[resourceapi.QualifiedName]resourceapi.DeviceCapacity{"memory": {Value: resource.MustParse("512Mi")}}},
				{Name: "shared0", Attributes: attrs("0xC1AE0001", true),
					Capacity: map[resourceapi.QualifiedName]resourceapi.DeviceCapacity{"shares": {Value: resource.MustParse("1M")}}},
				{Name: "shared1", Attributes: attrs("0xc1ae0002", true)},
			},
		},
	}
}

// localResourceSlice is the cxl.nri.io ResourceSlice of node1 with the local
// memdev 0xc100e2e1 and the shared local memdev 0xc100e2e2.
func localResourceSlice() *resourceapi.ResourceSlice {
	return nodeResourceSlice(testNode,
		localMemdevDevice(localDeviceName, &device.Memdev{Serial: localSerial, Size: localRegionSize, NodeAffinity: 0, BlockSize: localBlockSize}),
		localMemdevDevice("memdev-c100e2e2", &device.Memdev{Serial: 0xc100e2e2, Size: localRegionSize, NodeAffinity: 0, Shared: true}))
}

// nodeResourceSlice returns the cxl.nri.io ResourceSlice of a node with the
// devices.
func nodeResourceSlice(node string, devs ...resourceapi.Device) *resourceapi.ResourceSlice {
	return &resourceapi.ResourceSlice{
		ObjectMeta: metav1.ObjectMeta{Name: node + "-cxl"},
		Spec: resourceapi.ResourceSliceSpec{
			Driver:   device.DriverName,
			Pool:     resourceapi.ResourcePool{Name: node, ResourceSliceCount: 1},
			NodeName: ptr(node),
			Devices:  devs,
		},
	}
}

// persistentPoolSlice is a ResourceSlice of the pool controller with the
// shared persistent device llm0 (0xc1af0001) and the exclusive persistent
// device llm1 (0xc1af0002).
func persistentPoolSlice() *resourceapi.ResourceSlice {
	attrs := func(serial string, shared bool) map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
		return map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
			"type": {StringValue: ptr("memdev")}, "source": {StringValue: ptr("pool")}, "serial": {StringValue: &serial},
			"shared": {BoolValue: ptr(shared)}, "size": {IntValue: ptr(int64(1 << 29))}, "persistent": {BoolValue: ptr(true)},
		}
	}
	return &resourceapi.ResourceSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "fake-cxl-pool-persistent"},
		Spec: resourceapi.ResourceSliceSpec{
			Driver:   device.PoolDriverName,
			Pool:     resourceapi.ResourcePool{Name: "fake-cxl-pool-persistent", ResourceSliceCount: 1},
			AllNodes: ptr(true),
			Devices: []resourceapi.Device{
				{Name: "llm0", Attributes: attrs("0xc1af0001", true),
					Capacity: map[resourceapi.QualifiedName]resourceapi.DeviceCapacity{"shares": {Value: resource.MustParse("1M")}}},
				{Name: "llm1", Attributes: attrs("0xc1af0002", false),
					Capacity: map[resourceapi.QualifiedName]resourceapi.DeviceCapacity{"memory": {Value: resource.MustParse("512Mi")}}},
			},
		},
	}
}

// newSlicesBrokerEnv returns a broker env whose client has the pool and
// the local ResourceSlices, that of node2 with the shared local memdev
// 0xc100e2e3, and the persistent pool devices.
func newSlicesBrokerEnv(t *testing.T) *brokerEnv {
	e := newBrokerEnv(t)
	node2 := nodeResourceSlice("node2", localMemdevDevice("memdev-c100e2e3", &device.Memdev{Serial: 0xc100e2e3, Size: localRegionSize, NodeAffinity: -1, Shared: true}))
	for _, s := range []*resourceapi.ResourceSlice{poolSlice(), localResourceSlice(), node2, persistentPoolSlice()} {
		_, err := e.client.ResourceV1().ResourceSlices().Create(context.Background(), s, metav1.CreateOptions{})
		noErr(t, err)
	}
	return e
}

func TestBrokerRequestOptions(t *testing.T) {
	e := newSlicesBrokerEnv(t)
	for _, tc := range []struct {
		req  api.Request
		want lease
		err  string
	}{
		{req: api.Request{Size: "1Gi"}, want: lease{Size: "1Gi", Mode: "numa"}},
		{req: api.Request{Size: "1024Mi", Mode: "dax", ReadOnly: true}, want: lease{Size: "1Gi", Mode: "dax", ReadOnly: true}},
		{req: api.Request{Shared: true, Size: "256Mi"}, want: lease{Shared: true, SharedDevice: true, Size: "256Mi", Mode: "dax"}},
		// a reader and the writer of a shared device
		{req: api.Request{Serial: "0xC1AE0001", Shared: true, ReadOnly: true}, want: lease{Serial: "0xc1ae0001", Shared: true, SharedDevice: true, DeviceSource: "pool", Mode: "dax", ReadOnly: true}},
		{req: api.Request{Serial: "3249405953"}, want: lease{Serial: "0xc1ae0001", Mode: "dax", SharedDevice: true, DeviceSource: "pool"}},
		{req: api.Request{Serial: "0xc1ae0001", Mode: "dax", ReadOnly: true, Source: "pool"}, want: lease{Source: "pool", Serial: "0xc1ae0001", Mode: "dax", ReadOnly: true, SharedDevice: true}},
		// a shared device has no capacity that the broker reads
		{req: api.Request{Serial: "0xc1ae0002"}, want: lease{Serial: "0xc1ae0002", Mode: "dax", SharedDevice: true, DeviceSource: "pool"}},
		// a reader and the writer of a shared local device
		{req: api.Request{Serial: "0xc100e2e2", Shared: true, ReadOnly: true}, want: lease{Serial: "0xc100e2e2", Shared: true, SharedDevice: true, DeviceSource: "local", Mode: "dax", ReadOnly: true}},
		{req: api.Request{Serial: "0xc100e2e2", Source: "local"}, want: lease{Source: "local", Serial: "0xc100e2e2", Mode: "dax", SharedDevice: true}},
		{req: api.Request{Source: "local", Shared: true, Size: "64Mi"}, want: lease{Source: "local", Shared: true, SharedDevice: true, Size: "64Mi", Mode: "dax"}},
		{req: api.Request{Size: "64Mi", Source: "local"}, want: lease{Source: "local", Size: "64Mi", Mode: "numa"}},
		{req: api.Request{Size: "64Mi", Source: "local", Mode: "dax", ReadOnly: true, Serial: "0xC100E2E1"},
			want: lease{Source: "local", Size: "64Mi", Mode: "dax", ReadOnly: true, Serial: "0xc100e2e1"}},
		{req: api.Request{Size: "64Mi", Source: "pool", Serial: "0xc1ee0001"}, want: lease{Source: "pool", Size: "64Mi", Mode: "numa", Serial: "0xc1ee0001"}},
		// a serial of no published device
		{req: api.Request{Serial: "0x1234", Shared: true}, want: lease{Serial: "0x1234", Shared: true, SharedDevice: true, Mode: "dax"}},
		{req: api.Request{Serial: "0xc1ee0001", Shared: true}, err: "device 0xc1ee0001: not shareable"},
		{req: api.Request{Serial: "0xc100e2e1", Shared: true}, err: "device 0xc100e2e1: not shareable"},
		{req: api.Request{Serial: "0xc1ae0001", Mode: "numa"}, err: "shared memory is never onlined as RAM: use mode dax"},
		{req: api.Request{Serial: "0xc1ae0001", Source: "local"}, err: "device 0xc1ae0001: not a local device"},
		{req: api.Request{Serial: "0xc100e2e2", Source: "pool"}, err: "device 0xc100e2e2: not a pool device"},
		{req: api.Request{Serial: "0xc100e2e3", Shared: true}, err: "device 0xc100e2e3: a local device of node node2, not of this node"},
		{req: api.Request{Serial: "0xc100e2e2", Mode: "numa"}, err: "shared memory is never onlined as RAM: use mode dax"},
		// the refusals in their order
		{req: api.Request{Serial: "0xc100e2e2", Source: "pool", Mode: "numa"}, err: "device 0xc100e2e2: not a pool device"},
		{req: api.Request{Serial: "0xc100e2e3", Mode: "numa"}, err: "device 0xc100e2e3: a local device of node node2, not of this node"},
		{req: api.Request{Serial: "0xc1ae0001", Source: "local", Mode: "numa"}, err: "device 0xc1ae0001: not a local device"},
		{req: api.Request{Size: "lots"}, err: `invalid size "lots"`},
		// mode fs on persistent devices, shared or not
		{req: api.Request{Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs"},
			want: lease{Serial: "0xc1af0001", Shared: true, SharedDevice: true, DeviceSource: "pool", Mode: "fs", ReadOnly: true, Access: "direct"}},
		{req: api.Request{Serial: "0xc1af0001", ReadOnly: true, Mode: "fs", Access: "cached", Name: "models", Source: "pool"},
			want: lease{Source: "pool", Serial: "0xc1af0001", SharedDevice: true, Mode: "fs", ReadOnly: true, Access: "cached", Name: "models"}},
		{req: api.Request{Serial: "0xc1af0002", ReadOnly: true, Mode: "fs", Size: "512Mi"},
			want: lease{Serial: "0xc1af0002", DeviceSource: "pool", Mode: "fs", ReadOnly: true, Access: "direct", Size: "512Mi"}},
		{req: api.Request{Shared: true, ReadOnly: true, Mode: "fs", Size: "256Mi"},
			want: lease{Shared: true, SharedDevice: true, Mode: "fs", ReadOnly: true, Access: "direct", Size: "256Mi"}},
		// B3, B4 after the checks of the device and its source
		{req: api.Request{Serial: "0xc1ae0001", Shared: true, ReadOnly: true, Mode: "fs"}, err: "device 0xc1ae0001: mode fs needs a persistent device"},
		{req: api.Request{Serial: "0xc1ee0001", ReadOnly: true, Mode: "fs"}, err: "device 0xc1ee0001: mode fs needs a persistent device"},
		{req: api.Request{Serial: "0xc100e2e2", Shared: true, ReadOnly: true, Mode: "fs"}, err: "device 0xc100e2e2: mode fs needs a persistent device"},
		{req: api.Request{Serial: "0xc1af0001", Shared: true, ReadOnly: true}, err: "device 0xc1af0001: a persistent device needs mode block or fs"},
		{req: api.Request{Serial: "0xc1af0001", Mode: "numa"}, err: "device 0xc1af0001: a persistent device needs mode block or fs"},
		{req: api.Request{Serial: "0xc1af0002", Size: "64Mi"}, err: "device 0xc1af0002: a persistent device needs mode block or fs"},
		{req: api.Request{Serial: "0xc1af0002", Mode: "dax"}, err: "device 0xc1af0002: a persistent device needs mode block or fs"},
		{req: api.Request{Serial: "0xc1ee0001", Shared: true, ReadOnly: true, Mode: "fs"}, err: "device 0xc1ee0001: not shareable"},
		{req: api.Request{Serial: "0xc1af0001", Source: "local", Mode: "numa"}, err: "device 0xc1af0001: not a local device"},
		{req: api.Request{Serial: "0xc100e2e3", Shared: true, ReadOnly: true, Mode: "fs"}, err: "device 0xc100e2e3: a local device of node node2, not of this node"},
		// mode block on persistent devices: the whole device, or a share read-only
		{req: api.Request{Serial: "0xc1af0001", Mode: "block"}, want: lease{Serial: "0xc1af0001", SharedDevice: true, DeviceSource: "pool", Mode: "block"}},
		{req: api.Request{Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "block", Source: "pool"},
			want: lease{Source: "pool", Serial: "0xc1af0001", Shared: true, SharedDevice: true, Mode: "block", ReadOnly: true}},
		{req: api.Request{Serial: "0xc1af0002", Mode: "block", Size: "512Mi"}, want: lease{Serial: "0xc1af0002", DeviceSource: "pool", Mode: "block", Size: "512Mi"}},
		{req: api.Request{Size: "256Mi", Mode: "block"}, want: lease{Size: "256Mi", Mode: "block"}},
		{req: api.Request{Serial: "0xc1ae0001", Mode: "block"}, err: "device 0xc1ae0001: mode block needs a persistent device"},
		{req: api.Request{Serial: "0xc1ee0001", Mode: "block", ReadOnly: true}, err: "device 0xc1ee0001: mode block needs a persistent device"},
		{req: api.Request{Serial: "0xc100e2e2", Shared: true, ReadOnly: true, Mode: "block"}, err: "device 0xc100e2e2: mode block needs a persistent device"},
		{req: api.Request{Serial: "0xc1ee0001", Shared: true, ReadOnly: true, Mode: "block"}, err: "device 0xc1ee0001: not shareable"},
	} {
		var l lease
		tc.req.Op = api.OpRequest
		noErr(t, tc.req.Validate())
		err := e.b.requestOptions(&l, &tc.req)
		switch {
		case tc.err != "" && (err == nil || err.Error() != tc.err):
			t.Errorf("%+v: expected error %q, got %v", tc.req, tc.err, err)
		case tc.err == "" && (err != nil || !reflect.DeepEqual(l, tc.want)):
			t.Errorf("%+v: got %+v %v, expected %+v", tc.req, l, err, tc.want)
		}
	}

	// without the pool driver only local memory can be leased
	e.b.cfg.PoolDriver = ""
	for _, tc := range []struct {
		req  api.Request
		want lease
		err  string
	}{
		{req: api.Request{Size: "1Gi", Source: "pool"}, err: "pool driver disabled (--pool-driver-name)"},
		{req: api.Request{Size: "1Gi", Source: "pool", Shared: true}, err: "pool driver disabled (--pool-driver-name)"},
		{req: api.Request{Size: "1Gi", Mode: "fs", ReadOnly: true}, err: "pool driver disabled (--pool-driver-name)"},
		{req: api.Request{Size: "1Gi", Mode: "block"}, err: "pool driver disabled (--pool-driver-name)"},
		// shared local devices serve --shared
		{req: api.Request{Shared: true, Size: "64Mi"}, want: lease{Shared: true, SharedDevice: true, Size: "64Mi", Mode: "dax"}},
		{req: api.Request{Serial: "0xc100e2e2", Shared: true}, want: lease{Serial: "0xc100e2e2", Shared: true, SharedDevice: true, DeviceSource: "local", Mode: "dax"}},
		{req: api.Request{Size: "1Gi"}, want: lease{Size: "1Gi", Mode: "numa"}},
		{req: api.Request{Size: "1Gi", Source: "local"}, want: lease{Source: "local", Size: "1Gi", Mode: "numa"}},
	} {
		var l lease
		tc.req.Op = api.OpRequest
		err := e.b.requestOptions(&l, &tc.req)
		switch {
		case tc.err != "" && (err == nil || err.Error() != tc.err):
			t.Errorf("no pool driver: %+v: expected error %q, got %v", tc.req, tc.err, err)
		case tc.err == "" && (err != nil || !reflect.DeepEqual(l, tc.want)):
			t.Errorf("no pool driver: %+v: got %+v %v, expected %+v", tc.req, l, err, tc.want)
		}
	}
}

// deviceConfigOf returns the DeviceConfig of driver of a companion claim,
// nil if it has none.
func deviceConfigOf(t *testing.T, c *resourceapi.ResourceClaim, driver string) *deviceConfig {
	t.Helper()
	for _, cfg := range c.Spec.Devices.Config {
		var dc deviceConfig
		noErr(t, json.Unmarshal(cfg.Opaque.Parameters.Raw, &dc))
		if cfg.Opaque.Driver == driver && dc.Kind == device.DeviceConfigKind {
			return &dc
		}
	}
	return nil
}

// leaseFdEnv is a broker and a pool driver with a fake dax device that
// records how it was opened.
type leaseFdEnv struct {
	*brokerEnv
	pe       *poolTestEnv
	p        *poolDriver
	mu       sync.Mutex
	readOnly []bool
}

func newLeaseFdEnv(t *testing.T, serial string) *leaseFdEnv {
	pe := newPoolTestEnv(t)
	pe.f.plug(serial)
	e := &leaseFdEnv{brokerEnv: newSlicesBrokerEnv(t), pe: pe, p: pe.driver(t)}
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	e.p.lender.set(e.lender, e.b)
	daxFile := filepath.Join(e.dir, "fake-dax")
	noErr(t, os.WriteFile(daxFile, []byte("TAG"), 0o600))
	e.b.openDevice = func(path string, readOnly bool) (*os.File, error) {
		if path != "/dev/dax0.0" {
			return nil, fmt.Errorf("unexpected dax %s", path)
		}
		e.mu.Lock()
		e.readOnly = append(e.readOnly, readOnly)
		e.mu.Unlock()
		return os.Open(daxFile)
	}
	return e
}

func (e *leaseFdEnv) opened() []bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.readOnly)
}

// prepareLease requests a lease in the background, waits for its companion
// claim, prepares it as the scheduler, the pool controller and kubelet
// would, and returns the claim and the response with its fd.
func (e *leaseFdEnv) prepareLease(req api.Request, dev, data string) (*resourceapi.ResourceClaim, api.Response, int) {
	e.t.Helper()
	type result struct {
		resp api.Response
		fd   int
	}
	ch := make(chan result, 1)
	go func() {
		r, fd := e.call(req)
		ch <- result{r, fd}
	}()
	claim := e.waitClaim("cxl-lease-000000a1")
	noErr(e.t, prepare(e.t, e.p, allocated(claim, dev, data)).Err)
	r := <-ch
	return claim, r.resp, r.fd
}

func TestBrokerExclusiveReadOnlySharedLease(t *testing.T) {
	e := newLeaseFdEnv(t, "0xc1ae0001")
	claim, resp, fd := e.prepareLease(api.Request{Op: "request", Serial: "0xc1ae0001", Mode: "dax", ReadOnly: true}, "shared0", sharedData)
	// no shares request: the whole device, so that nothing else gets it
	ex := claim.Spec.Devices.Requests[0].Exactly
	if ex == nil || ex.DeviceClassName != "cxl-pool-shared" || ex.Capacity != nil {
		t.Fatalf("exclusive request %+v", claim.Spec.Devices.Requests[0])
	}
	if dc := deviceConfigOf(t, claim, device.PoolDriverName); dc == nil || dc.Mode != api.ModeDax || !dc.ReadOnly {
		t.Fatalf("companion DeviceConfig %+v", dc)
	}
	e.wantDaxFd(resp, fd)
	if resp.Shared || !resp.ReadOnly || resp.Env["CXL_C1AE0001_SHARED"] != "1" || resp.Env["CXL_C1AE0001_READONLY"] != "1" {
		t.Fatalf("response %+v", resp)
	}
	// the fd is opened read-only, also when it is sent again
	resp, fd = e.call(api.Request{Op: "fd", Lease: resp.Lease})
	e.wantDaxFd(resp, fd)
	if got := e.opened(); !slices.Equal(got, []bool{true, true}) {
		t.Fatalf("dax opened read-only: %v", got)
	}
	e.wantReleaseAll(1)
}

func TestBrokerPoolDaxLease(t *testing.T) {
	e := newLeaseFdEnv(t, "0xc1ee0001")
	claim, resp, fd := e.prepareLease(api.Request{Op: "request", Source: "pool", Size: "256Mi", Mode: "dax"}, "pooled0", exclusiveData)
	ex := claim.Spec.Devices.Requests[0].Exactly
	if size := ex.Capacity.Requests["memory"]; ex.DeviceClassName != device.ClassPool || size.String() != "256Mi" {
		t.Fatalf("memory request %+v", ex)
	}
	if dc := deviceConfigOf(t, claim, device.PoolDriverName); dc == nil || dc.Mode != api.ModeDax || dc.ReadOnly {
		t.Fatalf("companion DeviceConfig %+v", dc)
	}
	e.pe.f.wantCommand(t, "daxctl reconfigure-device --mode=devdax --force dax0.0")
	e.pe.f.wantBlocks(t, "offline")
	e.wantDaxFd(resp, fd)
	if got := e.opened(); !slices.Equal(got, []bool{false}) {
		t.Fatalf("dax opened read-only: %v", got)
	}
	if calls := e.lender.callLog(); strings.Contains(calls, "lend") {
		t.Fatalf("dax memory lent as a node:\n%s", calls)
	}
	// a numa lease has its DeviceConfig too: the claim shows what was asked
	l := &lease{ID: "x", Source: "pool", Size: "1Gi", Mode: api.ModeNUMA, Pod: podRef{Namespace: testNS, Name: testPod, UID: testPodUID}}
	plain, _, err := e.b.companionObjects(l)
	noErr(t, err)
	if dc := deviceConfigOf(t, plain, device.PoolDriverName); dc == nil || dc.Mode != api.ModeNUMA || len(plain.Spec.Devices.Config) != 1 {
		t.Fatalf("numa companion configs %+v", plain.Spec.Devices.Config)
	}
	e.wantReleaseAll(1)
}

// wantDaxFd checks a Ready dax lease response that came with the fd of
// the fake dax device, and closes the fd.
func (e *leaseFdEnv) wantDaxFd(resp api.Response, fd int) {
	e.t.Helper()
	if resp.State != api.StateReady || resp.Mode != api.ModeDax || resp.Dax != "/dev/dax0.0" || resp.Node != nil || resp.Size != 268435456 || fd < 0 {
		e.t.Fatalf("response %+v fd %d", resp, fd)
	}
	f := os.NewFile(uintptr(fd), "dax")
	defer func() { _ = f.Close() }()
	buf := make([]byte, 3)
	if _, err := f.ReadAt(buf, 0); err != nil || string(buf) != "TAG" {
		e.t.Fatalf("read %q through the fd: %v", buf, err)
	}
}

// wantReleaseAll releases all leases of the pod and checks that the n
// leases are gone.
func (e *brokerEnv) wantReleaseAll(n int) {
	e.t.Helper()
	rel, _ := e.call(api.Request{Op: "release", All: true})
	if rel.Leases == nil || len(*rel.Leases) != n {
		e.t.Fatalf("release all %+v", rel)
	}
	for _, l := range *rel.Leases {
		if l.State != api.StateReleased {
			e.t.Fatalf("release all: %+v", l)
		}
	}
}

// opaqueConfig is a companion claim config: its driver, the requests it
// applies to and its parameters.
type opaqueConfig struct {
	driver   string
	requests []string
	params   string
}

// companionConfigsOf returns the configs of a companion claim.
func companionConfigsOf(c *resourceapi.ResourceClaim) []opaqueConfig {
	var out []opaqueConfig
	for _, cfg := range c.Spec.Devices.Config {
		out = append(out, opaqueConfig{driver: cfg.Opaque.Driver, requests: cfg.Requests, params: string(cfg.Opaque.Parameters.Raw)})
	}
	return out
}

// TestBrokerCompanionClaims checks the companion claim of every source,
// sharing and serial combination.
func TestBrokerCompanionClaims(t *testing.T) {
	e := newSlicesBrokerEnv(t)
	pod := podRef{Namespace: testNS, Name: testPod, UID: testPodUID}
	const (
		localNUMA = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"DeviceConfig","mode":"numa"}`
		localDax  = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"DeviceConfig","mode":"dax"}`
		localRO   = `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"DeviceConfig","mode":"dax","readOnly":true}`
		poolNUMA  = `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"numa"}`
		poolDax   = `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"dax"}`
		poolRO    = `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"dax","readOnly":true}`
		// no path: the companion pod gets no mount
		poolFsDirect = `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"fs","readOnly":true,"access":"direct"}`
		poolFsCached = `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"fs","readOnly":true,"access":"cached"}`
		poolBlock    = `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"block"}`
		poolBlockRO  = `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"block","readOnly":true}`
	)
	memory := func(q string) *resourceapi.CapacityRequirements {
		return &resourceapi.CapacityRequirements{Requests: map[resourceapi.QualifiedName]resource.Quantity{"memory": resource.MustParse(q)}}
	}
	share := &resourceapi.CapacityRequirements{Requests: map[resourceapi.QualifiedName]resource.Quantity{"shares": resource.MustParse("1")}}
	sel := func(exprs ...string) []resourceapi.DeviceSelector {
		var out []resourceapi.DeviceSelector
		for _, e := range exprs {
			out = append(out, resourceapi.DeviceSelector{CEL: &resourceapi.CELDeviceSelector{Expression: e}})
		}
		return out
	}
	serial := func(driver, serial string) string {
		return `device.attributes["` + driver + `"].serial == "` + serial + `"`
	}
	for _, tc := range []struct {
		name    string
		req     api.Request
		noPool  bool
		want    resourceapi.DeviceRequest
		configs []opaqueConfig
	}{
		{
			name: "local numa",
			req:  api.Request{Size: "128Mi", Source: "local"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-local", Capacity: memory("128Mi")}},
			configs: []opaqueConfig{{driver: "cxl.nri.io", params: localNUMA}},
		},
		{
			name: "local dax read-only of a device",
			req:  api.Request{Size: "64Mi", Source: "local", Mode: "dax", ReadOnly: true, Serial: "0xC100E2E1"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-local", Capacity: memory("64Mi"), Selectors: sel(serial("cxl.nri.io", "0xc100e2e1"))}},
			configs: []opaqueConfig{{driver: "cxl.nri.io", params: localRO}},
		},
		{
			name: "pool numa of a device",
			req:  api.Request{Size: "256Mi", Source: "pool", Serial: "0xc1ee0001"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool", Capacity: memory("256Mi"), Selectors: sel(serial("cxl-pool.nri.io", "0xc1ee0001"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolNUMA}},
		},
		{
			name: "local, then pool, dax",
			req:  api.Request{Size: "64Mi", Mode: "dax"},
			want: resourceapi.DeviceRequest{Name: "lease", FirstAvailable: []resourceapi.DeviceSubRequest{
				{Name: "local", DeviceClassName: "cxl-local", Capacity: memory("64Mi")},
				{Name: "pool", DeviceClassName: "cxl-pool", Capacity: memory("64Mi")},
			}},
			configs: []opaqueConfig{
				{driver: "cxl.nri.io", requests: []string{"lease/local"}, params: localDax},
				{driver: "cxl-pool.nri.io", requests: []string{"lease/pool"}, params: poolDax},
			},
		},
		{
			name: "numa of a local device: its source only",
			req:  api.Request{Size: "64Mi", Serial: "0xc100e2e1"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-local", Capacity: memory("64Mi"), Selectors: sel(serial("cxl.nri.io", "0xc100e2e1"))}},
			configs: []opaqueConfig{{driver: "cxl.nri.io", params: localNUMA}},
		},
		{
			name: "numa of a pool device: its source only",
			req:  api.Request{Size: "64Mi", Serial: "0xc1ee0001"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool", Capacity: memory("64Mi"), Selectors: sel(serial("cxl-pool.nri.io", "0xc1ee0001"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolNUMA}},
		},
		{
			name: "local, then pool, numa of a serial that no slice has",
			req:  api.Request{Size: "64Mi", Serial: "0x1234"},
			want: resourceapi.DeviceRequest{Name: "lease", FirstAvailable: []resourceapi.DeviceSubRequest{
				{Name: "local", DeviceClassName: "cxl-local", Capacity: memory("64Mi"), Selectors: sel(serial("cxl.nri.io", "0x1234"))},
				{Name: "pool", DeviceClassName: "cxl-pool", Capacity: memory("64Mi"), Selectors: sel(serial("cxl-pool.nri.io", "0x1234"))},
			}},
			configs: []opaqueConfig{
				{driver: "cxl.nri.io", requests: []string{"lease/local"}, params: localNUMA},
				{driver: "cxl-pool.nri.io", requests: []string{"lease/pool"}, params: poolNUMA},
			},
		},
		{
			name: "a share of a serial that no slice has, local then pool",
			req:  api.Request{Serial: "0x1234", Shared: true},
			want: resourceapi.DeviceRequest{Name: "lease", FirstAvailable: []resourceapi.DeviceSubRequest{
				{Name: "local", DeviceClassName: "cxl-local-shared", Capacity: share, Selectors: sel(serial("cxl.nri.io", "0x1234"))},
				{Name: "pool", DeviceClassName: "cxl-pool-shared", Capacity: share, Selectors: sel(serial("cxl-pool.nri.io", "0x1234"))},
			}},
			configs: []opaqueConfig{
				{driver: "cxl.nri.io", requests: []string{"lease/local"}, params: localDax},
				{driver: "cxl-pool.nri.io", requests: []string{"lease/pool"}, params: poolDax},
			},
		},
		{
			name:   "local without the pool driver",
			req:    api.Request{Size: "64Mi"},
			noPool: true,
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-local", Capacity: memory("64Mi")}},
			configs: []opaqueConfig{{driver: "cxl.nri.io", params: localNUMA}},
		},
		{
			name: "join a shared pool device",
			req:  api.Request{Serial: "0xc1ae0001", Shared: true, Source: "pool"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-shared", Capacity: share, Selectors: sel(serial("cxl-pool.nri.io", "0xc1ae0001"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolDax}},
		},
		{
			name: "a reader of a shared pool device without --source",
			req:  api.Request{Serial: "0xc1ae0001", Shared: true, ReadOnly: true},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-shared", Capacity: share, Selectors: sel(serial("cxl-pool.nri.io", "0xc1ae0001"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolRO}},
		},
		{
			name: "a reader of a shared local device without --source",
			req:  api.Request{Serial: "0xc100e2e2", Shared: true, ReadOnly: true},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-local-shared", Capacity: share, Selectors: sel(serial("cxl.nri.io", "0xc100e2e2"))}},
			configs: []opaqueConfig{{driver: "cxl.nri.io", params: localRO}},
		},
		{
			name: "a shared local device exclusively without --source",
			req:  api.Request{Serial: "0xc100e2e2"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-local-shared", Selectors: sel(serial("cxl.nri.io", "0xc100e2e2"))}},
			configs: []opaqueConfig{{driver: "cxl.nri.io", params: localDax}},
		},
		{
			name: "any shared device of a size, local then pool",
			req:  api.Request{Shared: true, Size: "256Mi"},
			want: resourceapi.DeviceRequest{Name: "lease", FirstAvailable: []resourceapi.DeviceSubRequest{
				{Name: "local", DeviceClassName: "cxl-local-shared", Capacity: share, Selectors: sel(`device.attributes["cxl.nri.io"].size >= 268435456`)},
				{Name: "pool", DeviceClassName: "cxl-pool-shared", Capacity: share, Selectors: sel(`device.attributes["cxl-pool.nri.io"].size >= 268435456`)},
			}},
			configs: []opaqueConfig{
				{driver: "cxl.nri.io", requests: []string{"lease/local"}, params: localDax},
				{driver: "cxl-pool.nri.io", requests: []string{"lease/pool"}, params: poolDax},
			},
		},
		{
			name: "a shared pool device exclusively (the writer)",
			req:  api.Request{Serial: "0xc1ae0001", Size: "128Mi", Source: "pool"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-shared",
				Selectors:       sel(serial("cxl-pool.nri.io", "0xc1ae0001"), `device.attributes["cxl-pool.nri.io"].size >= 134217728`)}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolDax}},
		},
		{
			name: "a shared pool device exclusively without --source",
			req:  api.Request{Serial: "0xc1ae0001"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-shared", Selectors: sel(serial("cxl-pool.nri.io", "0xc1ae0001"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolDax}},
		},
		{
			name: "a shared local device exclusively (the writer)",
			req:  api.Request{Serial: "0xc100e2e2", Source: "local"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-local-shared", Selectors: sel(serial("cxl.nri.io", "0xc100e2e2"))}},
			configs: []opaqueConfig{{driver: "cxl.nri.io", params: localDax}},
		},
		{
			name: "a reader of a shared local device",
			req:  api.Request{Serial: "0xc100e2e2", Shared: true, ReadOnly: true, Source: "local"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-local-shared", Capacity: share, Selectors: sel(serial("cxl.nri.io", "0xc100e2e2"))}},
			configs: []opaqueConfig{{driver: "cxl.nri.io", params: localRO}},
		},
		{
			name: "a share of any shared local device of a size",
			req:  api.Request{Shared: true, Size: "64Mi", Source: "local"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-local-shared", Capacity: share, Selectors: sel(`device.attributes["cxl.nri.io"].size >= 67108864`)}},
			configs: []opaqueConfig{{driver: "cxl.nri.io", params: localDax}},
		},
		{
			name: "fs of a share of a shared persistent device",
			req:  api.Request{Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-persistent", Capacity: share, Selectors: sel(serial("cxl-pool.nri.io", "0xc1af0001"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolFsDirect}},
		},
		{
			name: "fs cached of a shared persistent device, whole",
			req:  api.Request{Serial: "0xc1af0001", ReadOnly: true, Mode: "fs", Access: "cached", Name: "models"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-persistent", Selectors: sel(serial("cxl-pool.nri.io", "0xc1af0001"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolFsCached}},
		},
		{
			name: "fs of an exclusive persistent device",
			req:  api.Request{Serial: "0xc1af0002", ReadOnly: true, Mode: "fs", Size: "512Mi"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-persistent", Capacity: memory("512Mi"), Selectors: sel(serial("cxl-pool.nri.io", "0xc1af0002"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolFsDirect}},
		},
		{
			name: "fs of a share of any persistent device of a size: the pool only",
			req:  api.Request{Shared: true, ReadOnly: true, Mode: "fs", Size: "64Mi"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-persistent", Capacity: share, Selectors: sel(`device.attributes["cxl-pool.nri.io"].size >= 67108864`)}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolFsDirect}},
		},
		{
			name: "block of a shared persistent device, whole (the writer)",
			req:  api.Request{Serial: "0xc1af0001", Mode: "block"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-persistent", Selectors: sel(serial("cxl-pool.nri.io", "0xc1af0001"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolBlock}},
		},
		{
			name: "block of a share of a shared persistent device, read-only",
			req:  api.Request{Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "block"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-persistent", Capacity: share, Selectors: sel(serial("cxl-pool.nri.io", "0xc1af0001"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolBlockRO}},
		},
		{
			name: "block of an exclusive persistent device",
			req:  api.Request{Serial: "0xc1af0002", Mode: "block", Size: "512Mi"},
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-pool-persistent", Capacity: memory("512Mi"), Selectors: sel(serial("cxl-pool.nri.io", "0xc1af0002"))}},
			configs: []opaqueConfig{{driver: "cxl-pool.nri.io", params: poolBlock}},
		},
		{
			name:   "a share without the pool driver",
			req:    api.Request{Shared: true, Size: "64Mi"},
			noPool: true,
			want: resourceapi.DeviceRequest{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
				DeviceClassName: "cxl-local-shared", Capacity: share, Selectors: sel(`device.attributes["cxl.nri.io"].size >= 67108864`)}},
			configs: []opaqueConfig{{driver: "cxl.nri.io", params: localDax}},
		},
	} {
		e.b.cfg.PoolDriver = device.PoolDriverName
		if tc.noPool {
			e.b.cfg.PoolDriver = ""
		}
		l := &lease{ID: "x", Pod: pod, Container: testCtr}
		tc.req.Op = api.OpRequest
		noErr(t, tc.req.Validate())
		noErr(t, e.b.requestOptions(l, &tc.req))
		claim, _, err := e.b.companionObjects(l)
		noErr(t, err)
		if got := claim.Spec.Devices.Requests; len(got) != 1 || !reflect.DeepEqual(got[0], tc.want) {
			data, _ := json.Marshal(got)
			t.Errorf("%s: requests %s", tc.name, data)
		}
		if got := companionConfigsOf(claim); !reflect.DeepEqual(got, tc.configs) {
			t.Errorf("%s: configs\n%+v\nexpected\n%+v", tc.name, got, tc.configs)
		}
		wantLabels := map[string]string{"cxl.nri.io/lease": "x", "cxl.nri.io/requester-uid": testPodUID, "cxl.nri.io/node": testNode}
		if !reflect.DeepEqual(claim.Labels, wantLabels) {
			t.Errorf("%s: labels %v", tc.name, claim.Labels)
		}
	}
	// pool memory without the pool driver
	e.b.cfg.PoolDriver = ""
	_, _, err := e.b.companionObjects(&lease{ID: "x", Source: api.SourcePool, Shared: true, Mode: api.ModeDax, Pod: pod})
	wantErr(t, err, "pool driver disabled (--pool-driver-name)")
	_, _, err = e.b.companionObjects(&lease{ID: "x", Shared: true, ReadOnly: true, Mode: api.ModeFs, Access: api.AccessDirect, Pod: pod})
	wantErr(t, err, "pool driver disabled (--pool-driver-name)")
	_, _, err = e.b.companionObjects(&lease{ID: "x", Mode: api.ModeBlock, Serial: "0xc1af0001", SharedDevice: true, Pod: pod})
	wantErr(t, err, "pool driver disabled (--pool-driver-name)")
}

// newLocalLeaseEnv returns a broker env with the companionLender of the
// cxl.nri.io driver set up, and a fake dax device /dev/dax1.1.
func newLocalLeaseEnv(t *testing.T) (*brokerEnv, *companionLender) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	lender := newCompanionLender(device.DriverName)
	lender.set(e.lender, e.b)
	daxFile := filepath.Join(e.dir, "fake-dax")
	noErr(t, os.WriteFile(daxFile, []byte("TAG"), 0o600))
	e.b.openDevice = func(path string, readOnly bool) (*os.File, error) {
		if path != "/dev/dax1.1" || !readOnly {
			return nil, fmt.Errorf("unexpected dax %s read-only %v", path, readOnly)
		}
		return os.Open(daxFile)
	}
	return e, lender
}

// wantResponse checks a lease response, ignoring the lease id.
func wantResponse(t *testing.T, got, want api.Response) {
	t.Helper()
	want.Lease = got.Lease
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response %+v, expected %+v", got, want)
	}
}

// TestBrokerLocalDaxLease runs a dax lease through the broker with the
// hooks that the cxl.nri.io driver calls when the scheduler picked a
// local device: the response tells the source.
func TestBrokerLocalDaxLease(t *testing.T) {
	e, lender := newLocalLeaseEnv(t)
	ch := e.async(api.Request{Op: "request", Size: "64Mi", Mode: "dax", ReadOnly: true, Wait: "5s"})
	claim := e.waitClaim("cxl-lease-000000a1")
	if r := claim.Spec.Devices.Requests[0]; r.Exactly != nil || len(r.FirstAvailable) != 2 {
		t.Fatalf("local, then pool request %+v", r)
	}
	c := allocatedLocal(claim, "lease/local", localDeviceName)
	if id := leaseOf(c); id != "000000a1" {
		t.Fatalf("lease of the companion %q", id)
	}
	dc := &deviceConfig{}
	_, err := parseConfig(c, device.DriverName, device.DeviceConfigKind, "lease/local", dc)
	noErr(t, err)
	if mode, err := dc.modeFor(false); err != nil || mode != api.ModeDax || !dc.ReadOnly {
		t.Fatalf("DeviceConfig %+v: mode %q %v", dc, mode, err)
	}
	rec, err := lender.check("000000a1", c)
	noErr(t, err)
	devs := []lentDevice{{Driver: device.DriverName, Source: api.SourceLocal, Request: "lease/local", Device: localDeviceName,
		Serial: 0xc100e2e1, Size: 64 << 20, Mode: api.ModeDax, ReadOnly: true, Node: -1, DaxDevice: "/dev/dax1.1"}}
	noErr(t, lender.lend(context.Background(), rec, devs))
	if len(rec.Nodes) != 0 {
		t.Fatalf("dax slice lent as a node: %+v", rec)
	}
	lender.prepared("000000a1", devs)
	wantResponse(t, <-ch, api.Response{State: api.StateReady, Source: "local", Mode: "dax", ReadOnly: true,
		Size: 64 << 20, Serial: "0xc100e2e1", Dax: "/dev/dax1.1", Env: map[string]string{
			"CXL_C100E2E1_DAX": "/dev/dax1.1", "CXL_C100E2E1_MODE": "dax", "CXL_C100E2E1_READONLY": "1",
			"CXL_C100E2E1_SERIAL": "0xc100e2e1", "CXL_C100E2E1_SHARED": "0", "CXL_C100E2E1_SIZE": "67108864"}})
	e.wantReleaseAll(1)
}

// TestBrokerLocalNumaLease runs a source local numa lease through the
// broker with the hooks of the cxl.nri.io driver: the node is lent by
// the driver, re-applied and revoked by the broker.
func TestBrokerLocalNumaLease(t *testing.T) {
	e, lender := newLocalLeaseEnv(t)
	resp, _ := e.call(api.Request{Op: "request", Size: "128Mi", Source: "local", Wait: "0s"})
	wantResponse(t, resp, api.Response{State: api.StatePending, Source: "local", Mode: "numa", Size: 128 << 20})
	rec, err := lender.check(resp.Lease, e.waitClaim(companionName(resp.Lease)))
	noErr(t, err)
	devs := []lentDevice{{Driver: device.DriverName, Source: api.SourceLocal, Serial: 0xc100e2e2, Size: 128 << 20, Mode: api.ModeNUMA, Node: 2}}
	noErr(t, lender.lend(context.Background(), rec, devs))
	lender.prepared(resp.Lease, devs)
	e.waitState(resp.Lease, api.StateReady)
	list, _ := e.call(api.Request{Op: "list"})
	if list.Leases == nil || len(*list.Leases) != 1 {
		t.Fatalf("list %+v", list)
	}
	wantResponse(t, (*list.Leases)[0], api.Response{State: api.StateReady, Source: "local", Mode: "numa", Node: ptr(2),
		Size: 128 << 20, Serial: "0xc100e2e2", Env: map[string]string{"CXL_C100E2E2_MODE": "numa", "CXL_C100E2E2_NODE": "2",
			"CXL_C100E2E2_SERIAL": "0xc100e2e2", "CXL_C100E2E2_SHARED": "0", "CXL_C100E2E2_SIZE": "134217728"}})
	e.lender.mu.Lock()
	e.lender.lent = map[string]map[int][]string{}
	e.lender.mu.Unlock()
	e.b.reconcile()
	if got := e.lender.LentNodes(testPodUID, testCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("lend not re-applied: %v", got)
	}
	e.wantReleaseAll(1)
	if !strings.Contains(e.lender.callLog(), "revoke pod-uid-1/app 2") {
		t.Fatalf("local node not revoked:\n%s", e.lender.callLog())
	}
}

// TestBrokerDefaultLeaseFromPool prepares a lease without a source through
// the real pool driver: the scheduler took the pool subrequest, and the
// pool driver applies only its own configs of the claim.
func TestBrokerDefaultLeaseFromPool(t *testing.T) {
	e := newLeaseFdEnv(t, "0xc1ee0001")
	ch := make(chan api.Response, 1)
	go func() {
		r, fd := e.call(api.Request{Op: "request", Size: "256Mi", Mode: "dax"})
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		ch <- r
	}()
	claim := e.waitClaim("cxl-lease-000000a1")
	c := allocated(claim, "pooled0", exclusiveData)
	c.Status.Allocation.Devices.Results[0].Request = "lease/pool"
	noErr(t, prepare(t, e.p, c).Err)
	resp := <-ch
	if resp.State != api.StateReady || resp.Source != "pool" || resp.Mode != "dax" || resp.Dax != "/dev/dax0.0" || resp.Serial != "0xc1ee0001" {
		t.Fatalf("lease from the pool %+v", resp)
	}
	e.pe.f.wantCommand(t, "daxctl reconfigure-device --mode=devdax --force dax0.0")
	if l := e.lease(resp.Lease); l.Source != api.SourcePool {
		t.Fatalf("stored lease %+v", l)
	}
	e.wantReleaseAll(1)
}

// TestBrokerStrictStore starts with an empty lease table when the store
// cannot be decoded strictly.
func TestBrokerStrictStore(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.b.stop()
	path := filepath.Join(e.dir, leasesFileName)
	data, err := os.ReadFile(path)
	noErr(t, err)
	var store map[string]any
	noErr(t, json.Unmarshal(data, &store))
	store["leases"] = map[string]any{"0ld": map[string]any{
		"id": "0ld", "claim": testLeaseClaimUID, "kind": "memory", "size": "256Mi", "mode": "numa", "serial": "0xc1ee0001",
		"pod": map[string]any{"namespace": testNS, "name": testPod, "uid": testPodUID}, "container": testCtr,
		"state": "Ready", "node": 2, "bytes": 268435456, "created": "2026-10-01T00:00:00Z",
	}}
	data, err = json.Marshal(store)
	noErr(t, err)
	noErr(t, os.WriteFile(path, data, 0o600))
	e.b = nil
	e.restart()
	if len(e.b.store.Leases) != 0 || len(e.b.store.Claims) != 0 {
		t.Fatalf("loaded %+v", e.b.store)
	}
	// a store of this version loads
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.b.stop()
	e.b = nil
	e.restart()
	if len(e.b.store.Claims) != 1 {
		t.Fatalf("loaded %+v", e.b.store)
	}
}

// allocatedLocal returns the companion claim as the scheduler leaves it
// when it allocated a local memdev to request: the configs of the
// request's driver copied from the spec.
func allocatedLocal(c *resourceapi.ResourceClaim, request, dev string) *resourceapi.ResourceClaim {
	c = c.DeepCopy()
	c.UID = types.UID("uid-" + c.Name)
	var cfgs []resourceapi.DeviceAllocationConfiguration
	for _, sc := range c.Spec.Devices.Config {
		if len(sc.Requests) == 0 || slices.Contains(sc.Requests, request) {
			cfgs = append(cfgs, resourceapi.DeviceAllocationConfiguration{Source: resourceapi.AllocationConfigSourceClaim, Requests: sc.Requests, DeviceConfiguration: sc.DeviceConfiguration})
		}
	}
	c.Status.Allocation = &resourceapi.AllocationResult{Devices: resourceapi.DeviceAllocationResult{
		Results: []resourceapi.DeviceRequestAllocationResult{{Request: request, Driver: device.DriverName, Pool: testNode, Device: dev}},
		Config:  cfgs,
	}}
	return c
}

// TestBrokerTwoLeasesOneNode holds one NUMA node by two leases of a
// container (a local device and a pool device under one host bridge):
// releasing one keeps the node lent to the container.
func TestBrokerTwoLeasesOneNode(t *testing.T) {
	e, lender := newLocalLeaseEnv(t)
	pod := podRef{Namespace: testNS, Name: testPod, UID: testPodUID}
	var ids []string
	for _, source := range []string{"local", "pool"} {
		resp, _ := e.call(api.Request{Op: "request", Size: "64Mi", Source: source, Wait: "0s"})
		rec, err := lender.check(resp.Lease, e.waitClaim(companionName(resp.Lease)))
		noErr(t, err)
		devs := []lentDevice{{Source: source, Serial: 0xc100e2e1, Size: 64 << 20, Mode: api.ModeNUMA, Node: 2}}
		noErr(t, lender.lend(context.Background(), rec, devs))
		lender.prepared(resp.Lease, devs)
		e.waitState(resp.Lease, api.StateReady)
		ids = append(ids, resp.Lease)
	}
	if got := e.lender.holders(testPodUID, testCtr, 2); !slices.Equal(got, ids) {
		t.Fatalf("holders of node 2: %v, expected %v", got, ids)
	}

	// the reconcile re-applies the node for both leases
	e.lender.mu.Lock()
	e.lender.lent = map[string]map[int][]string{}
	e.lender.mu.Unlock()
	e.b.reconcile()
	if got := e.lender.holders(testPodUID, testCtr, 2); len(got) != 2 || !slices.Contains(got, ids[0]) || !slices.Contains(got, ids[1]) {
		t.Fatalf("holders after reconcile: %v", got)
	}

	rel, _ := e.call(api.Request{Op: "release", Lease: ids[0]})
	if rel.State != api.StateReleased {
		t.Fatalf("release %+v", rel)
	}
	noErr(t, lender.revoke(context.Background(), &lendRecord{Lease: ids[0], Pod: pod, Container: testCtr, Nodes: []int{2}}, "ns/c"))
	if got := e.lender.holders(testPodUID, testCtr, 2); !slices.Equal(got, ids[1:]) {
		t.Fatalf("holders after the first release: %v", got)
	}
	if got := e.lender.LentNodes(testPodUID, testCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("node revoked while a lease holds it: %v", got)
	}
	e.wantReleaseAll(1)
	if got := e.lender.LentNodes(testPodUID, testCtr); len(got) != 0 {
		t.Fatalf("still lent after both releases: %v", got)
	}
}

// toJSON returns v as JSON, for messages.
func toJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	return string(data)
}

// fsLeaseData is the claim status data of a share of llm0 of
// persistentPoolSlice.
const fsLeaseData = `{"serial":"0xc1af0001","shared":true,"size":536870912,"persistent":true}`

// leaseFsEnv is a broker and a pool driver with the shared persistent
// device llm0, whose labels have an fsdax namespace. Like kubelet, the
// fake client unprepares a companion claim through the pool driver when it
// is deleted, and keeps the claim while that fails.
type leaseFsEnv struct {
	*brokerEnv
	pe *poolTestEnv
	p  *poolDriver
}

func newLeaseFsEnv(t *testing.T) *leaseFsEnv {
	pe := newPoolTestEnv(t)
	pe.f.plugPersistent("0xc1af0001")
	pe.f.labels = true
	e := &leaseFsEnv{brokerEnv: newSlicesBrokerEnv(t), pe: pe}
	pe.leaseFsRoot = filepath.Join(e.dir, leaseFsDirName)
	e.mounts = pe.m.Mounts
	e.b.cfg.Mounts = pe.m.Mounts
	e.p = pe.driver(t)
	// added before the broker uses the client: the fake client does not
	// lock its reactor chain
	e.client.PrependReactor("delete", "resourceclaims", func(a k8stesting.Action) (bool, runtime.Object, error) {
		name := a.(k8stesting.DeleteAction).GetName()
		if !strings.HasPrefix(name, "cxl-lease-") {
			return false, nil, nil
		}
		uid := types.UID("uid-" + name)
		res, err := e.p.UnprepareResourceClaims(context.Background(), []kubeletplugin.NamespacedObject{{UID: uid}})
		if err != nil || res[uid] != nil {
			return true, nil, nil // kept until the next try
		}
		return false, nil, nil
	})
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	e.p.lender.set(e.lender, e.b)
	return e
}

// prepareFs requests a lease in the background, waits for its companion
// claim cxl-lease-<id>, prepares it as the scheduler, the pool controller
// and kubelet would, and returns the claim and the response with its fd.
func (e *leaseFsEnv) prepareFs(id string, req api.Request) (*resourceapi.ResourceClaim, api.Response, int) {
	e.t.Helper()
	type result struct {
		resp api.Response
		fd   int
	}
	ch := make(chan result, 1)
	go func() {
		r, fd := e.call(req)
		ch <- result{r, fd}
	}()
	claim := e.waitClaim(companionName(id))
	r := prepare(e.t, e.p, allocated(claim, "llm0", fsLeaseData))
	noErr(e.t, r.Err)
	e.pe.wantNoCDIDevices(e.t, r)
	res := <-ch
	return claim, res.resp, res.fd
}

// fsEnv returns the environment of an fs lease of llm0.
func fsEnv(access, path string) map[string]string {
	return map[string]string{"CXL_C1AF0001_ACCESS": access, "CXL_C1AF0001_MODE": "fs", "CXL_C1AF0001_PATH": path, "CXL_C1AF0001_READONLY": "1",
		"CXL_C1AF0001_SERIAL": "0xc1af0001", "CXL_C1AF0001_SHARED": "1", "CXL_C1AF0001_SIZE": "534773760"}
}

// TestBrokerFsLease runs fs leases through the broker and the pool driver:
// the companion claim, the bind in the lease-fs directory of the lease
// claim, the response, names, a release that waits for the borrower to
// close the files, and the removal of the lease-fs directory.
func TestBrokerFsLease(t *testing.T) {
	e := newLeaseFsEnv(t)
	ctx := context.Background()
	fsDir := filepath.Join(e.dir, "lease-fs", testLeaseClaimUID)
	direct, cached := e.p.nodeMountPath(0xc1af0001, "direct"), e.p.nodeMountPath(0xc1af0001, "cached")

	// a direct lease with the default name
	claim, resp, fd := e.prepareFs("000000a1", api.Request{Op: "request", Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs", Wait: "5s"})
	params := `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"fs","readOnly":true,"access":"direct"}`
	wantSpec := resourceapi.ResourceClaimSpec{Devices: resourceapi.DeviceClaim{
		Requests: []resourceapi.DeviceRequest{{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
			DeviceClassName: "cxl-pool-persistent",
			Selectors:       []resourceapi.DeviceSelector{{CEL: &resourceapi.CELDeviceSelector{Expression: `device.attributes["cxl-pool.nri.io"].serial == "0xc1af0001"`}}},
			Capacity:        &resourceapi.CapacityRequirements{Requests: map[resourceapi.QualifiedName]resource.Quantity{"shares": resource.MustParse("1")}},
		}}},
		Config: []resourceapi.DeviceClaimConfiguration{{DeviceConfiguration: resourceapi.DeviceConfiguration{Opaque: &resourceapi.OpaqueDeviceConfiguration{
			Driver: "cxl-pool.nri.io", Parameters: runtime.RawExtension{Raw: []byte(params)},
		}}}},
	}}
	if !reflect.DeepEqual(claim.Spec, wantSpec) {
		t.Fatalf("claim spec:\n%s", toJSON(claim.Spec))
	}
	if fd >= 0 {
		t.Fatalf("fd %d with an fs lease", fd)
	}
	wantResponse(t, resp, api.Response{State: api.StateReady, Source: "pool", Mode: "fs", Shared: true, ReadOnly: true, Access: "direct",
		Path: "/run/cxl/fs/000000a1", Size: fakePmemBytes, Serial: "0xc1af0001", Env: fsEnv("direct", "/run/cxl/fs/000000a1")})
	bind := filepath.Join(fsDir, "000000a1")
	if mi, _ := e.pe.m.Mounted(bind); mi == nil || mi.FsType != "erofs" || mi.Source != "/dev/pmem0" {
		t.Fatalf("bind %+v", mi)
	}
	if len(e.pe.m.callsOf(bindCall(direct, bind))) != 1 {
		t.Fatalf("not a bind of the node mount: %q", e.pe.m.callsOf(""))
	}
	// env: the same environment, no fd; fd: not a dax or block lease
	env, fd := e.call(api.Request{Op: "env", Lease: "000000a1"})
	if fd >= 0 || env.State != api.StateReady || !reflect.DeepEqual(env.Env, resp.Env) || env.Path != resp.Path {
		t.Fatalf("env %+v fd %d", env, fd)
	}
	r, fd := e.call(api.Request{Op: "fd", Lease: "000000a1"})
	if fd >= 0 || r.Error != "lease 000000a1 is not a dax or block lease; use env" || r.Mode != "fs" {
		t.Fatalf("fd of an fs lease %+v fd %d", r, fd)
	}

	// a cached lease with a name
	_, resp, _ = e.prepareFs("000000a2", api.Request{Op: "request", Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs",
		Access: "cached", Name: "models", Wait: "5s"})
	wantResponse(t, resp, api.Response{State: api.StateReady, Source: "pool", Mode: "fs", Shared: true, ReadOnly: true, Access: "cached",
		Path: "/run/cxl/fs/models", Size: fakePmemBytes, Serial: "0xc1af0001", Env: fsEnv("cached", "/run/cxl/fs/models")})
	models := filepath.Join(fsDir, "models")
	if mi, _ := e.pe.m.Mounted(models); mi == nil || mi.Source != "/dev/loop0" || len(e.pe.m.callsOf(bindCall(cached, models))) != 1 {
		t.Fatalf("bind %+v, calls %q", mi, e.pe.m.callsOf(""))
	}

	// names are unique per lease claim, default names included; nothing
	// is stored for a refused request
	for _, c := range []struct{ name, err string }{
		{"models", `name "models" is in use by lease 000000a2`},
		{"000000a1", `name "000000a1" is in use by lease 000000a1`},
	} {
		r, _ := e.call(api.Request{Op: "request", Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs", Name: c.name})
		if r.Error != c.err || r.Lease != "" {
			t.Errorf("name %s: %+v, expected %q", c.name, r, c.err)
		}
	}
	e.b.mu.Lock()
	n := len(e.b.store.Leases)
	e.b.mu.Unlock()
	if l, _ := e.client.ResourceV1().ResourceClaims(testNS).List(ctx, metav1.ListOptions{}); n != 2 || len(l.Items) != 3 {
		t.Fatalf("%d leases, %d claims after refused requests", n, len(l.Items))
	}

	// the store has the new fields after a restart
	e.restart()
	e.start()
	e.p.lender.set(e.lender, e.b)
	if l := e.lease("000000a2"); l == nil || l.Mode != "fs" || l.Access != "cached" || l.Name != "models" || l.Path != "/run/cxl/fs/models" || !l.ReadOnly {
		t.Fatalf("lease after a restart %+v", l)
	}
	if tc := e.b.store.Claims[testLeaseClaimUID]; tc == nil || tc.FsDir != fsDir {
		t.Fatalf("lease claim after a restart %+v", tc)
	}
	list, _ := e.call(api.Request{Op: "list"})
	if list.Leases == nil || len(*list.Leases) != 2 || (*list.Leases)[0].Path != "/run/cxl/fs/000000a1" || (*list.Leases)[1].Path != "/run/cxl/fs/models" {
		t.Fatalf("list %s", toJSON(list))
	}

	// release while the borrower has files of the bind open: the Unprepare
	// of the companion fails, the lease stays Releasing, the bind stays
	e.pe.m.setBusy(bind, true)
	rel, _ := e.call(api.Request{Op: "release", Lease: "000000a1", Wait: "200ms"})
	if rel.State != api.StateReleasing {
		t.Fatalf("release of a busy fs lease %+v", rel)
	}
	if mi, _ := e.pe.m.Mounted(bind); mi == nil {
		t.Fatal("busy bind unmounted")
	}
	if _, err := e.client.ResourceV1().ResourceClaims(testNS).Get(ctx, companionName("000000a1"), metav1.GetOptions{}); err != nil {
		t.Fatalf("companion claim of a busy bind: %v", err)
	}
	// the borrower closes the files: kubelet's next try succeeds
	e.pe.m.setBusy(bind, false)
	e.waitState("000000a1", api.StateReleased)
	e.wantGone(companionName("000000a1"))
	if _, err := os.Stat(bind); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bind directory left: %v", err)
	}

	// the pod ends with a busy bind: the lease-fs directory stays while
	// the bind is in it, also through a reconcile
	e.pe.m.setBusy(models, true)
	noErr(t, e.b.CloseClaim(ctx, testLeaseClaimUID))
	if _, err := os.Stat(models); err != nil {
		t.Fatalf("bind directory removed while mounted: %v", err)
	}
	// the socket is gone; the mount point of /run/cxl/fs stays with the bind
	if _, err := os.Stat(e.sock()); !os.IsNotExist(err) {
		t.Fatalf("socket left: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(e.sock()), "fs")); err != nil {
		t.Fatalf("mount point of /run/cxl/fs removed while a bind is in lease-fs: %v", err)
	}
	e.b.reconcile()
	if l := e.lease("000000a2"); l == nil || l.State != api.StateReleasing {
		t.Fatalf("lease %+v", l)
	}
	if _, err := os.Stat(models); err != nil {
		t.Fatalf("bind directory swept while mounted: %v", err)
	}
	// the bind goes, the lease is dropped and the directory removed
	e.pe.m.setBusy(models, false)
	e.waitState("000000a2", api.StateReleased)
	for _, d := range []string{fsDir, filepath.Dir(e.sock())} {
		if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directory %s left: %v", d, err)
		}
	}
	e.pe.f.wantReleased(t)
	e.pe.wantClean(t, e.p)
	e.pe.wantNoMounts(t, e.p)
}

// TestBrokerFsLeaseClaims checks the lease claims without a filesystem
// directory (B1) and the removal of lease-fs directories of closed lease
// claims.
func TestBrokerFsLeaseClaims(t *testing.T) {
	e := newSlicesBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()

	// a lease claim prepared by an older driver: no /run/cxl/fs in its
	// containers, no fs leases, also after OpenClaim again
	e.b.mu.Lock()
	e.b.store.Claims[testLeaseClaimUID].FsDir = ""
	e.b.mu.Unlock()
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.b.mu.Lock()
	dev := e.b.leaseCDIDevice(testLeaseClaimUID)
	fsDir := e.b.store.Claims[testLeaseClaimUID].FsDir
	e.b.mu.Unlock()
	if fsDir != "" || len(dev.ContainerEdits.Mounts) != 2 || dev.ContainerEdits.Mounts[1].ContainerPath != "/usr/local/bin/cxl-request" {
		t.Fatalf("FsDir %q, CDI mounts %s", fsDir, toJSON(dev.ContainerEdits.Mounts))
	}
	r, _ := e.call(api.Request{Op: "request", Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs"})
	if r.Error != "lease claim demo/lease has no filesystem directory (prepared by an older driver): recreate the pod" {
		t.Fatalf("fs lease of an old lease claim %+v", r)
	}
	e.b.mu.Lock()
	n := len(e.b.store.Leases)
	e.b.mu.Unlock()
	if l, _ := e.client.ResourceV1().ResourceClaims(testNS).List(context.Background(), metav1.ListOptions{}); len(l.Items) != 1 || n != 0 {
		t.Fatalf("objects for a refused request: %d claims, %d leases", len(l.Items), n)
	}
	// the other modes are served
	r, _ = e.call(api.Request{Op: "request", Size: "64Mi", Wait: "0s"})
	if r.Error != "" || r.State != api.StatePending {
		t.Fatalf("numa lease of an old lease claim %+v", r)
	}

	// lease-fs directories of claims not in the store are removed at
	// start and by the reconcile, unless a mount is in them
	root := filepath.Join(e.dir, "lease-fs")
	var mu sync.Mutex
	var mounts []mountInfo
	e.mounts = func() ([]mountInfo, error) {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(mounts), nil
	}
	for _, d := range []string{"gone/x", "gone/y", "held/x", "held/y", "nested/x/sub"} {
		noErr(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	mu.Lock()
	mounts = []mountInfo{{Target: filepath.Join(root, "held/x")}, {Target: filepath.Join(root, "nested/x/sub")}}
	mu.Unlock()
	e.restart()
	e.start()
	for d, exists := range map[string]bool{"gone": false, "held": true, "held/x": true, "held/y": false, "nested/x/sub": true} {
		if _, err := os.Stat(filepath.Join(root, d)); (err == nil) != exists {
			t.Errorf("%s exists %v, expected %v", d, err == nil, exists)
		}
	}
	mu.Lock()
	mounts = nil
	mu.Unlock()
	e.b.reconcile()
	// that of the open lease claim stays, and nothing is removed
	// recursively
	var left []string
	entries, _ := os.ReadDir(root)
	for _, d := range entries {
		left = append(left, d.Name())
	}
	if !slices.Equal(left, []string{testLeaseClaimUID, "nested"}) {
		t.Fatalf("lease-fs directories left: %v", left)
	}
}

// TestBrokerPreparedModeMismatch fails a lease whose companion device has
// mode fs or block when the lease is not in that mode, or the reverse.
func TestBrokerPreparedModeMismatch(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	for i, c := range []struct {
		req api.Request
		dev lentDevice
		err string
	}{
		{api.Request{Op: "request", Shared: true, ReadOnly: true, Mode: "fs", Size: "64Mi", Wait: "5s"},
			lentDevice{Source: api.SourcePool, Serial: 0xc1ae0001, Size: 1 << 28, Mode: api.ModeDax, Node: -1, DaxDevice: "/dev/dax0.0"},
			"companion prepared mode dax, lease is mode fs"},
		{api.Request{Op: "request", Source: "pool", Mode: "dax", Size: "64Mi", Wait: "5s"},
			lentDevice{Source: api.SourcePool, Serial: 0xc1af0001, Size: fakePmemBytes, Mode: api.ModeFs, Node: -1, Access: "direct"},
			"companion prepared mode fs, lease is mode dax"},
		{api.Request{Op: "request", Shared: true, ReadOnly: true, Mode: "block", Size: "64Mi", Wait: "5s"},
			lentDevice{Source: api.SourcePool, Serial: 0xc1af0001, Size: fakePmemBytes, Mode: api.ModeFs, Node: -1, Access: "direct", BlockDevice: "/dev/pmem0"},
			"companion prepared mode fs, lease is mode block"},
		{api.Request{Op: "request", Shared: true, ReadOnly: true, Mode: "fs", Size: "64Mi", Wait: "5s"},
			lentDevice{Source: api.SourcePool, Serial: 0xc1af0001, Size: fakePmemBytes, Mode: api.ModeBlock, ReadOnly: true, Node: -1, BlockDevice: "/dev/pmem0"},
			"companion prepared mode block, lease is mode fs"},
		{api.Request{Op: "request", Source: "pool", Mode: "block", Size: "64Mi", Wait: "5s"},
			lentDevice{Source: api.SourcePool, Serial: 0xc1ee0001, Size: 1 << 28, Mode: api.ModeDax, Node: -1, DaxDevice: "/dev/dax0.0"},
			"companion prepared mode dax, lease is mode block"},
	} {
		id := fmt.Sprintf("%08x", 0xa1+i)
		ch := e.async(c.req)
		e.waitClaim(companionName(id))
		_, err := e.b.OnLending(id, companionClaim(id))
		noErr(t, err)
		e.b.OnPrepared(id, []lentDevice{c.dev})
		if r := <-ch; r.State != api.StateFailed || r.Error != c.err || r.Path != "" || r.Block != "" {
			t.Errorf("%s: response %+v", c.err, r)
		}
		e.waitState(id, api.StateReleased)
		e.wantGone(companionName(id))
	}
}

// TestBrokerRemoveFsDirMountsError keeps a lease-fs directory when the
// mounts cannot be read.
func TestBrokerRemoveFsDirMountsError(t *testing.T) {
	e := newBrokerEnv(t)
	dir := filepath.Join(e.dir, "lease-fs", "gone")
	noErr(t, os.MkdirAll(filepath.Join(dir, "x"), 0o755))
	e.mounts = func() ([]mountInfo, error) { return nil, errors.New("no mountinfo") }
	e.restart() // the sweep at start
	e.b.mu.Lock()
	removed := e.b.removeFsDir("gone")
	e.b.mu.Unlock()
	if removed {
		t.Fatal("removed without mountinfo")
	}
	if _, err := os.Stat(filepath.Join(dir, "x")); err != nil {
		t.Fatalf("directory removed without mountinfo: %v", err)
	}
}

// TestBrokerRecoveredStoreKeepsDirs keeps the directories of lease claims
// at start when the lease table could not be decoded.
func TestBrokerRecoveredStoreKeepsDirs(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.b.stop()
	noErr(t, os.WriteFile(filepath.Join(e.dir, leasesFileName), []byte(`{"claims":{},"leases":{},"bogus":1}`), 0o600))
	e.b = nil
	e.restart()
	e.start()
	if !e.b.store.Recovered || len(e.b.store.Claims) != 0 {
		t.Fatalf("store %+v", e.b.store)
	}
	e.b.reconcile()
	for _, d := range []string{filepath.Join(e.dir, "lease-fs", testLeaseClaimUID), filepath.Join(filepath.Dir(e.sock()), "fs")} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("directory of a lease claim removed after a recovered store: %v", err)
		}
	}
	// a store of this version sweeps again after the next start
	e.b.stop()
	noErr(t, os.WriteFile(filepath.Join(e.dir, leasesFileName), []byte(`{"claims":{},"leases":{}}`), 0o600))
	e.b = nil
	e.restart()
	if e.b.store.Recovered {
		t.Fatal("recovered again")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "lease-fs", testLeaseClaimUID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory of an unknown lease claim kept: %v", err)
	}
}

// closingHooks closes the lease claim when the companion claim of one of
// its leases is being prepared, right after OnLending.
type closingHooks struct {
	*broker
	close func()
}

func (h *closingHooks) OnLending(id string, claim *resourceapi.ResourceClaim) (*lendRecord, error) {
	rec, err := h.broker.OnLending(id, claim)
	if err == nil && h.close != nil {
		h.close()
		h.close = nil
	}
	return rec, err
}

// TestBrokerFsLeaseCloseRace prepares the companion of an fs lease past
// OnLending while CloseClaim removes the lease-fs directory: the bind
// creates it again, the Unprepare of the companion unmounts the bind, and
// the reconcile removes the directories.
func TestBrokerFsLeaseCloseRace(t *testing.T) {
	pe := newPoolTestEnv(t)
	pe.f.plugPersistent("0xc1af0001")
	pe.f.labels = true
	e := newSlicesBrokerEnv(t)
	pe.leaseFsRoot = filepath.Join(e.dir, leaseFsDirName)
	e.mounts = pe.m.Mounts
	e.b.cfg.Mounts = pe.m.Mounts
	p := pe.driver(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	fsDir := filepath.Join(e.dir, "lease-fs", testLeaseClaimUID)
	bind := filepath.Join(fsDir, "models")
	closed := false
	p.lender.set(e.lender, &closingHooks{broker: e.b, close: func() {
		noErr(t, e.b.CloseClaim(context.Background(), testLeaseClaimUID))
		_, err := os.Stat(fsDir)
		closed = errors.Is(err, os.ErrNotExist)
	}})

	ch := e.async(api.Request{Op: "request", Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs", Name: "models", Wait: "5s"})
	claim := e.waitClaim(companionName("000000a1"))
	noErr(t, prepare(t, p, allocated(claim, "llm0", fsLeaseData)).Err)
	if !closed {
		t.Fatal("CloseClaim did not remove the lease-fs directory")
	}
	if r := <-ch; r.State == api.StateReady {
		t.Fatalf("lease of a closed claim Ready: %+v", r)
	}
	if mi, _ := pe.m.Mounted(bind); mi == nil {
		t.Fatal("no bind in the directory made again")
	}
	e.waitState("000000a1", api.StateReleased)
	e.b.reconcile()
	if _, err := os.Stat(bind); err != nil {
		t.Fatalf("bind directory swept while mounted: %v", err)
	}
	// kubelet unprepares the companion
	noErr(t, unprepare(t, p, "uid-cxl-lease-000000a1"))
	e.b.reconcile()
	for _, d := range []string{fsDir, filepath.Dir(e.sock())} {
		if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directory %s left: %v", d, err)
		}
	}
	pe.f.wantReleased(t)
	pe.wantClean(t, p)
	pe.wantNoMounts(t, p)
}

// blockWriterData is the claim status data of llm0 of persistentPoolSlice
// taken whole, exclusively.
const blockWriterData = `{"serial":"0xc1af0001","shared":true,"size":536870912,"persistent":true,"exclusive":true}`

// leaseBlockEnv is a leaseFsEnv whose broker opens a fake block device and
// records the paths and read-only settings of the opens.
type leaseBlockEnv struct {
	*leaseFsEnv
	mu     sync.Mutex
	opened []string // "<path> rw" or "<path> ro"
}

func newLeaseBlockEnv(t *testing.T) *leaseBlockEnv {
	e := &leaseBlockEnv{leaseFsEnv: newLeaseFsEnv(t)}
	pmem := filepath.Join(e.dir, "fake-pmem")
	noErr(t, os.WriteFile(pmem, []byte("BLK"), 0o600))
	e.b.openDevice = func(path string, readOnly bool) (*os.File, error) {
		access := "rw"
		if readOnly {
			access = "ro"
		}
		e.mu.Lock()
		e.opened = append(e.opened, path+" "+access)
		e.mu.Unlock()
		if path != "/dev/pmem0" {
			return nil, fmt.Errorf("unexpected device %s", path)
		}
		return os.Open(pmem)
	}
	return e
}

// opens returns the opens of the fake block device so far.
func (e *leaseBlockEnv) opens() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.opened)
}

// prepareBlock requests a lease in the background, waits for its companion
// claim cxl-lease-<id>, prepares it with the claim status data and returns
// the claim and the response with its fd.
func (e *leaseBlockEnv) prepareBlock(id string, req api.Request, data string) (*resourceapi.ResourceClaim, api.Response, int) {
	e.t.Helper()
	type result struct {
		resp api.Response
		fd   int
	}
	ch := make(chan result, 1)
	go func() {
		r, fd := e.call(req)
		ch <- result{r, fd}
	}()
	claim := e.waitClaim(companionName(id))
	r := prepare(e.t, e.p, allocated(claim, "llm0", data))
	noErr(e.t, r.Err)
	e.pe.wantNoCDIDevices(e.t, r)
	res := <-ch
	return claim, res.resp, res.fd
}

// wantBlockFd checks that fd is an fd of the fake block device, and closes
// it.
func (e *leaseBlockEnv) wantBlockFd(fd int) {
	e.t.Helper()
	if fd < 0 {
		e.t.Fatal("no fd with the response of a block lease")
	}
	f := os.NewFile(uintptr(fd), "pmem")
	defer func() { _ = f.Close() }()
	buf := make([]byte, 3)
	if _, err := f.ReadAt(buf, 0); err != nil || string(buf) != "BLK" {
		e.t.Fatalf("read %q through the fd: %v", buf, err)
	}
}

// blockEnv returns the environment of a block lease of llm0.
func blockEnv(readOnly string) map[string]string {
	return map[string]string{"CXL_C1AF0001_MODE": "block", "CXL_C1AF0001_PATH": "/dev/pmem0", "CXL_C1AF0001_READONLY": readOnly,
		"CXL_C1AF0001_SERIAL": "0xc1af0001", "CXL_C1AF0001_SHARED": "1", "CXL_C1AF0001_SIZE": "534773760"}
}

// TestBrokerBlockLease runs block leases of the shared persistent device
// llm0 through the broker and the pool driver: the writer takes the whole
// device and creates its fsdax namespace, a reader takes a share
// read-only; both get an fd of /dev/pmem0 with the response and with fd,
// none with env.
func TestBrokerBlockLease(t *testing.T) {
	e := newLeaseBlockEnv(t)
	e.pe.f.labels = false // a fresh device: the writer creates the namespace
	serialSel := []resourceapi.DeviceSelector{{CEL: &resourceapi.CELDeviceSelector{Expression: `device.attributes["cxl-pool.nri.io"].serial == "0xc1af0001"`}}}

	// the writer: the whole device, no capacity, read-write
	claim, resp, fd := e.prepareBlock("000000a1", api.Request{Op: "request", Serial: "0xc1af0001", Mode: "block", Wait: "5s"}, blockWriterData)
	params := `{"apiVersion":"cxl-pool.nri.io/v1alpha1","kind":"DeviceConfig","mode":"block"}`
	wantSpec := resourceapi.ResourceClaimSpec{Devices: resourceapi.DeviceClaim{
		Requests: []resourceapi.DeviceRequest{{Name: "lease", Exactly: &resourceapi.ExactDeviceRequest{
			DeviceClassName: "cxl-pool-persistent", Selectors: serialSel}}},
		Config: []resourceapi.DeviceClaimConfiguration{{DeviceConfiguration: resourceapi.DeviceConfiguration{Opaque: &resourceapi.OpaqueDeviceConfiguration{
			Driver: "cxl-pool.nri.io", Parameters: runtime.RawExtension{Raw: []byte(params)},
		}}}},
	}}
	if !reflect.DeepEqual(claim.Spec, wantSpec) {
		t.Fatalf("claim spec:\n%s", toJSON(claim.Spec))
	}
	if dc := deviceConfigOf(t, claim, device.PoolDriverName); dc == nil || dc.Mode != api.ModeBlock || dc.ReadOnly || dc.Access != "" || dc.Path != "" {
		t.Fatalf("companion DeviceConfig %+v", dc)
	}
	e.pe.f.wantCommand(t, "ndctl create-namespace -f -r region0 -m fsdax -M mem")
	e.wantBlockFd(fd)
	wantResponse(t, resp, api.Response{State: api.StateReady, Source: "pool", Mode: "block", Block: "/dev/pmem0",
		Size: fakePmemBytes, Serial: "0xc1af0001", Env: blockEnv("0")})
	if calls := e.lender.callLog(); strings.Contains(calls, "lend") {
		t.Fatalf("block device lent as a node:\n%s", calls)
	}
	if l := e.lease("000000a1"); l == nil || l.Block != "/dev/pmem0" || l.Node != -1 || l.Dax != "" || l.Path != "" {
		t.Fatalf("stored lease %+v", l)
	}
	if mounts, _ := e.pe.m.Mounts(); len(mounts) != 0 {
		t.Fatalf("mounts of a block lease %+v", mounts)
	}

	// the fd again, and the env without it
	r, fd := e.call(api.Request{Op: "fd", Lease: "000000a1", Wait: "1s"})
	e.wantBlockFd(fd)
	wantResponse(t, r, resp)
	env, fd := e.call(api.Request{Op: "env", Lease: "000000a1"})
	if fd >= 0 || !reflect.DeepEqual(env.Env, blockEnv("0")) || env.Block != "/dev/pmem0" {
		t.Fatalf("env %+v fd %d", env, fd)
	}
	if got := e.opens(); !slices.Equal(got, []string{"/dev/pmem0 rw", "/dev/pmem0 rw"}) {
		t.Fatalf("opens %v", got)
	}
	// the store has the block device after a restart
	e.restart()
	e.start()
	e.p.lender.set(e.lender, e.b)
	if l := e.lease("000000a1"); l == nil || l.Mode != "block" || l.Block != "/dev/pmem0" || l.ReadOnly {
		t.Fatalf("lease after a restart %+v", l)
	}
	e.wantReleaseAll(1)
	e.wantGone(companionName("000000a1"))
	e.pe.f.wantReleased(t)

	// a reader: one share, read-only; the namespace of the writer
	e.restart()
	e.start()
	e.p.lender.set(e.lender, e.b)
	pmem := filepath.Join(e.dir, "fake-pmem")
	e.b.openDevice = func(path string, readOnly bool) (*os.File, error) {
		if path != "/dev/pmem0" || !readOnly {
			return nil, fmt.Errorf("unexpected open of %s read-only %v", path, readOnly)
		}
		return os.Open(pmem)
	}
	claim, resp, fd = e.prepareBlock("000000a1", api.Request{Op: "request", Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "block", Wait: "5s"}, fsLeaseData)
	share := &resourceapi.CapacityRequirements{Requests: map[resourceapi.QualifiedName]resource.Quantity{"shares": resource.MustParse("1")}}
	if ex := claim.Spec.Devices.Requests[0].Exactly; ex == nil || ex.DeviceClassName != "cxl-pool-persistent" || !reflect.DeepEqual(ex.Capacity, share) ||
		!reflect.DeepEqual(ex.Selectors, serialSel) {
		t.Fatalf("reader request %s", toJSON(claim.Spec.Devices.Requests))
	}
	if dc := deviceConfigOf(t, claim, device.PoolDriverName); dc == nil || dc.Mode != api.ModeBlock || !dc.ReadOnly {
		t.Fatalf("companion DeviceConfig %+v", dc)
	}
	e.wantBlockFd(fd)
	wantResponse(t, resp, api.Response{State: api.StateReady, Source: "pool", Mode: "block", Shared: true, ReadOnly: true, Block: "/dev/pmem0",
		Size: fakePmemBytes, Serial: "0xc1af0001", Env: blockEnv("1")})
	if n := strings.Count(e.pe.f.commands(), "ndctl create-namespace"); n != 1 {
		t.Fatalf("ndctl create-namespace ran %d times:\n%s", n, e.pe.f.commands())
	}
	r, fd = e.call(api.Request{Op: "fd", Lease: "000000a1"})
	e.wantBlockFd(fd)
	if r.Error != "" || r.Block != "/dev/pmem0" {
		t.Fatalf("fd %+v", r)
	}
	e.wantReleaseAll(1)
	e.wantGone(companionName("000000a1"))
	e.pe.f.wantReleased(t)
	e.pe.wantClean(t, e.p)
	e.pe.wantNoMounts(t, e.p)
}

// TestBrokerBlockLeaseOpenError answers a block lease whose block device
// cannot be opened with the error, and keeps the lease.
func TestBrokerBlockLeaseOpenError(t *testing.T) {
	e := newLeaseBlockEnv(t)
	e.b.openDevice = func(path string, readOnly bool) (*os.File, error) {
		return nil, syscall.ENXIO
	}
	_, resp, fd := e.prepareBlock("000000a1", api.Request{Op: "request", Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "block", Wait: "5s"}, fsLeaseData)
	if fd >= 0 || resp.Error != "opening /dev/pmem0: no such device or address" || resp.State != api.StateReady {
		t.Fatalf("response %+v fd %d", resp, fd)
	}
	e.wantReleaseAll(1)
	e.pe.f.wantReleased(t)
}

// TestOpenBlockDevice opens a device read-write and read-only, waits for a
// node that appears, and fails at once with another error.
func TestOpenBlockDevice(t *testing.T) {
	dir := t.TempDir()
	dev := filepath.Join(dir, "pmem0")
	noErr(t, os.WriteFile(dev, []byte("BLK"), 0o600))
	for _, readOnly := range []bool{false, true} {
		f, err := openBlockDevice(dev, readOnly)
		noErr(t, err)
		_, werr := f.Write([]byte("x"))
		_ = f.Close()
		if (werr == nil) == readOnly {
			t.Fatalf("read-only %v: write error %v", readOnly, werr)
		}
	}
	late := filepath.Join(dir, "pmem1")
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.WriteFile(late, []byte("BLK"), 0o600)
	}()
	f, err := openBlockDevice(late, true)
	noErr(t, err)
	_ = f.Close()
	start := time.Now()
	if _, err := openBlockDevice(filepath.Join(dev, "x"), true); err == nil || time.Since(start) > time.Second {
		t.Fatalf("open below a file: %v after %v", err, time.Since(start))
	}
}

// restoringLender is a fakeLender that hears when the lends are restored.
type restoringLender struct {
	*fakeLender
	restored chan string // the call log at LendsRestored
}

func (l *restoringLender) LendsRestored() { l.restored <- l.callLog() }

// TestBrokerLendsRestored checks that the lender hears that the lends are
// restored once, after the first reconcile has lent the nodes of Ready numa
// leases again.
func TestBrokerLendsRestored(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	resp, _ := e.call(api.Request{Op: "request", Size: "256Mi", Wait: "0s"})
	id := resp.Lease
	_, err := e.b.OnLending(id, companionClaim(id))
	noErr(t, err)
	e.b.OnPrepared(id, []lentDevice{{Source: api.SourcePool, Serial: 0xc1ee0001, Size: 1 << 28, Mode: api.ModeNUMA, Node: 2}})
	e.waitState(id, api.StateReady)

	e.restart()
	e.lender.mu.Lock()
	e.lender.calls = nil
	e.lender.mu.Unlock()
	l := &restoringLender{fakeLender: e.lender, restored: make(chan string, 2)}
	e.b.reconcileEvery = 10 * time.Millisecond
	e.b.start(l)
	select {
	case calls := <-l.restored:
		if !strings.Contains(calls, "lend pod-uid-1/app 2") {
			t.Fatalf("lends restored before the lend:\n%s", calls)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lends not restored")
	}
	time.Sleep(50 * time.Millisecond) // more reconciles
	select {
	case <-l.restored:
		t.Fatal("lends restored twice")
	default:
	}
}
