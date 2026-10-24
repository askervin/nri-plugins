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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"

	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/client"
)

// fakePool is an in-memory fake-cxl-pool server.
type fakePool struct {
	mu      sync.Mutex
	hosts   []api.Host
	devices map[string]api.Device
	atts    map[string]api.Attachment
	// attachErr: device -> error code returned by attach
	attachErr map[string]string
	// detachHold: detach leaves the attachment detaching and returns 409
	detachHold bool
	attaches   []string // "device@host owner"
	attachReqs []api.AttachRequest
	detaches   []string // "device@host"
	counter    int
	// name is the name in GET /status, statuses counts the requests
	name     string
	statuses int
}

func newFakePool() *fakePool {
	return &fakePool{
		name: "fake-cxl-pool",
		hosts: []api.Host{
			{Name: "vm1", UUID: "b6a78455-edb1-558d-8cf1-01a259f76e97", State: api.HostRunning},
			{Name: "node2", UUID: "", State: api.HostRunning},
			{Name: "foreign", UUID: "11111111-2222-3333-4444-555555555555", State: api.HostRunning},
		},
		devices: map[string]api.Device{
			"pooled0":     {Name: "pooled0", Serial: "0xC1EE0001", Size: 512 << 20, Pool: "default", Scope: api.ScopePool, State: api.DeviceFree},
			"shared0":     {Name: "shared0", Serial: "0xc1ae0001", Size: 256 << 20, Shared: true, Pool: "default", Scope: api.ScopePool, State: api.DeviceFree},
			"bad0":        {Name: "bad0", Serial: "0xc1ee0002", Size: 256 << 20, Pool: "default", Scope: api.ScopePool, State: api.DeviceError},
			"weird.name_": {Name: "weird.name_", Serial: "0xc1ee0003", Size: 256 << 20, Pool: "default", Scope: api.ScopePool, State: api.DeviceFree},
			"vm1.memdev0": {Name: "vm1.memdev0", Serial: "0xc100e2e0", Size: 256 << 20, Pool: "default", Scope: api.ScopeLocal, State: api.DeviceFree},
		},
		atts:      map[string]api.Attachment{},
		attachErr: map[string]string{},
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, e *api.Error) {
	writeJSON(w, e.HTTPStatus(), e)
}

func (p *fakePool) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(api.RouteStatus, func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.statuses++
		writeJSON(w, 200, api.Status{Name: p.name})
	})
	mux.HandleFunc(api.RouteHosts, func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		writeJSON(w, 200, p.hosts)
	})
	mux.HandleFunc(api.RouteDevices, func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		scope := r.URL.Query().Get("scope")
		out := []api.Device{}
		for _, d := range p.devices {
			if scope == "" || d.Scope == scope {
				out = append(out, d)
			}
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc(api.RouteAttachments, func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		out := []api.Attachment{}
		for _, a := range p.atts {
			out = append(out, a)
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc(api.RouteDeviceAttach, func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		var req api.AttachRequest
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &req); err != nil {
			writeErr(w, api.InvalidArgument("%v", err))
			return
		}
		name := r.PathValue("name")
		d, ok := p.devices[name]
		if !ok {
			writeErr(w, api.NotFound("device %q not found", name))
			return
		}
		call := api.AttachmentID(name, req.Host) + " " + req.Owner
		if req.Exclusive {
			call += " exclusive"
		}
		p.attaches = append(p.attaches, call)
		p.attachReqs = append(p.attachReqs, req)
		if code := p.attachErr[name]; code != "" {
			writeErr(w, &api.Error{Code: code, Message: "injected " + code})
			return
		}
		id := api.AttachmentID(name, req.Host)
		for _, a := range p.atts {
			switch {
			case a.Device != name || a.Host == req.Host:
			case !d.Shared:
				writeErr(w, api.Conflict("device %q is not shared and it is attached to %q", name, a.Host))
				return
			case req.Exclusive || a.Exclusive:
				writeErr(w, api.Conflict("device %q is attached to %q (exclusive attach)", name, a.Host))
				return
			}
		}
		if a, ok := p.atts[id]; ok {
			a.Exclusive = req.Exclusive
			p.atts[id] = a
			writeJSON(w, 200, a)
			return
		}
		p.counter++
		bus := fmt.Sprintf("ds%d", p.counter)
		if req.Slot != "" {
			bus = req.Slot
		}
		a := api.Attachment{
			ID: id, Device: name, Host: req.Host, Serial: d.Serial, Owner: req.Owner,
			Slot:         api.Slot{Bus: bus},
			QemuDeviceID: fmt.Sprintf("fcp_%s.hp%d", name, p.counter),
			State:        api.AttachmentAttached,
			Exclusive:    req.Exclusive,
		}
		p.atts[id] = a
		writeJSON(w, 201, a)
	})
	mux.HandleFunc(api.RouteDeviceDetach, func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		id := api.AttachmentID(r.PathValue("name"), r.PathValue("host"))
		a, ok := p.atts[id]
		if !ok {
			writeErr(w, api.NotFound("not attached"))
			return
		}
		p.detaches = append(p.detaches, id)
		if p.detachHold {
			a.State = api.AttachmentDetaching
			p.atts[id] = a
			writeJSON(w, 409, &api.Error{Code: api.CodeConflict, Message: "guest did not release", Object: a})
			return
		}
		delete(p.atts, id)
		a.State = api.AttachmentDetached
		writeJSON(w, 200, a)
	})
	return mux
}

func (p *fakePool) addAttachment(a api.Attachment) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if a.ID == "" {
		a.ID = api.AttachmentID(a.Device, a.Host)
	}
	if a.State == "" {
		a.State = api.AttachmentAttached
	}
	p.atts[a.ID] = a
}

func (p *fakePool) calls() (attaches, detaches []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.attaches...), append([]string(nil), p.detaches...)
}

func (p *fakePool) attachmentIDs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for id := range p.atts {
		ids = append(ids, id)
	}
	return ids
}

type env struct {
	t    *testing.T
	ctx  context.Context
	pool *fakePool
	kube *fake.Clientset
	rec  *record.FakeRecorder
	c    *Controller
	logs *lockedBuf
}

// lockedBuf is a log buffer that tests read while the controller writes.
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(b)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// node returns a Node whose kubernetes.io/hostname label is "h-<name>".
func node(name, uuid string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name), Labels: map[string]string{corev1.LabelHostname: "h-" + name}},
		Status:     corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{SystemUUID: uuid}},
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, nil)
}

// newEnvWith is newEnv with the fake pool and the controller config
// modified by setup before the controller resolves its pool name.
func newEnvWith(t *testing.T, setup func(*fakePool, *Config)) *env {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := newFakePool()
	hs := httptest.NewServer(p.handler())
	t.Cleanup(hs.Close)
	kube := fake.NewClientset(
		// node1: vm1 by uuid (upper case, no dashes); node2: by name; node3: no host
		node("node1", "B6A78455EDB1558D8CF101A259F76E97"),
		node("node2", "00000000-0000-0000-0000-000000000002"),
		node("node3", "00000000-0000-0000-0000-000000000003"),
	)
	rec := record.NewFakeRecorder(100)
	logs := &lockedBuf{}
	cfg := Config{
		Logger:  log.New(io.MultiWriter(testWriter{t}, logs), "controller: ", 0),
		Verbose: true,
	}
	if setup != nil {
		setup(p, &cfg)
	}
	c := New(cfg, kube, client.New(hs.URL), rec)
	if _, err := c.resolvePoolName(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c.slices != nil {
			c.slices.Stop()
		}
		cancel()
		c.factory.Shutdown()
	})
	return &env{t: t, ctx: ctx, pool: p, kube: kube, rec: rec, c: c, logs: logs}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(b), "\n"))
	return len(b), nil
}

func (e *env) eventually(what string, f func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// sync runs one mapNodes + publish + reconcile.
func (e *env) sync() {
	e.t.Helper()
	hm, err := e.c.mapNodes(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.c.publish(e.ctx, hm); err != nil {
		e.t.Fatal(err)
	}
	if err := e.c.reconcile(e.ctx, hm); err != nil {
		e.t.Fatal(err)
	}
}

// createClaim creates a claim allocated with devName on node and waits
// until the lister has it.
func (e *env) createClaim(name, devName, nodeName string, shareID string) *resourceapi.ResourceClaim {
	e.t.Helper()
	return e.createClaimShares(name, devName, nodeName, shareID, 0)
}

// createClaimShares is createClaim with the shares capacity consumed by a
// shared device (0: no consumed capacity in the result).
func (e *env) createClaimShares(name, devName, nodeName string, shareID string, shares int64) *resourceapi.ResourceClaim {
	e.t.Helper()
	return e.createClaimConfig(name, devName, nodeName, shareID, shares, nil)
}

// createClaimConfig is createClaimShares with the config entries of the
// allocation.
func (e *env) createClaimConfig(name, devName, nodeName string, shareID string, shares int64, config []resourceapi.DeviceAllocationConfiguration) *resourceapi.ResourceClaim {
	e.t.Helper()
	r := resourceapi.DeviceRequestAllocationResult{
		Request: "mem", Driver: DefaultDriverName, Pool: DefaultPoolName, Device: devName,
		BindingConditions:        []string{DefaultDriverName + "/Attached"},
		BindingFailureConditions: []string{DefaultDriverName + "/AttachFailed"},
	}
	if shareID != "" {
		r.ShareID = ptr.To(types.UID(shareID))
	}
	if shares > 0 {
		r.ConsumedCapacity = map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: *resource.NewQuantity(shares, resource.DecimalSI)}
	}
	claim := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
		Status: resourceapi.ResourceClaimStatus{
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{Results: []resourceapi.DeviceRequestAllocationResult{
					// a result of another driver is ignored
					{Request: "local", Driver: "cxl.nri.io", Pool: "node1", Device: "region0-node2"},
					r,
				}, Config: config},
				NodeSelector: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{nodeName}}},
				}}},
			},
		},
	}
	claim, err := e.kube.ResourceV1().ResourceClaims("default").Create(e.ctx, claim, metav1.CreateOptions{})
	if err != nil {
		e.t.Fatal(err)
	}
	e.waitLister(name, func(c *resourceapi.ResourceClaim) bool { return c.Status.Allocation != nil })
	return claim
}

// waitLister waits until the lister has the claim and f(claim) is true,
// or, with f == nil, until the claim is gone.
func (e *env) waitLister(name string, f func(*resourceapi.ResourceClaim) bool) {
	e.t.Helper()
	e.eventually("lister: claim "+name, func() bool {
		c, err := e.c.claims.ResourceClaims("default").Get(name)
		if f == nil {
			return err != nil
		}
		return err == nil && f(c)
	})
}

// waitStatus waits until the lister sees n status entries of the claim.
func (e *env) waitStatus(name string, n int) {
	e.t.Helper()
	e.waitLister(name, func(c *resourceapi.ResourceClaim) bool { return len(c.Status.Devices) == n })
}

func (e *env) deallocate(name string) {
	e.t.Helper()
	c := e.claim(name)
	c.Status.Allocation = nil
	c.Status.Devices = nil
	if _, err := e.kube.ResourceV1().ResourceClaims("default").UpdateStatus(e.ctx, c, metav1.UpdateOptions{}); err != nil {
		e.t.Fatal(err)
	}
	e.waitLister(name, func(c *resourceapi.ResourceClaim) bool { return c.Status.Allocation == nil })
}

func (e *env) deleteClaim(name string) {
	e.t.Helper()
	if err := e.kube.ResourceV1().ResourceClaims("default").Delete(e.ctx, name, metav1.DeleteOptions{}); err != nil {
		e.t.Fatal(err)
	}
	e.waitLister(name, nil)
}

func (e *env) claim(name string) *resourceapi.ResourceClaim {
	e.t.Helper()
	c, err := e.kube.ResourceV1().ResourceClaims("default").Get(e.ctx, name, metav1.GetOptions{})
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// condition returns a condition of the pool device status entry, and the
// entry.
func (e *env) condition(name, condType string) (*metav1.Condition, *resourceapi.AllocatedDeviceStatus) {
	e.t.Helper()
	c := e.claim(name)
	for i := range c.Status.Devices {
		d := &c.Status.Devices[i]
		if d.Driver == DefaultDriverName && d.Pool == DefaultPoolName {
			return meta.FindStatusCondition(d.Conditions, condType), d
		}
	}
	return nil, nil
}

func (e *env) events() []string {
	var out []string
	for {
		select {
		case ev := <-e.rec.Events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func (e *env) slices() []resourceapi.ResourceSlice {
	e.t.Helper()
	l, err := e.kube.ResourceV1().ResourceSlices().List(e.ctx, metav1.ListOptions{})
	if err != nil {
		e.t.Fatal(err)
	}
	return l.Items
}

// (1) publish
func TestPublish(t *testing.T) {
	e := newEnv(t)
	e.sync()
	e.eventually("ResourceSlice", func() bool { return len(e.slices()) == 1 })
	slice := e.slices()[0]
	s := slice.Spec
	if s.Driver != DefaultDriverName || s.Pool.Name != DefaultPoolName || s.Pool.ResourceSliceCount != 1 ||
		s.AllNodes != nil || s.NodeName != nil || s.PerDeviceNodeSelection != nil {
		t.Fatalf("unexpected slice spec %+v", s)
	}
	// the nodes that are hosts of the server, by their hostname labels:
	// node1 (vm1 by uuid) and node2 (by name), not node3
	if got := selectorString(s.NodeSelector); got != "kubernetes.io/hostname In [h-node1 h-node2]" {
		t.Fatalf("node selector %s", got)
	}
	byName := map[string]resourceapi.Device{}
	for _, d := range s.Devices {
		byName[d.Name] = d
	}
	if len(byName) != 3 {
		t.Fatalf("expected pooled0, shared0, weird-name: %v", deviceNames(s.Devices))
	}
	if _, ok := byName["bad0"]; ok {
		t.Fatal("device in state error published")
	}
	// exactly the attributes of the contract: type, source, serial,
	// shared, persistent, size
	for _, name := range []string{"pooled0", "shared0"} {
		var keys []string
		for k := range byName[name].Attributes {
			keys = append(keys, string(k))
		}
		sort.Strings(keys)
		if got := strings.Join(keys, ","); got != "persistent,serial,shared,size,source,type" {
			t.Fatalf("%s: attributes %s", name, got)
		}
		if a := byName[name].Attributes; *a["type"].StringValue != "memdev" || *a["source"].StringValue != "pool" ||
			a["persistent"].BoolValue == nil || *a["persistent"].BoolValue {
			t.Fatalf("%s: type %q source %q", name, *a["type"].StringValue, *a["source"].StringValue)
		}
	}
	p := byName["pooled0"]
	memory := p.Capacity["memory"]
	if *p.Attributes["serial"].StringValue != "0xc1ee0001" || *p.Attributes["shared"].BoolValue ||
		*p.Attributes["size"].IntValue != 512<<20 || len(p.Capacity) != 1 ||
		!memory.Value.Equal(resource.MustParse("512Mi")) || p.AllowMultipleAllocations != nil ||
		!ptr.Deref(p.BindsToNode, false) ||
		strings.Join(p.BindingConditions, ",") != "cxl-pool.nri.io/Attached" ||
		strings.Join(p.BindingFailureConditions, ",") != "cxl-pool.nri.io/AttachFailed" {
		t.Fatalf("unexpected exclusive device %+v", p)
	}
	sh := byName["shared0"]
	// shares 1M without a requestPolicy: no request is exclusive
	shares, ok := sh.Capacity["shares"]
	if *sh.Attributes["serial"].StringValue != "0xc1ae0001" ||
		!*sh.Attributes["shared"].BoolValue || *sh.Attributes["size"].IntValue != 256<<20 ||
		!ptr.Deref(sh.AllowMultipleAllocations, false) || len(sh.Capacity) != 1 || !ok ||
		shares.Value.Value() != 1000000 || shares.Value.String() != "1M" || shares.RequestPolicy != nil ||
		!ptr.Deref(sh.BindsToNode, false) ||
		strings.Join(sh.BindingConditions, ",") != "cxl-pool.nri.io/Attached" ||
		strings.Join(sh.BindingFailureConditions, ",") != "cxl-pool.nri.io/AttachFailed" {
		t.Fatalf("unexpected shared device %+v", sh)
	}
	if _, ok := byName["weird-name"]; !ok {
		t.Fatalf("sanitized name missing: %v", deviceNames(s.Devices))
	}
	// a device change is published
	e.pool.mu.Lock()
	delete(e.pool.devices, "weird.name_")
	e.pool.mu.Unlock()
	e.sync()
	e.eventually("updated ResourceSlice", func() bool {
		l := e.slices()
		return len(l) == 1 && len(l[0].Spec.Devices) == 2
	})
	// shutdown deletes the slice
	e.c.shutdown()
	if l := e.slices(); len(l) != 0 {
		t.Fatalf("slices left after shutdown: %+v", l)
	}
}

func TestDeviceName(t *testing.T) {
	for in, want := range map[string]string{
		"pooled0":                      "pooled0",
		"Shared_0":                     "shared-0",
		"-a.b-":                        "a-b",
		"___":                          "",
		strings.Repeat("a", 62) + "_b": strings.Repeat("a", 62),
		strings.Repeat("x", 70):        strings.Repeat("x", 63),
	} {
		if got := DeviceName(in); got != want {
			t.Errorf("DeviceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDuplicateNamesSkipped(t *testing.T) {
	e := newEnv(t)
	devs, byName := e.c.buildDevices([]api.Device{
		{Name: "a.b", Scope: api.ScopePool, Size: 256 << 20},
		{Name: "a-b", Scope: api.ScopePool, Size: 256 << 20},
	})
	if len(devs) != 1 || byName["a-b"].Name != "a-b" {
		t.Fatalf("unexpected devices %v %v", deviceNames(devs), byName)
	}
}

func TestMapHosts(t *testing.T) {
	hm := mapHosts(newFakePool().hosts, []*corev1.Node{
		node("node1", "B6A78455EDB1558D8CF101A259F76E97"),
		node("node2", "x"),
		node("node3", ""),
		node("vm1", ""), // vm1 is taken by node1's uuid
	})
	if hm.String() != "[node1=vm1 node2=node2]" || hm.hostNode["vm1"] != "node1" {
		t.Fatalf("unexpected map %s", hm)
	}
}

// (2) allocated claim on a known node
func TestAttachAndStatus(t *testing.T) {
	e := newEnv(t)
	claim := e.createClaim("pooled-memory", "pooled0", "node1", "")
	e.sync()
	att, _ := e.pool.calls()
	if len(att) != 1 || att[0] != "pooled0@vm1 k8s:resourceclaim/"+string(claim.UID) {
		t.Fatalf("unexpected attach requests %v", att)
	}
	cond, st := e.condition("pooled-memory", "cxl-pool.nri.io/Attached")
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "Attached" ||
		cond.Message != "pooled0 attached to vm1 (slot ds1)" {
		t.Fatalf("unexpected condition %+v", cond)
	}
	var data map[string]any
	if err := json.Unmarshal(st.Data.Raw, &data); err != nil {
		t.Fatal(err)
	}
	if data["serial"] != "0xc1ee0001" || data["shared"] != false || data["size"] != float64(512<<20) ||
		data["host"] != "vm1" || data["hostUUID"] != "b6a78455-edb1-558d-8cf1-01a259f76e97" ||
		data["attachment"] != "pooled0@vm1" || data["qemuDeviceId"] != "fcp_pooled0.hp1" || st.ShareID != nil {
		t.Fatalf("unexpected data %s", st.Data.Raw)
	}
	if ev := e.events(); len(ev) != 1 || !strings.HasPrefix(ev[0], "Normal Attached pooled0 attached to vm1") {
		t.Fatalf("unexpected events %v", ev)
	}
	// steady state: no new requests, no status writes
	e.waitStatus("pooled-memory", 1)
	rv := e.claim("pooled-memory").ResourceVersion
	e.sync()
	if att, det := e.pool.calls(); len(att) != 1 || len(det) != 0 {
		t.Fatalf("unexpected requests %v %v", att, det)
	}
	if e.claim("pooled-memory").ResourceVersion != rv {
		t.Fatal("status rewritten in steady state")
	}
}

// (3) node without host
func TestNoHost(t *testing.T) {
	e := newEnv(t)
	e.createClaim("c3", "pooled0", "node3", "")
	e.sync()
	if att, _ := e.pool.calls(); len(att) != 0 {
		t.Fatalf("unexpected attach %v", att)
	}
	cond, _ := e.condition("c3", "cxl-pool.nri.io/AttachFailed")
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != ReasonNoHost {
		t.Fatalf("unexpected condition %+v", cond)
	}
	if ev := e.events(); len(ev) != 1 || !strings.HasPrefix(ev[0], "Warning AttachFailed") {
		t.Fatalf("unexpected events %v", ev)
	}
	// written once
	e.waitStatus("c3", 1)
	e.sync()
	if ev := e.events(); len(ev) != 0 {
		t.Fatalf("unexpected events %v", ev)
	}
}

// (4) attach 409
func TestAttachConflict(t *testing.T) {
	e := newEnv(t)
	e.pool.mu.Lock()
	e.pool.attachErr["pooled0"] = api.CodeConflict
	e.pool.mu.Unlock()
	e.createClaim("c4", "pooled0", "node2", "")
	e.sync()
	cond, _ := e.condition("c4", "cxl-pool.nri.io/AttachFailed")
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != ReasonConflict || !strings.Contains(cond.Message, "injected Conflict") {
		t.Fatalf("unexpected condition %+v", cond)
	}
	if c, _ := e.condition("c4", "cxl-pool.nri.io/Attached"); c != nil {
		t.Fatalf("unexpected Attached condition %+v", c)
	}
	// the conflict goes away: Attached replaces AttachFailed
	e.pool.mu.Lock()
	delete(e.pool.attachErr, "pooled0")
	e.pool.mu.Unlock()
	e.waitStatus("c4", 1)
	e.sync()
	if c, _ := e.condition("c4", "cxl-pool.nri.io/Attached"); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("expected Attached, got %+v", c)
	}
	if c, _ := e.condition("c4", "cxl-pool.nri.io/AttachFailed"); c != nil {
		t.Fatalf("AttachFailed not cleared: %+v", c)
	}
}

// (5) allocation removed
func TestDetachOnDeallocation(t *testing.T) {
	e := newEnv(t)
	e.createClaim("c5", "pooled0", "node2", "")
	e.sync()
	if ids := e.pool.attachmentIDs(); len(ids) != 1 || ids[0] != "pooled0@node2" {
		t.Fatalf("unexpected attachments %v", ids)
	}
	e.events()
	e.deallocate("c5")
	// the guest has not released the device: 409, the attachment stays
	// detaching, and is not requested again while it is detaching
	e.pool.mu.Lock()
	e.pool.detachHold = true
	e.pool.mu.Unlock()
	e.sync()
	e.sync()
	if _, det := e.pool.calls(); len(det) != 1 {
		t.Fatalf("unexpected detach requests %v", det)
	}
	// the server gave up the device_del and reports it attached again: retried
	e.pool.mu.Lock()
	e.pool.detachHold = false
	a := e.pool.atts["pooled0@node2"]
	a.State = api.AttachmentAttached
	e.pool.atts["pooled0@node2"] = a
	e.pool.mu.Unlock()
	e.sync()
	if ids := e.pool.attachmentIDs(); len(ids) != 0 {
		t.Fatalf("attachments left: %v", ids)
	}
	if ev := e.events(); len(ev) != 1 || !strings.HasPrefix(ev[0], "Normal Detached pooled0 detached from node2") {
		t.Fatalf("unexpected events %v", ev)
	}
}

// (6) restart: the attachment exists, the status is missing
func TestRestartWithExistingAttachment(t *testing.T) {
	e := newEnv(t)
	claim := e.createClaimShares("c6", "shared0", "node1", "share-1", 1)
	e.pool.addAttachment(api.Attachment{Device: "shared0", Host: "vm1", Serial: "0xc1ae0001", Owner: e.c.Owner(claim.UID),
		Slot: api.Slot{Bus: "ds9"}, QemuDeviceID: "fcp_shared0.hp7"})
	e.sync()
	if att, det := e.pool.calls(); len(att) != 0 || len(det) != 0 {
		t.Fatalf("unexpected requests %v %v", att, det)
	}
	cond, st := e.condition("c6", "cxl-pool.nri.io/Attached")
	if cond == nil || cond.Message != "shared0 attached to vm1 (slot ds9)" || st.ShareID == nil || *st.ShareID != "share-1" {
		t.Fatalf("unexpected status %+v %+v", cond, st)
	}
	var data DeviceData
	if err := json.Unmarshal(st.Data.Raw, &data); err != nil || !data.Shared || data.Serial != "0xc1ae0001" ||
		data.Size != 256<<20 || data.QemuDeviceID != "fcp_shared0.hp7" {
		t.Fatalf("unexpected data %s %v", st.Data.Raw, err)
	}
}

// (7) two claims, same shared device, same node
func TestSharedTwoClaimsOneNode(t *testing.T) {
	e := newEnv(t)
	e.createClaimShares("a", "shared0", "node1", "share-a", 1)
	e.createClaimShares("b", "shared0", "node1", "share-b", 1)
	e.sync()
	att, _ := e.pool.calls()
	if len(att) != 1 || att[0] != "shared0@vm1 k8s:resourceclaim/uid-a" {
		t.Fatalf("unexpected attach requests %v", att)
	}
	for _, n := range []string{"a", "b"} {
		c, st := e.condition(n, "cxl-pool.nri.io/Attached")
		if c == nil {
			t.Fatalf("claim %s: no Attached condition", n)
		}
		// one share each: not exclusive
		var data DeviceData
		if err := json.Unmarshal(st.Data.Raw, &data); err != nil || data.Exclusive {
			t.Fatalf("claim %s: data %s %v", n, st.Data.Raw, err)
		}
	}
	// the claim that owns the attachment goes first: still attached
	e.deleteClaim("a")
	e.sync()
	if _, det := e.pool.calls(); len(det) != 0 {
		t.Fatalf("detached while claim b uses it: %v", det)
	}
	e.deallocate("b")
	e.sync()
	if _, det := e.pool.calls(); len(det) != 1 || det[0] != "shared0@vm1" {
		t.Fatalf("unexpected detach requests %v", det)
	}
}

// (8) other owners and foreign hosts
func TestForeignAttachmentsKept(t *testing.T) {
	e := newEnv(t)
	e.pool.addAttachment(api.Attachment{Device: "pooled0", Host: "vm1", Owner: "manual"})
	e.pool.addAttachment(api.Attachment{Device: "shared0", Host: "vm1", Owner: "", Adopted: true})
	e.pool.addAttachment(api.Attachment{Device: "shared0", Host: "foreign", Owner: "k8s:resourceclaim/other-cluster"})
	e.pool.addAttachment(api.Attachment{Device: "weird.name_", Host: "node2", Owner: "k8s:resourceclaim/gone", State: api.AttachmentFailed, Error: "zombie"})
	e.sync()
	e.sync()
	if _, det := e.pool.calls(); len(det) != 0 {
		t.Fatalf("unexpected detach requests %v", det)
	}
	if ids := e.pool.attachmentIDs(); len(ids) != 4 {
		t.Fatalf("attachments changed: %v", ids)
	}
}

func TestExclusiveMovesBetweenNodes(t *testing.T) {
	e := newEnv(t)
	e.createClaim("m", "pooled0", "node1", "")
	e.sync()
	// reallocated to node2: the attach conflicts until vm1 is detached in
	// the same reconcile, without AttachFailed; the next one attaches
	e.deleteClaim("m")
	e.createClaim("m2", "pooled0", "node2", "")
	e.sync()
	if c, _ := e.condition("m2", "cxl-pool.nri.io/AttachFailed"); c != nil {
		t.Fatalf("unexpected AttachFailed %+v", c)
	}
	e.sync()
	if c, _ := e.condition("m2", "cxl-pool.nri.io/Attached"); c == nil {
		t.Fatal("not attached after the move")
	}
	if ids := e.pool.attachmentIDs(); len(ids) != 1 || ids[0] != "pooled0@node2" {
		t.Fatalf("unexpected attachments %v", ids)
	}
}

func TestExclusiveSharedClaim(t *testing.T) {
	e := newEnv(t)
	// all of the shares: attached exclusively
	e.createClaimShares("w", "shared0", "node1", "share-w", device.SharesUnlimited)
	e.sync()
	if att, _ := e.pool.calls(); len(att) != 1 || att[0] != "shared0@vm1 k8s:resourceclaim/uid-w exclusive" {
		t.Fatalf("unexpected attach requests %v", att)
	}
	c, st := e.condition("w", "cxl-pool.nri.io/Attached")
	if c == nil || !strings.Contains(string(st.Data.Raw), `"exclusive":true`) {
		t.Fatalf("claim w: condition %+v data %s", c, st.Data.Raw)
	}
	// readers on the same node right after the writer: the attachment
	// stays, its flag is dropped
	e.deallocate("w")
	e.createClaimShares("r1", "shared0", "node1", "share-r1", 1)
	e.sync()
	att, det := e.pool.calls()
	if len(det) != 0 || len(att) != 2 || att[1] != "shared0@vm1 k8s:resourceclaim/uid-r1" {
		t.Fatalf("attach %v detach %v", att, det)
	}
	if c, st := e.condition("r1", "cxl-pool.nri.io/Attached"); c == nil || strings.Contains(string(st.Data.Raw), `"exclusive"`) {
		t.Fatalf("claim r1: condition %+v data %s", c, st.Data.Raw)
	}
	// and the other way round: an exclusive claim (no shares consumed
	// in the result) on the node of the reader sets the flag before it
	// is Attached
	e.deallocate("r1")
	e.createClaimShares("w2", "shared0", "node1", "share-w2", 0)
	e.sync()
	if att, _ = e.pool.calls(); len(att) != 3 || att[2] != "shared0@vm1 k8s:resourceclaim/uid-w2 exclusive" {
		t.Fatalf("attach %v", att)
	}
	if c, _ := e.condition("w2", "cxl-pool.nri.io/Attached"); c == nil {
		t.Fatal("claim w2: no Attached condition")
	}
}

func TestExclusiveSharedConflict(t *testing.T) {
	e := newEnv(t)
	// another cluster has the device: an exclusive attach conflicts
	e.pool.addAttachment(api.Attachment{Device: "shared0", Host: "foreign", Owner: "k8s:resourceclaim/other-cluster"})
	e.createClaimShares("w", "shared0", "node1", "share-w", device.SharesUnlimited)
	e.sync()
	c, _ := e.condition("w", "cxl-pool.nri.io/AttachFailed")
	if c == nil || c.Reason != ReasonConflict {
		t.Fatalf("claim w: AttachFailed %+v", c)
	}
	if c, _ := e.condition("w", "cxl-pool.nri.io/Attached"); c != nil {
		t.Fatalf("claim w: Attached %+v", c)
	}
	// an exclusive device is never attached with the flag
	if e.c.exclusiveResult(&resourceapi.DeviceRequestAllocationResult{Device: "pooled0",
		ConsumedCapacity: map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse("1M")}}) {
		t.Fatal("pooled0 is exclusive")
	}
}

func TestExclusiveResult(t *testing.T) {
	e := newEnv(t)
	e.sync()
	for _, tc := range []struct {
		name     string
		consumed map[resourceapi.QualifiedName]resource.Quantity
		want     bool
	}{
		{"all shares", map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse("1M")}, true},
		{"one share", map[resourceapi.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse("1")}, false},
		{"shares missing", nil, true},
		{"other capacity only", map[resourceapi.QualifiedName]resource.Quantity{"memory": resource.MustParse("1Gi")}, true},
	} {
		r := &resourceapi.DeviceRequestAllocationResult{Device: "shared0", ConsumedCapacity: tc.consumed}
		if got := e.c.exclusiveResult(r); got != tc.want {
			t.Errorf("%s: exclusive %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPersistentAttributeAndStatus(t *testing.T) {
	e := newEnv(t)
	e.pool.mu.Lock()
	e.pool.devices["llm0"] = api.Device{Name: "llm0", Serial: "0xc1ae0002", Size: 512 << 20, Shared: true, Persistent: true,
		Pool: "default", Scope: api.ScopePool, State: api.DeviceFree}
	e.pool.mu.Unlock()
	e.sync()
	e.eventually("ResourceSlice", func() bool { return len(e.slices()) == 1 })
	attrs := map[string]map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{}
	for _, d := range e.slices()[0].Spec.Devices {
		attrs[d.Name] = d.Attributes
	}
	for name, want := range map[string]bool{"llm0": true, "shared0": false, "pooled0": false} {
		if a := attrs[name]["persistent"]; a.BoolValue == nil || *a.BoolValue != want {
			t.Fatalf("%s: attribute persistent %+v, want %v", name, a, want)
		}
	}
	// status data: persistent true for llm0, omitted for volatile devices
	e.createClaimShares("w", "llm0", "node1", "share-w", device.SharesUnlimited)
	e.createClaim("p", "pooled0", "node1", "")
	e.sync()
	for claim, want := range map[string]any{"w": true, "p": nil} {
		c, st := e.condition(claim, "cxl-pool.nri.io/Attached")
		if c == nil {
			t.Fatalf("claim %s: no Attached condition", claim)
		}
		var data map[string]any
		if err := json.Unmarshal(st.Data.Raw, &data); err != nil {
			t.Fatal(err)
		}
		if data["persistent"] != want {
			t.Fatalf("claim %s: data %s, want persistent %v", claim, st.Data.Raw, want)
		}
		if claim == "w" && (data["serial"] != "0xc1ae0002" || data["shared"] != true || data["size"] != float64(512<<20) || data["exclusive"] != true) {
			t.Fatalf("claim w: unexpected data %s", st.Data.Raw)
		}
	}
}
