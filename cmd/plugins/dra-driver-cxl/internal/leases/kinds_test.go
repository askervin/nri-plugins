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

package leases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// The leases of every kind through the broker and the real plugins of both
// drivers on the fake kernel: the request, the companion claim and pod,
// the Prepare of the companion (the scheduler's allocation and kubelet
// done by the test), READY with the response, the release (the companion
// deleted, its claim unprepared by the fake kubelet of the env), the
// devices released.

// fdEnv is a leaseEnv whose broker opens a fake device for the fds of the
// responses and records the paths and read-only settings of the opens.
type fdEnv struct {
	*leaseEnv
	mu     sync.Mutex
	opened []string // "<path> rw" or "<path> ro"
}

// newFdEnv returns a node with the devices, a fake device for fds and the
// ResourceSlices of the pool and the node in the API; the broker is started
// with the env's lease claim open.
func newFdEnv(t *testing.T, local []fake.MemdevSpec, pool ...fake.MemdevSpec) *fdEnv {
	e := &fdEnv{leaseEnv: newLeaseEnv(t, local, pool...)}
	tag := filepath.Join(t.TempDir(), "fake-device")
	mustOK(t, os.WriteFile(tag, []byte("TAG"), 0o600))
	e.opts = func(o *Options) {
		o.OpenDevice = func(path string, readOnly bool) (*os.File, error) {
			access := "rw"
			if readOnly {
				access = "ro"
			}
			e.mu.Lock()
			e.opened = append(e.opened, path+" "+access)
			e.mu.Unlock()
			return os.Open(tag)
		}
	}
	e.restart()
	e.addSlices(poolSlice(), persistentPoolSlice(), localResourceSlice())
	e.openClaim()
	e.start()
	return e
}

// opens returns the opens of the fake device so far.
func (e *fdEnv) opens() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.opened)
}

// wantFd checks that fd is an fd of the fake device, and closes it.
func wantFd(t *testing.T, fd int) {
	t.Helper()
	if fd < 0 {
		t.Fatal("no fd with the response")
	}
	f := os.NewFile(uintptr(fd), "device")
	defer func() { _ = f.Close() }()
	buf := make([]byte, 3)
	if _, err := f.ReadAt(buf, 0); err != nil || string(buf) != "TAG" {
		t.Fatalf("read %q through the fd: %v", buf, err)
	}
}

// wantResponse checks a lease response, ignoring the lease id.
func wantResponse(t *testing.T, got, want api.Response) {
	t.Helper()
	want.Lease = got.Lease
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response\n%+v\nexpected\n%+v", got, want)
	}
}

// requestPool requests a lease in the background, prepares its companion
// cxl-lease-<id> through the pool driver on the pool device dev with the
// status data, and returns the companion claim and the response with its
// fd.
func (e *leaseEnv) requestPool(id string, req api.Request, dev, data string) (*resourcev1.ResourceClaim, fdResponse) {
	e.t.Helper()
	ch := e.callFd(req)
	claim := e.waitClaim(CompanionName(id))
	r := e.prepare(e.pool, allocatedPool(claim, dev, data))
	mustOK(e.t, r.Err)
	e.wantNoCDIDevices(r)
	return claim, <-ch
}

// requestLocal requests a lease in the background, prepares its companion
// cxl-lease-<id> through cxl.nri.io on the local memdev with the serial,
// and returns the companion claim and the response with its fd.
func (e *leaseEnv) requestLocal(id string, req api.Request, serial uint64) (*resourcev1.ResourceClaim, fdResponse) {
	e.t.Helper()
	ch := e.callFd(req)
	claim := e.waitClaim(CompanionName(id))
	r := e.prepare(e.local, allocatedLocal(claim, dra.MemdevDeviceName(serial)))
	mustOK(e.t, r.Err)
	e.wantNoCDIDevices(r)
	return claim, <-ch
}

// deviceConfigOf returns the device section of the MemoryConfig of driver
// of a companion claim, nil if it has none.
func deviceConfigOf(t *testing.T, c *resourcev1.ResourceClaim, driver string) *config.Device {
	t.Helper()
	for _, cfg := range c.Spec.Devices.Config {
		if cfg.Opaque.Driver != driver {
			continue
		}
		var mc config.MemoryConfig
		mustOK(t, json.Unmarshal(cfg.Opaque.Parameters.Raw, &mc))
		if mc.APIVersion != config.APIVersion || mc.Kind != config.Kind || mc.Container != nil || mc.Pool != nil || mc.Device == nil {
			t.Fatalf("companion config of %s: %s", driver, cfg.Opaque.Parameters.Raw)
		}
		return mc.Device
	}
	return nil
}

// A pool numa lease: the companion claim and pod exactly, the node lent at
// the Prepare, the response, the requestId, list, env and fd; a started
// container gets the node again; the release revokes it, deletes the
// companion, whose Unprepare releases the region.
func TestPoolNumaLease(t *testing.T) {
	e := newLeaseEnv(t, nil, fake.MemdevSpec{Serial: serialPoolX})
	e.openClaim()
	e.start()
	ch := e.async(api.Request{Op: api.OpRequest, Source: "pool", Size: "256Mi", Wait: "5s", RequestID: "r1"})
	name := "cxl-lease-000000a1"
	claim := e.waitClaim(name)
	e.waitState("000000a1", state.LeasePending)

	params := `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"numa"}}`
	wantSpec := resourcev1.ResourceClaimSpec{Devices: resourcev1.DeviceClaim{
		Requests: []resourcev1.DeviceRequest{{Name: "lease", Exactly: &resourcev1.ExactDeviceRequest{
			DeviceClassName: "cxl-pool",
			Capacity:        &resourcev1.CapacityRequirements{Requests: map[resourcev1.QualifiedName]resource.Quantity{"memory": resource.MustParse("256Mi")}},
		}}},
		Config: []resourcev1.DeviceClaimConfiguration{{DeviceConfiguration: resourcev1.DeviceConfiguration{Opaque: &resourcev1.OpaqueDeviceConfiguration{
			Driver: "cxl-pool.nri.io", Parameters: runtime.RawExtension{Raw: []byte(params)},
		}}}},
	}}
	if !reflect.DeepEqual(claim.Spec, wantSpec) {
		got, _ := json.Marshal(claim.Spec)
		t.Fatalf("claim spec:\n%s", got)
	}
	if want := []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: envPod, UID: envPodUID, Controller: ptr(true)}}; !reflect.DeepEqual(claim.OwnerReferences, want) {
		t.Fatalf("claim owners %+v", claim.OwnerReferences)
	}
	wantLabels := map[string]string{"cxl.nri.io/lease": "000000a1", "cxl.nri.io/requester-uid": envPodUID, "cxl.nri.io/node": envNode}
	if !reflect.DeepEqual(claim.Labels, wantLabels) || !reflect.DeepEqual(claim.Annotations, map[string]string{"cxl.nri.io/requester": "demo/borrower/app"}) {
		t.Fatalf("claim labels %v, annotations %v", claim.Labels, claim.Annotations)
	}
	pod, err := e.client.CoreV1().Pods(envNS).Get(context.Background(), name, metav1.GetOptions{})
	mustOK(t, err)
	if !reflect.DeepEqual(pod.Labels, wantLabels) || !reflect.DeepEqual(pod.OwnerReferences, []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: envPod, UID: envPodUID}}) {
		t.Fatalf("pod labels %v, owners %+v", pod.Labels, pod.OwnerReferences)
	}
	res := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("16Mi")}
	wantPodSpec := corev1.PodSpec{
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{envNode}}}}},
		}}},
		Tolerations:                   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
		RestartPolicy:                 corev1.RestartPolicyAlways,
		AutomountServiceAccountToken:  ptr(false),
		EnableServiceLinks:            ptr(false),
		TerminationGracePeriodSeconds: ptr(int64(1)),
		SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true), RunAsUser: ptr(int64(65535)), RunAsGroup: ptr(int64(65535)),
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		ResourceClaims: []corev1.PodResourceClaim{{Name: "lease", ResourceClaimName: ptr(name)}},
		Containers: []corev1.Container{{
			Name: "pause", Image: "registry.k8s.io/pause:3.10",
			Resources: corev1.ResourceRequirements{Requests: res, Limits: res},
			SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr(false), ReadOnlyRootFilesystem: ptr(true),
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
		}},
	}
	if !reflect.DeepEqual(pod.Spec, wantPodSpec) {
		got, _ := json.Marshal(pod.Spec)
		t.Fatalf("pod spec:\n%s", got)
	}

	alloc := allocatedPool(claim, "pooled0", poolExclusiveData)
	r := e.prepare(e.pool, alloc)
	mustOK(t, r.Err)
	if len(r.Devices) != 1 || len(r.Devices[0].CDIDeviceIDs) != 0 {
		t.Fatalf("CDI devices of a companion claim: %+v", r.Devices)
	}
	if got := e.ctrs.lentNodes(envPodUID, envCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("lent nodes %v", got)
	}
	numaEnv := map[string]string{"CXL_C1EE0001_MODE": "numa", "CXL_C1EE0001_NODE": "2", "CXL_C1EE0001_SERIAL": "0xc1ee0001",
		"CXL_C1EE0001_SHARED": "0", "CXL_C1EE0001_SIZE": "268435456"}
	wantResponse(t, <-ch, api.Response{State: api.StateReady, Source: "pool", Mode: "numa", Node: ptr(2), Size: 268435456, Serial: "0xc1ee0001", Env: numaEnv})
	data, _ := os.ReadFile(filepath.Join(e.poolDir, "preparedPoolClaims.json"))
	if !strings.Contains(string(data), `"lease": "000000a1"`) || !strings.Contains(string(data), `"nodes": [`) {
		t.Fatalf("lend not in the view of the pool claims:\n%s", data)
	}
	if l := e.stored("000000a1"); l == nil || l.Lend == nil || state.NumaNodeOf(l.Lend.NumaNode) != 2 {
		t.Fatalf("the lease's lend %+v", l)
	}
	if g := e.st.Snapshot().Grant(state.GrantRef{Claim: string(alloc.UID)}); g == nil || g.Got.Lend == nil || g.Got.Lend.Lease != "000000a1" ||
		state.NumaNodeOf(g.Got.Lend.NumaNode) != 2 {
		t.Fatalf("the companion grant's lend %+v", g)
	}

	again, _ := e.call(api.Request{Op: api.OpRequest, Source: "pool", Size: "256Mi", RequestID: "r1"})
	if again.Lease != "000000a1" || again.State != api.StateReady {
		t.Fatalf("retry with requestId: %+v", again)
	}
	list, _ := e.call(api.Request{Op: api.OpList})
	if list.Leases == nil || len(*list.Leases) != 1 || (*list.Leases)[0].Lease != "000000a1" || (*list.Leases)[0].Env["CXL_C1EE0001_NODE"] != "2" {
		t.Fatalf("list %+v", list)
	}
	env, fd := e.call(api.Request{Op: api.OpEnv, Lease: "000000a1"})
	if fd >= 0 || env.State != api.StateReady || !reflect.DeepEqual(env.Env, again.Env) {
		t.Fatalf("env %+v fd %d", env, fd)
	}
	resp, fd := e.call(api.Request{Op: api.OpFd, Lease: "000000a1"})
	if fd >= 0 || resp.Error != "lease 000000a1 is not a dax or block lease; use env" || resp.Mode != "numa" {
		t.Fatalf("fd of a numa lease %+v fd %d", resp, fd)
	}

	e.ctrs.forget()
	e.ctrs.started[0](requester.Pod, envCtr)
	if got := e.ctrs.lentNodes(envPodUID, envCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("not lent again after a restart of the container: %v", got)
	}

	rel, _ := e.call(api.Request{Op: api.OpRelease, Lease: "000000a1"})
	if rel.State != api.StateReleased {
		t.Fatalf("release %+v", rel)
	}
	e.wantGone(name)
	if !strings.Contains(e.ctrs.callLog(), "revoke pod-uid-1/app 2") || len(e.ctrs.lentNodes(envPodUID, envCtr)) != 0 {
		t.Fatalf("not revoked:\n%s", e.ctrs.callLog())
	}
	e.wantNoRegions()
	e.check("released")
}

// A pool dax lease: the memory stays offline as devdax, the fd of the dax
// device goes with the response; a numa lease's claim has its device
// section too.
func TestPoolDaxLease(t *testing.T) {
	e := newFdEnv(t, nil, fake.MemdevSpec{Serial: serialPoolX})
	claim, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Source: "pool", Size: "256Mi", Mode: "dax", Wait: "5s"}, "pooled0", poolExclusiveData)
	ex := claim.Spec.Devices.Requests[0].Exactly
	if size := ex.Capacity.Requests["memory"]; ex.DeviceClassName != device.ClassPool || size.String() != "256Mi" {
		t.Fatalf("memory request %+v", ex)
	}
	if dc := deviceConfigOf(t, claim, device.PoolDriverName); dc == nil || dc.Mode != api.ModeDax || dc.IsReadOnly() {
		t.Fatalf("companion device section %+v", dc)
	}
	dax := filepath.Join(e.k.DevRoot(), "dax0.0")
	wantFd(t, r.fd)
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "pool", Mode: "dax", Size: 268435456, Serial: "0xc1ee0001", Dax: dax,
		Env: map[string]string{"CXL_C1EE0001_DAX": dax, "CXL_C1EE0001_MODE": "dax", "CXL_C1EE0001_READONLY": "0", "CXL_C1EE0001_SERIAL": "0xc1ee0001",
			"CXL_C1EE0001_SHARED": "0", "CXL_C1EE0001_SIZE": "268435456"}})
	if got := e.k.DaxDriver("dax0.0"); got != "device_dax" || e.onlineBlocks() != 0 {
		t.Fatalf("dax driver %s, %d memory blocks online", got, e.onlineBlocks())
	}
	if got := e.opens(); !slices.Equal(got, []string{dax + " rw"}) {
		t.Fatalf("opens %v", got)
	}
	if calls := e.ctrs.callLog(); strings.Contains(calls, "lend") {
		t.Fatalf("dax memory lent as a node:\n%s", calls)
	}
	if l := e.stored("000000a1"); l == nil || l.Lend != nil || l.Got == nil || l.Got.Dax != dax {
		t.Fatalf("stored lease %+v", l)
	}
	e.wantReleaseAll(1)
	e.wantGone("cxl-lease-000000a1")
	e.wantNoRegions()
}

// A share of a shared pool device: one share, mode dax, the fd again with
// fd, none with env; nothing lent as a node.
func TestPoolSharedLeaseFd(t *testing.T) {
	e := newFdEnv(t, nil, fake.MemdevSpec{Serial: serialPoolS})
	claim, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Serial: "0xC1AE0001", Shared: true, Source: "pool"}, "shared0", poolSharedData)
	want := resourcev1.ExactDeviceRequest{
		DeviceClassName: "cxl-pool-shared",
		Selectors:       []resourcev1.DeviceSelector{{CEL: &resourcev1.CELDeviceSelector{Expression: `device.attributes["cxl-pool.nri.io"].serial == "0xc1ae0001"`}}},
		Capacity:        &resourcev1.CapacityRequirements{Requests: map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse("1")}},
	}
	if !reflect.DeepEqual(*claim.Spec.Devices.Requests[0].Exactly, want) {
		t.Fatalf("shared request %+v", claim.Spec.Devices.Requests[0].Exactly)
	}
	dax := filepath.Join(e.k.DevRoot(), "dax0.0")
	sharedEnv := map[string]string{"CXL_C1AE0001_DAX": dax, "CXL_C1AE0001_MODE": "dax", "CXL_C1AE0001_READONLY": "0",
		"CXL_C1AE0001_SERIAL": "0xc1ae0001", "CXL_C1AE0001_SHARED": "1", "CXL_C1AE0001_SIZE": "268435456"}
	wantFd(t, r.fd)
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "pool", Mode: "dax", Shared: true, Size: 268435456, Serial: "0xc1ae0001",
		Dax: dax, Env: sharedEnv})
	resp, fd := e.call(api.Request{Op: api.OpFd, Lease: "000000a1", Wait: "1s"})
	wantFd(t, fd)
	wantResponse(t, resp, r.resp)
	resp, fd = e.call(api.Request{Op: api.OpEnv, Lease: "000000a1"})
	if fd >= 0 || !reflect.DeepEqual(resp.Env, sharedEnv) {
		t.Fatalf("env %+v fd %d", resp, fd)
	}
	if got := e.opens(); !slices.Equal(got, []string{dax + " rw", dax + " rw"}) || strings.Contains(e.ctrs.callLog(), "lend") {
		t.Fatalf("opens %v, calls %s", got, e.ctrs.callLog())
	}
	// the fd is only for the requester container
	other := requester
	other.Container = "sidecar"
	e.ctrs.setPeer(&other)
	if resp, fd := e.call(api.Request{Op: api.OpFd, Lease: "000000a1"}); fd >= 0 || resp.Error != "no such lease of this container" {
		t.Fatalf("fd of another container %+v %d", resp, fd)
	}
	if resp, _ := e.call(api.Request{Op: api.OpEnv, Lease: "000000a1"}); resp.Error != "" || resp.State != api.StateReady {
		t.Fatalf("env of another container %+v", resp)
	}
	e.ctrs.setPeer(&requester)
	e.wantReleaseAll(1)
	e.wantGone("cxl-lease-000000a1")
}

// A shared pool device taken whole, read-only: no shares request, the fd
// opened read-only, also when it is sent again.
func TestExclusiveReadOnlySharedLease(t *testing.T) {
	e := newFdEnv(t, nil, fake.MemdevSpec{Serial: serialPoolS})
	claim, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Serial: "0xc1ae0001", Mode: "dax", ReadOnly: true}, "shared0",
		`{"serial":"0xc1ae0001","shared":true,"size":268435456,"exclusive":true}`)
	if ex := claim.Spec.Devices.Requests[0].Exactly; ex == nil || ex.DeviceClassName != "cxl-pool-shared" || ex.Capacity != nil {
		t.Fatalf("exclusive request %+v", claim.Spec.Devices.Requests[0])
	}
	if dc := deviceConfigOf(t, claim, device.PoolDriverName); dc == nil || dc.Mode != api.ModeDax || !dc.IsReadOnly() {
		t.Fatalf("companion device section %+v", dc)
	}
	wantFd(t, r.fd)
	dax := filepath.Join(e.k.DevRoot(), "dax0.0")
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "pool", Mode: "dax", ReadOnly: true, Size: 268435456, Serial: "0xc1ae0001",
		Dax: dax, Env: map[string]string{"CXL_C1AE0001_DAX": dax, "CXL_C1AE0001_MODE": "dax", "CXL_C1AE0001_READONLY": "1",
			"CXL_C1AE0001_SERIAL": "0xc1ae0001", "CXL_C1AE0001_SHARED": "1", "CXL_C1AE0001_SIZE": "268435456"}})
	again, fd := e.call(api.Request{Op: api.OpFd, Lease: r.resp.Lease})
	wantFd(t, fd)
	wantResponse(t, again, r.resp)
	if got := e.opens(); !slices.Equal(got, []string{dax + " ro", dax + " ro"}) {
		t.Fatalf("opens %v", got)
	}
	e.wantReleaseAll(1)
}

// A lease without a source, prepared from the pool: the scheduler took the
// pool subrequest, the pool driver applies its own config only, the lease
// records the source.
func TestDefaultLeaseFromPool(t *testing.T) {
	e := newFdEnv(t, nil, fake.MemdevSpec{Serial: serialPoolX})
	claim, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Size: "256Mi", Mode: "dax"}, "pooled0", poolExclusiveData)
	if fr := claim.Spec.Devices.Requests[0]; fr.Exactly != nil || len(fr.FirstAvailable) != 2 {
		t.Fatalf("local, then pool request %+v", fr)
	}
	wantFd(t, r.fd)
	dax := filepath.Join(e.k.DevRoot(), "dax0.0")
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "pool", Mode: "dax", Size: 268435456, Serial: "0xc1ee0001", Dax: dax,
		Env: map[string]string{"CXL_C1EE0001_DAX": dax, "CXL_C1EE0001_MODE": "dax", "CXL_C1EE0001_READONLY": "0", "CXL_C1EE0001_SERIAL": "0xc1ee0001",
			"CXL_C1EE0001_SHARED": "0", "CXL_C1EE0001_SIZE": "268435456"}})
	if got := e.k.DaxDriver("dax0.0"); got != "device_dax" {
		t.Fatalf("dax driver %s", got)
	}
	if l := e.lease(r.resp.Lease); sourceOf(l) != state.SourcePool || l.Asked.Source != "" {
		t.Fatalf("stored lease %+v", l)
	}
	e.wantReleaseAll(1)
}

// A local numa lease: the node of the local slice lent by cxl.nri.io, lent
// again by the reconcile, revoked by the release.
func TestLocalNumaLease(t *testing.T) {
	e := newLeaseEnv(t, []fake.MemdevSpec{{Serial: serialSliced, Ram: 1 << 30}})
	e.openClaim()
	e.start()
	claim, r := e.requestLocal("000000a1", api.Request{Op: api.OpRequest, Size: "128Mi", Source: "local", Wait: "5s"}, serialSliced)
	if ex := claim.Spec.Devices.Requests[0].Exactly; ex == nil || ex.DeviceClassName != device.ClassLocal {
		t.Fatalf("local request %+v", claim.Spec.Devices.Requests[0])
	}
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "local", Mode: "numa", Node: ptr(2), Size: 128 << 20, Serial: "0xc100e2e1",
		Env: map[string]string{"CXL_C100E2E1_MODE": "numa", "CXL_C100E2E1_NODE": "2", "CXL_C100E2E1_SERIAL": "0xc100e2e1",
			"CXL_C100E2E1_SHARED": "0", "CXL_C100E2E1_SIZE": "134217728"}})
	if got := e.ctrs.lentNodes(envPodUID, envCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("lent %v", got)
	}
	e.ctrs.forget()
	e.b.reconcile()
	if got := e.ctrs.lentNodes(envPodUID, envCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("lend not re-applied: %v", got)
	}
	e.wantReleaseAll(1)
	if !strings.Contains(e.ctrs.callLog(), "revoke pod-uid-1/app 2") || len(e.ctrs.lentNodes(envPodUID, envCtr)) != 0 {
		t.Fatalf("local node not revoked:\n%s", e.ctrs.callLog())
	}
	e.wantNoRegions()
}

// A local dax lease without a source: the scheduler took the local
// subrequest; the config of the pool driver applies to the pool
// subrequest only; the response tells the source; the fd read-only.
func TestLocalDaxLease(t *testing.T) {
	e := newFdEnv(t, []fake.MemdevSpec{{Serial: serialSliced, Ram: 1 << 30}})
	ch := e.callFd(api.Request{Op: api.OpRequest, Size: "128Mi", Mode: "dax", ReadOnly: true, Wait: "5s"})
	claim := e.waitClaim("cxl-lease-000000a1")
	if fr := claim.Spec.Devices.Requests[0]; fr.Exactly != nil || len(fr.FirstAvailable) != 2 {
		t.Fatalf("local, then pool request %+v", fr)
	}
	c := allocatedLocal(claim, dra.MemdevDeviceName(serialSliced))
	mustOK(t, config.CheckEntries(c, device.DriverName))
	res, err := config.Resolve(c, device.DriverName, "lease/local")
	mustOK(t, err)
	if mode, err := res.Config.DeviceSection().MemdevMode(false); err != nil || mode != api.ModeDax || !res.Config.DeviceSection().IsReadOnly() {
		t.Fatalf("MemoryConfig %s: mode %q %v", res.Config.Compact(), mode, err)
	}
	if lres, err := config.Resolve(c, device.PoolDriverName, "lease/local"); err != nil || lres.Config.Compact() != "{}" {
		t.Fatalf("pool MemoryConfig of the local subrequest %+v %v", lres, err)
	}
	// the entry of the pool driver targets the pool subrequest only
	pc := claim.DeepCopy()
	pc.Status.Allocation = &resourcev1.AllocationResult{Devices: resourcev1.DeviceAllocationResult{
		Results: []resourcev1.DeviceRequestAllocationResult{{Request: "lease/pool", Driver: device.PoolDriverName, Pool: envPool, Device: "pooled0"}},
		Config:  allocationConfigs(pc, "lease/pool"),
	}}
	mustOK(t, config.CheckEntries(pc, device.PoolDriverName))
	pres, err := config.Resolve(pc, device.PoolDriverName, "lease/pool")
	mustOK(t, err)
	if got := pres.Config.Compact(); got != `{"device":{"mode":"dax","readOnly":true}}` {
		t.Fatalf("pool MemoryConfig %s", got)
	}
	mustOK(t, e.prepare(e.local, c).Err)
	r := <-ch
	wantFd(t, r.fd)
	dax := filepath.Join(e.k.DevRoot(), "dax0.0")
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "local", Mode: "dax", ReadOnly: true, Size: 128 << 20, Serial: "0xc100e2e1",
		Dax: dax, Env: map[string]string{"CXL_C100E2E1_DAX": dax, "CXL_C100E2E1_MODE": "dax", "CXL_C100E2E1_READONLY": "1",
			"CXL_C100E2E1_SERIAL": "0xc100e2e1", "CXL_C100E2E1_SHARED": "0", "CXL_C100E2E1_SIZE": "134217728"}})
	if got := e.opens(); !slices.Equal(got, []string{dax + " ro"}) {
		t.Fatalf("opens %v", got)
	}
	if strings.Contains(e.ctrs.callLog(), "lend") {
		t.Fatalf("dax lent as a node:\n%s", e.ctrs.callLog())
	}
	e.wantReleaseAll(1)
	e.wantNoRegions()
}

// A share of a shared local memdev: the class of shared local devices, one
// share, the environment of a shared device, the region kept.
func TestLocalSharedLease(t *testing.T) {
	e := newFdEnv(t, []fake.MemdevSpec{{Serial: serialShared, Ram: 1 << 30}})
	e.setShared(serialShared)
	claim, r := e.requestLocal("000000a1", api.Request{Op: api.OpRequest, Serial: "0xc100e2e2", Shared: true, ReadOnly: true, Source: "local", Wait: "5s"}, serialShared)
	ex := claim.Spec.Devices.Requests[0].Exactly
	if q := ex.Capacity.Requests[device.CapacityShares]; ex.DeviceClassName != device.ClassLocalShared || q.String() != "1" {
		t.Fatalf("companion request %+v", ex)
	}
	wantFd(t, r.fd)
	dax := filepath.Join(e.k.DevRoot(), "dax0.0")
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "local", Mode: "dax", Shared: true, ReadOnly: true, Size: 1 << 30,
		Serial: "0xc100e2e2", Dax: dax, Env: map[string]string{"CXL_C100E2E2_DAX": dax, "CXL_C100E2E2_MODE": "dax", "CXL_C100E2E2_READONLY": "1",
			"CXL_C100E2E2_SERIAL": "0xc100e2e2", "CXL_C100E2E2_SHARED": "1", "CXL_C100E2E2_SIZE": "1073741824"}})
	if got := e.k.DaxDriver("dax0.0"); got != "device_dax" || e.onlineBlocks() != 0 {
		t.Fatalf("dax driver %s, %d memory blocks online", got, e.onlineBlocks())
	}
	e.wantReleaseAll(1)
	if len(e.regions()) != 1 {
		t.Fatalf("the region of a shared memdev not kept: %v", e.regions())
	}
}

// Two leases of a container hold one NUMA node (a local device and a pool
// device under one host bridge): releasing one keeps the node lent.
func TestTwoLeasesOneNode(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	lender := dra.NewLender(device.DriverName)
	lender.Set(e.ctrs, e.b)
	var ids []string
	for _, source := range []string{"local", "pool"} {
		resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "64Mi", Source: source, Wait: "0s"})
		rec, err := lender.Check(resp.Lease, e.waitClaim(CompanionName(resp.Lease)))
		mustOK(t, err)
		devs := []lend.LentDevice{{Source: source, Serial: serialSliced, Size: 64 << 20, Mode: api.ModeNUMA, NumaNode: 2}}
		mustOK(t, lender.Lend(context.Background(), rec, devs))
		lender.Prepared(resp.Lease, devs)
		e.waitState(resp.Lease, state.LeaseReady)
		ids = append(ids, resp.Lease)
	}
	if got := e.ctrs.holders(envPodUID, envCtr, 2); !slices.Equal(got, ids) {
		t.Fatalf("holders of node 2: %v, expected %v", got, ids)
	}
	if got := state.LeaseLends(&e.st.Snapshot().Records, envPodUID, envCtr); !reflect.DeepEqual(got, map[int][]string{2: ids}) {
		t.Fatalf("lends %v", got)
	}
	e.ctrs.forget()
	e.b.reconcile()
	if got := e.ctrs.holders(envPodUID, envCtr, 2); len(got) != 2 || !slices.Contains(got, ids[0]) || !slices.Contains(got, ids[1]) {
		t.Fatalf("holders after reconcile: %v", got)
	}
	rel, _ := e.call(api.Request{Op: api.OpRelease, Lease: ids[0]})
	if rel.State != api.StateReleased {
		t.Fatalf("release %+v", rel)
	}
	mustOK(t, lender.Revoke(context.Background(), &lend.Lend{Lease: ids[0], Pod: requester.Pod, Container: envCtr, NumaNodes: []int{2}}, "ns/c"))
	if got := e.ctrs.holders(envPodUID, envCtr, 2); !slices.Equal(got, ids[1:]) {
		t.Fatalf("holders after the first release: %v", got)
	}
	e.wantReleaseAll(1)
	if got := e.ctrs.lentNodes(envPodUID, envCtr); len(got) != 0 {
		t.Fatalf("still lent after both releases: %v", got)
	}
}

// newFsEnv returns a node with the shared persistent pool device llm0,
// formatted with a filesystem of the type, and its ResourceSlices.
func newFsEnv(t *testing.T, typ string) *leaseEnv {
	e := newLeaseEnv(t, nil, fake.MemdevSpec{Serial: serialPoolP, Pmem: 512 << 20})
	e.formatPmem(serialPoolP, typ)
	e.addSlices(persistentPoolSlice())
	e.openClaim()
	e.start()
	return e
}

// fsEnv returns the environment of an fs lease of llm0.
func fsEnv(fsType, access, path, readOnly string) map[string]string {
	return map[string]string{"CXL_C1AF0001_ACCESS": access, "CXL_C1AF0001_FSTYPE": fsType, "CXL_C1AF0001_MODE": "fs", "CXL_C1AF0001_PATH": path,
		"CXL_C1AF0001_READONLY": readOnly, "CXL_C1AF0001_SERIAL": "0xc1af0001", "CXL_C1AF0001_SHARED": "1", "CXL_C1AF0001_SIZE": "534773760"}
}

// fs leases through the pool driver: the companion claim, the bind in the
// lease-fs directory of the lease claim, the responses, the names; a
// release while the borrower has files of the bind open waits busy
// (RELEASING_BUSY) until the holder ends; a closed lease claim keeps its
// directories while a bind is in them, also through a reconcile, and the
// release of its last lease removes them.
func TestFsLease(t *testing.T) {
	e := newFsEnv(t, "erofs")
	ctx := context.Background()
	fsDir := filepath.Join(e.dir, "lease-fs", envLeaseClaim)

	claim, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs", Wait: "5s"},
		"llm0", poolPmemData)
	params := `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":true}}`
	wantSpec := resourcev1.ResourceClaimSpec{Devices: resourcev1.DeviceClaim{
		Requests: []resourcev1.DeviceRequest{{Name: "lease", Exactly: &resourcev1.ExactDeviceRequest{
			DeviceClassName: "cxl-pool-persistent",
			Selectors:       []resourcev1.DeviceSelector{{CEL: &resourcev1.CELDeviceSelector{Expression: `device.attributes["cxl-pool.nri.io"].serial == "0xc1af0001"`}}},
			Capacity:        &resourcev1.CapacityRequirements{Requests: map[resourcev1.QualifiedName]resource.Quantity{"shares": resource.MustParse("1")}},
		}}},
		Config: []resourcev1.DeviceClaimConfiguration{{DeviceConfiguration: resourcev1.DeviceConfiguration{Opaque: &resourcev1.OpaqueDeviceConfiguration{
			Driver: "cxl-pool.nri.io", Parameters: runtime.RawExtension{Raw: []byte(params)},
		}}}},
	}}
	if !reflect.DeepEqual(claim.Spec, wantSpec) {
		got, _ := json.Marshal(claim.Spec)
		t.Fatalf("claim spec:\n%s", got)
	}
	if r.fd >= 0 {
		t.Fatalf("fd %d with an fs lease", r.fd)
	}
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "pool", Mode: "fs", FsType: "erofs", Shared: true, ReadOnly: true, Access: "direct",
		Path: "/run/cxl/fs/000000a1", Size: pmemBytes, Serial: "0xc1af0001", Env: fsEnv("erofs", "direct", "/run/cxl/fs/000000a1", "1")})
	bind := filepath.Join(fsDir, "000000a1")
	direct, cached := e.nodeMount(serialPoolP, "direct"), e.nodeMount(serialPoolP, "cached")
	if mi := e.mounted(bind); mi == nil || mi.FsType != "erofs" || mi.Source != e.pmem {
		t.Fatalf("bind %+v", mi)
	}
	if len(e.k.MountCalls(bindCall(direct, bind))) != 1 {
		t.Fatalf("not a bind of the node mount: %q", e.k.MountCalls(""))
	}
	if l := e.stored("000000a1"); l == nil || l.Lend == nil || l.Lend.BindTarget != bind || l.Lend.NumaNode != nil {
		t.Fatalf("the lease's lend %+v", l)
	}
	env, fd := e.call(api.Request{Op: api.OpEnv, Lease: "000000a1"})
	if fd >= 0 || env.State != api.StateReady || !reflect.DeepEqual(env.Env, r.resp.Env) || env.Path != r.resp.Path {
		t.Fatalf("env %+v fd %d", env, fd)
	}
	if r, fd := e.call(api.Request{Op: api.OpFd, Lease: "000000a1"}); fd >= 0 || r.Error != "lease 000000a1 is not a dax or block lease; use env" || r.Mode != "fs" {
		t.Fatalf("fd of an fs lease %+v fd %d", r, fd)
	}

	_, r = e.requestPool("000000a2", api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs", Access: "cached",
		Name: "models", Wait: "5s"}, "llm0", poolPmemData)
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "pool", Mode: "fs", FsType: "erofs", Shared: true, ReadOnly: true, Access: "cached",
		Path: "/run/cxl/fs/models", Size: pmemBytes, Serial: "0xc1af0001", Env: fsEnv("erofs", "cached", "/run/cxl/fs/models", "1")})
	models := filepath.Join(fsDir, "models")
	if mi := e.mounted(models); mi == nil || mi.Source != filepath.Join(e.k.DevRoot(), "loop0") || len(e.k.MountCalls(bindCall(cached, models))) != 1 {
		t.Fatalf("bind %+v, calls %q", mi, e.k.MountCalls(""))
	}
	for _, c := range []struct{ name, err string }{
		{"models", `name "models" is in use by lease 000000a2`},
		{"000000a1", `name "000000a1" is in use by lease 000000a1`},
	} {
		r, _ := e.call(api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs", Name: c.name})
		if r.Error != c.err || r.Lease != "" {
			t.Errorf("name %s: %+v, expected %q", c.name, r, c.err)
		}
	}
	if l, _ := e.client.ResourceV1().ResourceClaims(envNS).List(ctx, metav1.ListOptions{}); e.numLeases() != 2 || len(l.Items) != 3 {
		t.Fatalf("%d leases, %d claims after refused requests", e.numLeases(), len(l.Items))
	}

	e.restart()
	e.start()
	if l := e.lease("000000a2"); l == nil || l.Asked.Mode != state.ModeFs || accessOf(l) != state.AccessCached || l.Asked.Name != "models" ||
		got(l).Path != "/run/cxl/fs/models" || !l.Asked.ReadOnly {
		t.Fatalf("lease after a restart %+v", l)
	}
	if lc := e.claim(envLeaseClaim); lc == nil || lc.FsDir != fsDir {
		t.Fatalf("lease claim after a restart %+v", lc)
	}
	list, _ := e.call(api.Request{Op: api.OpList})
	if list.Leases == nil || len(*list.Leases) != 2 || (*list.Leases)[0].Path != "/run/cxl/fs/000000a1" || (*list.Leases)[1].Path != "/run/cxl/fs/models" {
		t.Fatalf("list %+v", list)
	}

	// release while the borrower has files of the bind open
	e.k.SetBusy(bind, true)
	rel, _ := e.call(api.Request{Op: api.OpRelease, Lease: "000000a1", Wait: "200ms"})
	if rel.State != api.StateReleasing {
		t.Fatalf("release of a busy fs lease %+v", rel)
	}
	e.waitState("000000a1", state.LeaseReleasingBusy)
	if l := e.stored("000000a1"); l == nil || l.State != state.LeaseReleasingBusy {
		t.Fatalf("stored busy lease %+v", l)
	}
	if data, _ := os.ReadFile(filepath.Join(e.dir, store.ViewLeases)); !strings.Contains(string(data), `"state": "Releasing"`) {
		t.Fatalf("leases.json of a busy lease:\n%s", data)
	}
	if e.mounted(bind) == nil {
		t.Fatal("busy bind unmounted")
	}
	if _, err := e.client.ResourceV1().ResourceClaims(envNS).Get(ctx, CompanionName("000000a1"), metav1.GetOptions{}); err != nil {
		t.Fatalf("companion claim of a busy bind: %v", err)
	}
	e.k.SetBusy(bind, false)
	e.waitState("000000a1", state.LeaseNone)
	e.wantGone(CompanionName("000000a1"))
	if _, err := os.Stat(bind); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bind directory left: %v", err)
	}

	// the pod ends with a busy bind
	e.k.SetBusy(models, true)
	mustOK(t, e.b.CloseClaim(ctx, envLeaseClaim))
	if _, err := os.Stat(models); err != nil {
		t.Fatalf("bind directory removed while mounted: %v", err)
	}
	if _, err := os.Stat(e.sock()); !os.IsNotExist(err) {
		t.Fatalf("socket left: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(e.sock()), "fs")); err != nil {
		t.Fatalf("mount point of /run/cxl/fs removed while a bind is in lease-fs: %v", err)
	}
	e.b.reconcile()
	if l := e.lease("000000a2"); l == nil || !releasingState(l.State) {
		t.Fatalf("lease %+v", l)
	}
	if _, err := os.Stat(models); err != nil {
		t.Fatalf("bind directory swept while mounted: %v", err)
	}
	e.k.SetBusy(models, false)
	e.waitState("000000a2", state.LeaseNone)
	for _, d := range []string{fsDir, filepath.Dir(e.sock())} {
		e.waitGoneDir(d)
	}
	e.wantClean()
}

// A read-write and a read-only fs lease of one ext4: the companion configs
// say readOnly explicitly, the responses have the type, the lease records
// the opt-in.
func TestFsLeaseReadWrite(t *testing.T) {
	e := newFsEnv(t, "ext4")
	_, rw := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Shared: true, ReadWrite: true, Mode: "fs", Name: "rw", Wait: "5s"},
		"llm0", poolPmemRWData)
	wantResponse(t, rw.resp, api.Response{State: api.StateReady, Source: "pool", Mode: "fs", FsType: "ext4", Shared: true, Access: "direct",
		Path: "/run/cxl/fs/rw", Size: pmemBytes, Serial: "0xc1af0001", Env: fsEnv("ext4", "direct", "/run/cxl/fs/rw", "0")})
	fsDir := filepath.Join(e.dir, "lease-fs", envLeaseClaim)
	direct := e.nodeMount(serialPoolP, "direct")
	if mi := e.mounted(filepath.Join(fsDir, "rw")); mi == nil || !slices.Equal(mi.MountFlags, []string{"rw", "nosuid", "nodev"}) || mi.FsType != "ext4" {
		t.Fatalf("read-write bind %+v", mi)
	}
	if mi := e.mounted(direct); mi == nil || len(mi.SuperOpts) == 0 || mi.SuperOpts[0] != "rw" {
		t.Fatalf("node mount %+v", mi)
	}
	_, ro := e.requestPool("000000a2", api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Shared: true, Mode: "fs", Name: "ro", Wait: "5s"},
		"llm0", poolPmemData)
	wantResponse(t, ro.resp, api.Response{State: api.StateReady, Source: "pool", Mode: "fs", FsType: "ext4", Shared: true, ReadOnly: true, Access: "direct",
		Path: "/run/cxl/fs/ro", Size: pmemBytes, Serial: "0xc1af0001", Env: fsEnv("ext4", "direct", "/run/cxl/fs/ro", "1")})
	if c := e.k.MountCalls("robind"); !slices.Equal(c, []string{"robind " + direct + " " + filepath.Join(fsDir, "ro")}) {
		t.Fatalf("read-only bind calls %q", c)
	}
	for id, want := range map[string]string{
		"000000a1": `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":false}}`,
		"000000a2": `{"apiVersion":"cxl.nri.io/v1alpha1","kind":"MemoryConfig","device":{"mode":"fs","readOnly":true}}`,
	} {
		claim := e.waitClaim(CompanionName(id))
		if got := string(claim.Spec.Devices.Config[0].Opaque.Parameters.Raw); got != want {
			t.Errorf("%s: config %s", id, got)
		}
	}
	if l := e.stored("000000a1"); l == nil || !l.Asked.ReadWrite || l.Asked.ReadOnly || fsTypeOf(l) != "ext4" || readOnly(l) {
		t.Fatalf("lease %+v", l)
	}
	if v := e.k.Violations(); len(v) > 0 {
		t.Fatalf("mount rules violated: %v", v)
	}
	e.wantReleaseAll(2)
	e.wantClean()
}

// An fs lease of a persistent local memdev, prepared by cxl.nri.io.
func TestLocalFsLease(t *testing.T) {
	e := newLeaseEnv(t, []fake.MemdevSpec{{Serial: serialPmem, Pmem: 512 << 20, HostBridge: 24}})
	e.formatPmem(serialPmem, "erofs")
	e.rescan()
	e.addSlices(localResourceSlice())
	e.openClaim()
	e.start()
	claim, r := e.requestLocal("000000a1", api.Request{Op: api.OpRequest, Serial: "0xc100f5e1", Shared: true, Mode: "fs", Source: "local", Wait: "5s"}, serialPmem)
	if ex := claim.Spec.Devices.Requests[0].Exactly; ex == nil || ex.DeviceClassName != device.ClassLocalPersistent {
		t.Fatalf("local persistent request %+v", claim.Spec.Devices.Requests[0])
	}
	if r.resp.State != api.StateReady || r.resp.Source != "local" || r.resp.Mode != "fs" || r.resp.FsType != "erofs" || r.resp.Path != "/run/cxl/fs/000000a1" {
		t.Fatalf("response %+v", r.resp)
	}
	bind := filepath.Join(e.dir, "lease-fs", envLeaseClaim, "000000a1")
	if e.mounted(bind) == nil {
		t.Fatalf("no bind at %s", bind)
	}
	e.wantReleaseAll(1)
	if e.mounted(bind) != nil {
		t.Fatal("bind left")
	}
}

// The companion of an fs lease is prepared past OnLending while CloseClaim
// removes the lease-fs directory: the bind creates it again, the lease is
// not Ready, the companion's Unprepare unmounts the bind and the reconcile
// removes the directories.
func TestFsLeaseCloseRace(t *testing.T) {
	e := newFsEnv(t, "erofs")
	fsDir := filepath.Join(e.dir, "lease-fs", envLeaseClaim)
	bind := filepath.Join(fsDir, "models")
	closed := false
	hooks := &closingHooks{Broker: e.b, close: func() {
		mustOK(t, e.b.CloseClaim(context.Background(), envLeaseClaim))
		_, err := os.Stat(fsDir)
		closed = errors.Is(err, os.ErrNotExist)
	}}
	e.pool.Lender().Set(e.ctrs, hooks)
	ch := e.async(api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs", Name: "models", Wait: "5s"})
	claim := e.waitClaim(CompanionName("000000a1"))
	mustOK(t, e.prepare(e.pool, allocatedPool(claim, "llm0", poolPmemData)).Err)
	if !closed {
		t.Fatal("CloseClaim did not remove the lease-fs directory")
	}
	if r := <-ch; r.State == api.StateReady {
		t.Fatalf("lease of a closed claim Ready: %+v", r)
	}
	if e.mounted(bind) == nil {
		t.Fatal("no bind in the directory made again")
	}
	e.waitState("000000a1", state.LeaseNone)
	e.b.reconcile()
	if _, err := os.Stat(bind); err != nil {
		t.Fatalf("bind directory swept while mounted: %v", err)
	}
	// kubelet unprepares the companion
	mustOK(t, e.unprepare(e.pool, "uid-"+CompanionName("000000a1")))
	e.b.reconcile()
	for _, d := range []string{fsDir, filepath.Dir(e.sock())} {
		if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directory %s left: %v", d, err)
		}
	}
	e.wantClean()
}

// closingHooks close the lease claim when the companion claim of one of
// its leases is being prepared, right after OnLending.
type closingHooks struct {
	*Broker
	close func()
}

// OnLending is the broker's, then closes the lease claim once.
func (h *closingHooks) OnLending(id string, claim *resourcev1.ResourceClaim) (*lend.Lend, error) {
	rec, err := h.Broker.OnLending(id, claim)
	if err == nil && h.close != nil {
		h.close()
		h.close = nil
	}
	return rec, err
}

// newBlockEnv returns an fdEnv with the shared persistent pool device llm0
// whose labels have no namespace yet: the writer creates it.
func newBlockEnv(t *testing.T) *fdEnv {
	e := newFdEnv(t, nil, fake.MemdevSpec{Serial: serialPoolP, Pmem: 512 << 20})
	e.k.SetLabels(serialPoolP, false)
	return e
}

// blockEnv returns the environment of a block lease of llm0.
func blockEnv(dev, readOnly string) map[string]string {
	return map[string]string{"CXL_C1AF0001_MODE": "block", "CXL_C1AF0001_PATH": dev, "CXL_C1AF0001_READONLY": readOnly,
		"CXL_C1AF0001_SERIAL": "0xc1af0001", "CXL_C1AF0001_SHARED": "1", "CXL_C1AF0001_SIZE": "534773760"}
}

// Block leases of the shared persistent device llm0: the writer takes the
// whole device and creates its fsdax namespace, a reader takes a share
// read-only; both get an fd of the block device with the response and
// with fd, none with env.
func TestBlockLease(t *testing.T) {
	e := newBlockEnv(t)
	serialSel := []resourcev1.DeviceSelector{{CEL: &resourcev1.CELDeviceSelector{Expression: `device.attributes["cxl-pool.nri.io"].serial == "0xc1af0001"`}}}
	claim, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Mode: "block", Wait: "5s"}, "llm0", poolWriterData)
	if ex := claim.Spec.Devices.Requests[0].Exactly; ex == nil || ex.DeviceClassName != "cxl-pool-persistent" || ex.Capacity != nil ||
		!reflect.DeepEqual(ex.Selectors, serialSel) {
		t.Fatalf("writer request %+v", claim.Spec.Devices.Requests[0])
	}
	if dc := deviceConfigOf(t, claim, device.PoolDriverName); dc == nil || dc.Mode != api.ModeBlock || dc.IsReadOnly() || dc.Access != "" || dc.Path != "" {
		t.Fatalf("companion device section %+v", dc)
	}
	wantFd(t, r.fd)
	l := e.stored("000000a1")
	if l == nil || l.Got == nil || l.Got.Block == "" || l.Lend != nil || l.Got.Dax != "" || l.Got.Path != "" {
		t.Fatalf("stored lease %+v", l)
	}
	pmem := l.Got.Block
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "pool", Mode: "block", Block: pmem, Size: pmemBytes, Serial: "0xc1af0001",
		Env: blockEnv(pmem, "0")})
	if !strings.Contains(e.k.Commands(), "ndctl create-namespace -f -r region0 -m fsdax -M mem") {
		t.Fatalf("no namespace created:\n%s", e.k.Commands())
	}
	if mounts, _ := e.k.Kernel().Mounts(); len(mounts) != 0 {
		t.Fatalf("mounts of a block lease %+v", mounts)
	}
	resp, fd := e.call(api.Request{Op: api.OpFd, Lease: "000000a1", Wait: "1s"})
	wantFd(t, fd)
	wantResponse(t, resp, r.resp)
	if env, fd := e.call(api.Request{Op: api.OpEnv, Lease: "000000a1"}); fd >= 0 || !reflect.DeepEqual(env.Env, blockEnv(pmem, "0")) || env.Block != pmem {
		t.Fatalf("env %+v fd %d", env, fd)
	}
	if got := e.opens(); !slices.Equal(got, []string{pmem + " rw", pmem + " rw"}) {
		t.Fatalf("opens %v", got)
	}
	e.restart()
	e.start()
	if l := e.lease("000000a1"); l == nil || l.Asked.Mode != state.ModeBlock || got(l).Block != pmem || l.Asked.ReadOnly {
		t.Fatalf("lease after a restart %+v", l)
	}
	e.wantReleaseAll(1)
	e.wantGone(CompanionName("000000a1"))
	e.wantNoRegions()

	_, r = e.requestPool("000000a1", api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "block", Wait: "5s"},
		"llm0", poolPmemData)
	wantFd(t, r.fd)
	wantResponse(t, r.resp, api.Response{State: api.StateReady, Source: "pool", Mode: "block", Shared: true, ReadOnly: true, Block: pmem,
		Size: pmemBytes, Serial: "0xc1af0001", Env: blockEnv(pmem, "1")})
	if n := strings.Count(e.k.Commands(), "ndctl create-namespace"); n != 1 {
		t.Fatalf("ndctl create-namespace ran %d times", n)
	}
	resp, fd = e.call(api.Request{Op: api.OpFd, Lease: "000000a1"})
	wantFd(t, fd)
	if resp.Error != "" || resp.Block != pmem {
		t.Fatalf("fd %+v", resp)
	}
	if got := e.opens()[2:]; !slices.Equal(got, []string{pmem + " ro", pmem + " ro"}) {
		t.Fatalf("opens of the reader %v", got)
	}
	e.wantReleaseAll(1)
	e.wantClean()
}

// A block lease whose block device does not open is answered with the
// error, and kept.
func TestBlockLeaseOpenError(t *testing.T) {
	e := newBlockEnv(t)
	e.opts = func(o *Options) {
		o.OpenDevice = func(string, bool) (*os.File, error) { return nil, syscall.ENXIO }
	}
	e.restart()
	e.start()
	_, r := e.requestPool("000000a1", api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Mode: "block", Wait: "5s"}, "llm0", poolWriterData)
	l := e.stored("000000a1")
	if r.fd >= 0 || l == nil || r.resp.Error != "opening "+got(l).Block+": no such device or address" || r.resp.State != api.StateReady {
		t.Fatalf("response %+v fd %d", r.resp, r.fd)
	}
	e.wantReleaseAll(1)
	e.wantNoRegions()
}

// A companion claim of a lease that the broker does not have is refused by
// the pool driver before any device is touched.
func TestCompanionRefused(t *testing.T) {
	e := newLeaseEnv(t, nil, fake.MemdevSpec{Serial: serialPoolX})
	before := e.k.Commands()
	c := allocatedPool(companionClaim("abc"), "pooled0", poolExclusiveData)
	wantErrText(t, e.prepare(e.pool, c).Err, "lending to running containers is disabled (--leases=false)")
	e.startWith(nil)
	wantErrText(t, e.prepare(e.pool, c).Err, "lending unavailable: NRI not connected")
	e.pool.Lender().Set(e.ctrs, e.b)
	wantErrText(t, e.prepare(e.pool, c).Err, fmt.Sprintf("claim %s/%s: not the companion of lease abc", envNS, c.Name))
	if strings.Contains(e.k.CommandsSince(before), "create-region") {
		t.Fatalf("device touched for a refused lend:\n%s", e.k.CommandsSince(before))
	}
}
