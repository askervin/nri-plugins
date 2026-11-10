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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiparser "tags.cncf.io/container-device-interface/pkg/parser"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// cdiID is the qualified CDI device name of a lease claim.
func cdiID(claimUID string) string {
	return cdiparser.QualifiedName(device.CDIVendor, device.CDIClass, CDIDeviceName(claimUID))
}

// numaDevice is the lent device of a pool numa lease on node 2.
var numaDevice = preparedDev(serialPoolX, 1<<28, api.ModeNUMA, 2)

// preparedDev returns a memdev of a companion claim as a driver tells the
// broker: its serial, size, mode and the NUMA node of mode numa (-1 for
// none).
func preparedDev(serial, size uint64, mode string, node int) state.DeviceInfo {
	d := state.DeviceInfo{DeviceType: device.DeviceTypeMemdev, Serial: api.FormatSerial(serial), TotalBytes: size, Mode: mode,
		Persistent: mode == api.ModeBlock || mode == api.ModeFs}
	if node >= 0 {
		d.NUMANodes = []int{node}
	}
	return d
}

// withDev returns d changed by fn.
func withDev(d state.DeviceInfo, fn func(d *state.DeviceInfo)) state.DeviceInfo {
	fn(&d)
	return d
}

// readyNUMA requests a numa lease and makes it READY through the hooks, as
// a companion's Prepare does, and returns its id.
func (e *leaseEnv) readyNUMA() string {
	e.t.Helper()
	resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	id := resp.Lease
	e.waitClaim(CompanionName(id))
	_, err := e.b.OnLending(id, companionClaim(id))
	mustOK(e.t, err)
	e.b.OnPrepared(id, state.SourcePool, []state.DeviceInfo{numaDevice})
	e.waitState(id, state.LeaseReady)
	return id
}

// The socket and the CDI device of a lease claim: modes, mounts, the
// environment; requests answered "lending unavailable" before the start;
// the socket again after a restart; CloseClaim removes them, and an
// unknown claim is no error.
func TestLeaseClaimSocketAndCDI(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.openClaim() // idempotent
	st, err := os.Stat(e.sock())
	mustOK(t, err)
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode %v", st.Mode())
	}
	if st, _ := os.Stat(filepath.Dir(e.sock())); st.Mode().Perm() != 0o755 {
		t.Fatalf("directory mode %v", st.Mode())
	}
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(e.cdiDir), cdiapi.WithAutoRefresh(false))
	mustOK(t, err)
	dev := cache.GetDevice(cdiID(envLeaseClaim))
	if dev == nil || cdiID(envLeaseClaim) != "nri.io/cxl=lease-lc1" {
		t.Fatalf("CDI device %s missing: %v", cdiID(envLeaseClaim), cache.ListDevices())
	}
	fsDir := filepath.Join(e.dir, "lease-fs", envLeaseClaim)
	wantMounts := []*cdiSpecs.Mount{
		{HostPath: filepath.Dir(e.sock()), ContainerPath: "/run/cxl", Type: "bind", Options: []string{"rbind", "ro"}},
		{HostPath: fsDir, ContainerPath: "/run/cxl/fs", Type: "bind", Options: []string{"rbind", "ro", "rslave"}},
		{HostPath: e.cli, ContainerPath: "/usr/local/bin/cxl-request", Type: "bind", Options: []string{"bind", "ro"}},
	}
	if !reflect.DeepEqual(dev.ContainerEdits.Mounts, wantMounts) {
		t.Fatalf("mounts %+v", dev.ContainerEdits.Mounts)
	}
	for _, d := range []string{fsDir, filepath.Join(filepath.Dir(e.sock()), "fs")} {
		if st, err := os.Stat(d); err != nil || !st.IsDir() || st.Mode().Perm() != 0o755 {
			t.Fatalf("directory %s: %v %v", d, st, err)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(e.cdiDir, device.LeasesCDISpecName+".*")); len(m) != 1 {
		t.Fatalf("CDI spec files %v", m)
	}
	if l := e.st.Snapshot().Leases; len(l) != 0 {
		t.Fatalf("lease records %+v", l)
	}
	if lc := e.st.Snapshot().LeaseClaim(envLeaseClaim); lc == nil || lc.FsDir != fsDir || lc.State != state.LeaseClaimOpen ||
		!reflect.DeepEqual(lc.Pods, []state.PodRef{requester.Pod}) {
		t.Fatalf("lease claim record %+v", lc)
	}
	if !slices.Equal(dev.ContainerEdits.Env, []string{"CXL_LEASE_SOCKET=/run/cxl/cxl.sock"}) ||
		leaseContainerDir+"/"+leaseSocketName != api.DefaultSocket {
		t.Fatalf("env %v", dev.ContainerEdits.Env)
	}
	// before the start a request waits for it, bounded
	e.opts = func(o *Options) { o.Timeouts.SyncWait = 200 * time.Millisecond }
	e.restart()
	e.opts = nil
	start := time.Now()
	resp, _ := e.call(api.Request{Op: api.OpList})
	wantErrText(t, errors.New(resp.Error), "lending unavailable: NRI not connected")
	if took := time.Since(start); took < 200*time.Millisecond || took > 5*time.Second {
		t.Fatalf("a request before the start answered after %v", took)
	}

	e.restart()
	e.start()
	resp, _ = e.call(api.Request{Op: api.OpList})
	if resp.Error != "" || resp.Leases == nil || len(*resp.Leases) != 0 {
		t.Fatalf("list after restart: %+v", resp)
	}

	mustOK(t, e.b.CloseClaim(context.Background(), envLeaseClaim))
	for _, d := range []string{filepath.Dir(e.sock()), fsDir} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("directory %s not removed: %v", d, err)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(e.cdiDir, device.LeasesCDISpecName+".*")); len(m) != 0 {
		t.Fatalf("CDI spec not removed: %v", m)
	}
	if e.st.Snapshot().LeaseClaim(envLeaseClaim) != nil {
		t.Fatal("lease claim record left")
	}
	mustOK(t, e.b.CloseClaim(context.Background(), envLeaseClaim)) // unknown: fine
}

// The peer must be a container of a pod of the lease claim; a pod added to
// the claim later is found by reading its reservedFor again; the
// validation texts of requests.
func TestAuthRejection(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.ctrs.setPeer(&Requester{Pod: state.PodRef{Namespace: envNS, Name: "intruder", UID: "other-pod"}, Container: "x"})
	e.start()
	resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "512Mi"})
	if resp.Error != "not a container of the claim's pod (pid "+fmt.Sprint(os.Getpid())+" is in demo/intruder/x)" {
		t.Fatalf("intruder: %+v", resp)
	}
	e.ctrs.setPeer(nil)
	resp, _ = e.call(api.Request{Op: api.OpList})
	if resp.Error != "not a container of the claim's pod (pid "+fmt.Sprint(os.Getpid())+" is in no known container)" {
		t.Fatalf("unknown process: %+v", resp)
	}
	if l, _ := e.client.ResourceV1().ResourceClaims(envNS).List(context.Background(), metav1.ListOptions{}); len(l.Items) != 1 {
		t.Fatalf("objects created for a rejected request: %d claims", len(l.Items))
	}

	// a pod added to a shared lease claim later
	lc := leaseClaimObj()
	lc.Status.ReservedFor = append(lc.Status.ReservedFor, resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "second", UID: "pod-uid-2"})
	_, err := e.client.ResourceV1().ResourceClaims(envNS).Update(context.Background(), lc, metav1.UpdateOptions{})
	mustOK(t, err)
	e.ctrs.setPeer(&Requester{Pod: state.PodRef{Namespace: envNS, Name: "second", UID: "pod-uid-2"}, Container: "x"})
	resp, _ = e.call(api.Request{Op: api.OpList})
	if resp.Error != "" {
		t.Fatalf("second pod rejected: %+v", resp)
	}
	if c := e.st.Snapshot().LeaseClaim(envLeaseClaim); c == nil || len(c.Pods) != 2 {
		t.Fatalf("pods of the lease claim %+v", c)
	}

	e.ctrs.setPeer(&requester)
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
		{api.Request{Op: "request", Size: "64Mi", Mode: "dax", FsType: "ext4"}, "fsType needs mode fs"},
		{api.Request{Op: "request", Size: "64Mi", Mode: "fs", FsType: "Ext4"}, `invalid fsType "Ext4" (lower-case letters, digits, "_" and "-")`},
		{api.Request{Op: "request", Size: "64Mi", Mode: "block", ReadWrite: true}, "readWrite needs mode fs"},
		{api.Request{Op: "request", Size: "64Mi", Mode: "fs", ReadOnly: true, ReadWrite: true}, "readOnly and readWrite exclude each other"},
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
		wantErrText(t, errors.New(resp.Error), "invalid request: ")
	}
	if resp, _ := e.callRaw(`{"op":"request","kind":"memory"}`); resp.Error != `invalid request: json: unknown field "kind"` {
		t.Fatalf("old protocol: %+v", resp)
	}
	if e.numLeases() != 0 {
		t.Fatalf("%d leases of refused requests", e.numLeases())
	}
}

// An Identity of the options resolves the peers instead of the container
// table; its own errors refuse the connection.
func TestIdentity(t *testing.T) {
	var fails atomic.Bool
	e := brokerEnv(t)
	e.opts = func(o *Options) {
		o.Identity = identityFunc(func(pid int) (Requester, error) {
			if fails.Load() {
				return Requester{}, errors.New("pod resources unreachable")
			}
			return requester, nil
		})
	}
	e.restart()
	e.openClaim()
	e.ctrs.setPeer(nil)
	e.start()
	if resp, _ := e.call(api.Request{Op: api.OpList}); resp.Error != "" {
		t.Fatalf("list: %+v", resp)
	}
	fails.Store(true)
	resp, _ := e.call(api.Request{Op: api.OpList})
	if want := fmt.Sprintf("not a container of the claim's pod (pid %d: pod resources unreachable)", os.Getpid()); resp.Error != want {
		t.Fatalf("list: %+v", resp)
	}
	// without the container plugin: unavailable whatever the identity
	e.restart()
	e.startWith(nil)
	if resp, _ := e.call(api.Request{Op: api.OpList}); resp.Error != "lending unavailable: NRI not connected" {
		t.Fatalf("without NRI: %+v", resp)
	}
}

// identityFunc is an Identity of a function.
type identityFunc func(pid int) (Requester, error)

// Resolve calls the function.
func (f identityFunc) Resolve(pid int) (Requester, error) { return f(pid) }

// A request without a wait waits --lease-wait, then the lease is released
// and the response is Failed with the timeout; without --lease-wait the
// wait is 120 s.
func TestLeaseWaitDefault(t *testing.T) {
	e := brokerEnv(t)
	e.opts = func(o *Options) { o.WaitDefault = 300 * time.Millisecond }
	e.restart()
	e.openClaim()
	e.start()
	start := time.Now()
	resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "64Mi"})
	took := time.Since(start)
	if resp.State != api.StateFailed || resp.Error != "timeout: not Ready after 300ms" || took < 300*time.Millisecond || took > 2*time.Second {
		t.Fatalf("response %+v after %v", resp, took)
	}
	e.waitState(resp.Lease, state.LeaseNone)
	e.wantGone(CompanionName(resp.Lease))

	st, err := store.Open(context.Background(), store.Options{Dir: t.TempDir()})
	mustOK(t, err)
	defer func() { _ = st.Close() }()
	b, err := New(Options{Store: st, DataDir: t.TempDir(), NodeName: envNode})
	mustOK(t, err)
	defer b.Stop()
	if b.opts.WaitDefault != 120*time.Second || b.opts.Image != "registry.k8s.io/pause:3.10" || DefaultCLI != "/usr/local/bin/cxl-request" {
		t.Fatalf("defaults: wait %v, image %s", b.opts.WaitDefault, b.opts.Image)
	}
	if b.t != (Timeouts{Close: 5 * time.Second, Poll: 500 * time.Millisecond, Reconcile: time.Minute, CreatingGrace: 2 * time.Minute,
		SyncWait: 30 * time.Second, Persist: time.Minute}) {
		t.Fatalf("timeouts %+v", b.t)
	}
	if _, err := New(Options{DataDir: t.TempDir()}); err == nil {
		t.Fatal("a broker without a store")
	}
}

// The requestId of a container's request returns the lease of an earlier
// request with it, Pending or Ready, also after a restart; another
// container of the pod with the same requestId gets a lease of its own.
func TestLeaseRequestID(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	req := api.Request{Op: api.OpRequest, Size: "64Mi", RequestID: "r1", Wait: "0s"}
	first, _ := e.call(req)
	e.waitClaim(CompanionName(first.Lease))
	second, _ := e.call(req)
	if first.State != api.StatePending || second.Lease != first.Lease || second.State != api.StatePending {
		t.Fatalf("first %+v, second %+v", first, second)
	}
	_, err := e.b.OnLending(first.Lease, companionClaim(first.Lease))
	mustOK(t, err)
	e.b.OnPrepared(first.Lease, state.SourcePool, []state.DeviceInfo{preparedDev(serialPoolX, 64<<20, api.ModeNUMA, 2)})
	third, _ := e.call(req)
	if third.Lease != first.Lease || third.State != api.StateReady {
		t.Fatalf("third %+v", third)
	}
	claims, err := e.client.ResourceV1().ResourceClaims(envNS).List(context.Background(), metav1.ListOptions{LabelSelector: device.LeaseLabel})
	mustOK(t, err)
	if len(claims.Items) != 1 {
		t.Fatalf("%d companion claims", len(claims.Items))
	}
	other := requester
	other.Container = "sidecar"
	e.ctrs.setPeer(&other)
	own, _ := e.call(req)
	if own.Lease == "" || own.Lease == first.Lease || own.Error != "" {
		t.Fatalf("other container's request %+v", own)
	}
	e.waitClaim(CompanionName(own.Lease))

	e.restart()
	e.start()
	e.ctrs.setPeer(&requester)
	again, _ := e.call(req)
	if again.Lease != first.Lease || again.State != api.StateReady {
		t.Fatalf("after a restart %+v", again)
	}
}

// A request line of 64 KiB is served, a longer one ends the connection
// without a response, and the next connection is served.
func TestLeaseRequestLineLimit(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	line := func(n int) string {
		return `{"op":"list"` + strings.Repeat(" ", n-len(`{"op":"list"}`)) + "}"
	}
	resp, _ := e.callRaw(line(64 * 1024))
	if resp.Error != "" || resp.Leases == nil {
		t.Fatalf("64 KiB line: %+v", resp)
	}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: e.sock(), Net: "unix"})
	mustOK(t, err)
	_, err = c.Write([]byte(line(64*1024+1) + "\n"))
	mustOK(t, err)
	mustOK(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	data, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil || len(data) != 0 {
		t.Fatalf("longer line: %q %v", data, err)
	}
	resp, _ = e.call(api.Request{Op: api.OpList})
	if resp.Error != "" || resp.Leases == nil {
		t.Fatalf("next connection: %+v", resp)
	}
}

// Several requests on one connection, each answered in order.
func TestLeaseRequestsOfOneConnection(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: e.sock(), Net: "unix"})
	mustOK(t, err)
	defer func() { _ = c.Close() }()
	_, err = c.Write([]byte(`{"op":"list"}` + "\n" + `{"op":"request","size":"64Mi","wait":"0s"}` + "\n" + `{"op":"list"}` + "\n"))
	mustOK(t, err)
	mustOK(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 0, 4096)
	for strings.Count(string(buf), "\n") < 3 {
		chunk := make([]byte, 4096)
		n, err := c.Read(chunk)
		mustOK(t, err)
		buf = append(buf, chunk[:n]...)
	}
	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"leases":[]`) || !strings.Contains(lines[1], `"state":"Pending"`) ||
		!strings.Contains(lines[2], `"lease":"000000a1"`) {
		t.Fatalf("responses %q", lines)
	}
}

// The timeout of a request releases its lease and answers Failed; wait 0
// returns Pending at once; fd and env wait for Ready and keep a lease that
// is not Ready.
func TestTimeoutReleases(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "1Gi", Wait: "50ms"})
	if resp.State != api.StateFailed || resp.Error != "timeout: not Ready after 50ms" {
		t.Fatalf("timeout response %+v", resp)
	}
	e.waitState(resp.Lease, state.LeaseNone)
	e.wantGone(CompanionName(resp.Lease))

	resp, _ = e.call(api.Request{Op: api.OpRequest, Size: "1Gi", Mode: "dax", Wait: "0s"})
	if resp.State != api.StatePending || resp.Error != "" || resp.Size != 1<<30 || resp.Env != nil {
		t.Fatalf("wait 0 response %+v", resp)
	}
	for _, op := range []string{api.OpFd, api.OpEnv} {
		r, fd := e.call(api.Request{Op: op, Lease: resp.Lease, Wait: "20ms"})
		if fd >= 0 || r.State != api.StatePending || r.Error != "" {
			t.Fatalf("%s of a pending lease %+v fd %d", op, r, fd)
		}
	}
	if l := e.lease(resp.Lease); l == nil || l.State != state.LeasePending || l.ReleaseRequested {
		t.Fatalf("lease after fd and env %+v", l)
	}
	// a request id whose lease is still CREATING: its wait ends too
	e.b.mu.Lock()
	l := e.b.leases[resp.Lease]
	l.RequestID = "r9"
	l.State = state.LeaseCreating
	e.b.mu.Unlock()
	r, _ := e.call(api.Request{Op: api.OpRequest, Size: "1Gi", RequestID: "r9", Wait: "20ms"})
	if r.State != api.StateFailed || r.Lease != resp.Lease {
		t.Fatalf("request id of a CREATING lease %+v", r)
	}
	e.waitState(resp.Lease, state.LeaseNone)
}

// Only the companion claim of a lease is lent: its name, namespace and
// owner; a failed lease is not lent again.
func TestOnLending(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	id := resp.Lease
	wrongName, wrongNS, wrongOwner, noOwner := companionClaim(id), companionClaim(id), companionClaim(id), companionClaim(id)
	wrongName.Name = "cxl-lease-ffffffff"
	wrongNS.Namespace = "other"
	wrongOwner.OwnerReferences[0].UID = "pod-uid-2"
	noOwner.OwnerReferences = nil
	for _, c := range []struct {
		id    string
		claim *resourcev1.ResourceClaim
	}{
		{"ffffffff", companionClaim("ffffffff")}, {id, wrongName}, {id, wrongNS}, {id, wrongOwner}, {id, noOwner},
	} {
		_, err := e.b.OnLending(c.id, c.claim)
		if err == nil || err.Error() != fmt.Sprintf("claim %s/%s: not the companion of lease %s", c.claim.Namespace, c.claim.Name, c.id) {
			t.Errorf("lease %s claim %s/%s owners %v: %v", c.id, c.claim.Namespace, c.claim.Name, c.claim.OwnerReferences, err)
		}
	}
	if l := e.lease(id); l.State != state.LeasePending {
		t.Fatalf("refused companions changed the lease: %+v", l)
	}
	rec, err := e.b.OnLending(id, companionClaim(id))
	mustOK(t, err)
	if !reflect.DeepEqual(rec, &lend.Lend{Lease: id, Pod: requester.Pod, Container: envCtr}) {
		t.Fatalf("lend %+v", rec)
	}
	if l := e.stored(id); l == nil || l.State != state.LeaseLending {
		t.Fatalf("lease %+v", l)
	}
	if _, err := e.b.OnLending(id, companionClaim(id)); err != nil {
		t.Fatalf("a Prepare again: %v", err)
	}
	e.b.OnLendFailed(id, errors.New("boom"))
	_, err = e.b.OnLending(id, companionClaim(id))
	if err == nil || err.Error() != "lease "+id+" is Failed" {
		t.Fatalf("a failed lease lent: %v", err)
	}
	// the hooks of an unknown lease change nothing
	e.b.OnPrepared("ffffffff", state.SourcePool, []state.DeviceInfo{numaDevice})
	e.b.OnLendFailed("ffffffff", errors.New("boom"))
	e.b.OnReleasing("ffffffff")
	e.waitState(id, state.LeaseNone)
	if e.numLeases() != 0 {
		t.Fatalf("leases %d", e.numLeases())
	}
}

// A lend that failed fails the lease and releases it in place: it stays
// FAILED with the error until it is gone; the waiting client gets Failed
// with the error.
func TestLendFailed(t *testing.T) {
	var stay atomic.Bool
	e := brokerEnv(t)
	e.client.PrependReactor("delete", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return stay.Load(), nil, nil // accepted, the pod stays (Terminating)
	})
	e.openClaim()
	e.start()
	ch := e.async(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "5s"})
	claim := e.waitClaim(CompanionName("000000a1"))
	stay.Store(true)
	_, err := e.b.OnLending("000000a1", claim)
	mustOK(t, err)
	e.b.OnLendFailed("000000a1", errors.New("lease 000000a1: lending node 2 to demo/borrower/app: container is steered"))
	resp := <-ch
	if resp.State != api.StateFailed || resp.Error != "lease 000000a1: lending node 2 to demo/borrower/app: container is steered" {
		t.Fatalf("response %+v", resp)
	}
	l := e.lease("000000a1")
	if l == nil || l.State != state.LeaseFailed || !l.ReleaseRequested {
		t.Fatalf("lease %+v", l)
	}
	// the list shows why while it is released
	list, _ := e.call(api.Request{Op: api.OpList})
	if list.Leases == nil || len(*list.Leases) != 1 || (*list.Leases)[0].State != api.StateFailed || (*list.Leases)[0].Error != l.Error {
		t.Fatalf("list %+v", list)
	}
	e.b.OnLendFailed("000000a1", errors.New("again"))
	if l := e.lease("000000a1"); l.Error == "again" {
		t.Fatalf("a failed lease failed again %+v", l)
	}
	stay.Store(false)
	e.waitState("000000a1", state.LeaseNone)
	e.wantGone(CompanionName("000000a1"))
}

// A device of the companion whose mode is fs or block when the lease's is
// not, or the reverse, fails the lease, and it is released.
func TestPreparedModeMismatch(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	for i, c := range []struct {
		req api.Request
		dev state.DeviceInfo
		err string
	}{
		{api.Request{Op: "request", Shared: true, ReadOnly: true, Mode: "fs", Size: "64Mi", Wait: "5s"},
			withDev(preparedDev(serialPoolS, 1<<28, api.ModeDax, -1), func(d *state.DeviceInfo) { d.DaxDevice = "/dev/dax0.0" }),
			"companion prepared mode dax, lease is mode fs"},
		{api.Request{Op: "request", Source: "pool", Mode: "dax", Size: "64Mi", Wait: "5s"},
			withDev(preparedDev(serialPoolP, pmemBytes, api.ModeFs, -1), func(d *state.DeviceInfo) { d.Access = "direct" }),
			"companion prepared mode fs, lease is mode dax"},
		{api.Request{Op: "request", Shared: true, ReadOnly: true, Mode: "block", Size: "64Mi", Wait: "5s"},
			withDev(preparedDev(serialPoolP, pmemBytes, api.ModeFs, -1), func(d *state.DeviceInfo) { d.Access, d.BlockDevice = "direct", "/dev/pmem0" }),
			"companion prepared mode fs, lease is mode block"},
		{api.Request{Op: "request", Shared: true, ReadOnly: true, Mode: "fs", Size: "64Mi", Wait: "5s"},
			withDev(preparedDev(serialPoolP, pmemBytes, api.ModeBlock, -1), func(d *state.DeviceInfo) { d.ReadOnly, d.BlockDevice = true, "/dev/pmem0" }),
			"companion prepared mode block, lease is mode fs"},
		{api.Request{Op: "request", Source: "pool", Mode: "block", Size: "64Mi", Wait: "5s"},
			withDev(preparedDev(serialPoolX, 1<<28, api.ModeDax, -1), func(d *state.DeviceInfo) { d.DaxDevice = "/dev/dax0.0" }),
			"companion prepared mode dax, lease is mode block"},
	} {
		id := fmt.Sprintf("%08x", 0xa1+i)
		ch := e.async(c.req)
		e.waitClaim(CompanionName(id))
		_, err := e.b.OnLending(id, companionClaim(id))
		mustOK(t, err)
		e.b.OnPrepared(id, state.SourcePool, []state.DeviceInfo{c.dev})
		if r := <-ch; r.State != api.StateFailed || r.Error != c.err || r.Path != "" || r.Block != "" {
			t.Errorf("%s: response %+v", c.err, r)
		}
		e.waitState(id, state.LeaseNone)
		e.wantGone(CompanionName(id))
	}
}

// The restart keeps the leases and the sockets, the reconcile lends the
// node of a READY numa lease again, deletes the companions without a lease
// (and nothing else), keeps the lease of a restarting requester and
// releases that of a deleted requester pod.
func TestRestartAndReconcile(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	id := e.readyNUMA()
	if got := state.LeaseLends(&e.st.Snapshot().Records, envPodUID, envCtr); !reflect.DeepEqual(got, map[int][]string{2: {id}}) {
		t.Fatalf("lends of the store %v", got)
	}
	if l := e.stored(id); l == nil || l.Lend == nil || state.NumaNodeOf(l.Lend.NumaNode) != 2 || l.Got == nil || l.Got.Bytes != 1<<28 {
		t.Fatalf("stored lease %+v", l)
	}

	e.restart()
	e.ctrs.forget()
	e.start()
	if l := e.lease(id); l == nil || l.State != state.LeaseReady || numaNodeOf(l) != 2 {
		t.Fatalf("lease after restart %+v", l)
	}
	list, _ := e.call(api.Request{Op: api.OpList})
	if list.Leases == nil || len(*list.Leases) != 1 {
		t.Fatalf("list after restart %+v", list)
	}
	e.b.reconcile()
	if got := e.ctrs.lentNodes(envPodUID, envCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("lend not re-applied by reconcile: %v", got)
	}

	others := []metav1.ObjectMeta{
		{Name: "cxl-lease-0badf00e", Namespace: envNS, Labels: map[string]string{device.NodeLabel: envNode}},
		{Name: "workload", Namespace: envNS, Labels: map[string]string{device.LeaseLabel: "0badf00f", device.NodeLabel: envNode}},
		{Name: "cxl-lease-0badf00c", Namespace: envNS, Labels: map[string]string{device.LeaseLabel: "0badf00c", device.NodeLabel: "node2"}},
	}
	for _, meta := range append(others, metav1.ObjectMeta{Name: "cxl-lease-0badf00d", Namespace: envNS,
		Labels: map[string]string{device.LeaseLabel: "0badf00d", device.NodeLabel: envNode}}) {
		_, err := e.client.CoreV1().Pods(envNS).Create(context.Background(), &corev1.Pod{ObjectMeta: meta}, metav1.CreateOptions{})
		mustOK(t, err)
		_, err = e.client.ResourceV1().ResourceClaims(envNS).Create(context.Background(), &resourcev1.ResourceClaim{ObjectMeta: meta}, metav1.CreateOptions{})
		mustOK(t, err)
	}
	e.b.reconcile()
	e.wantGone("cxl-lease-0badf00d")
	for _, meta := range others {
		_, perr := e.client.CoreV1().Pods(envNS).Get(context.Background(), meta.Name, metav1.GetOptions{})
		_, cerr := e.client.ResourceV1().ResourceClaims(envNS).Get(context.Background(), meta.Name, metav1.GetOptions{})
		if perr != nil || cerr != nil {
			t.Fatalf("%s deleted: %v %v", meta.Name, perr, cerr)
		}
	}
	if e.lease(id) == nil {
		t.Fatal("live lease dropped by reconcile")
	}

	// the requester container stopped but the pod restarts it: kept
	e.ctrs.setRunning(envPodUID, envCtr, false)
	e.b.reconcile()
	if e.lease(id) == nil {
		t.Fatal("lease of a restarting container dropped")
	}
	// the requester pod is deleted: released
	mustOK(t, e.client.CoreV1().Pods(envNS).Delete(context.Background(), envPod, metav1.DeleteOptions{}))
	e.b.reconcile()
	e.waitState(id, state.LeaseNone)
	e.wantGone(CompanionName(id))
	if got := state.LeaseLends(&e.st.Snapshot().Records, envPodUID, envCtr); got != nil {
		t.Fatalf("lends %v after the release", got)
	}
	if !strings.Contains(e.ctrs.callLog(), "revoke pod-uid-1/app 2") {
		t.Fatalf("not revoked:\n%s", e.ctrs.callLog())
	}
}

// A lease that the companion made READY just as the wait of its request
// ended is released: the wait's end releases a READY lease too.
func TestTimeoutOfAReadyLease(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	id := e.readyNUMA()
	resp := e.b.startRelease(id, "timeout: not Ready after 1s", state.TriggerRequest)
	if resp.State != api.StateReleasing {
		t.Fatalf("response %+v", resp)
	}
	e.waitState(id, state.LeaseNone)
	e.wantGone(CompanionName(id))
	if !strings.Contains(e.ctrs.callLog(), "revoke pod-uid-1/app 2") {
		t.Fatalf("not revoked:\n%s", e.ctrs.callLog())
	}
}

// RELEASING is committed before the node of a numa lease is revoked, so
// that a requester container created after the revoke is not seeded with
// the node (state.LeaseLends of the store): released by the client and by
// CloseClaim.
func TestReleasingCommittedBeforeRevoke(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	var seeded []string
	e.ctrs.setOnRevoke(func(podUID, container string, node int, holder string) {
		for _, h := range state.LeaseLends(&e.st.Snapshot().Records, podUID, container)[node] {
			if h == holder {
				seeded = append(seeded, holder)
			}
		}
		if l := e.st.Snapshot().Lease(holder); l == nil || !releasingState(l.State) || !l.ReleaseRequested {
			seeded = append(seeded, holder+" not RELEASING")
		}
	})
	id := e.readyNUMA()
	if rel, _ := e.call(api.Request{Op: api.OpRelease, Lease: id}); rel.State != api.StateReleased {
		t.Fatalf("release %+v", rel)
	}
	id2 := e.readyNUMA()
	mustOK(t, e.b.CloseClaim(context.Background(), envLeaseClaim))
	e.waitState(id2, state.LeaseNone)
	if calls := e.ctrs.callLog(); strings.Count(calls, "revoke pod-uid-1/app 2") != 2 {
		t.Fatalf("revokes:\n%s", calls)
	}
	if len(seeded) != 0 {
		t.Fatalf("leases of the store at their revoke: %v", seeded)
	}
}

// The reconcile releases a lease that is Creating for longer than the
// grace (left over by a crash) and keeps a newer one.
func TestLeaseCreatingGrace(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	pod := requester.Pod
	e.b.mu.Lock()
	for id, created := range map[string]time.Time{"0000old0": time.Now().Add(-time.Second), "0000new0": time.Now().Add(time.Hour)} {
		e.b.leases[id] = &state.Lease{ID: id, Claim: envLeaseClaim, Asked: state.LeaseAsked{Mode: state.ModeNUMA, Size: "64Mi"}, Pod: pod,
			Container: envCtr, State: state.LeaseCreating, Created: created.UTC()}
	}
	mustOK(t, e.b.persistLocked())
	e.b.mu.Unlock()
	e.opts = func(o *Options) { o.Timeouts.CreatingGrace = 100 * time.Millisecond }
	e.restart()
	e.start()
	e.b.reconcile()
	e.waitState("0000old0", state.LeaseNone)
	if l := e.lease("0000new0"); l == nil || l.State != state.LeaseCreating {
		t.Fatalf("newer Creating lease %+v", l)
	}
}

// The lends are restored once, after the first reconcile has lent the
// nodes of the READY numa leases again.
func TestLendsRestored(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	e.readyNUMA()
	e.opts = func(o *Options) { o.Timeouts.Reconcile = 10 * time.Millisecond }
	e.restart()
	e.ctrs.forget()
	e.ctrs.restored = make(chan string, 2)
	e.start()
	select {
	case calls := <-e.ctrs.restored:
		if !strings.Contains(calls, "lend pod-uid-1/app 2") {
			t.Fatalf("lends restored before the lend:\n%s", calls)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lends not restored")
	}
	time.Sleep(50 * time.Millisecond) // more reconciles
	select {
	case <-e.ctrs.restored:
		t.Fatal("lends restored twice")
	default:
	}
}

// The companion unprepared behind the broker fails the lease and the
// reconcile releases it, its companion pod deleted; the requester
// with restartPolicy Never releases its leases when its container stops;
// a started container gets its nodes again.
func TestCompanionGoneAndContainerGone(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	r1, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	r2, _ := e.call(api.Request{Op: api.OpRequest, Serial: "0xc1ae0001", Shared: true, Wait: "0s"})
	e.waitClaim(CompanionName(r2.Lease))

	e.b.OnReleasing(r1.Lease)
	if l := e.lease(r1.Lease); l.State != state.LeaseFailed || l.Error != "companion claim unprepared (companion pod deleted or evicted)" {
		t.Fatalf("lease %+v", l)
	}
	// released by the reconcile, also while its companion runs
	e.b.reconcile()
	e.waitState(r1.Lease, state.LeaseNone)
	e.wantGone(CompanionName(r1.Lease))

	// a started container gets the nodes of its READY numa leases again
	id := e.readyNUMA()
	e.ctrs.forget()
	for _, fn := range e.ctrs.started {
		fn(requester.Pod, envCtr)
	}
	if got := e.ctrs.lentNodes(envPodUID, envCtr); !slices.Equal(got, []int{2}) {
		t.Fatalf("not lent again at the start of the container: %v", got)
	}

	// the container is gone but restarts: kept
	e.ctrs.setRunning(envPodUID, envCtr, false)
	for _, fn := range e.ctrs.gone {
		fn(requester.Pod, envCtr)
	}
	if e.lease(r2.Lease) == nil || e.lease(id) == nil {
		t.Fatal("leases of a restarting container released")
	}
	// a new instance is there already: kept
	e.ctrs.setRunning(envPodUID, envCtr, true)
	pod := requesterPod()
	pod.Spec.RestartPolicy = corev1.RestartPolicyNever
	_, err := e.client.CoreV1().Pods(envNS).Update(context.Background(), pod, metav1.UpdateOptions{})
	mustOK(t, err)
	e.b.containerGone(requester.Pod, envCtr)
	if e.lease(r2.Lease) == nil {
		t.Fatal("lease of a new instance released")
	}
	// restartPolicy Never: released
	e.ctrs.setRunning(envPodUID, envCtr, false)
	e.b.containerGone(requester.Pod, envCtr)
	e.waitState(r2.Lease, state.LeaseNone)
	e.waitState(id, state.LeaseNone)
	e.wantGone(CompanionName(r2.Lease))
}

// CloseClaim releases the leases of the lease claim.
func TestCloseClaimReleasesLeases(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	r, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	mustOK(t, e.b.CloseClaim(context.Background(), envLeaseClaim))
	e.waitState(r.Lease, state.LeaseNone)
	e.wantGone(CompanionName(r.Lease))
	if e.claim(envLeaseClaim) != nil {
		t.Fatal("lease claim left")
	}
}

// CloseClaim of a lease claim whose lease has a companion that stays
// Terminating, as the companion of a local lease does while the Unprepare
// of the lease claim runs (kubelet unprepares the companion's claim
// through the same driver, after it): it returns once the node is revoked
// and the deletion requested; a restart meanwhile continues the release.
func TestCloseClaimDoesNotWaitForCompanions(t *testing.T) {
	e := brokerEnv(t)
	var stay atomic.Bool
	e.client.PrependReactor("delete", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return stay.Load(), nil, nil
	})
	e.openClaim()
	e.start()
	r, _ := e.call(api.Request{Op: api.OpRequest, Size: "64Mi", Source: "local", Wait: "0s"})
	_, err := e.b.OnLending(r.Lease, companionClaim(r.Lease))
	mustOK(t, err)
	e.b.OnPrepared(r.Lease, state.SourceLocal, []state.DeviceInfo{preparedDev(serialSliced, 64<<20, api.ModeNUMA, 2)})
	mustOK(t, e.ctrs.LendNode(context.Background(), envPodUID, envCtr, 2, r.Lease))
	stay.Store(true)

	start := time.Now()
	mustOK(t, e.b.CloseClaim(context.Background(), envLeaseClaim))
	if d := time.Since(start); d > time.Second {
		t.Fatalf("CloseClaim waited %v for the companion", d)
	}
	if got := e.ctrs.lentNodes(envPodUID, envCtr); len(got) != 0 {
		t.Fatalf("CloseClaim returned before the revoke: %v lent", got)
	}
	if _, err := os.Stat(e.sock()); !os.IsNotExist(err) {
		t.Fatalf("socket left after CloseClaim: %v", err)
	}
	if l := e.stored(r.Lease); l == nil || l.State != state.LeaseReleasing || !l.ReleaseRequested || !l.DeletionRequested {
		t.Fatalf("lease with a terminating companion %+v", l)
	}

	e.restart()
	e.start()
	if l := e.lease(r.Lease); l == nil {
		t.Fatal("lease dropped before its companion is gone")
	}
	e.b.reconcile()
	stay.Store(false)
	e.waitState(r.Lease, state.LeaseNone)
	e.wantGone(CompanionName(r.Lease))
}

// CloseClaim fails while the deletion of a companion cannot be requested
// ("still releasing", kubelet retries): the claim is CLOSING with its
// socket, which refuses new leases and serves the others; a restart keeps
// it CLOSING and listens on it again; the retry closes it.
func TestCloseClaimRetry(t *testing.T) {
	e := brokerEnv(t)
	var fail atomic.Bool
	e.client.PrependReactor("delete", "resourceclaims", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if fail.Load() {
			return true, nil, errors.New("apiserver unavailable")
		}
		return false, nil, nil
	})
	e.opts = func(o *Options) { o.Timeouts.Close = 50 * time.Millisecond }
	e.restart()
	e.openClaim()
	e.start()
	r, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	fail.Store(true)
	wantErrText(t, e.b.CloseClaim(context.Background(), envLeaseClaim), "claim demo/lease: still releasing 1 leases, retry")
	if _, err := os.Stat(e.sock()); err != nil {
		t.Fatalf("socket closed too early: %v", err)
	}
	if c := e.st.Snapshot().LeaseClaim(envLeaseClaim); c == nil || c.State != state.LeaseClaimClosing {
		t.Fatalf("lease claim %+v", c)
	}
	// lists are served while it closes, new leases refused
	if resp, _ := e.call(api.Request{Op: api.OpList}); resp.Error != "" {
		t.Fatalf("list on a closing claim %+v", resp)
	}
	if resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"}); resp.Error != "lease claim demo/lease is being unprepared: no new leases" {
		t.Fatalf("request on a closing claim %+v", resp)
	}
	wantErrText(t, e.b.CloseClaim(context.Background(), envLeaseClaim), "still releasing 1 leases, retry")

	e.opts = nil
	e.restart()
	if c := e.st.Snapshot().LeaseClaim(envLeaseClaim); c == nil || c.State != state.LeaseClaimClosing {
		t.Fatalf("lease claim after a restart %+v", c)
	}
	e.start()
	if resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"}); resp.Error == "" {
		t.Fatalf("request on a closing claim after a restart %+v", resp)
	}
	fail.Store(false)
	mustOK(t, e.b.CloseClaim(context.Background(), envLeaseClaim))
	e.waitState(r.Lease, state.LeaseNone)
	e.wantGone(CompanionName(r.Lease))
}

// A Prepare of a lease claim whose close timed out opens it again.
func TestOpenClaimOfAClosingClaim(t *testing.T) {
	e := brokerEnv(t)
	var fail atomic.Bool
	e.client.PrependReactor("delete", "resourceclaims", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if fail.Load() {
			return true, nil, errors.New("apiserver unavailable")
		}
		return false, nil, nil
	})
	e.opts = func(o *Options) { o.Timeouts.Close = 50 * time.Millisecond }
	e.restart()
	e.openClaim()
	e.start()
	r, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	fail.Store(true)
	wantErrText(t, e.b.CloseClaim(context.Background(), envLeaseClaim), "still releasing")
	e.openClaim()
	if c := e.claim(envLeaseClaim); c == nil || c.State != state.LeaseClaimOpen {
		t.Fatalf("lease claim %+v", c)
	}
	fail.Store(false)
	e.waitState(r.Lease, state.LeaseNone)
}

// CloseClaim waits for a removal of the claim's directories in progress
// (the sweep of a reconcile), and the socket of a claim is not started
// while its directories are removed.
func TestCloseClaimWaitsForRemoval(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	busy := make(chan struct{})
	e.b.mu.Lock()
	e.b.removing[envLeaseClaim] = busy
	e.b.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- e.b.CloseClaim(context.Background(), envLeaseClaim) }()
	select {
	case err := <-done:
		t.Fatalf("CloseClaim returned during a removal: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Stat(filepath.Dir(e.sock())); err != nil {
		t.Fatalf("directories removed during another removal: %v", err)
	}
	e.b.mu.Lock()
	delete(e.b.removing, envLeaseClaim)
	close(busy)
	e.b.mu.Unlock()
	mustOK(t, <-done)
	if _, err := os.Stat(filepath.Dir(e.sock())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directories left: %v", err)
	}
	e.b.mu.Lock()
	e.b.removing["lc3"] = make(chan struct{})
	err := e.b.listen("lc3")
	e.b.mu.Unlock()
	if err == nil || err.Error() != "the directories of lease claim lc3 are being removed, retry" {
		t.Fatalf("listen during a removal: %v", err)
	}
}

// What a container of before the read-only mount of its socket directory
// put there is never followed: a symlink at the socket path does not get
// the mode of the socket, a symlink at the mount point of api.FsDir is
// replaced by a directory, and the entries that the container wrote are
// removed with the claim, not their targets.
func TestLeaseSocketNoFollow(t *testing.T) {
	e := brokerEnv(t)
	dir := filepath.Dir(e.sock())
	victim := filepath.Join(t.TempDir(), "victim")
	mustOK(t, os.WriteFile(victim, []byte("x"), 0o600))
	victimDir := t.TempDir()
	mustOK(t, os.Chmod(victimDir, 0o700))
	mustOK(t, os.MkdirAll(dir, 0o755))
	mustOK(t, os.Symlink(victim, e.sock()))
	mustOK(t, os.Symlink(victimDir, filepath.Join(dir, leaseFsMountPoint)))
	mustOK(t, os.MkdirAll(filepath.Join(dir, "junk", "deep"), 0o755))
	mustOK(t, os.WriteFile(filepath.Join(dir, "junk", "deep", "f"), []byte("x"), 0o644))
	mustOK(t, os.Symlink(victimDir, filepath.Join(dir, "link")))

	e.openClaim()
	if st, err := os.Lstat(e.sock()); err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o666 {
		t.Fatalf("socket %v %v", st, err)
	}
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0o600 {
		t.Fatalf("the target of a symlink got mode %v", st.Mode())
	}
	if st, err := os.Lstat(filepath.Join(dir, leaseFsMountPoint)); err != nil || !st.IsDir() || st.Mode().Perm() != 0o755 {
		t.Fatalf("mount point %v %v", st, err)
	}
	if st, _ := os.Stat(victimDir); st.Mode().Perm() != 0o700 {
		t.Fatalf("the target of a symlink got mode %v", st.Mode())
	}
	mustOK(t, e.b.CloseClaim(context.Background(), envLeaseClaim))
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket directory left: %v", err)
	}
	for _, p := range []string{victim, victimDir} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("the target of a symlink was removed: %v", err)
		}
	}
}

// A lease-fs directory is kept when the mounts cannot be read.
func TestRemoveFsDirMountsError(t *testing.T) {
	e := brokerEnv(t)
	dir := filepath.Join(e.dir, "lease-fs", "gone")
	mustOK(t, os.MkdirAll(filepath.Join(dir, "x"), 0o755))
	e.opts = func(o *Options) { o.Mounts = func() ([]kernelMount, error) { return nil, errors.New("no mountinfo") } }
	e.restart() // the sweep at start
	if e.b.removeFsDir("gone") {
		t.Fatal("removed without mountinfo")
	}
	if _, err := os.Stat(filepath.Join(dir, "x")); err != nil {
		t.Fatalf("directory removed without mountinfo: %v", err)
	}
}

// A lease claim prepared without a filesystem directory has no fs leases
// and no /run/cxl/fs, also after OpenClaim again; the lease-fs directories
// of claims without a record are removed at the start and by the
// reconcile, unless a mount is in them.
func TestFsLeaseClaims(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	e.b.mu.Lock()
	e.b.claims[envLeaseClaim].FsDir = ""
	e.b.mu.Unlock()
	e.openClaim()
	e.b.mu.Lock()
	dev := e.b.cdiDevice(envLeaseClaim)
	fsDir := e.b.claims[envLeaseClaim].FsDir
	e.b.mu.Unlock()
	if fsDir != "" || len(dev.ContainerEdits.Mounts) != 2 || dev.ContainerEdits.Mounts[1].ContainerPath != "/usr/local/bin/cxl-request" {
		t.Fatalf("FsDir %q, CDI mounts %+v", fsDir, dev.ContainerEdits.Mounts)
	}
	r, _ := e.call(api.Request{Op: api.OpRequest, Serial: "0xc1af0001", Shared: true, ReadOnly: true, Mode: "fs"})
	if r.Error != "lease claim demo/lease has no filesystem directory (prepared by an older driver): recreate the pod" {
		t.Fatalf("fs lease of an old lease claim %+v", r)
	}
	if l, _ := e.client.ResourceV1().ResourceClaims(envNS).List(context.Background(), metav1.ListOptions{}); len(l.Items) != 1 || e.numLeases() != 0 {
		t.Fatalf("objects for a refused request: %d claims, %d leases", len(l.Items), e.numLeases())
	}
	r, _ = e.call(api.Request{Op: api.OpRequest, Size: "64Mi", Wait: "0s"})
	if r.Error != "" || r.State != api.StatePending {
		t.Fatalf("numa lease of an old lease claim %+v", r)
	}

	root := filepath.Join(e.dir, "lease-fs")
	var mu atomicMounts
	e.opts = func(o *Options) { o.Mounts = mu.get }
	for _, d := range []string{"gone/x", "gone/y", "held/x", "held/y", "nested/x/sub"} {
		mustOK(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	mu.set([]kernelMount{{Target: filepath.Join(root, "held/x")}, {Target: filepath.Join(root, "nested/x/sub")}})
	e.restart()
	e.start()
	for d, exists := range map[string]bool{"gone": false, "held": true, "held/x": true, "held/y": false, "nested/x/sub": true} {
		if _, err := os.Stat(filepath.Join(root, d)); (err == nil) != exists {
			t.Errorf("%s exists %v, expected %v", d, err == nil, exists)
		}
	}
	mu.set(nil)
	e.b.reconcile()
	var left []string
	entries, _ := os.ReadDir(root)
	for _, d := range entries {
		left = append(left, d.Name())
	}
	if !slices.Equal(left, []string{envLeaseClaim, "nested"}) {
		t.Fatalf("lease-fs directories left: %v", left)
	}
}

// A lost store: the broker starts without lease claims and leases, keeps
// every directory of lease claims, and refuses to open a lease claim with
// the text of the lost state.
func TestLostStore(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.b.Stop()
	_ = e.st.Close()
	mustOK(t, os.WriteFile(filepath.Join(e.dir, store.FileName), []byte("{"), 0o600))
	mustOK(t, os.WriteFile(filepath.Join(e.dir, store.PrevName), []byte("{"), 0o600))
	e.boot()
	if e.st.Lost() == nil {
		t.Fatal("the store is not lost")
	}
	e.start()
	if e.claim(envLeaseClaim) != nil || e.numLeases() != 0 || !e.b.lost {
		t.Fatalf("lease claims or leases of a lost store")
	}
	e.b.reconcile()
	for _, d := range []string{filepath.Join(e.dir, "lease-fs", envLeaseClaim), filepath.Join(filepath.Dir(e.sock()), "fs")} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("directory of a lease claim removed with a lost store: %v", err)
		}
	}
	wantErrText(t, e.b.OpenClaim(leaseClaimObj()), "--new-state")

	// a start with a new document sweeps the directories of the lease
	// claims that it does not know
	e.b.Stop()
	_ = e.st.Close()
	e.newState = true
	e.boot()
	if e.st.Lost() != nil || e.b.lost {
		t.Fatal("the new document is lost")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "lease-fs", envLeaseClaim)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory of an unknown lease claim kept: %v", err)
	}
}

// A reboot drops the leases of the old boot (the store does): a numa lease
// is neither lent to the restarted requester nor revoked, the reconcile
// deletes its companion, the lease claim keeps its socket and the
// requester's new request is served.
func TestOtherBoot(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	id := e.readyNUMA()
	e.ctrs.forget()
	e.reboot()
	if e.lease(id) != nil || state.LeaseLends(&e.st.Snapshot().Records, envPodUID, envCtr) != nil {
		t.Fatalf("lease of another boot %+v", e.lease(id))
	}
	if doc := e.st.Snapshot(); doc.Lease(id) != nil || doc.LeaseClaim(envLeaseClaim) == nil {
		t.Fatalf("stored leases %+v and lease claims %+v after the reboot", doc.Leases, doc.LeaseClaims)
	}
	e.start()
	list, _ := e.call(api.Request{Op: api.OpList})
	if list.Error != "" || list.Leases == nil || len(*list.Leases) != 0 {
		t.Fatalf("list after the reboot %+v", list)
	}
	e.b.reconcile()
	e.wantGone(CompanionName(id))
	if got := e.ctrs.lentNodes(envPodUID, envCtr); len(got) != 0 || e.ctrs.callLog() != "" {
		t.Fatalf("lent nodes %v, calls:\n%s", got, e.ctrs.callLog())
	}
	resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	if resp.Error != "" || resp.State != api.StatePending {
		t.Fatalf("new request %+v", resp)
	}
	e.waitClaim(CompanionName(resp.Lease))
}

// kernelMount is a mount of the fake mount table of a test.
type kernelMount = kernel.MountInfo

// atomicMounts is a mount table that a test changes while the broker reads
// it.
type atomicMounts struct {
	v atomic.Pointer[[]kernelMount]
}

func (m *atomicMounts) set(mounts []kernelMount) { m.v.Store(&mounts) }

func (m *atomicMounts) get() ([]kernelMount, error) {
	if p := m.v.Load(); p != nil {
		return slices.Clone(*p), nil
	}
	return nil, nil
}

// CloseClaim closes the open connections of the claim's socket with its
// listener: a client waiting on one reads EOF.
func TestCloseClaimClosesConnections(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: e.sock(), Net: "unix"})
	mustOK(t, err)
	defer func() { _ = c.Close() }()
	// an answered request: the connection is served
	_, err = c.Write([]byte(`{"op":"list"}` + "\n"))
	mustOK(t, err)
	mustOK(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	r := bufio.NewReader(c)
	if line, err := r.ReadString('\n'); err != nil || !strings.Contains(line, `"leases":[]`) {
		t.Fatalf("list: %q %v", line, err)
	}
	mustOK(t, e.b.CloseClaim(context.Background(), envLeaseClaim))
	if data, err := io.ReadAll(r); err != nil || len(data) != 0 {
		t.Fatalf("after CloseClaim: %q %v", data, err)
	}
}

// A pod with two lease claims lists and releases on the socket of each
// only the leases asked for on that socket.
func TestLeaseListAndReleaseOfTheClaim(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	other := leaseClaimObj()
	other.Name, other.UID = "lease2", "lc2"
	mustOK(t, e.b.OpenClaim(other))
	e.start()
	r, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	if r.Error != "" {
		t.Fatalf("request %+v", r)
	}
	r2 := e.callAt("lc2", api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	if r2.Error != "" {
		t.Fatalf("request on lc2 %+v", r2)
	}
	ids := func(resp api.Response) []string {
		var out []string
		if resp.Leases != nil {
			for _, l := range *resp.Leases {
				out = append(out, l.Lease)
			}
		}
		return out
	}
	if got, _ := e.call(api.Request{Op: api.OpList}); !slices.Equal(ids(got), []string{r.Lease}) {
		t.Fatalf("list on lc1 %+v", got)
	}
	if got := e.callAt("lc2", api.Request{Op: api.OpList}); !slices.Equal(ids(got), []string{r2.Lease}) {
		t.Fatalf("list on lc2 %+v", got)
	}
	if got := e.callAt("lc2", api.Request{Op: api.OpRelease, Lease: r.Lease, Wait: "0s"}); got.Error != "no such lease" {
		t.Fatalf("release of a lease of lc1 on lc2 %+v", got)
	}
	if got := e.callAt("lc2", api.Request{Op: api.OpRelease, All: true, Wait: "0s"}); !slices.Equal(ids(got), []string{r2.Lease}) {
		t.Fatalf("release --all on lc2 %+v", got)
	}
	e.b.mu.Lock()
	_, kept := e.b.leases[r.Lease]
	e.b.mu.Unlock()
	if !kept {
		t.Fatalf("lease %s of lc1 released by release --all on lc2", r.Lease)
	}
}

// The broker tells the companion gate the hash of the companion claim's
// spec as the API server returned it at its creation, while the lease
// waits for the claim's first Prepare.
func TestCompanionSpecHash(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	r, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	if r.Error != "" {
		t.Fatalf("request %+v", r)
	}
	claim, err := e.client.ResourceV1().ResourceClaims(envNS).Get(context.Background(), CompanionName(r.Lease), metav1.GetOptions{})
	mustOK(t, err)
	hash, first := e.b.CompanionSpecHash(r.Lease)
	if hash != lend.SpecHash(&claim.Spec) || !first {
		t.Fatalf("hash %q first %v, want %q first", hash, first, lend.SpecHash(&claim.Spec))
	}
	var hasher lend.SpecHasher = e.b
	if h, _ := hasher.CompanionSpecHash("00000000"); h != "" {
		t.Fatalf("hash of no lease %q", h)
	}
}

// A graceful stop does not release the lease of a request still waiting
// for Ready: the client is told to ask again, the lease stays for
// the restarted plugin.
func TestStopKeepsWaitingLease(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	ch := e.async(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "60s"})
	e.waitClaim(CompanionName("000000a1"))
	e.b.Stop()
	var resp api.Response
	select {
	case resp = <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("no response at the stop")
	}
	if !strings.Contains(resp.Error, "the driver is stopping: lease 000000a1 stays Pending, ask again") {
		t.Fatalf("response %+v", resp)
	}
	if l := e.st.Snapshot().Lease("000000a1"); l == nil || l.State != state.LeasePending {
		t.Fatalf("lease %+v after the stop", l)
	}
}

// A commit of the broker's records waits at most Timeouts.Persist for a
// stalled store: the error is returned, the mutex is not held for
// ever, the commit is applied later.
func TestPersistBounded(t *testing.T) {
	e := brokerEnv(t)
	e.opts = func(o *Options) { o.Timeouts.Persist = 50 * time.Millisecond }
	e.restart()
	stall, stalled := make(chan struct{}), make(chan struct{})
	go func() {
		_ = e.st.Commit(context.Background(), store.Lazy, func(*store.Document) error {
			close(stalled)
			<-stall
			return nil
		})
	}()
	<-stalled
	start := time.Now()
	e.b.mu.Lock()
	err := e.b.persistLocked()
	e.b.mu.Unlock()
	close(stall)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("persist of a stalled store: %v after %v", err, time.Since(start))
	}
}

// The reconcile releases a FAILED lease whose companion still runs: its
// companion is deleted and the lease goes.
func TestReconcileReleasesFailedLease(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	r, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	e.waitClaim(CompanionName(r.Lease))
	e.b.mu.Lock()
	l := e.b.leases[r.Lease]
	l.State, l.Error = state.LeaseFailed, "lending failed"
	e.b.mu.Unlock()
	e.b.reconcile()
	e.waitState(r.Lease, state.LeaseNone)
	e.wantGone(CompanionName(r.Lease))
}

// The identity of every request on a connection is evaluated again:
// a peer that is now in another pod is refused; a peer in no known
// container (its process exited) keeps the identity of the connection.
func TestIdentityPerRequest(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: e.sock(), Net: "unix"})
	mustOK(t, err)
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	list := func() string {
		t.Helper()
		_, err := c.Write([]byte(`{"op":"list"}` + "\n"))
		mustOK(t, err)
		mustOK(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
		line, err := r.ReadString('\n')
		mustOK(t, err)
		return line
	}
	if line := list(); !strings.Contains(line, `"leases":[]`) {
		t.Fatalf("first request %q", line)
	}
	e.ctrs.setPeer(&Requester{Pod: state.PodRef{Namespace: envNS, Name: "intruder", UID: "other-pod"}, Container: "x"})
	if line := list(); !strings.Contains(line, "is in demo/intruder/x") {
		t.Fatalf("a peer in another pod %q", line)
	}
	e.ctrs.setPeer(nil)
	if line := list(); !strings.Contains(line, `"leases":[]`) {
		t.Fatalf("a peer that exited %q", line)
	}
}

// A pid that another process holds now is not the peer: once the start
// time of the pid differs from that at connect, every later request keeps
// the identity of the connection, whatever container the pid is in now.
func TestIdentityPidReuse(t *testing.T) {
	start := "100"
	var mu sync.Mutex
	saved := processStartTime
	processStartTime = func(pid int) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		return start, nil
	}
	defer func() { processStartTime = saved }()
	e := brokerEnv(t)
	e.openClaim()
	e.start()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: e.sock(), Net: "unix"})
	mustOK(t, err)
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	list := func() string {
		t.Helper()
		_, err := c.Write([]byte(`{"op":"list"}` + "\n"))
		mustOK(t, err)
		mustOK(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
		line, err := r.ReadString('\n')
		mustOK(t, err)
		return line
	}
	if line := list(); !strings.Contains(line, `"leases":[]`) {
		t.Fatalf("first request %q", line)
	}
	e.ctrs.setPeer(&Requester{Pod: state.PodRef{Namespace: envNS, Name: "intruder", UID: "other-pod"}, Container: "x"})
	if line := list(); !strings.Contains(line, "is in demo/intruder/x") {
		t.Fatalf("the same process in another pod %q", line)
	}
	mu.Lock()
	start = "200"
	mu.Unlock()
	if line := list(); !strings.Contains(line, `"leases":[]`) {
		t.Fatalf("a reused pid in another pod %q", line)
	}
}

// The start time of a process is field 22 of its stat, after a command
// name that may hold spaces and parentheses.
func TestProcessStartTime(t *testing.T) {
	start, err := processStartTime(os.Getpid())
	mustOK(t, err)
	if _, err := strconv.ParseUint(start, 10, 64); err != nil {
		t.Fatalf("start time %q", start)
	}
	if _, err := processStartTime(-1); err == nil {
		t.Fatal("start time of pid -1")
	}
}

// A request that comes before the broker starts waits for the start
// (bounded), then is served.
func TestRequestWaitsForStart(t *testing.T) {
	e := brokerEnv(t)
	e.openClaim()
	ch := make(chan api.Response, 1)
	go func() {
		resp, _ := e.call(api.Request{Op: api.OpList})
		ch <- resp
	}()
	time.Sleep(100 * time.Millisecond)
	e.start()
	select {
	case resp := <-ch:
		if resp.Error != "" || resp.Leases == nil {
			t.Fatalf("response %+v", resp)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no response")
	}
}

// The limits of a lease socket and of the leases of a pod: a
// connection beyond the limit is closed at once, an idle one after the
// idle limit, a request beyond the leases of a pod refused.
func TestLimits(t *testing.T) {
	e := brokerEnv(t)
	e.opts = func(o *Options) { o.Limits = Limits{Connections: 1, Idle: 300 * time.Millisecond, LeasesPerPod: 1} }
	e.restart()
	e.openClaim()
	e.start()
	r, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	if r.Error != "" {
		t.Fatalf("request %+v", r)
	}
	resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "256Mi", Wait: "0s"})
	if resp.Error != "pod demo/borrower has 1 leases, the limit of --lease-max-per-pod" {
		t.Fatalf("a request beyond the leases of the pod %+v", resp)
	}
	// the connections of the calls are gone
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		e.b.mu.Lock()
		n := len(e.b.conns[envLeaseClaim])
		e.b.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections left", n)
		}
	}
	c1, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: e.sock(), Net: "unix"})
	mustOK(t, err)
	defer func() { _ = c1.Close() }()
	_, err = c1.Write([]byte(`{"op":"list"}` + "\n"))
	mustOK(t, err)
	r1 := bufio.NewReader(c1)
	mustOK(t, c1.SetReadDeadline(time.Now().Add(5*time.Second)))
	if _, err := r1.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	// a second connection while c1 is open
	c2, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: e.sock(), Net: "unix"})
	mustOK(t, err)
	defer func() { _ = c2.Close() }()
	mustOK(t, c2.SetReadDeadline(time.Now().Add(5*time.Second)))
	if data, err := io.ReadAll(c2); err != nil || len(data) != 0 {
		t.Fatalf("a connection beyond the limit: %q %v", data, err)
	}
	// c1 idle: closed
	start := time.Now()
	if data, err := io.ReadAll(r1); err != nil || len(data) != 0 || time.Since(start) > 4*time.Second {
		t.Fatalf("an idle connection: %q %v after %v", data, err, time.Since(start))
	}
}

// What a lease gets of the prepared memdev of its companion, by mode: the
// source, serial and bytes, and the node that it lends (numa), the device
// node (dax, block), or the access, type and path of its filesystem (fs);
// a shared device for a shared lease or a shared device.
func TestGotOfPrepared(t *testing.T) {
	e := brokerEnv(t)
	shared := func(d state.DeviceInfo) state.DeviceInfo { d.Shared = true; return d }
	for name, tc := range map[string]struct {
		asked state.LeaseAsked
		dev   state.DeviceInfo
		got   state.LeaseGot
		lend  *state.Lend
	}{
		"numa": {state.LeaseAsked{Mode: state.ModeNUMA}, preparedDev(serialPoolX, 1<<28, api.ModeNUMA, 2),
			state.LeaseGot{Source: state.SourcePool, Serial: serialPoolX, Bytes: 1 << 28}, &state.Lend{NumaNode: state.NumaNodePtr(2)}},
		"numa shared lease": {state.LeaseAsked{Mode: state.ModeNUMA, SharedDevice: true}, preparedDev(serialPoolX, 1<<28, api.ModeNUMA, -1),
			state.LeaseGot{Source: state.SourcePool, Serial: serialPoolX, SharedDevice: true, Bytes: 1 << 28}, nil},
		"dax": {state.LeaseAsked{Mode: state.ModeDax}, shared(withDev(preparedDev(serialPoolS, 1<<28, api.ModeDax, -1), func(d *state.DeviceInfo) { d.DaxDevice = "/dev/dax0.0" })),
			state.LeaseGot{Source: state.SourcePool, Serial: serialPoolS, SharedDevice: true, Bytes: 1 << 28, Dax: "/dev/dax0.0"}, nil},
		"block": {state.LeaseAsked{Mode: state.ModeBlock, SharedDevice: true}, withDev(preparedDev(serialPoolP, pmemBytes, api.ModeBlock, -1), func(d *state.DeviceInfo) { d.BlockDevice = "/dev/pmem0" }),
			state.LeaseGot{Source: state.SourcePool, Serial: serialPoolP, Bytes: pmemBytes, Block: "/dev/pmem0"}, nil},
		"fs": {state.LeaseAsked{Mode: state.ModeFs, Name: "data"}, shared(withDev(preparedDev(serialPoolP, pmemBytes, api.ModeFs, -1), func(d *state.DeviceInfo) {
			d.Access, d.FsType, d.BlockDevice = api.AccessDirect, "ext4", "/dev/pmem0"
		})), state.LeaseGot{Source: state.SourcePool, Serial: serialPoolP, SharedDevice: true, Bytes: pmemBytes, Access: state.Access(api.AccessDirect),
			FsType: "ext4", Path: api.FsDir + "/data"}, nil},
	} {
		got, lend := e.b.gotOf(&state.Lease{Asked: tc.asked}, state.SourcePool, &tc.dev)
		if !reflect.DeepEqual(*got, tc.got) || !reflect.DeepEqual(lend, tc.lend) {
			t.Errorf("%s: got %+v, lend %+v; expected %+v, %+v", name, *got, lend, tc.got, tc.lend)
		}
	}
}
