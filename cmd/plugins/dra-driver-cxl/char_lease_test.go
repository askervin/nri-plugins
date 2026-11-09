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
	"io"
	"net"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// TestCharLeaseWaitDefault: a request without a wait waits --lease-wait,
// then the lease is released and the response is Failed with the timeout;
// without --lease-wait the wait is 120 s.
func TestCharLeaseWaitDefault(t *testing.T) {
	e := newBrokerEnv(t)
	e.b.cfg.WaitDefault = 300 * time.Millisecond
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	start := time.Now()
	resp, _ := e.call(api.Request{Op: api.OpRequest, Size: "64Mi"})
	took := time.Since(start)
	if resp.State != api.StateFailed || resp.Error != "timeout: not Ready after 300ms" || took < 300*time.Millisecond || took > 2*time.Second {
		t.Fatalf("response %+v after %v", resp, took)
	}
	e.waitState(resp.Lease, api.StateReleased)
	e.wantGone(companionName(resp.Lease))

	b, err := newBroker(brokerConfig{DataDir: t.TempDir(), NodeName: testNode})
	noErr(t, err)
	defer b.stop()
	if b.cfg.WaitDefault != 120*time.Second {
		t.Fatalf("default wait %v", b.cfg.WaitDefault)
	}
}

// TestCharLeaseRequestID: the requestId of a container's request returns
// the lease of an earlier request with it, Pending or Ready, also after a
// restart; another container of the pod with the same requestId gets a
// lease of its own.
func TestCharLeaseRequestID(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	req := api.Request{Op: api.OpRequest, Size: "64Mi", RequestID: "r1", Wait: "0s"}
	first, _ := e.call(req)
	e.waitClaim(companionName(first.Lease))
	second, _ := e.call(req)
	if first.State != api.StatePending || second.Lease != first.Lease || second.State != api.StatePending {
		t.Fatalf("first %+v, second %+v", first, second)
	}
	_, err := e.b.OnLending(first.Lease, companionClaim(first.Lease))
	noErr(t, err)
	e.b.OnPrepared(first.Lease, []lentDevice{{Source: api.SourcePool, Serial: 0xc1ee0001, Size: 64 << 20, Mode: api.ModeNUMA, Node: 2}})
	third, _ := e.call(req)
	if third.Lease != first.Lease || third.State != api.StateReady {
		t.Fatalf("third %+v", third)
	}
	claims, err := e.client.ResourceV1().ResourceClaims(testNS).List(context.Background(), metav1.ListOptions{LabelSelector: device.LeaseLabel})
	noErr(t, err)
	if len(claims.Items) != 1 {
		t.Fatalf("%d companion claims", len(claims.Items))
	}

	// another container of the pod
	other := testRef
	other.Name, other.ID = "sidecar", "c2"
	e.lender.setPeer(&other)
	own, _ := e.call(req)
	if own.Lease == "" || own.Lease == first.Lease || own.Error != "" {
		t.Fatalf("other container's request %+v", own)
	}
	e.waitClaim(companionName(own.Lease))

	// after a restart
	e.restart()
	e.start()
	e.lender.setPeer(&testRef)
	again, _ := e.call(req)
	if again.Lease != first.Lease || again.State != api.StateReady {
		t.Fatalf("after a restart %+v", again)
	}
}

// TestCharLeaseRequestLineLimit: a request line of 64 KiB is served, a
// longer one ends the connection without a response, and the next
// connection is served.
func TestCharLeaseRequestLineLimit(t *testing.T) {
	e := newBrokerEnv(t)
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	e.start()
	line := func(n int) string {
		return `{"op":"list"` + strings.Repeat(" ", n-len(`{"op":"list"}`)) + "}"
	}
	resp, _ := e.callRaw(line(64 * 1024))
	if resp.Error != "" || resp.Leases == nil {
		t.Fatalf("64 KiB line: %+v", resp)
	}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: e.sock(), Net: "unix"})
	noErr(t, err)
	_, err = c.Write([]byte(line(64*1024+1) + "\n"))
	noErr(t, err)
	noErr(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
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

// TestCharLeaseCreatingGrace: the reconcile releases a lease that is
// Creating for longer than the grace (left over by a crash) and keeps a
// newer one; the grace is 2 min.
func TestCharLeaseCreatingGrace(t *testing.T) {
	e := newBrokerEnv(t)
	if e.b.creatingGrace != 2*time.Minute {
		t.Fatalf("creating grace %v", e.b.creatingGrace)
	}
	noErr(t, e.b.OpenClaim(leaseClaimObj()))
	pod := podRef{Namespace: testNS, Name: testPod, UID: testPodUID}
	e.b.mu.Lock()
	for id, created := range map[string]time.Time{"0000old0": time.Now().Add(-time.Second), "0000new0": time.Now().Add(time.Hour)} {
		e.b.store.Leases[id] = &lease{ID: id, Claim: testLeaseClaimUID, Mode: api.ModeNUMA, Size: "64Mi", Pod: pod, Container: testCtr,
			State: api.StateCreating, Node: -1, Created: created.UTC()}
	}
	noErr(t, e.b.store.save())
	e.b.mu.Unlock()
	e.restart()
	e.b.creatingGrace = 100 * time.Millisecond
	e.start()
	e.b.reconcile()
	e.waitState("0000old0", api.StateReleased)
	if l := e.lease("0000new0"); l == nil || l.State != api.StateCreating {
		t.Fatalf("newer Creating lease %+v", l)
	}
}
