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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// The protocol of a lease socket: SOCK_STREAM, one JSON line each way,
// several requests per connection, a request line of at most
// maxRequestLine bytes decoded strictly; the response of a Ready dax or
// block lease carries the open fd of its device (SCM_RIGHTS) on the write
// of its line. The peer is the process that connected, fixed at connect by
// its pid, start time and pidfd; the identity of every request is that of
// the peer's container then, the connection's once the peer is gone.

// leaseFd names the device of a dax or block lease whose fd goes with a
// response: none if path is "".
type leaseFd struct {
	path     string
	readOnly bool
}

// accept serves the socket of a lease claim.
func (b *Broker) accept(claimUID string, l *net.UnixListener) {
	defer b.wg.Done()
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				klog.Errorf("lease broker: claim %s: accept: %v", claimUID, err)
			}
			return
		}
		go b.serveConn(claimUID, c)
	}
}

// serveConn answers the request lines of one connection until it ends or
// its lease claim is closed.
func (b *Broker) serveConn(claimUID string, c *net.UnixConn) {
	if !b.addConn(claimUID, c) {
		_ = c.Close()
		return
	}
	defer b.removeConn(claimUID, c)
	proc, procErr := openPeer(c)
	defer proc.close()
	who, authErr := b.authenticate(claimUID, proc, procErr)
	if authErr != nil {
		klog.Warningf("lease broker: claim %s: rejected connection: %v", claimUID, authErr)
	}
	connected, connectedErr := who, authErr
	r := bufio.NewReaderSize(c, 4096)
	for first := true; ; first = false {
		// a connection without a request for Limits.Idle is closed
		if err := c.SetReadDeadline(time.Now().Add(b.opts.Limits.Idle)); err != nil {
			return
		}
		line, err := readLine(r)
		if err != nil {
			return
		}
		if !first {
			who, authErr = b.reauthenticate(claimUID, proc, connected, connectedErr)
		}
		var resp *api.Response
		var fd leaseFd
		req, err := decodeRequest(line)
		switch {
		case err != nil:
			resp = &api.Response{Error: err.Error()}
		case authErr != nil:
			resp = &api.Response{Error: authErr.Error()}
		default:
			resp, fd = b.handle(claimUID, who, req)
		}
		if err := b.respond(c, resp, fd); err != nil {
			klog.Warningf("lease broker: claim %s: response to %s/%s: %v", claimUID, who.Pod.Name, who.Container, err)
			return
		}
	}
}

// addConn records an open connection of the socket of a lease claim, and
// returns false when the claim's socket is closed or has as many open
// connections as Limits.Connections.
func (b *Broker) addConn(claimUID string, c *net.UnixConn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listeners[claimUID] == nil {
		return false
	}
	if n := len(b.conns[claimUID]); n >= b.opts.Limits.Connections {
		klog.Warningf("lease broker: claim %s: refusing a connection: %d are open, the limit of --lease-max-connections", claimUID, n)
		return false
	}
	if b.conns[claimUID] == nil {
		b.conns[claimUID] = map[*net.UnixConn]bool{}
	}
	b.conns[claimUID][c] = true
	return true
}

// removeConn closes a connection of the socket of a lease claim and forgets
// it.
func (b *Broker) removeConn(claimUID string, c *net.UnixConn) {
	_ = c.Close()
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.conns[claimUID], c)
	if len(b.conns[claimUID]) == 0 {
		delete(b.conns, claimUID)
	}
}

// closeConnsLocked closes the open connections of the socket of a lease
// claim. Called with b.mu held.
func (b *Broker) closeConnsLocked(claimUID string) {
	for c := range b.conns[claimUID] {
		_ = c.Close()
	}
}

// decodeRequest returns the request of a line, decoded strictly.
func decodeRequest(line []byte) (*api.Request, error) {
	req := &api.Request{}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(req); err != nil {
		return nil, fmt.Errorf("invalid request: %v", err)
	}
	return req, nil
}

// readLine reads one request line of at most maxRequestLine bytes.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, chunk...)
		if len(line) > maxRequestLine {
			return nil, errors.New("request line too long")
		}
		if !isPrefix {
			return line, nil
		}
	}
}

// respond writes a response line, with the open device of fd as
// SCM_RIGHTS if it names one; a device that does not open is answered with
// the error.
func (b *Broker) respond(c *net.UnixConn, resp *api.Response, fd leaseFd) error {
	if fd.path != "" {
		f, err := b.openDevice(fd.path, fd.readOnly)
		if err != nil {
			resp = &api.Response{Lease: resp.Lease, State: resp.State, Error: fmt.Sprintf("opening %s: %v", fd.path, err)}
		} else {
			defer func() { _ = f.Close() }()
			data, err := json.Marshal(resp)
			if err != nil {
				return err
			}
			data = append(data, '\n')
			n, oobn, err := c.WriteMsgUnix(data, syscall.UnixRights(int(f.Fd())), nil)
			if err != nil {
				return err
			}
			if oobn == 0 {
				return errors.New("fd not sent")
			}
			if n < len(data) {
				_, err = c.Write(data[n:])
			}
			return err
		}
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = c.Write(append(data, '\n'))
	return err
}

// waitIdentity waits, at most Timeouts.SyncWait, until the broker is
// started and the container plugin has synchronized with the runtime: the
// identity of a peer is known only then.
func (b *Broker) waitIdentity() {
	ctx, cancel := context.WithTimeout(b.ctx, b.t.SyncWait)
	defer cancel()
	_ = b.waitFor(ctx, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.started
	})
	b.mu.Lock()
	containers := b.containers
	b.mu.Unlock()
	if containers != nil {
		_ = containers.WaitSynchronized(ctx)
	}
}

// authenticate maps the peer to a container of a pod of the lease claim,
// after the identity of the peers is known (waitIdentity); procErr is the
// error of reading the peer's credentials.
func (b *Broker) authenticate(claimUID string, proc *peer, procErr error) (Requester, error) {
	b.waitIdentity()
	b.mu.Lock()
	identity := b.identity
	b.mu.Unlock()
	lc := b.records().LeaseClaim(claimUID)
	if identity == nil {
		return Requester{}, errLendingUnavailable
	}
	if lc == nil {
		return Requester{}, errNotOurPod
	}
	if procErr != nil {
		return Requester{}, fmt.Errorf("peer credentials: %w", procErr)
	}
	pid := proc.pid
	who, err := identity.Resolve(pid)
	switch {
	case errors.Is(err, ErrUnknownPeer):
		return Requester{}, &peerGoneError{fmt.Errorf("%w (pid %d is in no known container)", errNotOurPod, pid)}
	case err != nil:
		return Requester{}, fmt.Errorf("%w (pid %d: %v)", errNotOurPod, pid, err)
	}
	if !hasPod(lc, who.Pod.UID) && !b.refreshClaimPods(lc, who.Pod.UID) {
		return Requester{}, fmt.Errorf("%w (pid %d is in %s/%s/%s)", errNotOurPod, pid, who.Pod.Namespace, who.Pod.Name, who.Container)
	}
	return who, nil
}

// reauthenticate returns the identity of a later request of a connection:
// that of its peer now while the process that connected runs, else the
// identity of the connection (connected, connectedErr). A peer in no known
// container keeps an identity that the connection had.
func (b *Broker) reauthenticate(claimUID string, proc *peer, connected Requester, connectedErr error) (Requester, error) {
	if proc == nil || !proc.running() {
		return connected, connectedErr
	}
	who, err := b.authenticate(claimUID, proc, nil)
	// the pid may have gone to another process while it was resolved
	if !proc.running() {
		return connected, connectedErr
	}
	if pe := (*peerGoneError)(nil); connectedErr == nil && errors.As(err, &pe) {
		return connected, nil
	}
	return who, err
}

// peerGoneError is the refusal of a peer whose process is in no known
// container: it has exited, or it is not in a container of the node.
type peerGoneError struct{ err error }

func (e *peerGoneError) Error() string { return e.err.Error() }
func (e *peerGoneError) Unwrap() error { return e.err }

// refreshClaimPods reads the reservedFor of a lease claim again (a claim
// shared by several pods is prepared only once), commits it, and reports
// whether the pod is in it now.
func (b *Broker) refreshClaimPods(lc *state.LeaseClaim, podUID string) bool {
	if b.opts.Client == nil {
		return false
	}
	ctx, cancel := b.apiContext()
	defer cancel()
	claim, err := b.opts.Client.ResourceV1().ResourceClaims(lc.Namespace).Get(ctx, lc.Name, metav1.GetOptions{})
	if err != nil || string(claim.UID) != lc.UID {
		return false
	}
	pods := reservedPods(claim)
	found := false
	return b.change(func(r *state.Records) {
		if cur := r.LeaseClaim(lc.UID); cur != nil {
			cur.Pods = pods
			if cur.State == state.LeaseClaimOpen {
				applyClaim(cur, state.LeaseClaimOpen, state.TriggerRequest)
			}
			found = hasPod(cur, podUID)
		}
	}) && found
}

// handle runs one authenticated request. It returns the response and the
// device whose fd goes with it.
func (b *Broker) handle(claimUID string, who Requester, req *api.Request) (*api.Response, leaseFd) {
	if err := req.Validate(); err != nil {
		return &api.Response{Lease: req.Lease, Error: err.Error()}, leaseFd{}
	}
	wait := b.parseWait(req.Wait)
	switch req.Op {
	case api.OpRequest:
		return b.requestLease(claimUID, who, req, wait)
	case api.OpRelease:
		if req.All {
			return b.releaseAll(claimUID, who, wait), leaseFd{}
		}
		return b.releaseOne(claimUID, who, req.Lease, wait), leaseFd{}
	case api.OpList:
		return b.list(claimUID, who), leaseFd{}
	case api.OpFd:
		return b.waitLease(who, req.Lease, wait, true)
	default: // api.OpEnv
		return b.waitLease(who, req.Lease, wait, false)
	}
}

// parseWait returns the duration of a validated wait, the default for "".
func (b *Broker) parseWait(s string) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return b.opts.WaitDefault
}
