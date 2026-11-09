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
	"errors"
	"fmt"
	"path/filepath"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// Lease: one request of a running container for memory, served through
// the socket of its lease claim; its memory comes from a companion claim
// cxl-lease-<id> that the broker creates with a companion pod, and that
// the driver of the device prepares and lends to the requester.
//
// Identity: the record state.Lease: ID, 8 hex digits, the suffix of the
// companion's name and the holder of its lent NUMA node; the requester
// (Pod, Container); Claim, the lease claim whose socket received it;
// RequestID, the client's idempotency key.
//
// States: state.LeaseState, in the protocol's words (stateName);
// RELEASING_BUSY is Releasing there.
//
// Transitions: state.LeaseTable, applied by apply. The request makes it
// CREATING, the companion's creation PENDING, the companion gate of its
// Prepare LENDING (OnLending), the lent devices READY (OnPrepared); a
// release (startRelease) makes it RELEASING, or keeps a FAILED lease FAILED
// so that a list shows why, and the release worker removes it once its
// companion pod and claim are gone; while the companion's bind is busy the
// lease is RELEASING_BUSY.
//
// Invariants: the lease owns its Lend, set at READY: the lent NUMA node of
// a numa lease, the bind target of an fs lease; the companion's grants
// keep a copy (state.GrantLend, recorded by the engine) so that the
// companion's Unprepare revokes without the lease. A RELEASING or
// RELEASING_BUSY lease is released by a running release or by the next
// reconcile; a FAILED one with ReleaseRequested by a running release, or by
// a reconcile once its companion pod is gone.
//
// Persistence: the record in the store, CREATING before any API object
// exists; a document of another boot has no leases (the store drops them,
// the reconcile deletes their companions).
//
// Locks and waits: the broker's mutex; the release worker waits for the
// companion with a backoff of 0.5 s to 8 s and calls the API and the
// container plugin without the mutex.

// stateName returns the protocol's word for a lease state.
func stateName(s state.LeaseState) string {
	switch s {
	case state.LeaseCreating:
		return api.StateCreating
	case state.LeasePending:
		return api.StatePending
	case state.LeaseLending:
		return api.StateLending
	case state.LeaseReady:
		return api.StateReady
	case state.LeaseReleasing, state.LeaseReleasingBusy:
		return api.StateReleasing
	case state.LeaseFailed:
		return api.StateFailed
	}
	return string(s)
}

// releasingState tells whether a lease in the state is being released and
// not failed.
func releasingState(s state.LeaseState) bool {
	return s == state.LeaseReleasing || s == state.LeaseReleasingBusy
}

// askedSerial returns the serial that a request named in the protocol's
// words, "" for none.
func askedSerial(a *state.LeaseAsked) string {
	if !a.AsksSerial() {
		return ""
	}
	return a.Serial.String()
}

// got returns what the companion's Prepare gave a lease, nothing before.
func got(l *state.Lease) state.LeaseGot {
	if l.Got == nil {
		return state.LeaseGot{}
	}
	return *l.Got
}

// sourceOf returns the source of the device of a lease, the requested one
// before it has one.
func sourceOf(l *state.Lease) state.Source {
	if g := got(l); g.Source != "" {
		return g.Source
	}
	return l.Asked.Source
}

// serialOf returns the serial of the device of a lease in the protocol's
// words, the requested one before it has one, "" for none.
func serialOf(l *state.Lease) string {
	if g := got(l); g.Serial != 0 {
		return g.Serial.String()
	}
	return askedSerial(&l.Asked)
}

// sharedDevice tells whether the device of a lease is a shared device.
func sharedDevice(l *state.Lease) bool {
	if l.Got != nil {
		return l.Got.SharedDevice
	}
	return l.Asked.SharedDevice
}

// accessOf and fsTypeOf return the access and the filesystem type of an fs
// lease: those mounted once it is Ready, the requested ones before.
func accessOf(l *state.Lease) state.Access {
	if g := got(l); g.Access != "" {
		return g.Access
	}
	return l.Asked.Access
}

func fsTypeOf(l *state.Lease) string {
	if g := got(l); g.FsType != "" {
		return g.FsType
	}
	return l.Asked.FsType
}

// numaNodeOf returns the lent NUMA node of a lease, -1 for none.
func numaNodeOf(l *state.Lease) int {
	if l.Lend == nil {
		return -1
	}
	return state.NumaNodeOf(l.Lend.NumaNode)
}

// readOnly tells whether a lease allows reads only: an fs lease unless it
// is read-write.
func readOnly(l *state.Lease) bool {
	return l.Asked.ReadOnly || (l.Asked.Mode == state.ModeFs && !l.Asked.ReadWrite)
}

// memory returns what a Ready lease gives its container, false before.
// The path of a block lease is the host path of its block device.
func memory(l *state.Lease) (api.Memory, bool) {
	text := serialOf(l)
	serial, err := api.ParseSerial(text)
	if l.State != state.LeaseReady || err != nil {
		return api.Memory{}, false
	}
	g := got(l)
	path := g.Path
	if l.Asked.Mode == state.ModeBlock {
		path = g.Block
	}
	// a persistent device: its attribute shared, whatever the share
	shared := l.Asked.Shared || sharedDevice(l)
	if persistent(l.Asked.Mode) {
		shared = sharedDevice(l)
	}
	m := api.Memory{
		Key:      api.Key(serial, 1),
		Serial:   text,
		Shared:   shared,
		Mode:     string(l.Asked.Mode),
		Size:     g.Bytes,
		Node:     numaNodeOf(l),
		Dax:      g.Dax,
		Path:     path,
		Access:   string(accessOf(l)),
		ReadOnly: readOnly(l),
	}
	if l.Asked.Mode == state.ModeFs {
		m.FsType = fsTypeOf(l)
	}
	return m, true
}

// leaseInfo is the response of a lease. Called with b.mu held.
func leaseInfo(l *state.Lease) *api.Response {
	g := got(l)
	r := &api.Response{Lease: l.ID, State: stateName(l.State), Source: string(sourceOf(l)), Mode: string(l.Asked.Mode),
		Shared: l.Asked.Shared, ReadOnly: readOnly(l), Access: string(accessOf(l)), FsType: fsTypeOf(l), Path: g.Path,
		Serial: serialOf(l), Dax: g.Dax, Block: g.Block, Error: l.Error, Size: g.Bytes}
	if n := numaNodeOf(l); n >= 0 {
		r.Node = &n
	}
	if r.Size == 0 && l.Asked.Size != "" {
		if q, err := resource.ParseQuantity(l.Asked.Size); err == nil {
			r.Size = uint64(q.Value())
		}
	}
	if m, ok := memory(l); ok {
		r.Env = api.Env(m)
	}
	return r
}

// fdOf returns the device whose fd goes with the response of a lease: that
// of a Ready dax or block lease.
func fdOf(l *state.Lease) leaseFd {
	g := got(l)
	switch {
	case l.State != state.LeaseReady:
	case g.Dax != "":
		return leaseFd{path: g.Dax, readOnly: l.Asked.ReadOnly}
	case l.Asked.Mode == state.ModeBlock && g.Block != "":
		return leaseFd{path: g.Block, readOnly: l.Asked.ReadOnly}
	}
	return leaseFd{}
}

// startRelease starts the release of a lease (once) on trigger and returns
// its response: a FAILED lease stays FAILED while it is released, so that
// it shows why.
func (b *Broker) startRelease(id, reason string, trigger state.Trigger) *api.Response {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.leases[id]
	if l == nil {
		return &api.Response{Lease: id, State: api.StateReleased}
	}
	if !b.releasing[id] {
		to, was := state.LeaseReleasing, stateName(l.State)
		if l.State == state.LeaseFailed || l.State == state.LeaseReleasingBusy {
			to = l.State
		}
		if apply(l, to, trigger) {
			klog.Infof("lease broker: lease %s: releasing (%s, was %s)", id, reason, was)
			b.releasing[id] = true
			l.ReleaseRequested = true
			b.saveLocked()
			cp := l.Clone()
			b.wg.Add(1)
			go b.release(&cp)
		}
	}
	return leaseInfo(l)
}

// release revokes the lent node of a numa lease, deletes the companion pod
// and claim, waits until both are gone and removes the lease; kubelet
// unprepares the companion claim in between (its driver releases the
// device), and while its bind is busy the lease is RELEASING_BUSY. The
// lease's DeletionRequested is set once the deletion of both is requested.
func (b *Broker) release(l *state.Lease) {
	defer b.wg.Done()
	b.mu.Lock()
	containers := b.containers
	b.mu.Unlock()
	if n := numaNodeOf(l); l.Asked.Mode == state.ModeNUMA && n >= 0 && containers != nil {
		ctx, cancel := b.apiContext()
		if err := containers.RevokeNode(ctx, l.Pod.UID, l.Container, n, l.ID); err != nil {
			// The driver of the device revokes again before it
			// releases it, and fails (kubelet retries) while it cannot.
			klog.Errorf("lease broker: lease %s: revoking node %d: %v", l.ID, n, err)
		}
		cancel()
	}
	name := CompanionName(l.ID)
	ns := l.Pod.Namespace
	delay := b.t.Poll
	for {
		gone, err := b.deleteCompanion(ns, name)
		if err != nil {
			klog.Warningf("lease broker: lease %s: %v", l.ID, err)
		} else {
			b.deletionRequested(l.ID)
		}
		b.noteBusy(l.ID, gone)
		if gone {
			break
		}
		select {
		case <-b.ctx.Done():
			return // continued by the next plugin instance
		case <-time.After(delay):
		}
		if delay < 5*time.Second {
			delay *= 2
		}
	}
	b.removeLease(l)
	klog.Infof("lease broker: lease %s: released", l.ID)
}

// deletionRequested records that the deletion of the companion of a lease
// was requested.
func (b *Broker) deletionRequested(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cur := b.leases[id]; cur != nil && !cur.DeletionRequested {
		cur.DeletionRequested = true
		b.saveLocked()
	}
}

// removeLease removes a released lease and the directories of its lease
// claim when the claim is closed and this was its last lease.
func (b *Broker) removeLease(l *state.Lease) {
	b.mu.Lock()
	if cur := b.leases[l.ID]; cur != nil && apply(cur, state.LeaseNone, state.TriggerRelease) {
		delete(b.leases, l.ID)
	}
	delete(b.releasing, l.ID)
	b.saveLocked()
	// the lease-fs directory of a closed lease claim may have waited for
	// the unmount of the companion's bind
	closed := b.claims[l.Claim] == nil && len(b.leasesOf(l.Claim)) == 0
	b.mu.Unlock()
	if closed {
		b.removeClaimDirs(l.Claim, state.TriggerRelease)
	}
}

// noteBusy makes a RELEASING lease RELEASING_BUSY while the bind of its
// companion is busy (its unbind failed with EBUSY: a file of it is mapped)
// and RELEASING again once it is not, or once the companion is gone.
func (b *Broker) noteBusy(id string, gone bool) {
	busy := !gone && companionBusy(&b.st.Snapshot().Records, id)
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.leases[id]
	switch {
	case l == nil:
	case busy && l.State == state.LeaseReleasing:
		if apply(l, state.LeaseReleasingBusy, state.TriggerRelease) {
			b.saveLocked()
		}
	case !busy && l.State == state.LeaseReleasingBusy:
		if apply(l, state.LeaseReleasing, state.TriggerRelease) {
			b.saveLocked()
		}
	}
}

// companionBusy tells whether the bind of a grant of the companion claim
// of the lease is STALE: its unmount failed busy and is retried.
func companionBusy(r *state.Records, id string) bool {
	for i := range r.Grants {
		g := &r.Grants[i]
		if g.Got.Bind == nil || g.Got.Bind.State != state.BindStale {
			continue
		}
		if (g.Got.Lend != nil && g.Got.Lend.Lease == id) || (g.Intent.Lend != nil && g.Intent.Lend.Lease == id) {
			return true
		}
	}
	return false
}

// deleteCompanion deletes the companion pod and claim and reports whether
// both are gone.
func (b *Broker) deleteCompanion(ns, name string) (bool, error) {
	if b.opts.Client == nil {
		return true, nil
	}
	ctx, cancel := b.apiContext()
	defer cancel()
	fg := metav1.DeletePropagationForeground
	opts := metav1.DeleteOptions{PropagationPolicy: &fg}
	var errs []error
	gone := true
	pod, err := b.opts.Client.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		gone = false
		errs = append(errs, err)
	default:
		gone = false
		if pod.DeletionTimestamp == nil {
			if err := b.opts.Client.CoreV1().Pods(ns).Delete(ctx, name, opts); err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("deleting companion pod %s/%s: %w", ns, name, err))
			}
		}
	}
	claim, err := b.opts.Client.ResourceV1().ResourceClaims(ns).Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		gone = false
		errs = append(errs, err)
	default:
		gone = false
		if claim.DeletionTimestamp == nil {
			if err := b.opts.Client.ResourceV1().ResourceClaims(ns).Delete(ctx, name, opts); err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("deleting companion claim %s/%s: %w", ns, name, err))
			}
		}
	}
	return gone, errors.Join(errs...)
}

// failUnrestored fails the READY leases whose companion claim the start
// did not restore (its preparation PREPARED_UNRESTORED): the requester's
// next list shows them Failed, and Start releases them. Called with b.mu
// held.
func (b *Broker) failUnrestored(r *state.Records) {
	changed := false
	for i := range r.Preparations {
		p := &r.Preparations[i]
		if p.Lease == "" || p.State != state.PreparationUnrestored {
			continue
		}
		l := b.leases[p.Lease]
		if l == nil || l.State != state.LeaseReady || !apply(l, state.LeaseFailed, state.TriggerRecover) {
			continue
		}
		l.Error = fmt.Sprintf("the device of companion claim %s was not restored at the start of the driver", p.ClaimName)
		klog.Warningf("lease broker: lease %s: %s", l.ID, l.Error)
		b.unrestored = append(b.unrestored, l.ID)
		changed = true
	}
	if changed {
		b.saveLocked()
	}
}

// CompanionName is the name of the companion claim and pod of a lease.
func CompanionName(id string) string {
	return "cxl-lease-" + id
}

// fsBindTarget returns the bind target of an fs lease in the filesystem
// directory of its lease claim, "" for none.
func fsBindTarget(fsDir, name string) string {
	if fsDir == "" || name == "" {
		return ""
	}
	return filepath.Join(fsDir, name)
}
