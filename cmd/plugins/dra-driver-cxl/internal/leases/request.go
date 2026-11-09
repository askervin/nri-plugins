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
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// The operations of the protocol: request, release (one or all), list, fd
// and env. A lease belongs to the pod of its requester for release, list
// and env, and to the requester container for fd.

// requestLease returns the response to a request of a container on the
// socket of a lease claim, and the device whose fd goes with it: it stores
// the lease, creates its companion and waits up to wait for it.
func (b *Broker) requestLease(claimUID string, who Requester, req *api.Request, wait time.Duration) (*api.Response, leaseFd) {
	if id := b.requested(who, req.RequestID); id != "" {
		return b.waitReady(id, wait, true)
	}
	l := &state.Lease{
		Claim:     claimUID,
		RequestID: req.RequestID,
		Pod:       who.Pod,
		Container: who.Container,
		State:     state.LeaseNone,
		Created:   time.Now().UTC(),
	}
	if err := b.requestOptions(&l.Asked, req); err != nil {
		return &api.Response{Error: err.Error()}, leaseFd{}
	}
	if err := b.storeCreating(l, req); err != nil {
		return &api.Response{Error: err.Error()}, leaseFd{}
	}
	a := &l.Asked
	klog.Infof("lease broker: lease %s: %s/%s/%s requests size %q serial %q (source %q, mode %s, shared %v, shared device %v, read-only %v, access %q, name %q)",
		l.ID, l.Pod.Namespace, l.Pod.Name, l.Container, a.Size, askedSerial(a), a.Source, a.Mode, a.Shared, a.SharedDevice, a.ReadOnly, a.Access, a.Name)

	if err := b.createCompanion(l); err != nil {
		klog.Errorf("lease broker: lease %s: %v", l.ID, err)
		b.mu.Lock()
		if cur := b.leases[l.ID]; cur != nil && apply(cur, state.LeaseFailed, state.TriggerRequest) {
			cur.Error = err.Error()
		}
		b.mu.Unlock()
		resp := b.startRelease(l.ID, err.Error(), state.TriggerRequest)
		resp.State, resp.Error = api.StateFailed, err.Error()
		return resp, leaseFd{}
	}
	b.mu.Lock()
	if cur := b.leases[l.ID]; cur != nil && cur.State == state.LeaseCreating {
		apply(cur, state.LeasePending, state.TriggerRequest)
		b.saveLocked()
	}
	b.mu.Unlock()
	return b.waitReady(l.ID, wait, true)
}

// requested returns the id of the lease that the container asked for with
// the request id before, "" for none.
func (b *Broker) requested(who Requester, requestID string) string {
	if requestID == "" {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range slices.Sorted(maps.Keys(b.leases)) {
		if l := b.leases[id]; l.RequestID == requestID && l.Pod.UID == who.Pod.UID && l.Container == who.Container {
			return id
		}
	}
	return ""
}

// storeCreating chooses the id (and the name of an fs lease) of a new
// lease and stores it CREATING before any API object exists; a failed
// write forgets it again.
func (b *Broker) storeCreating(l *state.Lease, req *api.Request) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.fsLeaseOptions(l, req); err != nil {
		return err
	}
	if !apply(l, state.LeaseCreating, state.TriggerRequest) {
		return fmt.Errorf("lease %s: not created", l.ID)
	}
	b.leases[l.ID] = l
	if err := b.persistLocked(); err != nil {
		delete(b.leases, l.ID)
		return err
	}
	return nil
}

// requestOptions sets the source, mode, sharing, access, name, size and
// device of a validated request on what a lease asks for.
func (b *Broker) requestOptions(a *state.LeaseAsked, req *api.Request) error {
	if b.opts.PoolDriver == "" && req.Source == api.SourcePool {
		return errPoolDisabled
	}
	a.Source, a.Shared, a.ReadOnly, a.Mode = state.Source(req.Source), req.Shared, req.ReadOnly, state.Mode(req.EffectiveMode())
	a.SharedDevice = req.Shared
	if a.Mode == state.ModeFs {
		// read-only unless readWrite; access "": by the type of the
		// filesystem, decided by the driver of the device
		a.Access, a.Name, a.FsType, a.ReadWrite = state.Access(req.Access), req.Name, req.FsType, req.ReadWrite
		a.ReadOnly = !req.ReadWrite
	}
	if req.Size != "" {
		q, err := resource.ParseQuantity(req.Size)
		if err != nil || q.Sign() <= 0 {
			return fmt.Errorf("invalid size %q", req.Size)
		}
		a.Size = q.String()
	}
	if req.Serial == "" {
		return nil
	}
	return b.serialOptions(a, req)
}

// serialOptions sets the serial of a validated request on what a lease
// asks for and, when it names a shared device, that the device is shared
// and, for a device of volatile memory, mode dax. Modes block and fs need a
// persistent device, and a persistent device needs mode block or fs. A
// share needs a device with the capacity shares.
func (b *Broker) serialOptions(a *state.LeaseAsked, req *api.Request) error {
	serial, _ := api.ParseSerial(req.Serial)
	a.Serial, a.SerialZero = state.Serial(serial), serial == 0
	text := a.Serial.String()
	dev, err := b.deviceBySerial(serial)
	switch {
	case err != nil:
		return err
	case dev == nil:
		return nil
	}
	if err := b.deviceRefusal(dev, a, req, text); err != nil {
		return err
	}
	switch {
	case persistent(a.Mode) && !dev.persistent:
		return fmt.Errorf("device %s: mode %s needs a persistent device", text, a.Mode)
	case !persistent(a.Mode) && dev.persistent:
		return fmt.Errorf("device %s: a persistent device needs mode %s or %s", text, api.ModeBlock, api.ModeFs)
	case !dev.shared:
		a.DeviceSource = deviceSourceOf(dev, req)
		return nil
	case req.Mode == api.ModeNUMA:
		return errors.New("shared memory is never onlined as RAM: use mode dax")
	}
	a.SharedDevice = true
	if !dev.persistent {
		a.Mode = state.ModeDax
	}
	a.DeviceSource = deviceSourceOf(dev, req)
	return nil
}

// deviceRefusal returns the error of a request for a share of a device
// without shares and, for a shared or persistent device, of the wrong
// source or of another node; text is the serial of the device.
func (b *Broker) deviceRefusal(dev *publishedDevice, a *state.LeaseAsked, req *api.Request, text string) error {
	switch {
	case !dev.shares && a.Shared:
		return fmt.Errorf("device %s: not shareable", text)
	case !dev.shared && !dev.persistent:
	case req.Source == api.SourceLocal && dev.driver != device.DriverName:
		return fmt.Errorf("device %s: not a local device", text)
	case req.Source == api.SourcePool && dev.driver == device.DriverName:
		return fmt.Errorf("device %s: not a pool device", text)
	case dev.driver == device.DriverName && dev.node != b.opts.NodeName:
		return fmt.Errorf("device %s: a local device of node %s, not of this node", text, dev.node)
	}
	return nil
}

// persistent tells whether a mode is a mode of persistent devices.
func persistent(mode state.Mode) bool {
	return mode == state.ModeBlock || mode == state.ModeFs
}

// deviceSourceOf returns the source of a device in a ResourceSlice when the
// request names no source, "" otherwise.
func deviceSourceOf(dev *publishedDevice, req *api.Request) state.Source {
	switch {
	case req.Source != "":
		return ""
	case dev.driver == device.DriverName:
		return state.SourceLocal
	}
	return state.SourcePool
}

// publishedDevice is a device with a serial in a ResourceSlice.
type publishedDevice struct {
	shared     bool
	shares     bool   // the device has the capacity shares
	persistent bool   // a device of persistent memory
	driver     string // the driver of the ResourceSlice
	node       string // the node of a ResourceSlice of cxl.nri.io
}

// deviceBySerial returns the device with the serial in the ResourceSlices
// of cxl.nri.io and the pool driver, nil if there is none or no
// Kubernetes client: the local device of this node first, then a pool
// device, then a local device of another node.
func (b *Broker) deviceBySerial(serial uint64) (*publishedDevice, error) {
	if b.opts.Client == nil {
		return nil, nil
	}
	ctx, cancel := b.apiContext()
	defer cancel()
	list, err := b.opts.Client.ResourceV1().ResourceSlices().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing ResourceSlices: %w", err)
	}
	// the first device of each preference: this node, the pool, another
	// node
	var found [3]*publishedDevice
	for i := range list.Items {
		rs := &list.Items[i]
		if rs.Spec.Driver != device.DriverName && (b.opts.PoolDriver == "" || rs.Spec.Driver != b.opts.PoolDriver) {
			continue
		}
		for j := range rs.Spec.Devices {
			if dev := publishedDeviceOf(rs, &rs.Spec.Devices[j], serial); dev != nil && found[b.preference(dev)] == nil {
				found[b.preference(dev)] = dev
			}
		}
		if found[0] != nil {
			break
		}
	}
	for _, dev := range found {
		if dev != nil {
			return dev, nil
		}
	}
	return nil, nil
}

// preference returns the rank of a device of a serial: 0 for the local
// device of this node, 1 for a pool device, 2 for a local device of
// another node.
func (b *Broker) preference(dev *publishedDevice) int {
	switch {
	case dev.driver != device.DriverName:
		return 1
	case dev.node == b.opts.NodeName:
		return 0
	}
	return 2
}

// publishedDeviceOf returns the device d of the ResourceSlice rs when it has
// the serial, nil otherwise.
func publishedDeviceOf(rs *resourcev1.ResourceSlice, d *resourcev1.Device, serial uint64) *publishedDevice {
	if s, ok := deviceSerial(d, rs.Spec.Driver); !ok || s != serial {
		return nil
	}
	dev := &publishedDevice{driver: rs.Spec.Driver}
	if a, ok := deviceAttribute(d, rs.Spec.Driver, device.AttrShared); ok && a.BoolValue != nil {
		dev.shared = *a.BoolValue
	}
	if a, ok := deviceAttribute(d, rs.Spec.Driver, device.AttrPersistent); ok && a.BoolValue != nil {
		dev.persistent = *a.BoolValue
	}
	_, dev.shares = d.Capacity[device.CapacityShares]
	if rs.Spec.Driver == device.DriverName && rs.Spec.NodeName != nil {
		dev.node = *rs.Spec.NodeName
	}
	return dev
}

// deviceAttribute returns the attribute of a device of driver, unqualified
// or qualified with the driver name.
func deviceAttribute(d *resourcev1.Device, driver string, name resourcev1.QualifiedName) (resourcev1.DeviceAttribute, bool) {
	for _, k := range []resourcev1.QualifiedName{name, resourcev1.QualifiedName(driver + "/" + string(name))} {
		if a, ok := d.Attributes[k]; ok {
			return a, true
		}
	}
	return resourcev1.DeviceAttribute{}, false
}

// deviceSerial returns the serial attribute of a device of driver, and
// whether it has a valid one.
func deviceSerial(d *resourcev1.Device, driver string) (uint64, bool) {
	if a, ok := deviceAttribute(d, driver, device.AttrSerial); ok && a.StringValue != nil {
		if v, err := api.ParseSerial(*a.StringValue); err == nil {
			return v, true
		}
	}
	return 0, false
}

// fsLeaseOptions chooses the id of a new lease and, for an fs lease, its
// name: the requested one, or the id. An fs lease needs a lease claim with
// a filesystem directory, and a name that no other lease of the claim has.
// Called with b.mu held.
func (b *Broker) fsLeaseOptions(l *state.Lease, req *api.Request) error {
	fs := l.Asked.Mode == state.ModeFs
	if fs {
		if lc := b.claims[l.Claim]; lc == nil || lc.FsDir == "" {
			ns, name := l.Pod.Namespace, l.Claim
			if lc != nil {
				ns, name = lc.Namespace, lc.Name
			}
			return fmt.Errorf("lease claim %s/%s has no filesystem directory (prepared by an older driver): recreate the pod", ns, name)
		}
	}
	// a default name never clashes with a name that a request chose
	for l.ID == "" || b.leases[l.ID] != nil || (fs && req.Name == "" && b.nameUser(l.Claim, l.ID) != nil) {
		l.ID = b.opts.NewID()
	}
	if !fs {
		return nil
	}
	if l.Asked.Name == "" {
		l.Asked.Name = l.ID
	}
	if other := b.nameUser(l.Claim, l.Asked.Name); other != nil {
		return fmt.Errorf("name %q is in use by lease %s", l.Asked.Name, other.ID)
	}
	return nil
}

// nameUser returns the lease of the lease claim whose fs mount has the
// name, nil if there is none. Called with b.mu held.
func (b *Broker) nameUser(claimUID, name string) *state.Lease {
	for _, l := range b.leases {
		if l.Claim == claimUID && l.Asked.Name == name {
			return l
		}
	}
	return nil
}

// waitReady waits until the lease is Ready or Failed, at most wait. At
// timeout a lease is released and reported Failed if release is set, else
// reported in its state. Wait 0 returns the state at once.
func (b *Broker) waitReady(id string, wait time.Duration, release bool) (*api.Response, leaseFd) {
	ctx, cancel := context.WithTimeout(b.ctx, wait)
	defer cancel()
	var resp *api.Response
	var fd leaseFd
	done := func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		l := b.leases[id]
		switch {
		case l == nil:
			resp = &api.Response{Lease: id, State: api.StateReleased, Error: "lease was released"}
			return true
		case l.State == state.LeaseReady || l.State == state.LeaseFailed || releasingState(l.State):
			resp, fd = leaseInfo(l), fdOf(l)
			return true
		}
		resp = leaseInfo(l)
		return wait == 0
	}
	if err := b.waitFor(ctx, done); err != nil && release {
		msg := fmt.Sprintf("timeout: not Ready after %v", wait)
		klog.Warningf("lease broker: lease %s: %s, releasing", id, msg)
		resp = b.startRelease(id, msg, state.TriggerRequest)
		resp.State, resp.Error = api.StateFailed, msg
		return resp, leaseFd{}
	}
	return resp, fd
}

// ownLease returns the lease if it belongs to the pod of the requester.
// Called with b.mu held.
func (b *Broker) ownLease(who Requester, id string) *state.Lease {
	l := b.leases[id]
	if l == nil || l.Pod.UID != who.Pod.UID {
		return nil
	}
	return l
}

// releaseOne releases a lease of the pod of the requester and returns its
// state after waiting up to wait for it to be gone.
func (b *Broker) releaseOne(who Requester, id string, wait time.Duration) *api.Response {
	b.mu.Lock()
	l := b.ownLease(who, id)
	b.mu.Unlock()
	if l == nil {
		return &api.Response{Lease: id, Error: "no such lease"}
	}
	b.startRelease(id, "released by "+who.Container, state.TriggerRelease)
	return b.waitReleased([]string{id}, wait)[0]
}

// releaseAll releases every lease of the pod of the requester and returns
// their states after waiting up to wait for them to be gone.
func (b *Broker) releaseAll(who Requester, wait time.Duration) *api.Response {
	var ids []string
	b.mu.Lock()
	for id, l := range b.leases {
		if l.Pod.UID == who.Pod.UID {
			ids = append(ids, id)
		}
	}
	b.mu.Unlock()
	slices.Sort(ids)
	for _, id := range ids {
		b.startRelease(id, "released by "+who.Container, state.TriggerRelease)
	}
	out := []api.Response{}
	for _, r := range b.waitReleased(ids, wait) {
		out = append(out, *r)
	}
	return &api.Response{Leases: &out}
}

// waitReleased waits until the leases are gone, at most wait, and returns
// their states (Released, or the current state).
func (b *Broker) waitReleased(ids []string, wait time.Duration) []*api.Response {
	ctx, cancel := context.WithTimeout(b.ctx, wait)
	defer cancel()
	gone := func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, id := range ids {
			if b.leases[id] != nil {
				return false
			}
		}
		return true
	}
	_ = b.waitFor(ctx, gone)
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*api.Response, 0, len(ids))
	for _, id := range ids {
		if l := b.leases[id]; l != nil {
			out = append(out, leaseInfo(l))
		} else {
			out = append(out, &api.Response{Lease: id, State: api.StateReleased})
		}
	}
	return out
}

// list returns the leases of the pod of the requester.
func (b *Broker) list(who Requester) *api.Response {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []api.Response{}
	for _, id := range slices.Sorted(maps.Keys(b.leases)) {
		if l := b.leases[id]; l.Pod.UID == who.Pod.UID {
			out = append(out, *leaseInfo(l))
		}
	}
	return &api.Response{Leases: &out}
}

// waitLease waits until a lease of the pod of the requester is Ready, at
// most wait, and returns its response, and with withFd the device of a dax
// or block lease of the requester container whose fd goes with it.
func (b *Broker) waitLease(who Requester, id string, wait time.Duration, withFd bool) (*api.Response, leaseFd) {
	b.mu.Lock()
	l := b.ownLease(who, id)
	switch {
	case l == nil || (withFd && l.Container != who.Container):
		b.mu.Unlock()
		return &api.Response{Lease: id, Error: "no such lease of this container"}, leaseFd{}
	case withFd && l.Asked.Mode != state.ModeDax && l.Asked.Mode != state.ModeBlock:
		resp := leaseInfo(l)
		b.mu.Unlock()
		resp.Error = fmt.Sprintf("lease %s is not a %s or %s lease; use %s", id, api.ModeDax, api.ModeBlock, api.OpEnv)
		return resp, leaseFd{}
	}
	b.mu.Unlock()
	resp, fd := b.waitReady(id, wait, false)
	if !withFd {
		fd = leaseFd{}
	}
	return resp, fd
}
