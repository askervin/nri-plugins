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

package server

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/pool"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/qemu"
)

// Status returns the server status.
func (s *Server) Status() api.Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := api.Status{
		Version:     api.ServerVersion,
		Qemu:        api.QemuStatus{Discovery: s.cfg.Discovery.QemuEnabled(), Versions: map[string]string{}},
		Hosts:       len(s.hosts),
		Devices:     len(s.devices),
		Attachments: len(s.atts),
		Uptime:      time.Since(s.started).Round(time.Second).String(),
		Started:     s.started.UTC(),
	}
	if s.persistenceEnabled() {
		st.StateFile = s.cfg.StateFile
	}
	for _, h := range s.hosts {
		if h.version != "" {
			st.Qemu.Versions[h.name] = h.version
		}
	}
	return st
}

// Pools lists pools.
func (s *Server) Pools() []api.Pool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []api.Pool{}
	for _, n := range s.poolOrder {
		out = append(out, s.poolViewLocked(n))
	}
	return out
}

// Pool returns a pool.
func (s *Server) Pool(name string) (api.Pool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.pools[name]; !ok {
		return api.Pool{}, api.NotFound("pool %q not found", name)
	}
	return s.poolViewLocked(name), nil
}

// Hosts lists hosts. Device trees are queried first unless cached is true.
func (s *Server) Hosts(ctx context.Context, cached bool) []api.Host {
	ctx = context.WithoutCancel(ctx) // a client disconnect must not fail monitor calls
	if !cached {
		s.refreshTrees(ctx)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []api.Host{}
	for _, h := range sortedHosts(s.hosts) {
		out = append(out, s.hostViewLocked(h))
	}
	return out
}

// Host returns a host by name or uuid.
func (s *Server) Host(ctx context.Context, ref string, cached bool) (api.Host, error) {
	s.mu.RLock()
	h := s.lookupHostLocked(ref)
	s.mu.RUnlock()
	if h == nil {
		return api.Host{}, api.NotFound("host %q not found", ref)
	}
	if !cached {
		s.refreshTrees(context.WithoutCancel(ctx), h.name)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hostViewLocked(h), nil
}

// Rescan rediscovers qemu processes.
func (s *Server) Rescan(ctx context.Context) []api.Host {
	ctx = context.WithoutCancel(ctx)
	s.Refresh(ctx, true)
	return s.Hosts(ctx, true)
}

// Resolve finds the host of a client by uuid and/or hostname.
func (s *Server) Resolve(hostname, uuid string) (api.Host, error) {
	if hostname == "" && uuid == "" {
		return api.Host{}, api.InvalidArgument("hostname or uuid required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	h := s.resolveHostLocked(hostname, uuid)
	if h == nil {
		return api.Host{}, api.NotFound("no host matches hostname %q uuid %q", hostname, uuid)
	}
	return s.hostViewLocked(h), nil
}

// DeviceFilter filters device lists.
type DeviceFilter struct {
	Shared *bool
	State  string
	Host   string // attached to or local to the host (name or uuid)
	Pool   string
	Scope  string
}

// Devices lists devices.
func (s *Server) Devices(f DeviceFilter) ([]api.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hostName := ""
	if f.Host != "" {
		h := s.lookupHostLocked(f.Host)
		if h == nil {
			return nil, api.NotFound("host %q not found", f.Host)
		}
		hostName = h.name
	}
	out := []api.Device{}
	for _, d := range sortedDevices(s.devices) {
		v := s.deviceViewLocked(d)
		if f.Shared != nil && v.Shared != *f.Shared {
			continue
		}
		if f.State != "" && v.State != f.State {
			continue
		}
		if f.Pool != "" && v.Pool != f.Pool {
			continue
		}
		if f.Scope != "" && v.Scope != f.Scope {
			continue
		}
		if hostName != "" {
			_, local := d.bindings[hostName]
			attached := false
			for _, a := range v.Attachments {
				if a.Host == hostName {
					attached = true
				}
			}
			if !local && !attached {
				continue
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// Device returns a device.
func (s *Server) Device(name string) (api.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.devices[name]
	if d == nil {
		return api.Device{}, api.NotFound("device %q not found", name)
	}
	return s.deviceViewLocked(d), nil
}

// CreateDevice creates a pool device and its backing file.
func (s *Server) CreateDevice(req api.DeviceCreate) (api.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	size := int64(req.Size)
	if size <= 0 {
		return api.Device{}, api.InvalidArgument("size is required")
	}
	if size%CapacityMultiplier != 0 {
		return api.Device{}, api.InvalidArgument("size %s is not a multiple of 256M (CXL capacity unit)", api.FormatSize(size))
	}
	poolName := req.Pool
	if poolName == "" {
		poolName = s.poolOrder[0]
	}
	p := s.pools[poolName]
	if p == nil {
		return api.Device{}, api.NotFound("pool %q not found", poolName)
	}
	if req.Shared && !p.Sharable {
		return api.Device{}, api.InvalidArgument("pool %q is not sharable", poolName)
	}
	name := req.Name
	if name == "" {
		for i := 0; ; i++ {
			name = "dev" + strconv.Itoa(i)
			if _, ok := s.devices[name]; !ok {
				break
			}
		}
	}
	if err := pool.ValidName(name); err != nil {
		return api.Device{}, api.InvalidArgument("%v", err)
	}
	if _, ok := s.devices[name]; ok {
		return api.Device{}, api.Conflict("device %q already exists", name)
	}
	var sn uint64
	if req.Serial != "" {
		v, err := api.ParseSerial(req.Serial)
		if err != nil {
			return api.Device{}, api.InvalidArgument("%v", err)
		}
		if ld := s.localDeviceWithSerialLocked(v, ""); ld != nil {
			return api.Device{}, api.Conflict("serial 0x%x is used by local device %q", v, ld.Name)
		}
		if err := s.serials.Use(v, name); err != nil {
			return api.Device{}, api.Conflict("%v", err)
		}
		sn = v
	} else {
		sn = s.serials.NextExcept(name, s.localSerialLocked)
	}
	if err := p.Reserve(name, size); err != nil {
		s.serials.Release(sn)
		return api.Device{}, api.Conflict("%v", err)
	}
	path := p.FilePath(name)
	if err := pool.EnsureBackingFile(path, size); err != nil {
		p.Unreserve(name)
		s.serials.Release(sn)
		return api.Device{}, api.Internal("cannot create backing file: %v", err)
	}
	d := &device{
		Device: api.Device{
			Name:    name,
			Serial:  api.FormatSerial(sn),
			Size:    size,
			Shared:  req.Shared,
			Backend: api.BackendFile,
			Path:    path,
			Pool:    p.Name,
			Scope:   api.ScopePool,
			Labels:  req.Labels,
			Created: time.Now().UTC(),
		},
		serial:   sn,
		dynamic:  true,
		bindings: map[string]*binding{},
	}
	s.devices[name] = d
	s.logf("device %s: created %s shared=%v serial %s file %s", name, api.FormatSize(size), req.Shared, d.Serial, path)
	s.saveStateLocked()
	v := s.deviceViewLocked(d)
	s.events.publish(api.EventDeviceUpdated, v)
	return v, nil
}

// PatchDevice updates shared and labels of a device that is not attached.
func (s *Server) PatchDevice(name string, patch api.DevicePatch) (api.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[name]
	if d == nil {
		return api.Device{}, api.NotFound("device %q not found", name)
	}
	if len(s.deviceAttachmentsLocked(name)) > 0 {
		return api.Device{}, api.Conflict("device %q is attached", name)
	}
	if patch.Shared != nil {
		if *patch.Shared && d.Pool != "" && !s.pools[d.Pool].Sharable {
			return api.Device{}, api.InvalidArgument("pool %q is not sharable", d.Pool)
		}
		d.Shared = *patch.Shared
	}
	if patch.Labels != nil {
		d.Labels = patch.Labels
	}
	d.patched = d.patched || patch.Shared != nil || patch.Labels != nil
	s.saveStateLocked()
	v := s.deviceViewLocked(d)
	s.events.publish(api.EventDeviceUpdated, v)
	return v, nil
}

// DeleteDevice deletes a dynamic device and its backing file. With force,
// attachments are detached first.
func (s *Server) DeleteDevice(ctx context.Context, name string, force bool) error {
	s.mu.RLock()
	d := s.devices[name]
	if d == nil {
		s.mu.RUnlock()
		return api.NotFound("device %q not found", name)
	}
	if !d.dynamic {
		s.mu.RUnlock()
		if d.Static {
			return api.Conflict("device %q is defined in the config file", name)
		}
		return api.Conflict("device %q is a local device of a qemu command line", name)
	}
	atts := s.deviceAttachmentsLocked(name)
	if d.Allocation != nil && !force {
		owner := d.Allocation.Owner
		s.mu.RUnlock()
		return api.Conflict("device %q is allocated to %q, release it first or use force", name, owner)
	}
	s.mu.RUnlock()
	if len(atts) > 0 {
		if !force {
			return api.Conflict("device %q is attached to %d host(s), detach first or use force", name, len(atts))
		}
		for _, a := range atts {
			if _, _, err := s.Detach(ctx, name, a.Host, DetachOptions{Wait: true, Timeout: time.Duration(s.cfg.DetachTimeout), Force: true}); err != nil {
				return err
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.devices[name] != d {
		return api.NotFound("device %q not found", name)
	}
	if len(s.deviceAttachmentsLocked(name)) > 0 {
		return api.Conflict("device %q was attached again", name)
	}
	delete(s.devices, name)
	if p := s.pools[d.Pool]; p != nil {
		p.Unreserve(name)
		if filepath.Dir(d.Path) == filepath.Clean(p.Dir) {
			if err := pool.RemoveBackingFile(d.Path); err != nil {
				s.logf("device %s: cannot remove %s: %v", name, d.Path, err)
			}
		}
	}
	s.serials.Release(d.serial)
	s.logf("device %s: deleted", name)
	s.saveStateLocked()
	v := d.Device
	v.State = "deleted"
	s.events.publish(api.EventDeviceUpdated, v)
	return nil
}

// Allocate records the owner of a device.
func (s *Server) Allocate(name string, req api.AllocationRequest) (api.Allocation, error) {
	if req.Owner == "" {
		return api.Allocation{}, api.InvalidArgument("owner is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[name]
	if d == nil {
		return api.Allocation{}, api.NotFound("device %q not found", name)
	}
	if d.Allocation != nil && d.Allocation.Owner != req.Owner {
		return *d.Allocation, api.Conflict("device %q is allocated to %q", name, d.Allocation.Owner)
	}
	if d.Allocation == nil {
		d.Allocation = &api.Allocation{Owner: req.Owner, Since: time.Now().UTC()}
		s.logf("device %s: allocated to %s", name, req.Owner)
	}
	d.Allocation.Note = req.Note
	s.saveStateLocked()
	s.events.publish(api.EventDeviceUpdated, s.deviceViewLocked(d))
	return *d.Allocation, nil
}

// ReleaseAllocation removes the owner of a device. If owner is given, it
// must match unless force.
func (s *Server) ReleaseAllocation(name, owner string, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[name]
	if d == nil {
		return api.NotFound("device %q not found", name)
	}
	if d.Allocation == nil {
		return nil
	}
	if owner != "" && owner != d.Allocation.Owner && !force {
		return api.Conflict("device %q is allocated to %q", name, d.Allocation.Owner)
	}
	s.logf("device %s: allocation of %s released", name, d.Allocation.Owner)
	d.Allocation = nil
	s.saveStateLocked()
	s.events.publish(api.EventDeviceUpdated, s.deviceViewLocked(d))
	return nil
}

// AttachmentFilter filters attachment lists.
type AttachmentFilter struct {
	Host   string
	Device string
}

// Attachments lists attachments.
func (s *Server) Attachments(f AttachmentFilter) ([]api.Attachment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hostName := ""
	if f.Host != "" {
		h := s.lookupHostLocked(f.Host)
		if h == nil {
			return nil, api.NotFound("host %q not found", f.Host)
		}
		hostName = h.name
	}
	out := []api.Attachment{}
	for _, a := range sortedAttachments(s.atts) {
		if hostName != "" && a.Host != hostName {
			continue
		}
		if f.Device != "" && a.Device != f.Device {
			continue
		}
		out = append(out, a.Attachment)
	}
	return out, nil
}

// Attachment returns an attachment by id ("<device>@<host>"; the host part
// may be a uuid).
func (s *Server) Attachment(id string) (api.Attachment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if a := s.atts[id]; a != nil {
		return a.Attachment, nil
	}
	if i := strings.LastIndex(id, "@"); i > 0 {
		if h := s.lookupHostLocked(id[i+1:]); h != nil {
			if a := s.atts[api.AttachmentID(id[:i], h.name)]; a != nil {
				return a.Attachment, nil
			}
		}
	}
	return api.Attachment{}, api.NotFound("attachment %q not found", id)
}

// DeviceAttachment returns the attachment of a device to a host.
func (s *Server) DeviceAttachment(device, hostRef string) (api.Attachment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.devices[device] == nil {
		return api.Attachment{}, api.NotFound("device %q not found", device)
	}
	h := s.lookupHostLocked(hostRef)
	if h == nil {
		return api.Attachment{}, api.NotFound("host %q not found", hostRef)
	}
	a := s.atts[api.AttachmentID(device, h.name)]
	if a == nil {
		return api.Attachment{}, api.NotFound("device %q is not attached to %q", device, h.name)
	}
	return a.Attachment, nil
}

// AttachResult tells how an attach request ended.
type AttachResult int

const (
	// AttachExisting: the device was already attached (200).
	AttachExisting AttachResult = iota
	// AttachCreated: the device was attached now (201).
	AttachCreated
	// AttachAccepted: attaching continues in the background (202).
	AttachAccepted
)

// checkAttachLocked checks the sharing and ownership rules.
func (s *Server) checkAttachLocked(d *device, h *host, req api.AttachRequest) error {
	if d.Allocation != nil && d.Allocation.Owner != req.Owner && !req.Force {
		return api.Conflict("device %q is allocated to %q (request owner %q)", d.Name, d.Allocation.Owner, req.Owner)
	}
	for _, a := range s.deviceAttachmentsLocked(d.Name) {
		if a.Host != h.name && !d.Shared {
			return api.Conflict("device %q is not shared and it is attached to %q", d.Name, a.Host)
		}
	}
	if _, ok := d.bindings[h.name]; !ok {
		if d.Scope == api.ScopeLocal && d.Backend != api.BackendFile {
			return api.InvalidArgument("device %q is a local device of host %q", d.Name, d.LocalHost)
		}
		// the guest finds devices by serial: it must be unique in the VM
		if ld := s.localDeviceWithSerialLocked(d.serial, h.name); ld != nil && ld != d {
			return api.Conflict("device %q has the serial %s of local device %q of host %q", d.Name, d.Serial, ld.Name, h.name)
		}
	}
	return nil
}

// fmwSizeLocked returns the fixed memory window size of a host bridge, 0
// if unknown.
func fmwSizeLocked(h *host, hb string) int64 {
	if h.fmw != nil {
		if v, ok := h.fmw[hb]; ok {
			return v
		}
	}
	if h.proc != nil {
		return h.proc.FMWSize(hb)
	}
	return 0
}

// attachedBytesLocked returns the size of the devices attached under a
// host bridge (leaked ones included: their guest address range stays
// reserved).
func (s *Server) attachedBytesLocked(h *host, hb string) int64 {
	var total int64
	for _, a := range s.atts {
		if a.Host == h.name && a.Slot.HostBridge == hb {
			if d := s.devices[a.Device]; d != nil {
				total += d.Size
			}
		}
	}
	return total
}

// chooseSlotLocked picks the slot for an attachment of a device of size.
func (s *Server) chooseSlotLocked(h *host, b *binding, req api.AttachRequest, size int64) (string, error) {
	busy := map[string]bool{}
	for _, a := range s.atts {
		if a.Host == h.name && a.State != api.AttachmentFailed {
			busy[a.Slot.Bus] = true
		}
	}
	fits := func(p *qemu.Port) bool {
		fmw := fmwSizeLocked(h, p.HostBridge)
		return fmw == 0 || s.attachedBytesLocked(h, p.HostBridge)+size <= fmw
	}
	free := func(p *qemu.Port) bool { return p.Occupant() == "" && !busy[p.Bus] }
	checkFits := func(p *qemu.Port) error {
		if !fits(p) {
			return api.Conflict("host bridge %s of host %q has no room for %s more: fixed memory window %s, attached %s",
				p.HostBridge, h.name, api.FormatSize(size), api.FormatSize(fmwSizeLocked(h, p.HostBridge)),
				api.FormatSize(s.attachedBytesLocked(h, p.HostBridge)))
		}
		return nil
	}
	if req.Slot != "" {
		p := h.tree.Port(req.Slot)
		if p == nil || !p.IsSlot() {
			return "", api.InvalidArgument("host %q has no CXL slot %q", h.name, req.Slot)
		}
		if !free(p) {
			return "", api.Conflict("slot %q of host %q is occupied by %q", req.Slot, h.name, s.slotLocked(h, req.Slot).Device)
		}
		return p.Bus, checkFits(p)
	}
	if b != nil && b.Bus != "" {
		p := h.tree.Port(b.Bus)
		if p == nil || !p.IsSlot() {
			return "", api.InvalidArgument("host %q has no CXL slot %q for its local device", h.name, b.Bus)
		}
		if !free(p) {
			return "", api.Conflict("slot %q of host %q is occupied by %q", b.Bus, h.name, s.slotLocked(h, b.Bus).Device)
		}
		return p.Bus, checkFits(p)
	}
	// Prefer slots that are not the default slot of an unplugged local
	// device, and slots on the requested NUMA node.
	reserved := map[string]bool{}
	for _, d := range s.devices {
		if lb := d.bindings[h.name]; lb != nil {
			reserved[lb.Bus] = true
		}
	}
	best, bestScore := "", -1
	full := false
	for _, sl := range s.slotsLocked(h) {
		p := h.tree.Port(sl.Bus)
		if p == nil || !free(p) {
			continue
		}
		if !fits(p) {
			full = true
			continue
		}
		// a slot reserved for a local device only if nothing else is
		// free; then the requested NUMA node
		score := 1
		if !reserved[p.Bus] {
			score += 4
		}
		if req.NumaNode != nil && sl.NumaNode == *req.NumaNode {
			score += 2
		}
		if score > bestScore {
			best, bestScore = p.Bus, score
		}
	}
	if best == "" {
		if full {
			return "", api.Conflict("host %q has no free CXL slot under a host bridge with room for %s", h.name, api.FormatSize(size))
		}
		return "", api.Conflict("host %q has no free CXL slot", h.name)
	}
	return best, nil
}

// Attach hotplugs a device to a host.
func (s *Server) Attach(ctx context.Context, name string, req api.AttachRequest) (api.Attachment, AttachResult, error) {
	if req.Host == "" {
		return api.Attachment{}, 0, api.InvalidArgument("host is required")
	}
	timeout := DefaultAttachTimeout
	if req.Timeout != "" {
		t, err := time.ParseDuration(req.Timeout)
		if err != nil {
			return api.Attachment{}, 0, api.InvalidArgument("invalid timeout %q", req.Timeout)
		}
		timeout = t
	}
	wait := req.Wait == nil || *req.Wait

	s.mu.Lock()
	d := s.devices[name]
	if d == nil {
		s.mu.Unlock()
		return api.Attachment{}, 0, api.NotFound("device %q not found", name)
	}
	h := s.lookupHostLocked(req.Host)
	if h == nil {
		s.mu.Unlock()
		return api.Attachment{}, 0, api.NotFound("host %q not found", req.Host)
	}
	if existing, ok, err := s.existingAttachmentLocked(d, h, req); ok || err != nil {
		att, state := existing.Attachment, existing.State // copy under the lock
		s.mu.Unlock()
		if err != nil || state == api.AttachmentAttached {
			return att, AttachExisting, err
		}
		// attaching
		if !wait {
			return att, AttachAccepted, nil
		}
		return s.waitAttaching(ctx, existing, timeout)
	}
	if err := s.checkAttachLocked(d, h, req); err != nil {
		s.mu.Unlock()
		return api.Attachment{}, 0, err
	}
	if h.state == api.HostStopped || h.mon == nil {
		s.mu.Unlock()
		return api.Attachment{}, 0, api.Unavailable("host %q is not running (%s)", h.name, h.state)
	}
	mon := h.mon
	s.mu.Unlock()

	// phase 1: pick a slot from a fresh tree and reserve it
	h.opMu.Lock()
	s.mu.RLock()
	gen := h.gen
	s.mu.RUnlock()
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	tree, err := mon.QueryTree(qctx)
	cancel()
	if err != nil {
		h.opMu.Unlock()
		return api.Attachment{}, 0, api.Unavailable("host %q: cannot query qemu: %v", h.name, err)
	}
	s.mu.Lock()
	if h.mon != mon {
		s.mu.Unlock()
		h.opMu.Unlock()
		return api.Attachment{}, 0, api.Unavailable("host %q: qemu monitor changed (VM restarted?)", h.name)
	}
	// the slot choice needs this tree even if attachments changed while it
	// was read (they are in s.atts); reconcile skips it in that case
	s.storeTreeLocked(h, tree, gen, true)
	if existing, ok, err := s.existingAttachmentLocked(d, h, req); ok || err != nil {
		att := existing.Attachment
		s.mu.Unlock()
		h.opMu.Unlock()
		if err != nil {
			return api.Attachment{}, 0, err
		}
		return att, AttachExisting, nil
	}
	if s.devices[name] != d {
		s.mu.Unlock()
		h.opMu.Unlock()
		return api.Attachment{}, 0, api.NotFound("device %q not found", name)
	}
	if err := s.checkAttachLocked(d, h, req); err != nil {
		s.mu.Unlock()
		h.opMu.Unlock()
		return api.Attachment{}, 0, err
	}
	b := d.bindings[h.name]
	bus, err := s.chooseSlotLocked(h, b, req, d.Size)
	if err != nil {
		s.mu.Unlock()
		h.opMu.Unlock()
		return api.Attachment{}, 0, err
	}
	h.counter++
	qemuID := fmt.Sprintf("fcp_%s.hp%d", d.Name, h.counter)
	objID, serial := qemuID, d.serial
	var backend *qemu.MemoryBackend
	if b != nil {
		objID, serial = b.ObjectID, b.Serial
	} else {
		backend = &qemu.MemoryBackend{QomType: qemu.MemoryBackendFile, ID: objID, Size: uint64(d.Size), MemPath: d.Path, Share: true}
	}
	now := time.Now().UTC()
	a := &attachment{
		Attachment: api.Attachment{
			ID:           api.AttachmentID(d.Name, h.name),
			Device:       d.Name,
			Host:         h.name,
			Serial:       api.FormatSerial(serial),
			Slot:         s.slotLocked(h, bus),
			QemuDeviceID: qemuID,
			QemuObjectID: objID,
			State:        api.AttachmentAttaching,
			Created:      now,
			Updated:      now,
		},
		done: make(chan struct{}),
	}
	s.atts[a.ID] = a
	a.Slot.Attachment = a.ID
	a.Slot.Device = qemuID
	s.logf("attachment %s: attaching to slot %s as %s (backend %s, serial %s)", a.ID, bus, qemuID, objID, a.Serial)
	s.saveStateLocked()
	s.publishAttachmentLocked(a)
	path, size := d.Path, d.Size
	s.mu.Unlock()
	h.opMu.Unlock()

	// phase 2: object-add + device_add
	run := func(ctx context.Context) error {
		h.opMu.Lock()
		defer h.opMu.Unlock()
		var err error
		if backend != nil {
			if err = pool.EnsureBackingFile(path, size); err == nil {
				err = mon.ObjectAdd(ctx, *backend)
			}
		}
		if err == nil {
			err = mon.DeviceAdd(ctx, qemu.CXLType3{ID: qemuID, Bus: bus, VolatileMemdev: objID, Serial: serial})
			if err != nil && backend != nil {
				if derr := mon.ObjectDel(context.WithoutCancel(ctx), objID); derr != nil {
					s.logf("attachment %s: object-del %s after failed device_add: %v", a.ID, objID, derr)
				}
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		a.Updated = time.Now().UTC()
		if err == nil && s.atts[a.ID] != a {
			// dropped meanwhile: the qemu of the host stopped or restarted
			err = fmt.Errorf("host %s stopped or restarted during the attach", h.name)
		}
		if err != nil {
			a.State = api.AttachmentFailed
			a.Error = err.Error()
			if s.atts[a.ID] == a {
				delete(s.atts, a.ID)
			}
			s.logf("attachment %s: failed: %v", a.ID, err)
		} else {
			a.State = api.AttachmentAttached
			s.logf("attachment %s: attached", a.ID)
		}
		close(a.done)
		s.saveStateLocked()
		s.publishAttachmentLocked(a)
		return err
	}
	if !wait {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			ctx, cancel := context.WithTimeout(s.ctx, timeout)
			defer cancel()
			_ = run(ctx)
		}()
		s.mu.RLock()
		defer s.mu.RUnlock()
		return a.Attachment, AttachAccepted, nil
	}
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer rcancel()
	if err := run(rctx); err != nil {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return a.Attachment, 0, &api.Error{Code: api.CodeUnavailable, Message: fmt.Sprintf("attach %s to %s failed: %v", d.Name, h.name, err), Object: a.Attachment}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return a.Attachment, AttachCreated, nil
}

// existingAttachmentLocked returns the existing attachment of the device to
// the host, and an error if it is in a state that does not allow attach.
func (s *Server) existingAttachmentLocked(d *device, h *host, req api.AttachRequest) (*attachment, bool, error) {
	a := s.atts[api.AttachmentID(d.Name, h.name)]
	if a == nil {
		return nil, false, nil
	}
	if d.Allocation != nil && d.Allocation.Owner != req.Owner && !req.Force {
		return a, true, api.Conflict("device %q is allocated to %q (request owner %q)", d.Name, d.Allocation.Owner, req.Owner)
	}
	switch a.State {
	case api.AttachmentAttached, api.AttachmentAttaching:
		if req.Slot != "" && req.Slot != a.Slot.Bus {
			return a, true, api.Conflict("device %q is already attached to %q in slot %q", d.Name, h.name, a.Slot.Bus)
		}
		return a, true, nil
	case api.AttachmentDetaching:
		return a, true, &api.Error{Code: api.CodeConflict, Message: fmt.Sprintf("device %q is being detached from %q", d.Name, h.name), Object: a.Attachment}
	}
	return a, true, api.Conflict("device %q: attachment to %q is %s", d.Name, h.name, a.State)
}

func (s *Server) waitAttaching(ctx context.Context, a *attachment, timeout time.Duration) (api.Attachment, AttachResult, error) {
	s.mu.RLock()
	done := a.done
	s.mu.RUnlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
		case <-time.After(timeout):
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch a.State {
	case api.AttachmentAttached:
		return a.Attachment, AttachExisting, nil
	case api.AttachmentAttaching:
		return a.Attachment, AttachAccepted, nil
	}
	return a.Attachment, 0, &api.Error{Code: api.CodeUnavailable, Message: "attach failed: " + a.Error, Object: a.Attachment}
}

// DetachOptions are the options of a detach request.
type DetachOptions struct {
	Wait    bool
	Timeout time.Duration
	Owner   string
	Force   bool
}

// DetachResult tells how a detach request ended.
type DetachResult int

const (
	// DetachDone: the device is gone from qemu (200).
	DetachDone DetachResult = iota
	// DetachAccepted: detaching continues in the background (202).
	DetachAccepted
)

// Detach hot-removes a device from a host. With Wait, it waits for qemu to
// delete the device until Timeout, and returns a Conflict error with the
// attachment (state detaching) if that did not happen; waiting continues in
// the background.
func (s *Server) Detach(ctx context.Context, name, hostRef string, opts DetachOptions) (api.Attachment, DetachResult, error) {
	// The detach must not depend on the client connection: a client that
	// gives up must not fake a timeout or skip the leak check and object-del.
	// Every wait below is bounded by opts.Timeout or a command timeout.
	ctx = context.WithoutCancel(ctx)
	if opts.Timeout <= 0 {
		opts.Timeout = time.Duration(s.cfg.DetachTimeout)
	}
	s.mu.Lock()
	d := s.devices[name]
	if d == nil {
		s.mu.Unlock()
		return api.Attachment{}, 0, api.NotFound("device %q not found", name)
	}
	h := s.lookupHostLocked(hostRef)
	if h == nil {
		s.mu.Unlock()
		return api.Attachment{}, 0, api.NotFound("host %q not found", hostRef)
	}
	a := s.atts[api.AttachmentID(d.Name, h.name)]
	if a == nil {
		s.mu.Unlock()
		return api.Attachment{}, 0, api.NotFound("device %q is not attached to %q", name, h.name)
	}
	att := a.Attachment // copy under the lock
	if d.Allocation != nil && opts.Owner != d.Allocation.Owner && !opts.Force {
		s.mu.Unlock()
		return att, 0, api.Conflict("device %q is allocated to %q (request owner %q)", name, d.Allocation.Owner, opts.Owner)
	}
	if a.State == api.AttachmentAttaching {
		s.mu.Unlock()
		return att, 0, api.Conflict("device %q is being attached to %q", name, h.name)
	}
	if a.State == api.AttachmentFailed {
		defer s.mu.Unlock()
		if !opts.Force {
			return att, 0, &api.Error{Code: api.CodeConflict, Object: att,
				Message: fmt.Sprintf("attachment %s failed: %s; use force to forget it", a.ID, a.Error)}
		}
		delete(s.atts, a.ID)
		a.State = api.AttachmentDetached
		a.Updated = time.Now().UTC()
		s.logf("attachment %s: forgotten (force)", a.ID)
		s.saveStateLocked()
		s.publishAttachmentLocked(a)
		return a.Attachment, DetachDone, nil
	}
	mon := h.mon
	if mon == nil {
		s.mu.Unlock()
		return att, 0, api.Unavailable("host %q has no monitor (%s)", h.name, h.state)
	}
	qemuID := a.QemuDeviceID
	already := a.State == api.AttachmentDetaching
	if !already {
		a.State = api.AttachmentDetaching
		a.Updated = time.Now().UTC()
		a.Error = ""
		s.logf("attachment %s: detaching qemu device %s", a.ID, qemuID)
		s.saveStateLocked()
		s.publishAttachmentLocked(a)
	}
	s.mu.Unlock()
	// Never send device_del twice: qemu refuses it while an unplug is
	// pending, and there is no way to cancel or repeat the guest's part.

	if !already {
		h.opMu.Lock()
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := mon.DeviceDel(dctx, qemuID)
		cancel()
		h.opMu.Unlock()
		switch {
		case err == nil, qemu.IsUnplugInProgress(err):
			s.mu.Lock()
			a.unplugPending = true
			if h.unplugged == nil {
				h.unplugged = map[string]bool{}
			}
			h.unplugged[qemuID] = true
			s.saveStateLocked()
			s.mu.Unlock()
		case qemu.IsNotFound(err):
			// already gone from qemu: still check that the guest does not
			// keep its memory
			return s.detachResult(a, name, h.name, s.completeDetach(ctx, a))
		default:
			s.mu.Lock()
			a.State = api.AttachmentAttached
			a.Error = "device_del: " + err.Error()
			a.Updated = time.Now().UTC()
			s.saveStateLocked()
			s.publishAttachmentLocked(a)
			att = a.Attachment
			s.mu.Unlock()
			return att, 0, api.Unavailable("detach %s from %s: %v", name, h.name, err)
		}
	}
	if !opts.Wait {
		s.mu.Lock()
		s.startBackgroundWaitLocked(a, opts.Timeout)
		att = a.Attachment
		s.mu.Unlock()
		return att, DetachAccepted, nil
	}
	wctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	err := mon.WaitDeviceDeleted(wctx, qemuID)
	cancel()
	if err == nil {
		return s.detachResult(a, name, h.name, s.completeDetach(ctx, a))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.atts[a.ID] != a {
		// finalized meanwhile by reconcile or a background waiter
		return a.Attachment, DetachDone, nil
	}
	if a.State != api.AttachmentFailed {
		s.markTimedOutLocked(a, opts.Timeout)
	}
	s.startBackgroundWaitLocked(a, 0)
	return a.Attachment, 0, &api.Error{
		Code:    api.CodeConflict,
		Message: fmt.Sprintf("detach %s from %s: %s", name, h.name, a.Error),
		Object:  a.Attachment,
	}
}

// detachResult turns the result of completeDetach into the reply of a
// detach request.
func (s *Server) detachResult(a *attachment, name, host string, res completeResult) (api.Attachment, DetachResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch res {
	case completeLeaked:
		return a.Attachment, 0, &api.Error{Code: api.CodeConflict, Object: a.Attachment,
			Message: fmt.Sprintf("detach %s from %s: %s", name, host, a.Error)}
	case completeUnknown:
		if s.atts[a.ID] == a {
			// could not check the backend: finish in the background
			s.startBackgroundWaitLocked(a, 0)
			return a.Attachment, DetachAccepted, nil
		}
	}
	return a.Attachment, DetachDone, nil
}
