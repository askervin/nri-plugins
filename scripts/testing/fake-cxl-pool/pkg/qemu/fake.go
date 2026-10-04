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

package qemu

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Fake is an in-memory Monitor for unit tests. It models the parts of qemu
// and of the guest that matter for hotplug: device and object id
// uniqueness, busy backends, slot occupancy and a guest that holds a device
// until it is released.
type Fake struct {
	mu          sync.Mutex
	VersionStr  string
	hostBridges []TreeHostBridge
	ports       []Port
	objects     map[string]MemoryBackend
	devices     map[string]CXLType3
	usedIDs     map[string]bool // qemu never reuses a device id
	mapped      map[string]bool // backend in use by a device
	pendingDel  map[string]bool
	held        map[string]bool // guest holds the device: device_del does not complete
	// Stock emulates unpatched qemu: a deleted cxl-type3 stays in the tree
	// forever (and its backend stays mapped).
	Stock bool
	// FailDeviceAdd, if set, is returned by the next DeviceAdd.
	FailDeviceAdd error
	// Unreachable makes every call fail.
	Unreachable bool
	Log         []string
	deletedCh   map[string]chan struct{}
	// leaked backends stay mapped after their device is gone (the guest
	// kept the memory online)
	leaked map[string]bool
	// LeakOnRelease makes Release of a held device remove the device but
	// leave its backend mapped (patched qemu, guest memory stuck online).
	LeakOnRelease bool
	// FMW are the fixed memory windows reported by QomGet /machine cxl-fmw.
	FMW []FMWWindow
}

// NewFake returns a fake monitor with the given host bridges (id ->
// numa node) and slots (bus -> host bridge, all downstream ports).
func NewFake(hostBridges map[string]int, slots map[string]string) *Fake {
	f := &Fake{
		VersionStr: "11.1.1 fake",
		objects:    map[string]MemoryBackend{},
		devices:    map[string]CXLType3{},
		usedIDs:    map[string]bool{},
		mapped:     map[string]bool{},
		pendingDel: map[string]bool{},
		held:       map[string]bool{},
		deletedCh:  map[string]chan struct{}{},
		leaked:     map[string]bool{},
	}
	for id, numa := range hostBridges {
		f.hostBridges = append(f.hostBridges, TreeHostBridge{ID: id, NumaNode: numa})
	}
	sort.Slice(f.hostBridges, func(i, j int) bool { return f.hostBridges[i].ID < f.hostBridges[j].ID })
	for bus, hb := range slots {
		f.ports = append(f.ports, Port{Bus: bus, Kind: PortDownstream, HostBridge: hb})
	}
	sort.Slice(f.ports, func(i, j int) bool { return f.ports[i].Bus < f.ports[j].Bus })
	return f
}

// AddObject pre-declares a memory backend (like -object on the command line).
func (f *Fake) AddObject(b MemoryBackend) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[b.ID] = b
}

// PlugDevice plugs a device as if done by someone else (or at boot).
func (f *Fake) PlugDevice(d CXLType3) error {
	return f.DeviceAdd(context.Background(), d)
}

// Hold makes the guest hold the device: device_del will not complete until
// Release.
func (f *Fake) Hold(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.held[id] = true
}

// Release releases a device in the guest. A pending device_del completes.
func (f *Fake) Release(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.held, id)
	if f.pendingDel[id] {
		if f.LeakOnRelease {
			f.leaked[f.devices[id].VolatileMemdev] = true
		}
		f.completeDelLocked(id)
	}
}

// BackendMapped implements Monitor.
func (f *Fake) BackendMapped(ctx context.Context, objID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(); err != nil {
		return false, err
	}
	return f.leaked[objID], nil
}

// HasDevice returns true if the device is plugged.
func (f *Fake) HasDevice(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.devices[id]
	return ok
}

// HasObject returns true if the object exists.
func (f *Fake) HasObject(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.objects[id]
	return ok
}

// Commands returns the log of mutating commands.
func (f *Fake) Commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Log...)
}

func (f *Fake) check() error {
	if f.Unreachable {
		return fmt.Errorf("fake monitor unreachable")
	}
	return nil
}

// Protocol implements Monitor.
func (f *Fake) Protocol() string { return "fake" }

// Version implements Monitor.
func (f *Fake) Version(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(); err != nil {
		return "", err
	}
	return f.VersionStr, nil
}

// ObjectAdd implements Monitor.
func (f *Fake) ObjectAdd(ctx context.Context, b MemoryBackend) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(); err != nil {
		return err
	}
	f.Log = append(f.Log, HMPObjectAdd(b))
	if _, ok := f.objects[b.ID]; ok {
		return &Error{Command: "object_add", Desc: fmt.Sprintf("attempt to add duplicate property '%s' to object (type 'container')", b.ID)}
	}
	f.objects[b.ID] = b
	return nil
}

// ObjectDel implements Monitor.
func (f *Fake) ObjectDel(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(); err != nil {
		return err
	}
	f.Log = append(f.Log, "object_del "+id)
	if _, ok := f.objects[id]; !ok {
		return &Error{Command: "object_del", Desc: fmt.Sprintf("object '%s' not found", id)}
	}
	if f.mapped[id] {
		return &Error{Command: "object_del", Desc: fmt.Sprintf("object '%s' is in use, can not be deleted", id)}
	}
	delete(f.objects, id)
	return nil
}

// DeviceAdd implements Monitor.
func (f *Fake) DeviceAdd(ctx context.Context, d CXLType3) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(); err != nil {
		return err
	}
	f.Log = append(f.Log, HMPDeviceAdd(d))
	if err := f.FailDeviceAdd; err != nil {
		f.FailDeviceAdd = nil
		return err
	}
	if f.usedIDs[d.ID] {
		return &Error{Command: "device_add", Desc: fmt.Sprintf("Duplicate device ID '%s'", d.ID)}
	}
	var port *Port
	for i := range f.ports {
		if f.ports[i].Bus == d.Bus {
			port = &f.ports[i]
		}
	}
	if port == nil {
		return &Error{Command: "device_add", Desc: fmt.Sprintf("Bus '%s' not found", d.Bus)}
	}
	if len(port.Children) > 0 {
		return &Error{Command: "device_add", Desc: "PCI: slot 0 function 0 already occupied by cxl-type3, new func cxl-type3 cannot be exposed to guest."}
	}
	if _, ok := f.objects[d.VolatileMemdev]; !ok {
		return &Error{Command: "device_add", Desc: fmt.Sprintf("Property 'cxl-type3.volatile-memdev' can't find value '%s'", d.VolatileMemdev)}
	}
	if f.mapped[d.VolatileMemdev] {
		return &Error{Command: "device_add", Desc: fmt.Sprintf("memory backend %s can't be used multiple times.", d.VolatileMemdev)}
	}
	f.usedIDs[d.ID] = true
	f.mapped[d.VolatileMemdev] = true
	f.devices[d.ID] = d
	port.Children = []TreeDevice{{Driver: "cxl-type3", ID: d.ID}}
	f.deletedCh[d.ID] = make(chan struct{})
	return nil
}

// DeviceDel implements Monitor.
func (f *Fake) DeviceDel(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(); err != nil {
		return err
	}
	f.Log = append(f.Log, "device_del "+id)
	if _, ok := f.devices[id]; !ok {
		return &Error{Command: "device_del", Class: "DeviceNotFound", Desc: fmt.Sprintf("Device '%s' not found", id)}
	}
	if f.pendingDel[id] {
		return &Error{Command: "device_del", Desc: fmt.Sprintf("Device %s is already in the process of unplug", id)}
	}
	f.pendingDel[id] = true
	if !f.held[id] {
		f.completeDelLocked(id)
	}
	return nil
}

func (f *Fake) completeDelLocked(id string) {
	if f.Stock {
		// the guest has released it, but qemu keeps the device
		return
	}
	d := f.devices[id]
	delete(f.devices, id)
	delete(f.pendingDel, id)
	if !f.leaked[d.VolatileMemdev] {
		delete(f.mapped, d.VolatileMemdev)
	}
	for i := range f.ports {
		if f.ports[i].Bus == d.Bus {
			f.ports[i].Children = nil
		}
	}
	if ch := f.deletedCh[id]; ch != nil {
		close(ch)
		delete(f.deletedCh, id)
	}
}

// QomGet implements Monitor for /machine cxl-fmw and
// power_controller_present of ports.
func (f *Fake) QomGet(ctx context.Context, path, property string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(); err != nil {
		return nil, err
	}
	switch {
	case path == "/machine" && property == "cxl-fmw":
		b, _ := json.Marshal(f.FMW)
		return b, nil
	case property == "power_controller_present":
		if f.Stock {
			return nil, &Error{Command: "qom-get", Desc: "Property 'cxl-downstream.power_controller_present' not found"}
		}
		return json.RawMessage("true"), nil
	}
	return nil, &Error{Command: "qom-get", Desc: fmt.Sprintf("Property '%s' not found", property)}
}

// DeviceExists implements Monitor.
func (f *Fake) DeviceExists(ctx context.Context, id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(); err != nil {
		return false, err
	}
	_, ok := f.devices[id]
	return ok, nil
}

// WaitDeviceDeleted implements Monitor.
func (f *Fake) WaitDeviceDeleted(ctx context.Context, id string) error {
	f.mu.Lock()
	_, ok := f.devices[id]
	ch := f.deletedCh[id]
	f.mu.Unlock()
	if !ok || ch == nil {
		return nil
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// QueryMemdevs implements Monitor.
func (f *Fake) QueryMemdevs(ctx context.Context) ([]Memdev, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(); err != nil {
		return nil, err
	}
	var out []Memdev
	for _, o := range f.objects {
		out = append(out, Memdev{ID: o.ID, Size: o.Size, Share: o.Share})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// QueryTree implements Monitor.
func (f *Fake) QueryTree(ctx context.Context) (*Tree, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(); err != nil {
		return nil, err
	}
	t := &Tree{HostBridges: append([]TreeHostBridge(nil), f.hostBridges...)}
	for _, p := range f.ports {
		p.Children = append([]TreeDevice(nil), p.Children...)
		t.Ports = append(t.Ports, p)
	}
	for _, d := range f.devices {
		t.Type3 = append(t.Type3, Type3Device{ID: d.ID, Bus: d.Bus, VolatileMemdev: d.VolatileMemdev, Serial: d.Serial, HasSerial: true})
	}
	sort.Slice(t.Type3, func(i, j int) bool { return t.Type3[i].ID < t.Type3[j].ID })
	return t, nil
}

// Close implements Monitor.
func (f *Fake) Close() error { return nil }

// String summarizes the fake state.
func (f *Fake) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for id := range f.devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return "fake{devices: " + strings.Join(ids, ",") + "}"
}

var (
	_ Monitor = (*Fake)(nil)
	_ Monitor = (*HMP)(nil)
	_ Monitor = (*QMP)(nil)
)
