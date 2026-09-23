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

// Package api defines the JSON types and the routes of the fake-cxl-pool
// REST API v1. The server and the client share these definitions.
package api

import (
	"time"
)

// ServerVersion is the version string reported by the server.
const ServerVersion = "fake-cxl-pool/v1.0"

// Status is the server status (GET /api/v1/status).
type Status struct {
	// Name is the name of the server, the DRA pool name of
	// fake-cxl-pool-controller ("" from a server without a name).
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Qemu        QemuStatus `json:"qemu"`
	Hosts       int        `json:"hosts"`
	Devices     int        `json:"devices"`
	Attachments int        `json:"attachments"`
	Uptime      string     `json:"uptime"`
	Started     time.Time  `json:"started"`
	StateFile   string     `json:"stateFile,omitempty"`
}

// QemuStatus summarizes the qemu processes the server controls.
type QemuStatus struct {
	Discovery bool              `json:"discovery"`
	Versions  map[string]string `json:"versions,omitempty"` // host name -> qemu version
}

// Pool is a memory resource: a directory of device backing files.
type Pool struct {
	Name     string `json:"name"`
	Dir      string `json:"dir"`
	Capacity int64  `json:"capacity"`
	Used     int64  `json:"used"`
	Free     int64  `json:"free"`
	Sharable bool   `json:"sharable"`
}

// Host states.
const (
	HostRunning     = "running"
	HostStopped     = "stopped"
	HostUnreachable = "unreachable"
)

// Host sources.
const (
	SourceConfig     = "config"
	SourceDiscovered = "discovered"
)

// Host is a memory consumer: a qemu VM.
type Host struct {
	Name        string `json:"name"`
	UUID        string `json:"uuid"` // SMBIOS system UUID (qemu -uuid), "" if not set
	PID         int    `json:"pid"`
	State       string `json:"state"`
	Control     string `json:"control"`
	QMP         string `json:"qmp"`
	HMP         string `json:"hmp"`
	QemuVersion string `json:"qemuVersion"`
	// HotRemoveCapable is false for qemu builds that cannot complete
	// hot-removal from cxl-downstream ports (stock qemu: the device stays
	// as a zombie and its slot and backend can never be reused).
	HotRemoveCapable bool         `json:"hotRemoveCapable"`
	Source           string       `json:"source"`
	Error            string       `json:"error,omitempty"`
	HostBridges      []HostBridge `json:"hostBridges"`
	Slots            []Slot       `json:"slots"`
	Attachments      []Attachment `json:"attachments"`
	LocalDevices     []string     `json:"localDevices"`
}

// HostBridge is a CXL host bridge (pxb-cxl) of a host.
type HostBridge struct {
	ID            string `json:"id"`
	NumaNode      int    `json:"numaNode"`
	FMWSize       int64  `json:"fmwSize"`
	AttachedBytes int64  `json:"attachedBytes"`
}

// Slot kinds.
const (
	SlotDownstream = "downstream"
	SlotRootPort   = "rootport"
)

// Slot is a place where a cxl-type3 device can be plugged in.
type Slot struct {
	Bus        string `json:"bus"`
	Kind       string `json:"kind"`
	HostBridge string `json:"hostBridge"`
	NumaNode   int    `json:"numaNode"`
	Device     string `json:"device"`
	Attachment string `json:"attachment"`
	// ReservedFor is the local device whose pre-declared backend names this
	// slot (beram_/befile_..._bus_<slot>_...). The server gives such slots
	// to other devices only when no other slot is free.
	ReservedFor string `json:"reservedFor,omitempty"`
}

// Device backends.
const (
	BackendFile = "file"
	BackendRAM  = "ram"
)

// Device scopes.
const (
	ScopePool  = "pool"
	ScopeLocal = "local"
)

// Device states.
const (
	DeviceFree      = "free"
	DeviceAttached  = "attached"
	DeviceAttaching = "attaching"
	DeviceDetaching = "detaching"
	DeviceError     = "error"
)

// Device is a pool memory device: a backing file or a ram object.
type Device struct {
	Name   string `json:"name"`
	Serial string `json:"serial"`
	Size   int64  `json:"size"`
	Shared bool   `json:"shared"`
	// Persistent devices are persistent memory with a label storage
	// area (LSA) file at LSAPath; others are volatile memory.
	Persistent  bool              `json:"persistent"`
	Backend     string            `json:"backend"`
	Path        string            `json:"path,omitempty"`
	LSAPath     string            `json:"lsaPath,omitempty"`
	Pool        string            `json:"pool"`
	Scope       string            `json:"scope"`
	LocalHost   string            `json:"localHost,omitempty"`
	LocalHosts  []string          `json:"localHosts,omitempty"`
	Static      bool              `json:"static,omitempty"`
	State       string            `json:"state"`
	Allocation  *Allocation       `json:"allocation"`
	Attachments []Attachment      `json:"attachments"`
	Labels      map[string]string `json:"labels,omitempty"`
	Created     time.Time         `json:"created"`
}

// DeviceCreate is the body of POST /api/v1/devices.
type DeviceCreate struct {
	Name       string            `json:"name,omitempty"`
	Size       Size              `json:"size"`
	Shared     bool              `json:"shared,omitempty"`
	Persistent bool              `json:"persistent,omitempty"`
	Pool       string            `json:"pool,omitempty"`
	Serial     string            `json:"serial,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// DevicePatch is the body of PATCH /api/v1/devices/{name}. Labels, when
// given, replace all labels of the device.
type DevicePatch struct {
	Shared *bool             `json:"shared,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Allocation records the logical owner of a device.
type Allocation struct {
	Owner string    `json:"owner"`
	Note  string    `json:"note,omitempty"`
	Since time.Time `json:"since"`
}

// AllocationRequest is the body of PUT /api/v1/devices/{name}/allocation.
type AllocationRequest struct {
	Owner string `json:"owner"`
	Note  string `json:"note,omitempty"`
}

// AttachRequest is the body of POST /api/v1/devices/{name}/attachments.
type AttachRequest struct {
	Host     string `json:"host"`
	Slot     string `json:"slot,omitempty"`
	NumaNode *int   `json:"numaNode,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Wait     *bool  `json:"wait,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	Force    bool   `json:"force,omitempty"`
	// Exclusive attaches a shared device to this host only: the attach
	// fails while the device is attached to another host, and attaching it
	// to another host fails while this attachment is exclusive. An attach
	// of an attached device sets the flag of the attachment.
	Exclusive bool `json:"exclusive,omitempty"`
}

// Attachment states.
const (
	AttachmentAttaching = "attaching"
	AttachmentAttached  = "attached"
	AttachmentDetaching = "detaching"
	AttachmentDetached  = "detached"
	AttachmentFailed    = "failed"
)

// Attachment is the hotplug state of a device in a host.
type Attachment struct {
	ID           string `json:"id"`
	Device       string `json:"device"`
	Host         string `json:"host"`
	Serial       string `json:"serial"`
	Slot         Slot   `json:"slot"`
	QemuDeviceID string `json:"qemuDeviceId"`
	QemuObjectID string `json:"qemuObjectId"`
	// QemuLSAObjectID is the label storage area backend of a persistent
	// device, "" for volatile devices.
	QemuLSAObjectID string `json:"qemuLsaObjectId,omitempty"`
	State           string `json:"state"`
	Error           string `json:"error,omitempty"`
	// Owner is the owner given in the attach request that created the
	// attachment ("" if none, or adopted). An attachment without owner
	// takes the owner of the first attach request that has one.
	Owner string `json:"owner,omitempty"`
	// Exclusive is the flag of the last attach request: no other host may
	// attach the device meanwhile.
	Exclusive bool      `json:"exclusive,omitempty"`
	Adopted   bool      `json:"adopted,omitempty"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
}

// AttachmentID returns the id of the attachment of a device to a host.
func AttachmentID(device, host string) string {
	return device + "@" + host
}

// Event types.
const (
	EventAttachmentUpdated = "attachment.updated"
	EventDeviceUpdated     = "device.updated"
	EventHostUpdated       = "host.updated"
)

// Event is one item of GET /api/v1/events (text/event-stream).
type Event struct {
	Type   string    `json:"type"`
	Time   time.Time `json:"time"`
	Object any       `json:"object"`
}
