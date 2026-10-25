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

// Observations (04-contract.txt 6). Decoding is lenient: unknown fields
// are ignored, a part that bash could not read is null (and listed in
// "errors"), and the oracle waits for it.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Observation is one settle observation (6.1).
type Observation struct {
	Step        int                        `json:"step"`
	Poll        int                        `json:"poll"`
	Pods        []ObsPod                   `json:"pods"`
	Companions  []ObsCompanion             `json:"companions"`
	Others      []string                   `json:"others"`
	Attachments map[string][]ObsAttachment `json:"attachments"`
	Drivers     map[string]*ObsDriver      `json:"drivers"`
	Controllers map[string]string          `json:"controllers"`
	VMs         map[string]*ObsVM          `json:"vms"`
	Inspect     map[string]*ObsInspect     `json:"inspect"`
	Slices      map[string][]ObsSliceDev   `json:"slices"`     // A13: cxl.nri.io devices per node
	PoolSlices  map[string][]ObsPoolSlice  `json:"poolSlices"` // A18: cxl-pool.nri.io slices per pool
	Errors      []string                   `json:"errors,omitempty"`
}

type ObsPod struct {
	Slot          string     `json:"slot"`
	Name          string     `json:"name"`
	UID           string     `json:"uid"`
	Gen           int        `json:"gen"`
	Node          *string    `json:"node"`
	Phase         string     `json:"phase"`
	Ready         bool       `json:"ready"`
	Deleting      bool       `json:"deleting"`
	Restarts      int        `json:"restarts"`
	Waiting       *string    `json:"waiting"`
	Unschedulable bool       `json:"unschedulable"`
	Claim         *ObsClaim  `json:"claim"`
	Event         *ObsEvent  `json:"event"`  // A10: the newest Warning event
	Events        []ObsEvent `json:"events"` // A12: Warning events, newest first
}

// ObsEvent is a Kubernetes event of a pod.
type ObsEvent struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

type ObsClaim struct {
	Name      string           `json:"name"`
	UID       string           `json:"uid"`
	Allocated bool             `json:"allocated"`
	Devices   []ObsClaimDevice `json:"devices"`
	Attached  *bool            `json:"attached"`
}

type ObsClaimDevice struct {
	Driver string `json:"driver"`
	Pool   string `json:"pool"`
	Device string `json:"device"`
}

type ObsCompanion struct {
	Name      string  `json:"name"`
	Node      string  `json:"node"`
	Phase     string  `json:"phase"`
	Lease     string  `json:"lease"`
	Requester *string `json:"requester"`
}

type ObsAttachment struct {
	Device    string `json:"device"`
	Host      string `json:"host"`
	State     string `json:"state"`
	Exclusive bool   `json:"exclusive"`
	Adopted   bool   `json:"adopted"`
	Owner     string `json:"owner"`
}

type ObsDriver struct {
	Pod      string `json:"pod"`
	Ready    bool   `json:"ready"`
	Restarts int    `json:"restarts"`
}

// ObsVM is the observation of mbt-observe.py in a VM (6.3).
type ObsVM struct {
	BootID     string              `json:"bootID"`
	Memdevs    []ObsMemdev         `json:"memdevs"`
	Regions    []ObsRegion         `json:"regions"`
	Nodes      map[string]ObsNode  `json:"nodes"`
	State      *ObsDriverState     `json:"state"`
	CDI        map[string][]string `json:"cdi"`
	Containers []ObsContainer      `json:"containers"`
	Ports      []ObsPort           `json:"ports"`     // A10: committed decoders
	DriverLog  *ObsDriverLog       `json:"driverLog"` // A13
	Missing    json.RawMessage     `json:"missing"`   // A11 (executor): running containers not observed
	Errors     []string            `json:"errors,omitempty"`
}

// ObsPoolSlice is a ResourceSlice of a pool's controller (A18).
type ObsPoolSlice struct {
	Name    string          `json:"name"`
	Devices json.RawMessage `json:"devices"`
	Nodes   []string        `json:"nodes"`
}

// ObsSliceDev is a device of a node's cxl.nri.io ResourceSlice (A13).
type ObsSliceDev struct {
	Name   string `json:"name"`
	Serial string `json:"serial"`
	Shared bool   `json:"shared"`
}

// ObsDriverLog is the summary of the current driver container's log
// (A13).
type ObsDriverLog struct {
	Container     *string  `json:"container"`
	Panics        int      `json:"panics"`
	Errors        []string `json:"errors"`
	LendsRestored *bool    `json:"lendsRestored"` // A15: NRI and lending up
	Sockets       *bool    `json:"sockets"`       // A15: both dra.sock
}

// ObsPort is a CXL port with its committed decoders (A10).
type ObsPort struct {
	Port      string       `json:"port"`
	Kind      string       `json:"kind"`
	HB        *string      `json:"hb"`
	Committed int          `json:"committed"`
	Decoders  []ObsDecoder `json:"decoders"`
}

type ObsDecoder struct {
	Name   string `json:"name"`
	Region string `json:"region"`
	Start  uint64 `json:"start"`
	Size   uint64 `json:"size"`
}

type ObsMemdev struct {
	Name   string `json:"name"`
	Serial string `json:"serial"`
	Size   uint64 `json:"size"`
}

type ObsRegion struct {
	Name    string   `json:"name"`
	Serials []string `json:"serials"`
	Mode    string   `json:"mode"`
	Size    uint64   `json:"size"`
	Node    *int     `json:"node"`
	Dax     []ObsDax `json:"dax"`
}

type ObsDax struct {
	Name   string  `json:"name"`
	Size   uint64  `json:"size"`
	Driver *string `json:"driver"`
	Online uint64  `json:"online"`
}

type ObsNode struct {
	MemTotal uint64 `json:"memtotal"`
}

type ObsDriverState struct {
	Prepared     []string         `json:"prepared"`
	Info         []string         `json:"info"`
	Pool         []string         `json:"pool"`
	LocalDevices *ObsLocalDevices `json:"localDevices"`
	Leases       json.RawMessage  `json:"leases"`
}

type ObsLocalDevices struct {
	BootID  string           `json:"bootID"`
	Devices []ObsLocalDevice `json:"devices"`
}

// ObsLocalDevice is a device of localDevices.json. The driver writes the
// serial as a number (and serialHex); a string is accepted too.
type ObsLocalDevice struct {
	Serial    json.RawMessage            `json:"serial"`
	SerialHex string                     `json:"serialHex"`
	Region    string                     `json:"region"`
	Claims    map[string]json.RawMessage `json:"claims"`
}

func (d *ObsLocalDevice) serial() (uint64, bool) {
	if d.SerialHex != "" {
		if v, ok := parseSerial(d.SerialHex); ok {
			return v, true
		}
	}
	raw := bytes.TrimSpace(d.Serial)
	if len(raw) == 0 {
		return 0, false
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return 0, false
		}
		if strings.HasPrefix(strings.ToLower(s), "0x") {
			return parseSerial(s)
		}
		v, err := strconv.ParseUint(s, 10, 64)
		return v, err == nil
	}
	v, err := strconv.ParseUint(string(raw), 10, 64)
	return v, err == nil
}

// slices returns the number of slices of a claim of the device.
func (d *ObsLocalDevice) slices(uid string) int {
	var list []json.RawMessage
	if json.Unmarshal(d.Claims[uid], &list) != nil {
		return 0
	}
	return len(list)
}

type ObsContainer struct {
	Ns            string `json:"ns"`
	Pod           string `json:"pod"`
	Name          string `json:"name"`
	ID            string `json:"id"`
	Mems          string `json:"mems"`
	MemsEffective string `json:"mems_effective"`
	MemoryHigh    string `json:"memory_high"`
}

type ObsInspect struct {
	UID      string            `json:"uid"`
	Restarts int               `json:"restarts"`
	Env      map[string]string `json:"env"`
	Leases   json.RawMessage   `json:"leases"`
}

// ObsLease is one lease of `cxl-request list`.
type ObsLease struct {
	Lease  string `json:"lease"`
	State  string `json:"state"`
	Mode   string `json:"mode"`
	Source string `json:"source"`
}

// leases decodes the list of an inspection: an array of leases, or the
// response object {"leases": [...]}; ok is false for null or garbage.
func (in *ObsInspect) leases() ([]ObsLease, bool) {
	raw := bytes.TrimSpace(in.Leases)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var list []ObsLease
	if json.Unmarshal(raw, &list) == nil {
		return list, true
	}
	var obj struct {
		Leases *[]ObsLease `json:"leases"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		if obj.Leases == nil {
			return nil, true
		}
		return *obj.Leases, true
	}
	return nil, false
}

// DoneObs is what a non-settle step returned (6.2) with its status.
type DoneObs struct {
	Status int     `json:"status"`
	Text   *string `json:"text"`
	Stderr string  `json:"stderr"`
	Lease  *string `json:"lease"`
}

func parseObservation(data []byte) (*Observation, error) {
	o := &Observation{}
	if err := json.Unmarshal(data, o); err != nil {
		return nil, fmt.Errorf("invalid observation: %w", err)
	}
	return o, nil
}

// parseDone parses the JSON of a done line.
func parseDone(status int, data []byte) (*DoneObs, error) {
	d := &DoneObs{}
	data = bytes.TrimSpace(data)
	if len(data) > 0 {
		if err := json.Unmarshal(data, d); err != nil {
			return nil, fmt.Errorf("invalid done JSON: %w", err)
		}
	}
	d.Status = status
	return d, nil
}

// parseObservedFile parses the file of `check --observed`: a settle
// observation (JSON or an "observe N JSON" line) or a done observation
// (a "done N STATUS JSON" line, or JSON with "status").
func parseObservedFile(data []byte) (*Observation, *DoneObs, error) {
	data = bytes.TrimSpace(data)
	switch {
	case bytes.HasPrefix(data, []byte("observe ")):
		f := strings.SplitN(string(data), " ", 3)
		if len(f) < 3 {
			return nil, nil, fmt.Errorf("invalid observe line")
		}
		o, err := parseObservation([]byte(f[2]))
		return o, nil, err
	case bytes.HasPrefix(data, []byte("done ")):
		f := strings.SplitN(string(data), " ", 4)
		if len(f) < 3 {
			return nil, nil, fmt.Errorf("invalid done line")
		}
		st, err := strconv.Atoi(f[2])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid done status %q", f[2])
		}
		js := ""
		if len(f) == 4 {
			js = f[3]
		}
		d, err := parseDone(st, []byte(js))
		return nil, d, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, nil, fmt.Errorf("invalid observation: %w", err)
	}
	if _, ok := probe["pods"]; ok {
		o, err := parseObservation(data)
		return o, nil, err
	}
	if _, ok := probe["vms"]; ok {
		o, err := parseObservation(data)
		return o, nil, err
	}
	d := &DoneObs{}
	if err := json.Unmarshal(data, d); err != nil {
		return nil, nil, fmt.Errorf("invalid done observation: %w", err)
	}
	return nil, d, nil
}

// parseNodeList parses a cpuset list ("0-1,3").
func parseNodeList(s string) (map[int]bool, error) {
	nodes := map[int]bool{}
	s = strings.TrimSpace(s)
	if s == "" {
		return nodes, nil
	}
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("invalid node list %q", s)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return nil, fmt.Errorf("invalid node list %q", s)
			}
		}
		for n := a; n <= b; n++ {
			nodes[n] = true
		}
	}
	return nodes, nil
}
