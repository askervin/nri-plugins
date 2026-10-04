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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/pool"
)

const stateVersion = 1

// persistedState is the content of the state file.
type persistedState struct {
	Version     int                        `json:"version"`
	Saved       time.Time                  `json:"saved"`
	Devices     []persistedDevice          `json:"devices,omitempty"`
	Overrides   map[string]*deviceOverride `json:"overrides,omitempty"`
	Hosts       []persistedHost            `json:"hosts,omitempty"`
	Attachments []api.Attachment           `json:"attachments,omitempty"`
}

// persistedDevice is a device created over the API.
type persistedDevice struct {
	Name       string            `json:"name"`
	Serial     string            `json:"serial"`
	Size       int64             `json:"size"`
	Shared     bool              `json:"shared,omitempty"`
	Path       string            `json:"path"`
	Pool       string            `json:"pool"`
	Labels     map[string]string `json:"labels,omitempty"`
	Allocation *api.Allocation   `json:"allocation,omitempty"`
	Created    time.Time         `json:"created"`
}

// deviceOverride holds the persisted mutable fields of config and local
// devices. Config devices take shared and labels from the config (only the
// allocation and the serial assigned to a config device without one are
// persisted); local devices persist shared and labels after a PATCH.
type deviceOverride struct {
	Shared     *bool             `json:"shared,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Allocation *api.Allocation   `json:"allocation,omitempty"`
	Serial     string            `json:"serial,omitempty"`
}

func (o *deviceOverride) apply(d *device, patchable bool) {
	if patchable {
		if o.Shared != nil {
			d.Shared = *o.Shared
			d.patched = true
		}
		if o.Labels != nil {
			d.Labels = o.Labels
			d.patched = true
		}
	}
	if o.Allocation != nil {
		d.Allocation = o.Allocation
	}
}

type persistedHost struct {
	Name      string `json:"name"`
	UUID      string `json:"uuid,omitempty"`
	PID       int    `json:"pid,omitempty"`
	StartTime uint64 `json:"startTime,omitempty"`
	Counter   int    `json:"counter,omitempty"`
	// Unplugged are qemu device ids that got device_del (never adopted).
	Unplugged []string `json:"unplugged,omitempty"`
}

func (s *Server) configDevice(name string) *DeviceConfig {
	for i := range s.cfg.Devices {
		if s.cfg.Devices[i].Name == name {
			return &s.cfg.Devices[i]
		}
	}
	return nil
}

func (s *Server) persistenceEnabled() bool {
	return s.cfg.StateFile != "" && s.cfg.StateFile != "-"
}

// loadState restores dynamic devices, overrides, hosts and attachments.
// It returns the serials that config devices without a configured serial
// had (assigned by New after the dynamic devices took theirs). Devices are
// never dropped silently: problems are logged and the device is kept.
func (s *Server) loadState() (map[string]uint64, error) {
	staticSerials := map[string]uint64{}
	if !s.persistenceEnabled() {
		return staticSerials, nil
	}
	b, err := os.ReadFile(s.cfg.StateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return staticSerials, nil
		}
		return nil, fmt.Errorf("state file: %w", err)
	}
	var st persistedState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("state file %s: %w", s.cfg.StateFile, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pd := range st.Devices {
		if _, ok := s.devices[pd.Name]; ok {
			s.logf("state: device %s is also in the config, using the config", pd.Name)
			continue
		}
		sn, err := api.ParseSerial(pd.Serial)
		if err != nil {
			sn = s.serials.Next(pd.Name)
			s.logf("ERROR: state: device %s: %v; kept with the new serial 0x%x", pd.Name, err, sn)
		} else if err := s.serials.Use(sn, pd.Name); err != nil {
			s.logf("ERROR: state: device %s: %v; kept with the duplicate serial", pd.Name, err)
		}
		if p := s.pools[pd.Pool]; p == nil {
			s.logf("ERROR: state: device %s: pool %q is not in the config any more; device kept (detach and delete it)", pd.Name, pd.Pool)
		} else if err := p.Reserve(pd.Name, pd.Size); err != nil {
			s.logf("state: device %s: %v", pd.Name, err)
		}
		if err := pool.EnsureBackingFile(pd.Path, pd.Size); err != nil {
			s.logf("state: device %s: %v", pd.Name, err)
		}
		s.devices[pd.Name] = &device{
			Device: api.Device{
				Name:       pd.Name,
				Serial:     api.FormatSerial(sn),
				Size:       pd.Size,
				Shared:     pd.Shared,
				Backend:    api.BackendFile,
				Path:       pd.Path,
				Pool:       pd.Pool,
				Scope:      api.ScopePool,
				Labels:     pd.Labels,
				Allocation: pd.Allocation,
				Created:    pd.Created,
			},
			serial:   sn,
			dynamic:  true,
			bindings: map[string]*binding{},
		}
	}
	for name, ov := range st.Overrides {
		if d := s.devices[name]; d != nil {
			// config devices: the config wins for shared and labels
			ov.apply(d, !d.Static)
			if d.needSerial && ov.Serial != "" {
				if sn, err := api.ParseSerial(ov.Serial); err == nil {
					staticSerials[name] = sn
				}
			}
		} else {
			s.overrides[name] = ov
		}
	}
	for _, ph := range st.Hosts {
		unplugged := map[string]bool{}
		for _, id := range ph.Unplugged {
			unplugged[id] = true
		}
		s.hosts[ph.Name] = &host{
			unplugged: unplugged,
			name:      ph.Name,
			uuid:      ph.UUID,
			source:    api.SourceDiscovered,
			pid:       ph.PID,
			startTime: ph.StartTime,
			counter:   ph.Counter,
			state:     api.HostStopped,
			fromState: true,
		}
	}
	for _, a := range st.Attachments {
		if a.State == api.AttachmentAttaching {
			// interrupted attach: the tree decides at reconcile
			a.State = api.AttachmentAttached
		}
		s.atts[a.ID] = &attachment{Attachment: a}
	}
	s.logf("state: loaded %s: %d devices, %d hosts, %d attachments",
		s.cfg.StateFile, len(st.Devices), len(st.Hosts), len(st.Attachments))
	return staticSerials, nil
}

// saveStateLocked writes the state file atomically.
func (s *Server) saveStateLocked() {
	if !s.persistenceEnabled() {
		return
	}
	st := persistedState{Version: stateVersion, Saved: time.Now().UTC(), Overrides: map[string]*deviceOverride{}}
	for name, ov := range s.overrides {
		st.Overrides[name] = ov
	}
	for _, d := range sortedDevices(s.devices) {
		if d.dynamic {
			st.Devices = append(st.Devices, persistedDevice{
				Name: d.Name, Serial: d.Serial, Size: d.Size, Shared: d.Shared, Path: d.Path,
				Pool: d.Pool, Labels: d.Labels, Allocation: d.Allocation, Created: d.Created,
			})
			continue
		}
		ov := &deviceOverride{Allocation: d.Allocation}
		if d.Static {
			// the serial of a config device without one in the config
			if cd := s.configDevice(d.Name); cd != nil && cd.Serial == nil {
				ov.Serial = d.Serial
			}
		} else if d.patched {
			shared := d.Shared
			ov.Shared, ov.Labels = &shared, d.Labels
		}
		if ov.Allocation == nil && ov.Serial == "" && ov.Shared == nil {
			continue
		}
		st.Overrides[d.Name] = ov
	}
	for _, h := range sortedHosts(s.hosts) {
		ph := persistedHost{Name: h.name, UUID: h.uuid, PID: h.pid, StartTime: h.startTime, Counter: h.counter}
		for id := range h.unplugged {
			ph.Unplugged = append(ph.Unplugged, id)
		}
		sort.Strings(ph.Unplugged)
		st.Hosts = append(st.Hosts, ph)
	}
	for _, a := range sortedAttachments(s.atts) {
		st.Attachments = append(st.Attachments, a.Attachment)
	}
	b, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		s.logf("state: marshal: %v", err)
		return
	}
	dir := filepath.Dir(s.cfg.StateFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.logf("state: %v", err)
		return
	}
	tmp, err := os.CreateTemp(dir, ".fake-cxl-pool-state-*")
	if err != nil {
		s.logf("state: %v", err)
		return
	}
	_, werr := tmp.Write(append(b, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		s.logf("state: write %s: %v %v", tmp.Name(), werr, cerr)
		return
	}
	if err := os.Rename(tmp.Name(), s.cfg.StateFile); err != nil {
		os.Remove(tmp.Name())
		s.logf("state: %v", err)
	}
}
