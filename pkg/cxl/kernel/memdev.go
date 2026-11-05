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

package kernel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Memdev: a CXL memory device memN (/sys/bus/cxl/devices/memN).
//
// Identity: the PCIe serial number. The name memN changes with the probe
// order and hot-plug: it is resolved from the serial at every call.
// Facts: RAM and persistent capacity, the CPU NUMA affinity, the ports from
// the CXL root to its endpoint, its device numbers.
// States (MemdevState): ABSENT (no memN has the serial), UNBOUND (no driver:
// its probe is running, cxl disable-memdev ran, or the probe was refused),
// BOUND (cxl_mem bound, no endpoint port yet), READY (bound with its
// endpoint port: regions can be created). Transitions: MemdevTransitions.
// Invariants: a READY memdev has exactly one endpoint whose uport is it.
// Waits: WaitMemdev polls until the memdev reaches a state.

// MemdevState is the state of a memdev.
type MemdevState int

const (
	// MemdevAbsent: no memdev has the serial.
	MemdevAbsent MemdevState = iota
	// MemdevUnbound: the memdev has no driver.
	MemdevUnbound
	// MemdevBound: cxl_mem is bound, the endpoint port is missing.
	MemdevBound
	// MemdevReady: cxl_mem is bound and the endpoint port exists.
	MemdevReady
)

var memdevStateNames = []string{"ABSENT", "UNBOUND", "BOUND", "READY"}

func (s MemdevState) String() string { return stateText(memdevStateNames, int(s)) }

// MarshalText returns the name of the state.
func (s MemdevState) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText sets the state of its name.
func (s *MemdevState) UnmarshalText(text []byte) error {
	v, err := parseState(memdevStateNames, text)
	*s = MemdevState(v)
	return err
}

// MemdevTransitions are the changes of the state of a memdev.
var MemdevTransitions = Table[MemdevState]{
	Object:   "MemdevInfo",
	Field:    "State",
	Observed: true,
	States:   list(MemdevAbsent, MemdevUnbound, MemdevBound, MemdevReady),
	Rows: []Transition[MemdevState]{
		{From: list(MemdevAbsent), To: MemdevUnbound, When: "hot-add (the pool attaches the device), boot",
			Effects: "the probe of cxl_mem starts"},
		{From: list(MemdevAbsent), To: MemdevBound, When: "hot-add, observed after the probe bound cxl_mem"},
		{From: list(MemdevAbsent), To: MemdevReady, When: "hot-add, observed after the probe finished"},
		{From: list(MemdevUnbound), To: MemdevBound, When: "EnableMemdev, the probe of cxl_mem",
			Effects: "the endpoint port is added asynchronously (add_dev() fails until then)"},
		{From: list(MemdevUnbound), To: MemdevReady, When: "EnableMemdev, observed after the probe finished"},
		{From: list(MemdevBound), To: MemdevReady, When: "the endpoint port added", Effects: "regions can be created"},
		{From: list(MemdevBound), To: MemdevUnbound, When: "DisableMemdev"},
		{From: list(MemdevReady), To: MemdevUnbound, When: "DisableMemdev",
			Guard: "no committed decoder of its endpoint", Effects: "the endpoint port goes"},
		{From: list(MemdevUnbound), To: MemdevAbsent, When: "hot-remove (the pool detaches the device)"},
		{From: list(MemdevBound), To: MemdevAbsent, When: "hot-remove"},
		{From: list(MemdevReady), To: MemdevAbsent, When: "hot-remove",
			Effects: "its regions become hollow"},
	},
}

// MemdevInfo is the observation of a memdev.
type MemdevInfo struct {
	// Name is memN, "" when the memdev is absent.
	Name   string      `json:"name,omitempty"`
	Serial uint64      `json:"serial"`
	State  MemdevState `json:"state"`
	// RamSize and PmemSize are the volatile and the persistent capacity
	// in bytes.
	RamSize  uint64 `json:"ramSize,omitempty"`
	PmemSize uint64 `json:"pmemSize,omitempty"`
	// NodeAffinity is the NUMA node of the CPUs near the memdev, -1 if not
	// known.
	NodeAffinity int `json:"nodeAffinity"`
	// Major and Minor are the numbers of its character device.
	Major int `json:"major,omitempty"`
	Minor int `json:"minor,omitempty"`
	// Endpoint is its endpoint port (endpointN), "" when not READY.
	Endpoint string `json:"endpoint,omitempty"`
	// Ports are the ports of its decoder path from the CXL root: portN
	// (host bridge, switches), and its endpoint port last.
	Ports []string `json:"ports,omitempty"`
	// Regions are the regions with a target decoder of its endpoint.
	Regions []string `json:"regions,omitempty"`
}

// memdevNames returns the names of the memdevs (memN) in natural order.
func (k *Kernel) memdevNames() []string {
	return k.listCXL("mem*")
}

// memdevSerial returns the serial of the memdev.
func (k *Kernel) memdevSerial(name string) (uint64, error) {
	s, err := ReadTrim(k.cxlDev(name, "serial"))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
}

// FindMemdev returns the name memN of the memdev with the serial, an error
// of kind ErrNotFound if there is none.
func (k *Kernel) FindMemdev(serial uint64) (string, error) {
	for _, name := range k.memdevNames() {
		if v, err := k.memdevSerial(name); err == nil && v == serial {
			return name, nil
		}
	}
	return "", errorf(ErrNotFound, "no CXL memory device with the serial 0x%x", serial)
}

// Memdev returns the observation of the memdev with the serial, in state
// MemdevAbsent if there is none.
func (k *Kernel) Memdev(serial uint64) MemdevInfo {
	name, err := k.FindMemdev(serial)
	if err != nil {
		return MemdevInfo{Serial: serial, State: MemdevAbsent, NodeAffinity: -1}
	}
	m, err := k.memdev(name, k.endpoints())
	if err != nil {
		return MemdevInfo{Serial: serial, State: MemdevAbsent, NodeAffinity: -1}
	}
	return m
}

// Memdevs returns the memdevs that are present, in natural order of their
// names.
func (k *Kernel) Memdevs() []MemdevInfo {
	endpoints := k.endpoints()
	var out []MemdevInfo
	for _, name := range k.memdevNames() {
		if m, err := k.memdev(name, endpoints); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// memdev returns the observation of the memdev name; endpoints maps memdev
// names to their endpoints.
func (k *Kernel) memdev(name string, endpoints map[string]string) (MemdevInfo, error) {
	serial, err := k.memdevSerial(name)
	if err != nil {
		return MemdevInfo{}, fmt.Errorf("%s: serial: %w", name, err)
	}
	m := MemdevInfo{Name: name, Serial: serial, State: MemdevUnbound, NodeAffinity: readInt(k.cxlDev(name, "numa_node"), -1)}
	m.RamSize, _ = ReadUint(k.cxlDev(name, "ram", "size"))
	m.PmemSize, _ = ReadUint(k.cxlDev(name, "pmem", "size"))
	if v, err := ReadTrim(k.cxlDev(name, "dev")); err == nil {
		m.Major, m.Minor, _ = parseDevNumbers(name, v)
	}
	if !hasDriver(k.cxlDev(name)) {
		return m, nil
	}
	m.State = MemdevBound
	if ep := endpoints[name]; ep != "" {
		m.State = MemdevReady
		m.Endpoint = ep
		for _, dir := range k.endpointPorts(ep) {
			m.Ports = append(m.Ports, filepath.Base(dir))
		}
		m.Regions = k.endpointRegions(ep)
	}
	return m, nil
}

// endpoints returns the endpoint port of each memdev that has one, by the
// memdev name: the uport of an endpoint links to its memdev.
func (k *Kernel) endpoints() map[string]string {
	out := map[string]string{}
	for _, ep := range k.listCXL("endpoint*") {
		if target, err := os.Readlink(k.cxlDev(ep, "uport")); err == nil {
			out[filepath.Base(target)] = ep
		}
	}
	return out
}

// endpoint returns the endpoint port (endpointN) of a memdev.
func (k *Kernel) endpoint(memdev string) (string, error) {
	if ep := k.endpoints()[memdev]; ep != "" {
		return ep, nil
	}
	return "", errorf(ErrEndpointNotReady, "no endpoint port for %s (is it enabled?)", memdev)
}

// Regions returns the regions that have a target decoder of the endpoint of
// the memdev, in natural order.
func (k *Kernel) Regions(memdev string) []string {
	ep, err := k.endpoint(memdev)
	if err != nil {
		return nil
	}
	return k.endpointRegions(ep)
}

// endpointRegions returns the regions with a target decoder of the
// endpoint.
func (k *Kernel) endpointRegions(ep string) []string {
	prefix := "decoder" + strings.TrimPrefix(ep, "endpoint") + "."
	var out []string
	for _, r := range k.listCXL("region*") {
		for _, t := range k.regionTargets(r) {
			if strings.HasPrefix(t, prefix) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// RamSize returns the RAM capacity of a memdev in bytes.
func (k *Kernel) RamSize(memdev string) (uint64, error) {
	return ReadUint(k.cxlDev(memdev, "ram", "size"))
}

// Persistent tells whether a memdev has persistent memory capacity.
func (k *Kernel) Persistent(memdev string) (bool, error) {
	size, err := ReadUint(k.cxlDev(memdev, "pmem", "size"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return size > 0, nil
}

var pciRootRe = regexp.MustCompile(`^(.*/pci([0-9a-f]{4}):([0-9a-f]{2}))/`)

// HostBridgeUID returns the uid of the host bridge of a memdev, as root
// decoders list it in target_list: N of the dportN of a CXL root port that
// links to the PCI root of the memdev, else the ACPI _UID of the PCI root
// (firmware_node/uid), else the bus number of the PCI root. The ACPI _UID
// equals the bus number with qemu pxb-cxl (bus_nr) but not on real
// hardware, where host bridge pci0000:63 can have the uid 35.
func (k *Kernel) HostBridgeUID(memdev string) (int, error) {
	real, err := filepath.EvalSymlinks(k.cxlDev(memdev))
	if err != nil {
		return 0, err
	}
	m := pciRootRe.FindStringSubmatch(real + "/")
	if m == nil {
		return 0, fmt.Errorf("cannot find the PCI root of %s in %s", memdev, real)
	}
	pciRoot := m[1]
	dports, _ := filepath.Glob(k.cxlDev("root*", "dport*"))
	for _, dport := range dports {
		target, err := filepath.EvalSymlinks(dport)
		if err != nil || target != pciRoot {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(dport), "dport")); err == nil {
			return v, nil
		}
	}
	if s, err := ReadTrim(filepath.Join(pciRoot, "firmware_node", "uid")); err == nil {
		if v, err := strconv.Atoi(s); err == nil {
			return v, nil
		}
	}
	v, _ := strconv.ParseInt(m[3], 16, 32)
	return int(v), nil
}

// EnableMemdev binds cxl_mem to a memdev without a driver (cxl
// enable-memdev). A memdev with a driver is left as it is. Its endpoint
// port appears asynchronously (WaitMemdev).
func (k *Kernel) EnableMemdev(ctx context.Context, memdev string) error {
	if hasDriver(k.cxlDev(memdev)) {
		return nil
	}
	if _, err := k.exec(ctx, "cxl", "enable-memdev", memdev); err != nil {
		return err
	}
	k.logf("%s: enabled", memdev)
	return nil
}

// DisableMemdev unbinds cxl_mem from a memdev (cxl disable-memdev), so that
// the pool can detach it. A memdev without a driver, or one that does not
// exist, is left as it is.
func (k *Kernel) DisableMemdev(ctx context.Context, memdev string) error {
	if !exists(k.cxlDev(memdev)) || !hasDriver(k.cxlDev(memdev)) {
		return nil
	}
	if _, err := k.exec(ctx, "cxl", "disable-memdev", memdev); err != nil {
		return err
	}
	k.logf("%s: disabled", memdev)
	return nil
}

// WaitMemdev waits until the memdev with the serial is in state want or a
// later one (MemdevUnbound < MemdevBound < MemdevReady) and returns its
// name.
func (k *Kernel) WaitMemdev(ctx context.Context, serial uint64, want MemdevState) (string, error) {
	var got MemdevInfo
	err := k.poll(ctx, func() (bool, error) {
		got = k.Memdev(serial)
		return got.State >= want, nil
	})
	if err != nil {
		return "", fmt.Errorf("timeout waiting for CXL memory device with serial 0x%x: %w", serial, err)
	}
	return got.Name, nil
}
