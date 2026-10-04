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
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
)

// Process is a qemu process found from /proc, or parsed from a command line.
type Process struct {
	PID       int
	StartTime uint64 // /proc/PID/stat starttime: detects pid reuse/restarts
	Exe       string
	Args      []string
	Cwd       string
	// Name is the VM name: <name> of .vagrant/machines/<name>/ in a
	// -drive file path, else -name guest=<name>, else "".
	Name string
	// ProjectDir is the directory that contains .vagrant/ (the e2e test
	// output directory where monitor.sock and qmp.sock are created).
	ProjectDir string
	UUID       string
	// QMPSockets and HMPSockets are monitor socket paths in order of
	// preference, as given on the command line (maybe relative).
	QMPSockets  []string
	HMPSockets  []string
	Objects     []Object
	Devices     []DeviceArg
	HostBridges []CmdHostBridge
	FMWs        []FMW
}

// Object is a -object argument.
type Object struct {
	Type  string
	ID    string
	Props map[string]string
}

// DeviceArg is a -device argument.
type DeviceArg struct {
	Driver string
	ID     string
	Props  map[string]string
}

// CmdHostBridge is a pxb-cxl device of the command line.
type CmdHostBridge struct {
	ID       string
	BusNr    int
	NumaNode int // -1 if not given
}

// FMW is a CXL fixed memory window (-M cxl-fmw.N.*).
type FMW struct {
	Index   int
	Targets []string
	Size    int64
}

var vagrantMachineRe = regexp.MustCompile(`^(.*)/\.vagrant/machines/([^/]+)/`)

// options that take a value and that the parser looks at
var qemuValueOptions = map[string]bool{
	"drive": true, "qmp": true, "qmp-pretty": true, "monitor": true,
	"chardev": true, "mon": true, "object": true, "device": true,
	"M": true, "machine": true, "name": true, "uuid": true,
}

// ParseCmdline parses a qemu command line. Socket paths are not resolved.
func ParseCmdline(args []string) *Process {
	p := &Process{Args: args}
	if len(args) > 0 {
		p.Exe = args[0]
	}
	type chardev struct{ path string }
	chardevs := map[string]chardev{}
	type mon struct{ chardev, mode string }
	var mons []mon
	nameOpt := ""
	fmws := map[int]*FMW{}
	for i := 1; i < len(args); i++ {
		opt := strings.TrimLeft(args[i], "-")
		if !strings.HasPrefix(args[i], "-") || !qemuValueOptions[opt] || i+1 >= len(args) {
			continue
		}
		val := args[i+1]
		i++
		switch opt {
		case "drive":
			o := ParseOpts(val, "")
			if m := vagrantMachineRe.FindStringSubmatch(o.Get("file")); m != nil && p.Name == "" {
				p.ProjectDir, p.Name = m[1], m[2]
			}
		case "name":
			o := ParseOpts(val, "guest")
			nameOpt = o.First
		case "uuid":
			p.UUID = strings.ToLower(strings.TrimSpace(val))
		case "qmp", "qmp-pretty":
			if path, ok := unixSocketPath(val); ok {
				p.QMPSockets = append(p.QMPSockets, path)
			}
		case "monitor":
			if path, ok := unixSocketPath(val); ok {
				p.HMPSockets = append(p.HMPSockets, path)
			}
		case "chardev":
			o := ParseOpts(val, "backend")
			if o.First == "socket" && o.Get("path") != "" && isOn(o, "server") {
				chardevs[o.Get("id")] = chardev{path: o.Get("path")}
			}
		case "mon":
			o := ParseOpts(val, "chardev")
			cd := o.Get("chardev")
			if cd == "" {
				cd = o.First
			}
			mode := o.Get("mode")
			if mode == "" {
				mode = "readline"
			}
			mons = append(mons, mon{chardev: cd, mode: mode})
		case "object":
			o := ParseOpts(val, "qom-type")
			p.Objects = append(p.Objects, Object{Type: o.First, ID: o.Get("id"), Props: o.Props})
		case "device":
			o := ParseOpts(val, "driver")
			d := DeviceArg{Driver: o.First, ID: o.Get("id"), Props: o.Props}
			p.Devices = append(p.Devices, d)
			if d.Driver == "pxb-cxl" {
				hb := CmdHostBridge{ID: d.ID, NumaNode: -1, BusNr: -1}
				if v, err := strconv.Atoi(o.Get("numa_node")); err == nil {
					hb.NumaNode = numaOrUnknown(v)
				}
				if v, err := strconv.ParseInt(o.Get("bus_nr"), 0, 32); err == nil {
					hb.BusNr = int(v)
				}
				p.HostBridges = append(p.HostBridges, hb)
			}
		case "M", "machine":
			o := ParseOpts(val, "type")
			for _, k := range o.Keys {
				parseFMWKey(fmws, k, o.Props[k])
			}
		}
	}
	for _, m := range mons {
		cd, ok := chardevs[m.chardev]
		if !ok {
			continue
		}
		if m.mode == "control" {
			p.QMPSockets = append(p.QMPSockets, cd.path)
		} else {
			p.HMPSockets = append(p.HMPSockets, cd.path)
		}
	}
	if p.Name == "" {
		p.Name = nameOpt
	}
	idx := make([]int, 0, len(fmws))
	for i := range fmws {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		p.FMWs = append(p.FMWs, *fmws[i])
	}
	return p
}

func isOn(o *Opts, key string) bool {
	if !o.Has(key) {
		return false
	}
	switch o.Get(key) {
	case "", "on", "yes", "true":
		return true
	}
	return false
}

// unixSocketPath returns the path of "unix:PATH[,opts]" if it is a server.
func unixSocketPath(val string) (string, bool) {
	rest, ok := strings.CutPrefix(val, "unix:")
	if !ok {
		return "", false
	}
	o := ParseOpts(rest, "path")
	if o.First == "" {
		return "", false
	}
	if o.Has("server") && !isOn(o, "server") {
		return "", false
	}
	return o.First, true
}

// parseFMWKey parses cxl-fmw.N.targets.M=X and cxl-fmw.N.size=S.
func parseFMWKey(fmws map[int]*FMW, key, val string) {
	rest, ok := strings.CutPrefix(key, "cxl-fmw.")
	if !ok {
		return
	}
	parts := strings.Split(rest, ".")
	n, err := strconv.Atoi(parts[0])
	if err != nil || len(parts) < 2 {
		return
	}
	f := fmws[n]
	if f == nil {
		f = &FMW{Index: n}
		fmws[n] = f
	}
	switch parts[1] {
	case "targets":
		f.Targets = append(f.Targets, val)
	case "size":
		if v, err := api.ParseSize(val); err == nil {
			f.Size = v
		}
	}
}

// ResolvePath resolves a socket path of the command line. Relative paths
// are relative to the cwd of qemu when it started; a daemonized qemu has
// cwd "/" by now, so the vagrant project dir is tried, too. The first
// candidate for which exists returns true is returned, else the most
// likely candidate.
func (p *Process) ResolvePath(path string, exists func(string) bool) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	var cands []string
	if p.Cwd != "" && p.Cwd != "/" {
		cands = append(cands, filepath.Join(p.Cwd, path))
	}
	if p.ProjectDir != "" {
		cands = append(cands, filepath.Join(p.ProjectDir, path))
	}
	if p.Cwd == "/" {
		cands = append(cands, filepath.Join("/", path))
	}
	for _, c := range cands {
		if exists != nil && exists(c) {
			return c
		}
	}
	if len(cands) > 0 {
		return cands[0]
	}
	return path
}

// IsSocket returns true if path is a unix socket.
func IsSocket(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// HostBridgeNuma returns the NUMA node of a host bridge, -1 if unknown.
func (p *Process) HostBridgeNuma(id string) int {
	for _, hb := range p.HostBridges {
		if hb.ID == id {
			return hb.NumaNode
		}
	}
	return -1
}

// FMWSize returns the capacity of the fixed memory windows that target
// the host bridge. A window interleaved over several host bridges counts
// with an equal share for each.
func (p *Process) FMWSize(hb string) int64 {
	var total int64
	for _, f := range p.FMWs {
		for _, t := range f.Targets {
			if t == hb {
				total += f.Size / int64(len(f.Targets))
				break
			}
		}
	}
	return total
}

// LocalBackend is a memory backend object pre-declared on the qemu command
// line for a CXL memory device (test/e2e/lib/topology2qemuopts.py naming:
// beram_<memdev>__bus_<bus>__sn_<serial> or befile_...).
type LocalBackend struct {
	ObjectID  string
	QomType   string
	Memdev    string // e.g. cxl_memdev3
	Bus       string
	Serial    uint64
	HasSerial bool
	Size      int64
	MemPath   string
	Share     bool
}

var localBackendRe = regexp.MustCompile(`^(beram|befile)_(.+?)__bus_(.+?)__sn_(.+)$`)

// ParseLocalBackendID parses a beram_/befile_ object id.
func ParseLocalBackendID(id string) (LocalBackend, bool) {
	m := localBackendRe.FindStringSubmatch(id)
	if m == nil {
		return LocalBackend{}, false
	}
	lb := LocalBackend{ObjectID: id, Memdev: m[2], Bus: m[3]}
	if sn, err := api.ParseSerial(m[4]); err == nil {
		lb.Serial, lb.HasSerial = sn, true
	}
	if m[1] == "befile" {
		lb.QomType = MemoryBackendFile
	} else {
		lb.QomType = MemoryBackendRAM
	}
	return lb, true
}

// LocalBackends returns the pre-declared CXL memory backends.
func (p *Process) LocalBackends() []LocalBackend {
	var out []LocalBackend
	for _, o := range p.Objects {
		lb, ok := ParseLocalBackendID(o.ID)
		if !ok {
			continue
		}
		if o.Type != "" {
			lb.QomType = o.Type
		}
		if v, err := api.ParseSize(o.Props["size"]); err == nil {
			lb.Size = v
		}
		lb.MemPath = o.Props["mem-path"]
		lb.Share = o.Props["share"] == "on" || o.Props["share"] == "true"
		out = append(out, lb)
	}
	return out
}

// Discover scans procRoot (normally "/proc") for qemu-system-* processes.
func Discover(procRoot string) ([]*Process, error) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	var out []*Process
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		if !strings.HasPrefix(filepath.Base(args[0]), "qemu-system-") {
			continue
		}
		p := ParseCmdline(args)
		p.PID = pid
		p.Cwd, _ = os.Readlink(filepath.Join(dir, "cwd"))
		p.StartTime = readStartTime(filepath.Join(dir, "stat"))
		for i, s := range p.QMPSockets {
			p.QMPSockets[i] = p.ResolvePath(s, IsSocket)
		}
		for i, s := range p.HMPSockets {
			p.HMPSockets[i] = p.ResolvePath(s, IsSocket)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

func readStartTime(statPath string) uint64 {
	b, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(b[i+1:]))
	// fields after comm: state(3) ... starttime is field 22 overall
	if len(f) < 20 {
		return 0
	}
	v, _ := strconv.ParseUint(f[19], 10, 64)
	return v
}

// ProcessAlive returns true if the process exists and has the start time.
func ProcessAlive(procRoot string, pid int, startTime uint64) bool {
	if pid <= 0 {
		return false
	}
	st := readStartTime(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if st == 0 {
		return false
	}
	return startTime == 0 || st == startTime
}
