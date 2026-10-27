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

// A simulated SUT for the protocol tests and the experiments: it keeps
// its own model state as "the truth", decides what the model leaves
// open (the node of an "any" slot, the outcome of a controller kill,
// steering in a restart window) at random, keeps the bytes of the
// devices, and answers with the observations that the contract
// describes. Settles can first return transient observations (pods not
// Running yet, attachments in flux), and deviations can be injected.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"strings"
)

type sim struct {
	cfg       *Config
	truth     *State
	rng       *rand.Rand
	phys      [nDevs]string
	inspected map[string]bool
	leaseSeq  int
	// transient polls before the stable observation of a settle
	transient int
	// deviate changes a stable settle observation (fault injection)
	deviate func(step int, o *Observation)
	// deviateDone changes a done observation
	deviateDone func(step int, a Act, d *DoneObs)
	// what the run went through
	sawEnd, sawFail string
	failStep        int
	prev            *State
	// ref, if set, is the independent reference of the pool side
	// (refpool.go): it decides the pool facts of every observation, and
	// which outcome of the model's a settle has (simref.go)
	ref *refPool
	// pend is the prediction of the settle being observed (ref only)
	pend *State
}

func newSim(cfg *Config, seed int64) *sim {
	s := &sim{cfg: cfg, truth: newState(cfg), rng: rand.New(rand.NewSource(seed)), inspected: map[string]bool{}}
	for d := range s.phys {
		s.phys[d] = fmt.Sprintf("junk-%d", s.rng.Intn(1000))
	}
	return s
}

// do applies an action to the truth and returns the done observation
// (nil for settle).
func (s *sim) do(step int, a Act) *DoneObs {
	from := s.truth
	if a.Verb == VSettle {
		s.prev = from
		if s.ref != nil {
			// resolved against the reference at every poll
			s.pend = from.apply(a)
			s.truth = s.resolveRef(s.pend)
			return nil
		}
		s.truth = s.resolve(from.apply(a))
		return nil
	}
	if s.ref != nil {
		s.ref.do(a, freesClaim(from, a))
	}
	to := from.apply(a)
	d := &DoneObs{}
	switch a.Verb {
	case VWrite:
		if to.slot(int(a.Slot)).Kind == KSRo {
			d.Status = 1
			d.Stderr = "PermissionError: [Errno 13] Permission denied"
		}
	case VRead:
		t := from.token(int(a.Slot))
		txt := t.Text
		if !t.Known {
			sl := from.slot(int(a.Slot))
			if sl.Kind == KLDax {
				txt = "" // a new slice is zeroed
			} else {
				txt = s.phys[sl.Dev]
			}
		}
		d.Text = &txt
		to = adoptDone(to, a, d)
	case VLeaseGet:
		s.leaseSeq++
		id := fmt.Sprintf("L%04d", s.leaseSeq)
		d.Lease = &id
		to = adoptDone(to, a, d)
	}
	for dev := DevID(0); dev < nDevs; dev++ {
		switch {
		case to.Data[dev].Known:
			s.phys[dev] = to.Data[dev].Text
		case from.Data[dev].Known:
			s.phys[dev] = fmt.Sprintf("junk-%d", s.rng.Intn(1000))
		}
	}
	s.truth = to
	if s.deviateDone != nil {
		s.deviateDone(step, a, d)
	}
	return d
}

// resolve decides what a settled state leaves open, as an SUT would:
// one of the outcomes of its races, the node of any pods, the outcomes
// of controller kills, steering, the retries of unblocking pods.
func (s *sim) resolve(st *State) *State {
	if len(st.Alts) > 0 {
		if j := s.rng.Intn(len(st.Alts) + 1); j > 0 {
			st = st.Alts[j-1]
		}
	}
	n := st.clone()
	// The scheduler's hold of a device whose claim was deleted before
	// its pod was bound ends within 5 s of the delete (A19, bug-08):
	// here it lasts through the window after the settle that ended the
	// delete's window. Never longer: the oracle ends it at a settle at
	// least heldSeconds after that one, and a contender that the truth
	// stalls after the model's hold has ended would be a difference of
	// the simulator's (M8). The step of that settle is kept in HeldAt
	// (the oracle keeps its clock there).
	for d := DevID(0); d < nDevs; d++ {
		switch {
		case !n.held(Res(d)):
		case n.HeldAt[d] == 0:
			n.HeldAt[d] = int64(n.Steps)
		default:
			n.Held &^= 1 << uint(d)
			n.HeldAt[d] = 0
		}
	}
	for i := range n.Slots {
		ss := &n.Slots[i]
		if ss.Phase == Stalled && s.rng.Intn(2) == 0 {
			sl := n.slot(i)
			n.setUnblockAt(i, 0)
			if n.Ctrl[sl.Pool].Up {
				// bound: an "any" pod on a host of its pool, and its
				// Prepare makes its region there, unless a hole is in
				// the way (A9; as simref.go and the oracle's resolve)
				if ss.Node == VMAny {
					hosts := poolHosts[sl.Pool]
					ss.Node = hosts[s.rng.Intn(len(hosts))]
				}
				ss.Phase = Running
				if si, key, ok := n.userRegion(int16(i)); ok && !n.Stacks[si].contains(key) {
					if n.Stacks[si].hasHole() {
						ss.Phase = Blocked
					} else {
						n.Stacks[si].push(key)
					}
				}
			} else {
				ss.Phase = Attaching
			}
			continue
		}
		if ss.Phase == Unblocking && s.rng.Intn(2) == 0 {
			ss.Phase = Running
			n.setUnblockAt(i, 0)
			if si, key, ok := n.userRegion(int16(i)); ok && !n.Stacks[si].contains(key) {
				n.Stacks[si].push(key)
			}
		}
	}
	for i := range n.Slots {
		ss := &n.Slots[i]
		sl := n.slot(i)
		if ss.Node == VMAny && (ss.Phase == Running || ss.Phase == Either) {
			hosts := poolHosts[sl.Pool]
			ss.Node = hosts[s.rng.Intn(len(hosts))]
		}
		if ss.Phase == Either {
			c := &n.Ctrl[sl.Pool]
			d := int(sl.Dev) - 2*int(sl.Pool)
			if s.rng.Intn(2) == 0 {
				ss.Phase = Running
				c.Att[d][ss.Node] = TriYes
			} else {
				ss.Phase = Attaching
			}
		}
		if ss.Steer == SteerAny && ss.Phase == Running {
			if s.rng.Intn(2) == 0 {
				ss.Steer = SteerOn
			} else {
				ss.Steer = SteerOff
			}
		}
	}
	for p := Pool(0); p < nPools; p++ {
		c := &n.Ctrl[p]
		if c.Up {
			n.deriveAtt(p)
			continue
		}
		for d := 0; d < 2; d++ {
			for v := VM(0); v < nVMs; v++ {
				if c.Att[d][v] == TriMaybe {
					if s.rng.Intn(2) == 0 {
						c.Att[d][v] = TriNo
					} else {
						c.Att[d][v] = TriYes
					}
				}
			}
		}
	}
	for v := VM(0); v < nVMs; v++ {
		d := &n.Drv[v]
		if d.Pod == "" || d.PodBefore != "" {
			d.Pod = fmt.Sprintf("nri-dra-driver-cxl-%s-%d", v, d.PodGen)
			d.PodBefore = ""
		}
	}
	n.growFence()
	return n
}

// names of the simulated objects
func podName(sl *Slot, gen uint16) string {
	return fmt.Sprintf("mbt-%s-%s-%d-g%d", sl.KindName(), sl.VM, sl.Index, gen)
}
func podUID(sl *Slot, gen uint16) string   { return fmt.Sprintf("pod-%s-%d", sl.Label(), gen) }
func claimUID(sl *Slot, gen uint16) string { return fmt.Sprintf("c-%s-%d", sl.Label(), gen) }
func companionName(id string) string       { return "cxl-lease-" + strings.ToLower(id) }
func companionUID(id string) string        { return "comp-" + strings.ToLower(id) }

// observe returns the stable observation of the truth.
func (s *sim) observe(step, poll int) *Observation {
	st := s.truth
	cfg := s.cfg
	o := &Observation{
		Step: step, Poll: poll,
		Others:      []string{},
		Attachments: map[string][]ObsAttachment{},
		Drivers:     map[string]*ObsDriver{},
		Controllers: map[string]string{},
		VMs:         map[string]*ObsVM{},
		Inspect:     map[string]*ObsInspect{},
	}
	t := true
	f := false
	for i := range st.Slots {
		ss := &st.Slots[i]
		sl := st.slot(i)
		if ss.Phase == Absent {
			continue
		}
		p := ObsPod{Slot: sl.Name, Name: podName(sl, ss.Gen), UID: podUID(sl, ss.Gen), Gen: int(ss.Gen), Restarts: int(ss.Restarts)}
		switch ss.Phase {
		case Running:
			node := ss.Node.String()
			p.Node, p.Phase, p.Ready = &node, "Running", true
		case Pending, Unsched, Stalled:
			p.Phase, p.Unschedulable = "Pending", true
		case Attaching:
			p.Phase = "Pending"
		case Blocked, Unblocking:
			node := ss.Node.String()
			w := "ContainerCreating"
			p.Node, p.Phase, p.Waiting = &node, "Pending", &w
			si, _, _ := st.userRegion(int16(i))
			ev := ObsEvent{Reason: "FailedPrepareDynamicResources", Message: "Failed to prepare dynamic resources: prepare: cxl create-region: ... (" +
				blockedText + ": port2 has 3 committed decoders, decoder2.1 without a region below region3 of " + stackName(si) + ")"}
			// the newest event may be another one (a retry while the
			// driver was away): the text is in "events" (A12)
			p.Event = &ObsEvent{Reason: "FailedPrepareDynamicResources", Message: "rpc error: code = Unavailable"}
			p.Events = []ObsEvent{*p.Event, ev}
		}
		if sl.Kind.claimed() {
			held := ss.Phase == Running || ss.Phase == Attaching || ss.Phase == Blocked || ss.Phase == Unblocking
			c := &ObsClaim{Name: p.Name + "-c0", UID: claimUID(sl, ss.Gen), Allocated: held}
			if sl.Kind.pooled() && c.Allocated {
				c.Devices = []ObsClaimDevice{{Driver: "cxl-pool.nri.io", Pool: "pool-" + sl.Pool.String(), Device: devices[sl.Dev].Name}}
				if ss.Phase == Attaching {
					c.Attached = &f
				} else {
					c.Attached = &t
				}
			}
			p.Claim = c
		}
		o.Pods = append(o.Pods, p)
		if sl.Kind == KLease && ss.Lease == LeaseHeld {
			id := st.LeaseIDs[i]
			req := sl.Name
			o.Companions = append(o.Companions, ObsCompanion{Name: companionName(id), Node: sl.VM.String(), Phase: "Running", Lease: id, Requester: &req})
		}
		if ss.Phase == Running {
			key := podUID(sl, ss.Gen) + "/" + strconv.Itoa(int(ss.Restarts))
			if !s.inspected[key] {
				s.inspected[key] = true
				in := &ObsInspect{UID: p.UID, Restarts: int(ss.Restarts), Env: s.env(sl, ss)}
				if sl.Kind == KLease {
					var ls []ObsLease
					if ss.Lease == LeaseHeld {
						ls = append(ls, ObsLease{Lease: st.LeaseIDs[i], State: "Ready", Mode: ss.LeaseMode.String(), Source: "local"})
					}
					in.Leases, _ = json.Marshal(ls)
				}
				o.Inspect[sl.Name] = in
			}
		}
	}
	for p := Pool(0); p < nPools; p++ {
		c := &st.Ctrl[p]
		list := []ObsAttachment{}
		_, excl := st.desiredAtt(p)
		for d := 0; d < 2; d++ {
			for v := VM(0); v < nVMs; v++ {
				if c.Att[d][v] == TriYes {
					list = append(list, ObsAttachment{Device: devices[2*int(p)+d].Name, Host: v.String(), State: "attached",
						Exclusive: c.Up && excl[d][v], Owner: "k8s:resourceclaim/x"})
				}
			}
		}
		// the setup's local memdevs (pool-a: vm2, vm1; pool-b: vm0)
		switch p {
		case PoolA:
			list = append(list, ObsAttachment{Device: "vm2.memdev1", Host: "vm2", State: "attached", Owner: "e2e:dra-local-device"},
				ObsAttachment{Device: "vm1.memdev1", Host: "vm1", State: "attached", Owner: "e2e:dra-local-device"})
		case PoolB:
			list = append(list, ObsAttachment{Device: "vm0.memdev1", Host: "vm0", State: "attached", Owner: "e2e:dra-local-device"})
		}
		o.Attachments[p.String()] = list
		if c.Up {
			o.Controllers[p.String()] = "active"
		} else {
			o.Controllers[p.String()] = "failed"
		}
	}
	o.PoolSlices = map[string][]ObsPoolSlice{}
	for _, p := range cfg.poolsUsed() {
		list := []ObsPoolSlice{}
		if st.Ctrl[p].Slices == SlicesPresent {
			var nodes []string
			for _, v := range poolHosts[p] {
				nodes = append(nodes, v.String())
			}
			list = append(list, ObsPoolSlice{Name: "pool-" + p.String() + "-slice", Devices: json.RawMessage(`["pooled0","shared0"]`), Nodes: nodes})
		}
		o.PoolSlices[p.String()] = list
	}
	o.Slices = map[string][]ObsSliceDev{}
	for v := VM(0); v < nVMs; v++ {
		d := &st.Drv[v]
		o.Drivers[v.String()] = &ObsDriver{Pod: d.Pod, Ready: true, Restarts: int(d.Restarts)}
		o.VMs[v.String()] = s.observeVM(v)
		o.Slices[v.String()] = []ObsSliceDev{{Name: "memdev-c100e2e1", Serial: formatSerial(localSerial)}, {Name: "dram"}}
	}
	if s.ref != nil {
		s.refOverride(o)
	}
	return o
}

func (s *sim) env(sl *Slot, ss *SlotState) map[string]string {
	env := map[string]string{"PATH": "/usr/bin", "CXL_CLAIM_" + strings.ReplaceAll(claimUID(sl, ss.Gen), "-", "_") + "_0": "1"}
	if !sl.Kind.claimed() {
		delete(env, "CXL_CLAIM_"+strings.ReplaceAll(claimUID(sl, ss.Gen), "-", "_")+"_0")
	}
	for k, v := range envWant(s.cfg, sl) {
		if strings.HasSuffix(v, "*") {
			v = strings.TrimSuffix(v, "*") + "3.1"
		}
		env[k] = v
	}
	return env
}

func (s *sim) observeVM(v VM) *ObsVM {
	st := s.truth
	if s.ref != nil {
		// the pool memdevs are those that the reference attached
		st = st.clone()
		s.refAtts(st)
	}
	cfg := s.cfg
	ov := &ObsVM{
		BootID:  "boot-" + v.String(),
		Memdevs: []ObsMemdev{{Name: "mem1", Serial: formatSerial(localSerial), Size: uint64(cfg.LocalBlocks[v]) * blockSize}},
		Regions: []ObsRegion{},
		Nodes:   map[string]ObsNode{"0": {MemTotal: 4 << 30}, "1": {MemTotal: 4 << 30}},
		CDI:     map[string][]string{},
	}
	for p := Pool(0); p < nPools; p++ {
		for d := 0; d < 2; d++ {
			if st.Ctrl[p].Att[d][v] == TriYes {
				dev := devices[2*int(p)+d]
				ov.Memdevs = append(ov.Memdevs, ObsMemdev{Name: fmt.Sprintf("mem%d", 2+2*int(p)+d), Serial: formatSerial(dev.Serial), Size: dev.Size})
			}
		}
	}
	mem := map[int]uint64{}
	var poolMode [nDevs]int
	var prepared, pool, claimsCDI, poolCDI, leasesCDI []string
	localClaims := map[string]json.RawMessage{}
	kmem, ddax := "kmem", "device_dax"
	var localDax []ObsDax
	slice := func(uid string, numa bool) {
		localClaims[uid] = json.RawMessage(`[{"request":"c0","size":134217728}]`)
		if numa {
			localDax = append(localDax, ObsDax{Name: fmt.Sprintf("dax9.%d", len(localDax)+1), Size: blockSize, Driver: &kmem, Online: blockSize})
			mem[cfg.bridgeNode(HB0)] += blockSize
		} else {
			localDax = append(localDax, ObsDax{Name: fmt.Sprintf("dax9.%d", len(localDax)+1), Size: blockSize, Driver: &ddax})
		}
	}
	containers := []ObsContainer{}
	for i := range st.Slots {
		ss := &st.Slots[i]
		sl := st.slot(i)
		if sl.Kind == KLease && sl.VM == v && ss.Lease == LeaseHeld {
			id := st.LeaseIDs[i]
			prepared = append(prepared, companionUID(id))
			slice(companionUID(id), ss.LeaseMode == ModeNuma)
			containers = append(containers, ObsContainer{Ns: "mbt", Pod: companionName(id), Name: "pause", Mems: "0-1", MemsEffective: "0-1", MemoryHigh: "max"})
		}
		if ss.Phase != Running || ss.Node != v {
			continue
		}
		uid := claimUID(sl, ss.Gen)
		mems := map[int]bool{0: true, 1: true}
		switch {
		case sl.Kind.pooled():
			pool = append(pool, uid)
			poolCDI = append(poolCDI, "claim-"+uid+"-0")
			if sl.Kind == KXNuma {
				poolMode[sl.Dev] = 1
				mem[sl.numaNode(cfg)] += devices[sl.Dev].Size
				mems[sl.numaNode(cfg)] = true
			} else if poolMode[sl.Dev] == 0 {
				poolMode[sl.Dev] = 2
			}
		case sl.Kind.local():
			prepared = append(prepared, uid)
			claimsCDI = append(claimsCDI, "claim-"+uid+"-0")
			slice(uid, sl.Kind != KLDax)
			if sl.Kind.numa() {
				mems[sl.numaNode(cfg)] = true
			}
		case sl.Kind == KLease:
			prepared = append(prepared, uid)
			claimsCDI = append(claimsCDI, "claim-"+uid+"-0")
			leasesCDI = append(leasesCDI, "lease-"+uid)
			if ss.Lease == LeaseHeld && ss.LeaseMode == ModeNuma {
				mems[cfg.bridgeNode(HB0)] = true
			}
		}
		high := "max"
		if sl.Kind == KLSteer && ss.Steer == SteerOn {
			high = "134479872"
		}
		ms := nodeListString(mems)
		containers = append(containers, ObsContainer{Ns: "mbt", Pod: podName(sl, ss.Gen), Name: "main", ID: fmt.Sprintf("ctr-%s-%d-%d", sl.Label(), ss.Gen, ss.Restarts), Mems: ms, MemsEffective: ms, MemoryHigh: high})
	}
	for d := DevID(0); d < nDevs; d++ {
		if poolMode[d] == 0 {
			continue
		}
		dev := devices[d]
		node := cfg.bridgeNode(poolBridge[dev.Pool])
		r := ObsRegion{Name: fmt.Sprintf("region%d", 10+int(d)), Serials: []string{formatSerial(dev.Serial)}, Mode: "ram", Size: dev.Size, Node: &node}
		if poolMode[d] == 1 {
			r.Dax = []ObsDax{{Name: fmt.Sprintf("dax%d.0", 10+int(d)), Size: dev.Size, Driver: &kmem, Online: dev.Size}}
		} else {
			r.Dax = []ObsDax{{Name: fmt.Sprintf("dax%d.0", 10+int(d)), Size: dev.Size, Driver: &ddax}}
		}
		ov.Regions = append(ov.Regions, r)
	}
	ld := &ObsLocalDevices{BootID: ov.BootID, Devices: []ObsLocalDevice{}}
	if len(localDax) > 0 {
		node := cfg.bridgeNode(HB0)
		dax := append([]ObsDax{{Name: "dax9.0", Size: 0, Driver: &ddax}}, localDax...)
		ov.Regions = append(ov.Regions, ObsRegion{Name: "region9", Serials: []string{formatSerial(localSerial)}, Mode: "ram",
			Size: uint64(cfg.LocalBlocks[v]) * blockSize, Node: &node, Dax: dax})
		ld.Devices = append(ld.Devices, ObsLocalDevice{Serial: json.RawMessage(strconv.FormatUint(localSerial, 10)),
			SerialHex: "c100e2e1", Region: "region9", Claims: localClaims})
	}
	for _, n := range cfg.cxlNodes() {
		ov.Nodes[strconv.Itoa(n)] = ObsNode{MemTotal: mem[n]}
	}
	ov.State = &ObsDriverState{Prepared: prepared, Info: append([]string(nil), prepared...), Pool: pool, LocalDevices: ld, Leases: s.leaseStore(v)}
	ctr, yes := fmt.Sprintf("drv-%s-%d", v, st.Drv[v].Inc), true
	ov.DriverLog = &ObsDriverLog{Container: &ctr, LendsRestored: &yes, Sockets: &yes}
	ov.Missing = json.RawMessage("[]")
	for b := Bridge(0); b < nBridges; b++ {
		st := &st.Stacks[stackIndex(v, b)]
		hb := "hb" + string(rune('0'+b))
		port := ObsPort{Port: fmt.Sprintf("port%d", 2+int(b)), Kind: "hostbridge", HB: &hb, Committed: int(st.N), Decoders: []ObsDecoder{}}
		for x, k := range st.keys() {
			d := ObsDecoder{Name: fmt.Sprintf("decoder%d.%d", 2+int(b), x)}
			switch {
			case k == rkLocal:
				d.Region = "region9"
			case k != rkHole:
				d.Region = fmt.Sprintf("region%d", 10+int(k-1))
			}
			port.Decoders = append(port.Decoders, d)
		}
		ov.Ports = append(ov.Ports, port)
	}
	ov.CDI["/etc/cdi/cxl-claims.yaml"] = claimsCDI
	ov.CDI["/etc/cdi/cxl-pool.yaml"] = poolCDI
	ov.CDI["/etc/cdi/cxl-leases.yaml"] = leasesCDI
	ov.Containers = containers
	return ov
}

// leaseStore is the leases.json of a VM.
func (s *sim) leaseStore(v VM) json.RawMessage {
	st := s.truth
	type lease struct {
		ID    string `json:"id"`
		Mode  string `json:"mode"`
		State string `json:"state"`
		Node  int    `json:"node"`
		Pod   struct {
			Name string `json:"name"`
		} `json:"pod"`
	}
	store := struct {
		Claims map[string]any   `json:"claims"`
		Leases map[string]lease `json:"leases"`
	}{map[string]any{}, map[string]lease{}}
	for i := range st.Slots {
		ss := &st.Slots[i]
		sl := st.slot(i)
		if sl.Kind != KLease || sl.VM != v || ss.Phase != Running {
			continue
		}
		store.Claims[claimUID(sl, ss.Gen)] = map[string]string{"uid": claimUID(sl, ss.Gen)}
		if ss.Lease == LeaseHeld {
			l := lease{ID: st.LeaseIDs[i], Mode: ss.LeaseMode.String(), State: "Ready", Node: -1}
			if ss.LeaseMode == ModeNuma {
				l.Node = s.cfg.bridgeNode(HB0)
			}
			l.Pod.Name = podName(sl, ss.Gen)
			store.Leases[st.LeaseIDs[i]] = l
		}
	}
	js, _ := json.Marshal(store)
	return js
}

func nodeListString(nodes map[int]bool) string {
	var parts []string
	for n := 0; n < 16; n++ {
		if nodes[n] {
			parts = append(parts, strconv.Itoa(n))
		}
	}
	return strings.Join(parts, ",")
}

// transientObservation is a legitimate observation of the SUT on its
// way from the state before the settle to the truth: pods that were
// starting are Pending, crashed ones show the old restart count, deleted
// ones are still there being deleted, new attachments are attaching.
func (s *sim) transientObservation(step, poll int) *Observation {
	o := s.observe(step, poll)
	// keep the inspections for the stable observation
	for k := range o.Inspect {
		delete(s.inspected, o.Inspect[k].UID+"/"+strconv.Itoa(o.Inspect[k].Restarts))
	}
	o.Inspect = map[string]*ObsInspect{}
	prev := s.prev
	if prev == nil {
		return o
	}
	for i := range prev.Slots {
		ps := &prev.Slots[i]
		sl := prev.slot(i)
		switch ps.Phase {
		case Starting:
			for j := range o.Pods {
				if o.Pods[j].Slot == sl.Name && o.Pods[j].Phase == "Running" {
					w := "ContainerCreating"
					o.Pods[j].Phase, o.Pods[j].Ready, o.Pods[j].Waiting = "Pending", false, &w
				}
			}
		case Restarting:
			for j := range o.Pods {
				if o.Pods[j].Slot == sl.Name && o.Pods[j].Restarts > 0 {
					o.Pods[j].Restarts--
				}
			}
		case Deleting:
			p := ObsPod{Slot: sl.Name, Name: podName(sl, ps.Gen), UID: podUID(sl, ps.Gen), Gen: int(ps.Gen), Phase: "Running", Deleting: true, Restarts: int(ps.Restarts)}
			o.Pods = append(o.Pods, p)
		}
	}
	for p := Pool(0); p < nPools; p++ {
		for j := range o.Attachments[p.String()] {
			a := &o.Attachments[p.String()][j]
			if d, v, err := parseDevAt(a.Device + "@" + a.Host); err == nil {
				if prev.Ctrl[p].Up && prev.Ctrl[p].Att[int(d)-2*int(p)][v] != TriYes {
					a.State = "attaching"
				}
			}
		}
	}
	return o
}

// serve answers the protocol on in/out until "end" or "fail" (or EOF).
func (s *sim) serve(in io.Reader, out io.Writer) error {
	rd := bufio.NewReaderSize(in, 1<<20)
	readLine := func() (string, error) {
		line, err := rd.ReadString('\n')
		return strings.TrimRight(line, "\n"), err
	}
	for {
		line, err := readLine()
		if err != nil {
			return err
		}
		f := strings.SplitN(line, " ", 3)
		switch f[0] {
		case "end":
			s.sawEnd = line
			return nil
		case "fail":
			s.sawFail = line
			s.failStep, _ = strconv.Atoi(f[1])
			return nil
		case "step":
		default:
			return fmt.Errorf("sim: unexpected line %q", line)
		}
		n, _ := strconv.Atoi(f[1])
		a, err := parseAct(s.cfg, f[2])
		if err != nil {
			fmt.Fprintf(out, "done %d 2 {}\n", n)
		} else if a.Verb == VSettle {
			s.do(n, a)
			poll := 0
			for {
				poll++
				var o *Observation
				if s.ref != nil {
					s.refPoll(poll)
					o = s.observe(n, poll)
				} else if poll <= s.transient {
					o = s.transientObservation(n, poll)
				} else {
					o = s.observe(n, poll)
					if s.deviate != nil {
						s.deviate(n, o)
					}
				}
				js, _ := json.Marshal(o)
				fmt.Fprintf(out, "observe %d %s\n", n, js)
				ans, err := readLine()
				if err != nil {
					return err
				}
				af := strings.SplitN(ans, " ", 3)
				if af[0] == "wait" {
					continue
				}
				if af[0] == "fail" {
					s.sawFail = ans
					s.failStep, _ = strconv.Atoi(af[1])
					return nil
				}
				if af[0] != "ok" {
					return fmt.Errorf("sim: unexpected answer %q", ans)
				}
				break
			}
			continue
		} else {
			d := s.do(n, a)
			js, _ := json.Marshal(struct {
				Text   *string `json:"text"`
				Stderr string  `json:"stderr"`
				Lease  *string `json:"lease,omitempty"`
			}{d.Text, d.Stderr, d.Lease})
			fmt.Fprintf(out, "done %d %d %s\n", n, d.Status, js)
		}
		ans, err := readLine()
		if err != nil {
			return err
		}
		af := strings.SplitN(ans, " ", 3)
		switch af[0] {
		case "ok":
		case "fail":
			s.sawFail = ans
			s.failStep, _ = strconv.Atoi(af[1])
			return nil
		default:
			return fmt.Errorf("sim: unexpected answer %q", ans)
		}
	}
}
