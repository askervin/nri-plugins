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

// refPool is an independent reference of the pool side of the SUT, for
// the simulated SUT (sim.go): the pool controllers, the pool servers'
// attachments, kube-scheduler's allocation of pool claims with binding
// conditions and the resourceclaim controller. It is written from
// contract A18/A19, plan-13-gofmbt/08-analysis-claim-after-pod-deleted.txt
// and the controller's code (scripts/testing/fake-cxl-pool/pkg/controller:
// Run, sync, publish, reconcile, attach, writeStatus, detach, shutdown),
// NOT from the model's prediction functions: it knows the static
// topology (slots, devices, pool hosts) and nothing of the model's
// phases, alternatives or rules. It runs on a virtual clock (ms) with
// random but plausible durations, so that the races the model leaves
// open are decided by timing, as in the cluster.
//
// What it models:
//   - controller: a start (ctrl-start, the start half of ctrl-restart)
//     syncs its informers (0.3-1.5 s), then every sync publishes the
//     pool's ResourceSlice if it is not there (written 0.1-0.8 s later;
//     unchanged content is no API write) and reconciles. A graceful stop
//     (ctrl-restart) deletes the slices; SIGKILL (ctrl-kill) keeps them
//     and loses a publish that was not written yet.
//   - reconcile: desired = (device, node) of every allocated claim of
//     the pool; attach the missing ones (an exclusive device, or the
//     shared device attached exclusively, waits for its detach from
//     another host), set the exclusive flag of existing ones, write
//     Attached into claims whose attachment is attached, detach the
//     undesired attached ones. Triggered by claim changes and server
//     events (debounce 0.5 s), every 10 s otherwise; only while the
//     controller runs and its server answers.
//   - server: an attach or detach completes 0.3-2 s after its request,
//     also when the controller is killed meanwhile (then no Attached is
//     written until the next incarnation reconciles). server-restart
//     makes it unreachable for 3-6.5 s.
//   - scheduler: a pending pool pod is attempted shortly after its
//     creation and after every requeueing event (a claim deallocated, a
//     ResourceSlice added: the pool's publish, kubelet and driver
//     restarts sometimes), else at the unschedulable flush (5:00-5:30
//     after its last attempt). An attempt needs the pool's slices and a
//     free device: exclusive devices and sexcl conflict with every other
//     allocation of the device, shares only with sexcl; in-flight
//     allocations count. PreBind polls every 5 s from the allocation:
//     the pod binds once its claim is Attached; it fails on AttachFailed
//     (the controller's attach conflicts with an attachment of the
//     device on another host that a claim still wants, e.g. one being
//     detached after an exclusive use) and after 600 s (binding
//     timeout): the claim is deallocated, the pod tried again.
//   - delete: a bound pod is gone after kubelet's termination (0.6-2.6
//     s), then its claim is deallocated (a requeueing event). An unbound
//     pod is gone at once, its claim deallocated 0.1-0.35 s later (a
//     requeueing event that comes while the deleted claim is still in
//     flight in the scheduler: the HOLD of A19), and the scheduler drops
//     the in-flight allocation at the next PreBind poll after the claim
//     is deleted, without an event (bug-08).
// What it does not model: the node side (Prepare, regions, decoder
// stacks, fencing), which the simulated SUT takes from the model.

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync/atomic"
)

// Durations of the reference (ms of its virtual clock).
const (
	refPollPeriod     = 5000   // PreBind's poll of the binding conditions
	refBindingTimeout = 600000 // DynamicResources bindingTimeout
	refFlushAfter     = 300000 // DefaultPodMaxInUnschedulablePodsDuration
	refFlushPeriod    = 30000  // flushUnschedulableEntitiesLeftover
	refSyncInterval   = 10000  // controller DefaultSyncInterval
	refDebounce       = 500    // controller DefaultDebounce
)

// refPhase is what the reference says of the pod of a pool slot.
type refPhase uint8

const (
	rpNone    refPhase = iota // no pod
	rpUnalloc                 // Pending, its claim not allocated
	rpAlloc                   // allocated, PreBind waits for Attached
	rpBound                   // bound to its node
)

var refPhaseNames = []string{"none", "unallocated", "allocated", "bound"}

func (p refPhase) String() string { return refPhaseNames[p] }

type refPod struct {
	slot    int
	gen     uint16
	deleted bool  // a delete was issued
	goneAt  int64 // deleted: the pod object is gone then
	gone    bool
	// the claim's deallocation by the resourceclaim controller (deleted,
	// allocated); inflightTo: the PreBind poll that drops the scheduler's
	// in-flight allocation of a claim deleted before its pod was bound
	deallocAt  int64
	dealloced  bool
	inflight   bool
	inflightTo int64
	// scheduling
	alloc     bool
	node      VM
	allocAt   int64
	pollAt    int64 // the next PreBind poll (allocated, not bound)
	attached  bool  // the claim's Attached condition
	failed    bool  // the claim's AttachFailed condition (a binding failure)
	bound     bool
	attemptAt int64 // the next scheduling attempt (0: none)
	unsched   bool  // the last attempt failed (FailedScheduling)
	flushAt   int64
}

func (p *refPod) phase() refPhase {
	switch {
	case p == nil:
		return rpNone
	case p.bound:
		return rpBound
	case p.alloc:
		return rpAlloc
	}
	return rpUnalloc
}

type refAtt struct {
	dev    DevID
	host   VM
	state  string // attaching, attached, detaching
	excl   bool
	doneAt int64
	inc    int // the controller incarnation that waits for the attach
}

type refCtrl struct {
	running    bool
	inc        int
	readyAt    int64 // the first sync of the incarnation
	syncAt     int64 // the next reconcile (0: none)
	publishAt  int64 // the slices are written then (0: nothing pending)
	slices     bool
	serverUpAt int64 // the pool server answers again (server-restart)
}

type refPool struct {
	cfg      *Config
	rng      *rand.Rand
	now      int64
	clock    atomic.Int64 // now, for readers on other goroutines
	ctrl     [nPools]refCtrl
	pods     []*refPod // the live pod of every slot (pool kinds), nil if none
	old      []*refPod // deleted pods until gone and their claims released
	gens     []uint16
	atts     []*refAtt
	requeues []int64 // pending requeueing events
	hist     []string
	// Count counts what happened, by event
	Count map[string]int
	// Anomalies are situations the reference does not model: never
	// expected (none are detected at the moment)
	Anomalies []string
}

func newRefPool(cfg *Config, seed int64) *refPool {
	r := &refPool{cfg: cfg, rng: rand.New(rand.NewSource(seed)), pods: make([]*refPod, len(cfg.Slots)), gens: make([]uint16, len(cfg.Slots)), Count: map[string]int{}}
	for p := range r.ctrl {
		r.ctrl[p] = refCtrl{running: true, slices: true, syncAt: refSyncInterval}
	}
	return r
}

func (r *refPool) rnd(lo, hi int64) int64 { return lo + r.rng.Int63n(hi-lo+1) }

func (r *refPool) logf(format string, args ...any) {
	r.hist = append(r.hist, fmt.Sprintf("%8.1fs ", float64(r.now)/1000)+fmt.Sprintf(format, args...))
	if len(r.hist) > 80 {
		r.hist = r.hist[len(r.hist)-80:]
	}
}

// History is the recent log of the reference.
func (r *refPool) History() []string { return append([]string(nil), r.hist...) }

func (r *refPool) setNow(t int64) {
	r.now = t
	r.clock.Store(t)
}

// Now is the virtual clock in ms.
func (r *refPool) Now() int64 { return r.clock.Load() }

func (r *refPool) slot(i int) *Slot { return &r.cfg.Slots[i] }

// do applies a non-settle action at the current time and advances the
// clock by the time the executor takes for it. freesClaim: a pod with an
// allocated claim that is not a pool claim was deleted (a requeueing
// event when its claim is deallocated).
func (r *refPool) do(a Act, freesClaim bool) {
	cost := int64(0)
	switch a.Verb {
	case VCreate:
		cost = r.rnd(300, 600)
		if r.slot(int(a.Slot)).Kind.pooled() {
			r.create(int(a.Slot))
		}
	case VDelete:
		cost = r.rnd(200, 450)
		if r.slot(int(a.Slot)).Kind.pooled() {
			r.delete(int(a.Slot))
		} else if freesClaim {
			r.requeueAt(r.now + r.rnd(700, 2900))
		}
	case VCrash:
		cost = r.rnd(100, 300)
	case VWrite, VRead:
		cost = r.rnd(300, 700)
	case VLeaseGet, VLeasePut:
		cost = r.rnd(300, 900)
	case VCtrlKill:
		cost = r.rnd(200, 400)
		c := &r.ctrl[a.Pool]
		c.running, c.publishAt, c.syncAt = false, 0, 0
		c.inc++
		r.logf("ctrl-kill %s (slices %v)", a.Pool, c.slices)
	case VCtrlStart:
		cost = r.rnd(500, 1000)
		r.start(a.Pool, r.now)
	case VCtrlRestart:
		cost = r.rnd(900, 1300)
		// systemctl stop: shutdown deletes the slices before the process
		// exits; systemctl start
		c := &r.ctrl[a.Pool]
		c.running, c.publishAt, c.syncAt, c.slices = false, 0, 0, false
		c.inc++
		r.logf("ctrl-restart %s: slices deleted", a.Pool)
		r.start(a.Pool, r.now+r.rnd(200, 500))
	case VServerRestart:
		c := &r.ctrl[a.Pool]
		c.serverUpAt = r.now + r.rnd(3000, 6500)
		cost = c.serverUpAt - r.now + r.rnd(50, 300)
		r.logf("server-restart %s: up at %.1fs", a.Pool, float64(c.serverUpAt)/1000)
	case VKubeletRestart:
		cost = r.rnd(800, 3000)
		// the node's slice is removed and published again (bug-06):
		// a ResourceSlice add, sometimes before the settle
		if r.rng.Intn(2) == 0 {
			r.requeueAt(r.now + r.rnd(1000, 3000))
		}
	case VDriverKill, VDriverRestart, VContainerdRestart:
		cost = r.rnd(300, 5000)
		if r.rng.Intn(3) == 0 {
			r.requeueAt(r.now + r.rnd(1000, 4000))
		}
	}
	r.advance(r.now + cost)
}

func (r *refPool) create(i int) {
	r.gens[i]++
	// its first attempt: its claim is made from the template and the
	// scheduler tries it within a fraction of the executor's next step
	// (no overtaking by the next create: the model's issue order)
	r.pods[i] = &refPod{slot: i, gen: r.gens[i], attemptAt: r.now + r.rnd(20, 150)}
	r.logf("create %s g%d", r.slot(i).Name, r.gens[i])
}

func (r *refPool) delete(i int) {
	p := r.pods[i]
	if p == nil {
		return
	}
	r.pods[i] = nil
	p.deleted = true
	switch {
	case p.bound:
		p.goneAt = r.now + r.rnd(600, 2600)
		p.deallocAt = p.goneAt + r.rnd(80, 300)
	case p.alloc:
		// not bound: PreBind waits for the binding conditions; the
		// deleted claim stays in flight until its next poll
		p.goneAt = r.now + r.rnd(20, 120)
		p.deallocAt = r.now + r.rnd(100, 350)
		p.inflight = true
		del := p.deallocAt + 50
		p.inflightTo = p.allocAt + refPollPeriod*((del-p.allocAt+refPollPeriod-1)/refPollPeriod)
	default:
		p.goneAt = r.now + r.rnd(20, 120)
	}
	r.old = append(r.old, p)
	r.logf("delete %s g%d (%s)", r.slot(i).Name, p.gen, p.phase())
}

// start starts a controller incarnation at t.
func (r *refPool) start(p Pool, t int64) {
	c := &r.ctrl[p]
	c.running = true
	c.inc++
	c.readyAt = t + r.rnd(300, 1500)
	c.syncAt = c.readyAt
	c.publishAt = 0
	r.logf("ctrl %s starts, first sync at %.1fs", p, float64(c.readyAt)/1000)
}

func (r *refPool) requeueAt(t int64) { r.requeues = append(r.requeues, t) }

// requeueAll: a requeueing event of the DynamicResources plugin: every
// unschedulable pool pod is tried again (backoff and queue: soon).
func (r *refPool) requeueAll(why string) {
	n := 0
	for _, p := range r.pods {
		if p != nil && p.unsched && p.attemptAt == 0 {
			p.attemptAt = r.now + r.rnd(0, 800)
			n++
		}
	}
	if n > 0 {
		r.logf("requeue %d pods: %s", n, why)
	}
}

// trigger asks the controller of a pool for a (debounced) reconcile.
func (r *refPool) trigger(p Pool) {
	c := &r.ctrl[p]
	if !c.running {
		return
	}
	t := r.now + refDebounce
	if t < c.readyAt {
		t = c.readyAt
	}
	if c.syncAt == 0 || c.syncAt > t {
		c.syncAt = t
	}
}

// advance runs the reference until the given time.
func (r *refPool) advance(until int64) {
	for guard := 0; ; guard++ {
		if guard > 1000000 {
			panic("refPool: no progress")
		}
		t := r.nextEvent()
		if t < 0 || t > until {
			r.setNow(until)
			return
		}
		if t > r.now {
			r.setNow(t)
		}
		r.step()
	}
}

// nextEvent returns the time of the next pending event, -1 if none.
func (r *refPool) nextEvent() int64 {
	next := int64(-1)
	at := func(t int64) {
		if next < 0 || t < next {
			next = t
		}
	}
	for _, p := range r.old {
		if !p.gone {
			at(p.goneAt)
		}
		if p.alloc && !p.dealloced {
			at(p.deallocAt)
		}
		if p.inflight {
			at(p.inflightTo)
		}
	}
	for _, t := range r.requeues {
		at(t)
	}
	for _, p := range r.pods {
		if p == nil {
			continue
		}
		if p.attemptAt > 0 {
			at(p.attemptAt)
		} else if p.unsched {
			at(p.flushAt)
		}
		if p.alloc && !p.bound {
			at(p.pollAt)
		}
	}
	for _, a := range r.atts {
		if a.state != "attached" {
			at(a.doneAt)
		}
	}
	for p := range r.ctrl {
		c := &r.ctrl[p]
		if !c.running {
			continue
		}
		if c.syncAt > 0 {
			at(c.syncAt)
		}
		if c.publishAt > 0 {
			at(c.publishAt)
		}
	}
	return next
}

// step processes everything that is due at the current time.
func (r *refPool) step() {
	now := r.now
	// deleted pods and their claims
	keep := r.old[:0]
	for _, p := range r.old {
		sl := r.slot(p.slot)
		if !p.gone && now >= p.goneAt {
			p.gone = true
		}
		if p.alloc && !p.dealloced && now >= p.deallocAt {
			p.dealloced = true
			r.logf("claim of %s g%d deallocated", sl.Name, p.gen)
			r.requeueAll("claim of " + sl.Name + " deallocated")
			r.trigger(sl.Pool)
		}
		if p.inflight && now >= p.inflightTo {
			p.inflight = false
			r.Count["hold"]++
			r.logf("in-flight allocation of %s g%d dropped (Unreserve, no event)", sl.Name, p.gen)
		}
		if !p.gone || p.inflight || (p.alloc && !p.dealloced) {
			keep = append(keep, p)
		}
	}
	r.old = keep
	// requeueing events
	rq := r.requeues[:0]
	for _, t := range r.requeues {
		if now >= t {
			r.requeueAll("a ResourceSlice or claim event")
		} else {
			rq = append(rq, t)
		}
	}
	r.requeues = rq
	// the scheduler
	for _, p := range r.pods {
		if p == nil {
			continue
		}
		if p.attemptAt == 0 && p.unsched && now >= p.flushAt {
			p.attemptAt = now
			r.Count["flush"]++
			r.logf("flush %s g%d from the unschedulable pods", r.slot(p.slot).Name, p.gen)
		}
		if p.attemptAt > 0 && now >= p.attemptAt {
			r.attempt(p)
		}
		if p.alloc && !p.bound && now >= p.pollAt {
			r.poll(p)
		}
	}
	// the pool servers
	var done []*refAtt
	atts := r.atts[:0]
	for _, a := range r.atts {
		if a.state != "attached" && now >= a.doneAt {
			done = append(done, a)
			if a.state == "detaching" {
				r.logf("detached %s@%s", a.dev, a.host)
				continue
			}
			a.state = "attached"
			r.logf("attached %s@%s", a.dev, a.host)
		}
		atts = append(atts, a)
	}
	r.atts = atts
	for _, a := range done {
		p := devices[a.dev].Pool
		c := &r.ctrl[p]
		if a.state == "attached" && c.running && a.inc == c.inc {
			// the synchronous attach of reconcile returns
			r.writeStatus(p)
		}
		r.trigger(p)
	}
	// the controllers
	for p := Pool(0); p < nPools; p++ {
		c := &r.ctrl[p]
		if !c.running {
			continue
		}
		if c.publishAt > 0 && now >= c.publishAt {
			c.publishAt = 0
			if !c.slices {
				c.slices = true
				r.Count["republish"]++
				r.logf("pool %s: ResourceSlice published", p)
				r.requeueAll("pool " + p.String() + " ResourceSlice added")
			}
		}
		if c.syncAt > 0 && now >= c.syncAt {
			if now < c.serverUpAt {
				// the server does not answer: the sync fails; the
				// event stream reconnects after it is back
				c.syncAt = c.serverUpAt + r.rnd(1000, 2000)
				continue
			}
			if !c.slices && c.publishAt == 0 {
				c.publishAt = now + r.rnd(100, 800)
			}
			r.reconcile(p)
			c.syncAt = now + refSyncInterval
		}
	}
}

// claimsOf calls f for every claim of a pool that has an allocation in
// the API: live pods and deleted ones whose claim is not deallocated.
func (r *refPool) claimsOf(p Pool, f func(rp *refPod, live bool)) {
	for _, rp := range r.pods {
		if rp != nil && rp.alloc && r.slot(rp.slot).Pool == p && r.slot(rp.slot).Kind.pooled() {
			f(rp, true)
		}
	}
	for _, rp := range r.old {
		if rp.alloc && !rp.dealloced && r.slot(rp.slot).Kind.pooled() && r.slot(rp.slot).Pool == p {
			f(rp, false)
		}
	}
}

func (r *refPool) findAtt(d DevID, v VM) *refAtt {
	for _, a := range r.atts {
		if a.dev == d && a.host == v {
			return a
		}
	}
	return nil
}

type refKey struct {
	dev  DevID
	host VM
}

// reconcile is one reconcile of a pool's controller (reconciler.go).
func (r *refPool) reconcile(p Pool) {
	c := &r.ctrl[p]
	desired := map[refKey]bool{} // -> exclusive
	r.claimsOf(p, func(rp *refPod, _ bool) {
		sl := r.slot(rp.slot)
		k := refKey{sl.Dev, rp.node}
		desired[k] = desired[k] || sl.Kind == KSExcl
	})
	var keys []refKey
	for k := range desired {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ei, ej := r.findAtt(keys[i].dev, keys[i].host) != nil, r.findAtt(keys[j].dev, keys[j].host) != nil
		if ei != ej {
			return ei
		}
		if keys[i].dev != keys[j].dev {
			return keys[i].dev < keys[j].dev
		}
		return keys[i].host < keys[j].host
	})
	for _, k := range keys {
		excl := desired[k]
		if a := r.findAtt(k.dev, k.host); a != nil {
			if a.state == "attached" && a.excl != excl {
				a.excl = excl
				r.logf("attachment %s@%s exclusive %v", k.dev, k.host, excl)
			}
			continue
		}
		wait, conflict := false, false
		for _, o := range r.atts {
			if o.dev != k.dev || o.host == k.host {
				continue
			}
			if !devices[k.dev].Shared || excl || o.excl {
				wait = true
				if _, still := desired[refKey{o.dev, o.host}]; still {
					// the server refuses it and the other one is
					// wanted: AttachFailed (Conflict, attach)
					conflict = true
				}
			}
		}
		if conflict {
			r.claimsOf(p, func(rp *refPod, live bool) {
				if sl := r.slot(rp.slot); live && !rp.attached && !rp.failed && sl.Dev == k.dev && rp.node == k.host {
					rp.failed = true
					r.Count["attach-failed"]++
					r.logf("claim of %s g%d AttachFailed: %s conflicts", sl.Name, rp.gen, k.dev)
				}
			})
		}
		if wait {
			continue
		}
		r.atts = append(r.atts, &refAtt{dev: k.dev, host: k.host, state: "attaching", excl: excl, doneAt: r.now + r.rnd(500, 2000), inc: c.inc})
		r.logf("attach %s@%s (exclusive %v)", k.dev, k.host, excl)
	}
	r.writeStatus(p)
	for _, a := range r.atts {
		if devices[a.dev].Pool != p || a.state != "attached" {
			continue
		}
		if _, ok := desired[refKey{a.dev, a.host}]; !ok {
			a.state, a.doneAt = "detaching", r.now+r.rnd(300, 1500)
			r.logf("detach %s@%s", a.dev, a.host)
		}
	}
}

// writeStatus writes Attached into the allocated claims of a pool whose
// attachment is attached (and exclusive, for sexcl).
func (r *refPool) writeStatus(p Pool) {
	r.claimsOf(p, func(rp *refPod, live bool) {
		sl := r.slot(rp.slot)
		if !live || rp.attached {
			return
		}
		if a := r.findAtt(sl.Dev, rp.node); a != nil && a.state == "attached" && (sl.Kind != KSExcl || a.excl) {
			rp.attached = true
			r.logf("claim of %s g%d Attached", sl.Name, rp.gen)
		}
	})
}

// attempt is a scheduling attempt of a pool pod.
func (r *refPool) attempt(rp *refPod) {
	rp.attemptAt = 0
	sl := r.slot(rp.slot)
	why := ""
	if !r.ctrl[sl.Pool].slices {
		why = "no ResourceSlice of pool " + sl.Pool.String()
	} else if o := r.conflict(rp); o != "" {
		why = "device " + sl.Dev.String() + " taken by " + o
	}
	if why != "" {
		if !rp.unsched {
			r.logf("%s g%d unschedulable: %s", sl.Name, rp.gen, why)
		}
		if strings.HasSuffix(why, "(deleted)") {
			r.Count["stall"]++
		} else if !r.ctrl[sl.Pool].slices {
			r.Count["no-slices"]++
		}
		rp.unsched = true
		rp.flushAt = refFlushPeriod * ((r.now + refFlushAfter + refFlushPeriod - 1) / refFlushPeriod)
		return
	}
	rp.unsched = false
	rp.alloc, rp.attached, rp.bound, rp.failed = true, false, false, false
	rp.node = sl.VM
	if sl.Any() {
		hosts := poolHosts[sl.Pool]
		rp.node = hosts[r.rng.Intn(len(hosts))]
	}
	rp.allocAt, rp.pollAt = r.now, r.now
	r.logf("%s g%d allocated %s on %s", sl.Name, rp.gen, sl.Dev, rp.node)
	r.trigger(sl.Pool)
}

// conflict names an allocation that the device of a pod conflicts with
// ("" if none): the scheduler's allocated devices and in-flight
// allocations.
func (r *refPool) conflict(rp *refPod) string {
	sl := r.slot(rp.slot)
	clash := func(o *refPod) bool {
		os := r.slot(o.slot)
		return os.Kind.pooled() && os.Dev == sl.Dev && !(os.Kind.share() && sl.Kind.share())
	}
	for _, o := range r.pods {
		if o != nil && o != rp && o.alloc && clash(o) {
			return r.slot(o.slot).Name
		}
	}
	for _, o := range r.old {
		if ((o.alloc && !o.dealloced) || o.inflight) && clash(o) {
			return r.slot(o.slot).Name + " (deleted)"
		}
	}
	return ""
}

// poll is a PreBind poll of an allocated pod.
func (r *refPool) poll(rp *refPod) {
	rp.pollAt += refPollPeriod
	sl := r.slot(rp.slot)
	switch {
	case rp.attached:
		rp.bound = true
		r.logf("%s g%d bound to %s", sl.Name, rp.gen, rp.node)
	case rp.failed || r.now-rp.allocAt >= refBindingTimeout:
		// a binding failure (AttachFailed) or the binding timeout:
		// Unreserve, the claim is deallocated, the pod is tried again
		// after its backoff
		failed := rp.failed
		if failed {
			r.logf("%s g%d: binding failure (AttachFailed)", sl.Name, rp.gen)
		}
		rp.alloc, rp.attached, rp.failed = false, false, false
		rp.attemptAt = r.now + r.rnd(1000, 10000)
		if !failed {
			r.Count["binding-timeout"]++
		}
		r.logf("%s g%d: binding timeout, claim deallocated", sl.Name, rp.gen)
		r.requeueAll("claim of " + sl.Name + " deallocated (binding timeout)")
		r.trigger(sl.Pool)
	}
}

// --- facts for the simulated SUT ---

// pod returns the live pod of a slot (nil: none).
func (r *refPool) pod(i int) *refPod { return r.pods[i] }

// deletingPod returns a deleted pod of a slot whose object is not gone.
func (r *refPool) deletingPod(i int) *refPod {
	for _, p := range r.old {
		if p.slot == i && !p.gone {
			return p
		}
	}
	return nil
}

// attState returns the state of the attachment of a device on a VM, ""
// if none.
func (r *refPool) attState(d DevID, v VM) string {
	if a := r.findAtt(d, v); a != nil {
		return a.state
	}
	return ""
}

// String is a summary of the reference's state.
func (r *refPool) String() string {
	s := fmt.Sprintf("reference at %.1fs:", float64(r.now)/1000)
	for p := Pool(0); p < nPools; p++ {
		c := &r.ctrl[p]
		s += fmt.Sprintf(" ctrl %s running %v slices %v;", p, c.running, c.slices)
	}
	for i, p := range r.pods {
		if p != nil {
			s += fmt.Sprintf(" %s g%d %s", r.slot(i).Name, p.gen, p.phase())
			if p.alloc {
				s += "@" + p.node.String()
			}
			if p.unsched {
				s += " unsched"
			}
			s += ";"
		}
	}
	for _, a := range r.atts {
		s += fmt.Sprintf(" att %s@%s %s;", a.dev, a.host, a.state)
	}
	for _, p := range r.old {
		s += fmt.Sprintf(" deleted %s g%d gone %v dealloc %v inflight %v;", r.slot(p.slot).Name, p.gen, p.gone, p.dealloced, p.inflight)
	}
	return s
}
