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

package provenance

import (
	"context"
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// Watcher lists the ResourceSlices of the pool driver and the pool claims
// allocated to the node, and keeps the provenance of the serials of the
// memdevs that it observes (the scans of the publisher).
//
// Identity: one per process, of the pool driver (Options.Driver) and the
// node.
//
// States: the Provenance record of each serial (provenance.go); the lists:
// never listed, listed, failing.
//
// Transitions: see the table of Provenance.State in internal/state.
//
// Invariants: a serial that a pool ResourceSlice lists is POOL; a POOL
// serial never turns LOCAL; a HELD memdev is not published.
//
// Persistence: the Provenance records and the listed pools are records of
// the store, changed by committed steps (provenance.go); in memory without
// a store or with a LOST one. Process memory: the last list, the serials
// prepared at the last scan, the absence timers, the conflicts logged and
// the kinds of the steps whose last commit failed.
//
// Locks and waits: mu guards the process memory and the records in memory,
// a leaf lock: no list of the API server (bounded by apiTimeout), commit
// (bounded by commitTimeout) or read of the store is made while it is
// held.
type Watcher struct {
	opts Options
	// st is the store of the records, nil without one or with a LOST one;
	// storeCommit is its Commit.
	st          *store.Store
	storeCommit func(ctx context.Context, d store.Durability, fn store.Func) error

	// mu guards the fields below: a leaf lock.
	mu sync.Mutex
	// mem are the records without st, replaced at each commit.
	mem *state.Records
	// serials are the serials of the last successful list, with their
	// pools; listed the pools with serials in it.
	serials  map[uint64]string
	listed   map[string]bool
	known    bool      // a list succeeded
	failing  bool      // the last list failed
	listErr  error     // the error of the last list that failed
	lastList time.Time // of the last successful list
	// prepared has the serials that the pool driver prepared at the last
	// scan (NotePrepared).
	prepared map[uint64]bool
	// absent and poolAbsent have when the serials and pools not seen at
	// the last observation were first observed absent, over observations
	// no more than ObservationGap apart; lastObs is the time of the last
	// observation of the memdevs (Gate).
	absent     map[uint64]time.Time
	poolAbsent map[string]time.Time
	lastObs    time.Time
	// lost is why the records could not be loaded ("" if they could),
	// lostAt when the first scan saw that.
	lost   string
	lostAt time.Time
	// uncommitted has the kinds of the steps whose last commit failed.
	uncommitted map[string]bool
	// conflicts has the pool serials whose use by local claims is logged.
	conflicts map[uint64]bool
}

// Options are the settings of a Watcher.
type Options struct {
	// Store keeps the records.
	Store *store.Store
	// List lists the ResourceSlices of the pool driver, Claims the
	// ResourceClaims (nil: none listed).
	List   func(ctx context.Context) ([]resourcev1.ResourceSlice, error)
	Claims func(ctx context.Context) ([]resourcev1.ResourceClaim, error)
	// Driver is the name of the pool driver, "" for device.PoolDriverName;
	// NodeName the node of the driver.
	Driver, NodeName string
	// Name names the records in the log lines (the path of the document
	// of Store).
	Name string
	// Forget are the serials whose records the operator removes at the
	// start (--forget-pool-serial).
	Forget []uint64
	// Now is the clock, nil for time.Now.
	Now func() time.Time
}

var (
	// apiTimeout bounds a list of the API server.
	apiTimeout = 15 * time.Second
	// ListRetry is how often the watch ticks: it scans while the last list
	// failed, a new memdev is held or the last commit failed.
	ListRetry = 30 * time.Second
	// Poll is how long the watch lets the node go without a scan: without
	// udev events it scans that often (at the next tick), so that the pool
	// slices and the memdevs are observed and returning pool slices are
	// noticed.
	Poll = 2 * time.Minute
)

// New returns the watcher of the pool driver's devices with the records
// of the store, after removing the records of Options.Forget.
func New(opts Options) *Watcher {
	if opts.Driver == "" {
		opts.Driver = device.PoolDriverName
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	w := &Watcher{
		opts:        opts,
		mem:         &state.Records{},
		absent:      map[uint64]time.Time{},
		poolAbsent:  map[string]time.Time{},
		conflicts:   map[uint64]bool{},
		uncommitted: map[string]bool{},
	}
	w.open()
	w.forget(opts.Forget)
	return w
}

// ClientLists returns the lists of the ResourceSlices of the pool driver
// (a field selector of the driver) and of the ResourceClaims through the
// client.
func ClientLists(client coreclientset.Interface, driver string) (func(context.Context) ([]resourcev1.ResourceSlice, error),
	func(context.Context) ([]resourcev1.ResourceClaim, error)) {
	if driver == "" {
		driver = device.PoolDriverName
	}
	slices := func(ctx context.Context) ([]resourcev1.ResourceSlice, error) {
		sel := fields.OneTermEqualSelector(resourcev1.ResourceSliceSelectorDriver, driver).String()
		l, err := client.ResourceV1().ResourceSlices().List(ctx, metav1.ListOptions{FieldSelector: sel})
		if err != nil {
			return nil, err
		}
		return l.Items, nil
	}
	claims := func(ctx context.Context) ([]resourcev1.ResourceClaim, error) {
		l, err := client.ResourceV1().ResourceClaims("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return l.Items, nil
	}
	return slices, claims
}

// Serials lists the ResourceSlices and returns the serials of the devices
// of the pool driver and the remembered pool serials, and whether the
// ResourceSlices are known; the listed serials are made POOL. After a
// failed list it returns the serials of the last successful one and the
// remembered ones, not known before the first one succeeded. A nil watcher
// knows that there are none.
func (w *Watcher) Serials(ctx context.Context) (map[uint64]bool, bool) {
	if w == nil {
		return nil, true
	}
	lctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	items, err := w.opts.List(lctx)
	r0 := w.records()
	out := poolSerialsOf(r0)
	if err != nil {
		w.mu.Lock()
		w.failing, w.listErr = true, err
		known := w.known
		for s := range w.serials {
			out[s] = true
		}
		w.mu.Unlock()
		if known {
			klog.Warningf("listing the ResourceSlices of pool controllers: %v; using the serials of the last list", err)
		} else {
			klog.Warningf("listing the ResourceSlices of pool controllers: %v; no local memory device is published until a list succeeds", err)
		}
		return out, known
	}
	now := w.opts.Now()
	serials, listed := map[uint64]string{}, map[string]bool{}
	for i := range items {
		rs := &items[i]
		if rs.Spec.Driver != w.opts.Driver { // the field selector of a fake client
			continue
		}
		pool := rs.Spec.Driver + "/" + rs.Spec.Pool.Name
		for j := range rs.Spec.Devices {
			if s, ok := DeviceSerial(&rs.Spec.Devices[j], rs.Spec.Driver); ok {
				serials[s], listed[pool] = pool, true
			}
		}
	}
	w.mu.Lock()
	gone := w.observePoolsLocked(r0, listed, now)
	for s := range serials {
		delete(w.absent, s)
	}
	w.serials, w.listed, w.known, w.failing = serials, listed, true, false
	w.mu.Unlock()
	w.commitStep("list", now, r0, func(s *step, r *state.Records) {
		for _, serial := range slices.Sorted(maps.Keys(serials)) {
			s.notePool(r, serial, serials[serial], triggerList)
		}
		s.notePools(r, listed, gone)
	})
	for s := range serials {
		out[s] = true
	}
	return out, true
}

// DeviceSerial returns the serial attribute of a device of a ResourceSlice
// of driver, unqualified or qualified with the driver name, and whether it
// has a valid one.
func DeviceSerial(d *resourcev1.Device, driver string) (uint64, bool) {
	for _, k := range []resourcev1.QualifiedName{device.AttrSerial, resourcev1.QualifiedName(driver + "/" + string(device.AttrSerial))} {
		a, ok := d.Attributes[k]
		if !ok {
			continue
		}
		if a.StringValue != nil {
			if v, err := api.ParseSerial(*a.StringValue); err == nil {
				return v, true
			}
		}
		return 0, false
	}
	return 0, false
}

// PoolSerials returns the serials of the POOL records, without a list; nil
// for a nil watcher.
func (w *Watcher) PoolSerials() map[uint64]bool {
	if w == nil {
		return nil
	}
	return poolSerialsOf(w.records())
}

// Failing tells whether the last list failed.
func (w *Watcher) Failing() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.failing
}

// Holding tells whether a new memdev is held.
func (w *Watcher) Holding() bool {
	if w == nil {
		return false
	}
	return slices.ContainsFunc(w.records().Provenance, func(p state.Provenance) bool { return p.State == state.ProvenanceHeld })
}

// retrying tells whether the last commit of a step of a list, the
// prepared serials or an observation failed.
func (w *Watcher) retrying() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.uncommitted["list"] || w.uncommitted["prepared"] || w.uncommitted["observation"]
}

// NotePrepared remembers the serials that the pool driver prepares as pool
// serials.
func (w *Watcher) NotePrepared(serials map[uint64]bool) {
	if w == nil {
		return
	}
	now := w.opts.Now()
	w.mu.Lock()
	w.prepared = maps.Clone(serials)
	for s := range serials {
		delete(w.absent, s)
	}
	w.mu.Unlock()
	if len(serials) == 0 {
		return
	}
	w.commitStep("prepared", now, w.records(), func(s *step, r *state.Records) {
		for _, serial := range slices.Sorted(maps.Keys(serials)) {
			s.notePool(r, serial, "", triggerPrepare)
		}
	})
}

// CheckLocal returns an error if the memdev with the serial must not be
// used as a local memory device: a current pool ResourceSlice lists it (a
// fresh list; the serials of the last list if that fails), or the list
// fails. The listed serials are made POOL.
func (w *Watcher) CheckLocal(ctx context.Context, serial uint64) error {
	if w == nil {
		return nil
	}
	w.Serials(ctx)
	w.mu.Lock()
	pool, listed := w.serials[serial]
	failing, listErr := w.failing, w.listErr
	w.mu.Unlock()
	switch {
	case listed:
		return fmt.Errorf("memory device serial 0x%x is a pool device of %s: it is not used as a local memory device", serial, pool)
	case failing:
		return fmt.Errorf("the ResourceSlices of pool controllers cannot be listed (%v): memory device serial 0x%x is not used as a local memory device until a list succeeds",
			listErr, serial)
	}
	return nil
}

// Watch scans the node by rescan at every ListRetry tick while the last
// list failed, a new memdev is held or the last commit failed, and when
// the node was not scanned for Poll (last: the time of the last scan;
// periodic), until ctx ends.
func (w *Watcher) Watch(ctx context.Context, rescan func(ctx context.Context, periodic bool), last func() time.Time) {
	t := time.NewTicker(ListRetry)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			switch {
			case w.Failing() || w.Holding() || w.retrying():
				rescan(ctx, false)
			case time.Since(last()) >= Poll:
				rescan(ctx, true)
			}
		}
	}
}

// claimEvidence is what the pool claims of the node tell about the pool
// devices on the node.
type claimEvidence struct {
	// serials are the serials in the status of pool claims allocated to
	// the node, with <driver>/<pool> of their results.
	serials map[uint64]string
	// attaching are the pool claims allocated to the node with a result
	// whose status has neither a serial nor a failed attach: its device
	// may be on the node already.
	attaching []string
}

// claimEvidence lists the ResourceClaims and returns the evidence of the
// pool claims allocated to the node.
func (w *Watcher) claimEvidence(ctx context.Context) (*claimEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	claims, err := w.opts.Claims(ctx)
	if err != nil {
		return nil, err
	}
	ev := &claimEvidence{serials: map[uint64]string{}}
	for i := range claims {
		c := &claims[i]
		a := c.Status.Allocation
		if a == nil || allocationNode(a) != w.opts.NodeName {
			continue
		}
		attaching := false
		for j := range a.Devices.Results {
			r := &a.Devices.Results[j]
			if r.Driver != w.opts.Driver {
				continue
			}
			if serial, err := StatusSerial(c, r); err == nil {
				ev.serials[serial] = r.Driver + "/" + r.Pool
			} else if !attachFailed(c, r) {
				attaching = true
			}
		}
		if attaching {
			ev.attaching = append(ev.attaching, c.Namespace+"/"+c.Name)
		}
	}
	slices.Sort(ev.attaching)
	return ev, nil
}

// StatusSerial returns the serial of the status data that the pool
// controller wrote for an allocation result of a claim (the entry of
// status.devices matched by driver, pool and device), and an error if it
// has none or it does not parse.
func StatusSerial(c *resourcev1.ResourceClaim, r *resourcev1.DeviceRequestAllocationResult) (uint64, error) {
	data, err := StatusData(c, r)
	if err != nil {
		return 0, err
	}
	return data.Serial, nil
}

// allocationNode returns the node of an allocation that binds to a node
// (matchFields metadata.name In [node]), "" for another one.
func allocationNode(a *resourcev1.AllocationResult) string {
	ns := a.NodeSelector
	if ns == nil || len(ns.NodeSelectorTerms) != 1 {
		return ""
	}
	for _, f := range ns.NodeSelectorTerms[0].MatchFields {
		if f.Key == "metadata.name" && len(f.Values) == 1 {
			return f.Values[0]
		}
	}
	return ""
}

// attachFailed tells whether the status of a result of a pool claim has
// the condition <driver>/AttachFailed True: nothing was attached for it.
func attachFailed(c *resourcev1.ResourceClaim, r *resourcev1.DeviceRequestAllocationResult) bool {
	for _, st := range c.Status.Devices {
		if st.Driver == r.Driver && st.Pool == r.Pool && st.Device == r.Device {
			return meta.IsStatusConditionPresentAndEqual(st.Conditions, r.Driver+"/AttachFailed", metav1.ConditionTrue)
		}
	}
	return false
}

// Flags are the command line flags of the provenance records.
type Flags struct {
	// Forget are the serials of --forget-pool-serial.
	Forget []uint64
}

// Register registers the flags in fs.
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.Var((*serialsFlag)(&f.Forget), "forget-pool-serial",
		"serial (0x<hex> or decimal) whose remembered provenance is removed at start, so that a memdev of it is new again; repeatable, or a comma-separated list")
}

// serialsFlag is a list of serials as a flag value.
type serialsFlag []uint64

// String returns the serials, comma-separated.
func (s *serialsFlag) String() string {
	if s == nil {
		return ""
	}
	var out []string
	for _, v := range *s {
		out = append(out, api.FormatSerial(v))
	}
	return strings.Join(out, ",")
}

// Set adds the serials of a comma-separated list.
func (s *serialsFlag) Set(value string) error {
	for _, text := range strings.Split(value, ",") {
		if text = strings.TrimSpace(text); text == "" {
			continue
		}
		v, err := api.ParseSerial(text)
		if err != nil {
			return err
		}
		*s = append(*s, v)
	}
	return nil
}
