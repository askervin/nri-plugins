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

import (
	"context"
	"maps"
	"sync"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// A memdev whose serial a pool controller publishes in its ResourceSlices
// is a pool device, also before the pool driver prepares it for a claim:
// cxl.nri.io never publishes it as a local memdev, also after the
// ResourceSlices are gone (pool_serials.go).

var (
	// poolListRetry is how often the pool watch ticks: it rescans while
	// the last list of the devices of pool controllers failed or a new
	// memdev is held back.
	poolListRetry = 30 * time.Second
	// poolSlicesPoll is how long the pool watch lets the node go without
	// a rescan: without udev events it rescans that often (at the next
	// tick), so that the pool slices and the memdevs are observed
	// (pool_serials.go) and returning pool slices are noticed.
	poolSlicesPoll = 2 * time.Minute
)

// poolSlices finds the serials of the devices in the ResourceSlices of the
// pool driver (--pool-driver-name, by default cxl-pool.nri.io) and
// remembers them (pool_serials.go).
type poolSlices struct {
	list func(ctx context.Context) ([]resourceapi.ResourceSlice, error)
	// claims lists the ResourceClaims, nil for none (pool_serials.go,
	// claimEvidence).
	claims   func(ctx context.Context) ([]resourceapi.ResourceClaim, error)
	driver   string           // of the pool slices and claims
	nodeName string           // of this node
	file     string           // of the remembered serials, "" for none
	now      func() time.Time // the clock
	mu       sync.Mutex
	serials  map[uint64]bool // of the last successful list
	listed   map[string]bool // the pools with serials in the last successful list
	known    bool            // a list succeeded
	failing  bool            // the last list failed
	lastList time.Time       // of the last successful list
	// prepared has the serials that the pool driver prepared at the last
	// scan (NotePrepared).
	prepared map[uint64]bool
	// records are the remembered serials, pools the remembered pools
	// with the time of their last list (pool_serials.go).
	records map[uint64]*serialRecord
	pools   map[string]time.Time
	// absent and poolAbsent have when the serials and pools not seen at
	// the last observation were first observed absent, of observations
	// no more than poolObservationGap apart (pool_serials.go); lastObs
	// is the time of the last observation of the memdevs (Gate).
	absent     map[uint64]time.Time
	poolAbsent map[string]time.Time
	lastObs    time.Time
	// lost is why the file could not be loaded ("" if it could or did
	// not exist), lostAt when the first scan saw that.
	lost   string
	lostAt time.Time
	// held has the new memdevs that are held back, with the time they
	// were first held back.
	held  map[uint64]time.Time
	saved time.Time // when the file was written
	dirty bool      // times changed since
	// conflicts has the pool serials whose use by local claims is logged.
	conflicts map[uint64]bool
}

// newPoolSlices returns a poolSlices that lists the ResourceSlices and
// ResourceClaims of the pool driver (driver, "" for cxl-pool.nri.io)
// through the client for the node and remembers serials in file ("": in
// memory only), nil without a client.
func newPoolSlices(client coreclientset.Interface, nodeName, driver, file string) *poolSlices {
	if client == nil {
		return nil
	}
	if driver == "" {
		driver = device.PoolDriverName
	}
	p := &poolSlices{
		list: func(ctx context.Context) ([]resourceapi.ResourceSlice, error) {
			sel := fields.OneTermEqualSelector(resourceapi.ResourceSliceSelectorDriver, driver).String()
			l, err := client.ResourceV1().ResourceSlices().List(ctx, metav1.ListOptions{FieldSelector: sel})
			if err != nil {
				return nil, err
			}
			return l.Items, nil
		},
		claims: func(ctx context.Context) ([]resourceapi.ResourceClaim, error) {
			l, err := client.ResourceV1().ResourceClaims("").List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			return l.Items, nil
		},
		driver:     driver,
		nodeName:   nodeName,
		file:       file,
		now:        time.Now,
		held:       map[uint64]time.Time{},
		absent:     map[uint64]time.Time{},
		poolAbsent: map[string]time.Time{},
		conflicts:  map[uint64]bool{},
	}
	p.loadRecords()
	return p
}

// Serials lists the ResourceSlices and returns the serials of the devices
// of the pool driver and the remembered pool serials, and whether the
// ResourceSlices are known. After a failed list it returns the serials of
// the last successful one and the remembered ones, not known before the
// first one succeeded. A nil poolSlices knows that there are none.
func (p *poolSlices) Serials(ctx context.Context) (map[uint64]bool, bool) {
	if p == nil {
		return nil, true
	}
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	items, err := p.list(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.failing = true
		if p.known {
			klog.Warningf("listing the ResourceSlices of pool controllers: %v; using the serials of the last list", err)
		} else {
			klog.Warningf("listing the ResourceSlices of pool controllers: %v; no local memory device is published until a list succeeds", err)
		}
		out := p.poolSerialsLocked()
		maps.Copy(out, p.serials)
		return out, p.known
	}
	now, changed := p.now(), false
	serials, listed := map[uint64]bool{}, map[string]bool{}
	for i := range items {
		rs := &items[i]
		if rs.Spec.Driver != p.driver { // the field selector of a fake client
			continue
		}
		pool := rs.Spec.Driver + "/" + rs.Spec.Pool.Name
		for j := range rs.Spec.Devices {
			if s, ok := deviceSerial(&rs.Spec.Devices[j], rs.Spec.Driver); ok {
				serials[s] = true
				listed[pool] = true
				changed = p.notePoolLocked(s, pool, now) || changed
			}
		}
	}
	changed = p.notePoolsLocked(listed, now) || changed
	p.serials, p.listed, p.known, p.failing = serials, listed, true, false
	p.saveLocked(changed, now)
	out := p.poolSerialsLocked()
	maps.Copy(out, serials)
	return out, true
}

// Failing tells whether the last list failed.
func (p *poolSlices) Failing() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failing
}

// scanInput returns the configuration and the pool serials of a scan: the
// serials of the memdevs that the pool driver prepares, of the devices
// that pool controllers publish, and the remembered pool serials. While
// the devices of the pool controllers are not known, the configuration
// publishes no local memdevs.
func scanInput(ctx context.Context, driverConfig *DriverConfig, pool *poolDriver, slices *poolSlices) (*DriverConfig, map[uint64]bool) {
	serials := pool.Serials()
	if serials == nil {
		serials = map[uint64]bool{}
	}
	slices.NotePrepared(serials)
	remote, known := slices.Serials(ctx)
	for s := range remote {
		serials[s] = true
	}
	if known || !driverConfig.manageMemdevs() {
		return driverConfig, serials
	}
	klog.Warning("not publishing local memory devices: the devices of the pool controllers are not known")
	cfg := *driverConfig
	cfg.ManageMemdevs = ptr(false)
	return &cfg, serials
}

// poolWatch rescans the devices at every poolListRetry tick while the last
// list of the devices of pool controllers failed or a new memdev is held
// back, and when the node has not been rescanned for poolSlicesPoll, until
// ctx ends.
func (d *driver) poolWatch(ctx context.Context) {
	t := time.NewTicker(poolListRetry)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			switch {
			case d.poolSlices.Failing() || d.poolSlices.Holding():
				d.rescan(ctx, false)
			case time.Since(d.lastRescan()) >= poolSlicesPoll:
				d.rescan(ctx, true)
			}
		}
	}
}
