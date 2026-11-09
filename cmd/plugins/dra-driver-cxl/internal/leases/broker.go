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

package leases

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// The lease broker serves the lease sockets of lease claims. A request
// from a container creates, in the container's namespace, a ResourceClaim
// and a companion pause pod "cxl-lease-<id>" pinned to this node. The
// scheduler allocates a local memdev (cxl.nri.io) or a pool device to the
// claim, the pool controller attaches a pool device, and kubelet prepares
// the claim through the driver of the device, which lends the memory to
// the requesting container (the hooks of dra.LeaseHooks). Deleting the
// companion releases it again. See docs/memory/cxl/leases.md.

const (
	// DefaultWait is the wait of a request that names none (--lease-wait).
	DefaultWait = 120 * time.Second
	// DefaultCompanionImage is the image of the companion pods
	// (--lease-companion-image).
	DefaultCompanionImage = "registry.k8s.io/pause:3.10"
	// DefaultCLI is the host path of the cxl-request CLI (--lease-cli).
	DefaultCLI = "/usr/local/bin/cxl-request"

	// apiTimeout bounds one Kubernetes API call.
	apiTimeout = 15 * time.Second
	// maxRequestLine bounds a request line.
	maxRequestLine = 64 * 1024
)

var (
	errLendingUnavailable = dra.ErrLendingUnavailable
	errNotOurPod          = errors.New("not a container of the claim's pod")
	errPoolDisabled       = errors.New("pool driver disabled (--pool-driver-name)")
)

// Timeouts are the waits and periods of the broker; zero for the
// defaults.
type Timeouts struct {
	// Close bounds how long the Unprepare of a lease claim waits for its
	// leases to be revoked and the deletion of their companions to be
	// requested (not gone: a companion of a local lease is unprepared by
	// cxl.nri.io, whose calls the kubelet plugin helper serializes); 5 s.
	Close time.Duration
	// Poll is the period of the waits for lease changes; 500 ms.
	Poll time.Duration
	// Reconcile is the period of the reconcile; 60 s.
	Reconcile time.Duration
	// CreatingGrace is how long a lease may stay CREATING before the
	// reconcile takes it as left over by a crash; 2 min.
	CreatingGrace time.Duration
	// SyncWait bounds the wait of the first reconcile for the container
	// plugin to synchronize; 30 s.
	SyncWait time.Duration
	// Persist bounds the wait of a commit of the records, which runs with
	// the broker's mutex held; 1 min.
	Persist time.Duration
}

// withDefaults returns the timeouts with the defaults for the zero ones.
func (t Timeouts) withDefaults() Timeouts {
	t.Close = cmp.Or(t.Close, 5*time.Second)
	t.Poll = cmp.Or(t.Poll, 500*time.Millisecond)
	t.Reconcile = cmp.Or(t.Reconcile, 60*time.Second)
	t.CreatingGrace = cmp.Or(t.CreatingGrace, 2*time.Minute)
	t.SyncWait = cmp.Or(t.SyncWait, 30*time.Second)
	t.Persist = cmp.Or(t.Persist, time.Minute)
	return t
}

// Options are the settings of a Broker.
type Options struct {
	// Store keeps the lease and lease claim records.
	Store *store.Store
	// Client is the Kubernetes client; nil makes every API step a no-op
	// or an error.
	Client coreclientset.Interface
	// NodeName is the node of the driver.
	NodeName string
	// DataDir is the plugin data directory of cxl.nri.io.
	DataDir string
	// CDI writes the CDI spec of the lease claims, nil for none.
	CDI *cdiapi.Cache
	// CLI is the host path of cxl-request, Image the image of the
	// companion pods ("": DefaultCompanionImage), WaitDefault the wait of
	// a request that names none (0: DefaultWait).
	CLI         string
	Image       string
	WaitDefault time.Duration
	// PoolDriver is the name of the pool driver, "" when it is disabled.
	PoolDriver string
	// Mounts returns the mounts of the plugin's mount namespace; nil:
	// /proc/self/mountinfo.
	Mounts func() ([]kernel.MountInfo, error)
	// Identity resolves the peers of the sockets when Start gets a
	// container plugin (without one every request is refused); nil: the
	// container table of that plugin.
	Identity Identity
	// Timeouts are the waits and periods.
	Timeouts Timeouts
	// OpenDevice opens the device of a dax or block lease for passing it
	// to a container; nil: the device node, waiting for udev.
	OpenDevice func(path string, readOnly bool) (*os.File, error)
	// NewID returns a new lease id; nil: 8 random hex digits.
	NewID func() string
}

// Broker is the lease broker of the node: the lease claims of the pods and
// their sockets, the leases asked for on them and their companions.
//
// Identity: one per process, with --leases.
//
// States: the records of state.Lease and state.LeaseClaim (lease.go,
// leaseclaim.go); in memory besides them the listeners of the sockets, the
// running releases and the directories being removed.
//
// Transitions: state.LeaseTable and state.LeaseClaimTable, applied by
// apply and applyClaim.
//
// Invariants: every lease and lease claim of the store is in leases and
// claims, which are written to the store after every change; a running
// release (releasing) is that of a lease with ReleaseRequested; a
// RELEASING or RELEASING_BUSY lease without one is released again by the
// next reconcile.
//
// Persistence: the records in the store's document, written whole by
// every change (persistLocked); the memory stays authoritative when a
// write fails: the failure is logged, and it refuses a new lease (which is
// forgotten) or the Prepare of a lease claim (which kubelet retries).
//
// Locks and waits: mu guards the fields below it; it is held across a
// commit of the store (a leaf) and a CDI write, never across an API call
// or a call of the container plugin. Waiters poll changed and every
// Timeouts.Poll.
type Broker struct {
	opts Options
	st   *store.Store
	t    Timeouts

	mu sync.Mutex
	// containers is the container plugin (nil: NRI not connected) and
	// started: Start ran; identity the identity of the peers (nil:
	// requests are refused).
	started    bool
	containers Containers
	identity   Identity
	leases     map[string]*state.Lease
	claims     map[string]*state.LeaseClaim
	// lost: the store is lost, the lease claims of the node are unknown.
	lost bool
	// listeners are the sockets of the lease claims by uid, conns their
	// open connections.
	listeners map[string]*net.UnixListener
	conns     map[string]map[*net.UnixConn]bool
	// specHashes are the hashes of the specs of the companion claims that
	// the broker created, by lease (dra.SpecHash).
	specHashes map[string]string
	// releasing are the leases whose release runs.
	releasing map[string]bool
	// removing are the lease claims (uid) whose directories are being
	// removed (removeClaimDirs, without mu), with the channel closed when
	// the removal ends: their socket is not started meanwhile.
	removing map[string]chan struct{}
	// unrestored are the leases that failed at the start because the
	// device of their companion was not restored: released by Start.
	unrestored []string
	// changed is closed and replaced on every change.
	changed chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New loads the lease claims and leases from the store, fails the READY
// leases whose companion's device the start did not restore, rewrites the
// CDI spec and starts the sockets of the lease claims. Requests are
// answered with "lending unavailable" until Start.
func New(opts Options) (*Broker, error) {
	if opts.Store == nil {
		return nil, errors.New("lease broker: the broker needs the state store")
	}
	if opts.WaitDefault <= 0 {
		opts.WaitDefault = DefaultWait
	}
	opts.Image = cmp.Or(opts.Image, DefaultCompanionImage)
	if opts.OpenDevice == nil {
		opts.OpenDevice = openDevice
	}
	if opts.NewID == nil {
		opts.NewID = randomLeaseID
	}
	if err := os.MkdirAll(filepath.Join(opts.DataDir, leaseDirName), 0755); err != nil {
		return nil, fmt.Errorf("lease broker: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{
		opts:       opts,
		st:         opts.Store,
		t:          opts.Timeouts.withDefaults(),
		leases:     map[string]*state.Lease{},
		claims:     map[string]*state.LeaseClaim{},
		listeners:  map[string]*net.UnixListener{},
		conns:      map[string]map[*net.UnixConn]bool{},
		specHashes: map[string]string{},
		releasing:  map[string]bool{},
		removing:   map[string]chan struct{}{},
		changed:    make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
	}
	b.mu.Lock()
	b.load()
	if err := b.writeCDISpec(); err != nil {
		b.mu.Unlock()
		cancel()
		return nil, fmt.Errorf("lease broker: %w", err)
	}
	b.recoverClaims()
	b.mu.Unlock()
	b.sweepFsDirs(state.TriggerRecover)
	klog.Infof("lease broker: loaded %d lease claims and %d leases from %s", len(b.claims), len(b.leases),
		filepath.Join(opts.DataDir, store.FileName))
	return b, nil
}

// load takes the lease claims and the leases of the store, and fails the
// READY leases whose companion's device the start did not restore. A lost
// store has none: the lease claims of the node are unknown. Called with
// b.mu held.
func (b *Broker) load() {
	if err := b.st.Lost(); err != nil {
		klog.Errorf("lease broker: %v; starting with an empty lease table", err)
		b.lost = true
		return
	}
	doc := b.st.Snapshot()
	for i := range doc.LeaseClaims {
		c := doc.LeaseClaims[i].Clone()
		b.claims[c.UID] = &c
	}
	for i := range doc.Leases {
		l := doc.Leases[i].Clone()
		b.leases[l.ID] = &l
	}
	b.failUnrestored(&doc.Records)
}

// randomLeaseID returns 4 random bytes as 8 hex digits.
func randomLeaseID() string {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// Start sets the container plugin (nil: NRI is not connected, requests
// fail), registers its callbacks, releases the leases that failed at the
// start and starts the reconcile loop.
func (b *Broker) Start(containers Containers) {
	b.mu.Lock()
	b.started = true
	b.containers = containers
	if containers != nil {
		b.identity = b.opts.Identity
		if b.identity == nil {
			b.identity = tableIdentity{containers: containers}
		}
	}
	unrestored := b.unrestored
	b.unrestored = nil
	b.notify()
	b.mu.Unlock()
	if containers != nil {
		containers.OnContainerGone(b.containerGone)
		containers.OnContainerStarted(b.containerStarted)
	}
	for _, id := range unrestored {
		b.startRelease(id, "companion not restored", state.TriggerRecover)
	}
	b.wg.Add(1)
	go b.reconcileLoop(containers)
}

// Stop closes the sockets and stops the background work. The leases are
// kept: a restarted plugin continues with them.
func (b *Broker) Stop() {
	if b == nil {
		return
	}
	b.cancel()
	b.mu.Lock()
	for uid, l := range b.listeners {
		_ = l.Close()
		delete(b.listeners, uid)
	}
	b.mu.Unlock()
	b.wg.Wait()
}

// notify wakes up the waiters of lease changes. Called with b.mu held.
func (b *Broker) notify() {
	close(b.changed)
	b.changed = make(chan struct{})
}

// waitFor polls cond on every lease change and every poll interval until
// it is true or ctx is done.
func (b *Broker) waitFor(ctx context.Context, cond func() bool) error {
	for {
		b.mu.Lock()
		ch := b.changed
		b.mu.Unlock()
		if cond() {
			return nil
		}
		t := time.NewTimer(b.t.Poll)
		select {
		case <-ch:
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			if cond() {
				return nil
			}
			return ctx.Err()
		}
		t.Stop()
	}
}

// persistLocked writes the lease claims and the leases to the store and
// wakes up the waiters, and returns the error of the write. Called with
// b.mu held.
func (b *Broker) persistLocked() error {
	claims := make([]state.LeaseClaim, 0, len(b.claims))
	for _, uid := range slices.Sorted(maps.Keys(b.claims)) {
		claims = append(claims, b.claims[uid].Clone())
	}
	leases := make([]state.Lease, 0, len(b.leases))
	for _, id := range slices.Sorted(maps.Keys(b.leases)) {
		leases = append(leases, b.leases[id].Clone())
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.t.Persist)
	defer cancel()
	err := b.st.Commit(ctx, store.Durable, func(doc *store.Document) error {
		doc.LeaseClaims, doc.Leases = claims, leases
		return nil
	})
	b.notify()
	if err != nil {
		return fmt.Errorf("lease broker: %w", err)
	}
	return nil
}

// saveLocked persists the records and logs an error of the write: the
// records in memory stay authoritative. Called with b.mu held.
func (b *Broker) saveLocked() {
	if err := b.persistLocked(); err != nil {
		klog.Errorf("%v", err)
	}
}

// apply takes the lease to the state to on trigger, if the lease table
// has the transition, and reports whether it did; a refused transition is
// logged. Called with b.mu held.
func apply(l *state.Lease, to state.LeaseState, trigger state.Trigger) bool {
	if err := state.Apply(&state.LeaseTable, &l.State, to, trigger); err != nil {
		klog.Errorf("lease broker: lease %s: %v", l.ID, err)
		return false
	}
	return true
}

// applyClaim takes the lease claim to the state to on trigger, if the
// lease claim table has the transition; a refused transition is logged.
// Called with b.mu held.
func applyClaim(c *state.LeaseClaim, to state.LeaseClaimState, trigger state.Trigger) bool {
	if err := state.Apply(&state.LeaseClaimTable, &c.State, to, trigger); err != nil {
		klog.Errorf("lease broker: lease claim %s: %v", c.UID, err)
		return false
	}
	return true
}

// leasesOf returns the leases received on the socket of the lease claim.
// Called with b.mu held.
func (b *Broker) leasesOf(claimUID string) []*state.Lease {
	var out []*state.Lease
	for _, id := range slices.Sorted(maps.Keys(b.leases)) {
		if l := b.leases[id]; l.Claim == claimUID {
			out = append(out, l)
		}
	}
	return out
}

// mounts returns the mounts of the mount namespace of the plugin.
func (b *Broker) mounts() ([]kernel.MountInfo, error) {
	if b.opts.Mounts != nil {
		return b.opts.Mounts()
	}
	return kernel.New().Mounts()
}

// apiContext returns the context of one API call.
func (b *Broker) apiContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(b.ctx, apiTimeout)
}

var (
	_ dra.LeaseHooks  = (*Broker)(nil)
	_ dra.LeaseClaims = (*Broker)(nil)
)
