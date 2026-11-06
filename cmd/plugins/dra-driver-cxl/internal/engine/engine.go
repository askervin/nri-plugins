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

package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// Engine: the one owner of the CXL kernel objects that the driver makes on
// the node.
//
// Identity: one per process.
//
// States: the records of the store (Memdev, Region, Grant) and, in memory,
// the Busy flag of each memdev (state.MemdevBusyTable) and the last kernel
// observation.
//
// Transitions: the tables of package state, applied in store commits.
//
// Invariants: invariants.go (I1-I12 of the design over the records and a
// kernel snapshot).
//
// Persistence: the records only; a commit is durable before the next
// kernel command that depends on it.
//
// Locks and waits: a queue per memdev (one request of a memdev at a time),
// and the engine lock around each short kernel call and the durable commit
// of the note that must precede it, never across a wait. Waits (a pool
// memdev to appear, an nd region to settle, a holder to go, memory blocks
// to stay offline) and zeroing run outside the lock with Busy set. The
// lock order is queue -> engine lock -> store commit.
type Engine struct {
	k     *kernel.Kernel
	store *store.Store
	opts  Options

	// mu is the engine lock.
	mu sync.Mutex

	// qmu guards queues, busy, last, hollowLogged and devices.
	qmu          sync.Mutex
	queues       map[state.Serial]chan struct{}
	busy         map[state.Serial]bool
	last         *kernel.Snapshot
	hollowLogged map[string]bool
	// devices are the DRA devices of the requests of the grants, for the
	// errors of their release.
	devices map[state.GrantRef]string

	// afterCommit is called after every commit that the store applied, nil
	// outside the tests that stop the process at a commit.
	afterCommit func()
}

// Options configure an Engine.
type Options struct {
	// Kernel observes and changes the kernel objects. Its Serialize stays
	// nil: the engine holds its own lock around each call.
	Kernel *kernel.Kernel
	// Store keeps the records.
	Store *store.Store
	// Drivers are the names of the drivers of the sources, the prefix of
	// the log lines of their devices.
	Drivers map[state.Source]string
	// MountsDirs are the directories of the node mounts of mode fs of the
	// sources, <plugin data dir of the driver>/mounts.
	MountsDirs map[state.Source]string
	// LeaseFsRoot is the directory of the lease-fs directories of the
	// lease claims, "" for no sweep of lease binds.
	LeaseFsRoot string
	// FsTypes are the filesystem types that mode fs may mount, nil for
	// erofs only.
	FsTypes []string
	// Filesystems is the list of the filesystem types of the kernel, ""
	// for /proc/filesystems.
	Filesystems string
	// Fence fences a NUMA node before memory of it goes online, nil for
	// no fencing; it returns once the node is fenced or the fence is not
	// ready, or when its context (Timeouts.Fence) ends.
	Fence func(ctx context.Context, node int)
	// LocalGuard returns an error if a local grant on the serial must not
	// be made: the serial is listed by a pool ResourceSlice now (a fresh
	// list; a failed list is an error). Nil: no such check.
	LocalGuard func(ctx context.Context, serial state.Serial) error
	// Shared tells whether a local memdev is configured shared, nil for
	// none.
	Shared func(serial state.Serial) bool
	// Sources are the sources whose records the engine owns, nil for all.
	Sources []state.Source
	// Records are the names that the log lines of the recovery give the
	// record of a claim whose Prepare did not finish, per source: for the
	// pool, the file preparingPoolClaims.json.
	Records map[state.Source]string
	// Timeouts are the bounds of the waits; zero values are the defaults.
	Timeouts Timeouts
}

// Timeouts are the bounds of the waits of the engine.
type Timeouts struct {
	// Memdev is how long a pool grant waits for its memdev to appear.
	Memdev time.Duration
	// ProbeGrace is how long a pool grant waits for the driver of a memdev
	// that is present.
	ProbeGrace time.Duration
	// RegionRetry is the pause before the one retry of a region creation
	// whose memdev had no endpoint port yet.
	RegionRetry time.Duration
	// Settle is how long a grant waits for the kernel to set up its
	// region: the dax region and the memory blocks of a ram region, the nd
	// region and the namespaces of a pmem region.
	Settle time.Duration
	// Restore is how long the verification of a block device waits for the
	// namespaces of its region.
	Restore time.Duration
	// Holder is how long one release waits for the block devices of its
	// persistent grants to have no holder.
	Holder time.Duration
	// Rollback bounds a rollback and the release of leftovers, which do
	// not end with the context of the request.
	Rollback time.Duration
	// OfflineSettle is how long memory blocks must stay offline before
	// their dax device changes driver, Offline how long the engine
	// offlines them again when they come online.
	OfflineSettle, Offline time.Duration
	// Fence bounds the fence of a NUMA node: the memory goes online
	// anyway (with a warning) when it ends first.
	Fence time.Duration
}

// The defaults of Timeouts.
const (
	defaultMemdevTimeout = 30 * time.Second
	defaultProbeGrace    = 2 * time.Second
	defaultRegionRetry   = 3 * time.Second
	defaultSettle        = 30 * time.Second
	defaultRestore       = 5 * time.Second
	defaultHolderWait    = 10 * time.Second
	defaultRollback      = time.Minute
	defaultOfflineSettle = 500 * time.Millisecond
	defaultOffline       = 30 * time.Second
	defaultFence         = 10 * time.Second
	// holderPoll is the interval of the checks of the holder wait.
	holderPoll = 100 * time.Millisecond
)

// withDefaults returns the timeouts with the defaults for zero values.
func (t Timeouts) withDefaults() Timeouts {
	set := func(v *time.Duration, def time.Duration) {
		if *v <= 0 {
			*v = def
		}
	}
	set(&t.Memdev, defaultMemdevTimeout)
	set(&t.ProbeGrace, defaultProbeGrace)
	set(&t.RegionRetry, defaultRegionRetry)
	set(&t.Settle, defaultSettle)
	set(&t.Restore, defaultRestore)
	set(&t.Holder, defaultHolderWait)
	set(&t.Rollback, defaultRollback)
	set(&t.OfflineSettle, defaultOfflineSettle)
	set(&t.Offline, defaultOffline)
	set(&t.Fence, defaultFence)
	return t
}

// KernelLogf logs what package kernel does, as the driver logged memctl's
// steps.
func KernelLogf(format string, args ...any) {
	klog.InfofDepth(1, "memctl: "+format, args...)
}

// kernelDebugf logs the details of package kernel's lookups at debug level.
func kernelDebugf(format string, args ...any) {
	klog.V(3).InfofDepth(1, format, args...)
}

// sysWarningf logs what the system calls of package kernel find unexpected
// as warnings.
func sysWarningf(format string, args ...any) {
	klog.WarningfDepth(1, format, args...)
}

// New returns an engine over the kernel and the store of opts. A kernel
// without Logf logs through KernelLogf, its lookups' details at klog V(3),
// the unexpected findings of its system calls as warnings.
func New(opts Options) (*Engine, error) {
	if opts.Kernel == nil || opts.Store == nil {
		return nil, errors.New("engine: a kernel and a store are required")
	}
	if opts.Kernel.Serialize != nil {
		return nil, errors.New("engine: the kernel's Serialize must be nil: the engine holds its own lock")
	}
	if opts.Kernel.Logf == nil {
		opts.Kernel.Logf = KernelLogf
	}
	if opts.Kernel.Debugf == nil {
		opts.Kernel.Debugf = kernelDebugf
	}
	if sys, ok := opts.Kernel.Sys.(*kernel.SysCalls); ok && sys.Logf == nil {
		c := *sys
		c.Logf = sysWarningf
		opts.Kernel.Sys = &c
	}
	if opts.FsTypes == nil {
		opts.FsTypes = []string{config.FsTypeErofs}
	}
	if opts.Filesystems == "" {
		opts.Filesystems = "/proc/filesystems"
	}
	opts.Timeouts = opts.Timeouts.withDefaults()
	return &Engine{
		k:            opts.Kernel,
		store:        opts.Store,
		opts:         opts,
		queues:       map[state.Serial]chan struct{}{},
		busy:         map[state.Serial]bool{},
		hollowLogged: map[string]bool{},
		devices:      map[state.GrantRef]string{},
	}, nil
}

// GrantRequest is a grant that a front-end asks the engine to realise: the
// result of a claim on a memdev, with what it asks and the facts of the
// memdev.
type GrantRequest struct {
	Ref state.GrantRef
	// ClaimName (namespace/name) and Device (the DRA device of the
	// allocation result) name the grant in the log lines.
	ClaimName, Device string
	Serial            state.Serial
	Asked             state.Asked
	// Facts are the facts of the memdev that the source knows (the pool
	// controller's status data, the local configuration).
	Facts state.MemdevFacts
	// SingleHost: no other host has the device while the claim is
	// allocated. For a pool device: the status data's singleHost or
	// exclusive, or a device that is not shared.
	SingleHost bool
	// BindTarget is the lease bind of the grant of mode fs of a companion
	// claim, <lease claim FsDir>/<name>; "" for none.
	BindTarget string
	// Lend is the lend of a grant of a companion claim, nil for others:
	// the engine binds the lease of mode fs, the front-end lends the NUMA
	// node of mode numa after PrepareGrants returned (so a rollback never
	// releases a lent grant) and revokes it before ReleaseGrants.
	Lend *state.GrantLend
}

// claimName returns the claim of the request for the log lines: its name,
// else its uid.
func (r *GrantRequest) claimName() string {
	if r.ClaimName != "" {
		return r.ClaimName
	}
	return r.Ref.Claim
}

// device returns the device of the request for the log lines: the DRA
// device, else the memdev.
func (r *GrantRequest) device(memdev string) string {
	if r.Device != "" {
		return r.Device
	}
	return memdev
}

// queue returns the queue of the memdev with the serial.
func (e *Engine) queue(serial state.Serial) chan struct{} {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	q := e.queues[serial]
	if q == nil {
		q = make(chan struct{}, 1)
		e.queues[serial] = q
	}
	return q
}

// acquire waits for the queue of the memdev with the serial and returns
// the function that leaves it; a request whose ctx ended does not start.
func (e *Engine) acquire(ctx context.Context, serial state.Serial) (func(), error) {
	q := e.queue(serial)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("waiting for the requests of memdev %s: %w", serial, err)
	}
	select {
	case q <- struct{}{}:
		return func() { <-q }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for the requests of memdev %s: %w", serial, ctx.Err())
	}
}

// tryAcquire takes the queue of the memdev with the serial when it is
// free and returns the function that leaves it, nil when another request
// of the memdev is in progress.
func (e *Engine) tryAcquire(serial state.Serial) func() {
	q := e.queue(serial)
	select {
	case q <- struct{}{}:
		return func() { <-q }
	default:
		return nil
	}
}

// setDevices remembers the DRA devices of the requests.
func (e *Engine) setDevices(reqs []GrantRequest) {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	for i := range reqs {
		if reqs[i].Device != "" {
			e.devices[reqs[i].Ref] = reqs[i].Device
		}
	}
}

// forgetDevice forgets the DRA device of a grant that is released.
func (e *Engine) forgetDevice(ref state.GrantRef) {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	delete(e.devices, ref)
}

// deviceOf returns the DRA device of the request of the grant ref for the
// errors, else the grant.
func (e *Engine) deviceOf(ref state.GrantRef) string {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	if d := e.devices[ref]; d != "" {
		return d
	}
	return ref.String()
}

// locked runs fn, a short kernel call, holding the engine lock.
func (e *Engine) locked(fn func() error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return fn()
}

// waiting runs fn, a wait or zeroing of the memdev with the serial,
// outside the engine lock with the memdev Busy.
func (e *Engine) waiting(serial state.Serial, trigger state.Trigger, fn func() error) error {
	e.setBusy(serial, true, trigger)
	defer e.setBusy(serial, false, trigger)
	return fn()
}

// setBusy sets the Busy flag of the memdev with the serial.
func (e *Engine) setBusy(serial state.Serial, busy bool, trigger state.Trigger) {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	b := e.busy[serial]
	if err := state.Apply(&state.MemdevBusyTable, &b, busy, trigger); err != nil {
		klog.Errorf("engine: memdev %s: %v", serial, err)
		return
	}
	if b {
		e.busy[serial] = true
	} else {
		delete(e.busy, serial)
	}
}

// Busy tells whether a wait or zeroing of the memdev with the serial is in
// progress.
func (e *Engine) Busy(serial state.Serial) bool {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	return e.busy[serial]
}

// records returns the records of the last written document; the caller
// must not change them.
func (e *Engine) records() *state.Records {
	return &e.store.Snapshot().Records
}

// commit applies fn to the records in one durable commit. The commit is
// bounded by the rollback timeout, not by ctx: a commit that the store
// applied is not withdrawn when ctx ends.
func (e *Engine) commit(ctx context.Context, fn func(r *state.Records) error) error {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.opts.Timeouts.Rollback)
	defer cancel()
	err := e.store.Commit(cctx, store.Durable, func(doc *store.Document) error { return fn(&doc.Records) })
	if err == nil && e.afterCommit != nil {
		e.afterCommit()
	}
	return err
}

// commitLazy applies fn to the records in a lazy commit.
func (e *Engine) commitLazy(ctx context.Context, fn func(r *state.Records) error) error {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.opts.Timeouts.Rollback)
	defer cancel()
	err := e.store.Commit(cctx, store.Lazy, func(doc *store.Document) error { return fn(&doc.Records) })
	if err == nil && e.afterCommit != nil {
		e.afterCommit()
	}
	return err
}

// rollbackContext returns the context of a rollback or a release of
// leftovers: not ended by ctx, bounded by the rollback timeout.
func (e *Engine) rollbackContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), e.opts.Timeouts.Rollback)
}

// driver returns the name of the driver of a source for the log lines.
func (e *Engine) driver(source state.Source) string {
	if d := e.opts.Drivers[source]; d != "" {
		return d
	}
	return string(source)
}

// owns tells whether the engine owns the records of the source
// (Options.Sources).
func (e *Engine) owns(source state.Source) bool {
	return e.opts.Sources == nil || slices.Contains(e.opts.Sources, source)
}

// logf logs at info level with the driver of the source as the prefix.
func (e *Engine) logf(source state.Source, format string, args ...any) {
	klog.InfofDepth(1, e.driver(source)+": "+format, args...)
}

// warnf logs a warning with the driver of the source as the prefix.
func (e *Engine) warnf(source state.Source, format string, args ...any) {
	klog.WarningfDepth(1, e.driver(source)+": "+format, args...)
}

// errorf logs an error with the driver of the source as the prefix.
func (e *Engine) errorf(source state.Source, format string, args ...any) {
	klog.ErrorfDepth(1, e.driver(source)+": "+format, args...)
}

// serialText returns the serial as the log lines and errors write it.
func serialText(serial state.Serial) string {
	return api.FormatSerial(uint64(serial))
}

// removeRecord removes the records of a section for which drop is true.
func removeRecord[T any](records *[]T, drop func(*T) bool) {
	out := (*records)[:0]
	for i := range *records {
		if !drop(&(*records)[i]) {
			out = append(out, (*records)[i])
		}
	}
	*records = out
}

// removeRef returns refs without ref.
func removeRef[T comparable](refs []T, ref T) []T {
	out := refs[:0:0]
	for _, r := range refs {
		if r != ref {
			out = append(out, r)
		}
	}
	return out
}

// addRef returns refs with ref, once.
func addRef[T comparable](refs []T, ref T) []T {
	for _, r := range refs {
		if r == ref {
			return refs
		}
	}
	return append(refs, ref)
}
