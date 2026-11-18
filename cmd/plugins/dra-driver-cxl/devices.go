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
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

const (
	// defaultPoolPrepareTimeout is how long a Prepare of the pool driver
	// waits for the memdev to appear.
	defaultPoolPrepareTimeout = 30 * time.Second
	// mountsDirName is the directory of the node mounts of mode fs in the
	// plugin data directory of a driver.
	mountsDirName = "mounts"
	// localProbesFileName keeps the usable sizes that the address line
	// probe found, by serial, across restarts and reboots.
	localProbesFileName = "localProbes.json"
)

// deviceConfig are the settings of the device engine of the driver.
type deviceConfig struct {
	// Engine are the options of the engine. MountsDirs needs the
	// directory of each source of the engine; newDeviceEngine sets the
	// sources, their drivers, the probes file and the callbacks.
	Engine engine.Options
	// PoolDriver is the name of the pool driver, "" when it is disabled.
	PoolDriver string
	// LocalDir is the plugin data directory of cxl.nri.io, "" when it
	// manages no local memdevs.
	LocalDir string
}

// deviceEngine is the engine of the CXL kernel objects of both sources and
// what its callbacks need from the drivers: the check of a local memdev
// against the pool, the local memdevs that are shared, and the lenders of
// the companion claims of each source.
type deviceEngine struct {
	*engine.Engine
	k  *kernel.Kernel
	st *store.Store
	// drivers are the DRA driver names of the sources.
	drivers map[state.Source]string

	// mu guards guard, shared and lenders: a leaf lock.
	mu sync.Mutex
	// guard refuses a local memdev that is a pool device (or may be one),
	// nil for no check.
	guard func(ctx context.Context, serial uint64) error
	// shared are the local memdevs that the configuration declares shared,
	// and those that a claim used shared since the start.
	shared map[state.Serial]bool
	// lenders lend the memory of the companion claims of each source.
	lenders map[state.Source]*dra.Lender
}

// newDeviceEngine returns the device engine of the sources of cfg: the
// pool when PoolDriver is set, the local memdevs when LocalDir is.
func newDeviceEngine(cfg deviceConfig) (*deviceEngine, error) {
	d := &deviceEngine{
		k:       cfg.Engine.Kernel,
		st:      cfg.Engine.Store,
		drivers: map[state.Source]string{},
		shared:  map[state.Serial]bool{},
		lenders: map[state.Source]*dra.Lender{},
	}
	opts := cfg.Engine
	opts.Drivers, opts.MountsDirs = d.drivers, map[state.Source]string{}
	opts.LocalGuard, opts.Shared, opts.Revoke = d.localGuard, d.isShared, d.revoke
	// no source is an engine that owns nothing, nil one that owns all
	opts.Sources = []state.Source{}
	if cfg.PoolDriver != "" {
		d.drivers[state.SourcePool] = cfg.PoolDriver
		opts.Sources = append(opts.Sources, state.SourcePool)
	}
	if cfg.LocalDir != "" {
		// the lines of the local memdevs that the local allocator logged
		d.drivers[state.SourceLocal] = device.DriverName
		opts.Sources = append(opts.Sources, state.SourceLocal)
		opts.ProbesFile = filepath.Join(cfg.LocalDir, localProbesFileName)
	}
	for _, src := range opts.Sources {
		if opts.MountsDirs[src] = cfg.Engine.MountsDirs[src]; opts.MountsDirs[src] == "" {
			return nil, fmt.Errorf("no directory of the node mounts of the %s source", src)
		}
	}
	e, err := engine.New(opts)
	if err != nil {
		return nil, err
	}
	d.Engine = e
	return d, nil
}

// recover matches the records of the store with the kernel at the start
// (engine.Recover), nothing when the store is LOST: then every Prepare
// fails with the loss and nothing is released.
func (d *deviceEngine) recover(ctx context.Context) (*engine.Recovered, error) {
	if err := d.st.Lost(); err != nil {
		klog.Errorf("%v: the devices of the drivers are not recovered", err)
		return &engine.Recovered{Why: map[state.GrantRef]error{}}, nil
	}
	rec, err := d.Recover(ctx)
	if err != nil {
		return nil, fmt.Errorf("recovering the devices: %w", err)
	}
	return rec, nil
}

// retryStale unmounts the stale lease binds of the device engine again and
// finishes the releases that they kept (engine.RetryStale), nothing when
// the store is LOST: then nothing is released.
func (d *deviceEngine) retryStale(ctx context.Context) {
	if d.st.Lost() != nil {
		return
	}
	d.RetryStale(ctx)
}

// forgetPoolSerials forgets the records of the local memdevs that are pool
// devices now (poolSerials) whose region was being created, without
// touching their regions.
func (d *deviceEngine) forgetPoolSerials(ctx context.Context, poolSerials map[uint64]bool) error {
	if d.st.Lost() != nil {
		return nil
	}
	var serials []state.Serial
	for s, ok := range poolSerials {
		if ok {
			serials = append(serials, state.Serial(s))
		}
	}
	slices.Sort(serials)
	return d.ForgetLocal(ctx, serials)
}

// setGuard sets the check of a local memdev before the engine uses it.
func (d *deviceEngine) setGuard(guard func(ctx context.Context, serial uint64) error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.guard = guard
}

// localGuard returns the error of the check of the local memdev with the
// serial, nil without a check.
func (d *deviceEngine) localGuard(ctx context.Context, serial state.Serial) error {
	d.mu.Lock()
	guard := d.guard
	d.mu.Unlock()
	if guard == nil {
		return nil
	}
	return guard(ctx, uint64(serial))
}

// setShared sets the local memdevs that the configuration declares shared.
func (d *deviceEngine) setShared(serials map[uint64]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.shared = map[state.Serial]bool{}
	for s, ok := range serials {
		if ok {
			d.shared[state.Serial(s)] = true
		}
	}
}

// addShared records that a claim uses the local memdev with the serial
// shared: its idle region is kept from then on.
func (d *deviceEngine) addShared(serial uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.shared[state.Serial(serial)] = true
}

// isShared tells whether the local memdev with the serial is shared.
func (d *deviceEngine) isShared(serial state.Serial) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.shared[serial]
}

// setLender sets the lender of the companion claims of the source.
func (d *deviceEngine) setLender(source state.Source, lender *dra.Lender) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lenders[source] = lender
}

// revoke revokes the NUMA node that the grant ref of a companion claim
// lends, through the lender of the source of the grant.
func (d *deviceEngine) revoke(ctx context.Context, ref state.GrantRef, lend state.GrantLend) error {
	r := &d.st.Snapshot().Records
	source, claimName := state.SourcePool, ref.Claim
	if g := r.Grant(ref); g != nil {
		source = g.Asked.Source
	}
	if prep := r.Preparation(d.drivers[source], ref.Claim); prep != nil && prep.ClaimName != "" {
		claimName = prep.ClaimName
	}
	d.mu.Lock()
	lender := d.lenders[source]
	d.mu.Unlock()
	return lender.RevokeGrant(ctx, lend, claimName)
}
