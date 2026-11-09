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
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/leases"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/provenance"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

type driver struct {
	client coreclientset.Interface
	config *DriverConfig
	// nri is the NRI plugin, nil when NRI did not start.
	nri         *containers.Plugin
	udevWatcher *UdevEventWatcher
	sysfsRoot   string
	// local is cxl.nri.io, pool the pool driver (nil when it is
	// disabled), publisher the publisher of the node's ResourceSlice,
	// watcher the watcher of the pool devices (nil without a client).
	local     *dra.Plugin
	pool      *dra.Plugin
	publisher *dra.Publisher
	watcher   *provenance.Watcher
	broker    leaseBroker // nil when lending is disabled
	// closeStore writes the pending commits of the state store and
	// closes it.
	closeStore func()
	// stop ends the periodic passes of the driver.
	stop chan struct{}
	// stopEvents stops the uevents that wake the waits of the kernel.
	stopEvents func()
}

// leaseBroker is the lease broker as the driver stops it.
type leaseBroker interface {
	Stop()
}

// loadDriverConfig returns the configuration of the flags (-c or -f) and
// the sysfs root of --sysfs, and logs the container defaults and the
// filesystem types; a "/sys" suffix is trimmed from the flag.
func loadDriverConfig(cxlFlags *CXLFlags) (*DriverConfig, string, error) {
	configStr, err := resolveConfigStr(cxlFlags)
	if err != nil {
		return nil, "", fmt.Errorf("resolveConfigStr: %w", err)
	}
	driverConfig, err := newDriverConfigFromString(configStr)
	if err != nil {
		return nil, "", fmt.Errorf("newDriverConfigFromString: %w", err)
	}
	// Trim "/sys" suffix if present in SysfsRoot
	sysfsRoot := cxlFlags.SysfsRoot
	if len(sysfsRoot) >= 4 && sysfsRoot[len(sysfsRoot)-4:] == "/sys" {
		cxlFlags.SysfsRoot = sysfsRoot[:len(sysfsRoot)-4]
	}
	driverConfig.logDefaults()
	driverConfig.logFsTypes()
	driverConfig.logDeadKeys()
	return driverConfig, sysfsRoot, nil
}

// newBroker returns the lease broker of the lease claims and the leases of
// the store st, nil when lending is disabled; cxl.nri.io tells it of its
// lease claims.
func newBroker(config *pluginConfig, cxlFlags *CXLFlags, driverConfig *DriverConfig, st *store.Store, fe *frontEnds) (*leases.Broker, error) {
	if !driverConfig.PublishLeaseDevice {
		return nil, nil
	}
	b, err := leases.New(leases.Options{
		Store:       st,
		Client:      config.Client,
		NodeName:    config.Flags.NodeName,
		DataDir:     config.KubeletPluginDir,
		CDI:         cdiapi.GetDefaultCache(),
		CLI:         cxlFlags.LeaseCLI,
		Image:       cxlFlags.LeaseCompanionImage,
		WaitDefault: cxlFlags.LeaseWait,
		PoolDriver:  fe.pool.Name(),
		Limits:      cxlFlags.LeaseLimits,
	})
	if err != nil {
		return nil, err
	}
	fe.local.SetLeases(b)
	return b, nil
}

// wireLenders sets the lenders of the companion claims of both drivers: the
// NRI plugin nri and the broker, none when lending is disabled (a lend
// recorded before is not revoked then). It returns the containers of the
// broker's requests: nri, nil when NRI did not start, which makes lease
// requests and companion claims fail with errLendingUnavailable.
func wireLenders(nri *containers.Plugin, broker *leases.Broker, fe *frontEnds) leases.Containers {
	var lender leases.Containers
	var nodes dra.NodeLender
	if nri != nil {
		lender, nodes = nri, nri
	}
	if broker != nil {
		fe.pool.Lender().Set(nodes, broker)
		fe.local.Lender().Set(nodes, broker)
	} else {
		fe.pool.Lender().Set(nil, nil)
		fe.local.Lender().Set(nil, nil)
	}
	return lender
}

// recoverCompanions keeps the numa companions of the pool driver whose
// Prepare did not finish for kubelet's Unprepare (which revokes, then
// releases) and Prepare again (engine.RecoverCompanions).
func recoverCompanions(fe *frontEnds, devices *deviceEngine) {
	if fe.pool == nil {
		return
	}
	for _, ref := range devices.RecoverCompanions() {
		klog.V(3).Infof("%s: grant %s of a companion claim is kept for its Unprepare", fe.pool.Name(), ref)
	}
}

// startPlugins registers the kubelet plugins of cxl.nri.io and of the pool
// driver, starts the publisher of the node's ResourceSlice and the watcher
// of the pool devices.
func (d *driver) startPlugins(ctx context.Context, config *pluginConfig, fe *frontEnds, watcher *provenance.Watcher) error {
	klog.Infof(`Starting DRA driver kubelet plugin
RegistrarDirectoryPath: %v
PluginDataDirectoryPath: %v`,
		config.KubeletPluginsRegistryDir,
		config.KubeletPluginDir)

	if err := fe.local.Start(ctx,
		kubeletplugin.KubeClient(config.Client),
		kubeletplugin.NodeName(config.Flags.NodeName),
		kubeletplugin.DriverName(device.DriverName),
		kubeletplugin.RegistrarDirectoryPath(config.KubeletPluginsRegistryDir),
		kubeletplugin.PluginDataDirectoryPath(config.KubeletPluginDir),
	); err != nil {
		return err
	}
	if err := startPoolDriver(ctx, config, fe.pool); err != nil {
		fe.local.Stop()
		return err
	}
	if err := fe.publisher.Start(ctx); err != nil {
		return err
	}
	go watcher.Watch(ctx, fe.publisher.Trigger, fe.publisher.LastScan)
	return nil
}

// staleBindPeriod is how often the stale lease binds are unmounted again
// between releases.
const staleBindPeriod = 60 * time.Second

// kernelEvents are the uevents of the kernel objects that wake the waits of
// the kernel package.
type kernelEvents interface {
	kernel.Events
	Start(fifoPath string) error
	Stop()
}

// newKernelEvents returns the uevents of the kernel objects (a variable for
// tests).
var newKernelEvents = func() (kernelEvents, error) {
	ev, err := kernel.NewUdevEvents(0)
	if err != nil {
		return nil, err
	}
	ev.Logf = func(format string, args ...any) { klog.Infof("kernel uevents: "+format, args...) }
	return ev, nil
}

// wakeOnUevents makes the uevents of the kernel objects wake the waits of
// the kernel of the device engine early (they still poll), and returns
// their stop; without uevents the waits only poll.
func wakeOnUevents(devices *deviceEngine) func() {
	ev, err := newKernelEvents()
	if err == nil {
		err = ev.Start("")
	}
	if err != nil {
		klog.Warningf("kernel uevents: %v: the waits for kernel objects only poll", err)
		return func() {}
	}
	devices.k.Events = ev
	return ev.Stop
}

// repairPeriod is how often the fence pass of the NRI plugin tries the
// failed updates of the cpuset.mems of the fenced containers again.
const repairPeriod = 60 * time.Second

// everyPeriod runs pass every period until stop is closed.
func everyPeriod(period time.Duration, stop <-chan struct{}, pass func()) {
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			pass()
		}
	}
}

// startUdev starts the watcher of udev events for NUMA node hotplug
// detection unless ignoreNewNodes is set; a watcher that cannot be made or
// started is logged and the driver runs without it.
func (d *driver) startUdev(ctx context.Context, driverConfig *DriverConfig) error {
	if driverConfig.IgnoreNewNodes {
		klog.V(3).Info("Udev node watcher disabled (ignoreNewNodes=true)")
		return nil
	}
	stableDuration, err := parseUdevStableDuration(driverConfig.UdevStableDuration)
	if err != nil {
		return err
	}
	watcher, err := NewUdevEventWatcher(stableDuration)
	if err != nil {
		klog.Warningf("Failed to create udev watcher (continuing without it): %v", err)
		return nil
	}
	var fifoPath string
	if driverConfig.Testability != nil {
		fifoPath = driverConfig.Testability.FakeUdevFifo
	}
	if err := watcher.Start(fifoPath); err != nil {
		klog.Warningf("Failed to start udev watcher (continuing without it): %v", err)
		return nil
	}
	d.udevWatcher = watcher
	go d.udevRescanLoop(ctx)
	return nil
}

// fenceOf returns the fence of the NUMA nodes of the NRI plugin nri that
// the device engine calls before memory goes online, nil with fencing none.
func fenceOf(nri *containers.Plugin) func(ctx context.Context, node int) {
	if !nri.Fencing() {
		return nil
	}
	return nri.Fence
}

// startNRI connects the NRI plugin nri to the runtime and returns it, nil
// when it did not start: then the driver runs without NRI. A Prepare of
// either driver waits for its first Synchronize; without the lease broker
// (withBroker false) there are no lends to restore.
func startNRI(ctx context.Context, nri *containers.Plugin, cxlFlags *CXLFlags, fe *frontEnds, withBroker bool) *containers.Plugin {
	if err := nri.Start(ctx, containers.Connection{Name: cxlFlags.NRIName, Idx: cxlFlags.NRIIdx, Socket: cxlFlags.NRISocket}); err != nil {
		klog.Warningf("Failed to start NRI plugin (continuing without it): %v", err)
		return nil
	}
	wait := func(ctx context.Context) error { return waitNRI(ctx, nri) }
	fe.local.SetWaitNRI(wait)
	fe.pool.SetWaitNRI(wait)
	if !withBroker {
		// no lends to restore
		nri.LendsRestored()
	}
	return nri
}

// storeLockWait is how long the driver waits at start for the lock of the
// state store that another driver process holds.
const storeLockWait = 2 * time.Minute

// driverRules are the SourceRules of the DRA drivers of the process.
type driverRules struct {
	local dra.SourceRules
	pool  *dra.SourceRules // nil when the pool driver is disabled
}

// newDriverRules returns the rules of cxl.nri.io and of the pool driver
// unless it is disabled (empty --pool-driver-name): the node mounts of each
// in the mounts directory of its plugin data directory.
func newDriverRules(config *pluginConfig, cxlFlags *CXLFlags) driverRules {
	r := driverRules{local: dra.LocalRules(filepath.Join(config.KubeletPluginDir, mountsDirName))}
	if cxlFlags.PoolDriverName != "" {
		poolDir := filepath.Join(filepath.Dir(config.KubeletPluginDir), cxlFlags.PoolDriverName)
		pool := dra.PoolRules(cxlFlags.PoolDriverName, filepath.Join(poolDir, mountsDirName), filepath.Join(poolDir, poolPreparingFileName))
		r.pool = &pool
	}
	return r
}

// all returns the rules of the drivers that run.
func (r driverRules) all() []dra.SourceRules {
	if r.pool == nil {
		return []dra.SourceRules{r.local}
	}
	return []dra.SourceRules{r.local, *r.pool}
}

// openDriverStore opens the state store in the plugin data directory of
// cxl.nri.io with the state files of the pool driver in its own, and
// returns it and its close.
func openDriverStore(ctx context.Context, config *pluginConfig, cxlFlags *CXLFlags, sysfsRoot, bootID string, rules driverRules) (*store.Store, func(), error) {
	poolDir := ""
	if cxlFlags.PoolDriverName != "" {
		poolDir = filepath.Join(filepath.Dir(config.KubeletPluginDir), cxlFlags.PoolDriverName)
		if err := os.MkdirAll(poolDir, 0750); err != nil {
			return nil, nil, fmt.Errorf("pool driver data directory: %w", err)
		}
	}
	mem := newMemctl(sysfsRoot)
	sysRoot := mem.SysRoot
	// a driver pod that still runs holds the lock: wait for its exit
	ctx, cancel := context.WithTimeout(ctx, storeLockWait)
	defer cancel()
	st, err := store.Open(ctx, store.Options{
		Dir:             config.KubeletPluginDir,
		PoolDir:         poolDir,
		PoolDriver:      cxlFlags.PoolDriverName,
		BootID:          bootID,
		NewState:        cxlFlags.Store.NewState,
		DiscardOldState: cxlFlags.Store.DiscardOldState,
		CompatViews:     cxlFlags.Store.CompatViews,
		SysRoot:         sysRoot,
		DevRoot:         mem.DevRoot,
		RegionExists: func(name string) bool {
			_, err := os.Stat(filepath.Join(sysRoot, "bus", "cxl", "devices", name))
			return err == nil
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("state store: %w", err)
	}
	return st, func() {
		if err := st.Close(); err != nil {
			klog.Errorf("closing the state store: %v", err)
		}
	}, nil
}

// newDriverDevices returns the device engine of the drivers over the
// kernel of the sysfs under sysfsRoot and the records of the store st: of
// the pool driver unless it is disabled (empty --pool-driver-name), of the
// local memdevs unless they are not managed (manageMemdevs: false); the
// node mounts of each source in the MountsDir of its rules.
func newDriverDevices(config *pluginConfig, cxlFlags *CXLFlags, driverConfig *DriverConfig, sysfsRoot string, fence func(ctx context.Context, node int), st *store.Store, rules driverRules) (*deviceEngine, error) {
	cfg := deviceConfig{
		Kernel:          systemKernel(newMemctl(sysfsRoot)),
		Store:           st,
		MountsDirs:      dra.MountsDirs(rules.all()...),
		LeaseFsRoot:     leases.LeaseFsRoot(config.KubeletPluginDir),
		FsTypes:         driverConfig.fsTypes(),
		Fence:           fence,
		ProbeAddressing: driverConfig.verifyAddressing(),
		PoolTimeout:     cxlFlags.PoolPrepareTimeout,
	}
	if cxlFlags.PoolDriverName != "" {
		cfg.PoolDriver = cxlFlags.PoolDriverName
		cfg.PoolDataDir = filepath.Join(filepath.Dir(config.KubeletPluginDir), cxlFlags.PoolDriverName)
		if err := os.MkdirAll(cfg.PoolDataDir, 0750); err != nil {
			return nil, fmt.Errorf("pool driver data directory: %w", err)
		}
	}
	if driverConfig.manageMemdevs() {
		cfg.LocalDir = config.KubeletPluginDir
	}
	devices, err := newDeviceEngine(cfg)
	if err != nil {
		return nil, fmt.Errorf("device engine: %w", err)
	}
	return devices, nil
}

// newWatcher returns the watcher of the pool driver's devices with the
// provenance records of the store st, nil without a Kubernetes client.
func newWatcher(config *pluginConfig, cxlFlags *CXLFlags, st *store.Store) *provenance.Watcher {
	if config.Client == nil {
		return nil
	}
	list, claims := provenance.ClientLists(config.Client, cxlFlags.PoolDriverName)
	return provenance.New(provenance.Options{
		Store:    st,
		List:     list,
		Claims:   claims,
		Driver:   cxlFlags.PoolDriverName,
		NodeName: cxlFlags.NodeName,
		Name:     filepath.Join(config.KubeletPluginDir, poolSerialsFileName),
		Forget:   cxlFlags.Provenance.Forget,
	})
}

// frontEnds are the two DRA drivers of the process and the publisher of the
// node's ResourceSlice.
type frontEnds struct {
	local     *dra.Plugin
	pool      *dra.Plugin // nil when the pool driver is disabled
	publisher *dra.Publisher
	watcher   *provenance.Watcher
	// poolDir is the plugin data directory of the pool driver.
	poolDir string
}

// newFrontEnds returns the DRA drivers of rules over the store st and the
// device engine devices: cxl.nri.io, which publishes the node's
// ResourceSlice of the devices of the sysfs under sysfsRoot, and the pool
// driver unless it is disabled (rules.pool nil).
func newFrontEnds(config *pluginConfig, cxlFlags *CXLFlags, driverConfig *DriverConfig, sysfsRoot, bootID string, st *store.Store, devices *deviceEngine, watcher *provenance.Watcher, rules driverRules) (*frontEnds, error) {
	fe := &frontEnds{watcher: watcher}
	if rules.pool != nil {
		fe.poolDir = filepath.Join(filepath.Dir(config.KubeletPluginDir), cxlFlags.PoolDriverName)
		pool, err := dra.New(dra.Options{
			Rules:    *rules.pool,
			Store:    st,
			Engine:   devices.Engine,
			NodeName: cxlFlags.NodeName,
			BootID:   bootID,
			DevRoot:  devices.k.DevRoot,
		})
		if err != nil {
			return nil, fmt.Errorf("pool driver: %w", err)
		}
		fe.pool = pool
		devices.setLender(state.SourcePool, pool.Lender())
	}
	publisher, err := dra.NewPublisher(dra.PublishOptions{
		Config:      driverConfig.publishConfig(),
		NodeName:    cxlFlags.NodeName,
		Client:      config.Client,
		Scan:        driverConfig.scanFunc(sysfsRoot),
		Watcher:     watcher,
		PoolSerials: fe.pool.Serials,
		Store:       st,
		Probes:      devices.Probes,
		BlockSize:   devices.k.BlockSize,
	})
	if err != nil {
		return nil, err
	}
	fe.publisher = publisher
	local, err := dra.New(dra.Options{
		Rules:     rules.local,
		Store:     st,
		Engine:    devices.Engine,
		NodeName:  cxlFlags.NodeName,
		BootID:    bootID,
		DevRoot:   devices.k.DevRoot,
		Local:     driverConfig.localConfig(),
		OnShared:  devices.addShared,
		Publisher: fe.publisher,
	})
	if err != nil {
		return nil, err
	}
	fe.local = local
	fe.publisher.SetOnError(local.HandleError)
	devices.setLender(state.SourceLocal, local.Lender())
	return fe, nil
}

// recover recovers the records of the device engine at a start and makes
// the first scan: the configured shared local memdevs known, the records of
// the local memdevs that are pool devices now forgotten, the recovery of
// the engine (before any scan: the regions of the drivers are never
// published as region devices), the local guard, the first scan of the
// devices of the sysfs under sysfsRoot, the CDI specs of the claims of
// cxl.nri.io rewritten in the directory cdiRoot.
func (fe *frontEnds) recover(ctx context.Context, cdiRoot, sysfsRoot string, driverConfig *DriverConfig, devices *deviceEngine) error {
	detected, err := nricxl.DevicesFromSysfs(sysfsRoot)
	if err != nil {
		return fmt.Errorf("failed to detect devices: %v", err)
	}
	if driverConfig.Testability != nil {
		injectFakeDevices(driverConfig.Testability, detected)
	}
	// phase 1 knows the pool serials of the records: those that the pool
	// driver prepares and the remembered ones
	known := map[uint64]bool{}
	maps.Copy(known, fe.pool.Serials())
	maps.Copy(known, fe.watcher.PoolSerials())
	devices.setShared(dra.SharedSerials(driverConfig.publishConfig(), detected.MemoryDevices, known))
	if err := devices.forgetPoolSerials(ctx, known); err != nil {
		return err
	}
	rec, err := devices.recover(ctx)
	if err != nil {
		return err
	}
	fe.pool.Recovered(rec, filepath.Join(fe.poolDir, poolStateFileName))
	devices.setGuard(localPoolGuard(fe.pool, fe.watcher))
	// the first list of the pool ResourceSlices, after phase 1: it gates
	// the publication of local memdevs
	cfg, poolSerials := fe.publisher.ScanInput(ctx)
	devices.setShared(dra.SharedSerials(cfg, detected.MemoryDevices, poolSerials))
	if driverConfig.manageMemdevs() {
		if _, err := devices.k.BlockSize(); err != nil {
			klog.Warningf("local: memory block size: %v: local memory devices are not published until the memory block size is known", err)
		}
	}
	if err := fe.publisher.ScanWith(ctx, cfg, poolSerials); err != nil {
		return err
	}
	klog.V(3).Info("Creating new NodeState")
	klog.V(5).Info("Refreshing CDI registry")
	if err := cdiapi.Configure(cdiapi.WithSpecDirs(cdiRoot)); err != nil {
		return fmt.Errorf("failed to create new NodeState: unable to refresh the CDI registry: %v", err)
	}
	cache := cdiapi.GetDefaultCache()
	if err := dra.RemoveCXLSpecs(cache); err != nil {
		return fmt.Errorf("failed to create new NodeState: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	fe.local.SetCDI(cache)
	fe.pool.SetCDI(cache)
	// The CDI specs of the claims prepared before a restart.
	fe.local.Recovered(rec, "")
	if err := fe.local.WriteCDI(); err != nil {
		return fmt.Errorf("failed to create new NodeState: %v", err)
	}
	return nil
}

// localPoolGuard returns the check of a local memdev before the engine
// uses it: a memdev that the pool driver prepares, or that the watcher
// knows as a pool device or holds, is refused (with a fresh list).
func localPoolGuard(pool *dra.Plugin, watcher *provenance.Watcher) func(ctx context.Context, serial uint64) error {
	return func(ctx context.Context, serial uint64) error {
		if pool.Serials()[serial] {
			return fmt.Errorf("memory device serial 0x%x is prepared by the pool driver %s: it is not used as a local memory device", serial, pool.Name())
		}
		return watcher.CheckLocal(ctx, serial)
	}
}

// systemKernel returns the kernel of the device engine on the sysfs and
// device roots, commands and sysfs writes of mem; the engine holds its
// lock around each call.
func systemKernel(mem *memctl.Manager) *kernel.Kernel {
	return &kernel.Kernel{
		SysRoot:      mem.SysRoot,
		DevRoot:      mem.DevRoot,
		Exec:         mem.Exec,
		WriteFile:    mem.WriteFile,
		Sys:          &kernel.SysCalls{DevRoot: mem.DevRoot},
		PollInterval: mem.PollInterval,
	}
}

// newMemctl returns a memctl manager for the sysfs under sysfsRoot.
func newMemctl(sysfsRoot string) *memctl.Manager {
	mem := memctl.New()
	mem.SysRoot = sysfsRoot + "/sys"
	mem.Logf = func(format string, args ...any) { klog.Infof("memctl: "+format, args...) }
	return mem
}

// startPoolDriver registers the pool driver as a second kubelet plugin
// (nothing if pool is nil). The start removed all old CDI specs of both
// drivers, so the pool driver writes its own again first.
func startPoolDriver(ctx context.Context, config *pluginConfig, pool *dra.Plugin) error {
	if pool == nil {
		return nil
	}
	return pool.Start(ctx,
		kubeletplugin.KubeClient(config.Client),
		kubeletplugin.NodeName(config.Flags.NodeName),
		kubeletplugin.DriverName(pool.Name()),
		kubeletplugin.RegistrarDirectoryPath(config.KubeletPluginsRegistryDir),
		kubeletplugin.PluginDataDirectoryPath(filepath.Join(filepath.Dir(config.KubeletPluginDir), pool.Name())),
	)
}

// nriPrepareWait bounds how long a Prepare waits for the first NRI
// Synchronize (waitNRI): well within kubelet's 45 s timeout of the call,
// so that kubelet gets the error and retries (a variable for tests).
var nriPrepareWait = 30 * time.Second

// waitNRI waits before a Prepare of claims until the NRI plugin has
// synchronized with the runtime, at most nriPrepareWait. kubelet creates
// the containers of a pod after its claims are prepared, also after the
// Prepare of a claim that is prepared already. A container created before
// the NRI plugin is in the runtime is only found by Synchronize, and its
// CreateContainer is never seen: a container that its claims steer is
// never steered, a fenced one runs with the fenced nodes until the first
// fence pass. Once Synchronize has returned, the runtime creates no
// container before the plugin gets its CreateContainer. No wait without an
// NRI plugin (nil: it failed to start, and the driver runs without it). The
// lends do not need to be restored: a new container gets the kept lends of
// its leases at its creation.
func waitNRI(ctx context.Context, nri *containers.Plugin) error {
	if nri == nil {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, nriPrepareWait)
	defer cancel()
	if err := nri.WaitSynchronized(wctx); err != nil {
		return fmt.Errorf("%w: the containers of the claims would be created before the NRI plugin sees them; kubelet retries the Prepare", err)
	}
	return nil
}

// udevRescanLoop reads stable-notifications from the udev watcher and asks
// the publisher for a rescan on each one.
func (d *driver) udevRescanLoop(ctx context.Context) {
	for range d.udevWatcher.Events() {
		d.publisher.Trigger(ctx, false)
	}
	klog.V(3).Info("udevRescanLoop: exiting (watcher channel closed)")
}

func (d *driver) Shutdown(ctx context.Context) error {
	klog.V(5).Info("Shutting down driver")

	// First: the runtime may close the NRI connection while the rest
	// stops (the broker waits for its reconciles), which is no loss now.
	if d.nri != nil {
		d.nri.MarkStopping()
	}
	if d.udevWatcher != nil {
		d.udevWatcher.Stop()
	}
	if d.stop != nil {
		close(d.stop)
	}
	if d.stopEvents != nil {
		d.stopEvents()
	}
	if d.broker != nil {
		d.broker.Stop()
	}
	if d.nri != nil {
		d.nri.Stop()
	}
	d.pool.Stop()
	d.publisher.Stop()
	d.local.Stop()
	if d.closeStore != nil {
		d.closeStore()
	}

	return nil
}

// readBootID returns the boot id of the running kernel, "" if it cannot be
// read.
func readBootID(sysfsRoot string) string {
	b, err := os.ReadFile(filepath.Join(sysfsRoot, "/", bootIDFile))
	if err != nil {
		klog.Warningf("cannot read the boot id: %v; the claims, slices and leases of an earlier boot are taken as those of this one", err)
		return ""
	}
	return strings.TrimSpace(string(b))
}

// bootIDFile identifies the running kernel (under the sysfs root).
const bootIDFile = "proc/sys/kernel/random/boot_id"
