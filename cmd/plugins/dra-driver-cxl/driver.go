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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"
	"k8s.io/utils/cpuset"
	"sigs.k8s.io/yaml"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/provenance"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

type driver struct {
	client      coreclientset.Interface
	config      *DriverConfig
	nriPlugin   *nriPlugin
	udevWatcher *UdevEventWatcher
	sysfsRoot   string
	// local is cxl.nri.io, pool the pool driver (nil when it is
	// disabled), publisher the publisher of the node's ResourceSlice,
	// watcher the watcher of the pool devices (nil without a client).
	local     *dra.Plugin
	pool      *dra.Plugin
	publisher *dra.Publisher
	watcher   *provenance.Watcher
	broker    *broker // nil when lending is disabled
	// closeStore writes the pending commits of the state store and
	// closes it.
	closeStore func()
}

// TestabilityConfig holds configuration for injecting fake CXL
// devices for testing without real hardware. Fake devices are
// appended to the real detected devices before buildDevInfos()
// processes them.
type TestabilityConfig struct {
	// FakeRegionDevices lists CXL region devices to inject.
	// Each entry is appended to nricxl.Devices.RegionDevices
	// right after DevicesFromSysfs() returns. Memory devices
	// referenced in Memories are also appended to
	// nricxl.Devices.MemoryDevices.
	FakeRegionDevices []nricxl.RegionDevice `json:"fakeRegionDevices,omitempty"`
	// FakeUdevFifo is a path to a named pipe (FIFO) from which
	// the driver reads fake udev events. Each line is a JSON
	// object whose keys and values are udev event properties.
	// The driver creates the FIFO if it does not exist. Example:
	//   {"ACTION":"add","SUBSYSTEM":"node","DEVPATH":"/devices/system/node/node2"}
	FakeUdevFifo string `json:"fakeUdevFifo,omitempty"`
}

type DriverConfig struct {
	// IgnoreDevices is a list of CXL memory devices. Matches
	// uevent DEVNAME, <major>:<minor>, or serial number in
	// decimal format, or 0x<hex>. Example: ["mem0", "cxl/mem0",
	// "251:0", "3238060771", "0xc100e2e0"]
	IgnoreDevices []string `json:"ignoreDevices,omitempty"`
	// SharedDevices is a list of local CXL memory devices that are
	// published as shared devices (class cxl-local-shared): one devdax
	// device for all claims, never sliced, onlined or zeroed. Matched
	// like IgnoreDevices; IgnoreDevices and pool devices take
	// precedence. Example: ["0xc100e2e1"]
	SharedDevices []string `json:"sharedDevices,omitempty"`
	// IgnoreRegions is a list of CXL memory regions ["region0"]
	// to be ignored by the driver.
	IgnoreRegions []string `json:"ignoreRegions,omitempty"`
	// IgnoreNodes is a list of NUMA nodes to be ignored by the
	// driver.
	IgnoreNodes []int `json:"ignoreNodes,omitempty"`

	// If IgnoreNew* is true, hotplugged devices, created regions
	// and enabled nodes will be ignored by the driver.
	IgnoreNewMemoryDevices bool `json:"ignoreNewMemoryDevices,omitempty"`
	IgnoreNewRegions       bool `json:"ignoreNewRegions,omitempty"`
	IgnoreNewNodes         bool `json:"ignoreNewNodes,omitempty"`

	// If IgnoreDRAMNodes is true, NUMA nodes with DRAM memory
	// will be ignored by the driver. By default, DRAM nodes are
	// exposed in DRAM ResourceSlices.
	IgnoreDRAMNodes bool `json:"ignoreDRAMNodes,omitempty"`

	// UdevStableDuration is the quiet period after the last udev
	// event before a rescan is triggered. Parsed as a Go
	// duration string (e.g. "200ms", "1s"). Default: "200ms".
	UdevStableDuration string `json:"udevStableDuration,omitempty"`

	// Testability enables injection of fake CXL devices for
	// testing without real hardware.
	Testability *TestabilityConfig `json:"testability,omitempty"`

	// ManageMemdevs publishes the local CXL memory devices that have
	// no regions as memdev devices, and creates and destroys their
	// regions for claims. Default: true.
	ManageMemdevs *bool `json:"manageMemdevs,omitempty"`

	// MemdevSettings are settings of individual local memdevs, such as
	// the usable part of a memdev whose memory aliases.
	MemdevSettings []MemdevSetting `json:"memdevSettings,omitempty"`

	// FsTypes are the filesystem types that mode fs mounts on the node,
	// for the local and the pool driver; nil is defaultFsTypes (erofs
	// only), an empty list mounts none. The node kernel parses what the
	// writer of a device wrote: a type other than erofs trusts every party
	// that can write the devices raw. A type that the plugin does not know
	// is single-host. Example: ["erofs", "ext4"]
	FsTypes []string `json:"fsTypes,omitempty"`

	// VerifyAddressing runs an address line test on every new region of
	// a local memdev before it is used: a memdev whose memory aliases
	// (offsets X and X+P reach the same memory) is used only up to P,
	// and remembered so. Default: true.
	VerifyAddressing *bool `json:"verifyAddressing,omitempty"`

	// Defaults are the container settings of every container of the
	// node (config.Defaults: container.steering, container.fencing),
	// overlaid by the settings of the claims that a container uses.
	// Decoded strictly by config.ParseDefaults into defaults.
	Defaults json.RawMessage `json:"defaults,omitempty"`
	defaults *config.Defaults

	// PublishLeaseDevice publishes the lease device (set from --leases,
	// not part of the configuration file).
	PublishLeaseDevice bool `json:"-"`
}

// containerDefaults returns the container settings of the defaults.
func (c *DriverConfig) containerDefaults() config.Container {
	return c.defaults.ContainerSettings()
}

// fencing returns defaults.container.fencing, config.FencingAllowedMems
// when it is not set.
func (c *DriverConfig) fencing() string {
	if f := c.containerDefaults().Fencing; f != "" {
		return f
	}
	return config.FencingAllowedMems
}

// steeringPolicy returns defaults.container.steering.policy,
// config.PolicyNone when it is not set.
func (c *DriverConfig) steeringPolicy() string {
	if s := c.containerDefaults().Steering; s != nil && s.Policy != "" {
		return s.Policy
	}
	return config.PolicyNone
}

// logDefaults logs the container defaults.
func (c *DriverConfig) logDefaults() {
	if fencing := c.fencing(); fencing == config.FencingAllowedMems {
		klog.Infof("defaults.container.fencing: %s: containers get the CXL nodes of the driver only by claims and leases", fencing)
	} else {
		klog.Infof("defaults.container.fencing: %s: containers are not kept off the CXL nodes of the driver", fencing)
	}
	if policy := c.steeringPolicy(); policy == config.PolicyNone {
		klog.Infof("defaults.container.steering.policy: %s: containers are steered only when their claims opt in", policy)
	} else {
		klog.Infof("defaults.container.steering.policy: %s: containers with numa claims are steered unless their claims say none", policy)
	}
}

// validate returns an error if a value of the configuration is invalid,
// and decodes the defaults.
func (c *DriverConfig) validate() error {
	if err := c.validateMemdevSettings(); err != nil {
		return err
	}
	for _, t := range c.FsTypes {
		if !config.ValidFsType(t) {
			return fmt.Errorf(`fsTypes: invalid filesystem type %q (lower-case letters, digits, "_" and "-")`, t)
		}
	}
	c.defaults = nil
	if len(c.Defaults) > 0 {
		d, err := config.ParseDefaults(c.Defaults)
		if err != nil {
			return err
		}
		c.defaults = d
	}
	return nil
}

// defaultFsTypes are the filesystem types that mode fs mounts when the
// configuration has no fsTypes: erofs only, the type that is designed for
// images from untrusted writers.
var defaultFsTypes = []string{config.FsTypeErofs}

// fsTypes returns the filesystem types that mode fs mounts on the node:
// FsTypes, defaultFsTypes when it is not set.
func (c *DriverConfig) fsTypes() []string {
	if c == nil || c.FsTypes == nil {
		return slices.Clone(defaultFsTypes)
	}
	return slices.Clone(c.FsTypes)
}

// logFsTypes logs the filesystem types that mode fs mounts on the node.
func (c *DriverConfig) logFsTypes() {
	types := c.fsTypes()
	if len(types) == 0 {
		klog.Infof("fsTypes: none: mode fs mounts no filesystem on this node")
		return
	}
	klog.Infof("fsTypes: %s: the filesystem types that mode fs mounts on this node", strings.Join(types, ", "))
}

// manageMemdevs tells whether local memdevs are published and get regions
// for claims (ManageMemdevs, default true).
func (c *DriverConfig) manageMemdevs() bool {
	return c.ManageMemdevs == nil || *c.ManageMemdevs
}

const defaultUdevStableDuration = 200 * time.Millisecond

// parseUdevStableDuration parses the UdevStableDuration config string.
// Returns the default (200ms) when the string is empty.
func parseUdevStableDuration(s string) (time.Duration, error) {
	if s == "" {
		return defaultUdevStableDuration, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid udevStableDuration %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("udevStableDuration must not be negative, got %v", d)
	}
	return d, nil
}

func newDriverConfigFromString(configStr string) (*DriverConfig, error) {
	driverConfig := &DriverConfig{}
	if err := yaml.UnmarshalStrict([]byte(configStr), driverConfig); err != nil {
		return nil, fmt.Errorf("failed to parse driver config: %v", err)
	}
	if err := driverConfig.validate(); err != nil {
		return nil, err
	}
	return driverConfig, nil
}

// resolveConfigStr returns the configuration string from either the
// -c flag or the -f flag. It returns an error if both are provided.
func resolveConfigStr(flags *CXLFlags) (string, error) {
	hasStr := flags.ConfigStr != ""
	hasFile := flags.ConfigFile != ""

	if hasStr && hasFile {
		return "", fmt.Errorf("provide configuration as a file (-f) or as a string (-c), but not both")
	}

	if hasFile {
		data, err := os.ReadFile(flags.ConfigFile)
		if err != nil {
			return "", fmt.Errorf("failed to read configuration file %q: %v", flags.ConfigFile, err)
		}
		return string(data), nil
	}

	return flags.ConfigStr, nil
}

// injectFakeDevices appends fake CXL region devices from the
// testability configuration into the detected devices structure.
// Sensible defaults are applied for fields left unset.
func injectFakeDevices(tc *TestabilityConfig, devices *nricxl.Devices) {
	if len(tc.FakeRegionDevices) == 0 {
		return
	}
	klog.Warning("Testability: injecting fake CXL devices - do not use in production")
	for i := range tc.FakeRegionDevices {
		reg := &tc.FakeRegionDevices[i]
		if reg.SysfsPath == "" {
			reg.SysfsPath = fmt.Sprintf("/fake/sys/bus/cxl/devices/%s", reg.Name)
		}
		if reg.Mode == "" {
			reg.Mode = "ram"
		}
		if reg.Node >= 0 {
			reg.Enabled = true
		}
		if reg.OnlineSize == 0 && reg.Enabled {
			reg.OnlineSize = reg.Size
		}
		for j := range reg.Memories {
			mem := reg.Memories[j]
			if mem.SysfsPath == "" {
				mem.SysfsPath = fmt.Sprintf("/fake/sys/bus/cxl/devices/%s", mem.Name)
			}
			if mem.Driver == "" {
				mem.Driver = "cxl_mem"
			}
			if mem.DevName == "" {
				mem.DevName = fmt.Sprintf("cxl/%s", mem.Name)
			}
			mem.Enabled = true
			devices.MemoryDevices = append(devices.MemoryDevices, mem)
		}
		klog.Infof("Testability: injecting fake region %q (node %d, size %d, memories %d)",
			reg.Name, reg.Node, reg.Size, len(reg.Memories))
		devices.RegionDevices = append(devices.RegionDevices, reg)
	}
}

// detectDevices detects the devices under the sysfs root (a variable for
// tests).
var detectDevices = nricxl.DevicesFromSysfs

// scanFunc returns the scan of the devices of the node under sysfsRoot:
// the devices of sysfs, with the fake devices of the testability
// configuration.
func (c *DriverConfig) scanFunc(sysfsRoot string) func() (*nricxl.Devices, error) {
	return func() (*nricxl.Devices, error) {
		detected, err := detectDevices(sysfsRoot)
		if err != nil {
			return nil, err
		}
		if c.Testability != nil {
			injectFakeDevices(c.Testability, detected)
		}
		return detected, nil
	}
}

// publishConfig returns the settings of the publisher of the
// configuration.
func (c *DriverConfig) publishConfig() dra.PublishConfig {
	return dra.PublishConfig{
		IgnoreDevices:      c.IgnoreDevices,
		SharedDevices:      c.SharedDevices,
		IgnoreRegions:      c.IgnoreRegions,
		IgnoreNodes:        c.IgnoreNodes,
		IgnoreDRAMNodes:    c.IgnoreDRAMNodes,
		ManageMemdevs:      c.manageMemdevs(),
		PublishLeaseDevice: c.PublishLeaseDevice,
		UsableSize:         c.configuredUsableSize,
	}
}

// localConfig returns the settings of the local memdevs of the
// configuration.
func (c *DriverConfig) localConfig() dra.LocalConfig {
	return dra.LocalConfig{Managed: c.manageMemdevs(), UsableSize: c.configuredUsableSize, Coherent: c.memdevCoherent}
}

// newDriver returns the driver with its kubelet plugins, NRI plugin and
// udev watcher started.
func newDriver(ctx context.Context, config *pluginConfig) (*driver, error) {
	cxlFlags := config.Flags
	configStr, err := resolveConfigStr(cxlFlags)
	if err != nil {
		return nil, fmt.Errorf("resolveConfigStr: %w", err)
	}

	driverConfig, err := newDriverConfigFromString(configStr)
	if err != nil {
		return nil, fmt.Errorf("newDriverConfigFromString: %w", err)
	}

	// Trim "/sys" suffix if present in SysfsRoot
	sysfsRoot := cxlFlags.SysfsRoot
	if len(sysfsRoot) >= 4 && sysfsRoot[len(sysfsRoot)-4:] == "/sys" {
		cxlFlags.SysfsRoot = sysfsRoot[:len(sysfsRoot)-4]
	}

	// The fenced nodes exist before any Prepare can online memory, and
	// without NRI too.
	fence := newNodeFence(driverConfig.fencing())
	driverConfig.logDefaults()
	driverConfig.logFsTypes()

	// The prepared claims, the slices of local memdevs and the leases of
	// another boot are not prepared: nothing of what their Prepares made
	// survives a reboot.
	bootID := readBootID(sysfsRoot)
	if bootID != "" {
		klog.Infof("boot id %s", bootID)
	}

	// The rules of the two DRA drivers: what they do differently.
	rules := newDriverRules(config, cxlFlags)

	// The records of both drivers are kept in the state store
	// (state.json), which writes five of them as its views; the store
	// drops or marks stale what is of another boot before they are read.
	st, closeStore, err := openDriverStore(ctx, config, cxlFlags, sysfsRoot, bootID, rules)
	if err != nil {
		return nil, err
	}
	started := false
	defer func() {
		if !started {
			closeStore()
		}
	}()

	// One device engine owns the CXL kernel objects of both drivers. Its
	// records are recovered before the first scan, so that the regions of
	// the drivers are never published as region devices. The pool
	// driver's kubelet plugin is started after cxl.nri.io.
	devices, err := newDriverDevices(config, cxlFlags, driverConfig, sysfsRoot, fence, st, rules)
	if err != nil {
		return nil, err
	}

	// The lease device and the lease broker lend local memdevs and, with
	// the pool driver, pool devices.
	driverConfig.PublishLeaseDevice = cxlFlags.Leases

	// The provenance of the serials is remembered across restarts: a pool
	// device on the node is never a local memdev, also while the pool
	// controller has deleted its ResourceSlices.
	watcher := newWatcher(config, cxlFlags, st)
	fe, err := newFrontEnds(config, cxlFlags, driverConfig, sysfsRoot, bootID, st, devices, watcher, rules)
	if err != nil {
		return nil, err
	}
	if err := fe.recover(ctx, config.Flags.CDIRoot, sysfsRoot, driverConfig, devices); err != nil {
		return nil, err
	}
	// Not the nodes of the claims of another boot: they have no memory
	// online, their Prepares again fence the nodes before they online it.
	fence.seed(cpuset.New(dra.NumaNodes(&st.Snapshot().Records, fe.local.Name(), fe.pool.Name())...))

	driver := &driver{
		client:     config.Client,
		config:     driverConfig,
		sysfsRoot:  sysfsRoot,
		local:      fe.local,
		pool:       fe.pool,
		publisher:  fe.publisher,
		watcher:    watcher,
		closeStore: closeStore,
	}

	// The lease broker re-creates the sockets of prepared lease claims
	// before kubelet can call Prepare or Unprepare.
	if driverConfig.PublishLeaseDevice {
		b, err := newBroker(brokerConfig{
			Client:      config.Client,
			NodeName:    config.Flags.NodeName,
			DataDir:     config.KubeletPluginDir,
			CDI:         cdiapi.GetDefaultCache(),
			CLI:         cxlFlags.LeaseCLI,
			Image:       cxlFlags.LeaseCompanionImage,
			WaitDefault: cxlFlags.LeaseWait,
			PoolDriver:  fe.pool.Name(),
			BootID:      bootID,
		})
		if err != nil {
			return nil, err
		}
		driver.broker = b
		fe.local.SetLeases(b)
	}

	// The NRI plugin starts before the kubelet plugins: kubelet creates the
	// containers of a pod after its claims are prepared, and a container
	// created before the NRI plugin is in the runtime is only found by
	// Synchronize: its CreateContainer is never seen. Its Synchronize may
	// use the prepared claims of both drivers and the lease table, loaded
	// above. A Prepare still waits for the first Synchronize (waitNRI): the
	// stub starts when the runtime has configured it, before it
	// synchronizes.
	nriOpts := NRIOpts{
		Name:   cxlFlags.NRIName,
		Idx:    cxlFlags.NRIIdx,
		Socket: cxlFlags.NRISocket,
	}
	var leases leaseNodes // the lease table is loaded: Synchronize may use it
	if driver.broker != nil {
		leases = driver.broker
	}
	nri, err := startNRIPlugin(ctx, fe.local, nriOpts, driverConfig.containerDefaults(), fence, fe.pool.ClaimResults, leases, sysfsRoot, config.KubeletPluginDir)
	if err != nil {
		klog.Warningf("Failed to start NRI plugin (continuing without it): %v", err)
		fence.setNoNRI()
	} else {
		driver.nriPlugin = nri
		wait := func(ctx context.Context) error { return waitNRI(ctx, nri) }
		fe.local.SetWaitNRI(wait)
		fe.pool.SetWaitNRI(wait)
		if driver.broker == nil {
			// no lends to restore
			nri.LendsRestored()
		}
	}
	// A nil lender (NRI not connected) makes lease requests and companion
	// claims fail with errLendingUnavailable.
	var lender nodeLender
	var nodes dra.NodeLender
	if driver.nriPlugin != nil {
		lender, nodes = driver.nriPlugin, driver.nriPlugin
	}
	if driver.broker != nil {
		fe.pool.Lender().Set(nodes, driver.broker)
		fe.local.Lender().Set(nodes, driver.broker)
	} else {
		// lending disabled: a lend recorded before is not revoked
		fe.pool.Lender().Set(nil, nil)
		fe.local.Lender().Set(nil, nil)
	}
	if fe.pool != nil {
		// numa companions whose Prepare did not finish stay for kubelet's
		// Unprepare (which revokes, then releases) and Prepare again
		for _, ref := range devices.RecoverCompanions() {
			klog.V(3).Infof("%s: grant %s of a companion claim is kept for its Unprepare", fe.pool.Name(), ref)
		}
	}

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
		return nil, err
	}
	if err := startPoolDriver(ctx, config, fe.pool); err != nil {
		fe.local.Stop()
		return nil, err
	}
	if err := fe.publisher.Start(ctx); err != nil {
		return nil, err
	}
	go watcher.Watch(ctx, fe.publisher.Trigger, fe.publisher.LastScan)

	if driver.broker != nil {
		driver.broker.start(lender)
	}

	// Start udev event watcher for NUMA node hotplug detection.
	if !driverConfig.IgnoreNewNodes {
		stableDuration, err := parseUdevStableDuration(driverConfig.UdevStableDuration)
		if err != nil {
			return nil, err
		}

		watcher, err := NewUdevEventWatcher(stableDuration)
		if err != nil {
			klog.Warningf("Failed to create udev watcher (continuing without it): %v", err)
		} else {
			var fifoPath string
			if driverConfig.Testability != nil {
				fifoPath = driverConfig.Testability.FakeUdevFifo
			}
			if err := watcher.Start(fifoPath); err != nil {
				klog.Warningf("Failed to start udev watcher (continuing without it): %v", err)
			} else {
				driver.udevWatcher = watcher
				go driver.udevRescanLoop(ctx)
			}
		}
	} else {
		klog.V(3).Info("Udev node watcher disabled (ignoreNewNodes=true)")
	}

	klog.V(3).Info("Finished creating new driver")
	started = true
	return driver, nil
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
// returns it and its close; the load applies the DropOtherBoot of rules.
func openDriverStore(ctx context.Context, config *pluginConfig, cxlFlags *CXLFlags, sysfsRoot, bootID string, rules driverRules) (*store.Store, func(), error) {
	poolDir := ""
	if cxlFlags.PoolDriverName != "" {
		poolDir = filepath.Join(filepath.Dir(config.KubeletPluginDir), cxlFlags.PoolDriverName)
		if err := os.MkdirAll(poolDir, 0750); err != nil {
			return nil, nil, fmt.Errorf("pool driver data directory: %w", err)
		}
	}
	mem := newMemctl(sysfsRoot)
	// a driver pod that still runs holds the lock: wait for its exit
	ctx, cancel := context.WithTimeout(ctx, storeLockWait)
	defer cancel()
	s, closeStore, err := openStateStore(ctx, stateStoreConfig{
		LocalDir:      config.KubeletPluginDir,
		PoolDir:       poolDir,
		PoolDriver:    cxlFlags.PoolDriverName,
		BootID:        bootID,
		Flags:         cxlFlags.Store,
		SysRoot:       mem.SysRoot,
		DevRoot:       mem.DevRoot,
		DropOtherBoot: dra.DropOtherBoot(rules.all()...),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("state store: %w", err)
	}
	return s.st, closeStore, nil
}

// newDriverDevices returns the device engine of the drivers over the
// kernel of the sysfs under sysfsRoot and the records of the store st: of
// the pool driver unless it is disabled (empty --pool-driver-name), of the
// local memdevs unless they are not managed (manageMemdevs: false); the
// node mounts of each source in the MountsDir of its rules.
func newDriverDevices(config *pluginConfig, cxlFlags *CXLFlags, driverConfig *DriverConfig, sysfsRoot string, fence *nodeFence, st *store.Store, rules driverRules) (*deviceEngine, error) {
	cfg := deviceConfig{
		Kernel:          systemKernel(newMemctl(sysfsRoot)),
		Store:           st,
		MountsDirs:      dra.MountsDirs(rules.all()...),
		LeaseFsRoot:     filepath.Join(config.KubeletPluginDir, leaseFsDirName),
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
	cfg, poolSerials := fe.publisher.ScanInput(ctx)
	detected, err := nricxl.DevicesFromSysfs(sysfsRoot)
	if err != nil {
		return fmt.Errorf("failed to detect devices: %v", err)
	}
	if driverConfig.Testability != nil {
		injectFakeDevices(driverConfig.Testability, detected)
	}
	devices.setShared(dra.SharedSerials(cfg, detected.MemoryDevices, poolSerials))
	if err := devices.forgetPoolSerials(ctx, poolSerials); err != nil {
		return err
	}
	rec, err := devices.recover(ctx)
	if err != nil {
		return err
	}
	fe.pool.Recovered(rec, filepath.Join(fe.poolDir, poolStateFileName))
	devices.setGuard(localPoolGuard(fe.pool, fe.watcher))
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
func waitNRI(ctx context.Context, nri *nriPlugin) error {
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
	if d.nriPlugin != nil {
		d.nriPlugin.markStopping()
	}
	if d.udevWatcher != nil {
		d.udevWatcher.Stop()
	}
	d.broker.stop()
	if d.nriPlugin != nil {
		d.nriPlugin.Stop()
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
