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
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"

	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"

	nricxl "github.com/containers/nri-plugins/pkg/cxl"
	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

type driver struct {
	client      coreclientset.Interface
	state       nodeState
	helper      *kubeletplugin.Helper
	config      *DriverConfig
	nriPlugin   *nriPlugin
	udevWatcher *UdevEventWatcher
	sysfsRoot   string
	pool        *poolDriver // nil when the pool driver is disabled
	broker      *broker     // nil when lending is disabled
	// started is set when the kubelet plugin runs and resources can be
	// published.
	started atomic.Bool
	// poolSlices has the serials of the devices of pool controllers.
	poolSlices *poolSlices
	// slices publishes the node's ResourceSlice (not the helper: see
	// nodeSliceSyncDelay).
	slices *nodeSlices
	// rescanMu serializes the rescans (udev events and the pool watch),
	// from the pool list to the publish: a rescan never stores and
	// publishes the result of an older one. rescanned is the time of the
	// last one (UnixNano).
	rescanMu  sync.Mutex
	rescanned atomic.Int64
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

// scanDevices discovers CXL and DRAM devices from sysfs, injects
// fake devices if testability is configured, and builds the filtered
// DevicesInfo map. This is the single place where device scanning
// happens, used both at startup and on udev-triggered rescans.
// Regions on memdevs whose serial is in poolSerials belong to the pool
// driver and are skipped; poolSlices adds the memdevs that it holds back
// (Gate); local has the memdevs that the local allocator uses and the
// memory block size.
func scanDevices(ctx context.Context, sysfsRoot string, driverConfig *DriverConfig, poolSerials map[uint64]bool, poolSlices *poolSlices, local *localSnapshot) (device.DevicesInfo, error) {
	detectedDevices, err := detectDevices(sysfsRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to detect devices: %v", err)
	}

	if driverConfig.Testability != nil {
		injectFakeDevices(driverConfig.Testability, detectedDevices)
	}
	return scanDetected(ctx, driverConfig, detectedDevices, poolSerials, poolSlices, local)
}

// detectDevices detects the devices under the sysfs root (a variable for
// tests).
var detectDevices = nricxl.DevicesFromSysfs

// scanDetected builds the DevicesInfo map of the detected devices as
// scanDevices does: the memdevs that poolSlices holds back or remembers as
// pool devices are not published.
func scanDetected(ctx context.Context, driverConfig *DriverConfig, detectedDevices *nricxl.Devices, poolSerials map[uint64]bool, poolSlices *poolSlices, local *localSnapshot) (device.DevicesInfo, error) {
	poolSerials, held := poolSlices.Gate(ctx, detectedDevices, poolSerials, local)

	if len(detectedDevices.RegionDevices) == 0 {
		klog.Info("No region devices detected")
	}

	devInfos, err := buildDevInfosHeld(driverConfig, detectedDevices, poolSerials, held, local)
	if err != nil {
		return nil, fmt.Errorf("failed to build device infos: %v", err)
	}

	return devInfos, nil
}

// newDriver returns the driver with its kubelet plugins, NRI plugin and
// udev watcher started.
func newDriver(ctx context.Context, config *pluginConfig) (*driver, error) {
	preparedClaimsFilePath := path.Join(config.KubeletPluginDir, device.PreparedClaimsFileName)

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

	// The prepared claims, the slices of local memdevs and the leases of
	// another boot are not prepared: nothing of what their Prepares made
	// survives a reboot (plan-13 bug-15).
	bootID := readBootID(sysfsRoot)
	if bootID != "" {
		klog.Infof("boot id %s", bootID)
	}

	// The pool driver's prepared claims are loaded before the first
	// scan, so that its devices are never published as cxl.nri.io
	// devices (D29). Its kubelet plugin is started after cxl.nri.io.
	pool, err := loadPoolDriver(config, cxlFlags, sysfsRoot, fence, bootID)
	if err != nil {
		return nil, err
	}

	// The lease device and the lease broker lend local memdevs and,
	// with the pool driver, pool devices.
	driverConfig.PublishLeaseDevice = cxlFlags.Leases

	// The serials of pool devices are remembered across restarts: a pool
	// device on the node is never a local memdev, also while the pool
	// controller has deleted its ResourceSlices.
	poolSlices := newPoolSlices(config.Client, config.Flags.NodeName, cxlFlags.PoolDriverName, filepath.Join(config.KubeletPluginDir, poolSerialsFileName))
	state, err := newDriverState(ctx, config, driverConfig, sysfsRoot, preparedClaimsFilePath, pool, poolSlices, fence, bootID)
	if err != nil {
		return nil, err
	}
	// Not the nodes of the claims of another boot: they have no memory
	// online, their Prepares again fence the nodes before they online it.
	fence.seed(preparedNodes(state, pool))

	driver := &driver{
		state:      *state,
		client:     config.Client,
		config:     driverConfig,
		sysfsRoot:  sysfsRoot,
		poolSlices: poolSlices,
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
			PoolDriver:  pool.driverName(),
			BootID:      bootID,
		})
		if err != nil {
			return nil, err
		}
		driver.broker = b
		driver.state.leases = b
	}

	// The NRI plugin starts before the kubelet plugins: kubelet creates the
	// containers of a pod after its claims are prepared, and a container
	// created before the NRI plugin is in the runtime is only found by
	// Synchronize: its CreateContainer is never seen (plan-13 bug-19). Its
	// Synchronize may use the prepared claims of both drivers and the
	// lease table, loaded above. A Prepare still waits for the first
	// Synchronize (waitNRI): the stub starts when the runtime has
	// configured it, before it synchronizes.
	nriOpts := NRIOpts{
		Name:   cxlFlags.NRIName,
		Idx:    cxlFlags.NRIIdx,
		Socket: cxlFlags.NRISocket,
	}
	var leases leaseNodes // the lease table is loaded: Synchronize may use it
	if driver.broker != nil {
		leases = driver.broker
	}
	nri, err := startNRIPlugin(ctx, &driver.state, nriOpts, driverConfig.containerDefaults(), fence, pool, leases, sysfsRoot, config.KubeletPluginDir)
	if err != nil {
		klog.Warningf("Failed to start NRI plugin (continuing without it): %v", err)
		fence.setNoNRI()
	} else {
		driver.nriPlugin = nri
		if pool != nil {
			pool.nri = nri
		}
		if driver.broker == nil {
			// no lends to restore
			nri.LendsRestored()
		}
	}
	// A nil lender (NRI not connected) makes lease requests and companion
	// claims fail with errLendingUnavailable.
	var lender nodeLender
	if driver.nriPlugin != nil {
		lender = driver.nriPlugin
	}
	if driver.broker != nil {
		pool.lending().set(lender, driver.broker)
		driver.state.lending.set(lender, driver.broker)
	} else {
		// lending disabled: a lend recorded before is not revoked
		pool.lending().set(nil, nil)
		driver.state.lending.set(nil, nil)
	}

	klog.Infof(`Starting DRA driver kubelet plugin
RegistrarDirectoryPath: %v
PluginDataDirectoryPath: %v`,
		config.KubeletPluginsRegistryDir,
		config.KubeletPluginDir)

	helper, err := kubeletplugin.Start(
		ctx,
		driver,
		kubeletplugin.KubeClient(config.Client),
		kubeletplugin.NodeName(config.Flags.NodeName),
		kubeletplugin.DriverName(device.DriverName),
		kubeletplugin.RegistrarDirectoryPath(config.KubeletPluginsRegistryDir),
		kubeletplugin.PluginDataDirectoryPath(config.KubeletPluginDir),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start kubelet plugin: %v", err)
	}

	driver.helper = helper
	driver.slices = newNodeSlices(config.Client, config.Flags.NodeName, driver.HandleError)
	driver.started.Store(true)

	if err := startPoolDriver(ctx, config, pool); err != nil {
		helper.Stop()
		return nil, err
	}
	driver.pool = pool

	if err := driver.PublishResourceSlice(ctx); err != nil {
		return nil, fmt.Errorf("startup error: %v", err)
	}
	driver.rescanned.Store(time.Now().UnixNano())
	go driver.poolWatch(ctx)

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
	return driver, nil
}

// loadPoolDriver returns the pool driver with its prepared claims loaded,
// those of another boot than bootID not prepared, and the fenced nodes
// fence, or nil if it is disabled (empty --pool-driver-name).
func loadPoolDriver(config *pluginConfig, cxlFlags *CXLFlags, sysfsRoot string, fence *nodeFence, bootID string) (*poolDriver, error) {
	if cxlFlags.PoolDriverName == "" {
		return nil, nil
	}
	poolDataDir := filepath.Join(filepath.Dir(config.KubeletPluginDir), cxlFlags.PoolDriverName)
	if err := os.MkdirAll(poolDataDir, 0750); err != nil {
		return nil, fmt.Errorf("pool driver data directory: %w", err)
	}
	mem := newMemctl(sysfsRoot)
	pool, err := newPoolDriver(cxlFlags.PoolDriverName, mem, newSysMounter(mem.SysRoot), filepath.Join(poolDataDir, poolStateFileName),
		cxlFlags.PoolPrepareTimeout, filepath.Join(config.KubeletPluginDir, leaseFsDirName), bootID)
	if err != nil {
		return nil, fmt.Errorf("pool driver: %w", err)
	}
	pool.fence = fence
	return pool, nil
}

// newDriverState returns the node state with the devices of the first scan
// and the local allocator, which fences the nodes of numa slices with
// fence. The claims prepared in another boot than bootID are not prepared.
func newDriverState(ctx context.Context, config *pluginConfig, driverConfig *DriverConfig, sysfsRoot, preparedClaimsFilePath string, pool *poolDriver, poolSlices *poolSlices, fence *nodeFence, bootID string) (*nodeState, error) {
	// The local allocator's state is reconciled before the first scan,
	// so that the regions it created are never published as region
	// devices.
	scanConfig, poolSerials := scanInput(ctx, driverConfig, pool, poolSlices)
	local, err := newLocalHelper(ctx, config, driverConfig, sysfsRoot, poolSerials, bootID)
	if err != nil {
		return nil, err
	}
	if local != nil {
		local.fence = fence
		local.poolGuard = localPoolGuard(pool, poolSlices)
	}

	devInfos, err := scanDevices(ctx, sysfsRoot, scanConfig, poolSerials, poolSlices, local.Snapshot())
	if err != nil {
		return nil, err
	}

	klog.V(3).Info("Creating new NodeState")
	state, err := newNodeState(devInfos, config.Flags.CDIRoot, preparedClaimsFilePath, config.Flags.NodeName, driverConfig, local, bootID)
	if err != nil {
		return nil, fmt.Errorf("failed to create new NodeState: %v", err)
	}
	return state, nil
}

// localPoolGuard returns the check of the local allocator before it uses a
// memdev: a memdev that the pool driver prepares, or that poolSlices
// knows as a pool device, is refused.
func localPoolGuard(pool *poolDriver, poolSlices *poolSlices) func(ctx context.Context, serial uint64) error {
	return func(ctx context.Context, serial uint64) error {
		if pool.Serials()[serial] {
			return fmt.Errorf("memory device serial 0x%x is prepared by the pool driver %s: it is not used as a local memory device", serial, pool.driverName())
		}
		return poolSlices.CheckLocal(ctx, serial)
	}
}

// newMemctl returns a memctl manager for the sysfs under sysfsRoot.
func newMemctl(sysfsRoot string) *memctl.Manager {
	mem := memctl.New()
	mem.SysRoot = sysfsRoot + "/sys"
	mem.Logf = func(format string, args ...any) { klog.Infof("memctl: "+format, args...) }
	return mem
}

// newLocalHelper returns the local allocator with its state loaded and
// reconciled with the prepared claims and the shared local devices of the
// configuration, or nil if local memdevs are not managed (manageMemdevs:
// false).
//   - poolSerials: the serials of pool devices, which are never shared
//     local devices
//   - bootID: the boot id of the running kernel, "" if unknown
func newLocalHelper(ctx context.Context, config *pluginConfig, driverConfig *DriverConfig, sysfsRoot string, poolSerials map[uint64]bool, bootID string) (*localAllocator, error) {
	if !driverConfig.manageMemdevs() {
		return nil, nil
	}
	dataDir := config.KubeletPluginDir
	local, err := newLocalAllocator(newMemctl(sysfsRoot), filepath.Join(dataDir, localStateFileName), bootID)
	if err != nil {
		return nil, fmt.Errorf("local allocator: %w", err)
	}
	// the claims of both files of this boot (newNodeState forgets the
	// others)
	_, claims, _, _, err := loadPreparedClaims(filepath.Join(dataDir, device.PreparedClaimsFileName))
	if err != nil {
		return nil, fmt.Errorf("local allocator: %w", err)
	}
	prepared := map[string]bool{}
	for uid, info := range claims {
		if !otherBoot(info.BootID, bootID) {
			prepared[uid] = true
		}
	}
	detected, err := nricxl.DevicesFromSysfs(sysfsRoot)
	if err != nil {
		return nil, fmt.Errorf("local allocator: failed to detect devices: %v", err)
	}
	if driverConfig.Testability != nil {
		injectFakeDevices(driverConfig.Testability, detected)
	}
	local.SetShared(sharedSerials(driverConfig, detected.MemoryDevices, poolSerials))
	local.SetUsableSizes(driverConfig.configuredUsableSize, driverConfig.verifyAddressing())
	local.Reconcile(ctx, prepared)
	return local, nil
}

// startPoolDriver registers the pool driver as a second kubelet plugin
// (nothing if pool is nil). newNodeState removed all old CDI specs of both
// drivers, so the pool driver writes its own again first.
func startPoolDriver(ctx context.Context, config *pluginConfig, pool *poolDriver) error {
	if pool == nil {
		return nil
	}
	return pool.start(ctx, cdiapi.GetDefaultCache(),
		kubeletplugin.KubeClient(config.Client),
		kubeletplugin.NodeName(config.Flags.NodeName),
		kubeletplugin.DriverName(pool.name),
		kubeletplugin.RegistrarDirectoryPath(config.KubeletPluginsRegistryDir),
		kubeletplugin.PluginDataDirectoryPath(filepath.Dir(pool.stateFile)),
	)
}

func (d *driver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (map[types.UID]kubeletplugin.PrepareResult, error) {
	klog.V(5).Infof("NodePrepareResource is called: request: %+v", claims)

	response := map[types.UID]kubeletplugin.PrepareResult{}
	if err := waitNRI(ctx, d.nriPlugin); err != nil {
		klog.Warningf("%s: preparing %d claims: %v", device.DriverName, len(claims), err)
		for _, claim := range claims {
			response[claim.UID] = kubeletplugin.PrepareResult{Err: err}
		}
		return response, nil
	}

	for _, claim := range claims {
		response[claim.UID] = d.prepareResourceClaim(ctx, claim)
	}

	return response, nil
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
// fence pass (plan-13 bug-19). Once Synchronize has returned, the runtime
// creates no container before the plugin gets its CreateContainer. No
// wait without an NRI plugin (nil: it failed to start, and the driver runs
// without it). The lends do not need to be restored: a new container gets
// the kept lends of its leases at its creation.
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

func (d *driver) prepareResourceClaim(ctx context.Context, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	klog.V(5).Infof("NodePrepareResource is called: request: %+v", claim)

	if err := d.state.Prepare(ctx, claim); err != nil {
		return kubeletplugin.PrepareResult{
			Err: err,
		}
	}

	d.state.Lock()
	defer d.state.Unlock()
	return d.state.Prepared[string(claim.UID)]
}

func (d *driver) UnprepareResourceClaims(ctx context.Context, claims []kubeletplugin.NamespacedObject) (map[types.UID]error, error) {
	klog.V(5).Infof("NodeUnprepareResource is called: number of claims: %d", len(claims))
	response := map[types.UID]error{}

	for _, claim := range claims {

		// Leases of a lease claim are released first (bounded; an
		// error makes kubelet retry).
		if d.broker != nil {
			if err := d.broker.CloseClaim(ctx, string(claim.UID)); err != nil {
				response[claim.UID] = err
				continue
			}
		}

		if err := d.state.Unprepare(ctx, string(claim.UID)); err != nil {
			response[claim.UID] = fmt.Errorf("error freeing devices: %v", err)
			continue
		}

		response[claim.UID] = nil
		klog.V(3).Infof("Freed devices for claim '%v'", claim.UID)

	}

	return response, nil
}

func (d *driver) PublishResourceSlice(ctx context.Context) error {
	resources := d.state.GetResources()
	klog.FromContext(ctx).Info("Publishing resources", "len", len(resources.Pools[d.state.NodeName].Slices[0].Devices))
	klog.V(5).Infof("devices: %+v", resources.Pools[d.state.NodeName].Slices[0].Devices)
	if err := d.slices.publish(ctx, resources); err != nil {
		return fmt.Errorf("error publishing resources: %v", err)
	}

	return nil
}

// udevRescanLoop reads stable-notifications from the udev watcher and
// triggers a resource rescan on each one.
func (d *driver) udevRescanLoop(ctx context.Context) {
	for range d.udevWatcher.Events() {
		d.rescanAndPublish(ctx)
	}
	klog.V(3).Info("udevRescanLoop: exiting (watcher channel closed)")
}

// rescanAndPublish re-discovers hardware resources and republishes
// ResourceSlices if the set of allocatable devices has changed. Before the
// kubelet plugin runs, it only re-discovers them.
func (d *driver) rescanAndPublish(ctx context.Context) {
	d.rescan(ctx, false)
}

// lastRescan returns the time of the last rescan, or of the start.
func (d *driver) lastRescan() time.Time {
	return time.Unix(0, d.rescanned.Load())
}

// rescan is rescanAndPublish, logged at V(4) for a periodic rescan of the
// pool watch that changes nothing.
func (d *driver) rescan(ctx context.Context, periodic bool) {
	d.rescanMu.Lock()
	defer d.rescanMu.Unlock()
	defer func() { d.rescanned.Store(time.Now().UnixNano()) }()
	logf := klog.Infof
	if periodic {
		logf = klog.V(4).Infof
	}
	logf("rescanAndPublish: rescanning devices")

	scanConfig, poolSerials := scanInput(ctx, d.config, d.pool, d.poolSlices)
	newDevInfos, err := scanDevices(ctx, d.sysfsRoot, scanConfig, poolSerials, d.poolSlices, d.state.local.Snapshot())
	if err != nil {
		klog.Errorf("rescanAndPublish: %v", err)
		return
	}

	d.state.Lock()
	old, _ := d.state.Allocatable.(device.DevicesInfo)
	d.state.Allocatable = newDevInfos
	d.state.Unlock()
	if periodic && !slices.Equal(slices.Sorted(maps.Keys(old)), slices.Sorted(maps.Keys(newDevInfos))) {
		logf = klog.Infof
		logf("rescanAndPublish: the periodic rescan changed the devices")
	}

	if !d.started.Load() {
		return
	}
	if err := d.PublishResourceSlice(ctx); err != nil {
		klog.Errorf("rescanAndPublish: failed to publish resources: %v", err)
		return
	}

	logf("rescanAndPublish: published updated resources (%d devices)", len(newDevInfos))
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
	d.pool.stop()
	d.slices.stop()
	d.helper.Stop()

	return nil
}

// HandleError is called by Kubelet when an error occures asyncronously, and
// needs to be communicated to the DRA driver.
//
// This is a mandatory method because drivers should check for errors
// which won't get resolved by retrying and then fail or change the
// slices that they are trying to publish:
// - dropped fields (see [resourceslice.DroppedFieldsError])
// - validation errors (see [apierrors.IsInvalid]).
func (d *driver) HandleError(ctx context.Context, err error, message string) {
	if errors.Is(err, kubeletplugin.ErrRecoverable) {
		// TODO: FIXME: error is ignored ATM, handle it properly.
		klog.FromContext(ctx).Error(err, "DRAPlugin encountered an error.")
	} else {
		klog.FromContext(ctx).Error(err, "Unrecoverable error.")
	}

	runtime.HandleErrorWithContext(ctx, err, message)
}

// WatchHealthStatus is required by the kubeletplugin.DRAPlugin
// interface. This driver does not report per-device health, so it
// declines the kubelet's health stream.
func (d *driver) WatchHealthStatus(ctx context.Context, reports chan<- kubeletplugin.DeviceHealthReport) error {
	return kubeletplugin.ErrHealthNotSupported
}
