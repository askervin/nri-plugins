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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	coreclientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/leases"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/provenance"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/version"
)

const (
	// kubeletPluginsDir is the parent of the plugin data directories of
	// the drivers (<dir>/<driver name>).
	kubeletPluginsDir = "/var/lib/kubelet/plugins"
	// kubeletPluginsRegistryDir is where kubelet finds the registration
	// sockets of the drivers.
	kubeletPluginsRegistryDir = "/var/lib/kubelet/plugins_registry"

	defaultCDIRoot      = "/etc/cdi"
	defaultKubeAPIQPS   = 5
	defaultKubeAPIBurst = 10
	defaultNRIName      = "dra-driver-cxl"
	defaultNRIIdx       = "30"
)

// CXLFlags are the command line flags of the driver.
type CXLFlags struct {
	NodeName     string
	KubeConfig   string
	KubeAPIQPS   float64
	KubeAPIBurst int
	CDIRoot      string

	SysfsRoot  string
	ConfigStr  string
	ConfigFile string
	NRIName    string
	NRIIdx     string
	NRISocket  string

	// PoolDriverName is the DRA driver name of the pool driver,
	// empty disables it.
	PoolDriverName string
	// PoolPrepareTimeout is how long the pool driver waits for a
	// memdev to appear.
	PoolPrepareTimeout time.Duration

	// Leases enables lending local and pool memory to running
	// containers: the lease device, lease sockets and companion pods.
	Leases bool
	// LeaseCLI is the host path of the static cxl-request CLI that is
	// bind-mounted into containers of lease claims.
	LeaseCLI string
	// LeaseCLISource is the path of a cxl-request CLI that is copied to
	// LeaseCLI at start, empty for none.
	LeaseCLISource string
	// LeaseWait is how long a lease request waits for Ready when the
	// request does not say.
	LeaseWait time.Duration
	// LeaseCompanionImage is the image of the companion pods.
	LeaseCompanionImage string
	// LeaseLimits are the limits of the lease sockets and of the leases of
	// a pod.
	LeaseLimits leases.Limits

	// Store are the flags of the state store (state.json).
	Store store.Flags
	// Provenance are the flags of the provenance records of the serials.
	Provenance provenance.Flags
}

// pluginConfig is the configuration of the kubelet plugins of the driver.
type pluginConfig struct {
	Flags                     *CXLFlags
	Client                    coreclientset.Interface
	KubeletPluginDir          string
	KubeletPluginsRegistryDir string
}

// flagEnvs maps flags to the environment variables of their defaults.
var flagEnvs = []struct{ flag, env string }{
	{"node-name", "NODE_NAME"},
	{"kubeconfig", "KUBECONFIG"},
	{"kube-api-qps", "KUBE_API_QPS"},
	{"kube-api-burst", "KUBE_API_BURST"},
	{"cdi-root", "CDI_ROOT"},
	{"sysfs", "SYSFS_ROOT"},
	{"config-str", "CONFIG_STR"},
	{"nri-name", "NRI_PLUGIN_NAME"},
	{"nri-idx", "NRI_PLUGIN_IDX"},
	{"nri-socket", "NRI_SOCKET"},
	{"pool-driver-name", "POOL_DRIVER_NAME"},
	{"pool-prepare-timeout", "POOL_PREPARE_TIMEOUT"},
	{"leases", "LEASES"},
	{"lease-cli", "LEASE_CLI"},
	{"lease-cli-source", "LEASE_CLI_SOURCE"},
	{"lease-wait", "LEASE_WAIT"},
	{"lease-companion-image", "LEASE_COMPANION_IMAGE"},
	{"lease-max-connections", "LEASE_MAX_CONNECTIONS"},
	{"lease-idle-timeout", "LEASE_IDLE_TIMEOUT"},
	{"lease-max-per-pod", "LEASE_MAX_PER_POD"},
}

// flagAliases maps short flags to their long names.
var flagAliases = map[string]string{
	"c": "config-str",
	"f": "config-file",
}

// parseFlags returns the flags of args registered in fs, with the defaults
// of unset flags taken from the environment variables of flagEnvs.
func parseFlags(fs *flag.FlagSet, args []string, lookupEnv func(string) (string, bool)) (*CXLFlags, error) {
	f := &CXLFlags{}
	fs.StringVar(&f.NodeName, "node-name", "", "name of the node of the driver (required)")
	fs.StringVar(&f.KubeConfig, "kubeconfig", "", "kubeconfig file, empty for the in-cluster configuration")
	fs.Float64Var(&f.KubeAPIQPS, "kube-api-qps", defaultKubeAPIQPS, "QPS of the Kubernetes API client")
	fs.IntVar(&f.KubeAPIBurst, "kube-api-burst", defaultKubeAPIBurst, "burst of the Kubernetes API client")
	fs.StringVar(&f.CDIRoot, "cdi-root", defaultCDIRoot, "directory of the generated CDI specs")
	fs.StringVar(&f.SysfsRoot, "sysfs", "", "root of the sysfs to use, empty for the host's /sys")
	fs.StringVar(&f.ConfigStr, "config-str", "", "driver configuration as a JSON or YAML string")
	fs.StringVar(&f.ConfigStr, "c", "", "shorthand for --config-str")
	fs.StringVar(&f.ConfigFile, "config-file", "", "path to a JSON or YAML configuration file (mutually exclusive with -c)")
	fs.StringVar(&f.ConfigFile, "f", "", "shorthand for --config-file")
	fs.StringVar(&f.NRIName, "nri-name", defaultNRIName, "NRI plugin name to register")
	fs.StringVar(&f.NRIIdx, "nri-idx", defaultNRIIdx, "NRI plugin index (place in the plugin chain, higher is later)")
	fs.StringVar(&f.NRISocket, "nri-socket", "", "NRI socket path (empty for default)")
	fs.StringVar(&f.PoolDriverName, "pool-driver-name", device.PoolDriverName, "DRA driver name of the CXL memory pool driver (empty disables it)")
	fs.DurationVar(&f.PoolPrepareTimeout, "pool-prepare-timeout", defaultPoolPrepareTimeout, "how long the pool driver waits for a hotplugged CXL memory device to appear")
	fs.BoolVar(&f.Leases, "leases", true, "lend memory to running containers: publish the lease device, serve lease sockets, create companions (needs NRI; pool memory needs the pool driver)")
	fs.StringVar(&f.LeaseCLI, "lease-cli", leases.DefaultCLI, "host path of the static cxl-request CLI, mounted into containers of lease claims")
	fs.StringVar(&f.LeaseCLISource, "lease-cli-source", "", "cxl-request CLI that is copied to --lease-cli at start (empty for none)")
	fs.DurationVar(&f.LeaseWait, "lease-wait", leases.DefaultWait, "default wait of a lease request for the lease to become Ready")
	fs.StringVar(&f.LeaseCompanionImage, "lease-companion-image", leases.DefaultCompanionImage, "container image of the companion pods that hold the devices of leases")
	fs.IntVar(&f.LeaseLimits.Connections, "lease-max-connections", leases.DefaultMaxConnections, "open connections of the lease socket of a lease claim")
	fs.DurationVar(&f.LeaseLimits.Idle, "lease-idle-timeout", leases.DefaultIdle, "how long a connection of a lease socket may stay without a request")
	fs.IntVar(&f.LeaseLimits.LeasesPerPod, "lease-max-per-pod", leases.DefaultMaxLeasesPerPod, "leases of the containers of a pod")
	f.Store.Register(fs)
	f.Provenance.Register(fs)
	for _, fe := range flagEnvs {
		fs.Lookup(fe.flag).Usage += " (env " + fe.env + ")"
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("arguments not supported: %v", fs.Args())
	}

	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) {
		name := fl.Name
		if long, ok := flagAliases[name]; ok {
			name = long
		}
		set[name] = true
	})
	for _, fe := range flagEnvs {
		if set[fe.flag] {
			continue
		}
		if value, ok := lookupEnv(fe.env); ok {
			if err := fs.Set(fe.flag, value); err != nil {
				return nil, fmt.Errorf("invalid %s=%q: %w", fe.env, value, err)
			}
		}
	}

	if f.NodeName == "" {
		return nil, errors.New("--node-name or NODE_NAME is required")
	}
	if f.LeaseCLISource != "" && f.LeaseCLI == "" {
		return nil, errors.New("--lease-cli-source needs --lease-cli")
	}
	return f, nil
}

// newKubeClient returns a Kubernetes client of the kubeconfig file, or of
// the in-cluster configuration if kubeconfig is empty.
func newKubeClient(kubeconfig string, qps float64, burst int) (coreclientset.Interface, error) {
	var (
		cfg *rest.Config
		err error
	)
	if kubeconfig == "" {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("create in-cluster client configuration: %w", err)
		}
	} else {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("create out-of-cluster client configuration: %w", err)
		}
	}
	cfg.QPS = float32(qps)
	cfg.Burst = burst
	client, err := coreclientset.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create core client: %w", err)
	}
	return client, nil
}

// ensureDir creates the directory dir if it does not exist, and returns an
// error if dir is not a directory.
func ensureDir(dir string) error {
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(dir, 0750)
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

// installLeaseCLI copies the cxl-request CLI src to dst atomically: dst is
// replaced by an executable copy, labelled for containers on SELinux hosts.
func installLeaseCLI(src, dst string) (retErr error) {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("lease CLI source: %w", err)
	}
	defer func() { _ = in.Close() }()
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("lease CLI directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".*")
	if err != nil {
		return fmt.Errorf("lease CLI: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		return fmt.Errorf("lease CLI: copy %s: %w", src, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("lease CLI: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0755); err != nil {
		return fmt.Errorf("lease CLI: %w", err)
	}
	leases.SELinuxLabel(tmp.Name())
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("lease CLI: %w", err)
	}
	klog.Infof("Installed lease CLI %s from %s", dst, src)
	return nil
}

// newDriver returns the driver of the configuration of config, started in
// the order of its start-up:
//  1. the boot id and the state store;
//  2. the device engine and the first phase of its recovery, with the first
//     list of the pool devices, the first scan and the CDI specs of the
//     prepared claims of cxl.nri.io;
//  3. the fence of the NRI plugin seeded with the NUMA nodes of the claims;
//  4. the lease broker loaded, the sockets of its lease claims made again;
//  5. the NRI plugin started, the lenders wired and the second phase of the
//     recovery (the numa companions whose Prepare did not finish);
//  6. the kubelet plugins of cxl.nri.io and of the pool driver registered,
//     the first publication of the node's ResourceSlice, the watchers, the
//     periodic pass over the stale lease binds and the periodic repair pass
//     of the cpuset.mems of the fenced containers.
func newDriver(ctx context.Context, config *pluginConfig) (*driver, error) {
	cxlFlags := config.Flags
	driverConfig, sysfsRoot, err := loadDriverConfig(cxlFlags)
	if err != nil {
		return nil, err
	}

	// 1. The prepared claims, the slices of local memdevs and the leases of
	// another boot are not prepared: nothing of what their Prepares made
	// survives a reboot. The records of both drivers are kept in the state
	// store (state.json), which writes five of them as its views; the store
	// drops or marks stale what is of another boot before they are read.
	bootID := readBootID(sysfsRoot)
	if bootID != "" {
		klog.Infof("boot id %s", bootID)
	}
	rules := newDriverRules(config, cxlFlags)
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

	// 2. The NRI plugin with the fenced nodes exists before any Prepare can
	// online memory, and without NRI too. One device engine owns the CXL
	// kernel objects of both drivers; its records are recovered before the
	// first scan, so that the regions of the drivers are never published as
	// region devices. The provenance of the serials is remembered across
	// restarts: a pool device on the node is never a local memdev, also
	// while the pool controller has deleted its ResourceSlices.
	nri, err := containers.New(containers.Options{Defaults: driverConfig.containerDefaults(), Store: st, Leases: cxlFlags.Leases,
		SysRoot: sysfsRoot})
	if err != nil {
		return nil, err
	}
	devices, err := newDriverDevices(config, cxlFlags, driverConfig, sysfsRoot, fenceOf(nri), st, rules)
	if err != nil {
		return nil, err
	}
	stopEvents := wakeOnUevents(devices)
	// the lease device and the lease broker lend local memdevs and, with
	// the pool driver, pool devices
	driverConfig.PublishLeaseDevice = cxlFlags.Leases
	watcher := newWatcher(config, cxlFlags, st)
	fe, err := newFrontEnds(config, cxlFlags, driverConfig, sysfsRoot, bootID, st, devices, watcher, rules)
	if err != nil {
		return nil, err
	}
	if err := fe.recover(ctx, config.Flags.CDIRoot, sysfsRoot, driverConfig, devices); err != nil {
		return nil, err
	}

	// 3. Not the nodes of the claims of another boot: they have no memory
	// online, their Prepares again fence the nodes before they online it.
	nri.Seed(dra.NumaNodes(&st.Snapshot().Records, fe.local.Name(), fe.pool.Name()))
	// fe.pool is a nil *dra.Plugin without the pool driver: its readers
	// are nil-receiver safe (no pool results)
	nri.SetResults(fe.local, fe.pool)

	d := &driver{
		client:     config.Client,
		config:     driverConfig,
		sysfsRoot:  sysfsRoot,
		local:      fe.local,
		pool:       fe.pool,
		publisher:  fe.publisher,
		watcher:    watcher,
		closeStore: closeStore,
		stop:       make(chan struct{}),
		stopEvents: stopEvents,
	}

	// 4. The lease broker re-creates the sockets of prepared lease claims
	// before kubelet can call Prepare or Unprepare.
	broker, err := newBroker(config, cxlFlags, driverConfig, st, fe)
	if err != nil {
		return nil, err
	}
	if broker != nil {
		d.broker = broker
		// the broker's leases seed the lends of the containers
		nri.SetLeaseLends(broker.LeaseLends)
	}

	// 5. The NRI plugin starts before the kubelet plugins: kubelet creates
	// the containers of a pod after its claims are prepared, and a container
	// created before the NRI plugin is in the runtime is only found by
	// Synchronize: its CreateContainer is never seen. Its Synchronize may
	// use the prepared claims of both drivers and the lease table, loaded
	// above. A Prepare still waits for the first Synchronize (waitNRI): the
	// stub starts when the runtime has configured it, before it
	// synchronizes.
	d.nri = startNRI(ctx, nri, cxlFlags, fe, broker != nil)
	lender := wireLenders(d.nri, broker, fe)
	recoverCompanions(fe, devices)

	// 6. The kubelet plugins, the publisher and the watchers.
	if err := d.startPlugins(ctx, config, fe, watcher); err != nil {
		return nil, err
	}
	if broker != nil {
		broker.Start(lender)
	}
	go everyPeriod(staleBindPeriod, d.stop, func() { devices.retryStale(ctx) })
	if d.nri != nil {
		go everyPeriod(repairPeriod, d.stop, func() { d.nri.Repair(ctx) })
	}
	if err := d.startUdev(ctx, driverConfig); err != nil {
		return nil, err
	}

	klog.V(3).Info("Finished creating new driver")
	started = true
	return d, nil
}

// run runs the driver until a signal stops it.
func run(ctx context.Context, flags *CXLFlags) error {
	klog.Infof("Starting %s version %s (build %s, %s, %s/%s), drivers %s and %q",
		filepath.Base(os.Args[0]), version.Version, version.Build,
		runtime.Version(), runtime.GOOS, runtime.GOARCH,
		device.DriverName, flags.PoolDriverName)

	client, err := newKubeClient(flags.KubeConfig, flags.KubeAPIQPS, flags.KubeAPIBurst)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	config := &pluginConfig{
		Flags:                     flags,
		Client:                    client,
		KubeletPluginDir:          filepath.Join(kubeletPluginsDir, device.DriverName),
		KubeletPluginsRegistryDir: kubeletPluginsRegistryDir,
	}
	if err := os.MkdirAll(config.KubeletPluginDir, 0750); err != nil {
		return err
	}
	if err := ensureDir(flags.CDIRoot); err != nil {
		return fmt.Errorf("CDI root: %w", err)
	}
	if flags.LeaseCLISource != "" {
		if err := installLeaseCLI(flags.LeaseCLISource, flags.LeaseCLI); err != nil {
			return err
		}
	}

	driver, err := newDriver(ctx, config)
	if err != nil {
		return err
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigc

	klog.Infof("Received signal %v, exiting.", sig)
	if err := driver.Shutdown(ctx); err != nil {
		klog.Errorf("Unable to cleanly shut down the driver: %v", err)
	}
	return nil
}

func main() {
	klog.InitFlags(nil)
	flags, err := parseFlags(flag.CommandLine, os.Args[1:], os.LookupEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	if err := run(context.Background(), flags); err != nil {
		klog.Errorf("Error: %v", err)
		klog.Flush()
		os.Exit(1)
	}
	klog.Flush()
}
