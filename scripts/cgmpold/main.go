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

// cgmpold steers memory allocations of cgroups across NUMA nodes
// according to a configuration file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
	"k8s.io/utils/cpuset"

	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
	logger "github.com/containers/nri-plugins/pkg/log"
	"github.com/containers/nri-plugins/pkg/mpolinject"
)

// CgroupConfig configures the steering of one cgroup.
type CgroupConfig struct {
	// CgroupPath is the cgroup v2 directory.
	CgroupPath string `json:"cgroupPath" yaml:"cgroupPath"`
	// Name is the name of the cgroup in log messages.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// DRAMNodes and CXLNodes are NUMA node lists, for example "0,2-3".
	DRAMNodes string `json:"dramNodes,omitempty" yaml:"dramNodes,omitempty"`
	CXLNodes  string `json:"cxlNodes,omitempty" yaml:"cxlNodes,omitempty"`
	// DRAMQuota and CXLQuota are memory sizes, for example "40Mi".
	DRAMQuota string `json:"dramQuota,omitempty" yaml:"dramQuota,omitempty"`
	CXLQuota  string `json:"cxlQuota,omitempty" yaml:"cxlQuota,omitempty"`
	// Policy tells how the quotas are consumed.
	cgmpolmgr.Policy `yaml:",inline"`
}

// Config is the daemon configuration.
type Config struct {
	Cgroups []CgroupConfig `json:"cgroups" yaml:"cgroups"`
}

func main() {
	configFile := flag.String("c", "", "configuration file (JSON or YAML)")
	verbose := flag.Bool("v", false, "print debug messages of memory steering")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -c CONFIG [-v]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "cgmpold - NUMA memory policy daemon for cgroup v2\n\n")
		fmt.Fprintf(os.Stderr, "The daemon steers memory allocations of the configured cgroups\n")
		fmt.Fprintf(os.Stderr, "across NUMA nodes. It throttles a cgroup with memory.high after\n")
		fmt.Fprintf(os.Stderr, "every step of new allocations and updates the memory policy of\n")
		fmt.Fprintf(os.Stderr, "the processes in the cgroup before letting it continue.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nConfiguration file (JSON or YAML, detected by extension):\n")
		fmt.Fprintf(os.Stderr, "  cgroups:\n")
		fmt.Fprintf(os.Stderr, "  - cgroupPath: /sys/fs/cgroup/mygroup\n")
		fmt.Fprintf(os.Stderr, "    dramNodes: \"0\"\n")
		fmt.Fprintf(os.Stderr, "    cxlNodes: \"1\"\n")
		fmt.Fprintf(os.Stderr, "    dramQuota: 4Gi\n")
		fmt.Fprintf(os.Stderr, "    cxlQuota: 16Gi\n")
		fmt.Fprintf(os.Stderr, "    memoryUseOrder: first-dram\n")
		fmt.Fprintf(os.Stderr, "    minStep: 256Mi\n")
		fmt.Fprintf(os.Stderr, "    maxStep: 1Gi\n")
		fmt.Fprintf(os.Stderr, "\nRequires root privileges.\n")
	}
	flag.Parse()

	if *configFile == "" {
		fmt.Fprintf(os.Stderr, "Error: configuration file is required\n\n")
		flag.Usage()
		os.Exit(1)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Error: must run as root\n")
		os.Exit(1)
	}
	if *verbose {
		logger.EnableDebug("cgmpolmgr")
	}

	config, err := loadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	managers := make([]*cgmpolmgr.Manager, 0, len(config.Cgroups))
	for i, cgroupCfg := range config.Cgroups {
		manager, err := newManager(cgroupCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid configuration of cgroup %d (%s): %v\n", i, cgroupCfg.CgroupPath, err)
			os.Exit(1)
		}
		managers = append(managers, manager)
	}

	started := make([]*cgmpolmgr.Manager, 0, len(managers))
	for i, manager := range managers {
		if err := manager.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start steering cgroup %s: %v\n", config.Cgroups[i].CgroupPath, err)
			stopAll(started)
			os.Exit(1)
		}
		started = append(started, manager)
	}
	fmt.Printf("cgmpold daemon started successfully, pid %d, steering %d cgroup(s)\n", os.Getpid(), len(started))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println("Shutting down...")
	stopAll(started)
	fmt.Println("cgmpold daemon stopped")
}

// stopAll stops the managers.
func stopAll(managers []*cgmpolmgr.Manager) {
	for _, manager := range managers {
		manager.Stop()
	}
}

// newManager returns a manager for the cgroup configuration.
func newManager(cfg CgroupConfig) (*cgmpolmgr.Manager, error) {
	if cfg.CgroupPath == "" {
		return nil, fmt.Errorf("cgroupPath is required")
	}
	var mem cgmpolmgr.MemoryTypes
	var err error
	if mem.DRAMNodes, err = parseNodes(cfg.DRAMNodes); err != nil {
		return nil, fmt.Errorf("invalid dramNodes: %w", err)
	}
	if mem.CXLNodes, err = parseNodes(cfg.CXLNodes); err != nil {
		return nil, fmt.Errorf("invalid cxlNodes: %w", err)
	}
	if mem.DRAMQuota, err = parseSize(cfg.DRAMQuota); err != nil {
		return nil, fmt.Errorf("invalid dramQuota: %w", err)
	}
	if mem.CXLQuota, err = parseSize(cfg.CXLQuota); err != nil {
		return nil, fmt.Errorf("invalid cxlQuota: %w", err)
	}
	if err := mpolinject.ValidateNumaNodes(append(append([]int{}, mem.DRAMNodes...), mem.CXLNodes...)); err != nil {
		return nil, err
	}
	plan, err := cfg.Plan(mem)
	if err != nil {
		return nil, err
	}
	var opts []cgmpolmgr.Option
	if cfg.Name != "" {
		opts = append(opts, cgmpolmgr.WithName(cfg.Name))
	}
	return cgmpolmgr.New(cfg.CgroupPath, plan, opts...)
}

// parseNodes returns the nodes in a node list such as "0,2-3". An
// empty list returns nil.
func parseNodes(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	nodes, err := cpuset.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	return nodes.List(), nil
}

// parseSize returns the bytes in a memory size such as "40Mi". An
// empty size returns 0.
func parseSize(s string) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	return cgmpolmgr.ParseMemorySize(s)
}

// loadConfig returns the configuration in the JSON or YAML file.
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	var config Config
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	}
	if len(config.Cgroups) == 0 {
		return nil, fmt.Errorf("no cgroups configured")
	}
	return &config, nil
}
