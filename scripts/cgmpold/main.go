// Copyright The NRI Plugins Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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

	"github.com/containers/nri-plugins/pkg/cgmemnotify"
	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
	"github.com/containers/nri-plugins/pkg/mpolinject"
	"gopkg.in/yaml.v3"
)

// Config represents the daemon configuration
type Config struct {
	Cgroups []cgmpolmgr.CgroupConfig `json:"cgroups" yaml:"cgroups"`
}

func main() {
	// Define command-line flags
	configFile := flag.String("c", "", "Configuration file (JSON or YAML)")
	showHelp := flag.Bool("h", false, "Show help message")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "cgmpold - NUMA memory policy daemon for cgroup v2\n\n")
		fmt.Fprintf(os.Stderr, "This daemon monitors cgroup v2 memory usage and dynamically adjusts\n")
		fmt.Fprintf(os.Stderr, "NUMA memory policies based on configured watermarks and memory.high\n")
		fmt.Fprintf(os.Stderr, "throttling events.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nConfiguration file format:\n")
		fmt.Fprintf(os.Stderr, "  Supports both JSON and YAML formats (auto-detected by extension)\n")
		fmt.Fprintf(os.Stderr, "  See config.example.json or config.example.yaml for examples\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s -c config.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -c /etc/cgmpold/config.yaml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nRequires root privileges to modify cgroup settings.\n")
	}

	flag.Parse()

	// Show help if requested
	if *showHelp {
		flag.Usage()
		os.Exit(0)
	}

	// Check if config file was provided
	if *configFile == "" {
		fmt.Fprintf(os.Stderr, "Error: configuration file is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Check privileges
	if err := cgmemnotify.CheckPrivileges(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Load configuration
	config, err := loadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting cgmpold with %d cgroup(s)\n", len(config.Cgroups))

	// Validate NUMA nodes in configuration
	for _, cgroupCfg := range config.Cgroups {
		for _, mp := range cgroupCfg.MemoryPolicies {
			parsed, err := cgmpolmgr.ParseMemoryPolicy(mp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid memory policy in %s: %v\n", cgroupCfg.Path, err)
				os.Exit(1)
			}
			if err := mpolinject.ValidateNumaNodes(parsed.Nodes); err != nil {
				fmt.Fprintf(os.Stderr, "Invalid NUMA nodes %v for %s: %v\n", parsed.Nodes, cgroupCfg.Path, err)
				os.Exit(1)
			}
		}
	}

	// Create managers for each cgroup
	managers := make([]*cgmpolmgr.Manager, 0, len(config.Cgroups))
	for _, cgroupCfg := range config.Cgroups {
		manager, err := cgmpolmgr.NewManager(cgroupCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create manager for %s: %v\n", cgroupCfg.Path, err)
			continue
		}
		managers = append(managers, manager)
	}

	if len(managers) == 0 {
		fmt.Fprintf(os.Stderr, "No cgroups to manage\n")
		os.Exit(1)
	}

	// Initialize memory policies for all cgroups
	for _, manager := range managers {
		if err := manager.Initialize(); err != nil {
			cgConfig := manager.GetConfig()
			fmt.Fprintf(os.Stderr, "Failed to initialize memory policy for %s: %v\n",
				cgConfig.Path, err)
		}
	}

	// Start watching all cgroups
	for _, manager := range managers {
		if err := manager.Start(); err != nil {
			cgConfig := manager.GetConfig()
			fmt.Fprintf(os.Stderr, "Failed to start watcher for %s: %v\n",
				cgConfig.Path, err)
		}
	}

	fmt.Printf("cgmpold daemon started successfully, pid %d\n", os.Getpid())

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	fmt.Println("\nShutting down...")

	// Stop all watchers
	for _, manager := range managers {
		manager.Stop()
	}

	fmt.Println("cgmpold daemon stopped")
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config

	// Determine format based on file extension
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		// Try JSON first, then YAML
		if err := json.Unmarshal(data, &config); err != nil {
			// If JSON fails, try YAML
			if yamlErr := yaml.Unmarshal(data, &config); yamlErr != nil {
				return nil, fmt.Errorf("failed to parse config as JSON or YAML: json=%v, yaml=%v", err, yamlErr)
			}
		}
	}

	// Validate configuration
	for i, cgroup := range config.Cgroups {
		if cgroup.Path == "" {
			return nil, fmt.Errorf("cgroup %d: path is required", i)
		}
		if len(cgroup.MemoryPolicies) == 0 {
			return nil, fmt.Errorf("cgroup %s: at least one memory policy is required", cgroup.Path)
		}
		for j, mp := range cgroup.MemoryPolicies {
			// Parse and validate each memory policy
			_, err := cgmpolmgr.ParseMemoryPolicy(mp)
			if err != nil {
				return nil, fmt.Errorf("cgroup %s, memoryPolicy %d: %w", cgroup.Path, j, err)
			}
		}
	}

	return &config, nil
}
