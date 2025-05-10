// Copyright 2023 Inter Corporation. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	_ "sigs.k8s.io/yaml"

	"github.com/sirupsen/logrus"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	libmem "github.com/containers/nri-plugins/pkg/resmgr/lib/memory"
	system "github.com/containers/nri-plugins/pkg/sysfs"
)

type plugin struct {
	stub   stub.Stub
	config *pluginConfig
}

type pluginConfig struct {
}

const (
	annotationSuffix = ".memory-policy.nri.io"
)

var (
	sys system.System
	log *logrus.Logger
)

// Configure handles connecting to container runtime's NRI server.
func (p *plugin) Configure(ctx context.Context, config, runtime, version string) (stub.EventMask, error) {
	log.Infof("Connected to %s %s...", runtime, version)
	if config != "" {
		log.Debugf("loading configuration from NRI server")
		if err := p.setConfig([]byte(config)); err != nil {
			return 0, err
		}
		return 0, nil
	}
	return 0, nil
}

// onClose handles losing connection to container runtime.
func (p *plugin) onClose() {
	log.Infof("Connection to the runtime lost, exiting...")
	os.Exit(0)
}

// setConfig applies new plugin configuration.
func (p *plugin) setConfig(config []byte) error {
	// cfg := pluginConfig{}
	// err := yaml.Unmarshal(config, &cfg)
	return nil
}

// pprintCtr() returns unique human readable container name.
func pprintCtr(pod *api.PodSandbox, ctr *api.Container) string {
	return fmt.Sprintf("%s/%s:%s", pod.GetNamespace(), pod.GetName(), ctr.GetName())
}

// associate adds new key-value pair to a map, or updates existing
// pair if called with override. Returns true if added/updated.
func associate(m map[string]string, key, value string, override bool) bool {
	if _, exists := m[key]; override || !exists {
		m[key] = value
		return true
	}
	return false
}

// effectiveAnnotations returns map of annotation key prefixes and
// values that are effective for a container.
// Example: a container-specific pod annotation
//
//	mode.memory-policy.nri.io/CTRNAME: MPOL_INTERLEAVE
//	nodes.memory-policy.nri.io/CTRNAME: same-package
//	flags.memory-policy.nri.io/CTRNAME: MPOL_F_STATIC_NODES
//
// shows up as
//
//	effAnn["mode"] = "MPOL_INTERLEAVE"
//	effAnn["nodes"] = "same-package"
//	effAnn["flags"] = "MPOL_F_STATIC_NODES"
func effectiveAnnotations(pod *api.PodSandbox, ctr *api.Container) map[string]string {
	effAnn := map[string]string{}
	for key, value := range pod.GetAnnotations() {
		annPrefix, hasSuffix := strings.CutSuffix(key, annotationSuffix+"/"+ctr.Name)
		if hasSuffix {
			// Override possibly already found pod-level annotation.
			log.Tracef("- found container-specific annotation %q", key)
			associate(effAnn, annPrefix, value, true)
			effAnn[annPrefix] = value
			continue
		}
		annPrefix, hasSuffix = strings.CutSuffix(key, annotationSuffix)
		if hasSuffix {
			// Do not override if there already is a
			// container-level annotation.
			if associate(effAnn, annPrefix, value, false) {
				log.Tracef("- found pod-level annotation %q", key)
			} else {
				log.Tracef("- ignoring pod-level annotation %q due to a container-level annotation", key)
			}
			continue
		}
		log.Tracef("- ignoring annotation %q", key)
	}
	return effAnn
}

// CreateContainer modifies container when it is being created.
func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	annMode := ""
	annNodes := ""
	annFlags := ""
	ppName := pprintCtr(pod, ctr)
	log.Tracef("CreateContainer %s", ppName)
	for annPrefix, value := range effectiveAnnotations(pod, ctr) {
		switch {
		case annPrefix == "mode":
			annMode = value
		case annPrefix == "nodes":
			annNodes = value
		case annPrefix == "flags":
			annFlags = value
		}
	}
	if annMode == "" {
		log.Tracef("no memory policy mode specified for %s", ppName)
		return nil, nil, nil
	}

	mode, ok := api.MpolMode_value[annMode]
	if !ok {
		log.Errorf("invalid memory policy mode %q for %s", annMode, ppName)
		return nil, nil, fmt.Errorf("invalid memory policy mode %q", annMode)
	}

	flags := []api.MpolFlag{}
	if annFlags != "" {
		for _, annFlag := range strings.Split(annFlags, ",") {
			if annFlag == "" {
				continue
			}
			annFlag = strings.TrimSpace(annFlag)
			if flag, ok := api.MpolFlag_value[annFlag]; ok {
				flags = append(flags, api.MpolFlag(flag))
			} else {
				log.Errorf("invalid memory policy flag %q for %s", annFlag, ppName)
				return nil, nil, fmt.Errorf("invalid memory policy flag %q", annFlag)
			}
		}
	}

	nodes := ""
	if annNodes != "" {
		nodeIds := sys.NodeIDs()
		ctrCpus := ctr.GetLinux().GetResources().GetCpu().GetCpus()
		switch {
		case annNodes == "same-package":
			// Use all nodes from the same package as the container's CPUs
			if ctrCpus != "" {
				log.Errorf("NOT IMPLEMENTED: get nodes for packages of CPUs %q", ctrCpus)
				return nil, nil, fmt.Errorf("NOT IMPLEMENTED: nodes:same-package for %s", ppName)
			}
		case annNodes == "same-nodes":
			if ctrCpus != "" {
				log.Errorf("NOT IMPLEMENTED: get nodes for CPUs %q", ctrCpus)
				return nil, nil, fmt.Errorf("NOT IMPLEMENTED: nodes:same-nodes for %s", ppName)
			}
		}
		nodes = libmem.NewNodeMask(nodeIds...).MemsetString()
	}
	ca := api.ContainerAdjustment{}
	ca.SetLinuxMemoryPolicy(api.MpolMode(mode), nodes, flags...)
	log.Debugf("CreateContainer %s: adjust: %+v", ppName, ca)
	return &ca, nil, nil
}

func main() {
	var (
		pluginName  string
		pluginIdx   string
		configFile  string
		err         error
		verbose     bool
		veryVerbose bool
	)

	log = logrus.StandardLogger()
	log.SetFormatter(&logrus.TextFormatter{
		PadLevelText: true,
	})

	flag.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	flag.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	flag.StringVar(&configFile, "config", "", "configuration file name")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.BoolVar(&veryVerbose, "vv", false, "very verbose output")
	flag.Parse()

	if verbose {
		log.SetLevel(logrus.DebugLevel)
	}
	if veryVerbose {
		log.SetLevel(logrus.TraceLevel)
	}

	p := &plugin{}

	if configFile != "" {
		log.Debugf("read configuration from %q", configFile)
		config, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("error reading configuration file %q: %s", configFile, err)
		}
		if err = p.setConfig(config); err != nil {
			log.Fatalf("error applying configuration from file %q: %s", configFile, err)
		}
	}

	sys, err = system.DiscoverSystem(system.DiscoverCPUTopology)
	if err != nil {
		log.Fatalf("failed to discover CPU topology needed by -dist: %v", err)
	}

	opts := []stub.Option{
		stub.WithOnClose(p.onClose),
	}
	if pluginName != "" {
		opts = append(opts, stub.WithPluginName(pluginName))
	}
	if pluginIdx != "" {
		opts = append(opts, stub.WithPluginIdx(pluginIdx))
	}

	if p.stub, err = stub.New(p, opts...); err != nil {
		log.Fatalf("failed to create plugin stub: %v", err)
	}

	if err = p.stub.Run(context.Background()); err != nil {
		log.Errorf("plugin exited (%v)", err)
		os.Exit(1)
	}
}
