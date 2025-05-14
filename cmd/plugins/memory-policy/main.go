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
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/sirupsen/logrus"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	libmem "github.com/containers/nri-plugins/pkg/resmgr/lib/memory"
	system "github.com/containers/nri-plugins/pkg/sysfs"
	"github.com/containers/nri-plugins/pkg/utils/cpuset"
	idset "github.com/intel/goresctrl/pkg/utils"
)

type plugin struct {
	stub   stub.Stub
	config *pluginConfig
}

type pluginConfig struct {
}

type annParameters struct {
	Mode  string   `json:"mode"`
	Nodes string   `json:"nodes"`
	Flags []string `json:"flags,omitempty"`
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
// parameters.memory-policy.nri.io/container.CTRNAME: |+
//
//	mode: MPOL_INTERLEAVE
//	nodes: cpu-packages
//	flags: [MPOL_F_STATIC_NODES]
func effectiveAnnotations(pod *api.PodSandbox, ctr *api.Container) map[string]string {
	effAnn := map[string]string{}
	for key, value := range pod.GetAnnotations() {
		annPrefix, hasSuffix := strings.CutSuffix(key, annotationSuffix+"/"+ctr.Name)
		if hasSuffix {
			// Override possibly already found pod-level annotation.
			log.Tracef("- found container-specific annotation %q", key)
			associate(effAnn, annPrefix, value, true)
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

func getParametersAnnotation(ann map[string]string) (*annParameters, error) {
	if value, ok := ann["parameters"]; ok {
		params := &annParameters{}
		if err := yaml.Unmarshal([]byte(value), params); err != nil {
			return nil, fmt.Errorf("failed to unmarshal parameters: %w", err)
		}
		return params, nil
	}
	return nil, nil
}

func applyParameters(ctr *api.Container, ppName string, parameters *annParameters) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	var err error
	mode, ok := api.MpolMode_value[parameters.Mode]
	if !ok {
		log.Errorf("invalid memory policy mode %q for %s", parameters.Mode, ppName)
		return nil, nil, fmt.Errorf("invalid memory policy mode %q", parameters.Mode)
	}

	nodeMask := libmem.NewNodeMask()
	ctrCpuset := sys.OnlineCPUs()
	if ctrCpus := ctr.GetLinux().GetResources().GetCpu().GetCpus(); ctrCpus != "" {
		ctrCpuset, err = cpuset.Parse(ctrCpus)
		if err != nil {
			log.Errorf("failed to parse CPUs %q: %v", ctrCpus, err)
			return nil, nil, fmt.Errorf("failed to parse CPUs %q: %v", ctrCpus, err)
		}
	}
	allowedMemsMask := libmem.NewNodeMask(sys.NodeIDs()...)
	ctrMems := ctr.GetLinux().GetResources().GetCpu().GetMems()
	if ctrMems != "" {
		if parsedMask, err := libmem.ParseNodeMask(ctrMems); err == nil {
			allowedMemsMask = parsedMask
		} else {
			log.Errorf("failed to parse allowed mems %q: %v", ctrMems, err)
		}
	}

	switch {
	case parameters.Nodes == "allowed-mems":
		nodeMask = allowedMemsMask
		log.Tracef("- allowed-mems, nodes: %q", nodeMask.MemsetString())

	case parameters.Nodes == "cpu-packages":
		pkgs := sys.IDSetForCPUs(ctrCpuset, func(cpu system.CPU) idset.ID {
			return cpu.PackageID()
		})
		nodeMask = libmem.NewNodeMask()
		log.Tracef("nodeids %v", sys.NodeIDs())
		for _, nodeId := range sys.NodeIDs() {
			log.Tracef("node %d: package %d", nodeId, sys.Node(nodeId).PackageID())
			nodePkgId := sys.Node(nodeId).PackageID()
			if pkgs.Has(nodePkgId) {
				nodeMask = nodeMask.Set(nodeId)
			}
		}
		log.Tracef("- cpu-packages with CPUs %q, packages: %q, nodes: %q", ctrCpuset, pkgs, nodeMask.MemsetString())

	case parameters.Nodes == "cpu-nodes":
		nodeIds := sys.IDSetForCPUs(ctrCpuset, func(cpu system.CPU) idset.ID {
			return cpu.NodeID()
		})
		nodeMask = libmem.NewNodeMask(nodeIds.Members()...)
		log.Tracef("- cpu-nodes with CPUs %q, nodes: %q", ctrCpuset, nodeMask.MemsetString())

	case strings.HasPrefix(parameters.Nodes, "max-dist:"):
		maxDist := parameters.Nodes[len("max-dist:"):]
		maxDistInt, err := strconv.Atoi(maxDist)
		if err != nil {
			log.Errorf("failed to parse max-dist %q: %v", maxDist, err)
			return nil, nil, fmt.Errorf("failed to parse max-dist %q: %v", maxDist, err)
		}
		nodeMask = libmem.NewNodeMask()
		fromNodes := sys.IDSetForCPUs(ctrCpuset, func(cpu system.CPU) idset.ID {
			return cpu.NodeID()
		})
		for _, fromNode := range fromNodes.Members() {
			for _, toNode := range sys.NodeIDs() {
				if sys.NodeDistance(fromNode, toNode) <= maxDistInt {
					log.Tracef("node %d is within distance %d from node %d (max-dist is %d)", toNode, maxDistInt, fromNode, sys.NodeDistance(fromNode, toNode))
					nodeMask = nodeMask.Set(toNode)
				}
			}
		}
		log.Tracef("- max-dist %d from CPU nodes %q of CPUs %q, nodes %q", maxDistInt, fromNodes, ctrCpuset, nodeMask.MemsetString())

	case parameters.Nodes[0] >= '0' && parameters.Nodes[0] <= '9':
		nodeMask, err = libmem.ParseNodeMask(parameters.Nodes)
		if err != nil {
			log.Errorf("failed to parse nodes %q: %v", parameters.Nodes, err)
			return nil, nil, fmt.Errorf("failed to parse nodes %q: %v", parameters.Nodes, err)
		}

	default:
		return nil, nil, fmt.Errorf("invalid nodes: %q", parameters.Nodes)
	}

	flags := []api.MpolFlag{}
	if len(parameters.Flags) > 0 {
		for _, flag := range parameters.Flags {
			flag = strings.TrimSpace(flag)
			if flagValue, ok := api.MpolFlag_value[flag]; ok {
				flags = append(flags, api.MpolFlag(flagValue))
			} else {
				log.Errorf("invalid memory policy flag %q for %s", flag, ppName)
				return nil, nil, fmt.Errorf("invalid memory policy flag %q", flag)
			}
		}
	}

	nodes := nodeMask.MemsetString()
	log.Tracef("CreateContainer %s: nodes: %q allowed: %q", ppName, nodes, ctrMems)
	if (nodeMask&allowedMemsMask) != nodeMask {
		log.Warningf("some memory policy nodes (%s) are not allowed (%s) for container %s", nodes, allowedMemsMask.MemsetString(), ppName)
	}

	ca := &api.ContainerAdjustment{}
	ca.SetLinuxMemoryPolicy(api.MpolMode(mode), nodes, flags...)
	log.Debugf("CreateContainer %s: adjust: %+v", ppName, ca)
	return ca, nil, nil
}

// CreateContainer modifies container when it is being created.
func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	ppName := pprintCtr(pod, ctr)
	log.Tracef("CreateContainer %s", ppName)

	effAnn := effectiveAnnotations(pod, ctr)
	parameters, err := getParametersAnnotation(effAnn)
	if err != nil {
		log.Errorf("invalid parameters annotation in %s: %v", ppName, err)
		return nil, nil, err
	}
	if parameters != nil {
		return applyParameters(ctr, ppName, parameters)
	}

	return nil, nil, nil
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
		log.Fatalf("failed to discover CPU topology: %v", err)
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
