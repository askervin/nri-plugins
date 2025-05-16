// Copyright 2025 Inter Corporation. All Rights Reserved.
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
	config *Config
}

type Config struct {
	InjectMpolset bool                 `json:"injectMpolset,omitempty"`
	Classes       []*MemoryPolicyClass `json:"classes,omitempty"`
}

type MemoryPolicyClass struct {
	Name   string        `json:"name"`
	Policy *MemoryPolicy `json:"policy"`
}

type MemoryPolicy struct {
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
	cfg := &Config{}
	if err := yaml.Unmarshal(config, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal configuration: %w", err)
	}
	p.config = cfg
	log.Debugf("plugin configuration: %+v", p.config)
	return nil
}

// pprintCtr() returns unique human readable container name.
func pprintCtr(pod *api.PodSandbox, ctr *api.Container) string {
	return fmt.Sprintf("%s/%s:%s", pod.GetNamespace(), pod.GetName(), ctr.GetName())
}

// effectiveAnnotations returns map of annotation key prefixes and
// values that are effective for a container. It checks for
// container-specific annotations first, and if not found, it
// returns pod-level annotations. "policy" and "class" annotations
// are mutually exclusive.
//
// Example: a container-specific pod annotation
//
// class.memory-policy.nri.io: my-default-class-for-containers-in-pod
// policy.memory-policy.nri.io/container.my-special-container: |+
//
//	mode: MPOL_INTERLEAVE
//	nodes: cpu-packages
//	flags: [MPOL_F_STATIC_NODES]
func effectiveAnnotations(pod *api.PodSandbox, ctr *api.Container) map[string]string {
	effAnn := map[string]string{}
	for key, value := range pod.GetAnnotations() {
		annPrefix, hasSuffix := strings.CutSuffix(key, annotationSuffix+"/container."+ctr.Name)
		if hasSuffix {
			// Override possibly already found pod-level annotation.
			log.Tracef("- found container-specific annotation %q", key)
			if annPrefix == "class" || annPrefix == "policy" {
				delete(effAnn, "class")
				delete(effAnn, "policy")
			}
			effAnn[annPrefix] = value
			continue
		}
		annPrefix, hasSuffix = strings.CutSuffix(key, annotationSuffix)
		if hasSuffix {
			if annPrefix == "class" || annPrefix == "policy" {
				_, hasClass := effAnn["class"]
				_, hasPolicy := effAnn["policy"]
				if hasClass || hasPolicy {
					log.Tracef("- ignoring pod-level annotation %q due to a container-level annotation", key)
					continue
				}
			}
			log.Tracef("- found pod-level annotation %q", key)
			effAnn[annPrefix] = value
			continue
		}
		log.Tracef("- ignoring annotation %q", key)
	}
	return effAnn
}

func takePolicyAnnotation(ann map[string]string) (*MemoryPolicy, error) {
	if value, ok := ann["policy"]; ok {
		delete(ann, "policy")
		policy := &MemoryPolicy{}
		if err := yaml.Unmarshal([]byte(value), policy); err != nil {
			return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
		}
		return policy, nil
	}
	return nil, nil
}

func (p *plugin) takeClassAnnotation(ann map[string]string) (*MemoryPolicyClass, error) {
	if value, ok := ann["class"]; ok {
		delete(ann, "class")
		for _, class := range p.config.Classes {
			if class.Name == value {
				return class, nil
			}
		}
		return nil, fmt.Errorf("class %q not found in configuration", value)
	}
	return nil, nil
}

func applyPolicy(ctr *api.Container, policy *MemoryPolicy) (*api.ContainerAdjustment, error) {
	var err error
	mode, ok := api.MpolMode_value[policy.Mode]
	if !ok {
		return nil, fmt.Errorf("invalid memory policy mode %q", policy.Mode)
	}

	nodeMask := libmem.NewNodeMask()
	ctrCpuset := sys.OnlineCPUs()
	if ctrCpus := ctr.GetLinux().GetResources().GetCpu().GetCpus(); ctrCpus != "" {
		ctrCpuset, err = cpuset.Parse(ctrCpus)
		if err != nil {
			return nil, fmt.Errorf("failed to parse allowed CPUs %q: %v", ctrCpus, err)
		}
	}
	allowedMemsMask := libmem.NewNodeMask(sys.NodeIDs()...)
	ctrMems := ctr.GetLinux().GetResources().GetCpu().GetMems()
	if ctrMems != "" {
		if parsedMask, err := libmem.ParseNodeMask(ctrMems); err == nil {
			allowedMemsMask = parsedMask
		} else {
			return nil, fmt.Errorf("failed to parse allowed mems %q: %v", ctrMems, err)
		}
	}
	log.Tracef("- allowed mems: %s, cpus %s", ctrMems, ctrCpuset)

	switch {
	case policy.Nodes == "all":
		nodeMask = libmem.NewNodeMask(sys.NodeIDs()...)
		log.Tracef("- nodes %q (all)", nodeMask.MemsetString())

	case policy.Nodes == "allowed-mems":
		nodeMask = allowedMemsMask
		log.Tracef("- nodes: %q (allowed-mems)", nodeMask.MemsetString())

	case policy.Nodes == "cpu-packages":
		pkgs := sys.IDSetForCPUs(ctrCpuset, func(cpu system.CPU) idset.ID {
			return cpu.PackageID()
		})
		nodeMask = libmem.NewNodeMask()
		for _, nodeId := range sys.NodeIDs() {
			nodePkgId := sys.Node(nodeId).PackageID()
			if pkgs.Has(nodePkgId) {
				nodeMask = nodeMask.Set(nodeId)
			}
		}
		log.Tracef("- nodes: %q (cpu-packages %q)", nodeMask.MemsetString(), pkgs)

	case policy.Nodes == "cpu-nodes":
		nodeIds := sys.IDSetForCPUs(ctrCpuset, func(cpu system.CPU) idset.ID {
			return cpu.NodeID()
		})
		nodeMask = libmem.NewNodeMask(nodeIds.Members()...)
		log.Tracef("- nodes: %q (cpu-nodes)", nodeMask.MemsetString())

	case strings.HasPrefix(policy.Nodes, "max-dist:"):
		maxDist := policy.Nodes[len("max-dist:"):]
		maxDistInt, err := strconv.Atoi(maxDist)
		if err != nil {
			return nil, fmt.Errorf("failed to parse max-dist %q: %v", maxDist, err)
		}
		nodeMask = libmem.NewNodeMask()
		fromNodes := sys.IDSetForCPUs(ctrCpuset, func(cpu system.CPU) idset.ID {
			return cpu.NodeID()
		})
		for _, fromNode := range fromNodes.Members() {
			for _, toNode := range sys.NodeIDs() {
				if sys.NodeDistance(fromNode, toNode) <= maxDistInt {
					nodeMask = nodeMask.Set(toNode)
				}
			}
		}
		log.Tracef("- nodes %q (max-dist %d from CPU nodes %q)", nodeMask.MemsetString(), maxDistInt, fromNodes)

	case policy.Nodes[0] >= '0' && policy.Nodes[0] <= '9':
		nodeMask, err = libmem.ParseNodeMask(policy.Nodes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse nodes %q: %v", policy.Nodes, err)
		}
		log.Tracef("- nodes %q (hardcoded)", nodeMask.MemsetString())

	default:
		return nil, fmt.Errorf("invalid nodes: %q", policy.Nodes)
	}

	flags := []api.MpolFlag{}
	if len(policy.Flags) > 0 {
		for _, flag := range policy.Flags {
			flag = strings.TrimSpace(flag)
			if flagValue, ok := api.MpolFlag_value[flag]; ok {
				flags = append(flags, api.MpolFlag(flagValue))
			} else {
				return nil, fmt.Errorf("invalid memory policy flag %q", flag)
			}
		}
	}

	nodes := nodeMask.MemsetString()
	if (nodeMask & allowedMemsMask) != nodeMask {
		log.Debugf("some memory policy nodes (%s) are not allowed (%s)", nodes, allowedMemsMask.MemsetString())
	}

	ca := &api.ContainerAdjustment{}
	ca.SetLinuxMemoryPolicy(api.MpolMode(mode), nodes, flags...)
	return ca, nil
}

// CreateContainer modifies container when it is being created.
func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	var ca *api.ContainerAdjustment
	var err error
	ppName := pprintCtr(pod, ctr)
	log.Tracef("CreateContainer %s", ppName)

	effAnn := effectiveAnnotations(pod, ctr)
	policy, err := takePolicyAnnotation(effAnn)
	if err != nil {
		log.Errorf("CreateContainer %s: invalid policy annotation: %v", ppName, err)
		return nil, nil, err
	}
	if policy != nil {
		ca, err = applyPolicy(ctr, policy)
		if err != nil {
			log.Errorf("CreateContainer %s failed to apply policy: %v", ppName, err)
			return nil, nil, err
		}
		log.Debugf("CreateContainer %s: from annotated policy: %s", ppName, ca)
	}

	class, err := p.takeClassAnnotation(effAnn)
	if err != nil {
		log.Errorf("invalid class annotation in %s: %v", ppName, err)
		return nil, nil, err
	}
	if ca == nil && class != nil && class.Policy != nil {
		ca, err := applyPolicy(ctr, class.Policy)
		if err != nil {
			log.Errorf("CreateContainer %s failed to apply policy: %v", ppName, err)
			return nil, nil, err
		}
		log.Debugf("CreateContainer %s: from annotated class %q: %s", ppName, class.Name, ca)
	}

	// Check for unknown annotations.
	for ann := range effAnn {
		log.Errorf("unknown annotation in %s: %s%s", ppName, ann, annotationSuffix)
		return nil, nil, fmt.Errorf("unknown annotation %s%s", ann, annotationSuffix)
	}

	if p.config.InjectMpolset && ca != nil && ca.Linux != nil && ca.Linux.MemoryPolicy != nil {
		log.Debugf("CreateContainer %s: injecting mpolset, workaround for old container runtimes", ppName)
		mpol := ca.Linux.MemoryPolicy
		ca.Linux.MemoryPolicy = nil
		ca.AddMount(&api.Mount{
			Source:      "TODO-WHERE-TO-GET-THIS",
			Destination: "/.nri-memory-policy",
			Type:        "bind",
			Options:     []string{"bind", "ro", "rslave"},
		})
		flags := []string{}
		for _, flag := range mpol.Flags {
			if flagName, ok := api.MpolFlag_name[int32(flag)]; ok {
				flags = append(flags, flagName)
			} else {
				log.Errorf("invalid memory policy flag %q", flag)
				return nil, nil, fmt.Errorf("invalid memory policy flag %q", flag)
			}
		}

		mpolsetArgs := []string{
			"/.nri-memory-policy/mpolset",
			"--mode %s", api.MpolMode_name[int32(mpol.Mode)],
			"--nodes", mpol.Nodes,
		}
		if len(flags) > 0 {
			mpolsetArgs = append(mpolsetArgs, "--flags", strings.Join(flags, ","))
		}
		mpolsetArgs = append(mpolsetArgs, "--")

		// Prefix the command with mpolset.
		ca.SetArgs(append(mpolsetArgs, ctr.GetArgs()...))
		log.Debugf("CreateContainer %s: new args: %q", ppName, ca.GetArgs())
	}

	return ca, nil, nil
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
