// Copyright 2023 Intel Corporation. All Rights Reserved.
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
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"gopkg.in/yaml.v2"

	"github.com/sirupsen/logrus"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

type plugin struct {
	stub   stub.Stub
	mask   stub.EventMask
	config *pluginConfig
}

type pluginConfig struct {
	// Classes define how memory of all workloads in each QoS
	// class should be managed.
	Classes     []QoSClass
}

type QoSClass struct {
	// Name of the QoS class. Can be a built-in Kubernetes QoS class
	// (BestEffort, Burstable, Guaranteed) or a custom class in
	// which a pod or container is annotated. Annotation examples:
	// annotations:
	//   # The default for all containers in the pod:
	//   class.memtierd.nri.io: swap
	//   # Override the default for CONTAINERNAME:
	//   class.memtierd.nri.io/CONTAINERNAME: noswap
	Name string

	// MemtierdConfig is a string that contains full configuration
	// for memtierd. If non-empty, memtierd will be launched to
	// track each container of this QoS class.
	MemtierdConfig string
}

type options struct {
	HostRoot string
}

const (
	annotationSuffix = ".memtierd.nri.io"
)

var opt = options{}

var (
	log *logrus.Logger
)

func (p *plugin) Configure(ctx context.Context, config, runtime, version string) (stub.EventMask, error) {
	log.Infof("Connected to %s %s...", runtime, version)

	if config != "" {
		log.Infof("loading configuration from NRI server:\n%s", config)
		cfg := pluginConfig{}
		err := yaml.Unmarshal([]byte(config), &cfg)
		if err != nil {
			return 0, fmt.Errorf("failed to parse provided configuration: %w", err)
		}
		p.config = &cfg
		return 0, nil
	}

	return 0, nil
}

// pprintCtr() returns human readable container name that is
// unique to the node.
func pprintCtr(pod *api.PodSandbox, ctr *api.Container) string {
	return fmt.Sprintf("%s/%s:%s", pod.GetNamespace(), pod.GetName(), ctr.GetName())
}

func loggedErrorf(s string, args... any) error {
	err := fmt.Errorf(s, args...)
	log.Errorf("%s", err)
	return err
}

// associate adds new key-value pair to a map, or updates existing
// pair if called with override. Returns true if added/updated.
func associate(m *map[string]string, key, value string, override bool) bool {
	if _, exists := (*m)[key]; override || !exists {
		(*m)[key] = value
		return true
	}
	return false
}

// effectiveAnnotations returns map of annotation key prefixes and
// values that are effective for a container.
// Example: a container-specific pod annotation
//
//	memory.high.memory-qos.nri.io/CTRNAME: 10000000
//
// shows up as
//
//	effAnn["memory.high"] = "10000000"
func effectiveAnnotations(pod *api.PodSandbox, ctr *api.Container) *map[string]string {
	effAnn := map[string]string{}
	for key, value := range pod.GetAnnotations() {
		annPrefix, hasSuffix := strings.CutSuffix(key, annotationSuffix+"/"+ctr.Name)
		if hasSuffix {
			// Override possibly already found pod-level annotation.
			log.Tracef("- found container-specific annotation %q", key)
			associate(&effAnn, annPrefix, value, true)
			effAnn[annPrefix] = value
			continue
		}
		annPrefix, hasSuffix = strings.CutSuffix(key, annotationSuffix)
		if hasSuffix {
			// Do not override if there already is a
			// container-level annotation.
			if associate(&effAnn, annPrefix, value, false) {
				log.Tracef("- found pod-level annotation %q", key)
			} else {
				log.Tracef("- ignoring pod-level annotation %q due to a container-level annotation", key)
			}
			continue
		}
		log.Tracef("- ignoring annotation %q", key)
	}
	return &effAnn
}

func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	ppName := pprintCtr(pod, ctr)
	annotations := pod.GetAnnotations()
	unified := map[string]string{}
	class := ""
	for key, value := range annotations {
		annPrefix, isMyAnn := strings.CutSuffix(key, annotationSuffix)
		if !isMyAnn {
			continue
		}
		switch annPrefix {
		case "memory.swap.max":
			unified["memory.swap.max"] = value
		case "memory.high":
			unified["memory.high"] = value
		case "class":
			class = value
		default:
			log.Errorf("CreateContainer %s: pod has invalid annotation: %q", ppName, key)
		}
	}
	if len(unified) == 0 {
		return nil, nil, nil
	}
	ca := api.ContainerAdjustment{
		Linux: &api.LinuxContainerAdjustment{
			Resources: &api.LinuxResources{
				Unified: unified,
			},
		},
	}
	log.Infof("CreateContainer %s: class %q, LinuxResources.Unified=%v", ppName, class, ca.Linux.Resources.Unified)
	return &ca, nil, nil
}

func (p *plugin) StartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	var qosClass string
	ppName := pprintCtr(pod, ctr)
	log.Tracef("StartContainer %s", ppName)

	hostRoot := opt.HostRoot

	namespace := pod.GetNamespace()
	podName := pod.GetName()
	containerName := ctr.GetName()
	for annPrefix, value := range *effectiveAnnotations(pod, ctr) {
		switch annPrefix {
		case "class":
			qosClass = value
		default:
			return loggedErrorf("container %q has invalid annotation %q", ppName, annPrefix)
		}
	}
	if qosClass == "" {
		log.Debugf("StartContainer: container %q has no QoS class", ppName)
		return nil
	}
	// Check that class is of correct form
	pattern := "^[A-Za-z0-9_-]+$"
	regex := regexp.MustCompile(pattern)
	if !regex.MatchString(qosClass) {
		return loggedErrorf("StartContainer: invalid characters in QoS class %q, does not match %q", qosClass, pattern)
	}

	// TODO: check that qosClass is in p.config.Classes,
	// use MemtierdConfig from there instead of a file.

	fullCgroupPath := getFullCgroupPath(ctr)
	podDirectory, outputFilePath, configFilePath, err := prepareMemtierdRunEnv(fullCgroupPath, namespace, podName, containerName, qosClass, hostRoot)
	if err != nil {
		log.Errorf("failed to prepare memtierd run environment: %v", err)
		return nil
	}
	err = startMemtierd(configFilePath, outputFilePath)
	if err != nil {
		log.Errorf("failed to start memtierd: %v", err)
		return nil
	}

	log.Infof("launched memtierd for %s, config and output files in %s", ppName, podDirectory)
	return nil
}

func (p *plugin) StopContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) ([]*api.ContainerUpdate, error) {
	log.Infof("Stopped container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())

	podName := pod.GetName()
	dirPath := fmt.Sprintf("%s/memtierd/%s", os.TempDir(), podName)

	// Kill the memtierd process
	out, err := exec.Command("sudo", "pkill", "-f", dirPath).CombinedOutput()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 1 {
			// Error occurred that is not related to "no processes found"
			log.Errorf("Error killing memtierd process matching %q: %v. Output: %s\n", dirPath, err, out)
		} else {
			// "No processes found" error, do nothing
			log.Printf("No processes found for memtierd process\n")
		}
	}

	err = os.RemoveAll(dirPath)
	if err != nil {
		fmt.Println(err)
	}

	return []*api.ContainerUpdate{}, nil
}

func (p *plugin) onClose() {
	log.Infof("Connection to the runtime lost, exiting...")
	os.Exit(0)
}

func getFullCgroupPath(ctr *api.Container) string {
	cgroupPath := ctr.Linux.CgroupsPath

	split := strings.Split(cgroupPath, ":")

	partOne := split[0]
	partTwo := fmt.Sprintf("%s-%s.scope", split[1], split[2])

	partialPath := fmt.Sprintf("%s/%s", partOne, partTwo)

	fullPath := fmt.Sprintf("*/kubepods*/%s", partialPath)

	if !strings.HasSuffix(fullPath, ".scope") && !strings.HasSuffix(fullPath, ".slice") {
		log.Fatalf("Cgroupfs not supported.")
	}

	file, err := os.Open("/proc/mounts")
	if err != nil {
		log.Fatalf("failed to open /proc/mounts: %v", err)
	}
	defer file.Close()

	cgroupMountPoint := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if fields[0] == "cgroup2" {
			cgroupMountPoint = fields[1]
			break
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("failed to read /proc/mounts: %v", err)
	}

	// Find the cgroup path corresponding to the container
	var fullCgroupPath string
	err = filepath.WalkDir(cgroupMountPoint, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			matches, err := filepath.Glob(filepath.Join(path, fullPath))
			if err != nil {
				return err
			}

			if len(matches) > 0 {
				fullCgroupPath = matches[0]
				return filepath.SkipDir
			}
		}

		return nil
	})

	if err != nil {
		log.Fatalf("failed to traverse cgroup directories: %v", err)
	}

	if fullCgroupPath == "" {
		log.Fatalf("cgroup path not found")
	}

	return fullCgroupPath
}

func prepareMemtierdRunEnv(fullCgroupPath string, namespace string, podName string, containerName string, qosClass string, hostRoot string) (string, string, string, error) {
	configTemplatePath := fmt.Sprintf("/templates/%s.yaml.in", qosClass)
	memtierdConfigIn, err := os.ReadFile(configTemplatePath)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot read memtierd configuration for class %q: %w", qosClass, err)
	}

	// Create pod directory if it doesn't exist
	podDirectory := fmt.Sprintf("%s%s/memtierd/%s/%s", hostRoot, os.TempDir(), namespace, podName)
	if err := os.MkdirAll(podDirectory, 0755); err != nil {
		return "", "", "", fmt.Errorf("cannot create memtierd run directory %q: %w", podDirectory, err)
	}

	outputFilePath := fmt.Sprintf("%s/%s.memtierd.output", podDirectory, containerName)
	statsFilePath := fmt.Sprintf("%s/%s.memtierd.stats", podDirectory, containerName)

	// Instantiate memtierd configuration from configuration template
	replace := map[string]string{
		"$CGROUP2_ABS_PATH": fullCgroupPath,
		"$MEMTIERD_SWAP_STATS_PATH": statsFilePath,
	}
	memtierdConfigOut := string(memtierdConfigIn)
	for key, value := range replace {
		memtierdConfigOut = strings.Replace(memtierdConfigOut, key, value, -1)
	}
	// var memtierdConfig MemtierdConfig
	// err = yaml.Unmarshal(yamlFile, &memtierdConfig)
	// if err != nil {
	// 	return "", "", "", fmt.Errorf("cannot parse class %q configuration YAML in %q: %w", class, configTemplatePath, err)
	// }
	// fullCgroupPathString := fullCgroupPath
	// policyConfigFieldString := string(memtierdConfig.Policy.Config)
	// policyConfigFieldString = strings.Replace(policyConfigFieldString, "$CGROUP2_ABS_PATH", fullCgroupPathString, 1)

	// // Loop through the routines
	// for i := 0; i < len(memtierdConfig.Routines); i++ {
	// 	routineConfigFieldString := string(memtierdConfig.Routines[i].Config)
	// 	routineConfigFieldString = strings.Replace(routineConfigFieldString, "$MEMTIERD_SWAP_STATS_PATH", statsFilePath, 1)
	// 	memtierdConfig.Routines[i].Config = routineConfigFieldString
	// }

	// memtierdConfig.Policy.Config = policyConfigFieldString

	// out, err := yaml.Marshal(&memtierdConfig)
	// if err != nil {
	// 	return "", "", "", fmt.Errorf("cannot marshal class %q configuration YAML: %w", class, err)
	// }

	configFilePath := fmt.Sprintf(podDirectory+"/%s.memtierd.config.yaml", containerName)
	err = os.WriteFile(configFilePath, []byte(memtierdConfigOut), 0644)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot write class %q configuration into file %q: %w", qosClass, configFilePath, err)
	}

	return podDirectory, outputFilePath, configFilePath, nil
}

func startMemtierd(configFilePath, outputFilePath string) error {
	outputFile, err := os.OpenFile(outputFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create memtierd output file: %w", err)
	}

	// Create the command and write its output to the output file
	cmd := exec.Command("memtierd", "-c", "", "-config", configFilePath)
	cmd.Stdout = outputFile
	cmd.Stderr = outputFile

	// Start the command in a new session and process group
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	// Start the command in the background
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command %s: %q", cmd, err)
	}
	return nil
}

func main() {
	var (
		pluginName string
		pluginIdx  string
		err        error
	)

	log = logrus.StandardLogger()
	log.SetFormatter(&logrus.TextFormatter{
		PadLevelText: true,
	})

	flag.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	flag.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	flag.StringVar(&opt.HostRoot, "host-root", "", "Directory prefix under which the host's tmp, etc. are mounted.")
	flag.Parse()

	p := &plugin{}
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
