/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
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

	"github.com/intel/memtierd/pkg/memtier"
)

type plugin struct {
	stub   stub.Stub
	mask   stub.EventMask
	config *pluginConfig
}

type pluginConfig struct {
	// DirectAnnotations lists cgroups v2 memory controls where
	// values from corresponding annotations can be directly
	// written to. No files are allowed by default. Example:
	// {"memory.swap.max", "memory.high"}
	// allows writing data from annotations to cgroups v2:
	// annotations:
	//   # The default for all containers in the pod:
	//   memory.swap.max.memtierd.nri: "max"
	//   # Applies only to CONTAINERNAME in the pod:
	//   memory.high.memtierd.nri/CONTAINERNAME: "4G"
	DirectAnnotations []string

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
	//   class.memtierd.nri: "swap"
	//   # Override the default for CONTAINERNAME:
	//   class.memtierd.nri/CONTAINERNAME: "Guaranteed"
	Name string

	// MemoryThrottlingFactor affects how memory.high is
	// calculated based on container and node resources.
	// https://kubernetes.io/blog/2023/05/05/qos-memory-resources/
	MemoryThrottlingFactor float32

	// SwapFactor defines the proportion of container's memory
	// (resources.limits.memory) that can be on swap. "1.0" means
	// that all memory can be swapped out. If containers memory
	// limit is undefined, positive SwapFactor value sets
	// memory.swap.max to "max".
	SwapFactor float32

	// MemtierdConfig is a string that contains full configuration
	// for memtierd. If non-empty, memtierd will be launched to
	// track each container of this QoS class.
	MemtierdConfig string
}

type MemtierdConfig struct {
	Policy   Policy     `yaml:"policy"`
	Routines []Routines `yaml:"routines"`
}

type Routines memtier.RoutineConfig
// struct {
// 	Name   string `yaml:"name"`
// 	Config string `yaml:"config"`
// }

type Policy memtier.PolicyConfig
// struct {
// 	Name   string `yaml:"name"`
// 	Config string `yaml:"config"`
// }

type options struct {
	HostRoot string
}

const (
	annotationSuffix = ".memtierd.nri"
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

func prettyPrintCtr(pod *api.PodSandbox, ctr *api.Container) string {
	return fmt.Sprintf("%s/%s:%s", pod.GetNamespace(), pod.GetName(), ctr.GetName())
}

func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	ppName := prettyPrintCtr(pod, ctr)
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
	ppName := prettyPrintCtr(pod, ctr)
	log.Infof("Starting container %s...", ppName)

	hostRoot := opt.HostRoot

	namespace := pod.GetNamespace()
	podName := pod.GetName()
	containerName := ctr.GetName()
	annotations := pod.GetAnnotations()

	// If memtierd annotation is not present, don't execute further
	class, ok := annotations["class.memtierd.nri"]
	if !ok {
		return nil
	}

	// Check that class is of correct form
	pattern := "^[A-Za-z0-9_-]+$"
	regex := regexp.MustCompile(pattern)

	if !regex.MatchString(class) {
		log.Errorf("invalid class.memtierd.nri %q, does not match %q", class, pattern)
		return nil
	}

	fullCgroupPath := getFullCgroupPath(ctr)
	podDirectory, outputFilePath, configFilePath, err := prepareMemtierdRunEnv(fullCgroupPath, namespace, podName, containerName, class, hostRoot)
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

func prepareMemtierdRunEnv(fullCgroupPath string, namespace string, podName string, containerName string, class string, hostRoot string) (string, string, string, error) {
	configTemplatePath := fmt.Sprintf("/templates/%s.yaml.in", class)
	yamlFile, err := ioutil.ReadFile(configTemplatePath)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot read memtierd configuration for class %q: %w", class, err)
	}

	// Create pod directory if it doesn't exist
	podDirectory := fmt.Sprintf("%s%s/memtierd/%s/%s", hostRoot, os.TempDir(), namespace, podName)
	if err := os.MkdirAll(podDirectory, 0755); err != nil {
		return "", "", "", fmt.Errorf("cannot create memtierd run directory %q: %w", podDirectory, err)
	}

	outputFilePath := fmt.Sprintf("%s/%s.memtierd.output", podDirectory, containerName)
	statsFilePath := fmt.Sprintf("%s/%s.memtierd.stats", podDirectory, containerName)

	// Instantiate memtierd configuration from configuration template
	var memtierdConfig MemtierdConfig
	err = yaml.Unmarshal(yamlFile, &memtierdConfig)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot parse class %q configuration YAML in %q: %w", class, configTemplatePath, err)
	}
	fullCgroupPathString := fullCgroupPath
	policyConfigFieldString := string(memtierdConfig.Policy.Config)
	policyConfigFieldString = strings.Replace(policyConfigFieldString, "$CGROUP2_ABS_PATH", fullCgroupPathString, 1)

	// Loop through the routines
	for i := 0; i < len(memtierdConfig.Routines); i++ {
		routineConfigFieldString := string(memtierdConfig.Routines[i].Config)
		routineConfigFieldString = strings.Replace(routineConfigFieldString, "$MEMTIERD_SWAP_STATS_PATH", statsFilePath, 1)
		memtierdConfig.Routines[i].Config = routineConfigFieldString
	}

	memtierdConfig.Policy.Config = policyConfigFieldString

	out, err := yaml.Marshal(&memtierdConfig)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot marshal class %q configuration YAML: %w", class, err)
	}

	configFilePath := fmt.Sprintf(podDirectory+"/%s.memtierd.config.yaml", containerName)
	err = ioutil.WriteFile(configFilePath, out, 0644)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot write class %q configuration into file %q: %w", class, configFilePath, err)
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
