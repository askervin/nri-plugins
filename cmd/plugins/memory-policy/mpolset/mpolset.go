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

// mpolset is an executable that sets the memory policy for a process
// and then executes the specified command.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	logger "github.com/containers/nri-plugins/pkg/log"
	"github.com/containers/nri-plugins/pkg/mempolicy"
	system "github.com/containers/nri-plugins/pkg/sysfs"
	"github.com/containers/nri-plugins/pkg/utils/cpuset"
	idset "github.com/intel/goresctrl/pkg/utils"
)

var (
	log = logger.NewLogger("mpolset")
)

// parseListSet parses "list set" syntax ("0,61-63,2") into a list ([0, 61, 62, 63, 2])
func parseListSet(listSet string) ([]int, error) {
	var result []int
	parts := strings.Split(listSet, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range: %s", part)
			}
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid range: %s (start > end)", part)
			}
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
		} else {
			num, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			result = append(result, num)
		}
	}
	return result, nil
}

func nodesWithinDistance(sys system.System, maxDist int, fromNodes idset.IDSet) idset.IDSet {
	result := idset.NewIDSet()
	for _, toNode := range sys.NodeIDs() {
		if fromNodes.Has(toNode) {
			result.Add(toNode)
			continue
		}
		for _, fromNode := range fromNodes.Members() {
			if sys.NodeDistance(fromNode, toNode) <= maxDist {
				result.Add(toNode)
			}
		}
	}
	return result
}

func nodesForCPUs(sys system.System, cpus cpuset.CPUSet) idset.IDSet {
	result := sys.IDSetForCPUs(cpus, func(cpu system.CPU) idset.ID { return cpu.NodeID() })
	log.Debug("nodesForCPUs(%v): %v\n", cpus.List(), result)
	return result
}

func packagesForCPUs(sys system.System, cpus cpuset.CPUSet) idset.IDSet {
	result := sys.IDSetForCPUs(cpus, func(cpu system.CPU) idset.ID { return cpu.PackageID() })
	log.Debug("packagesForCPUs(%v): %v\n", cpus.List(), result)
	return result
}

func nodesForPackages(sys system.System, packages idset.IDSet) idset.IDSet {
	result := idset.NewIDSet()
	for _, nodeId := range sys.NodeIDs() {
		pkgId := sys.Node(nodeId).PackageID()
		if packages.Has(pkgId) {
			result.Add(nodeId)
		}
	}
	log.Debug("nodesForPackages(%v): %v\n", packages.SortedMembers(), result)
	return result
}

func main() {
	var err error
	var sys system.System

	runtime.LockOSThread()
	debug.SetGCPercent(-1)
	runtime.GOMAXPROCS(1)
	modeFlag := flag.String("mode", "", "Memory policy mode. Valid values are mode numbers and names from linux/mempolicy.h, e.g. 3 or MPOL_INTERLEAVE")
	nodesFlag := flag.String("nodes", "", "Comma-separated list of nodes, e.g. 0,1-3")
	cpusFlag := flag.String("cpus", "", "Comma-separated list of CPUs, e.g. 24-47,97-99")
	pkgsFlag := flag.String("pkgs", "", "Comma-separated list of packages, e.g. 2-3")
	distFlag := flag.Int("dist", 0, "Max distance from given -cpus or -nodes when setting memory policy")
	ignoreErrorsFlag := flag.Bool("ignore-errors", false, "Ignore errors when setting memory policy")
	verboseFlag := flag.Bool("v", false, "Enable verbose logging")
	veryVerboseFlag := flag.Bool("vv", false, "Enable very verbose logging")
	flag.Parse()

	logger.SetLevel(logger.LevelError)
	if *verboseFlag || *veryVerboseFlag {
		logger.SetLevel(logger.LevelDebug)
		log.EnableDebug(true)
		if *veryVerboseFlag {
			logger.Get("sysfs").EnableDebug(true)
		}
	}

	args := flag.Args()

	mode := uint(0)
	switch {
	case *modeFlag == "help":
		fmt.Printf("Valid memory policy modes:\n")
		for mode := range len(mempolicy.ModeNames) {
			fmt.Printf("  %s (%d)\n", mempolicy.ModeNames[uint(mode)], mode)
		}
		os.Exit(0)
	case *modeFlag != "" && (*modeFlag)[0] >= '0' && (*modeFlag)[0] <= '9':
		imode, err := strconv.Atoi(*modeFlag)
		if err != nil {
			log.Fatalf("invalid -mode: %v", err)
		}
		mode = uint(imode)
	case *modeFlag != "":
		ok := false
		mode, ok = mempolicy.Modes[*modeFlag]
		if !ok {
			log.Fatalf("invalid -mode: %v", *modeFlag)
		}
	case len(args) > 0:
		log.Fatalf("missing -mode")
	}

	if len(args) == 0 {
		mode, nodes, err := mempolicy.GetMempolicy()
		if err != nil {
			log.Fatalf("GetMempolicy failed: %v", err)
		}
		fmt.Printf("Current memory policy: %d (%s), nodes: %v\n", mode, mempolicy.ModeNames[mode], nodes)
		os.Exit(0)
	}

	nodeSources := 0
	for _, nodeSource := range []*string{cpusFlag, nodesFlag, pkgsFlag} {
		if nodeSource != nil && *nodeSource != "" {
			nodeSources++
		}
	}

	if nodeSources > 1 {
		log.Fatalf("cannot specify more than one of -cpus, -nodes, or -pkgs")
	}
	if nodeSources == 1 {
		sys, err = system.DiscoverSystem(system.DiscoverCPUTopology)
		if err != nil {
			log.Fatalf("failed to discover CPU topology needed by -cpus, -nodes, or -pkgs: %v", err)
		}
	}

	// Build a list of nodes from cpus or nodes.
	nodes := []int{}
	switch {
	case *cpusFlag != "":
		cpus, err := parseListSet(*cpusFlag)
		if err != nil {
			log.Fatalf("invalid -cpus: %v", err)
		}
		if err != nil {
			log.Fatalf("failed to discover CPU topology needed by -cpus: %v", err)
		}
		for _, node := range nodesForCPUs(sys, cpuset.New(cpus...)).SortedMembers() {
			nodes = append(nodes, int(node))
		}
	case *nodesFlag != "":
		nodes, err = parseListSet(*nodesFlag)
		if err != nil {
			log.Fatalf("invalid -nodes: %v", err)
		}
	case *pkgsFlag != "":
		pkgs, err := parseListSet(*pkgsFlag)
		if err != nil {
			log.Fatalf("invalid -pkgs: %v", err)
		}
		for _, node := range nodesForPackages(sys, idset.NewIDSet(pkgs...)).SortedMembers() {
			nodes = append(nodes, int(node))
		}
	}

	if *distFlag > 0 {
		if sys == nil {
			sys, err = system.DiscoverSystem(system.DiscoverCPUTopology)
			if err != nil {
				log.Fatalf("failed to discover CPU topology needed by -dist: %v", err)
			}
		}
		expandedNodes := nodesWithinDistance(sys, *distFlag, idset.NewIDSet(nodes...)).SortedMembers()
		log.Info("nodes within distance %d of %v: %v", *distFlag, nodes, expandedNodes)
		nodes = expandedNodes
	}

	log.Debug("setting memory policy: %d, nodes: %v\n", mode, nodes)
	if err := mempolicy.SetMempolicy(mode, nodes); err != nil {
		log.Errorf("SetMempolicy failed: %v", err)
		if ignoreErrorsFlag == nil || !*ignoreErrorsFlag {
			os.Exit(1)
		}
	}

	log.Debug("executing: %v\n", args)
	err = syscall.Exec(args[0], args, os.Environ())
	if err != nil {
		log.Fatalf("Exec failed: %v", err)
	}
}
