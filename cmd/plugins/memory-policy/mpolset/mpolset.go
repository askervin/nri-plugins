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
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	logger "github.com/containers/nri-plugins/pkg/log"
	"github.com/containers/nri-plugins/pkg/mempolicy"
	libmem "github.com/containers/nri-plugins/pkg/resmgr/lib/memory"
	system "github.com/containers/nri-plugins/pkg/sysfs"
	"github.com/containers/nri-plugins/pkg/utils/cpuset"
	idset "github.com/intel/goresctrl/pkg/utils"
)

var (
	log = logger.NewLogger("mpolset")
)

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
	log.Debug("nodes of cpus %v: %v\n", cpus.List(), result)
	return result
}

func packagesForCPUs(sys system.System, cpus cpuset.CPUSet) idset.IDSet {
	result := sys.IDSetForCPUs(cpus, func(cpu system.CPU) idset.ID { return cpu.PackageID() })
	log.Debug("packages of cpus %v: %v\n", cpus.List(), result)
	return result
}

func cpuNodesForPackages(sys system.System, packages idset.IDSet) idset.IDSet {
	result := idset.NewIDSet()
	for _, nodeId := range sys.NodeIDs() {
		if sys.Node(nodeId).CPUSet().Size() == 0 {
			continue
		}
		pkgId := sys.Node(nodeId).PackageID()
		if packages.Has(pkgId) {
			result.Add(nodeId)
		}
	}
	log.Debug("cpu nodes of packages %v: %v\n", packages.SortedMembers(), result)
	return result
}

func modeToString(mode uint) string {
	// Convert mode to string representation
	flagsStr := ""
	for name, value := range mempolicy.Flags {
		if mode&value != 0 {
			flagsStr += "|"
			flagsStr += name
			mode &= ^value
		}
	}
	modeStr := mempolicy.ModeNames[mode]
	if modeStr == "" {
		modeStr = fmt.Sprintf("unknown mode %d)", mode)
	}
	return modeStr + flagsStr
}

func main() {
	var err error
	var sys system.System

	runtime.LockOSThread()
	debug.SetGCPercent(-1)
	runtime.GOMAXPROCS(1)
	modeFlag := flag.String("mode", "", "Memory policy mode. Valid values are mode numbers and names from linux/mempolicy.h, e.g. 3 or MPOL_INTERLEAVE")
	flagsFlag := flag.String("flags", "", "Comma-separated list of memory policy flags,e.g. MPOL_F_STATIC_NODES")
	nodesFlag := flag.String("nodes", "", "Comma-separated list of nodes, e.g. 0,1-3")
	nodesOfCpusFlag := flag.String("nodes-of-cpus", "", "Comma-separated list of CPUs, e.g. 24-47,97-99")
	nodesOfPkgsFlag := flag.String("nodes-of-pkgs", "", "Comma-separated list of packages, e.g. 2-3")
	pkgsOfCpusFlag := flag.String("pkgs-of-cpus", "", "Comma-separated list of CPUs, e.g. 24-47,97-99")
	distFlag := flag.Int("dist", 0, "Expand nodes with those within given distance from any of the specified nodes")
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
		modeStr := modeToString(mode)
		fmt.Printf("Current memory policy: %s (%d), nodes: %v\n", modeStr, mode, nodes)
		os.Exit(0)
	}

	nodeSources := 0
	for _, nodeSource := range []*string{nodesFlag, nodesOfCpusFlag, nodesOfPkgsFlag, pkgsOfCpusFlag} {
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
	case *nodesFlag != "":
		nodeMask, err := libmem.ParseNodeMask(*nodesFlag)
		if err != nil {
			log.Fatalf("invalid -nodes: %v", err)
		}
		nodes = nodeMask.Slice()
	case *nodesOfCpusFlag != "":
		cpus, err := cpuset.Parse(*nodesOfCpusFlag)
		if err != nil {
			log.Fatalf("invalid -nodes-of-cpus: %v", err)
		}
		for _, node := range nodesForCPUs(sys, cpus).SortedMembers() {
			nodes = append(nodes, int(node))
		}
	case *nodesOfPkgsFlag != "":
		pkgs, err := libmem.ParseNodeMask(*nodesOfPkgsFlag)
		if err != nil {
			log.Fatalf("invalid -nodes-of-pkgs: %v", err)
		}
		for _, node := range cpuNodesForPackages(sys, idset.NewIDSet(pkgs.Slice()...)).SortedMembers() {
			nodes = append(nodes, int(node))
		}
	case *pkgsOfCpusFlag != "":
		cpus, err := cpuset.Parse(*pkgsOfCpusFlag)
		if err != nil {
			log.Fatalf("invalid -pkgs-of-cpus: %v", err)
		}
		packages := packagesForCPUs(sys, cpus)
		for _, node := range cpuNodesForPackages(sys, packages).SortedMembers() {
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
		log.Debug("nodes within distance %d of %v: %v", *distFlag, nodes, expandedNodes)
		nodes = expandedNodes
	}

	if *flagsFlag != "" {
		if strings.Contains(*flagsFlag, "help") {
			fmt.Printf("Valid memory policy flags:\n")
			for flag := range mempolicy.Flags {
				fmt.Printf("  %s\n", flag)
			}
			os.Exit(0)
		}
		flags := strings.Split(*flagsFlag, ",")
		for _, flag := range flags {
			flagBit, ok := mempolicy.Flags[flag]
			if !ok {
				log.Fatalf("invalid -flags: %v", flag)
			}
			mode |= flagBit
		}
	}

	log.Debug("setting memory policy: %s (%d), nodes: %v\n", modeToString(mode), mode, nodes)
	if err := mempolicy.SetMempolicy(mode, nodes); err != nil {
		log.Errorf("SetMempolicy failed: %v", err)
		if ignoreErrorsFlag == nil || !*ignoreErrorsFlag {
			os.Exit(1)
		}
	}

	log.Debug("executing: %v\n", args)
	executable, err := exec.LookPath(args[0])
	if err != nil {
		log.Fatalf("Looking for executable %q failed: %v", args[0], err)
	}
	err = syscall.Exec(executable, args, os.Environ())
	if err != nil {
		log.Fatalf("Executing %q failed: %v", executable, err)
	}
}
