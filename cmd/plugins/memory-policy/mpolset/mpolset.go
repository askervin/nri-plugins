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

const (
	SYS_SET_MEMPOLICY = 238
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

func nodesForCPUs(sys system.System, cpus cpuset.CPUSet) (idset.IDSet, error) {
	result := idset.NewIDSet()
	sysCPUs := sys.PresentCPUs()
	for _, id := range cpus.UnsortedList() {
		if !sysCPUs.Contains(id) {
			return nil, fmt.Errorf("CPU %d not in system CPUs %v", id, sysCPUs.List())
		}
		cpu := sys.CPU(id)
		result.Add(cpu.NodeID())
	}
	fmt.Printf("nodesForCPUs(%v): %v\n", cpus.List(), result)
	return result, nil
}

func main() {
	var err error
	var sys system.System

	runtime.LockOSThread()
	debug.SetGCPercent(-1)
	runtime.GOMAXPROCS(1)
	//log.SetPrefix("mpolset: ")
	// log.SetFlags(0)
	modeFlag := flag.Uint("mode", 0, "Memory policy mode")
	nodesFlag := flag.String("nodes", "", "Comma-separated list of nodes, e.g. 0,1-3")
	ignoreErrorsFlag := flag.Bool("ignore-errors", false, "Ignore errors when setting memory policy")
	cpusFlag := flag.String("cpus", "", "Comma-separated list of CPUs, e.g. 24-47,97-99")
	distFlag := flag.Int("dist", 0, "Max distance from given -cpus or -nodes when setting memory policy")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		mode, nodes, err := mempolicy.GetMempolicy()
		if err != nil {
			log.Fatalf("GetMempolicy failed: %v", err)
		}
		fmt.Printf("Current memory policy: %d, nodes: %v\n", mode, nodes)
		os.Exit(0)
	}

	// Build a list of nodes from cpus or nodes.
	nodes := []int{}
	switch {
	case *cpusFlag != "" && *nodesFlag != "":
		log.Fatalf("cannot specify both cpus and nodes")
	case *cpusFlag != "":
		cpus, err := parseListSet(*cpusFlag)
		if err != nil {
			log.Fatalf("invalid -cpus: %v", err)
		}
		sys, err = system.DiscoverSystem(system.DiscoverCPUTopology)
		if err != nil {
			log.Fatalf("failed to discover CPU topology needed by -cpus: %v", err)
		}
		nodeset, err := nodesForCPUs(sys, cpuset.New(cpus...))
		if err != nil {
			log.Fatalf("failed to get nodes from -cpus %q: %v", *cpusFlag, err)
		}
		for _, node := range nodeset.Members() {
			nodes = append(nodes, int(node))
		}
	case *nodesFlag != "":
		nodes, err = parseListSet(*nodesFlag)
		if err != nil {
			log.Fatalf("invalid -nodes: %v", err)
		}
	}

	if *distFlag > 0 {
		if sys == nil {
			sys, err = system.DiscoverSystem(system.DiscoverCPUTopology)
			if err != nil {
				log.Fatalf("failed to discover CPU topology needed by -dist: %v", err)
			}
		}
		expandedNodes := nodesWithinDistance(sys, *distFlag, idset.NewIDSet(nodes...)).Members()
		log.Info("nodes within distance %d of %v: %v", *distFlag, nodes, expandedNodes)
		nodes = expandedNodes
	}

	if err := mempolicy.SetMempolicy(*modeFlag, nodes); err != nil {
		log.Errorf("SetMempolicy failed: %v", err)
		if ignoreErrorsFlag == nil || !*ignoreErrorsFlag {
			os.Exit(1)
		}

	}

	err = syscall.Exec(args[0], args, os.Environ())
	if err != nil {
		log.Fatalf("Exec failed: %v", err)
	}
}
