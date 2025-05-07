package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/containers/nri-plugins/pkg/mempolicy"
	system "github.com/containers/nri-plugins/pkg/sysfs"
	idset "github.com/intel/goresctrl/pkg/utils"
)

const (
	SYS_SET_MEMPOLICY = 238
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

func nodesWithinDistance(sys system.System, maxDist int, fromNodes ...idset.ID) idset.IDSet {
	result := idset.NewIDSet()
	for _, toNode := range sys.NodeIDs() {
		if fromNodes.Has(toNode) {
			result.Add(toNode)
			continue
		}
		for _, fromNode := range fromNodes {
			if sys.NodeDistance(fromNode, toNode) <= maxDist {
				result.Add(toNode)
			}
		}
	}
	return result
}

func main() {
	var err error

	runtime.LockOSThread()
	debug.SetGCPercent(-1)
	runtime.GOMAXPROCS(1)
	log.SetPrefix("mpolset: ")
	log.SetFlags(0)
	modeFlag := flag.Uint("mode", 0, "Memory policy mode")
	nodesFlag := flag.String("nodes", "", "Comma-separated list of NUMA nodes")
	ignoreErrorsFlag := flag.Bool("ignore-errors", false, "Ignore errors when setting memory policy")
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

	nodes := []int{}
	if *nodesFlag != "" {
		if nodes, err = parseListSet(*nodesFlag); err != nil {
			log.Fatalf("invalid nodes: %v", err)
		}
	}
	if len(nodes) == 0 && *modeFlag != 0 {
		log.Fatalf("no nodes specified but required by mode %d", *modeFlag)
	}

	// TODO: discover system only if needed
	//discoverSystem(*hostRootFlag)

	if err := mempolicy.SetMempolicy(*modeFlag, nodes); err != nil {
		log.Printf("SetMempolicy failed: %v", err)
		if ignoreErrorsFlag == nil || !*ignoreErrorsFlag {
			os.Exit(1)
		}

	}

	err = syscall.Exec(args[0], args, os.Environ())
	if err != nil {
		log.Fatalf("Exec failed: %v", err)
	}
}
