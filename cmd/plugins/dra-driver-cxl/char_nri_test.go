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

package main

// Characterization tests of the log lines of the NRI plugin that no test
// pinned: the lines of the fence, of CreateContainer, of the steering that
// Synchronize does not restart, and of the loss of the NRI connection.

import (
	"context"
	"strings"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"
	"k8s.io/utils/cpuset"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/compat"
	"github.com/containers/nri-plugins/pkg/cxl/config"
)

// TestCharFenceLogLines pins the lines of a fence that adds a node, of one
// without NRI and of the seed of the prepared claims.
func TestCharFenceLogLines(t *testing.T) {
	e := newFenceEnv(t, "0-2")
	logs := captureKlog(t)
	ctx := context.Background()
	e.readyFence()
	e.p.fence.Fence(ctx, 3)
	const fenced = "NRI fence: fencing CXL node 3 (fenced nodes 3)"
	if n := strings.Count(logs(), fenced); n != 1 {
		t.Fatalf("%d lines %q, expected 1:\n%s", n, fenced, logs())
	}
	e.p.fence.Fence(ctx, 3)
	if n := strings.Count(logs(), "NRI fence: fencing CXL node"); n != 1 {
		t.Fatalf("a fenced node logged again:\n%s", logs())
	}

	f := newNodeFence(config.FencingAllowedMems)
	f.setNoNRI()
	f.Fence(ctx, 3)
	const noNRI = "NRI fence: NRI not connected, containers are not fenced from CXL node 3"
	if !strings.Contains(logs(), noNRI) {
		t.Fatalf("no line %q:\n%s", noNRI, logs())
	}
	f.seed(cpuset.New(2))
	line := lineWith(logs(), "of prepared claims")
	if line == "" || !compat.Matches(compat.LogNRIFenceFencingCXLNodesNumaNodeOfPrepared, line) ||
		!strings.HasSuffix(line, "NRI fence: fencing CXL nodes 2 of prepared claims") {
		t.Fatalf("seed line %q:\n%s", line, logs())
	}
}

// TestCharCreateContainerLogLines pins the error line of a CreateContainer
// whose results conflict and the line of a container whose DRAM and region
// memory is not steered.
func TestCharCreateContainerLogLines(t *testing.T) {
	e := newFenceEnv(t, "0-1", 2)
	e.p.claims = nriClaims()
	e.p.poolResults = nriPoolResults
	logs := captureKlog(t)
	pod := ltPod("u1")

	_, _, err := e.p.CreateContainer(context.Background(), pod, withClaims(ltCtr(pod, "c6", "f", 0), "auto", "none"))
	const conflict = "NRI CreateContainer: container ns/pod-u1/f: container.steering.policy: claim ns/auto request mem says auto, claim ns/none request mem says none"
	if err == nil || !strings.Contains(logs(), conflict) {
		t.Fatalf("error %v, no line %q:\n%s", err, conflict, logs())
	}

	// DRAM and a region in mode numa with the default steering none: the
	// claims reserve capacity only (with policy auto the DRAM is steered)
	ctr := &nriapi.Container{Id: "c7", PodSandboxId: pod.GetId(), Name: "g",
		Env: []string{resultEnvVarName("split", 2) + "=1", resultEnvVarName("split", 3) + "=1"}}
	if got := e.createMems(pod, ctr); got != "0-1,4" {
		t.Fatalf("adjustment %s", got)
	}
	for _, line := range []string{
		"NRI CreateContainer: ctr=ns/pod-u1/g: memory fenced (steering none (default), fencing allowed-mems (default))",
		"NRI CreateContainer: ctr=ns/pod-u1/g: dram and region memory is not steered: the claims reserve capacity only",
	} {
		if !strings.Contains(logs(), line) {
			t.Errorf("no line %q:\n%s", line, logs())
		}
	}
	if line := lineWith(logs(), "ctr=ns/pod-u1/g: memory "); !compat.Matches(compat.LogNRICreateContainerCtrCtrMemoryMgmtSteering, line) {
		t.Errorf("line %q does not match %q", line, compat.LogNRICreateContainerCtrCtrMemoryMgmtSteering)
	}
}

// TestCharSynchronizeSteeringLog pins the lines of the containers whose
// steering a restarted plugin does not restart: one that the steering
// record of the killed plugin names (memory.high released) and one that
// its settings steer without a record (memory.high left alone).
func TestCharSynchronizeSteeringLog(t *testing.T) {
	e := newFenceEnv(t, "0-3", 2)
	e.p.claims = nriClaims()
	logs := captureKlog(t)
	ctx := context.Background()
	p1 := ltPod("u1")
	cg1 := e.proc(101, "kubepods/u1/c1", "0,2", "0,2")
	steerableCgroup(t, cg1, "140668928")
	cg7 := e.proc(107, "kubepods/u1/c7", "0-3", "")
	steerableCgroup(t, cg7, "536870912")
	c1 := withClaims(ltCtr(p1, "c1", "app", 101), "auto")
	c7 := withClaims(ltCtr(p1, "c7", "qos", 107), "auto")
	c1.State, c7.State = nriapi.ContainerState_CONTAINER_RUNNING, nriapi.ContainerState_CONTAINER_RUNNING
	e.p.steered = loadSteeredRecord(steeredFile(t, map[string]string{"c1": cg1}))
	if _, err := e.p.Synchronize(ctx, []*nriapi.PodSandbox{p1}, []*nriapi.Container{c1, c7}); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"NRI Synchronize: ctr=ns/pod-u1/app id=c1: steering not restarted, memory fenced; memory.high 140668928 removed (max)",
		"NRI Synchronize: ctr=ns/pod-u1/qos id=c7: steering not restarted, memory fenced; memory.high left alone: no manager steered it",
	} {
		if !strings.Contains(logs(), line) {
			t.Errorf("no line %q:\n%s", line, logs())
		}
	}
	if got := memoryHigh(t, cg1); got != "max" {
		t.Errorf("memory.high %s of the recorded container", got)
	}
	if got := memoryHigh(t, cg7); got != "536870912" {
		t.Errorf("memory.high %s of the container without a record", got)
	}
}

// TestCharNRILostLogLine pins the line of the loss of the NRI connection:
// logged with the exit, not after markStopping.
func TestCharNRILostLogLine(t *testing.T) {
	const lost = "NRI connection to the runtime lost, exiting to be restarted and connect again"
	ctx := context.Background()
	exits := recordExits(t)
	logs := captureKlog(t)
	p := newLtEnv(t).p
	p.connStarted(ctx)
	p.onClose(ctx)
	// klog writes an error line to the logs of every severity up to it
	n := strings.Count(logs(), lost)
	if n == 0 {
		t.Fatalf("no line %q:\n%s", lost, logs())
	}
	expectExits(t, exits, 1)

	exits = recordExits(t)
	p = newLtEnv(t).p
	p.connStarted(ctx)
	p.markStopping()
	p.onClose(ctx)
	if strings.Count(logs(), lost) != n {
		t.Fatalf("logged while stopping:\n%s", logs())
	}
	expectExits(t, exits)
}

// lineWith returns the last line of out that has text, "" for none.
func lineWith(out, text string) string {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], text) {
			return lines[i]
		}
	}
	return ""
}
