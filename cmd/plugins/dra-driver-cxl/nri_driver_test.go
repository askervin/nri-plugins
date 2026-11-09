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

// The NRI plugin (internal/containers) as the driver wires it: the fence of
// the device engine before memory goes online, the order of Shutdown.

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/cpuset"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/containers"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	cxlapi "github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
)

// fenceRecorder is the fence of the device engine of a test: it records
// the fenced nodes at the fence of each new node, and what at returns.
type fenceRecorder struct {
	mu     sync.Mutex
	at     func() string
	fenced cpuset.CPUSet
	calls  []string
}

// newRecordedFence returns a recorder and its fence.
func newRecordedFence(at func() string) (func(ctx context.Context, node int), *fenceRecorder) {
	r := &fenceRecorder{at: at, fenced: cpuset.New()}
	return r.fence, r
}

// fence records the fence of node, if it is new.
func (r *fenceRecorder) fence(_ context.Context, node int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fenced.Contains(node) {
		return
	}
	r.fenced = r.fenced.Union(cpuset.New(node))
	call := r.fenced.String()
	if r.at != nil {
		call += " " + r.at()
	}
	r.calls = append(r.calls, call)
}

// taken returns the recorded fences and forgets them.
func (r *fenceRecorder) taken() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.calls
	r.calls = nil
	return out
}

func TestFencePoolBeforeOnline(t *testing.T) {
	e := newPoolTestEnv(t)
	e.plug(0xc1ee0001)
	// the state of the first memory block of the region at the fence
	fence, r := newRecordedFence(func() string {
		blocks, _ := e.k.Kernel().RegionBlocks("region0")
		if len(blocks) == 0 {
			return "no blocks"
		}
		return e.k.BlockState(blocks[0])
	})
	e.fence = fence
	p := e.driver(t)

	noErr(t, prepare(t, p, poolClaim("u1", "c1", "pooled0", exclusiveData)).Err)
	if got := r.taken(); !reflect.DeepEqual(got, []string{"2 offline"}) {
		t.Fatalf("fences %v, expected one before onlining", got)
	}
	if e.onlineBlocks("region0") == 0 {
		t.Fatal("the memory of the region is not online")
	}
	if got := p.ClaimResults("u1"); len(got) != 1 || got[0].NumaNode != 2 || got[0].Mode != cxlapi.ModeNUMA || got[0].Index != 0 || got[0].Size != 256<<20 {
		t.Fatalf("claim results %+v", got)
	}
	if got := poolNumaNodes(p); !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("numa nodes %v", got)
	}
	p = e.driver(t)
	if got := cpuset.New(poolNumaNodes(p)...).String(); got != "2" {
		t.Fatalf("prepared nodes after a restart %s", got)
	}
	noErr(t, unprepare(t, p, "u1"))
	if got := p.ClaimResults("u1"); got != nil {
		t.Fatalf("claim results %v after unprepare", got)
	}
	var none *dra.Plugin
	if none.ClaimResults("u1") != nil || poolNumaNodes(none) != nil {
		t.Fatal("nodes of a disabled pool driver")
	}

	// dax devices are not fenced
	e2 := newPoolTestEnv(t)
	e2.plug(0xc1ee0001)
	fence2, r2 := newRecordedFence(nil)
	e2.fence = fence2
	p2 := e2.driver(t)
	claim := withConfig(poolClaim("u2", "c2", "pooled0", exclusiveData), resourceapi.AllocationConfigSourceClaim, nil, daxConfig)
	noErr(t, prepare(t, p2, claim).Err)
	if got := r2.taken(); len(got) != 0 || poolNumaNodes(p2) != nil {
		t.Fatalf("dax device fenced: %v, numa nodes %v", got, poolNumaNodes(p2))
	}
}

// The NUMA node of a local numa slice is fenced once, before its memory
// goes online; a dax slice is not fenced.
func TestFenceLocalBeforeOnline(t *testing.T) {
	e := newLocalTestEnv(t)
	// the memory blocks online at each fence
	online := func() string {
		m, _ := filepath.Glob(e.k.P("devices/system/memory/memory*/state"))
		n := 0
		for _, path := range m {
			if b, _ := os.ReadFile(path); strings.HasPrefix(string(b), "online") {
				n++
			}
		}
		return "online=" + strings.Repeat("x", n)
	}
	fence, r := newRecordedFence(online)
	e.fence = fence
	e.start()
	e.mustPrepare(localClaim("u1", localBlockSize, localDaxConfig))
	if got := r.taken(); len(got) != 0 {
		t.Fatalf("dax slice fenced: %v", got)
	}
	e.mustPrepare(localClaim("u2", localBlockSize))
	if got := r.taken(); !reflect.DeepEqual(got, []string{"2 online="}) {
		t.Fatalf("fences %v, expected one before onlining", got)
	}
	// the block of the numa slice is the only one, online movable
	(&sliceTestEnv{e}).wantMemoryBlocks(75)
	e.mustPrepare(localClaim("u3", localBlockSize))
	if got := r.taken(); len(got) != 0 {
		t.Fatalf("fenced node fenced again: %v", got)
	}
	for _, uid := range []string{"u1", "u2", "u3"} {
		e.mustUnprepare(uid)
	}
	e.wantClean()
}

// TestShutdownStopsNRIFirst checks that Shutdown makes a close of the NRI
// connection no loss before it stops anything else: the runtime may close
// it while the broker stops (05-review D4).
func TestShutdownStopsNRIFirst(t *testing.T) {
	e := newLocalTestEnv(t)
	e.start()
	nri, err := containers.New(containers.Options{Store: e.st, SysRoot: t.TempDir()})
	noErr(t, err)
	stopping := false
	d := &driver{nri: nri, broker: stopFunc(func() { stopping = nri.Stopping() })}
	_ = d.Shutdown(context.Background()) // always nil
	if !stopping {
		t.Fatal("the broker stopped before the NRI plugin was marked stopping")
	}
}

// createdContainer returns the record of a container demo/pod/ctr whose
// env has the markers of the results of the claim uid, as an NRI plugin
// with the prepared claims local and pool creates it, and the error of its
// creation.
func createdContainer(t *testing.T, st *store.Store, local containers.LocalResults, pool containers.PoolResults, uid string, results ...int) (containers.Container, error) {
	t.Helper()
	p, err := containers.New(containers.Options{Store: st, SysRoot: t.TempDir()})
	noErr(t, err)
	p.SetResults(local, pool)
	pod := &nriapi.PodSandbox{Id: "sb", Uid: "pod-uid", Namespace: "demo", Name: "pod"}
	ctr := &nriapi.Container{Id: "ctr-id", PodSandboxId: "sb", Name: "ctr"}
	for _, n := range results {
		ctr.Env = append(ctr.Env, resultEnvVarName(uid, n)+"=1")
	}
	_, _, err = p.CreateContainer(context.Background(), pod, ctr)
	c, _ := p.Record(ctr.Id)
	return c, err
}

// TestFenceOf checks the fence that the device engine gets: the NRI
// plugin's with fencing allowed-mems (also before NRI connects: the node is
// recorded), none with fencing none.
func TestFenceOf(t *testing.T) {
	st, err := store.Open(context.Background(), store.Options{Dir: t.TempDir()})
	noErr(t, err)
	t.Cleanup(func() { _ = st.Close() })
	for _, fencing := range []string{"", config.FencingAllowedMems, config.FencingNone} {
		nri, err := containers.New(containers.Options{Defaults: config.Container{Fencing: fencing}, Store: st, SysRoot: t.TempDir()})
		noErr(t, err)
		fence := fenceOf(nri)
		if (fence == nil) != (fencing == config.FencingNone) {
			t.Fatalf("fencing %q: fence %v", fencing, fence != nil)
		}
		if fence != nil {
			fence(context.Background(), 2)
			if got := nri.Fenced().String(); got != "2" {
				t.Fatalf("fencing %q: fenced %s", fencing, got)
			}
		}
	}
	// the driver configuration and the plugin agree on the mode
	for _, cfg := range []string{"", `{"defaults":{"container":{"fencing":"none"}}}`} {
		dc, err := newDriverConfigFromString(cfg)
		noErr(t, err)
		nri, err := containers.New(containers.Options{Defaults: dc.containerDefaults(), Store: st, SysRoot: t.TempDir()})
		noErr(t, err)
		if nri.Fencing() != (dc.fencing() == config.FencingAllowedMems) {
			t.Fatalf("config %q: plugin fencing %v, driver %s", cfg, nri.Fencing(), dc.fencing())
		}
	}
}

// captureKlog makes klog write to a buffer at verbosity 3 for the test and
// returns a function that returns the output so far.
func captureKlog(t *testing.T) func() string {
	t.Helper()
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	noErr(t, fs.Set("logtostderr", "false"))
	noErr(t, fs.Set("alsologtostderr", "false"))
	noErr(t, fs.Set("v", "3"))
	var mu sync.Mutex
	var buf bytes.Buffer
	klog.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	t.Cleanup(func() {
		klog.Flush()
		_ = fs.Set("logtostderr", "true")
		_ = fs.Set("v", "0")
	})
	return func() string {
		klog.Flush()
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
