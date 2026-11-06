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

package engine

import (
	"context"
	"flag"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// The changes of the kernel objects between two observations that the
// kernel's tables have give no line; one that they do not have does.
func TestUnknownTransitions(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	k := v.f.Kernel()
	before, err := k.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	v.mustPrepare(poolDriver, "c", poolReq("c", 0, serialA, state.ModeNUMA, state.KindExclusive))
	after, err := k.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lines := UnknownTransitions(before, after); len(lines) > 0 {
		t.Fatalf("documented changes reported: %v", lines)
	}
	// a memdev that loses its endpoint port without being disabled
	bad := *after
	bad.Memdevs = append([]kernel.MemdevInfo(nil), after.Memdevs...)
	bad.Memdevs[0].State = kernel.MemdevBound
	bad.DaxDevices = append([]kernel.DaxDeviceInfo(nil), after.DaxDevices...)
	bad.DaxDevices[0].State = kernel.DaxOther
	lines := UnknownTransitions(after, &bad)
	want := []string{
		"memdev 0xa1: MemdevInfo.State: READY -> BOUND: transition not in the table",
		"dax device dax0.0: DaxDeviceInfo.State: KMEM -> OTHER: transition not in the table",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	v.mustUnprepare(poolDriver, "c")
}

// Observe logs the unknown changes at debug level, with the start of the
// line that the gates grep for.
func TestObserveLogsUnknownTransitions(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	logs := captureKlogV(t, "4")
	if _, err := v.e.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	// the removal of a memdev is a row: nothing is logged
	v.f.Unplug(serialA)
	if _, err := v.e.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs(), UnknownTransition) {
		t.Fatalf("a documented change logged: %s", logs())
	}
	v.e.qmu.Lock()
	last := *v.e.last
	v.e.last = &last
	last.Memdevs = []kernel.MemdevInfo{{Serial: serialB, State: kernel.MemdevReady}}
	v.e.qmu.Unlock()
	v.f.EndpointDelay = time.Second
	v.f.Plug(fake.MemdevSpec{Serial: serialB})
	if _, err := v.e.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs(), UnknownTransition+"memdev 0xb1: MemdevInfo.State: READY -> BOUND") {
		t.Fatalf("logs %s", logs())
	}
}

// captureKlogV returns the klog output from now on at the verbosity.
func captureKlogV(t *testing.T, verbosity string) func() string {
	t.Helper()
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	_ = fs.Set("logtostderr", "false")
	_ = fs.Set("alsologtostderr", "false")
	_ = fs.Set("v", verbosity)
	var mu sync.Mutex
	var buf strings.Builder
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

// A request that waits for its memdev does not hold up the requests of
// another memdev: one queue per memdev.
func TestQueuesPerMemdev(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialB})
	done := make(chan error, 1)
	go func() {
		_, err := v.e.PrepareGrants(context.Background(), []GrantRequest{poolReq("wait", 0, serialA, state.ModeDax, state.KindExclusive)})
		done <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); !v.e.Busy(serialA); {
		if time.Now().After(deadline) {
			t.Fatal("the waiting memdev is not busy")
		}
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{poolReq("other", 0, serialB, state.ModeDax, state.KindExclusive)}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("the other memdev waited %v", time.Since(start))
	}
	v.f.Plug(fake.MemdevSpec{Serial: serialA})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := v.e.ReleaseGrants(context.Background(), []state.GrantRef{{Claim: "wait"}, {Claim: "other"}}, ReleaseUnprepare); err != nil {
		t.Fatal(err)
	}
	if r := v.records(); len(r.Grants)+len(r.Memdevs)+len(r.Regions) > 0 {
		t.Fatalf("records %+v", r)
	}
}

// The verify step of a Prepare compares the new observation with the last
// one: an unknown change is logged at V(4), and so is every violation of an
// invariant.
func TestVerifyStepLogs(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialA})
	logs := captureKlogV(t, "4")
	if _, err := v.e.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	// a memdev whose endpoint port is still missing (BOUND) that the last
	// observation had READY: READY -> BOUND is no row
	v.f.EndpointDelay = time.Second
	v.f.Plug(fake.MemdevSpec{Serial: serialB})
	v.e.qmu.Lock()
	last := *v.e.last
	last.Memdevs = append(append([]kernel.MemdevInfo(nil), last.Memdevs...), kernel.MemdevInfo{Serial: serialB, State: kernel.MemdevReady})
	v.e.last = &last
	v.e.qmu.Unlock()
	if _, err := v.e.PrepareGrants(context.Background(), []GrantRequest{poolReq("c", 0, serialA, state.ModeDax, state.KindExclusive)}); err != nil {
		t.Fatal(err)
	}
	if err := v.st.Commit(context.Background(), 0, func(doc *storeDocument) error {
		doc.Provenance = append(doc.Provenance, state.Provenance{Serial: serialL, State: state.ProvenanceHeld})
		doc.Grants = append(doc.Grants, state.Grant{Ref: state.GrantRef{Claim: "l"}, Serial: serialL,
			Asked: state.Asked{Source: state.SourceLocal}, State: state.GrantJournaled})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := v.e.ReleaseGrants(context.Background(), []state.GrantRef{{Claim: "c"}}, ReleaseUnprepare); err != nil {
		t.Fatal(err)
	}
	out := logs()
	for _, want := range []string{
		UnknownTransition + "memdev 0xb1: MemdevInfo.State: READY -> BOUND",
		"engine invariant: I10: grant l/0: a new local grant on serial 0x11 of provenance HELD",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no line %q in\n%s", want, out)
		}
	}
}
