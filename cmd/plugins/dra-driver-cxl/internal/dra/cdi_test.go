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

package dra

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// TestRemoveCXLSpecs removes the CDI specs of both drivers, also of their
// earlier names, and keeps the others.
func TestRemoveCXLSpecs(t *testing.T) {
	dir := t.TempDir()
	for name, kind := range map[string]string{"cxl-claims": "nri.io/cxl", "cxl-local": "nri.io/cxl", "cxl-pool": "nri.io/cxl-pool", "gpu": "example.com/gpu"} {
		data := "cdiVersion: 0.6.0\nkind: " + kind + "\ndevices:\n- name: " + name + "\n  containerEdits:\n    env: [A=1]\n"
		mustOK(t, os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(data), 0o600))
	}
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(dir), cdiapi.WithAutoRefresh(false))
	mustOK(t, err)
	mustOK(t, RemoveCXLSpecs(cache))
	m, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(m) != 1 || filepath.Base(m[0]) != "gpu.yaml" {
		t.Fatalf("left %v", m)
	}
}

// TestClaimsCDISpec checks the CDI spec of the claims of cxl.nri.io built
// from their records: the env of the DRAM and of a region with their
// consumed sizes, the marker only of the lease device, nothing of a result
// of another driver or of a companion claim.
func TestClaimsCDISpec(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()})
	e.lending()
	e.setLeases()
	region := e.addRegion("region0", 2, 2<<30)
	// result 1 is of another driver
	u1 := localClaim("u1", device.DRAMDeviceName, 64*mib)
	u1.Status.Allocation.Devices.Results = append(u1.Status.Allocation.Devices.Results,
		poolClaim("x", "pooled0", "").Status.Allocation.Devices.Results[0])
	addLocalResult(u1, "region", region, 64*mib)
	e.mustPrepare(e.local, u1)
	e.mustPrepare(e.local, localClaim("u2", device.LeaseDeviceName, 0))
	// a companion claim
	e.mustPrepare(e.local, companion(localClaim("u3", localDev, 64*mib), "l1"))
	want := []cdiSpecs.Device{
		{Name: "claim-u1-0", ContainerEdits: cdiSpecs.ContainerEdits{Env: []string{
			"CXL_CLAIM_u1_0=1", "CXL_DRAM_MODE=numa", "CXL_DRAM_NODES=0-1", "CXL_DRAM_SIZE=67108864"}}},
		{Name: "claim-u1-2", ContainerEdits: cdiSpecs.ContainerEdits{Env: []string{
			"CXL_CLAIM_u1_2=1", "CXL_REGION0_MODE=numa", "CXL_REGION0_NODE=2", "CXL_REGION0_SIZE=67108864"}}},
		{Name: "claim-u2-0", ContainerEdits: cdiSpecs.ContainerEdits{Env: []string{"CXL_CLAIM_u2_0=1"}}},
	}
	spec, err := buildCDISpec(e.st.Snapshot(), device.DriverName, device.CDIKind, e.st.ViewOptions(), "", true)
	mustOK(t, err)
	if spec.Kind != "nri.io/cxl" || !reflect.DeepEqual(spec.Devices, want) {
		t.Fatalf("CDI spec %+v", spec)
	}
	if onDisk := e.cdiSpec(device.ClaimsCDISpecName); onDisk == nil || !reflect.DeepEqual(onDisk.Devices, want) {
		t.Fatalf("CDI spec on disk %+v", onDisk)
	}
}

// The CDI specs of the claims of both drivers, built from the records:
// sorted by claim, a second result on one memdev with the env key _2, of
// the kind and in the file of the driver; companions, claims whose
// devices did not verify at the start and claims whose Prepare is not
// finishing are left out, UNPREPARING ones are kept by cxl.nri.io only;
// the spec of no device is removed.
func TestCDISpecOfClaims(t *testing.T) {
	e := newDriverEnv(t, []fake.MemdevSpec{slicedSpec()}, fake.MemdevSpec{Serial: serialPoolS, HostBridge: 24})
	b := addLocalResult(localClaim("b", localDev, envBlockSize), "second", localDev, envBlockSize)
	e.mustPrepare(e.local, b)
	e.mustPrepare(e.local, localClaim("a", device.DRAMDeviceName, 64*mib))
	e.mustPrepare(e.pool, poolClaim("p2", "shared0", poolSharedData))
	e.mustPrepare(e.pool, poolClaim("p1", "shared0", poolSharedData))
	if got := e.cdiNames(e.local); !slices.Equal(got, []string{"claim-a-0", "claim-b-0", "claim-b-1"}) {
		t.Fatalf("local CDI devices %v", got)
	}
	if got := e.cdiNames(e.pool); !slices.Equal(got, []string{"claim-p1-0", "claim-p2-0"}) {
		t.Fatalf("pool CDI devices %v", got)
	}
	if spec := e.cdiSpec(device.PoolCDISpecName); spec.Kind != device.PoolCDIKind {
		t.Fatalf("pool CDI spec kind %q", spec.Kind)
	}
	b1 := e.cdiDevice(e.local, "claim-b-1")
	hasEnv(t, b1, "CXL_CLAIM_b_1=1", "CXL_C100E2E1_2_MODE=numa", "CXL_C100E2E1_2_SERIAL=0xc100e2e1", "CXL_C100E2E1_2_SIZE=134217728")
	hasEnv(t, e.cdiDevice(e.local, "claim-b-0"), "CXL_C100E2E1_MODE=numa")

	// the claims as the spec takes them by their state
	doc := e.st.Snapshot().Clone()
	setState := func(driver, uid string, s state.PreparationState) {
		doc.Preparation(driver, uid).State = s
	}
	names := func(p *Plugin, pending string) []string {
		spec, err := buildCDISpec(doc, p.Name(), p.Rules().CDIKind, e.st.ViewOptions(), pending, p.Rules().CDIUnpreparing)
		mustOK(t, err)
		var out []string
		for _, d := range spec.Devices {
			out = append(out, d.Name)
		}
		return out
	}
	setState(device.DriverName, "a", state.PreparationUnpreparing)
	setState(device.DriverName, "b", state.PreparationUnrestored)
	setState(device.PoolDriverName, "p1", state.PreparationUnpreparing)
	setState(device.PoolDriverName, "p2", state.PreparationPreparing)
	if got := names(e.local, ""); !slices.Equal(got, []string{"claim-a-0"}) {
		t.Fatalf("local %v", got)
	}
	if got := names(e.pool, ""); len(got) != 0 {
		t.Fatalf("pool %v", got)
	}
	if got := names(e.pool, "p2"); !slices.Equal(got, []string{"claim-p2-0"}) {
		t.Fatalf("pool with the pending claim %v", got)
	}
	doc.Preparation(device.DriverName, "a").Lease = "l1"
	if got := names(e.local, "a"); len(got) != 0 {
		t.Fatalf("a pending companion %v", got)
	}

	for _, uid := range []string{"a", "b"} {
		e.mustUnprepare(e.local, uid)
	}
	if e.cdiSpec(device.ClaimsCDISpecName) != nil || e.cdiSpec(device.PoolCDISpecName) == nil {
		t.Fatal("the spec of no device is not removed, or the spec of the other driver is")
	}
	for _, uid := range []string{"p1", "p2"} {
		e.mustUnprepare(e.pool, uid)
	}
	e.wantClean()
}

// writeCDISpec writes a spec of devices and removes the spec file of no
// devices; writeCDI writes nothing without a CDI cache.
func TestWriteCDISpec(t *testing.T) {
	dir := t.TempDir()
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(dir), cdiapi.WithAutoRefresh(false))
	mustOK(t, err)
	v := PoolRules(device.PoolDriverName, "", "").voice
	spec := &cdiSpecs.Spec{Kind: device.PoolCDIKind, Devices: []cdiSpecs.Device{{Name: "claim-u1-0",
		ContainerEdits: cdiSpecs.ContainerEdits{Env: []string{"CXL_CLAIM_u1_0=1"}}}}}
	mustOK(t, writeCDISpec(cache, spec, device.PoolCDISpecName, v))
	m, _ := filepath.Glob(filepath.Join(dir, device.PoolCDISpecName+".*"))
	if len(m) != 1 || spec.Version == "" {
		t.Fatalf("spec files %v, version %q", m, spec.Version)
	}
	data, err := os.ReadFile(m[0])
	mustOK(t, err)
	if !strings.Contains(string(data), "claim-u1-0") {
		t.Fatalf("spec\n%s", data)
	}
	mustOK(t, writeCDISpec(cache, &cdiSpecs.Spec{Kind: device.PoolCDIKind}, device.PoolCDISpecName, v))
	if m, _ := filepath.Glob(filepath.Join(dir, "*")); len(m) != 0 {
		t.Fatalf("left %v", m)
	}
	// again: nothing to remove is not an error
	mustOK(t, writeCDISpec(cache, &cdiSpecs.Spec{Kind: device.PoolCDIKind}, device.PoolCDISpecName, v))
	st, err := store.Open(t.Context(), store.Options{Dir: t.TempDir(), BootID: "b1"})
	mustOK(t, err)
	defer func() { _ = st.Close() }()
	p := &Plugin{rules: PoolRules(device.PoolDriverName, "", ""), st: st}
	mustOK(t, p.WriteCDI())
}

// The words of the two drivers about their CDI specs: cxl.nri.io's without
// a prefix and its errors not wrapped, the pool driver's with its name and
// its errors wrapped (and no line for the removal of an empty spec).
func TestCDIWords(t *testing.T) {
	for _, rules := range []SourceRules{LocalRules(""), PoolRules(device.PoolDriverName, "", "")} {
		t.Run(rules.Name, func(t *testing.T) {
			dir := t.TempDir()
			cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(dir), cdiapi.WithAutoRefresh(false))
			mustOK(t, err)
			name := rules.CDISpecName
			spec := func() *cdiSpecs.Spec {
				return &cdiSpecs.Spec{Kind: rules.CDIKind, Devices: []cdiSpecs.Device{{Name: "claim-u1-0",
					ContainerEdits: cdiSpecs.ContainerEdits{Env: []string{"CXL_CLAIM_u1_0=1"}}}}}
			}
			logs := captureKlogV(t, "5")
			mustOK(t, writeCDISpec(cache, spec(), name, rules.voice))
			mustOK(t, writeCDISpec(cache, &cdiSpecs.Spec{Kind: rules.CDIKind}, name, rules.voice))
			// the spec file a directory with an entry: the write fails
			mustOK(t, os.MkdirAll(filepath.Join(dir, name+".yaml", "entry"), 0o755))
			err = writeCDISpec(cache, spec(), name, rules.voice)
			wantErrText(t, err, "failed to write CDI spec "+name+": ")
			wrote, removed := "Wrote CDI spec "+name+" with 1 devices", "Removed empty CDI spec "+name
			if rules.Source == state.SourcePool {
				wrote, removed = rules.Name+": wrote CDI spec "+name+" with 1 devices", ""
			}
			out := logs()
			wantLogText(t, out, wrote)
			if removed != "" {
				wantLogText(t, out, removed)
			} else if strings.Contains(out, "Removed empty CDI spec") {
				t.Fatalf("a removal line of the pool driver:\n%s", out)
			}
			if wrapped := errors.Unwrap(err) != nil; wrapped != (rules.Source == state.SourcePool) {
				t.Fatalf("the error %v wrapped: %v", err, wrapped)
			}
			if verr := rules.voice.cdiVersionError(errSteered); rules.Source == state.SourcePool {
				if verr.Error() != "CDI spec version: "+errSteered.Error() || !errors.Is(verr, errSteered) {
					t.Fatalf("version error %v", verr)
				}
			} else if verr.Error() != "failed to get minimum required CDI spec version: "+errSteered.Error() || errors.Is(verr, errSteered) {
				t.Fatalf("version error %v", verr)
			}
		})
	}
}

// The words of the two drivers about the errors of a rollback, by step.
func TestRollbackWords(t *testing.T) {
	want := map[string][]string{
		device.DriverName: {"claim demo/c1: rollback: " + errSteered.Error(), "claim demo/c1: rollback: " + errSteered.Error(),
			"claim u1: rollback: " + errSteered.Error(), "claim demo/c1: rollback: " + errSteered.Error()},
		device.PoolDriverName: {"cxl-pool.nri.io: rollback: claim demo/c1: " + errSteered.Error(), "cxl-pool.nri.io: rollback: " + errSteered.Error(),
			"cxl-pool.nri.io: claim demo/c1: " + errSteered.Error(), "cxl-pool.nri.io: " + errSteered.Error()},
	}
	for _, rules := range []SourceRules{LocalRules(""), PoolRules(device.PoolDriverName, "", "")} {
		for i, step := range []rollbackStep{rollbackRevoke, rollbackRelease, rollbackCommit, rollbackCDI} {
			logs := captureKlogV(t, "0")
			rules.voice.rollbackError(step, "u1", "demo/c1", errSteered)
			if out := logs(); !strings.HasSuffix(strings.TrimSpace(out), "] "+want[rules.Name][i]) {
				t.Errorf("%s: step %d: %q, want %q", rules.Name, step, out, want[rules.Name][i])
			}
		}
	}
}

// The names of the CDI devices and of the result markers: the claim UID
// and the result, the UID's hyphens as underscores in the marker.
func TestCDINames(t *testing.T) {
	if got := ClaimCDIDeviceName("a-b", 3); got != "claim-a-b-3" {
		t.Fatalf("device name %q", got)
	}
	if got := ResultEnvVarName("a-b", 3); got != "CXL_CLAIM_a_b_3" {
		t.Fatalf("marker %q", got)
	}
	for _, tc := range []struct {
		env string
		uid string
		n   int
		ok  bool
	}{
		{"CXL_CLAIM_a_b_3=1", "a-b", 3, true},
		{"CXL_CLAIM_u1_0", "u1", 0, true},
		{"CXL_CLAIM_u1_03=1", "", 0, false},
		{"CXL_CLAIM_u1_x=1", "", 0, false},
		{"CXL_CLAIM__1=1", "", 0, false},
		{"CXL_DRAM_SIZE=1", "", 0, false},
	} {
		uid, n, ok := ResultFromEnvVar(tc.env)
		if uid != tc.uid || n != tc.n || ok != tc.ok {
			t.Errorf("%s: %q %d %v", tc.env, uid, n, ok)
		}
	}
}
