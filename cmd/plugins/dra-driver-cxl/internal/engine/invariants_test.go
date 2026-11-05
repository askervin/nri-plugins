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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// Each invariant finds the violation of one rule on a node whose records
// and kernel otherwise agree.
func TestInvariantViolations(t *testing.T) {
	v := pmemEnv(t, "ext4")
	v.f.Plug(fake.MemdevSpec{Serial: serialA})
	v.mustPrepare(poolDriver, "n", poolReq("n", 0, serialA, state.ModeNUMA, state.KindExclusive))
	v.mustPrepare(poolDriver, "w", fsGrant("w", false, ""))
	k := v.f.Kernel()
	snap, err := k.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	opts := CheckOptions{
		MountsDirs:  []string{filepath.Join(v.dir, poolDriver, "mounts")},
		LeaseFsRoot: filepath.Join(v.dir, localDriver, "lease-fs"),
		Fenced:      []int{2},
	}
	if out := Check(v.records(), snap, opts); len(out) > 0 {
		t.Fatalf("violations of a consistent node: %v", out)
	}
	numa := v.grant("n", 0)
	for _, c := range []struct {
		inv    string
		change func(r *state.Records, s *kernel.Snapshot, o *CheckOptions)
		want   string
	}{
		{"I1", func(r *state.Records, s *kernel.Snapshot, o *CheckOptions) {
			s.Regions = append(s.Regions, kernel.RegionInfo{Name: "region9", State: kernel.RegionEnabled, Serials: []uint64{serialA}})
		}, "region9 on it that no record names"},
		{"I1", func(r *state.Records, s *kernel.Snapshot, o *CheckOptions) {
			for i := range s.Regions {
				if s.Regions[i].Name == string(numa.Got.Region) {
					s.Regions[i].State = kernel.RegionDisabled
				}
			}
		}, "OWNED, the kernel has it DISABLED"},
		{"I2", func(r *state.Records, s *kernel.Snapshot, o *CheckOptions) {
			s.DaxDevices = append(s.DaxDevices, kernel.DaxDeviceInfo{Name: "dax9.1", Region: string(numa.Got.Region), State: kernel.DaxUnbound, Size: mib})
		}, "dax9.1 (UNBOUND) that no record names"},
		{"I3", func(r *state.Records, s *kernel.Snapshot, o *CheckOptions) {
			g := r.Grant(state.GrantRef{Claim: "w"})
			g.Got.BlockDevice.Dev.Minor = 99
		}, "is not in the kernel"},
		{"I5", func(r *state.Records, s *kernel.Snapshot, o *CheckOptions) { o.Fenced = []int{} }, "which is not fenced"},
		{"I6", func(r *state.Records, s *kernel.Snapshot, o *CheckOptions) {
			r.Grant(state.GrantRef{Claim: "w"}).Asked.ReadOnly = true
		}, "superblock read-only false with writer false"},
		{"I7", func(r *state.Records, s *kernel.Snapshot, o *CheckOptions) {
			for i := range s.Devices {
				s.Devices[i].ReadOnly = true
			}
		}, "read-only true with writer true"},
		{"I8", func(r *state.Records, s *kernel.Snapshot, o *CheckOptions) {
			s.Mounts = append(s.Mounts, kernel.MountInfo{Target: filepath.Join(o.MountsDirs[0], "a1-direct"), Source: "/dev/pmem7"})
		}, "no realised grant of a prepared claim lists it"},
		{"I10", func(r *state.Records, s *kernel.Snapshot, o *CheckOptions) {
			r.Provenance = append(r.Provenance, state.Provenance{Serial: serialL, State: state.ProvenanceHeld})
			r.Grants = append(r.Grants, state.Grant{Ref: state.GrantRef{Claim: "l"}, Serial: serialL,
				Asked: state.Asked{Source: state.SourceLocal}, State: state.GrantJournaled})
		}, "a new local grant on serial 0x11 of provenance HELD"},
		{"I12", func(r *state.Records, s *kernel.Snapshot, o *CheckOptions) {
			r.Leases = append(r.Leases, state.Lease{ID: "0123abcd", State: state.LeaseReady, Lend: &state.Lend{NumaNode: state.NumaNodePtr(7)}})
		}, "lends NUMA node 7, which has no memory online"},
	} {
		r := v.records().Clone()
		s := *snap
		s.Regions = append([]kernel.RegionInfo(nil), snap.Regions...)
		s.DaxDevices = append([]kernel.DaxDeviceInfo(nil), snap.DaxDevices...)
		s.Devices = append([]kernel.BlockDevice(nil), snap.Devices...)
		s.Mounts = append([]kernel.MountInfo(nil), snap.Mounts...)
		o := opts
		c.change(&r, &s, &o)
		found := false
		for _, viol := range Check(&r, &s, o) {
			found = found || (viol.Invariant == c.inv && strings.Contains(viol.Text, c.want))
		}
		if !found {
			t.Errorf("%s: no violation %q in %v", c.inv, c.want, Check(&r, &s, o))
		}
	}
	// the records of a source that the engine does not own are not checked
	r := v.records().Clone()
	s := *snap
	s.Regions = append(append([]kernel.RegionInfo(nil), snap.Regions...),
		kernel.RegionInfo{Name: "region9", State: kernel.RegionEnabled, Serials: []uint64{serialA}})
	if out := Check(&r, &s, CheckOptions{Sources: []state.Source{state.SourceLocal}}); len(out) > 0 {
		t.Errorf("records of the pool checked: %v", out)
	}
	_ = os.Remove(filepath.Join(opts.MountsDirs[0], "a1-direct"))
	v.mustUnprepare(poolDriver, "w")
	v.mustUnprepare(poolDriver, "n")
}
