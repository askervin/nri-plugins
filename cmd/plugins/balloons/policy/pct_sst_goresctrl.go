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

package balloons

import (
	"fmt"
	"sort"

	gosst "github.com/intel/goresctrl/pkg/sst"
	"github.com/intel/goresctrl/pkg/utils"
)

// sstGoresctrl is the real-hardware sst backed by
// goresctrl/pkg/sst.
type sstGoresctrl struct {
	plat *gosst.Platform
}

func newSstGoresctrl() (sst, error) {
	b := &sstGoresctrl{}
	if !gosst.SstSupported() {
		return b, nil
	}
	plat, err := gosst.Init()
	if err != nil {
		return nil, fmt.Errorf("SST init failed: %w", err)
	}
	b.plat = plat
	return b, nil
}

func (b *sstGoresctrl) Supported() bool { return b.plat != nil }

func (b *sstGoresctrl) ClosCount() int {
	if b.plat == nil {
		return 0
	}
	return b.plat.ClosCount()
}

func (b *sstGoresctrl) PackageIDs() []int {
	if b.plat == nil {
		return nil
	}
	pkgs := b.plat.Packages()
	ids := make([]int, 0, len(pkgs))
	for _, p := range pkgs {
		ids = append(ids, p.ID())
	}
	sort.Ints(ids)
	return ids
}

func (b *sstGoresctrl) CPUsOfPackage(pkgID int) []int {
	if b.plat == nil {
		return nil
	}
	pkg, ok := b.plat.Package(pkgID)
	if !ok {
		return nil
	}
	st, err := pkg.GetStatus()
	if err != nil {
		log.Warnf("pct: failed to get package %d status: %v", pkgID, err)
		return nil
	}
	out := []int{}
	for _, pu := range st.Punits {
		out = append(out, pu.CPUs.Members()...)
	}
	sort.Ints(out)
	return out
}

func (b *sstGoresctrl) PrepareManagedMode() error {
	if b.plat == nil {
		return fmt.Errorf("SST not supported on this host")
	}
	for _, pkg := range b.plat.Packages() {
		if err := pkg.CPReset(); err != nil {
			return fmt.Errorf("CPReset on package %d: %w", pkg.ID(), err)
		}
		if err := pkg.TFEnable(); err != nil {
			return fmt.Errorf("TFEnable on package %d: %w", pkg.ID(), err)
		}
		if err := pkg.CPSetPriorityType(gosst.Ordered); err != nil {
			return fmt.Errorf("CPSetPriorityType on package %d: %w", pkg.ID(), err)
		}
	}
	return nil
}

func (b *sstGoresctrl) ConfigureClos(cfg pctClosConfig) error {
	if b.plat == nil {
		return fmt.Errorf("SST not supported on this host")
	}
	cc := gosst.ClosConfig{MinFreq: cfg.MinFreq, MaxFreq: cfg.MaxFreq}
	for _, pkg := range b.plat.Packages() {
		if err := pkg.ClosConfigure(cfg.ClosID, cc); err != nil {
			return fmt.Errorf("ClosConfigure(%d) on package %d: %w", cfg.ClosID, pkg.ID(), err)
		}
	}
	return nil
}

func (b *sstGoresctrl) EnableCP() error {
	if b.plat == nil {
		return fmt.Errorf("SST not supported on this host")
	}
	for _, pkg := range b.plat.Packages() {
		if err := pkg.CPEnable(); err != nil {
			return fmt.Errorf("CPEnable on package %d: %w", pkg.ID(), err)
		}
	}
	return nil
}

func (b *sstGoresctrl) AssociateCPUs(assocs []pctClosAssoc) error {
	if b.plat == nil {
		return fmt.Errorf("SST not supported on this host")
	}
	byClos := map[int]utils.IDSet{}
	for _, a := range assocs {
		if _, ok := byClos[a.ClosID]; !ok {
			byClos[a.ClosID] = utils.NewIDSet()
		}
		byClos[a.ClosID].Add(utils.ID(a.CPU))
	}
	for clos, cpus := range byClos {
		if err := b.plat.ClosAssociate(clos, cpus); err != nil {
			return fmt.Errorf("ClosAssociate(%d) for cpus %s: %w", clos, cpus, err)
		}
	}
	return nil
}

func (b *sstGoresctrl) GetCPUClosID(cpu int) (int, error) {
	if b.plat == nil {
		return 0, fmt.Errorf("SST not supported on this host")
	}
	return b.plat.GetCPUClosID(utils.ID(cpu))
}

// MaxHpCpus returns the per-package SST-BF priority-core count.
// The second return value is false when SST-BF support is not
// exposed on the package.
func (b *sstGoresctrl) MaxHpCpus(pkgID int) (int, bool) {
	if b.plat == nil {
		return 0, false
	}
	pkg, ok := b.plat.Package(pkgID)
	if !ok {
		return 0, false
	}
	st, err := pkg.GetStatus()
	if err != nil {
		return 0, false
	}
	total := 0
	any := false
	for _, pu := range st.Punits {
		if !pu.BF.Supported {
			continue
		}
		any = true
		total += pu.BF.Cores.Size()
	}
	if !any {
		return 0, false
	}
	return total, true
}

func (b *sstGoresctrl) Shutdown() error {
	if b.plat == nil {
		return nil
	}
	for _, pkg := range b.plat.Packages() {
		if err := pkg.CPReset(); err != nil {
			return fmt.Errorf("CPReset on package %d: %w", pkg.ID(), err)
		}
	}
	return nil
}
