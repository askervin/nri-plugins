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
	"strings"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

// A persistent local memdev whose Prepare a process stop cut once its
// region was made is not forgotten when it is a pool device now: only a ram
// region is in the making until its first part; the recovery releases the
// region of the cut Prepare.
func TestLocalForgetLocalPersistent(t *testing.T) {
	v := newEnv(t, fake.MemdevSpec{Serial: serialP, Pmem: gib})
	v.f.CutAfter("ndctl create-namespace")
	if !v.cut(func() {
		_ = v.prepare(localDriver, "p", localReq("p", 0, serialP, state.ModeBlock, state.KindPersistent, 0))
	}) {
		t.Fatal("not cut")
	}
	reg := ownRegion(v.records(), serialP, state.RegionPmem)
	if reg == nil || reg.State != state.RegionOwned {
		t.Fatalf("region %+v", reg)
	}
	_ = v.st.Close()
	v.open()
	logs := captureKlog(t)
	if err := v.e.ForgetLocal(context.Background(), []state.Serial{serialP}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs(), "forgetting it without touching its regions") {
		t.Fatalf("the persistent memdev forgotten:\n%s", logs())
	}
	if v.records().Memdev(serialP) == nil {
		t.Fatal("the record of the persistent memdev is gone")
	}
	before := v.f.Commands()
	if _, err := v.e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cmds := v.f.CommandsSince(before); !strings.Contains(cmds, "cxl destroy-region "+string(reg.Ref())) {
		t.Fatalf("the region of the cut Prepare is not released:\n%s", cmds)
	}
	finish(t, v, "recovered")
}
