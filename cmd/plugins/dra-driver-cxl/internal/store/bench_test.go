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

package store

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state/statetest"
)

// bigRecords returns the test records with 50 more prepared claims.
func bigRecords() state.Records {
	r := statetest.Records()
	for i := range 50 {
		uid := fmt.Sprintf("99999999-0000-0000-0000-%012d", i)
		r.Preparations = append(r.Preparations, state.Preparation{
			UID: uid, Driver: statetest.LocalDriver, ClaimName: "demo/c" + uid, BootID: statetest.BootID,
			State: state.PreparationPrepared,
			Results: []state.Result{{
				Index: 0, Kind: state.ResultDRAM, Request: "dram", Pool: statetest.Node, Device: "dram",
				DRAM: &state.DRAMResult{NumaNodes: []int{0}, Size: 1 << 30},
			}},
		})
	}
	return r
}

// benchmarkCommits commits b.N changes of the steering records of a
// document of 50 claims from parallel callers.
func benchmarkCommits(b *testing.B, callers int) {
	s, err := Open(context.Background(), Options{
		Dir: b.TempDir(), BootID: statetest.BootID,
		PoolDir: b.TempDir(), PoolDriver: statetest.PoolDriver,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			b.Error(err)
		}
	}()
	if err := s.Commit(context.Background(), Durable, func(doc *Document) error {
		doc.Records = bigRecords()
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	writes := s.writes.Load()
	b.ResetTimer()
	var wg sync.WaitGroup
	for c := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := c; i < b.N; i += callers {
				if err := s.Commit(context.Background(), Durable, addSteered(fmt.Sprintf("c%d", i))); err != nil {
					b.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	b.ReportMetric(float64(s.writes.Load()-writes)/float64(b.N), "writes/commit")
}

func BenchmarkDurableCommit(b *testing.B)          { benchmarkCommits(b, 1) }
func BenchmarkDurableCommit8Callers(b *testing.B)  { benchmarkCommits(b, 8) }
func BenchmarkDurableCommit50Callers(b *testing.B) { benchmarkCommits(b, 50) }
