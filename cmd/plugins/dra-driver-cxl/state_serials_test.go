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

import (
	"encoding/json"
	"maps"
	"slices"
	"time"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
)

// The tests read and write the provenance records of the serials as the
// content of poolSerials.json.
func init() {
	serialsFileContent = serialsContent
	putSerialsFileContent = func(doc *store.Document, data []byte) error {
		var f poolSerialsFile
		if err := json.Unmarshal(data, &f); err != nil {
			return err
		}
		putSerials(doc, &f)
		return nil
	}
}

// serialRecord is a remembered serial.
type serialRecord struct {
	Serial string `json:"serial"` // 0x<lower-case hex>
	// Pool is <driver>/<pool> of the ResourceSlice or claim that listed
	// it last, "" when it was not listed (prepared or local).
	Pool string `json:"pool,omitempty"`
	// Local is true for a memdev taken as a local one: it was never in a
	// pool slice or prepared by the pool driver.
	Local bool `json:"local,omitempty"`
	// Seen is when it was last seen in a pool slice, prepared or on the
	// node (for information: the rules use observed absence).
	Seen time.Time `json:"seen"`
}

// poolSerialsFile is the content of poolSerials.json.
type poolSerialsFile struct {
	Serials []*serialRecord `json:"serials"`
	// Pools are the pools with serials in their ResourceSlices, with the
	// time of the last list that had them.
	Pools map[string]time.Time `json:"pools,omitempty"`
}

// putSerials replaces the provenance of the serials and the listed pools
// in doc with those of the content of poolSerials.json.
func putSerials(doc *store.Document, f *poolSerialsFile) {
	doc.Provenance, doc.ListedPools = nil, nil
	for _, r := range f.Serials {
		if r == nil {
			continue
		}
		v, err := api.ParseSerial(r.Serial)
		if err != nil {
			continue
		}
		p := state.Provenance{Serial: state.Serial(v), State: state.ProvenancePool, Pool: r.Pool, LastSeen: r.Seen}
		if r.Local {
			p.State = state.ProvenanceLocal
		}
		doc.Provenance = append(doc.Provenance, p)
	}
	for _, pool := range slices.Sorted(maps.Keys(f.Pools)) {
		doc.ListedPools = append(doc.ListedPools, state.ListedPool{Pool: pool, Listed: f.Pools[pool]})
	}
}

// serialsContent returns the content of poolSerials.json of the records in
// doc.
func serialsContent(doc *store.Document) ([]byte, error) {
	f := poolSerialsFile{}
	for _, p := range doc.Provenance {
		f.Serials = append(f.Serials, &serialRecord{Serial: p.Serial.String(), Pool: p.Pool, Local: p.State == state.ProvenanceLocal, Seen: p.LastSeen})
	}
	if len(doc.ListedPools) > 0 {
		f.Pools = map[string]time.Time{}
		for _, lp := range doc.ListedPools {
			f.Pools[lp.Pool] = lp.Listed
		}
	}
	return json.MarshalIndent(&f, "", "  ")
}
