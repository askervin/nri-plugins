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

package server

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestExampleConfig(t *testing.T) {
	cfg, err := LoadConfig("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9909" || uint64(*cfg.SharedSerialBase) != 0xc1ae0000 || uint64(*cfg.ExclusiveSerialBase) != 0xc1ee0000 || len(cfg.Devices) != 3 ||
		uint64(*cfg.Devices[0].Serial) != 0xc1ae0001 || cfg.Devices[1].Size != 512<<20 || cfg.Devices[1].Pool != "default" ||
		time.Duration(cfg.DetachTimeout) != 15*time.Second || time.Duration(cfg.Discovery.Interval) != 10*time.Second ||
		cfg.Pools[0].Capacity != 8<<30 || !*cfg.Pools[0].Sharable ||
		cfg.Devices[1].Persistent || !cfg.Devices[2].Persistent || !cfg.Devices[2].Shared ||
		cfg.Name != "fake-cxl-pool" || cfg.Discovery.Control != "" || cfg.Discovery.Slots != nil {
		t.Fatalf("unexpected config %+v", cfg)
	}
}

// TestExampleConfigSecondServer parses the commented config of the second
// server of "Several pool servers" in the example.
func TestExampleConfigSecondServer(t *testing.T) {
	b, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(b), "# Several pool servers\n")
	if !ok {
		t.Fatal("no \"Several pool servers\" block")
	}
	var lines []string
	for _, l := range strings.Split(block, "\n") {
		if y, ok := strings.CutPrefix(l, "#   "); ok {
			lines = append(lines, y)
		}
	}
	cfg, err := ParseConfig([]byte(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatalf("%v\n%s", err, strings.Join(lines, "\n"))
	}
	if cfg.Name != "pool-b" || cfg.Listen != "127.0.0.1:9910" || uint64(*cfg.SharedSerialBase) != 0xc1ae1000 ||
		uint64(*cfg.ExclusiveSerialBase) != 0xc1ee1000 || cfg.StateFile != "/tmp/fake-cxl-pool-b.state.json" ||
		cfg.Pools[0].Dir != "/tmp/fake-cxl-pool-b" || len(cfg.Discovery.Names) != 1 || uint64(*cfg.Devices[0].Serial) != 0xc1ee1001 {
		t.Fatalf("unexpected config %+v", cfg)
	}
}
