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
	"testing"
	"time"
)

func TestExampleConfig(t *testing.T) {
	cfg, err := LoadConfig("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9909" || uint64(*cfg.SharedSerialBase) != 0xc1ae0000 || uint64(*cfg.ExclusiveSerialBase) != 0xc1ee0000 || len(cfg.Devices) != 2 ||
		uint64(*cfg.Devices[0].Serial) != 0xc1ae0001 || cfg.Devices[1].Size != 512<<20 || cfg.Devices[1].Pool != "default" ||
		time.Duration(cfg.DetachTimeout) != 15*time.Second || time.Duration(cfg.Discovery.Interval) != 10*time.Second ||
		cfg.Pools[0].Capacity != 8<<30 || !*cfg.Pools[0].Sharable {
		t.Fatalf("unexpected config %+v", cfg)
	}
}
