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

// Command statedoc renders the transition tables and the record headers of
// the CXL driver's internal/state package, and those of the kernel objects
// of pkg/cxl/kernel, into docs/memory/cxl/states.md.
// It runs by go generate in cmd/plugins/dra-driver-cxl.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	stateDir := flag.String("state", "internal/state", "the directory of the Go files of the state package")
	kernelDir := flag.String("kernel", "../../../pkg/cxl/kernel", "the directory of the Go files of the kernel package")
	out := flag.String("o", "../../../docs/memory/cxl/states.md", "the markdown file to write")
	flag.Parse()
	data, err := render(*stateDir, *kernelDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "statedoc: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "statedoc: %v\n", err)
		os.Exit(1)
	}
}
