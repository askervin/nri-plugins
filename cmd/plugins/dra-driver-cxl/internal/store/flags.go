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
	"flag"
)

// Flags are the command line flags of the store.
type Flags struct {
	// CompatViews writes the views of state.json (Options.CompatViews).
	CompatViews bool
	// DiscardOldState starts with old state files and CXL regions on the
	// node, moving the files aside.
	DiscardOldState bool
	// NewState starts with a new document when neither the document nor
	// the previous one decodes.
	NewState bool
}

// Register registers the flags in fs.
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.BoolVar(&f.CompatViews, "compat-views", true,
		"write preparedClaims.json, preparedClaimsInfo.json, preparedPoolClaims.json, localDevices.json and leases.json as views of state.json")
	fs.BoolVar(&f.DiscardOldState, "discard-old-state", false,
		"start although old state files and CXL regions exist, moving the files aside")
	fs.BoolVar(&f.NewState, "new-state", false,
		"start with a new state.json when neither state.json nor state.json.prev can be read")
}
