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

package qemu

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// maxSunPath is the longest unix socket path that connect(2) accepts
// (sun_path is 108 bytes with the terminating NUL).
const maxSunPath = 107

// dialUnix connects to a unix socket. Paths that do not fit in sun_path
// (e2e output dirs make them ~103-107 characters) are reached through the
// /proc/self/fd/N magic link of their directory, which keeps the path short
// without changing the process working directory.
func dialUnix(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	if len(path) <= maxSunPath-8 {
		return d.DialContext(ctx, "unix", path)
	}
	dir, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	short := fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), filepath.Base(path))
	if len(short) > maxSunPath {
		return nil, fmt.Errorf("socket name too long: %s", path)
	}
	return d.DialContext(ctx, "unix", short)
}

// BackendMappedIn tells if "info mtree" output shows a CXL direct mapping
// alias of the memory backend. Such an alias exists while an HDM decoder of
// a cxl-type3 device that uses the backend is committed. If it is still
// there after the device is gone from the device tree, the guest did not
// release the memory: qemu cannot finalize the device (no DEVICE_DELETED)
// and the backend stays mapped into the guest until qemu restarts.
func BackendMappedIn(mtree, objID string) bool {
	re := regexp.MustCompile(`alias cxl-direct-mapping-alias-\d+ @` + regexp.QuoteMeta(objID) + `( |$)`)
	for _, l := range strings.Split(mtree, "\n") {
		if re.MatchString(strings.TrimRight(l, "\r")) {
			return true
		}
	}
	return false
}
