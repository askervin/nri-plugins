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

package kernel

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The reading of sysfs attributes. Units differ per attribute: hex with 0x
// (memdev ram/size, region size and resource), hex without 0x
// (block_size_bytes), decimal (dax device size, available_size), 512-byte
// sectors (block device size), kB (node meminfo).

// ReadTrim returns the content of a file without leading and trailing
// white space.
func ReadTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ParseHex returns the hex number in s, with or without 0x.
func ParseHex(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"), 16, 64)
}

// ReadUint returns the number in a sysfs attribute, decimal or 0x hex.
func ReadUint(path string) (uint64, error) {
	s, err := ReadTrim(path)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q in %s: %w", s, path, err)
	}
	return v, nil
}

// readInt returns the decimal number in a sysfs attribute, def if it
// cannot be read.
func readInt(path string, def int) int {
	s, err := ReadTrim(path)
	if err != nil {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// parseDevNumbers returns the device numbers in "major:minor".
func parseDevNumbers(name, v string) (major, minor int, err error) {
	ma, mi, ok := strings.Cut(v, ":")
	if ok {
		major, err = strconv.Atoi(ma)
		if err == nil {
			minor, err = strconv.Atoi(mi)
		}
	}
	if !ok || err != nil {
		return 0, 0, fmt.Errorf("%s: cannot parse device numbers %q", name, v)
	}
	return major, minor, nil
}

var trailingNum = regexp.MustCompile(`^(.*?)(\d+)$`)

// NatLess orders names with the same prefix by their trailing numbers
// (region2 before region10), others lexically.
func NatLess(a, b string) bool {
	ma, mb := trailingNum.FindStringSubmatch(a), trailingNum.FindStringSubmatch(b)
	if ma != nil && mb != nil && ma[1] == mb[1] {
		na, _ := strconv.Atoi(ma[2])
		nb, _ := strconv.Atoi(mb[2])
		return na < nb
	}
	return a < b
}

// sortNat sorts names in natural order.
func sortNat(names []string) {
	sort.Slice(names, func(i, j int) bool { return NatLess(names[i], names[j]) })
}

// hasDriver tells whether a device directory has a bound driver.
func hasDriver(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "driver"))
	return err == nil
}

// driverOf returns the driver bound to a device directory, "" if none.
func driverOf(dir string) string {
	t, err := os.Readlink(filepath.Join(dir, "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

// exists tells whether a path exists, following symlinks.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (k *Kernel) cxlDev(p ...string) string {
	return filepath.Join(append([]string{k.sysRoot(), "bus", "cxl", "devices"}, p...)...)
}

func (k *Kernel) daxDev(dax string, p ...string) string {
	return filepath.Join(append([]string{k.sysRoot(), "bus", "dax", "devices", dax}, p...)...)
}

func (k *Kernel) daxDriver(driver string, p ...string) string {
	return filepath.Join(append([]string{k.sysRoot(), "bus", "dax", "drivers", driver}, p...)...)
}

func (k *Kernel) ndDev(p ...string) string {
	return filepath.Join(append([]string{k.sysRoot(), "bus", "nd", "devices"}, p...)...)
}

func (k *Kernel) block(n int, p ...string) string {
	return filepath.Join(append([]string{k.sysRoot(), "devices", "system", "memory", "memory" + strconv.Itoa(n)}, p...)...)
}

// listCXL returns the names of the CXL devices that match pattern, in
// natural order.
func (k *Kernel) listCXL(pattern string) []string {
	m, _ := filepath.Glob(k.cxlDev(pattern))
	out := make([]string, 0, len(m))
	for _, p := range m {
		out = append(out, filepath.Base(p))
	}
	sortNat(out)
	return out
}
