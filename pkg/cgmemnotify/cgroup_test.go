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

package cgmemnotify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const numaStat = `anon N0=4096 N1=2912256 N2=0
file N0=1048576 N1=0 N2=8192
kernel_stack N0=16384 N1=0 N2=0
shmem N0=0 N1=100 N2=200
anon_thp N0=0 N1=2097152 N2=0
`

func TestParseNumaStat(t *testing.T) {
	usage, err := parseNumaStat(strings.NewReader(numaStat), []string{"anon", "shmem"})
	require.NoError(t, err)
	require.Equal(t, map[int]int64{0: 4096, 1: 2912356, 2: 200}, usage)

	usage, err = parseNumaStat(strings.NewReader(numaStat), []string{"missing"})
	require.NoError(t, err)
	require.Empty(t, usage)

	_, err = parseNumaStat(strings.NewReader("anon N0=4096 N1\n"), []string{"anon"})
	require.Error(t, err)

	_, err = parseNumaStat(strings.NewReader("anon N0=4096 X1=2\n"), []string{"anon"})
	require.Error(t, err)
}

func TestParseMemoryEvents(t *testing.T) {
	events, err := parseMemoryEvents(strings.NewReader("low 0\nhigh 42\nmax 1\noom 0\noom_kill 0\n"))
	require.NoError(t, err)
	require.Equal(t, int64(42), events["high"])
	require.Equal(t, int64(1), events["max"])

	_, err = parseMemoryEvents(strings.NewReader("high forty-two\n"))
	require.Error(t, err)
}

func TestParseInts(t *testing.T) {
	values, err := parseInts(strings.NewReader("12\n\n345\n"))
	require.NoError(t, err)
	require.Equal(t, []int{12, 345}, values)

	values, err = parseInts(strings.NewReader(""))
	require.NoError(t, err)
	require.Empty(t, values)

	_, err = parseInts(strings.NewReader("12\nabc\n"))
	require.Error(t, err)
}

func TestCgroupFileReaders(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "memory.current"), []byte("123456\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "memory.numa_stat"), []byte(numaStat), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("1\n22\n"), 0644))

	current, err := MemoryCurrent(dir)
	require.NoError(t, err)
	require.Equal(t, int64(123456), current)

	usage, err := NumaUsage(dir, "anon")
	require.NoError(t, err)
	require.Equal(t, map[int]int64{0: 4096, 1: 2912256, 2: 0}, usage)

	pids, err := Procs(dir)
	require.NoError(t, err)
	require.Equal(t, []int{1, 22}, pids)

	_, err = MemoryCurrent(filepath.Join(dir, "missing"))
	require.Error(t, err)
}

func TestCrossingString(t *testing.T) {
	require.Equal(t, "none", NoCrossing.String())
	require.Equal(t, "lower", LowerCrossed.String())
	require.Equal(t, "upper", UpperCrossed.String())
	require.Equal(t, "Crossing(7)", Crossing(7).String())
}
