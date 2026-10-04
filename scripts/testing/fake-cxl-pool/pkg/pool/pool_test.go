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

package pool

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPoolCapacity(t *testing.T) {
	p := New("default", t.TempDir(), 1<<30, true)
	if err := p.Reserve("a", 512<<20); err != nil {
		t.Fatal(err)
	}
	if err := p.Reserve("b", 512<<20); err != nil {
		t.Fatal(err)
	}
	if err := p.Reserve("c", 1); err == nil {
		t.Fatal("expected capacity error")
	}
	if p.Used() != 1<<30 || p.Free() != 0 {
		t.Fatalf("unexpected used %d free %d", p.Used(), p.Free())
	}
	// resizing an existing reservation does not double count
	if err := p.Reserve("b", 256<<20); err != nil {
		t.Fatal(err)
	}
	p.Unreserve("a")
	if p.Used() != 256<<20 {
		t.Fatalf("unexpected used %d", p.Used())
	}
}

func TestBackingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "d0.raw")
	if err := EnsureBackingFile(path, 256<<20); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() != 256<<20 {
		t.Fatalf("unexpected file %v %v", st, err)
	}
	// a larger existing file is kept
	if err := EnsureBackingFile(path, 1<<20); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Size() != 256<<20 {
		t.Fatalf("file was shrunk")
	}
	if err := RemoveBackingFile(path); err != nil {
		t.Fatal(err)
	}
	if err := RemoveBackingFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestSerials(t *testing.T) {
	s := NewSerials(0xc1f00000)
	if err := s.Use(0xc1f00001, "a"); err != nil {
		t.Fatal(err)
	}
	if sn := s.Next("b"); sn != 0xc1f00002 {
		t.Fatalf("unexpected serial 0x%x", sn)
	}
	if err := s.Use(0xc1f00002, "c"); err == nil {
		t.Fatal("expected conflict")
	}
	s.Release(0xc1f00001)
	if sn := s.Next("d"); sn != 0xc1f00001 {
		t.Fatalf("unexpected serial 0x%x", sn)
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"dev0", "shared0", "n4-cxl-fedora-43-containerd.memdev3", "a"} {
		if err := ValidName(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	for _, n := range []string{"", "Dev0", "a_b", "-a", "a@b", "a/b"} {
		if err := ValidName(n); err == nil {
			t.Errorf("%q: expected error", n)
		}
	}
}
