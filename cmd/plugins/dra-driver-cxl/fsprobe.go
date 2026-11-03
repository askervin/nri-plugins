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
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
)

// The filesystem of a block device of a persistent device is known by the
// signatures of the known types in its first fsProbeBytes
// (docs/memory/cxl/usage.md "Persistent memory").

const (
	// fsProbeBytes is how much of a block device the probe reads.
	fsProbeBytes = 128 << 10
	// gfs2SuperOffset is the offset of the gfs2 superblock.
	gfs2SuperOffset = 65536
	// gfs2LockProtoDLM is the gfs2 lock protocol of a cluster.
	gfs2LockProtoDLM = "lock_dlm"
)

// fsSignature is what the probe found in the head of a block device.
type fsSignature struct {
	// Types are the known types whose signature the head has, in the order
	// of config.KnownFsTypes.
	Types []string
	// Gfs2LockProto is the lock protocol in a gfs2 superblock.
	Gfs2LockProto string
	// Ext4NeedsRecovery is set when an ext4 superblock has the incompat
	// feature needs_recovery.
	Ext4NeedsRecovery bool
}

// parseFsSignature returns the signatures of the known filesystem types in
// the head of a block device. A short head matches the signatures that it
// covers.
func parseFsSignature(head []byte) fsSignature {
	le32 := func(off int) (uint32, bool) {
		if off+4 > len(head) {
			return 0, false
		}
		return binary.LittleEndian.Uint32(head[off:]), true
	}
	be32 := func(off int) (uint32, bool) {
		if off+4 > len(head) {
			return 0, false
		}
		return binary.BigEndian.Uint32(head[off:]), true
	}
	at := func(off int, magic string) bool {
		return off+len(magic) <= len(head) && string(head[off:off+len(magic)]) == magic
	}
	var s fsSignature
	if v, ok := le32(1024); ok && v == 0xE0F5E1E2 {
		s.Types = append(s.Types, config.FsTypeErofs)
	}
	if at(0, "hsqs") {
		s.Types = append(s.Types, config.FsTypeSquashfs)
	}
	if len(head) >= 1082 && binary.LittleEndian.Uint16(head[1080:]) == 0xEF53 {
		s.Types = append(s.Types, config.FsTypeExt4)
		if v, ok := le32(1024 + 0x60); ok && v&0x4 != 0 {
			s.Ext4NeedsRecovery = true
		}
	}
	if at(0, "XFSB") {
		s.Types = append(s.Types, config.FsTypeXfs)
	}
	if at(65600, "_BHRfS_M") {
		s.Types = append(s.Types, config.FsTypeBtrfs)
	}
	magic, ok1 := be32(gfs2SuperOffset)
	meta, ok2 := be32(gfs2SuperOffset + 4)
	if ok1 && ok2 && magic == 0x01161970 && meta == 1 {
		s.Types = append(s.Types, config.FsTypeGfs2)
		if off := gfs2SuperOffset + 96; off < len(head) {
			proto := head[off:min(off+64, len(head))]
			if i := bytes.IndexByte(proto, 0); i >= 0 {
				proto = proto[:i]
			}
			s.Gfs2LockProto = string(proto)
		}
	}
	return s
}

// readFsSignature returns the signatures of the head of the block device
// dev.
func readFsSignature(m nodeMounter, dev string) (fsSignature, error) {
	head, err := m.ReadHead(dev, fsProbeBytes)
	if err != nil {
		return fsSignature{}, err
	}
	return parseFsSignature(head), nil
}

// fsType returns the type of the filesystem of the block device dev of the
// device with the serial with the signatures s and the declared type ("":
// none). A type that the plugin does not know is taken as declared when
// the device has no signature of a known type.
func (s fsSignature) fsType(serial uint64, dev, declared string) (string, error) {
	prefix := "device " + api.FormatSerial(serial) + ": "
	switch {
	case len(s.Types) == 1 && (declared == "" || declared == s.Types[0]):
		return s.Types[0], nil
	case len(s.Types) == 1:
		return "", fmt.Errorf("%s%s has a filesystem of type %s, not %s", prefix, dev, s.Types[0], declared)
	case len(s.Types) > 1 && slices.Contains(s.Types, declared):
		return declared, nil
	case len(s.Types) > 1:
		return "", fmt.Errorf("%s%s has signatures of several filesystems (%s): set device.fsType", prefix, dev, strings.Join(s.Types, ", "))
	case declared == "":
		return "", fmt.Errorf("%s%s has no filesystem of a type that the plugin knows (%s): set device.fsType", prefix, dev, listOr(config.KnownFsTypes))
	case config.KnownFsType(declared):
		return "", fmt.Errorf("%s%s has no filesystem of type %s (no signature of a type that the plugin knows)", prefix, dev, declared)
	}
	return declared, nil
}

// cluster returns true if a filesystem of the type with the signatures s
// is a cluster filesystem (gfs2 with lock_dlm), else why it is
// single-host.
func (s fsSignature) cluster(fsType string) (bool, string) {
	switch {
	case !config.FsTypeCluster(fsType):
		return false, fsType + " is a single-host filesystem"
	case s.Gfs2LockProto == gfs2LockProtoDLM:
		return true, ""
	case s.Gfs2LockProto == "":
		return false, fsType + " without a lock protocol is a single-host filesystem"
	}
	return false, fsType + " with " + s.Gfs2LockProto + " is a single-host filesystem"
}

// listOr returns the values as "a, b or c".
func listOr(values []string) string {
	if len(values) < 2 {
		return strings.Join(values, "")
	}
	return strings.Join(values[:len(values)-1], ", ") + " or " + values[len(values)-1]
}
