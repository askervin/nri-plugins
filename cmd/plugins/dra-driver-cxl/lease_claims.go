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
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/klog/v2"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiparser "tags.cncf.io/container-device-interface/pkg/parser"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// The lease device "lease" of the cxl.nri.io slice: a claim on it gives
// the containers that reference the claim a lease socket. Prepare creates
// <data dir>/leases/<claim uid>/cxl.sock and <data dir>/lease-fs/<claim
// uid>, and returns the CDI device nri.io/cxl=lease-<claim uid>, which
// bind-mounts the socket directory at /run/cxl, the lease-fs directory
// read-only as a slave at /run/cxl/fs (the pool driver mounts the
// filesystems of fs leases below it, and they appear in the running
// containers) and the cxl-request CLI at /usr/local/bin. Requests on the
// socket are served by the broker (broker.go).

const (
	// leaseDirName is the directory of the per-claim socket directories
	// in the cxl.nri.io plugin data directory.
	leaseDirName = "leases"
	// leaseSocketName is the socket in a claim's directory.
	leaseSocketName = "cxl.sock"
	// leaseFsDirName is the directory of the per-claim directories of the
	// mounts of fs leases in the cxl.nri.io plugin data directory. Only
	// the plugin writes them; containers have them read-only.
	leaseFsDirName = "lease-fs"
	// leaseFsMountPoint is the mount point of api.FsDir in a claim's
	// socket directory, as runc would create it.
	leaseFsMountPoint = "fs"
	// leaseContainerDir is where the claim's directory is mounted: the
	// directory of api.DefaultSocket.
	leaseContainerDir = "/run/cxl"
	// leaseCLIContainerPath is where the CLI is mounted.
	leaseCLIContainerPath = "/usr/local/bin/cxl-request"

	defaultLeaseCLI            = "/usr/local/bin/cxl-request"
	defaultLeaseWait           = 120 * time.Second
	defaultLeaseCompanionImage = "registry.k8s.io/pause:3.10"

	// selinuxContainerFileLabel lets container processes use the socket
	// directory on SELinux hosts (best effort, ignored elsewhere).
	selinuxContainerFileLabel = "system_u:object_r:container_file_t:s0"
)

// leaseClaims is what nodeState needs from the broker for claims on the
// lease device.
type leaseClaims interface {
	// OpenClaim records the claim and starts its socket. Idempotent.
	OpenClaim(claim *resourceapi.ResourceClaim) error
	// CloseClaim starts releasing all leases of the claim, waits until
	// their nodes are revoked and the deletion of their companions is
	// requested, then stops the socket and removes the directories; a
	// lease-fs directory that has a mount in it is removed later. The
	// leases are dropped when their companions are gone. Returns an
	// error if that wait times out (kubelet retries Unprepare). Unknown
	// claims are not an error.
	CloseClaim(ctx context.Context, uid string) error
}

var _ leaseClaims = (*broker)(nil)

// leaseCDIDeviceName is the CDI device name of a lease claim.
func leaseCDIDeviceName(claimUID string) string {
	return "lease-" + claimUID
}

func leaseCDIDeviceID(claimUID string) string {
	return cdiparser.QualifiedName(device.CDIVendor, device.CDIClass, leaseCDIDeviceName(claimUID))
}

// leaseDir is the host directory of a lease claim.
func (b *broker) leaseDir(claimUID string) string {
	return filepath.Join(b.cfg.DataDir, leaseDirName, claimUID)
}

// leaseFsRoot returns the directory of the lease-fs directories of the
// lease claims.
func (b *broker) leaseFsRoot() string {
	return filepath.Join(b.cfg.DataDir, leaseFsDirName)
}

// leaseFsDir returns the host directory of the mounts of the fs leases of
// a lease claim.
func (b *broker) leaseFsDir(claimUID string) string {
	return filepath.Join(b.leaseFsRoot(), claimUID)
}

// leaseCDIDevice returns the CDI device of a lease claim. Called with b.mu
// held.
func (b *broker) leaseCDIDevice(claimUID string) cdiSpecs.Device {
	edits := cdiSpecs.ContainerEdits{
		Env: []string{api.SocketEnv + "=" + api.DefaultSocket},
		Mounts: []*cdiSpecs.Mount{{
			HostPath:      b.leaseDir(claimUID),
			ContainerPath: leaseContainerDir,
			Type:          "bind",
			Options:       []string{"rbind", "rw"},
		}},
	}
	// The containers of a claim prepared without FsDir were created
	// without this mount: their CDI device stays as it was.
	if tc := b.store.Claims[claimUID]; tc != nil && tc.FsDir != "" {
		edits.Mounts = append(edits.Mounts, &cdiSpecs.Mount{
			HostPath:      tc.FsDir,
			ContainerPath: api.FsDir,
			Type:          "bind",
			Options:       []string{"rbind", "ro", "rslave"},
		})
	}
	// A missing bind mount source fails the container creation, so the
	// CLI is mounted only if it exists. The socket works without it.
	if b.cfg.CLI != "" {
		if _, err := os.Stat(b.cfg.CLI); err == nil {
			edits.Mounts = append(edits.Mounts, &cdiSpecs.Mount{
				HostPath:      b.cfg.CLI,
				ContainerPath: leaseCLIContainerPath,
				Type:          "bind",
				Options:       []string{"bind", "ro"},
			})
		} else {
			klog.Warningf("lease broker: cxl-request CLI %s not mounted into containers: %v", b.cfg.CLI, err)
		}
	}
	return cdiSpecs.Device{Name: leaseCDIDeviceName(claimUID), ContainerEdits: edits}
}

// writeCDISpec writes the CDI spec of all lease claims, or removes it
// when there are none. Called with b.mu held.
func (b *broker) writeCDISpec() error {
	if b.cfg.CDI == nil {
		return nil
	}
	spec := &cdiSpecs.Spec{Kind: device.CDIKind}
	uids := make([]string, 0, len(b.store.Claims))
	for uid := range b.store.Claims {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		spec.Devices = append(spec.Devices, b.leaseCDIDevice(uid))
	}
	if len(spec.Devices) == 0 {
		if err := b.cfg.CDI.RemoveSpec(device.LeasesCDISpecName); err != nil {
			klog.V(5).Infof("lease broker: could not remove CDI spec %s (may not exist): %v", device.LeasesCDISpecName, err)
		}
		return nil
	}
	v, err := cdiapi.MinimumRequiredVersion(spec)
	if err != nil {
		return fmt.Errorf("CDI spec version: %w", err)
	}
	spec.Version = v
	if err := b.cfg.CDI.WriteSpec(spec, device.LeasesCDISpecName); err != nil {
		return fmt.Errorf("failed to write CDI spec %s: %w", device.LeasesCDISpecName, err)
	}
	return nil
}

// OpenClaim implements leaseClaims.
func (b *broker) OpenClaim(claim *resourceapi.ResourceClaim) error {
	uid := string(claim.UID)
	tc := &leaseClaim{UID: uid, Namespace: claim.Namespace, Name: claim.Name, Pods: reservedPods(claim), FsDir: b.leaseFsDir(uid)}
	b.mu.Lock()
	defer b.mu.Unlock()
	if old := b.store.Claims[uid]; old != nil {
		// containers created from the old CDI device keep their mounts
		tc.FsDir = old.FsDir
	}
	b.store.Claims[uid] = tc
	if err := b.store.save(); err != nil {
		return err
	}
	if err := b.writeCDISpec(); err != nil {
		return err
	}
	if err := b.listen(uid); err != nil {
		return err
	}
	klog.Infof("lease broker: claim %s/%s (%s): lease socket %s for pods %v",
		claim.Namespace, claim.Name, uid, filepath.Join(b.leaseDir(uid), leaseSocketName), tc.Pods)
	return nil
}

// reservedPods returns the pods in the claim's reservedFor.
func reservedPods(claim *resourceapi.ResourceClaim) []podRef {
	var pods []podRef
	for _, c := range claim.Status.ReservedFor {
		if c.Resource == "pods" && c.APIGroup == "" {
			pods = append(pods, podRef{Namespace: claim.Namespace, Name: c.Name, UID: string(c.UID)})
		}
	}
	return pods
}

// CloseClaim implements leaseClaims.
func (b *broker) CloseClaim(ctx context.Context, uid string) error {
	b.mu.Lock()
	tc := b.store.Claims[uid]
	var ids []string
	if tc != nil {
		for _, l := range b.store.leasesOf(uid) {
			ids = append(ids, l.ID)
		}
	}
	b.mu.Unlock()
	if tc == nil {
		return nil
	}
	for _, id := range ids {
		b.startRelease(id, "lease claim unprepared (pod done)")
	}
	ctx, cancel := context.WithTimeout(ctx, b.closeTimeout)
	defer cancel()
	remaining := func() int {
		b.mu.Lock()
		defer b.mu.Unlock()
		n := 0
		for _, l := range b.store.leasesOf(uid) {
			if !b.deleting[l.ID] {
				n++
			}
		}
		return n
	}
	if err := b.waitFor(ctx, func() bool { return remaining() == 0 }); err != nil {
		return fmt.Errorf("claim %s/%s: still releasing %d leases, retry", tc.Namespace, tc.Name, remaining())
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if l := b.listeners[uid]; l != nil {
		_ = l.Close()
		delete(b.listeners, uid)
	}
	delete(b.store.Claims, uid)
	errs := []error{b.store.save(), b.writeCDISpec()}
	sock := filepath.Join(b.leaseDir(uid), leaseSocketName)
	if err := os.Remove(sock); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if left := b.removeClaimDirs(uid); len(left) > 0 {
		klog.Infof("lease broker: claim %s/%s (%s): left %v, removed later", tc.Namespace, tc.Name, uid, left)
	}
	klog.Infof("lease broker: claim %s/%s (%s): lease socket closed", tc.Namespace, tc.Name, uid)
	return errors.Join(errs...)
}

// removeClaimDirs removes the directories of a closed lease claim and
// returns the paths that are left: lease-fs/<uid> (removeFsDir, os.Remove
// only), then, once it is gone, leases/<uid> with everything a container
// wrote into its /run/cxl. While a bind is in lease-fs/<uid>, leases/<uid>
// stays with the mount point of api.FsDir in it: an rmdir of that mount
// point would detach the bind lazily in a container that is still there.
// Nothing is mounted below leases/<uid> in the plugin's mount namespace.
// Called with b.mu held.
func (b *broker) removeClaimDirs(uid string) []string {
	if !b.removeFsDir(uid) {
		return []string{b.leaseFsDir(uid)}
	}
	dir := b.leaseDir(uid)
	if err := os.RemoveAll(dir); err != nil {
		klog.Warningf("lease broker: removing %s: %v", dir, err)
		return []string{dir}
	}
	return nil
}

// removeFsDir removes the lease-fs directory of a lease claim and its
// entries, except entries that are mount points or have mounts below them:
// those and the directory stay. It reports whether the directory is gone.
// Called with b.mu held; errors are logged.
func (b *broker) removeFsDir(uid string) bool {
	dir := b.leaseFsDir(uid)
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return true
	case err != nil:
		klog.Errorf("lease broker: %v", err)
		return false
	}
	mounts, err := b.mounts()
	if err != nil {
		klog.Errorf("lease broker: not removing %s: %v", dir, err)
		return false
	}
	left := 0
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if mountedAtOrBelow(mounts, p) {
			klog.V(3).Infof("lease broker: %s is mounted, keeping it and %s", p, dir)
			left++
			continue
		}
		// os.Remove only: RemoveAll could descend into a mount
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			klog.Warningf("lease broker: removing %s: %v", p, err)
			left++
		}
	}
	if left > 0 {
		return false
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		klog.Warningf("lease broker: removing %s: %v", dir, err)
		return false
	}
	klog.V(3).Infof("lease broker: removed %s", dir)
	return true
}

// mountedAtOrBelow tells whether a mount has the target p or a target
// below p.
func mountedAtOrBelow(mounts []mountInfo, p string) bool {
	for i := range mounts {
		if t := mounts[i].Target; t == p || strings.HasPrefix(t, p+"/") {
			return true
		}
	}
	return false
}

// sweepFsDirs removes the lease-fs and socket directories of lease
// claims that are not in the store (removeClaimDirs), unless the store was
// recovered empty: then the lease claims of the node are unknown, and
// nothing is removed. Called with b.mu held.
func (b *broker) sweepFsDirs() {
	if b.store.Recovered {
		klog.V(3).Infof("lease broker: the lease table was not decoded, keeping the directories of lease claims")
		return
	}
	seen := map[string]bool{}
	for _, root := range []string{b.leaseFsRoot(), filepath.Join(b.cfg.DataDir, leaseDirName)} {
		entries, err := os.ReadDir(root)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			klog.Errorf("lease broker: %v", err)
		}
		for _, e := range entries {
			uid := e.Name()
			if !e.IsDir() || seen[uid] || b.store.Claims[uid] != nil {
				continue
			}
			seen[uid] = true
			b.removeClaimDirs(uid)
		}
	}
}

// mounts returns the mounts of the mount namespace of the plugin.
func (b *broker) mounts() ([]mountInfo, error) {
	if b.cfg.Mounts != nil {
		return b.cfg.Mounts()
	}
	return newSysMounter("").Mounts()
}

// listen starts the socket of a lease claim if it is not running.
// Called with b.mu held.
func (b *broker) listen(uid string) error {
	if b.listeners[uid] != nil {
		return nil
	}
	dir := b.leaseDir(uid)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0755); err != nil {
		return err
	}
	if err := b.makeFsDirs(uid); err != nil {
		return err
	}
	sock := filepath.Join(dir, leaseSocketName)
	_ = os.Remove(sock)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listening on %s: %w", sock, err)
	}
	// The socket is removed explicitly (CloseClaim): a plugin that
	// stops must leave the path to the next instance.
	l.SetUnlinkOnClose(false)
	if err := os.Chmod(sock, 0666); err != nil {
		_ = l.Close()
		return err
	}
	selinuxLabel(dir, sock)
	b.listeners[uid] = l
	b.wg.Add(1)
	go b.accept(uid, l)
	return nil
}

// makeFsDirs creates, for a lease claim with FsDir, the mount point of
// api.FsDir in its socket directory and its lease-fs directory. Called
// with b.mu held.
func (b *broker) makeFsDirs(uid string) error {
	tc := b.store.Claims[uid]
	if tc == nil || tc.FsDir == "" {
		return nil
	}
	mp := filepath.Join(b.leaseDir(uid), leaseFsMountPoint)
	for _, d := range []string{mp, tc.FsDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return err
		}
		if err := os.Chmod(d, 0755); err != nil {
			return err
		}
	}
	selinuxLabel(mp, tc.FsDir)
	return nil
}

// selinuxLabel labels the socket directory and socket for containers
// when SELinux is enabled. Errors are logged only.
func selinuxLabel(paths ...string) {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err != nil {
		return
	}
	for _, p := range paths {
		if err := unix.Lsetxattr(p, "security.selinux", []byte(selinuxContainerFileLabel), 0); err != nil {
			klog.Warningf("lease broker: cannot label %s %s: %v", p, selinuxContainerFileLabel, err)
		}
	}
}
