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

package leases

import (
	"context"
	"errors"
	"net"
	"syscall"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
)

// Containers is what the broker needs of the container plugin of the node:
// the running containers, the NUMA nodes lent to them and the events of
// their life.
type Containers interface {
	// ContainerByPid returns the pod and the name of the container whose
	// cgroup has the process pid, false for none.
	ContainerByPid(pid int) (pod state.PodRef, container string, ok bool)
	// Running tells whether an instance of the container name of the pod
	// is created or started.
	Running(podUID, container string) bool
	// LendNode lends the NUMA node to the container on behalf of holder,
	// a lease id. Idempotent per node and holder.
	LendNode(ctx context.Context, podUID, container string, node int, holder string) error
	// RevokeNode drops holder of the NUMA node of the container; a
	// container that is gone is not an error. Idempotent.
	RevokeNode(ctx context.Context, podUID, container string, node int, holder string) error
	// OnContainerGone registers fn, called in a goroutine of its own for
	// a container that stopped, was removed or is gone at a Synchronize.
	OnContainerGone(fn func(pod state.PodRef, container string))
	// OnContainerStarted registers fn, called in a goroutine of its own
	// once a container has started.
	OnContainerStarted(fn func(pod state.PodRef, container string))
	// WaitSynchronized returns once the plugin has synchronized with the
	// runtime, or the error of ctx.
	WaitSynchronized(ctx context.Context) error
	// LendsRestored tells that the lends of the leases are restored.
	LendsRestored()
}

// Requester is the container that asks on a lease socket.
type Requester struct {
	Pod       state.PodRef
	Container string
}

// Identity tells which container a process that connected to a lease
// socket is in.
type Identity interface {
	// Resolve returns the container of the process pid, an error that is
	// ErrUnknownPeer when the process is in no known container.
	Resolve(pid int) (Requester, error)
}

// ErrUnknownPeer is the error of an Identity for a process that is in no
// known container.
var ErrUnknownPeer = errors.New("in no known container")

// tableIdentity is the Identity of the container table of the container
// plugin.
type tableIdentity struct {
	containers Containers
}

// Resolve returns the container of the table whose cgroup has the process.
func (t tableIdentity) Resolve(pid int) (Requester, error) {
	pod, name, ok := t.containers.ContainerByPid(pid)
	if !ok {
		return Requester{}, ErrUnknownPeer
	}
	return Requester{Pod: pod, Container: name}, nil
}

// peerPid returns the pid of the process that connected.
func peerPid(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return int(cred.Pid), nil
}
