// Copyright 2020 The gVisor Authors.
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

package fuse

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
	"syscall"
)

// TODO: configure this properly.
const MaxInFlightRequests = 1000

var (
	// Ordinary requests have even IDs, while interrupts IDs are odd.
	FUSE_INIT_REQ_BIT uint64 = 1
	FUSE_REQ_ID_STEP  uint64 = 2
)

// Request represents a FUSE operation request that hasn't been sent to the
// server yet.
//
// +stateify savable
type Request struct {
	requestEntry

	id   linux.FUSEOpID
	hdr  *linux.FUSEHeaderIn
	data []byte
}

// FutureResponse represents an in-flight request, that may or may not have
// completed yet. Convert it to a resolved Response by calling Resolve, but note
// that this may block.
//
// +stateify savable
type FutureResponse struct {
	ch   chan struct{}
	hdr  *linux.FUSEHeaderOut
	data []byte
}

// Connection is the struct by which the sentry communicates with the FUSE server daemon.
type Connection struct {
	fd *DeviceFD
}

// NewFUSEConnection creates a FUSE connection to fd
func NewFUSEConnection(ctx context.Context, fd *vfs.FileDescription, fs *filesystem) error {
	// Mark the device as ready so it can be used. /dev/fuse can only be used if the FD was used to
	// mount a FUSE filesystem.
	fuseFD := fd.Impl().(*DeviceFD)
	fuseFD.mounted = true

	// Create the writeBuf for the header to be stored in.
	hdrLen := uint32((*linux.FUSEHeaderOut)(nil).SizeBytes())
	fuseFD.writeBuf = make([]byte, hdrLen)
	fuseFD.completions = make(map[linux.FUSEOpID]*FutureResponse)
	fuseFD.requestKind = make(map[linux.FUSEOpID]linux.FUSEOpcode)
	fuseFD.waitCh = make(chan struct{}, MaxInFlightRequests)
	fuseFD.writeCursor = 0
	fuseFD.readCursor = 0

	conn := &Connection{
		fd:fuseFD,
	}
	fs.fuseConn = conn
	return nil
}

// NewRequest creates a new request that can be sent to the FUSE server.
func (conn *Connection) NewRequest(creds *auth.Credentials, pid uint32, ino uint64, opcode linux.FUSEOpcode, payload marshal.Marshallable) (*Request, error) {
	conn.fd.mu.Lock()
	defer conn.fd.mu.Unlock()
	conn.fd.nextOpID += linux.FUSEOpID(FUSE_REQ_ID_STEP)

	hdrLen := (*linux.FUSEHeaderIn)(nil).SizeBytes()
	hdr := linux.FUSEHeaderIn{
		Len:    uint32(hdrLen + payload.SizeBytes()),
		Opcode: opcode,
		Unique: conn.fd.nextOpID,
		NodeID: ino,
		UID:    uint32(creds.EffectiveKUID),
		GID:    uint32(creds.EffectiveKGID),
		PID:    pid,
	}

	buf := make([]byte, hdr.Len)
	hdr.MarshalUnsafe(buf[:hdrLen])
	payload.MarshalUnsafe(buf[hdrLen:])

	return &Request{
		id:   hdr.Unique,
		hdr:  &hdr,
		data: buf,
	}, nil
}

// Call makes a request to the server and blocks the invoking task until a
// server responds with a response.
func (conn *Connection) Call(t *kernel.Task, r *Request) (*Response, error) {
	fut, err := conn.callFuture(r)
	if err != nil {
		return nil, err
	}

	return fut.resolve(t)
}

// callFuture makes a request to the server and returns a future response.
// Call resolve() when the response needs to be fulfilled.
func (conn *Connection) callFuture(r *Request) (*FutureResponse, error) {
	conn.fd.mu.Lock()
	conn.fd.queue.PushBack(r)
	fut := newFutureResponse()
	conn.fd.completions[r.id] = fut
	conn.fd.requestKind[r.id] = r.hdr.Opcode
	conn.fd.mu.Unlock()

	// Signal a reader notifying them about a queued request. This
	// might block if the number of in flight requests exceed
	// MaxInFlightRequests.
	//
	// TODO: Consider possible starvation here if the waitCh is
	// continuously full. Will go channels respect FIFO order when
	// unblocking threads?
	conn.fd.waitCh <- struct{}{}

	return fut, nil
}

// newFutureResponse creates a future response to a FUSE request.
func newFutureResponse() *FutureResponse {
	return &FutureResponse{
		ch: make(chan struct{}),
	}
}

// resolve blocks the task until the server responds to its corresponding request,
// then returns a resolved response.
func (r *FutureResponse) resolve(t *kernel.Task) (*Response, error) {
	if err := t.Block(r.ch); err != nil {
		return nil, err
	}

	return &Response{
		hdr:  *r.hdr,
		data: r.data,
	}, nil
}

// Response represents an actual response from the server, including the
// response payload.
//
// +stateify savable
type Response struct {
	hdr  linux.FUSEHeaderOut
	data []byte
}

func (r *Response) Error() error {
	errno := r.hdr.Error
	if errno >= 0 {
		return nil
	}

	sysErrNo := syscall.Errno(-errno)
	return error(sysErrNo)
}

func (r *Response) UnmarshalPayload(m marshal.Marshallable) error {
	hdrLen := r.hdr.SizeBytes()
	haveDataLen := r.hdr.Len - uint32(hdrLen)
	wantDataLen := uint32(m.SizeBytes())

	if haveDataLen < wantDataLen {
		return fmt.Errorf("payload too small. Minimum data lenth required: %d,  but got data length %d", wantDataLen, haveDataLen)
	}

	m.UnmarshalUnsafe(r.data[hdrLen:])
	return nil
}
