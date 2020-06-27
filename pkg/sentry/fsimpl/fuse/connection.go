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
	"sync"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
)

// TODO: configure this properly.
const MaxInFlightRequests = 1000

var (
	// Ordinary requests have even IDs, while interrupts IDs are odd.
	FUSE_INIT_REQ_BIT uint64 = 1
	FUSE_REQ_ID_STEP  uint64 = 2
)

const (
	// FUSE_DEFAULT_MAX_BACKGROUND is the default maximum number of outstanding background requests.
	FUSE_DEFAULT_MAX_BACKGROUND = 12

	// FUSE_DEFAULT_CONGESTION_THRESHOLD is the default congestion threshold,
	// and is 75% of the default maximum.
	FUSE_DEFAULT_CONGESTION_THRESHOLD = (FUSE_DEFAULT_MAX_BACKGROUND * 3 / 4)

	// FUSE_DEFAULT_MAX_PAGES_PER_REQ is the maximum number of pages that can be used in a single read request.
	FUSE_DEFAULT_MAX_PAGES_PER_REQ = 32
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

	// MaxRead size in bytes.
	MaxRead uint32

	// MaxWrite size in bytes.
	MaxWrite uint32

	// MaxPages is the maximum number of pages for a single request to use.
	MaxPages uint16

	// NumberBackground is the number of requests in background.
	NumBackground uint16

	// CongestionThreshold for the number of background requests.
	CongestionThreshold uint16

	// MaxBackground is the maximum number of outstanding background requests.
	MaxBackground uint16

	// NumActiveBackground is the number of requests in background and currently queued for userspace.
	NumActiveBackground uint16

	// NumWating is the number of requests waiting for completion.
	NumWaiting uint32

	// Minor version negotiated.
	Minor uint32

	// TODO: BgQuque
	// some queue for background queued requests.

	// BgLock protects:
	// MaxBackground, CongestionThreshold, NumBackground,
	// NumActiveBackground, BgQueue, Blocked.
	BgLock sync.Mutex

	// Initialized if INIT reply has been received.
	// Until it's set, suspend sending FUSE requests.
	Initialized bool

	// protects Initialized.
	initializedLock sync.Mutex

	// Blocked when:
	//   before the INIT reply is received (Initialized == false),
	//   if there are too many outstading backgrounds requests (NumBackground == MaxBackground).
	// TODO: use a channel to block.
	Blocked bool

	// Connected if connection established.
	// Unset when:
	//   umount,
	//   connection abort,
	//   device release.
	Connected bool

	// Aborted via sysfs.
	Aborted bool

	// ConnError if connection failed (version mismatch).
	// Only set in INIT,
	// before any other request,
	// never unset.
	// Cannot race with other flags.
	ConnError bool

	// ConnInit if connection successful.
	// Only set in INIT.
	ConnInit bool

	// AsyncRead if read pages asynchronously.
	// Only set in INIT.
	AsyncRead bool

	// AbortErr is true if need to return an unique read error after abort.
	// Only set in INIT.
	AbortErr bool

	// AtomicOTrunc is true when FUSE does not send a separate SETATTR request
	// before open with O_TRUNC flag.
	AtomicOTrunc bool

	// ExportSupport is true if the daemon filesystem supports NFS exporting.
	// Only set in INIT.
	ExportSupport bool

	// WritebackCache is true for write-back cache policy,
	// false for write-through policy.
	WritebackCache bool

	// ParallelDirops is true if allowing lookup and readdir in parallel,
	// false if serialized.
	ParallelDirops bool

	// HandleKillpriv if the daemon filesystem handles killing suid/sgid/cap on write/chown/trunc.
	HandleKillpriv bool

	// CacheSymlinks if need to cache READLINK responses in page cache.
	CacheSymlinks bool

	/* Setting races on the following optimization-purpose flags are safe */

	// NoOpen if open/release not implemented by the filesystem.
	NoOpen bool

	// NoOpendir if opendir/releasedir not implemented by the filesystem.
	NoOpendir bool

	// NoFsync if fsync not implemented by the filesystem.
	NoFsync bool

	// NoFsyncdir if fsyncdir not implemented by the filesystem.
	NoFsyncdir bool

	// NoFlush if flush not implemented by the filesystem.
	NoFlush bool

	// NoSetxattr if setxattr not implemented by the filesystem.
	NoSetxattr bool

	// NoGetxattr if getxattr not implemented by the filesystem.
	NoGetxattr bool

	// NoListxattr if listxattr not implemented by the filesystem.
	NoListxattr bool

	// NoRemovexattr if removexattr not implemented by the filesystem.
	NoRemovexattr bool

	// NoLock if posix file locking primitives not implemented by the filesystem.
	NoLock bool

	// NoAccess if access not implemented by the filesystem.
	NoAccess bool

	// NoCreate if create not implemented by the filesystem.
	NoCreate bool

	// NoInterrupt if interrupt not implemented by the filesystem.
	NoInterrupt bool

	// NoBmap if bmap not implemented by the filesystem.
	NoBmap bool

	// NoPoll if poll not implemented by the filesystem.
	NoPoll bool

	// BigWrites if doing multi-page cached writes.
	BigWrites bool

	// DontMask don't apply umask to creation modes.
	DontMask bool

	// NoFLock if BSD file locking primitives not implemented by the filesystem.
	NoFLock bool

	// NoFallocate if fallocate not implemented by the filesystem.
	NoFallocate bool

	// NoRename2 if rename with flags not implemented by the filesystem.
	NoRename2 bool

	// AutoInvalData use enhanced/automatic page cache invalidation.
	AutoInvalData bool

	// ExplicitInvalData Filesystem is fully reponsible for page cache invalidation.
	ExplicitInvalData bool

	// DoReaddirplus if the filesystem supports readdirplus.
	DoReaddirplus bool

	// ReaddirplusAuto if the filesystem wants adaptive readdirplus.
	ReaddirplusAuto bool

	// AsyncDio if the filesystem supports asynchronous direct-IO submission.
	AsyncDio bool

	// NoLseek if lseek() not implemented by the filesystem.
	NoLseek bool

	// PosixACL if the filesystem supports posix acls.
	PosixACL bool

	// DefaultPermissions if to check permissions based on the file mode.
	DefaultPermissions bool

	// AllowOther user who is not the mounter to access the filesystem.
	AllowOther bool

	// NoCopyFileRange if the filesystem not supports copy_file_range.
	NoCopyFileRange bool

	// Destroy request will be sent.
	Destroy bool

	// DeleteStable dentries.
	DeleteStable bool

	// NoControl if not creating entry in fusectl fs.
	NonControl bool

	// NoForceUmount if not allowing MNT_FORCE umount.
	NoForceUmount bool

	// NoMountOptions if not showing mount options.
	NoMountOptions bool
}

// NewFUSEConnection creates a FUSE connection to fd
func NewFUSEConnection(ctx context.Context, fd *vfs.FileDescription) (*Connection, error) {
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

	return &Connection{
		fd:                  fuseFD,
		NumWaiting:          0,
		MaxBackground:       FUSE_DEFAULT_MAX_BACKGROUND,
		CongestionThreshold: FUSE_DEFAULT_CONGESTION_THRESHOLD,
		MaxPages:            FUSE_DEFAULT_MAX_PAGES_PER_REQ,
		Blocked:             false,
		Initialized:         false,
		Connected:           true,
	}, nil
}

// Atomically set the connection as initialized.
func (conn *Connection) setInitialized() {
	conn.initializedLock.Lock()
	defer conn.initializedLock.Unlock()

	conn.Initialized = true
}

// Atomically check if the connection is initialized.
// pairs with setInitialized().
func (conn *Connection) isInitialized() bool {
	conn.initializedLock.Lock()
	defer conn.initializedLock.Unlock()

	return conn.Initialized
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
// NOTE: If no task is provided then the Call will simply enqueue the request
// and return a nil response. No blocking will happen in this case. Instead,
// this is used to signify that the processing of this request will happen by
// the kernel.Task that writes the response. See FUSE_INIT for such an
// invocation.
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
	// If there is no Task associated with this request  - then we don't try to resolve
	// the response.  Instead, the task writing the response (proxy to the server) will
	// process the response on our behalf.
	if t == nil {
		log.Infof("fuse.Response: Not waiting on a response from server.")
		return nil, nil
	}

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
