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
	"io"
	"math"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

type regularFileFD struct {
	fileDescription

	// off is the file offset.
	off int64
	// offMu protects off.
	offMu sync.Mutex
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	size := uint64(dst.NumBytes())
	if size == 0 {
		// Early return if count is 0.
		return 0, nil
	} else if size > math.MaxUint32 {
		// FUSE only supports uint32 for size.
		// Overflow.
		return 0, syserror.EINVAL
	}

	rw := getRegularFDReadWriter(ctx, fd, size, offset)

	// TODO(gvisor.dev/issue/3678): Add direct IO support.

	rw.read()
	n, err := dst.CopyOutFrom(ctx, rw)

	putRegularFDReadWriter(rw)

	return n, err
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *regularFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.offMu.Lock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	fd.offMu.Unlock()
	return n, err
}

// Deprecated
type regularFDReader struct {
	ctx context.Context
	fd  *regularFileFD

	// TODO(gvisor.dev/issue/3678): Add direct IO support.

	// uint64 for sentry, FUSE protocol needs uint32.
	size uint64
	off  uint64

	// actual bytes of operation result.
	n   uint32
	err error

	// buf for IO.
	// For read, ideally it shares the same array
	// with the slice in FUSE response
	// for the reads that can fit in one FUSE_READ request.
	buf []byte
}

func (rw *regularFDReader) fs() *filesystem {
	return rw.fd.inode().fs
}

var regularFdReadWriterPool = sync.Pool{
	New: func() interface{} {
		return &regularFDReader{}
	},
}

func getRegularFDReadWriter(ctx context.Context, fd *regularFileFD, size uint64, offset int64) *regularFDReader {
	rw := regularFdReadWriterPool.Get().(*regularFDReader)
	rw.ctx = ctx
	rw.fd = fd
	rw.size = size
	rw.off = uint64(offset)
	return rw
}

func putRegularFDReadWriter(rw *regularFDReader) {
	rw.ctx = nil
	rw.fd = nil
	rw.buf = nil
	rw.n = 0
	rw.err = nil
	regularFdReadWriterPool.Put(rw)
}

// read handles and issues the actual FUSE read request.
// See ReadToBlocks() regarding its purpose.
func (rw *regularFDReader) read() {
	// TODO(gvisor.dev/issue/3237): support indirect IO (e.g. caching):
	// use caching when possible.

	inode := rw.fd.inode()

	// Reading beyond EOF, update file size if outdated.
	if rw.off+rw.size >= atomic.LoadUint64(&inode.size) {
		if err := inode.reviseAttr(rw.ctx); err != nil {
			rw.err = err
			return
		}
		// If the offset after update is still too large, return error.
		if rw.off >= atomic.LoadUint64(&inode.size) {
			rw.err = io.EOF
			return
		}
	}

	// Truncate the read with updated file size.
	fileSize := atomic.LoadUint64(&inode.size)
	if rw.off+rw.size > fileSize {
		rw.size = fileSize - rw.off
	}

	// Send the FUSE_READ request and store the data in rw.
	rw.buf, rw.n, rw.err = rw.fs().ReadInPages(rw.ctx, rw.fd, rw.off, uint32(rw.size))
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
// Due to a deadlock (both the caller of ReadToBlocks and the kernelTask.Block()
// will try to acquire the same lock,
// i.e. pkg/sentry/mm/address_space.go:mm.Deactivate():mm.activeMu),
// have to separate the rw.read() from the
// ReadToBlocks() function. Therefore, ReadToBlocks() only handles copying
// the result into user memory while read() handles the actual reading.
func (rw *regularFDReader) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	if rw.err != nil {
		return 0, rw.err
	}

	if dsts.IsEmpty() {
		return 0, nil
	}

	// TODO(gvisor.dev/issue/3237): support indirect IO (e.g. caching),
	// store the bytes that were read ahead.

	// The actual number of bytes to copy.
	var size uint32
	if uint32(rw.size) < rw.n {
		// Read more bytes: read ahead.
		// This is the common case since FUSE will round up the
		// size to read to a multiple of usermem.PageSize.
		size = uint32(rw.size)
	} else {
		size = rw.n
	}

	// Assume rw.size is less or equal to dsts.NumBytes().
	if cp, cperr := safemem.CopySeq(dsts, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(rw.buf[:size]))); cperr != nil {
		return cp, cperr
	}

	return uint64(size), nil
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *regularFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	n, _, err := fd.pwrite(ctx, src, offset, opts)
	return n, err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.offMu.Lock()
	n, off, err := fd.pwrite(ctx, src, fd.off, opts)
	fd.off = off
	fd.offMu.Unlock()
	return n, err
}

// pwrite returns the number of bytes written, final offset and error. The
// final offset should be ignored by PWrite.
func (fd *regularFileFD) pwrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (written, finalOff int64, err error) {
	if offset < 0 {
		return 0, offset, syserror.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, offset, syserror.EOPNOTSUPP
	}

	srclen := src.NumBytes()
	if srclen == 0 {
		// Early return if count is 0.
		return 0, offset, nil
	} else if srclen > math.MaxUint32 {
		// FUSE only supports uint32 for size.
		// Overflow.
		return 0, offset, syserror.EINVAL
	}

	inode := fd.inode()
	inode.metadataMu.Lock()
	defer inode.metadataMu.Unlock()

	// If the file is opened with O_APPEND, update offset to file size.
	if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 {
		// Locking inode.metadataMu is sufficient for reading size
		offset = int64(inode.size)
	}
	if end := offset + srclen; end < offset {
		// Overflow.
		return 0, offset, syserror.EINVAL
	}

	srclen, err = vfs.CheckLimit(ctx, offset, srclen)
	if err != nil {
		return 0, offset, err
	}
	src = src.TakeFirst64(srclen)

	rw := getRegularFDReadWriter(ctx, fd, uint64(srclen), offset)

	// TODO(gvisor.dev/issue/3678): Add direct IO support.

	rw.write()
	n, err := src.CopyInTo(ctx, rw)

	putRegularFDReadWriter(rw)

	return n, n + offset, err
}

func (rw *regularFDReader) write() {
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
//
// Preconditions: inode.metadataMu must be held.
func (rw *regularFDReader) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	if srcs.IsEmpty() {
		return 0, nil
	}

	if rw.off > rw.d.size {
		atomic.StoreUint64(&rw.d.size, rw.off)
		// The remote file's size will implicitly be extended to the correct
		// value when we write back to it.
	}

	return 0, nil
}
