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
	"io"
	"math"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// ReadInPages sends FUSE_READ requests for the size after
// round it up to a multiple of page size,
// blocks on it for reply,
// processes the reply and returns the payload (or joined payloads)
// as a byte slice.
// This is used for the general purpose reading.
// We do not support direct IO
// (which read the exact number of bytes) at this moment.
func (fs *filesystem) ReadInPages(ctx context.Context, fd *regularFileFD, off uint64, size uint32) ([]byte, uint32, error) {
	attributeVersion := atomic.LoadUint64(&fs.conn.attributeVersion)

	// Round up to a multiple of page size.
	readSize, _ := usermem.PageRoundUp(uint64(size))

	// One request cannnot exceed either maxRead or maxPages.
	maxPages := uint32(math.Floor(float64(fs.conn.maxRead) / usermem.PageSize))
	if maxPages > uint32(fs.conn.maxPages) {
		maxPages = uint32(fs.conn.maxPages)
	}

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		log.Warningf("fusefs.Read: couldn't get kernel task from context")
		return nil, 0, syserror.EINVAL
	}

	var outs [][]byte
	var sizeRead uint32

	// readSize is a multiple of usermem.PageSize.
	// Always request bytes as a multiple of pages.
	pagesRead, pagesToRead := uint32(0), uint32(readSize/usermem.PageSize)

	// Reuse the same struct for unmarshalling to avoid unnecessary memory allocation.
	in := linux.FUSEReadIn{
		Fh:        fd.Fh,
		LockOwner: 0, // TODO(gvisor.dev/issue/3245): file lock
		ReadFlags: 0, // TODO(gvisor.dev/issue/3245): |= linux.FUSE_READ_LOCKOWNER
		Flags:     fd.statusFlags(),
	}

	// This loop is intended for fragmented read where the bytes to read is
	// larger than either the maxPages or maxRead.
	// For the majority of reads with normal size, this loop should only
	// execute once.
	for pagesRead < pagesToRead {
		pagesCanRead := pagesToRead - pagesRead
		if pagesCanRead > maxPages {
			pagesCanRead = maxPages
		}

		in.Offset = off + (uint64(pagesRead) << usermem.PageShift)
		in.Size = pagesCanRead << usermem.PageShift

		req, err := fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(t.ThreadID()), fd.inode().NodeID, linux.FUSE_READ, &in)
		if err != nil {
			return nil, 0, err
		}

		// TODO(gvisor.dev/issue/3247): support async read.

		res, err := fs.conn.Call(t, req)
		if err != nil {
			return nil, 0, err
		}
		if err := res.Error(); err != nil {
			return nil, 0, err
		}

		// Not enough bytes in response,
		// either we reached EOF,
		// or the FUSE server sends back a response
		// that cannot even fit the hdr.
		if len(res.data) <= res.hdr.SizeBytes() {
			if len(res.data) < res.hdr.SizeBytes() {
				return nil, 0, fmt.Errorf("FUSE_READ response too small. Minimum length required: %d,  but got length %d", res.hdr.SizeBytes(), len(res.data))
			}
			break
		}

		// Directly using the slice to avoid extra copy.
		out := res.data[res.hdr.SizeBytes():]
		outs = append(outs, out)
		sizeRead += uint32(len(out))

		pagesRead += pagesCanRead
	}

	defer fs.ReadCallback(ctx, fd, off, size, sizeRead, attributeVersion)

	// No bytes returned: offset >= EOF
	if len(outs) == 0 {
		return []byte{}, 0, io.EOF
	}

	// Finished with one reply.
	// Return the slice directly from the buffer in response.
	if len(outs) == 1 {
		return outs[0], sizeRead, nil
	}

	// Join data from multiple fragmented replies.
	// TODO(gvisor.dev/issue/3628): avoid this extra copy,
	// perhaps we can use iovec, which requires upperstream support.
	buf := make([]byte, sizeRead)
	bufPos := 0
	for _, v := range outs {
		bufPos += copy(buf[bufPos:], v)
	}

	return buf, sizeRead, nil
}

// ReadCallback updates several information after receiving a read response.
func (fs *filesystem) ReadCallback(ctx context.Context, fd *regularFileFD, off uint64, size uint32, sizeRead uint32, attributeVersion uint64) {
	// TODO(gvisor.dev/issue/3247): support async read.
	// If this is called by an async read, correctly process it.
	// May need to update the signature.

	i := fd.inode()
	// TODO(gvisor.dev/issue/1193): Invalidate or update atime.

	// Reached EOF.
	if sizeRead < size {
		// TODO(gvisor.dev/issue/3630): If we have writeback cache, then we need to fill this hole.
		// Might need to update the buf to be returned from the Read().

		// Update existing size.
		newSize := off + uint64(sizeRead)
		fs.conn.mu.Lock()
		if attributeVersion == i.attributeVersion && newSize < atomic.LoadUint64(&i.size) {
			fs.conn.attributeVersion++
			i.attributeVersion = i.fs.conn.attributeVersion
			atomic.StoreUint64(&i.size, newSize)
		}
		fs.conn.mu.Unlock()
	}
}

// Write sends a FUSE_WRITE request.
func (fs *filesystem) Write(ctx context.Context, fd *regularFileFD, off uint64, size uint32) (uint32, error) {
	// One request cannnot exceed either maxWrite or maxPages.
	maxWrite := uint32(fs.conn.maxPages) << usermem.PageShift
	if maxWrite < fs.conn.maxWrite {
		maxWrite = fs.conn.maxWrite
	}

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		log.Warningf("fusefs.Read: couldn't get kernel task from context")
		return 0, syserror.EINVAL
	}

	// Reuse the same struct for unmarshalling to avoid unnecessary memory allocation.
	in := linux.FUSEWriteIn{
		Fh:         fd.Fh,
		LockOwner:  0, // TODO(gvisor.dev/issue/3245): file lock
		WriteFlags: 0,
		Flags:      0,
	}

	var written uint32
	// This loop is intended for fragmented write where the bytes to write is
	// larger than either the maxWrite or maxPages or when bigWrites is false.
	// Unless the user explicitly uses a small value for max_write, this loop
	// is expected to execute only once for the majority of the writes.
	for size > 0 {
		toWrite := size

		// Limit the write size to one page.
		// Note that the bigWrites flag is obsolete,
		// latest libfuse always sets it on.
		if !fs.conn.bigWrites && toWrite > usermem.PageSize {
			toWrite = usermem.PageSize
		}

		// Limit the write size to maxWrite.
		if toWrite > maxWrite {
			toWrite = maxWrite
		}

		in.Offset = off + uint64(written)
		in.Size = toWrite

		req, err := fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(t.ThreadID()), fd.inode().NodeID, linux.FUSE_WRITE, &in)
		if err != nil {
			return 0, err
		}

		// TODO(gvisor.dev/issue/3247): support async write.

		res, err := fs.conn.Call(t, req)
		if err != nil {
			return 0, err
		}
		if err := res.Error(); err != nil {
			return 0, err
		}

		// Not enough bytes in response,
		// the FUSE server sends back a response
		// that cannot fit the hdr.
		if len(res.data) <= res.hdr.SizeBytes() {
			if len(res.data) < res.hdr.SizeBytes() {
				return nil, 0, fmt.Errorf("FUSE_READ response too small. Minimum length required: %d,  but got length %d", res.hdr.SizeBytes(), len(res.data))
			}
			break
		}

		written += 1
	}

	if written > 0 {
		// update size
	}

	return written, nil
}
