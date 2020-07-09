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
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// consts used by FUSE_INIT negotation to have the expected behavior of the existing FUSE protocol.
const (
	// FUSE_MAX_MAX_PAGES is the maximum value for MaxPages received in InitOut.
	FUSE_MAX_MAX_PAGES = 256

	// Maximum value for the time granularity for file time stamps, 1s.
	fuseMaxTimeGranNs = 1000000000

	// Minimum value for MaxWrite.
	fuseMinMaxWrite = 4096

	// Temporary default value for max readahead, 128kb.
	fuseDefaultMaxReadahead = 131072
)

// Adjustable maximums for Connection's cogestion control parameters.
// Used as the upperbound of the config values.
// TODO: add adjust support.
var (
	MaxUserBackgroundRequest uint16 = FUSE_DEFAULT_MAX_BACKGROUND
	MaxUserCongestionThreshold uint16 = FUSE_DEFAULT_CONGESTION_THRESHOLD
)

// InitSend sends a FUSE_INIT request.
func (fs *filesystem) InitSend(creds *auth.Credentials, pid uint32) error {
	req, err := fs.initBuildRequest(creds, pid)
	if err != nil {
		return err
	}

	_, err = fs.fuseConn.Call(nil, req)
	return err
}

// InitRecv receives a FUSE_INIT reply and process it.
func (fs *filesystem) InitRecv(creds *auth.Credentials, k *kernel.Kernel, res *Response) error {
	if err := res.Error(); err != nil {
		return err
	}

	var out linux.FUSEInitOut
	if err := res.UnmarshalPayload(&out); err != nil {
		return err
	}

	return fs.initProcessReply(k, creds, &out)
}

// Builds a FUSE_INIT request.
func (fs *filesystem) initBuildRequest(creds *auth.Credentials, pid uint32) (*Request, error) {
	in := linux.FUSEInitIn{
		Major: linux.FUSE_KERNEL_VERSION,
		Minor: linux.FUSE_KERNEL_MINOR_VERSION,
		// TODO: find appropriate way to calculate this
		MaxReadahead: fuseDefaultMaxReadahead, 
		Flags: linux.FUSE_ASYNC_READ |
			linux.FUSE_POSIX_LOCKS |
			linux.FUSE_ATOMIC_O_TRUNC |
			linux.FUSE_EXPORT_SUPPORT |
			linux.FUSE_BIG_WRITES |
			linux.FUSE_DONT_MASK |
			linux.FUSE_SPLICE_WRITE |
			linux.FUSE_SPLICE_MOVE |
			linux.FUSE_SPLICE_READ |
			linux.FUSE_FLOCK_LOCKS |
			linux.FUSE_HAS_IOCTL_DIR |
			linux.FUSE_AUTO_INVAL_DATA |
			linux.FUSE_DO_READDIRPLUS |
			linux.FUSE_READDIRPLUS_AUTO |
			linux.FUSE_ASYNC_DIO |
			linux.FUSE_WRITEBACK_CACHE |
			linux.FUSE_NO_OPEN_SUPPORT |
			linux.FUSE_PARALLEL_DIROPS |
			linux.FUSE_HANDLE_KILLPRIV |
			linux.FUSE_POSIX_ACL |
			linux.FUSE_ABORT_ERROR |
			linux.FUSE_MAX_PAGES |
			linux.FUSE_CACHE_SYMLINKS |
			linux.FUSE_NO_OPENDIR_SUPPORT |
			linux.FUSE_EXPLICIT_INVAL_DATA,
	}

	return fs.fuseConn.NewRequest(creds, pid, 0, linux.FUSE_INIT, &in)
}

// Process the FUSE_INIT reply from the FUSE server.
// The handling process follows the rules of the FUSE protocol implementation of unix kernel.
func (fs *filesystem) initProcessReply(k *kernel.Kernel, creds *auth.Credentials, out *linux.FUSEInitOut) error {
	// No support for old major fuse versions.
	// This behavior is consistent with the Linux kernel (v5.8).
	if out.Major != linux.FUSE_KERNEL_VERSION {
		fs.fuseConn.ConnError = true
	} else {
		// No support for limits before minor version 13.
		if out.Minor >= 13 {
			fs.initProcessLimits(k, creds, out)
		}

		// No support for the following flags before minor version 6.
		if out.Minor >= 6 {
			if out.Flags&linux.FUSE_ASYNC_READ != 0 {
				fs.fuseConn.AsyncRead = true
			}

			if out.Flags&linux.FUSE_POSIX_LOCKS == 0 {
				fs.fuseConn.NoLock = true
			}

			// No support for FLOCK flag before minor version 17.
			if out.Minor >= 17 {
				if out.Flags & linux.FUSE_FLOCK_LOCKS == 0 {
					fs.fuseConn.NoFLock = true
				}
			} else {
				if out.Flags & linux.FUSE_POSIX_LOCKS == 0 {
					fs.fuseConn.NoFLock = true
				}
			}

			if out.Flags & linux.FUSE_ATOMIC_O_TRUNC != 0 {
				fs.fuseConn.AtomicOTrunc = true
			}

			// No support for EXPORT flag before minor version 9.
			if out.Minor >= 9 {
				if out.Flags & linux.FUSE_EXPORT_SUPPORT != 0 {
					fs.fuseConn.ExportSupport = true
				}
			}

			if out.Flags & linux.FUSE_BIG_WRITES != 0 {
				fs.fuseConn.BigWrites = true
			}

			if out.Flags & linux.FUSE_DONT_MASK != 0 {
				fs.fuseConn.DontMask = true
			}

			if out.Flags & linux.FUSE_AUTO_INVAL_DATA != 0 {
				fs.fuseConn.AutoInvalData = true
			} else if out.Flags & linux.FUSE_EXPLICIT_INVAL_DATA != 0 {
				fs.fuseConn.ExplicitInvalData = true
			}

			if out.Flags & linux.FUSE_DO_READDIRPLUS != 0 {
				fs.fuseConn.DoReaddirplus = true
				if out.Flags & linux.FUSE_READDIRPLUS_AUTO != 0 {
					fs.fuseConn.ReaddirplusAuto = true
				}
			}

			if out.Flags & linux.FUSE_ASYNC_DIO != 0 {
				fs.fuseConn.AsyncDio = true
			}

			if out.Flags & linux.FUSE_WRITEBACK_CACHE != 0 {
				fs.fuseConn.WritebackCache = true
			}

			if out.Flags & linux.FUSE_PARALLEL_DIROPS != 0 {
				fs.fuseConn.ParallelDirops = true
			}

			if out.Flags & linux.FUSE_HANDLE_KILLPRIV != 0 {
				fs.fuseConn.HandleKillpriv = true
			}

			// if out.TimeGran > 0 && out.TimeGran <= fuseMaxTimeGranNs {
				// TODO: figure out how to use this
				// superBlock.s_time_gran = reply.TimeGran
			// }

			if out.Flags & linux.FUSE_POSIX_ACL != 0 {
				fs.fuseConn.DefaultPermissions = true
				fs.fuseConn.PosixACL = true
				// TODO: add xattr handler support
				// superBlock.s_xattr = fuse_acl_xattr_handlers
			}

			if out.Flags & linux.FUSE_CACHE_SYMLINKS != 0 {
				fs.fuseConn.CacheSymlinks = true
			}

			if out.Flags & linux.FUSE_ABORT_ERROR != 0 {
				fs.fuseConn.AbortErr = true
			}

			if out.Flags & linux.FUSE_MAX_PAGES != 0 {
				maxPages := out.MaxPages
				if maxPages < 1 {
					maxPages = 1
				}
				if maxPages > FUSE_MAX_MAX_PAGES {
					maxPages = FUSE_MAX_MAX_PAGES
				}
				fs.fuseConn.MaxPages = maxPages
			}
		} else {
			fs.fuseConn.NoLock = true
			fs.fuseConn.NoFLock = true
		}

		// No support for negotiating MaxWrite before minor version 5.
		if out.Minor < 5 {
			fs.fuseConn.MaxWrite = fuseMinMaxWrite
		} else {
			fs.fuseConn.MaxWrite = out.MaxWrite
		}
		if fs.fuseConn.MaxWrite < fuseMinMaxWrite {
			fs.fuseConn.MaxWrite = fuseMinMaxWrite
		}

		fs.fuseConn.ConnInit = true

		fs.fuseConn.Minor = out.Minor
	}

	fs.fuseConn.setInitialized()

	// TODO: unblock all blocked requests so far
	// close(fs.fussConn.blockedWaitQueueCh)

	return nil
}

// Updates the MaxBackground and CongestionThreshold after negoiation.
// Supported after FUSE protocol version 7.13.
func (fs *filesystem) initProcessLimits(k *kernel.Kernel, creds *auth.Credentials, out *linux.FUSEInitOut) {
	isCapable := creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, k.RootUserNamespace())

	totalSize := k.MemoryFile().TotalSize()
	sanitizeFuseLimits(totalSize, &MaxUserBackgroundRequest)
	sanitizeFuseLimits(totalSize, &MaxUserCongestionThreshold)

	fs.fuseConn.BgLock.Lock()
	defer fs.fuseConn.BgLock.Unlock()

	if out.MaxBackground > 0 {
		fs.fuseConn.MaxBackground = out.MaxBackground

		if !isCapable &&
			fs.fuseConn.MaxBackground > MaxUserBackgroundRequest {
			fs.fuseConn.MaxBackground = MaxUserBackgroundRequest
		}
	}
	if out.CongestionThreshold > 0 {
		fs.fuseConn.CongestionThreshold = out.CongestionThreshold

		if !isCapable &&
			fs.fuseConn.CongestionThreshold > MaxUserCongestionThreshold {
			fs.fuseConn.CongestionThreshold = MaxUserCongestionThreshold
		}
	}
}

// Calculates a value for one maximum limit (for MaxUserBackgroundRequest and MaxUserCongestionThreshold)
// if the current value is 0.
func sanitizeFuseLimits(totalSize uint64, limit *uint16) {
	// Assume request has 392 bytes
	const requsetSize = 392
	const memoryFraction = 13

	// Calculate default number of async request
	// to be 1/2^13 of total memory
	if *limit == 0 {
		newLimit := (totalSize >> memoryFraction) / requsetSize
		if newLimit > math.MaxUint16 {
			newLimit = math.MaxUint16
		}
		*limit = uint16(newLimit)
	}
}
