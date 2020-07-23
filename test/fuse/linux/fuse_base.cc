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

#include <iostream>

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/fuse.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "fuse_base.h"

namespace gvisor {
namespace testing {

void FuseTest::SetUp() {
  MountFuse();
  SetUpFuseServer();
}

void FuseTest::TearDown() { UnmountFuse(); }

// Since CompareRequest is running in background thread, gTest assertions and
// expectations won't directly reflect the test result. However, the FUSE
// background server still connects to the same standard I/O as testing main
// thread. So EXPECT_XX can still be used to show different results. To
// ensure failed testing result is observable, return false and the result
// will be sent to test main thread via pipe.
bool FuseTest::CompareRequest(void* expected_mem, size_t expected_len,
                              void* real_mem, size_t real_len) {
  if (expected_len != real_len) return false;
  return memcmp(expected_mem, real_mem, expected_len) == 0;
}

// SetExpected is called by the testing main thread to set expected request-
// response pair of a single FUSE operation.
int FuseTest::SetExpected(struct iovec* iov_in, int iov_in_cnt,
                          struct iovec* iov_out, int iov_out_cnt) {
  if (writev(set_expected_[1], iov_in, iov_in_cnt) <= 0) {
    perror("writev iov_in failed");
    return -1;
  }

  if (writev(set_expected_[1], iov_out, iov_out_cnt) <= 0) {
    perror("writev iov_out failed");
    return -1;
  }

  WaitCompleted();
  return 0;
}

// WaitCompleted waits for the FUSE server to finish its job and check if it
// completes without errors.
void FuseTest::WaitCompleted() {
  char success;
  read(done_[0], &success, sizeof(success));
  EXPECT_EQ(success, 1);
}

void FuseTest::MountFuse() {
  char mount_opts[128];
  dev_fd_ = open("/dev/fuse", O_RDWR);
  ASSERT_GT(dev_fd_, 0);

  sprintf(mount_opts, "fd=%d,%s", dev_fd_, MOUNT_OPTS);
  ASSERT_EQ(
      0, mount("fuse", MOUNT_POINT, "fuse", MS_NODEV | MS_NOSUID, mount_opts));
}

void FuseTest::UnmountFuse() {
  EXPECT_EQ(umount(MOUNT_POINT), 0);
  // TODO(gvisor.dev/issue/3330): ensure the process is terminated successfully
}

// ConsumeFuseInit consumes the first FUSE request and returns 0 if succeed.
int FuseTest::ConsumeFuseInit() {
  if (buf_ == nullptr) buf_ = malloc(FUSE_MIN_READ_BUFFER);

  size_t in_len = sizeof(struct fuse_in_header) + sizeof(struct fuse_init_in);
  if (read(dev_fd_, buf_, in_len) < 0) {
    perror("read from /dev/fuse");
    return -1;
  }

  struct iovec iov_out[2];
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_init_out),
      .error = 0,
      .unique = 2,
  };
  // init out payload is ignored
  struct fuse_init_out out_payload;
  iov_out[0].iov_len = sizeof(out_header);
  iov_out[0].iov_base = &out_header;
  iov_out[1].iov_len = sizeof(out_payload);
  iov_out[1].iov_base = &out_payload;

  if (writev(dev_fd_, iov_out, 2) <= 0) {
    perror("write to /dev/fuse");
    return -1;
  }
  return 0;
}

// ReceiveExpected reads 1 pair of expected fuse request-response `iovec`s
// from pipe and save them into member variables of this testing instance.
int FuseTest::ReceiveExpected() {
  char success = 1;
  size_t offset = 0, payload_len = 0, header_len = 0;
  if (buf_ == nullptr) buf_ = malloc(FUSE_MIN_READ_BUFFER);

  // set expected fuse_in request
  header_len = sizeof(struct fuse_in_header);
  if (read(set_expected_[0], buf_, header_len) != ssize_t(header_len)) {
    std::cerr << "read fuse_in_header failed" << std::endl;
    success = 0;
  }
  offset += header_len;

  payload_len = GetPayloadSize(((struct fuse_in_header*)buf_)->opcode,
                               true /* look for fuse_in request */);
  if (read(set_expected_[0], (char*)buf_ + offset, payload_len) !=
      ssize_t(payload_len)) {
    std::cerr << "read fuse_in payload failed" << std::endl;
    success = 0;
  }
  offset += payload_len;

  if (mem_in_ == nullptr) mem_in_ = malloc(offset);
  if (offset > len_in_) mem_in_ = realloc(mem_in_, offset);
  len_in_ = offset;
  memcpy(mem_in_, buf_, len_in_);

  // set expected fuse_out response
  offset = 0;
  header_len = sizeof(struct fuse_out_header);
  payload_len = GetPayloadSize(((struct fuse_in_header*)buf_)->opcode,
                               false /* look for fuse_out response*/);
  if (read(set_expected_[0], buf_, header_len) != ssize_t(header_len)) {
    std::cerr << "read fuse_out header failed" << std::endl;
    success = 0;
  }
  offset += header_len;

  // if error != 0 in fuse_out_header, this response will not have payload
  if (((struct fuse_out_header*)buf_)->error == 0) {
    if (read(set_expected_[0], (char*)buf_ + offset, payload_len) !=
        ssize_t(payload_len)) {
      std::cerr << "read fuse_out payload failed" << std::endl;
      success = 0;
    }
    offset += payload_len;
  }

  if (mem_out_ == nullptr) mem_out_ = malloc(offset);
  if (offset > len_out_) mem_out_ = realloc(mem_out_, offset);
  len_out_ = offset;
  memcpy(mem_out_, buf_, len_out_);

  MarkDone(success);
  return 0;
}

// MarkDone writes 1 byte of success indicator through pipe.
void FuseTest::MarkDone(char success) {
  write(done_[1], &success, sizeof(success));
}

// FuseLoop is the implementation of the fake FUSE server. Read from /dev/fuse,
// compare the request by CompareRequest (use derived function if specified),
// and write the expected response to /dev/fuse.
void FuseTest::FuseLoop() {
  char success = 1;
  while (true) {
    ReceiveExpected();

    if (read(dev_fd_, buf_, len_in_) != ssize_t(len_in_)) {
      std::cerr << "read from /dev/fd failed" << std::endl;
      success = 0;
    }
    if (!CompareRequest(buf_, len_in_, mem_in_, len_in_)) {
      std::cerr << "memory is not equal" << std::endl;
      success = 0;
    }
    if (write(dev_fd_, mem_out_, len_out_) != ssize_t(len_out_)) {
      std::cerr << "write to /dev/fd failed" << std::endl;
      success = 0;
    }
    MarkDone(success);
  }
}

// SetUpFuseServer creates 2 pipes. First is for testing client to send the
// expected request-response pair, and the other acts as a checkpoint for the
// FUSE server to notify the client that it can proceed.
void FuseTest::SetUpFuseServer() {
  ASSERT_EQ(pipe(set_expected_), 0);
  ASSERT_EQ(pipe(done_), 0);

  switch (fork()) {
    case -1:
      perror("fork");
      GTEST_FAIL();
      return;
    case 0:
      break;
    default:
      close(set_expected_[0]);
      close(done_[1]);
      WaitCompleted();
      return;
  }

  close(set_expected_[1]);
  close(done_[0]);

  MarkDone(ConsumeFuseInit() == 0 ? 1 : 0);

  FuseLoop();
  _exit(0);
}

size_t FuseTest::GetPayloadSize(uint32_t opcode, bool in) {
  switch (opcode) {
    case FUSE_GETATTR:
      return in ? sizeof(struct fuse_getattr_in) : sizeof(struct fuse_attr_out);
    case FUSE_INIT:
      return in ? sizeof(struct fuse_init_in) : sizeof(struct fuse_init_out);
    default:
      break;
  };
  return 0;
}

}  // namespace testing
}  // namespace gvisor
