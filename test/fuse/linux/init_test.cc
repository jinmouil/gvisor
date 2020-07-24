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

#include <errno.h>
#include <fcntl.h>
#include <linux/fuse.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "fuse_base.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class InitTestNormal : public FuseTest {
 public:
  bool CompareRequest(void* expected_mem, size_t expected_len, void* real_mem,
                      size_t real_len) override {
    return true;
  }

  int ConsumeFuseInit() {
    if (buf_ == nullptr) buf_ = malloc(FUSE_MIN_READ_BUFFER);
    return 0;
  }
};

TEST_F(InitTestNormal, InitNormal) {
  if (buf_ == nullptr) buf_ = malloc(FUSE_MIN_READ_BUFFER);

  size_t offset = 0;

  // Read from the device to ensure we sent init request.

  // Read the header.
  size_t header_len = sizeof(struct fuse_in_header);
  ASSERT_THAT(read(dev_fd_, buf_, header_len), SyscallSucceedsWithValue(ssize_t(header_len));
  offset += header_len;

  struct fuse_in_header* init_header = (struct fuse_in_header*)buf_;

  // Read the payload.
  size_t payload_len = sizeof(struct fuse_init_in);
  ASSERT_THAT(read(dev_fd_, buf_, payload_len), SyscallSucceedsWithValue(ssize_t(payload_len));
  offset += payload_len;

  struct fuse_init_in* init_in = (struct fuse_init_in*)buf_;

  EXPECT_EQ(init_header->opcode, FUSE_INIT)

  WaitCompleted();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
