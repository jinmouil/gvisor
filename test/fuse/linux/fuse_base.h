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

#include <sys/uio.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace gvisor {
namespace testing {

constexpr char MOUNT_POINT[] = "/mnt";
constexpr char MOUNT_OPTS[] = "rootmode=755,user_id=0,group_id=0";

class FuseTest : public ::testing::Test {
 public:
  FuseTest() : buf_(nullptr), mem_in_(nullptr), mem_out_(nullptr) {}
  ~FuseTest() {
    if (buf_ != nullptr) free(buf_);
    if (mem_in_ != nullptr) free(mem_in_);
    if (mem_out_ != nullptr) free(mem_out_);
  }

  void SetUp() override;
  void TearDown() override;

  // CompareRequest is used by the FUSE server and should be implemented to
  // compare different FUSE operations. It compares the actual FUSE input
  // request with the expected one set by `SetExpected()`.
  virtual bool CompareRequest(void* expected_mem, size_t expected_len,
                              void* real_mem, size_t real_len);

  // SetExpected is called by the testing main thread. Writes a request-
  // response pair into FUSE server's member variables via pipe.
  int SetExpected(struct iovec* iov_in, int iov_in_cnt, struct iovec* iov_out,
                  int iov_out_cnt);

  // WaitCompleted waits for FUSE server to complete its processing. It
  // complains if the FUSE server responds failure during tests.
  void WaitCompleted();

 private:
  void MountFuse();
  void UnmountFuse();

  // ConsumeFuseInit is only used during FUSE server setup.
  int ConsumeFuseInit();

  // ReceiveExpected is the FUSE server side's corresponding code of
  // `SetExpected()`. Save the request-response pair into its memory.
  int ReceiveExpected();

  // MarkDone is used by the FUSE server to tell testing main if it's OK to
  // proceed next command.
  void MarkDone(char success);

  // FuseLoop is where the FUSE server stay until it is terminated.
  void FuseLoop();

  // SetUpFuseServer creates 2 pipes for communication and forks FUSE server.
  void SetUpFuseServer();

  // GetPayloadSize is a helper function to get the number of bytes of a
  // specific FUSE operation struct.
  size_t GetPayloadSize(uint32_t opcode, bool in);

  int dev_fd_;
  int set_expected_[2];
  int done_[2];

  void* buf_;
  void* mem_in_;
  size_t len_in_;
  void* mem_out_;
  size_t len_out_;
};

}  // namespace testing
}  // namespace gvisor
