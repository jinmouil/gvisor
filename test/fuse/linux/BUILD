load("//tools:defs.bzl", "cc_binary", "cc_library", "default_net_util", "gtest", "select_arch", "select_system")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

cc_library(
    name = "fuse_base",
    testonly = 1,
    srcs = [
        "fuse_base.h",
        "fuse_base.cc",
    ],
    deps = [
        gtest,
    ],
)
