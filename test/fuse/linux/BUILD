load("//third_party/gvisor/tools:defs.bzl", "cc_library", "gtest")

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

cc_test(
    name = "init_test",
    srcs = [
        "fuse_base.h",
        "init_test.cc",
    ],
    deps = [
        ":fuse_base",
        "//test/util:test_util",
        "//test/util:test_main",
    ],
)