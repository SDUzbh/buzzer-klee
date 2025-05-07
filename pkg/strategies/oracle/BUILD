load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
    default_visibility = [
        "//visibility:public",
    ],
)

go_library(
    name = "oracle",
    srcs = [
        "builder.go",
        "oracle.go",
    ],
    importpath = "buzzer/pkg/strategies/oracle",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/ebpf",
        "//proto:ebpf_go_proto",
    ],
)
