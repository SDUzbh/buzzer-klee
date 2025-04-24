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
    importpath = "buzzer/pkg/strategies/parse_verifier/oracle",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/ebpf",
        "//proto:ebpf_go_proto",
    ],
)

go_test(
    name = "oracle_test",
    srcs = [
        "builder_test.go",
        "oracle_test.go",
    ],
    embed = [":oracle"],  # This is fine, it already includes the necessary dependencies
    importpath = "buzzer/pkg/strategies/parse_verifier/oracle",  # Fix importpath to match the go_library
    deps = [
        "//pkg/ebpf",
    ],  # No need to add dependencies here
)


