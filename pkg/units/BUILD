# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
    default_visibility = [
        "//visibility:public",
    ],
)

go_library(
    name = "units",
    srcs = [
        "control.go",
        "coverage_manager.go",
        "ffi.go",
        "metrics_collection.go",
        "metrics_server.go",
        "metrics_unit.go",
        "symexec.go",
    ],
    cdeps = [
        "//ebpf_ffi",
    ],
    cgo = 1,
    importpath = "buzzer/pkg/units/units",
    deps = [
        "//pkg/cbpf",
        "//pkg/ebpf",
        "//proto:cbpf_go_proto",
        "//proto:ebpf_go_proto",
        "//proto:ffi_go_proto",
        "//proto:program_go_proto",
        "@com_github_go_echarts_go_echarts_v2//charts",
        "@com_github_go_echarts_go_echarts_v2//opts",
        "@com_github_go_echarts_go_echarts_v2//types",
        "@com_github_golang_protobuf//proto",
        "@com_github_google_safehtml//:safehtml",
    ],
)

go_test(
    name = "units_test",
    srcs = [
        "metrics_unit_test.go",
    ],
    embed = [":units"],
)
