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

load("@bazel_skylib//rules:build_test.bzl", "build_test")
load("@io_bazel_rules_go//go:def.bzl", "go_binary")

package(
    default_visibility = [
        "//:__subpackages__",
    ],
)

go_binary(
    name = "buzzer",
    srcs = ["main.go"],
    gc_linkopts = [
        "-linkmode=external",
        "-extldflags=-static",
    ],
    deps = [
        "//pkg/metrics",
        "//pkg/units",
    ],
)

build_test(
   name = "buzzer_build_test",
   targets = ["//:buzzer"],
)
