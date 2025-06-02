# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License".
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

load("@fbsource//tools/build_defs:fb_native_wrapper.bzl", "fb_native")
load(
    "@prelude//erlang:erlang_toolchain.bzl",
    "erlang_parse_transform",
)
# @fb-only

fb_native.export_file(
    name = "taint_models",
    src = "finer_taint/priv/models.cfg",
)

erlang_application(
    name = "finer_taint",
    srcs = glob(
        [
            "finer_taint/src/*.erl",
            "finer_taint/src/*.hrl",
            "finer_taint/src/models/*.erl",
        ],
    ),
    applications = [
        "kernel",
        "stdlib",
        "compiler",
        "crypto",
        "syntax_tools",
        ":taint_server",
    ],
    extra_includes = [],
    includes = glob(["finer_taint/include/*.hrl"]),
    resources = [":taint_models"],
    version = "0.1.0",
)

erlang_parse_transform(
    name = "finer_taint_compiler",
    src = "finer_taint/src/finer_taint_compiler.erl",
    extra_files = [
        "finer_taint/priv/finer_taint.cfg",
        "finer_taint/priv/instrument_ignorelist.cfg",
    ],
    visibility = ["PUBLIC"],
)

erlang_escript(
    name = "script",
    emu_args = [
        "+sbtu",
        "+A1",
    ],
    include_priv = True,
    main_module = "run_finer_taint_escript",
    script_name = "run_finer_taint",
    deps = [
        ":finer_taint",
    ],
)

erlang_tests(
    contacts = ["whatsapp_code_analysis"],
    labels = ["unit"],
    suites = ["finer_taint/test/finer_taint_SUITE.erl"],
    deps = [":finer_taint_unittest_deps"],
)

erlang_tests(
    contacts = ["whatsapp_code_analysis"],
    labels = ["unit"],
    suites = [
        "finer_taint/test/parallel_taint_SUITE.erl",
        "finer_taint/test/abstract_machine_util_SUITE.erl",
        "finer_taint/test/taint_gatherer_SUITE.erl",
        "finer_taint/test/abstract_machine_proclet_SUITE.erl",
    ],
    deps = [
        ":finer_taint_SUITE",
        ":finer_taint_unittest_deps",
    ],
)

erlang_application(
    name = "finer_taint_unittest_deps",
    srcs = ["finer_taint/test/capture_out.erl"],
    applications = [
        ":finer_taint",
        "stdlib",
        "common_test",
    ],
    labels = [
        "test_application",
        "unit_test_deps",
    ],
)

erlang_application(
    name = "taint_server",
    srcs = glob([
        "taint_server/src/*.erl",
        "taint_server/src/*.hrl",
    ]),
    app_src = "taint_server/src/taint_server.app.src",
    applications = [
        "kernel",
        "stdlib",
    ],
    includes = glob(["taint_server/include/*.hrl"]),
    version = "0.1.0",
    visibility = ["PUBLIC"],
)

erlang_tests(
    contacts = ["whatsapp_code_analysis"],
    labels = ["unit"],
    suites = glob(["taint_server/test/*_SUITE.erl"]),
    deps = [
        "common_test",
        "stdlib",
        ":taint_server",
    ],
)

erlang_application(
    name = "all_examples",
    srcs = glob(
        [
            "examples/*.erl",
        ],
    ),
    applications = [
        ":finer_taint",
        ":taint_server",
    ],
    version = "0.1.0",
    visibility = ["PUBLIC"],
)

erlang_escript(
    name = "examples",
    include_priv = True,
    main_module = "example_main",
    script_name = "example_main",
    deps = [":all_examples"],
)
