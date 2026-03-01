% Copyright (c) Meta Platforms, Inc. and affiliates.
%
% Licensed under the Apache License, Version 2.0 (the "License");
% you may not use this file except in compliance with the License.
% You may obtain a copy of the License at
%
%     http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS,
% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
% See the License for the specific language governing permissions and
% limitations under the License.

%%% % @format
%%%-------------------------------------------------------------------
%%%     Tests for finer taint analysis
%%%
%%%     They instrument an erlang file, run a function in the instrumented module,
%%%     capture output and run it throught the abstract machine to get the leaks
%%% -------------------------------------------------------------------
-module(finer_taint_SUITE).

-include_lib("common_test/include/ct.hrl").
% elp:ignore WA003 (better_assertions) - Open Source
-include_lib("stdlib/include/assert.hrl").

%% Test server callbacks
-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1
]).

%% Test cases
-export([
    finds_simple_taint/1,
    extract_pattern/1,
    calling_convention/1,
    recursion/1,
    case_clauses/1,
    list_patterns/1,
    record_main/1,
    nested_case_main/1,
    nested_calls_main/1,
    modeled_functions/1,
    joining_model/1,
    process_dict_model/1,
    lambdas/1,
    lambda_closures/1,
    try_catch/1,
    try_catch_nested/1,
    try_catch_define/1,
    try_catch_crs/1,
    try_after/1,
    if_clause/1,
    bitstrings/1,
    bitstring_constructed/1,
    integer_constructed_extracted/1,
    map_values/1,
    map_keys/1,
    map_updates/1,
    map_module/1,
    opaque_map/1,
    case_in_function_args/1,
    i13n_to_not_i13n_to_i13n/1,
    comprehension_transform/1,
    basic_list_comprehension/1,
    pattern_to_var/1,
    maybe_expr/1,
    string_plusplus_pattern/1,
    set_element/1,
    operators_in_pattern/1,
    lineage_annotations_merge_taint/1,
    shortcircuiting/1,
    macro_duplicator/1
]).

%Helpers
-export([assert_instruction_stream_equal/2]).

groups() ->
    [
        {basic, [
            finds_simple_taint,
            extract_pattern,
            calling_convention,
            recursion,
            case_clauses,
            list_patterns,
            record_main,
            nested_case_main,
            nested_calls_main,
            modeled_functions,
            lambdas,
            lambda_closures,
            try_catch,
            try_catch_nested,
            try_catch_define,
            try_catch_crs,
            try_after,
            joining_model,
            process_dict_model,
            bitstrings,
            bitstring_constructed,
            integer_constructed_extracted,
            if_clause,
            map_values,
            map_keys,
            map_updates,
            map_module,
            opaque_map,
            case_in_function_args,
            i13n_to_not_i13n_to_i13n,
            basic_list_comprehension,
            comprehension_transform,
            pattern_to_var,
            maybe_expr,
            string_plusplus_pattern,
            set_element,
            operators_in_pattern,
            lineage_annotations_merge_taint,
            shortcircuiting,
            macro_duplicator
        ]}
    ].

all() ->
    [{group, basic}].

init_per_suite(Config) ->
    {module, modeled_taint_maps} = finer_taint_compiler:instrument_loaded_module(modeled_taint_maps, [
        {finer_taint_module, ct_finer_taint}
    ]),
    {module, modeled_erlang} = finer_taint_compiler:instrument_loaded_module(modeled_erlang, [
        {finer_taint_module, ct_finer_taint}
    ]),
    Config.

end_per_suite(_Config) ->
    ok.

compile(Modules, Config) ->
    DataDir = ?config(data_dir, Config),
    CompileMod = fun(Mod) ->
        ModFilename = lists:flatten(io_lib:format("~p.erl", [Mod])),
        ModPath = filename:join([DataDir, ModFilename]),
        true = is_list(ModPath),
        {ok, Mod, Binary = <<_/binary>>} = compile:file(ModPath, [debug_info, binary]),
        {ok, {Mod, [{abstract_code, {_, Forms}} | _]}} = beam_lib:chunks(Binary, [abstract_code, compile_info]),
        io:format("~p~n", [Forms]),
        {Mod, Forms}
    end,
    [CompileMod(Elem) || Elem <:- Modules] ++ Config.

compile_and_load(Config, Module) ->
    [{_, Forms} | _] = compile([Module], Config),
    io:format("~p Forms: ~p~n", [Module, Forms]),
    InstrumentedForms = finer_taint_compiler:instrument_with_sinks(Forms),
    % erl_expand_records can crash in erl_expand_records:guard_tests/2 (erl_expand_records.erl, line 161)
    % if guards aren't set as lists of lists. This call ensure that the expanded code
    % does not crash erl_expand_records
    ?assertNotException(error, function_clause, erl_expand_records:module(InstrumentedForms, [debug_info])),
    io:format("~p: ~n~s~n", [Module, erl_prettypr:format(erl_syntax:form_list(InstrumentedForms))]),
    {ok, Module, Binary = <<_/binary>>} = compile:forms(InstrumentedForms, [debug_info]),
    DataDir = ?config(data_dir, Config),
    code:add_patha(DataDir),
    BeamFileName = lists:flatten(io_lib:format("~p.beam", [Module])),
    BeamPath = filename:join(DataDir, BeamFileName),
    true = is_list(BeamPath),
    ok = file:write_file(BeamPath, Binary),
    {module, Module} = code:load_binary(Module, BeamPath, Binary).

compile_and_run_function(Config, Module, Func) ->
    compile_and_load(Config, Module),
    {_Ret, OutputRaw} = capture_out:capture_output(fun() -> Module:Func() end),
    %% Prepend generated to ignore these files in phabricator
    Output = "{push,{\"@ge" ++ "nerated\"}}.\n{pop,{}}.\n" ++ OutputRaw,
    FixtureFilename = get_instr_fixture_filename(Config, Func),
    {Status, RepoRoot} = file:read_file("/tmp/erlang_taint_root"),
    ReadFileResult = file:read_file(FixtureFilename),
    case {ct:get_verbosity(default), Status} of
        %% Run with: echo -n `pwd` > /tmp/erlang_taint_root ;  buck2 test -c 'erlang.erlang_test_ct_opts=[{verbosity,101}]' <test_target>
        %% to update the local fixture
        {101, ok} ->
            ok = file:write_file(
                filename:join([
                    RepoRoot, "finer_taint/test/finer_taint_SUITE_data", io_lib:format("~p_analysis_instr", [Func])
                ]),
                Output
            );
        _ ->
            ok
    end,
    {ok, FileCont} = ReadFileResult,
    assert_instruction_stream_equal(binary_to_list(FileCont), Output),
    State = taint_abstract_machine:run_tracing(FixtureFilename),
    % Make sure there is only the return value of the main function left on the stack
    ?assertMatch([_], taint_abstract_machine:get_stack(State)),
    taint_abstract_machine:get_leaks(State).

% Compares live instruction stream with the one in fixture
% accoutning for differences due to OTP versions
assert_instruction_stream_equal(Expected, Actual) ->
    Replace = fun(Instructions) ->
        % GenLc<Suffix> variable names depend on a hash of a subexpression AST,
        % that can change with OTP versions
        re:replace(Instructions, "\"[^\"]*Gen.c[^\"]*\"", "<GenLCId>", [{return, list}, global])
    end,
    ?assertEqual(Replace(Expected), Replace(Actual)).

get_instr_fixture_filename(Config, Func) ->
    DataDir = ?config(data_dir, Config),
    filename:join(DataDir, io_lib:format("~p_analysis_instr", [Func])).

run_lineage_analysis(Config, Func) ->
    FixtureFilename = get_instr_fixture_filename(Config, Func),
    FullLineage = parallel_abstract_machine:run_lineage_with_line_history([FixtureFilename]),
    ReducedLineage = parallel_abstract_machine:run_lineage([FixtureFilename]),
    ?assertEqual(
        length(abstract_machine_util:get_arg_lineage_raw(FullLineage)),
        length(abstract_machine_util:get_arg_lineage_raw(ReducedLineage))
    ),
    FullLineage.

%%--------------------------------------------------------------------
%% TEST CASES
finds_simple_taint(Config) ->
    [{leak, _, Leaks}] = compile_and_run_function(Config, simple_example, one_clause),
    ?assertEqual(
        [
            {step, "simple_example.erl:26"},
            {return_site, {string, slice, 3}, "simple_example.erl:23"},
            {call_site, {string, slice, 3}, "simple_example.erl:23"},
            {step, "simple_example.erl:23"},
            {tagged_source, "phone_num", "simple_example.erl:21"}
        ],
        Leaks
    ).

if_clause(Config) ->
    [{leak, Sink, History}] = compile_and_run_function(Config, simple_example, if_clause),
    ?assertEqual(Sink, "simple_example.erl:33"),
    ?assertEqual(abstract_machine_util:get_sources(History), ["simple_example.erl:29"]).

lineage_annotations_merge_taint(Config) ->
    [] = compile_and_run_function(Config, simple_example, lineage_main),
    ArgLeaks = run_lineage_analysis(Config, lineage_main),
    Lineage = abstract_machine_util:get_arg_lineage(ArgLeaks, human_readable_annotated),
    ?assertEqual(
        "simple_example:lineage_entry/2-Arg1 -> simple_example:pack/1-Arg1\n"
        "  call@simple_example.erl:43\n"
        "  call@simple_example.erl:44\n"
        "simple_example:lineage_entry/2-Arg1 -> simple_example:unpack/1-Arg1\n"
        "  call@simple_example.erl:44\n"
        "simple_example:lineage_entry/2-Arg2 -> simple_example:pack/1-Arg1\n"
        "  call@simple_example.erl:44\n"
        "simple_example:pack/1-Arg1 -> simple_example:pack/1-Arg1\n"
        "  ret@simple_example.erl:43;call@simple_example.erl:44\n"
        "simple_example:pack/1-Arg1 -> simple_example:unpack/1-Arg1\n"
        "  ret@simple_example.erl:43;call@simple_example.erl:44\n"
        "simple_example:unpack/1-Arg1 -> simple_example:pack/1-Arg1\n"
        "  ret@simple_example.erl:44;call@simple_example.erl:44\n",
        Lineage
    ).

pattern_to_var(Config) ->
    [{leak, Sink, History}] = compile_and_run_function(Config, pattern_to_var, pattern_to_var),
    ?assertEqual(Sink, "pattern_to_var.erl:26"),
    ?assertEqual(abstract_machine_util:get_sources(History), ["pattern_to_var.erl:21"]).

maybe_expr(Config) ->
    [{leak, Sink2, History2}, {leak, Sink, History}] = compile_and_run_function(
        Config, pattern_to_var, maybe_expr_main
    ),
    ?assertEqual(Sink, "pattern_to_var.erl:88"),
    ?assertEqual(abstract_machine_util:get_sources(History), ["pattern_to_var.erl:86"]),
    ?assertEqual(Sink2, "pattern_to_var.erl:93"),
    ?assertEqual(abstract_machine_util:get_sources(History2), ["pattern_to_var.erl:86", "pattern_to_var.erl:81"]).

operators_in_pattern(Config) ->
    [{leak, Sink, History}] = compile_and_run_function(Config, pattern_to_var, operators_in_pattern_main),
    ?assertEqual(Sink, "pattern_to_var.erl:65"),
    ?assertEqual(abstract_machine_util:get_sources(History), ["pattern_to_var.erl:60"]).

set_element(Config) ->
    [{leak, Sink2, History2}, {leak, Sink1, History1}] = compile_and_run_function(
        Config, pattern_to_var, set_element_main
    ),
    ?assertEqual(Sink1, "pattern_to_var.erl:55"),
    ?assertEqual(abstract_machine_util:get_sources(History1), ["pattern_to_var.erl:49"]),
    ?assertEqual(Sink2, "pattern_to_var.erl:56"),
    ?assertEqual(abstract_machine_util:get_sources(History2), ["pattern_to_var.erl:50"]).

string_plusplus_pattern(Config) ->
    [{leak, Sink, History}] = compile_and_run_function(Config, pattern_to_var, string_plusplus_pattern),
    ?assertEqual(Sink, "pattern_to_var.erl:45"),
    ?assertEqual(abstract_machine_util:get_sources(History), ["pattern_to_var.erl:43"]).

extract_pattern(Config) ->
    Leaks = compile_and_run_function(Config, pattern_to_var, extract_pattern),
    ?assertEqual(length(Leaks), 3),
    LeakedSinks = [Sink || {leak, Sink, _History} <- Leaks],
    ?assertEqual(LeakedSinks, ["pattern_to_var.erl:38", "pattern_to_var.erl:37", "pattern_to_var.erl:32"]).

nested_calls_main(Config) ->
    Leaks = compile_and_run_function(Config, function_calls, nested_calls_main),
    [{leak, Sink, History}] = Leaks,
    ?assertEqual(Sink, "function_calls.erl:69"),
    ?assertEqual(abstract_machine_util:get_sources(History), ["function_calls.erl:68"]),
    ?assertEqual(
        [
            {return_site, {function_calls, at, 2}, "function_calls.erl:69"},
            {step, "function_calls.erl:64"},
            {step, "function_calls.erl:64"},
            {call_site, {function_calls, at, 2}, "function_calls.erl:69"},
            {step, "function_calls.erl:69"},
            {return_site, {function_calls, insert_at, 3}, "function_calls.erl:68"},
            {step, "function_calls.erl:59"},
            {step, "function_calls.erl:59"},
            {call_site, {function_calls, insert_at, 3}, "function_calls.erl:68"},
            {source, "function_calls.erl:68"}
        ],
        History
    ).

lambda_closures(Config) ->
    Leaks = compile_and_run_function(Config, function_calls, lambda_closures_main),
    [{leak, Sink, History}] = Leaks,
    ?assertEqual(Sink, "function_calls.erl:94"),
    ?assertEqual(abstract_machine_util:get_sources(History), ["function_calls.erl:92"]),
    ?assertEqual(
        [
            {return_site, {function_calls, variable_func, 0}, "function_calls.erl:94"},
            {return_site, {operators, '+', 2}, "function_calls.erl:89"},
            {call_site, {operators, '+', 2}, "function_calls.erl:89"},
            {step, "function_calls.erl:89"},
            {call_site, {function_calls, variable_func, 0}, "function_calls.erl:94"},
            {step, "function_calls.erl:94"},
            {return_site, {function_calls, create_lambda, 1}, "function_calls.erl:93"},
            {call_site, {function_calls, create_lambda, 1}, "function_calls.erl:93"},
            {step, "function_calls.erl:93"},
            {source, "function_calls.erl:92"}
        ],
        History
    ).

lambdas(Config) ->
    Leaks = compile_and_run_function(Config, function_calls, lambdas_main),
    [{leak, Sink1, History1}, {leak, Sink, History}] = Leaks,
    ?assertEqual(Sink, "function_calls.erl:75"),
    ?assertEqual(abstract_machine_util:get_sources(History), ["function_calls.erl:73"]),
    ?assertEqual(Sink1, "function_calls.erl:83"),
    ?assertEqual(abstract_machine_util:get_sources(History1), ["function_calls.erl:73"]),
    ?assertEqual(
        [
            {step, "function_calls.erl:83"},
            {step, "function_calls.erl:82"},
            {return_site, {function_calls, variable_func, 2}, "function_calls.erl:82"},
            {step, "function_calls.erl:79"},
            {return_site, {function_calls, variable_func, 1}, "function_calls.erl:79"},
            {return_site, {operators, '+', 2}, "function_calls.erl:77"},
            {call_site, {operators, '+', 2}, "function_calls.erl:77"},
            {step, "function_calls.erl:77"},
            {call_site, {function_calls, variable_func, 1}, "function_calls.erl:79"},
            {step, "function_calls.erl:79"},
            {call_site, {function_calls, variable_func, 2}, "function_calls.erl:82"},
            {step, "function_calls.erl:82"},
            {source, "function_calls.erl:73"}
        ],
        History1
    ).

calling_convention(Config) ->
    Leaks = compile_and_run_function(Config, function_calls, calling_convention_main),
    ?assertEqual(length(Leaks), 1),
    [{leak, Sink, History}] = Leaks,
    ?assertEqual(Sink, "function_calls.erl:26"),
    ?assertEqual(History, [
        {step, "function_calls.erl:26"},
        {return_site, {function_calls, process_two_lists, 2}, "function_calls.erl:23"},
        {return_site, {function_calls, concat_two_lists, 2}, "function_calls.erl:37"},
        {return_site, {operators, '++', 2}, "function_calls.erl:34"},
        {call_site, {operators, '++', 2}, "function_calls.erl:34"},
        {step, "function_calls.erl:34"},
        {call_site, {function_calls, concat_two_lists, 2}, "function_calls.erl:37"},
        {step, "function_calls.erl:37"},
        {return_site, {function_calls, append_to_list, 1}, "function_calls.erl:36"},
        {return_site, {operators, '++', 2}, "function_calls.erl:30"},
        {call_site, {operators, '++', 2}, "function_calls.erl:30"},
        {step, "function_calls.erl:30"},
        {call_site, {function_calls, append_to_list, 1}, "function_calls.erl:36"},
        {step, "function_calls.erl:36"},
        {call_site, {function_calls, process_two_lists, 2}, "function_calls.erl:23"},
        {step, "function_calls.erl:23"},
        {source, "function_calls.erl:22"}
    ]).

recursion(Config) ->
    Leaks = compile_and_run_function(Config, function_calls, recursion_main),
    [{leak, Sink2, _History}, {leak, Sink, History}] = Leaks,
    ?assertEqual(Sink, "function_calls.erl:47"),
    ?assertEqual(Sink2, "function_calls.erl:52"),
    ?assertEqual(
        [
            {step, "function_calls.erl:47"},
            {return_site, {function_calls, insert_at, 3}, "function_calls.erl:44"},
            {step, "function_calls.erl:62"},
            {step, "function_calls.erl:62"},
            {return_site, {function_calls, insert_at, 3}, "function_calls.erl:61"},
            {step, "function_calls.erl:62"},
            {step, "function_calls.erl:62"},
            {return_site, {function_calls, insert_at, 3}, "function_calls.erl:61"},
            {step, "function_calls.erl:59"},
            {step, "function_calls.erl:59"},
            {call_site, {function_calls, insert_at, 3}, "function_calls.erl:61"},
            {step, "function_calls.erl:61"},
            {call_site, {function_calls, insert_at, 3}, "function_calls.erl:61"},
            {step, "function_calls.erl:61"},
            {call_site, {function_calls, insert_at, 3}, "function_calls.erl:44"},
            {step, "function_calls.erl:44"},
            {source, "function_calls.erl:43"}
        ],
        History
    ),
    ArgLeaks = run_lineage_analysis(Config, recursion_main),
    Lineage = abstract_machine_util:get_arg_lineage(ArgLeaks, human_readable),
    ?assertEqual(
        lists:flatten(
            lists:join("\n", [
                "function_calls:at/2-Arg1 -> function_calls:at/2-Arg1",
                "function_calls:at/2-Arg2 -> function_calls:at/2-Arg2",
                "function_calls:generate_list/1-Arg1 -> function_calls:at/2-Arg2",
                "function_calls:generate_list/1-Arg1 -> function_calls:generate_list/1-Arg1",
                "function_calls:generate_list/1-Arg1 -> function_calls:insert_at/3-Arg3",
                "function_calls:insert_at/3-Arg1 -> function_calls:insert_at/3-Arg1",
                "function_calls:insert_at/3-Arg2 -> function_calls:at/2-Arg2",
                "function_calls:insert_at/3-Arg2 -> function_calls:insert_at/3-Arg2",
                "function_calls:insert_at/3-Arg3 -> function_calls:at/2-Arg2",
                "function_calls:insert_at/3-Arg3 -> function_calls:insert_at/3-Arg3",
                ""
            ])
        ),
        Lineage
    ),
    InsertAt_To_At_Lineage = abstract_machine_util:query_arg_lineage(ArgLeaks, {
        {function_calls, insert_at, 3}, 2, {function_calls, at, 2}, 2
    }),
    ?assertEqual(
        6,
        length(InsertAt_To_At_Lineage),
        "There are 6 times function_calls:insert_at/3-Arg2 flows to function_calls:at/2-Arg2 "
    ),
    ?assertEqual(
        [
            {dataflow_src, {{function_calls, insert_at, 3}, 2}, [
                {return_site, {function_calls, insert_at, 3}, "function_calls.erl:44"},
                {call_site, {function_calls, at, 2}, "function_calls.erl:50"}
            ]},

            {arg_leak, {{function_calls, at, 2}, 2}}
        ],
        lists:nth(1, lists:usort(InsertAt_To_At_Lineage))
    ).

try_catch_define(Config) ->
    Leaks = compile_and_run_function(Config, try_catch, try_catch_define_main),
    [{leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual("try_catch.erl:94", FirstSink),
    ?assertEqual(["try_catch.erl:91"], abstract_machine_util:get_sources(FirstHistory)).

try_catch_crs(Config) ->
    Leaks = compile_and_run_function(Config, try_catch, try_catch_crs_main),
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual("try_catch.erl:104", FirstSink),
    ?assertEqual(["try_catch.erl:99"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("try_catch.erl:114", SecondSink),
    ?assertEqual(["try_catch.erl:110"], abstract_machine_util:get_sources(SecondHistory)).

try_catch_nested(Config) ->
    Leaks = compile_and_run_function(Config, try_catch, try_catch_nested_main),
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual("try_catch.erl:82", FirstSink),
    ?assertEqual(["try_catch.erl:73"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("try_catch.erl:85", SecondSink),
    ?assertEqual(["try_catch.erl:73"], abstract_machine_util:get_sources(SecondHistory)).

try_after(Config) ->
    Leaks = compile_and_run_function(Config, try_catch, try_after_main),
    [{leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["try_catch.erl:118"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("try_catch.erl:122", FirstSink).

try_catch(Config) ->
    Leaks = compile_and_run_function(Config, try_catch, try_main),
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["try_catch.erl:37"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("try_catch.erl:49", FirstSink),
    ?assertEqual(["try_catch.erl:37"], abstract_machine_util:get_sources(SecondHistory)),
    ?assertEqual("try_catch.erl:53", SecondSink),

    Leaks1 = compile_and_run_function(Config, try_catch, try_catch_main2),
    [{leak, Sink1, History1}] = Leaks1,
    ?assertEqual("try_catch.erl:69", Sink1),
    ?assertEqual(["try_catch.erl:60"], abstract_machine_util:get_sources(History1)).

bitstrings(Config) ->
    Leaks = compile_and_run_function(Config, bitstrings, bitstring_main),
    [{leak, Sink, History}] = Leaks,
    ?assertEqual("bitstrings.erl:24", Sink),
    ?assertEqual(["bitstrings.erl:22"], abstract_machine_util:get_sources(History)).

bitstring_constructed(Config) ->
    Leaks = compile_and_run_function(Config, bitstrings, bitstring_constructed_main),
    [{leak, Sink2, History2}, {leak, Sink1, History1}] = Leaks,
    ?assertEqual("bitstrings.erl:32", Sink1),
    ?assertEqual(["bitstrings.erl:27"], abstract_machine_util:get_sources(History1)),
    ?assertEqual("bitstrings.erl:33", Sink2),
    ?assertEqual(["bitstrings.erl:27"], abstract_machine_util:get_sources(History2)).

integer_constructed_extracted(Config) ->
    Leaks = compile_and_run_function(Config, bitstrings, integer_constructed_extracted_main),
    [{leak, Sink1, History1}] = Leaks,
    ?assertEqual("bitstrings.erl:40", Sink1),
    ?assertEqual(["bitstrings.erl:36"], abstract_machine_util:get_sources(History1)).

case_clauses(Config) ->
    Leaks = compile_and_run_function(Config, case_clauses, case_main),
    [{leak, Sink, History}] = Leaks,
    ?assertEqual("case_clauses.erl:30", Sink),
    ?assertEqual(["case_clauses.erl:27"], abstract_machine_util:get_sources(History)).

record_main(Config) ->
    Leaks = compile_and_run_function(Config, case_clauses, record_main),
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["case_clauses.erl:44"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("case_clauses.erl:48", FirstSink),
    ?assertEqual(["case_clauses.erl:44"], abstract_machine_util:get_sources(SecondHistory)),
    ?assertEqual("case_clauses.erl:49", SecondSink).

list_patterns(Config) ->
    Leaks = compile_and_run_function(Config, case_clauses, lists_main),
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["case_clauses.erl:54"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("case_clauses.erl:35", FirstSink),
    ?assertEqual(["case_clauses.erl:34"], abstract_machine_util:get_sources(SecondHistory)),
    ?assertEqual("case_clauses.erl:36", SecondSink).

map_updates(Config) ->
    Leaks = compile_and_run_function(Config, map_examples, map_update_main),
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["map_examples.erl:49"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("map_examples.erl:53", FirstSink),
    ?assertEqual(["map_examples.erl:49"], abstract_machine_util:get_sources(SecondHistory)),
    ?assertEqual("map_examples.erl:56", SecondSink).

map_values(Config) ->
    Leaks = compile_and_run_function(Config, map_examples, map_values_main),
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["map_examples.erl:24"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("map_examples.erl:26", FirstSink),
    ?assertEqual(["map_examples.erl:24"], abstract_machine_util:get_sources(SecondHistory)),
    ?assertEqual("map_examples.erl:28", SecondSink).

map_keys(Config) ->
    Leaks = compile_and_run_function(Config, map_examples, map_keys_main),
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["map_examples.erl:33"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("map_examples.erl:36", FirstSink),
    ?assertEqual(["map_examples.erl:33"], abstract_machine_util:get_sources(SecondHistory)),
    ?assertEqual("map_examples.erl:44", SecondSink).

opaque_map(Config) ->
    Leaks = compile_and_run_function(Config, map_examples, opaque_map_main),
    [{leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["map_examples.erl:76"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("map_examples.erl:78", FirstSink).

map_module(Config) ->
    Leaks = compile_and_run_function(Config, map_examples, map_module_main),
    [{leak, ThirdSink, ThirdHistory}, {leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["map_examples.erl:59"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("map_examples.erl:61", FirstSink),
    ?assertEqual(["map_examples.erl:59"], abstract_machine_util:get_sources(SecondHistory)),
    ?assertEqual("map_examples.erl:62", SecondSink),
    ?assertEqual(["map_examples.erl:59"], abstract_machine_util:get_sources(ThirdHistory)),
    ?assertEqual("map_examples.erl:73", ThirdSink).

process_dict_model(Config) ->
    Leaks = compile_and_run_function(Config, modeled_functions, process_dict_main),
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["modeled_functions.erl:35"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("modeled_functions.erl:38", FirstSink),
    ?assertEqual(["modeled_functions.erl:35"], abstract_machine_util:get_sources(SecondHistory)),
    ?assertEqual("modeled_functions.erl:39", SecondSink).

joining_model(Config) ->
    Leaks = compile_and_run_function(Config, modeled_functions, joining_model_main),
    [{leak, Sink, History}] = Leaks,
    ?assertEqual("modeled_functions.erl:32", Sink),
    ?assertEqual(["modeled_functions.erl:31", "modeled_functions.erl:30"], abstract_machine_util:get_sources(History)).

i13n_to_not_i13n_to_i13n(Config) ->
    UnmodeledFilePath = io_lib:format("~s/not_instrumented/not_instrumented.erl", [?config(data_dir, Config)]),
    {ok, not_instrumented} = c:c(UnmodeledFilePath),
    Leaks = compile_and_run_function(Config, i13n_to_not_i13n_to_i13n, i13n_to_not_i13n_to_i13n_main),
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = Leaks,
    ?assertEqual(["i13n_to_not_i13n_to_i13n.erl:29"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("i13n_to_not_i13n_to_i13n.erl:31", FirstSink),
    ?assertEqual(["i13n_to_not_i13n_to_i13n.erl:35"], abstract_machine_util:get_sources(SecondHistory)),
    ?assertEqual("i13n_to_not_i13n_to_i13n.erl:37", SecondSink).

modeled_functions(Config) ->
    UnmodeledFilePath = io_lib:format("~s/not_instrumented/definetly_not_modeled.erl", [?config(data_dir, Config)]),
    {ok, definetly_not_modeled} = c:c(UnmodeledFilePath),
    Leaks = compile_and_run_function(Config, modeled_functions, modeled_functions_main),
    [{leak, Sink, History}] = Leaks,
    ?assertEqual("modeled_functions.erl:25", Sink),
    ?assertEqual(["modeled_functions.erl:22", "modeled_functions.erl:23"], abstract_machine_util:get_sources(History)).

basic_list_comprehension(Config) ->
    Leaks = compile_and_run_function(Config, list_comprehension, basic_main),
    [{leak, Sink, History}] = Leaks,
    ?assertEqual("list_comprehension.erl:31", Sink),
    ?assertEqual(["list_comprehension.erl:23"], abstract_machine_util:get_sources(History)),
    Leaks1 = compile_and_run_function(Config, list_comprehension, cartesian_main),
    [{leak, Sink1, History1}] = Leaks1,
    ?assertEqual("list_comprehension.erl:37", Sink1),
    ?assertEqual(["list_comprehension.erl:23"], abstract_machine_util:get_sources(History1)).

case_in_function_args(Config) ->
    Leaks = compile_and_run_function(Config, case_clauses, case_in_function_args_main),
    [{leak, Sink, History}] = Leaks,
    ?assertEqual("case_clauses.erl:83", Sink),
    ?assertEqual(["case_clauses.erl:81"], abstract_machine_util:get_sources(History)).

shortcircuiting(Config) ->
    [] = compile_and_run_function(Config, shortcircuiting, safe_shortcircuit),
    Leaks = compile_and_run_function(Config, shortcircuiting, unsafe_shortcircuit),
    [{leak, Sink0, _}, {leak, Sink1, _}, {leak, Sink2, _}] = Leaks,
    ?assertEqual("shortcircuiting.erl:36", Sink0),
    ?assertEqual("shortcircuiting.erl:29", Sink1),
    ?assertEqual("shortcircuiting.erl:26", Sink2),
    F = fun({_, _, Hist}) -> ?assertEqual(["shortcircuiting.erl:25"], abstract_machine_util:get_sources(Hist)) end,
    lists:foreach(F, Leaks).

test_comprehension(Comprehension, CompareWith) ->
    {ok, Tokens, _} = erl_scan:string(Comprehension),
    {ok, [Forms]} = erl_parse:parse_exprs(Tokens),
    InstrumentedLc = finer_taint_compiler:rewrite_comprehension(Forms),
    case CompareWith of
        nocompare -> ok;
        print -> io:format(lists:flatten(erl_pp:expr(InstrumentedLc)));
        map -> ok;
        map_c -> ok;
        _ -> ?assertEqual(CompareWith, lists:flatten(erl_pp:expr(InstrumentedLc)))
    end,
    {value, Result, #{}} = erl_eval:expr(Forms, #{}),
    {value, InstrumentedResult, #{}} = erl_eval:expr(InstrumentedLc, #{}),
    case CompareWith of
        map ->
            true = is_list(Result),
            true = is_list(InstrumentedResult),
            ?assertEqual(lists:sort(Result), lists:sort(InstrumentedResult));
        _ ->
            ?assertEqual(Result, InstrumentedResult)
    end.

comprehension_transform(_Config) ->
    BasicComprehensionExpected =
        "fun GenLc5ENHDPWZ([]) ->\n"
        "        [];\n"
        "    GenLc5ENHDPWZ([X | GenlcTail5ENHDPWZ]) ->\n"
        "        [X | GenLc5ENHDPWZ(GenlcTail5ENHDPWZ)];\n"
        "    GenLc5ENHDPWZ([_ | GenlcTail5ENHDPWZ]) ->\n"
        "        GenLc5ENHDPWZ(GenlcTail5ENHDPWZ)\n"
        "end([1, 2, 3])",
    test_comprehension("[X || X <- [1,2,3]].", BasicComprehensionExpected),
    test_comprehension("[{X, Y} || X <- [1,2,3], Y <- [a,b,c]].", nocompare),
    test_comprehension("[{X, Y} || X <- [1,2,3], {a,Y} <- [{a,1},b,c]].", print),
    test_comprehension("[Y || {X1, Y} <- [{1,2}, {1,3}, {2,2}], 1 == X1, _ <- [1,2]].", print),
    test_comprehension("[X || X <- [1,2,3], fun(Y) -> Y == 1 end(X)].", print),
    test_comprehension("[{X, Y} || {a,Y} <- [{a,1},b,c], X <- [1,2,3]].", print),
    test_comprehension("[X || <<X:8/binary,Y>> <= <<1,2,3>>].", print),
    test_comprehension("[X || <<X:2>> <= <<1:8,2:8,3:8>>].", print),
    test_comprehension("[A || A := _V <- #{1 => a, 2 => b}].", map),
    test_comprehension("#{A => a || A := _V <- #{1 => a, 2 => b}}.", map_c),
    test_comprehension("[{X, Y} || <<X:1>> <= <<27:8>>, X rem 2 == 0, <<Y:4>> <= <<42,255,127>>].", print),
    test_comprehension("[X || X <:- [1,2,3]].", print),
    test_comprehension("[{X, Y} || X <:- [1,2,3], Y <:- [a,b,c]].", print),
    test_comprehension("[X || <<X:2>> <:= <<1:8,2:8,3:8>>].", print),
    test_comprehension("[A || A := _V <:- #{1 => a, 2 => b}].", map),
    test_comprehension("[{X, Y} || X <- [1,2,3] && Y <- [a,b,c]].", print),
    test_comprehension("[{X, Y} || X <:- [1,2,3] && Y <:- [a,b,c]].", print).

nested_case_main(Config) ->
    Leaks = compile_and_run_function(Config, case_clauses, nested_case_with_call_main),
    [{leak, Sink, History}] = Leaks,
    ?assertEqual("case_clauses.erl:71", Sink),
    ?assertEqual(["case_clauses.erl:67"], abstract_machine_util:get_sources(History)).

macro_duplicator(Config) ->
    [{leak, Sink, History}] = compile_and_run_function(Config, simple_example, macro_duplicate_main),
    ?assertEqual("simple_example.erl:56", Sink),
    ?assertEqual(["simple_example.erl:53"], abstract_machine_util:get_sources(History)).
