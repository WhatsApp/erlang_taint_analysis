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
%%%     Tests for finer taint analysis focusing on multi processing abilities
%%%
%%%     The tests are similar to finer_taint_SUITE, except that they use
%%%     parallel_finer_taint instead pf ct_finer_taint
%%%
%%% -------------------------------------------------------------------
-module(parallel_taint_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% Test server callbacks
-export([
    suite/0,
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    two_pids/1,
    spawn_taint_transfer/1,
    spawn_taint_transfer_via_capture/1,
    test_gen_server/1,
    test_gen_server_init/1,
    scatter_gather/1,
    edge_annotations_msg/1,
    hibernate/1,
    not_instrumented_send/1
]).

suite() ->
    [{appatic, #{enable_autoclean => true}}].

groups() ->
    [
        {basic, [], [
            two_pids,
            spawn_taint_transfer,
            spawn_taint_transfer_via_capture,
            test_gen_server,
            test_gen_server_init,
            scatter_gather,
            edge_annotations_msg,
            hibernate,
            not_instrumented_send
        ]}
    ].

all() ->
    [{group, basic}].

init_per_suite(Config) ->
    ok = logger:add_handler_filter(default, no_progress, {fun logger_filters:progress/2, stop}),
    {module, modeled_erlang} = finer_taint_compiler:instrument_loaded_module(modeled_erlang, [
        {finer_taint_module, parallel_finer_taint}
    ]),
    {module, modeled_gen_server} = finer_taint_compiler:instrument_loaded_module(gen_server, [
        {finer_taint_module, parallel_finer_taint}
    ]),
    {module, modeled_gen} = finer_taint_compiler:instrument_loaded_module(gen, [
        {finer_taint_module, parallel_finer_taint}
    ]),
    {module, modeled_lists} = finer_taint_compiler:instrument_loaded_module(lists, [
        {finer_taint_module, parallel_finer_taint}
    ]),
    {module, modeled_proc_lib} = finer_taint_compiler:instrument_loaded_module(proc_lib, [
        {finer_taint_module, parallel_finer_taint}
    ]),
    Config.
end_per_suite(_Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    DataDir = ?config(priv_dir, Config),
    FileName = filename:join(DataDir, atom_to_list(TestCase) ++ "_analaysis_instr"),
    application:set_env(taint_server, instructions_stream_prefix, FileName),
    UpdatedConfig = wa_test_init:ensure_all_started(Config, taint_server),
    [{analysis_instr, FileName} | UpdatedConfig].

end_per_testcase(_TestCase, _Config) ->
    ok.

compile(Modules, Config) ->
    DataDir = ?config(data_dir, Config),
    CompileMod = fun(Mod) ->
        ModFilename = [_ | _] = unicode:characters_to_list(io_lib:format("~p.erl", [Mod])),
        ModPath = filename:join([DataDir, ModFilename]),
        {ok, Mod, Binary = <<_/binary>>} = compile:file(ModPath, [debug_info, binary]),
        {ok, {Mod, [{abstract_code, {_, Forms}} | _]}} = beam_lib:chunks(Binary, [abstract_code, compile_info]),
        io:format("~p~n", [Forms]),
        {Mod, Forms}
    end,
    lists:map(CompileMod, Modules) ++ Config.

replace_undeterministic(Binary) ->
    Opts = [{return, binary}, global],
    Binary0 = re:replace(
        Binary, "{receive_trace,{\"#Ref<[\.0-9]+>\",(\"[^\"]+\")}}", <<"{receive_trace,{==msg_id==,\\1}}">>, Opts
    ),
    Binary1 = re:replace(Binary0, "{send,{\"#Ref<[\.0-9]+>\",(\"[^\"]+\")}}", <<"{send,{==msg_id==,\\1}}">>, Opts),
    Binary2 = re:replace(
        Binary1, "\"(gen_server|gen|proc_lib|lists|map).erl:[0-9]+\"", <<"\"\\1.erl:==line==\"">>, Opts
    ),
    Binary3 = re:replace(
        Binary2, "{(store|get),{\"[^\"]+\",", <<"{\\1,{\"==VarName==\",">>, Opts
    ),
    Binary3.

compile_and_run_function(Config, Module, Func) ->
    [{_, Forms} | _] = compile([Module], Config),
    io:format("~p Forms: ~p~n", [Module, Forms]),
    InstrumentedForms = finer_taint_compiler:instrument_with_sinks(Forms, [{finer_taint_module, parallel_finer_taint}]),
    io:format("~p: ~n~s~n", [Module, erl_prettypr:format(erl_syntax:form_list(InstrumentedForms))]),
    {ok, Module, Binary} = compile:forms(InstrumentedForms),
    {module, Module} = code:load_binary(Module, "/fake/path/file.erl", Binary),
    put(taint_pid, erlang:crc32(io_lib:format("~p~p", [Module, Func]))),
    Module:Func(),
    application:stop(taint_server),
    FilenamePrefix = proplists:get_value(analysis_instr, Config),
    AnalysisInstrFiles = filelib:wildcard(FilenamePrefix ++ "-*"),
    DataDir = ?config(data_dir, Config),
    Verbosity = ct:get_verbosity(default),
    {Status, RepoRoot} = file:read_file("/tmp/erlang_taint_root"),
    GeneratedHeader = <<"{push,{\"@ge", "nerated\"}}.\n{pop,{}}.\n">>,
    HeaderSize = byte_size(GeneratedHeader),
    case Module of
        % In the scatter_gather case we do not have fixtures because it
        % spawns more processes with the spawned process we have no way of
        % controling the taint pids of the spawning process and its not worth
        % the effort to implement that just for testing
        scatter_gather ->
            ok;
        _ ->
            lists:foreach(
                fun(AnalysisInstrFile) ->
                    Basename = filename:basename(AnalysisInstrFile),
                    io:format("Comparing file ~s ~p~n", [Basename, Verbosity]),
                    FixtureFilename = filename:join(DataDir, Basename),
                    {ok, Actual} = file:read_file(AnalysisInstrFile),
                    Fixture = file:read_file(FixtureFilename),
                    %% Run with: echo -n `pwd` > /tmp/erlang_taint_root ;  buck2 test -c 'erlang.erlang_test_ct_opts=[{verbosity,101}]' <test_target>
                    %% to update the local fixture
                    if
                        Verbosity =:= 101 andalso Status =:= ok ->
                            ok = file:write_file(
                                filename:join([RepoRoot, "finer_taint/test/parallel_taint_SUITE_data", Basename]),
                                <<GeneratedHeader/binary, Actual/binary>>
                            );
                        true ->
                            ok
                    end,
                    case {Module, Verbosity =/= 101} of
                        % In the case of gen_server the fixtures rely on specific OTP version
                        % and don't work across OTP versions. So we disable the gen_server tests
                        % unless vebosity is set for local dev.
                        {example_gen_server, true} ->
                            ok;
                        _ ->
                            {ok, <<GeneratedHeader:HeaderSize/binary, ExpectedInstr/binary>>} = Fixture,
                            finer_taint_SUITE:assert_instruction_stream_equal(
                                replace_undeterministic(ExpectedInstr), replace_undeterministic(Actual)
                            )
                    end
                end,
                AnalysisInstrFiles
            )
    end,

    application:start(taint_server),
    % Open Source buck2 test can't handle the amount of stdout tracing spews out
    % parallel_abstract_machine:run_tracing(AnalysisInstrFiles).
    parallel_abstract_machine:run(AnalysisInstrFiles).

%%--------------------------------------------------------------------
%% TEST CASES

two_pids(Config) ->
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = compile_and_run_function(
        Config, two_pids, two_pids_main
    ),
    ?assertEqual(
        [
            {step, "two_pids.erl:36"},
            {step, "two_pids.erl:34"},
            {step, "two_pids.erl:32"},
            {step, "two_pids.erl:28"},
            {message_pass, "two_pids.erl:43"},
            {step, "two_pids.erl:43"},
            {step, "two_pids.erl:43"},
            {source, "two_pids.erl:40"}
        ],
        FirstHistory
    ),
    ?assertEqual("two_pids.erl:51", SecondSink),
    ?assertEqual(["two_pids.erl:40"], abstract_machine_util:get_sources(SecondHistory)),
    ?assertEqual("two_pids.erl:36", FirstSink),
    ?assertEqual(["two_pids.erl:40"], abstract_machine_util:get_sources(FirstHistory)).

edge_annotations_msg(Config) ->
    [{leak, _FirstSink, FirstHistory}] = compile_and_run_function(
        Config, edge_annot, edge_annotations_main
    ),
    ?assertEqual(
        [
            {step, "edge_annot.erl:26"},
            {step, "edge_annot.erl:25"},
            {call_site, {edge_annot, from_tuple, 1}, "edge_annot.erl:41"},
            {step, "edge_annot.erl:41"},
            {step, "edge_annot.erl:41"},
            {return_site, {edge_annot, to_tuple, 1}, "edge_annot.erl:40"},
            {return_site, {edge_annot, from_tuple, 1}, "edge_annot.erl:21"},
            {step, "edge_annot.erl:28"},
            {step, "edge_annot.erl:27"},
            {call_site, {edge_annot, from_tuple, 1}, "edge_annot.erl:21"},
            {step, "edge_annot.erl:21"},
            {step, "edge_annot.erl:21"},
            {call_site, {edge_annot, to_tuple, 1}, "edge_annot.erl:40"},
            {step, "edge_annot.erl:40"},
            {step, "edge_annot.erl:39"},
            {step, "edge_annot.erl:39"},
            {message_pass, "edge_annot.erl:24"},
            {step, "edge_annot.erl:24"},
            {step, "edge_annot.erl:23"},
            {call_site, {edge_annot, from_tuple, 1}, "edge_annot.erl:37"},
            {step, "edge_annot.erl:37"},
            {step, "edge_annot.erl:37"},
            {return_site, {edge_annot, to_tuple, 1}, "edge_annot.erl:36"},
            {return_site, {edge_annot, from_tuple, 1}, "edge_annot.erl:21"},
            {step, "edge_annot.erl:28"},
            {step, "edge_annot.erl:27"},
            {call_site, {edge_annot, from_tuple, 1}, "edge_annot.erl:21"},
            {step, "edge_annot.erl:21"},
            {step, "edge_annot.erl:21"},
            {call_site, {edge_annot, to_tuple, 1}, "edge_annot.erl:36"},
            {step, "edge_annot.erl:36"},
            {step, "edge_annot.erl:35"},
            {step, "edge_annot.erl:35"},
            {message_pass, "edge_annot.erl:24"},
            {step, "edge_annot.erl:24"},
            {step, "edge_annot.erl:23"},
            {call_site, {edge_annot, from_tuple, 1}, "edge_annot.erl:33"},
            {step, "edge_annot.erl:33"},
            {step, "edge_annot.erl:33"},
            {return_site, {edge_annot, to_tuple, 1}, "edge_annot.erl:32"},
            {return_site, {edge_annot, from_tuple, 1}, "edge_annot.erl:21"},
            {step, "edge_annot.erl:28"},
            {step, "edge_annot.erl:27"},
            {call_site, {edge_annot, from_tuple, 1}, "edge_annot.erl:21"},
            {step, "edge_annot.erl:21"},
            {step, "edge_annot.erl:21"},
            {call_site, {edge_annot, to_tuple, 1}, "edge_annot.erl:32"},
            {step, "edge_annot.erl:32"},
            {source, "edge_annot.erl:31"}
        ],
        FirstHistory
    ).

scatter_gather(Config) ->
    [Leak2, Leak1] = compile_and_run_function(Config, scatter_gather, scatter_gather_main),
    {leak, Sink, History} = Leak1,
    ?assertEqual("scatter_gather.erl:43", Sink),
    ?assertEqual(["scatter_gather.erl:23"], abstract_machine_util:get_sources(History)),
    {leak, SecondSink, SecondHistory} = Leak2,
    ?assertEqual("scatter_gather.erl:45", SecondSink),
    ?assertEqual(["scatter_gather.erl:30"], abstract_machine_util:get_sources(SecondHistory)).

spawn_taint_transfer(Config) ->
    [Leak1, Leak2] = compile_and_run_function(Config, taint_spawn, spawn_info_transfer_main),
    {leak, Sink, History} = Leak1,
    ?assertEqual("taint_spawn.erl:28", Sink),
    ?assertEqual(["taint_spawn.erl:37"], abstract_machine_util:get_sources(History)),
    {leak, SecondSink, SecondHistory} = Leak2,
    ?assertEqual("taint_spawn.erl:23", SecondSink),
    ?assertEqual(["taint_spawn.erl:37"], abstract_machine_util:get_sources(SecondHistory)).

spawn_taint_transfer_via_capture(Config) ->
    [Leak1] = compile_and_run_function(Config, taint_spawn, spawn_info_transfer_via_capture_main),
    {leak, Sink, History} = Leak1,
    ?assertEqual("taint_spawn.erl:54", Sink),
    ?assertEqual(["taint_spawn.erl:50"], abstract_machine_util:get_sources(History)).

test_gen_server_init(Config) ->
    [{leak, Sink, History}] = compile_and_run_function(Config, example_gen_server, gen_server_init_test_main),
    ?assertEqual("example_gen_server.erl:76", Sink),
    ?assertEqual(["example_gen_server.erl:49"], abstract_machine_util:get_sources(History)).

test_gen_server(Config) ->
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = compile_and_run_function(
        Config, example_gen_server, gen_server_test_main
    ),
    ?assertEqual("example_gen_server.erl:41", FirstSink),
    ?assertEqual(["example_gen_server.erl:40"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("example_gen_server.erl:44", SecondSink),
    ?assertEqual(["example_gen_server.erl:40"], abstract_machine_util:get_sources(SecondHistory)),

    % Lineage tests
    FilenamePrefix = proplists:get_value(analysis_instr, Config),
    AnalysisInstrFiles = filelib:wildcard(FilenamePrefix ++ "-*"),
    % Reset the message passing table
    application:stop(taint_server),
    application:start(taint_server),
    ReducedLeaks = parallel_abstract_machine:run_lineage(AnalysisInstrFiles),
    ReducedLineage = abstract_machine_util:get_arg_lineage(ReducedLeaks, human_readable),
    application:stop(taint_server),
    application:start(taint_server),
    FullLeaks = parallel_abstract_machine:run_lineage_with_line_history(AnalysisInstrFiles),
    FullLineage = abstract_machine_util:get_arg_lineage(FullLeaks, human_readable),
    ?assertEqual(FullLineage, ReducedLineage),
    Fixture = filename:join(?config(data_dir, Config), "lineage_example_gen_server"),
    {ok, <<"@gen", "erated\n", _FixtureLineage/binary>>} = file:read_file(Fixture),
    %Note: this assert doesn't work accross OTP versions
    %For now let's just check there is some lineage
    %?assertEqual(binary_to_list(FixtureLineage), Lineage),
    ?assert(length(ReducedLineage) > 100),
    application:stop(taint_server),

    % Escript test
    EscriptOutputFile = filename:join(?config(data_dir, Config), "escript_output_file.lineage"),
    run_finer_taint_escript:main(
        ["run-lineage"] ++ AnalysisInstrFiles ++ ["-arg-lineage-hr", "-to-file", EscriptOutputFile]
    ),
    {ok, EscriptLineage} = file:read_file(EscriptOutputFile),
    ?assertEqual(ReducedLineage, binary_to_list(EscriptLineage)).

hibernate(Config) ->
    [{leak, SecondSink, SecondHistory}, {leak, FirstSink, FirstHistory}] = compile_and_run_function(
        Config, two_pids, hibernate_main
    ),
    ?assertEqual("two_pids.erl:67", FirstSink),
    ?assertEqual(["two_pids.erl:78"], abstract_machine_util:get_sources(FirstHistory)),
    ?assertEqual("two_pids.erl:69", SecondSink),
    ?assertEqual(["two_pids.erl:75"], abstract_machine_util:get_sources(SecondHistory)).

% Ideally this case should detect the leak, but because
% the send is not instrumented, we currently don't detect it
not_instrumented_send(Config) ->
    [] = compile_and_run_function(Config, two_pids, not_instrumented_send_main).
