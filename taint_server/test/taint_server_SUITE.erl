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
%%%     Tests taint_writer
%%% -------------------------------------------------------------------
-module(taint_server_SUITE).

-include_lib("common_test/include/ct.hrl").
% elp:ignore WA003 (better_assertions) - Open Source
-include_lib("stdlib/include/assert.hrl").

%% Test server callbacks
-export([
    suite/0,
    all/0,
    groups/0
]).

%% Test cases
-export([
    can_write_parallel_instructions_to_file/1,
    can_roundtrip_instruction_with_high_codepoints/1
]).

suite() ->
    [{procmop, #{cleanup_procs => true}}].

groups() ->
    [
        {basic, [
            can_write_parallel_instructions_to_file,
            can_roundtrip_instruction_with_high_codepoints
        ]}
    ].

all() ->
    [{group, basic}].

%%--------------------------------------------------------------------
%% TEST CASES

can_write_parallel_instructions_to_file(Config) ->
    PrivDir = proplists:get_value(priv_dir, Config),
    AbstrInstructionPrefix = filename:join(PrivDir, "abstr-instr-tpid"),
    application:set_env(taint_server, instructions_stream_prefix, AbstrInstructionPrefix),
    application:start(taint_server),
    Parent = self(),
    abstract_machine_server:write_instruction(123, {pop, {}}),
    abstract_machine_server:write_instruction(42, {duplicate, {}}),
    spawn(fun() ->
        abstract_machine_server:write_instruction(43, {pop, {}}),
        Parent ! done
    end),
    done(),
    application:stop(taint_server),
    {ok, Data123} = file:read_file(AbstrInstructionPrefix ++ "-123"),
    ?assertEqual(<<"{pop,{}}.\n">>, Data123),
    {ok, Data43} = file:read_file(AbstrInstructionPrefix ++ "-43"),
    ?assertEqual(<<"{pop,{}}.\n">>, Data43),
    {ok, Data42} = file:read_file(AbstrInstructionPrefix ++ "-42"),
    ?assertEqual(<<"{duplicate,{}}.\n">>, Data42).

can_roundtrip_instruction_with_high_codepoints(Config) ->
    PrivDir = proplists:get_value(priv_dir, Config),
    AbstrInstructionPrefix = filename:join(PrivDir, "abstr-instr-high-cp"),
    application:set_env(taint_server, instructions_stream_prefix, AbstrInstructionPrefix),
    application:start(taint_server),
    %% A variable/source string carrying Latin-1 high code points (e.g. 233 = é). ~p renders
    %% it in string form, so without UTF-8-encoding the write, file:consult (which decodes
    %% UTF-8) rejects the raw byte 0xE9 as {file_io_server, invalid_unicode} on read-back.
    Instruction = {push, {"café-señor"}},
    Tid = 7,
    ok = abstract_machine_server:write_instruction_sync(Tid, Instruction),
    application:stop(taint_server),
    ?assertEqual(
        {ok, [Instruction]},
        file:consult(AbstrInstructionPrefix ++ "-" ++ integer_to_list(Tid))
    ).

done() ->
    receive
        done -> ok
    after 500 ->
        throw(timeout)
    end.
