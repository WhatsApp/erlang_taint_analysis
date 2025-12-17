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
%%% @doc
%%%     Tests abstract_machine_proclet
%%% @end
%%% -------------------------------------------------------------------
-module(abstract_machine_proclet_SUITE).

-include_lib("assert/include/assert.hrl").

%% Test server callbacks
-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    groups/0
]).

%% Test cases
-export([
    message_pass_between_proclets/1,
    runs_some_instructions/1
]).

groups() ->
    [
        {basic, [sequence], [
            message_pass_between_proclets,
            runs_some_instructions
        ]}
    ].

all() ->
    [{group, basic}].

init_per_suite(Config) ->
    Config.
end_per_suite(_Config) ->
    ok.
%%--------------------------------------------------------------------
%% TEST CASES

runs_some_instructions(_Config) ->
    {ok, _SupPid} = abstract_machine_proclet_sup:start_link(#{}),
    {ok, GathererPid} = taint_gatherer:start_link(),
    ProcletPid = abstract_machine_proclet_sup:new_proclet(GathererPid),
    abstract_machine_proclet:execute_instruction(ProcletPid, {push, {"some_source.erl:12"}}),
    abstract_machine_proclet:execute_instruction(ProcletPid, {sink, {"some_sink.erl:12"}}),
    abstract_machine_proclet:stop(ProcletPid),
    Leaks = taint_gatherer:get_gathered_leaks(GathererPid, 1000, [ProcletPid]),
    gen_server:stop(GathererPid),
    ?assertEqual(#{{leak, "some_sink.erl:12", [{source, "some_source.erl:12"}]} => ok}, Leaks).

done() ->
    receive
        done -> ok
    end.
message_pass_between_proclets(_Config) ->
    taint_message_passer:init(),
    {ok, SupPid} = online_finer_taint_sup:start_link(),
    ?assertNotEqual(whereis(taint_gatherer), undefined),
    ?assertNotEqual(whereis(abstract_machine_proclet_sup), undefined),
    Parent = self(),
    spawn(fun() ->
        online_finer_taint:write_instruction({push, {notaint}}),
        online_finer_taint:write_instruction({push, {"src:1"}}),
        online_finer_taint:write_instruction({send, {"msg-id-42", "src:1"}}),
        Parent ! done
    end),
    spawn(fun() ->
        online_finer_taint:write_instruction({receive_trace, {"msg-id-42", "other_proc:1"}}),
        online_finer_taint:write_instruction({sink, {"sink.erl1"}}),
        Parent ! done
    end),
    done(),
    done(),
    abstract_machine_proclet_sup:stop_all_proclets(),
    Leaks = taint_gatherer:get_gathered_leaks(taint_gatherer, 1000, [notapid]),
    ?assertEqual(
        #{
            {leak, "sink.erl1", [
                {step, "other_proc:1"},
                {message_pass, "src:1"},
                {source, "src:1"}
            ]} =>
                ok
        },
        Leaks
    ),
    unlink(SupPid),
    Ref = monitor(process, SupPid),
    exit(SupPid, shutdown),
    receive
        {'DOWN', Ref, process, SupPid, shutdown} ->
            ok
    after 1000 ->
        ?assert(false, "Shouldn't timeout")
    end.
