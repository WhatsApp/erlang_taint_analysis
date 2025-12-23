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
%%%     Tests taint_gatherer
%%% -------------------------------------------------------------------
-module(taint_gatherer_SUITE).

% elp:ignore WA003 (better_assertions) - Open Source
-include_lib("stdlib/include/assert.hrl").

%% Test server callbacks
-export([
    all/0,
    groups/0
]).

%% Test cases
-export([
    can_gather_leaks/1,
    waits_for_leaks/1
]).

groups() ->
    [
        {basic, [sequence], [
            can_gather_leaks,
            waits_for_leaks
        ]}
    ].

all() ->
    [{group, basic}].

%%--------------------------------------------------------------------
%% TEST CASES

can_gather_leaks(_Config) ->
    {ok, Pid} = taint_gatherer:start_link(),
    taint_gatherer:add_leaks(Pid, #{{leak, "loc", []} => ok}),
    taint_gatherer:add_leaks(Pid, #{{leak, "loc1", []} => ok}),
    % All pids have added leaks, should return immediately.
    Leaks = taint_gatherer:get_gathered_leaks(Pid, 0, [self(), self()]),
    gen_server:stop(Pid),
    ?assertEqual(#{{leak, "loc", []} => ok, {leak, "loc1", []} => ok}, Leaks).

waits_for_leaks(_Config) ->
    Parent = self(),
    GatherLeakTimeoutMs = 1000,
    {ok, Pid} = taint_gatherer:start_link(),
    spawn(fun() ->
        Parent ! started,
        Leaks = taint_gatherer:get_gathered_leaks(Pid, GatherLeakTimeoutMs, [Parent]),
        Parent ! {got_leaks, Leaks}
    end),
    receive
        started -> ok
    end,
    taint_gatherer:add_leaks(Pid, #{{leak, "loc", []} => ok}),
    RecLeaks =
        receive
            {got_leaks, L} -> L
        after 3 * GatherLeakTimeoutMs ->
            #{rec_leak_timeout => ok}
        end,
    gen_server:stop(Pid),
    ?assertEqual(#{{leak, "loc", []} => ok}, RecLeaks).
