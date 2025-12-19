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
%%%     Tests for taint message_passer
%%% -------------------------------------------------------------------
-module(message_passer_SUITE).

-include_lib("stdlib/include/assert.hrl").

%% Test server callbacks
-export([
    all/0,
    suite/0,
    init_per_testcase/2,
    init_per_suite/1,
    end_per_suite/1,
    end_per_testcase/2,
    groups/0
]).

%% Test cases
-export([
    first_set_then_get/1,
    get_twice_and_crash/1,
    message_after_timeout/1,
    first_get_then_set/1
]).

suite() ->
    % The tests in this suite shouldn't take a long time,
    % but if there is a bug, they could block forever, so
    % we set a generous but short timeout
    [{timetrap, {seconds, 10}}].

groups() ->
    [
        {basic, [sequence], [
            first_set_then_get,
            first_get_then_set,
            message_after_timeout,
            get_twice_and_crash
        ]}
    ].

all() ->
    [{group, basic}].

init_per_testcase(_TestCase, Config) ->
    taint_message_passer:init(),
    Config.

end_per_testcase(_TestCase, _Config) ->
    taint_message_passer:uninit(),
    ok.

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%%--------------------------------------------------------------------
%% TEST CASES

first_set_then_get(_Config) ->
    Msg1 = {taint, [{step, "msg1"}]},
    MsgId = ref_to_list(make_ref()),
    taint_message_passer:set(MsgId, Msg1),
    ?assertEqual(Msg1, taint_message_passer:blocking_get(MsgId)).

first_get_then_set(_Config) ->
    Msg2 = {taint, [{step, "msg2"}]},
    MsgId = ref_to_list(make_ref()),
    ReplyTo = self(),
    spawn_link(fun() ->
        ReplyTo ! started,
        Msg = taint_message_passer:blocking_get(MsgId),
        ReplyTo ! {got_msg, Msg}
    end),
    receive
        started -> ok
    end,
    taint_message_passer:set(MsgId, Msg2),
    Message =
        receive
            {got_msg, Msg} -> Msg
        after 5000 -> timeout
        end,
    ?assertEqual(Msg2, Message).

message_after_timeout(_Config) ->
    MsgId = ref_to_list(make_ref()),
    MsgId1 = ref_to_list(make_ref()),
    ReplyTo = self(),
    spawn_link(fun() ->
        % This needs to timeout, so we set a short timeout
        {notaint, []} = taint_message_passer:blocking_get(MsgId, 10),
        ReplyTo ! started,
        % This is expected to receive a message in this test, so
        % infinite timeout
        GotMsg = taint_message_passer:blocking_get(MsgId1, infinity),
        ReplyTo ! {got_msg, GotMsg}
    end),
    receive
        started -> ok
    end,

    % This message timed-out so we shouldn't receive it
    Msg = {taint, [{step, "msg"}]},
    taint_message_passer:set(MsgId, Msg),
    % This is the message we want
    Msg2 = {taint, [{step, "msg2"}]},
    taint_message_passer:set(MsgId1, Msg2),
    Message =
        receive
            {got_msg, RecMsg} -> RecMsg
        after 4000 -> timeout
        end,
    ?assertEqual(Msg2, Message).

% Getting the same message twice shouldn't
% happen so we expect to crash if it does
get_twice_and_crash(_Config) ->
    MsgId = ref_to_list(make_ref()),
    ReplyTo = self(),
    spawn_link(fun() ->
        ReplyTo ! started,
        taint_message_passer:blocking_get(MsgId),
        ?assertException(error, {badmatch, _}, taint_message_passer:blocking_get(MsgId)),
        ReplyTo ! ok
    end),
    receive
        started -> ok
    end,
    Msg2 = {taint, [{step, "msg2"}]},
    taint_message_passer:set(MsgId, Msg2),
    receive
        ok -> ok
    end.
