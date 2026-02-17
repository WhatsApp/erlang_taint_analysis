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

%% % @format
%% Implements some sort of message queue for passing taint messages.
%% The main idea is to block the get() operation until the message becomes available
-module(taint_message_passer).
-compile(warn_missing_spec_all).

-export([init/0, uninit/0, blocking_get/1, set/2, blocking_get/2]).

-spec init() -> ok.
init() ->
    %% taint_messages stores tuples:
    %% % MessageId has this taint value
    %%   {MessageId :: string(), taint_value(), nopid}
    %% % Tell pid() the message once it is set
    %% | {MessageId :: string(), nomsg, pid()}
    ets:new(taint_messages, [set, public, named_table]),
    ok.

-spec uninit() -> ok.
uninit() ->
    ets:delete(taint_messages),
    ok.

-spec blocking_get(string()) -> taint_abstract_machine:taint_value().
blocking_get(MessageId) ->
    blocking_get(MessageId, 12000).

-spec blocking_get(string(), erlang:timeout()) -> taint_abstract_machine:taint_value().
blocking_get(MessageId, Timeout) ->
    case ets:insert_new(taint_messages, {MessageId, nomsg, self()}) of
        false ->
            %Note: we could delete the ETS record at this point
            [{MessageId, Val, nopid}] = ets:lookup(taint_messages, MessageId),
            io:format("deliver msg ~p~n", [MessageId]),
            Val;
        true ->
            receive
                {got_key, MessageId, Message} ->
                    io:format("deliver msg ~p~n", [MessageId]),
                    Message
            after Timeout ->
                io:format("Skipping MessageId ~p~n", [MessageId]),
                {notaint, []}
            end
    end.

-spec set(string(), taint_abstract_machine:taint_value()) -> ok.
set(MessageId, Message) ->
    case ets:insert_new(taint_messages, {MessageId, Message, nopid}) of
        true ->
            ok;
        false ->
            [{MessageId, nomsg, Pid}] = ets:lookup(taint_messages, MessageId),
            Pid ! {got_key, MessageId, Message}
    end,
    ok.
