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

-module(capture_out).
-export([capture_output/1]).
-include_lib("kernel/include/logger.hrl").

%% capture_output's help function
-spec tracer([string()]) -> ok.
tracer(Trace) when is_list(Trace) ->
    receive
        {io_request, From, ReplyAs, {put_chars, _Encoding, Module, Function, Args}} ->
            Text = erlang:apply(Module, Function, Args),
            From ! {io_reply, ReplyAs, ok},
            tracer([Text | Trace]);
        {'$gen_call', From, get} ->
            gen:reply(From, Trace);
        Other ->
            ?LOG_WARNING("Unexpected I/O request: ~p", [Other]),
            tracer(Trace)
    end.
-spec capture_output(fun()) -> {term(), [string()]}.
capture_output(Fun) ->
    OldLeader = group_leader(),
    Tracer = spawn_link(fun() -> tracer([]) end),
    true = group_leader(Tracer, self()),

    Return =
        try
            Fun()
        after
            group_leader(OldLeader, self())
        end,
    IOCaptured = lists:flatten(lists:reverse(gen_server:call(Tracer, get))),
    {Return, IOCaptured}.
