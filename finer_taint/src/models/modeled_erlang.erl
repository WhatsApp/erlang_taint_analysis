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
-module(modeled_erlang).
-compile(warn_missing_spec_all).
-wacov(ignore).

-export([mapply/3, mapply/2, is_map_key/2, elemnt/2, mput/2, mget/1, real_put/2, mhibernate/3]).

% This module contains some models for functions in the erlang
% module: https://www.erlang.org/doc/man/erlang.html
% There is a lot of functions in the erlang module and
% not all of them need a model. Models should be added on-demand
% as needed.
%
% Examples of functions not needing a model:
%   * spawn family is handled by the instrumentation directly in finer_taint.erl
%   * is_* functions likely don't need a model, because they return boolean which isn't tainted
%
% binary_to_list/iolist_to_* and similar might need a model
% if we want to accurantely track taint through these datastructures
%

-spec mapply(atom(), atom(), list()) -> term().
mapply(M, F, []) ->
    M:F();
mapply(M, F, [Arg1]) ->
    M:F(Arg1);
mapply(M, F, [Arg1, Arg2]) ->
    M:F(Arg1, Arg2);
mapply(M, F, [Arg1, Arg2, Arg3]) ->
    M:F(Arg1, Arg2, Arg3);
mapply(M, F, [Arg1, Arg2, Arg3, Arg4]) ->
    M:F(Arg1, Arg2, Arg3, Arg4);
mapply(M, F, [Arg1, Arg2, Arg3, Arg4, Arg5]) ->
    M:F(Arg1, Arg2, Arg3, Arg4, Arg5);
mapply(M, F, [Arg1, Arg2, Arg3, Arg4, Arg5, Arg6]) ->
    M:F(Arg1, Arg2, Arg3, Arg4, Arg5, Arg6);
mapply(M, F, [Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7]) ->
    M:F(Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7);
mapply(M, F, [Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7, Arg8]) ->
    M:F(Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7, Arg8).

-spec is_map_key(Key, #{Key => term()}) -> boolean().
is_map_key(Key, Map) ->
    maps:is_key(Key, Map).

-spec elemnt(integer(), tuple()) -> term().
elemnt(1, {A1}) ->
    A1;
elemnt(1, {A1, _A2}) ->
    A1;
elemnt(1, {A1, _A2, _A3}) ->
    A1;
elemnt(1, {A1, _A2, _A3, _A4}) ->
    A1;
elemnt(1, {A1, _A2, _A3, _A4, _A5}) ->
    A1;
elemnt(1, {A1, _A2, _A3, _A4, _A5, _A6}) ->
    A1;
elemnt(1, {A1, _A2, _A3, _A4, _A5, _A6, _A7}) ->
    A1;
elemnt(1, {A1, _A2, _A3, _A4, _A5, _A6, _A7, _A8}) ->
    A1;
elemnt(1, {A1, _A2, _A3, _A4, _A5, _A6, _A7, _A8, _A9}) ->
    A1;
elemnt(2, {_A1, A2}) ->
    A2;
elemnt(2, {_A1, A2, _A3}) ->
    A2;
elemnt(2, {_A1, A2, _A3, _A4}) ->
    A2;
elemnt(2, {_A1, A2, _A3, _A4, _A5}) ->
    A2;
elemnt(2, {_A1, A2, _A3, _A4, _A5, _A6}) ->
    A2;
elemnt(2, {_A1, A2, _A3, _A4, _A5, _A6, _A7}) ->
    A2;
elemnt(2, {_A1, A2, _A3, _A4, _A5, _A6, _A7, _A8}) ->
    A2;
elemnt(2, {_A1, A2, _A3, _A4, _A5, _A6, _A7, _A8, _A9}) ->
    A2;
elemnt(3, {_A1, _A2, A3}) ->
    A3;
elemnt(3, {_A1, _A2, A3, _A4}) ->
    A3;
elemnt(3, {_A1, _A2, A3, _A4, _A5}) ->
    A3;
elemnt(3, {_A1, _A2, A3, _A4, _A5, _A6}) ->
    A3;
elemnt(3, {_A1, _A2, A3, _A4, _A5, _A6, _A7}) ->
    A3;
elemnt(3, {_A1, _A2, A3, _A4, _A5, _A6, _A7, _A8}) ->
    A3;
elemnt(3, {_A1, _A2, A3, _A4, _A5, _A6, _A7, _A8, _A9}) ->
    A3;
elemnt(Index, Tuple) ->
    lists:nth(Index, tuple_to_list(Tuple)).

-spec mapply(fun(), list()) -> term().
mapply(F, []) ->
    F();
mapply(F, [Arg1]) ->
    F(Arg1);
mapply(F, [Arg1, Arg2]) ->
    F(Arg1, Arg2);
mapply(F, [Arg1, Arg2, Arg3]) ->
    F(Arg1, Arg2, Arg3);
mapply(F, [Arg1, Arg2, Arg3, Arg4]) ->
    F(Arg1, Arg2, Arg3, Arg4);
mapply(F, [Arg1, Arg2, Arg3, Arg4, Arg5]) ->
    F(Arg1, Arg2, Arg3, Arg4, Arg5);
mapply(F, [Arg1, Arg2, Arg3, Arg4, Arg5, Arg6]) ->
    F(Arg1, Arg2, Arg3, Arg4, Arg5, Arg6);
mapply(F, [Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7]) ->
    F(Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7);
mapply(F, [Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7, Arg8]) ->
    F(Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7, Arg8).

% erlang:get/1 and erlang:put/2 are not rewritten in modeled erlang
% process_dict/0,1 is NOT instrumented by finer taint instrumentation
% instead it is modeled to set or return a process dict taint value
% inside the taint_abstract_machine. We still give an implementation
% here so that it works in real runs.
-spec process_dict() -> map().
process_dict() ->
    case erlang:get(process_dict) of
        undefined -> #{};
        Dict -> Dict
    end.

-spec process_dict(map()) -> ok.
process_dict(Pd) ->
    erlang:put(process_dict, Pd).

% This is not instrumented so that parralel_taint_SUITE can put taint pids
% in process dictonary
-spec real_put(term(), term()) -> undefined | term().
real_put(Key, Value) ->
    erlang:put(Key, Value).

-spec mput(term(), term()) -> undefined | map().
mput(Key, Value) ->
    Pd = process_dict(),
    ReturnValue = maps:get(Key, Pd, undefined),
    NewDict = Pd#{Key => Value},
    process_dict(NewDict),
    ReturnValue.

-spec mget(term()) -> undefined | term().
mget(Key) ->
    Pd = process_dict(),
    maps:get(Key, Pd, undefined).

-spec mhibernate(module(), atom(), list()) -> no_return().
mhibernate(M, F, Args) ->
    erlang:hibernate(?MODULE, mapply, [M, F, Args]).
