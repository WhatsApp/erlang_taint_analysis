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
-module(modeled_taint_lists).
-compile(warn_missing_spec_all).

% This module implements the nifs for the lists module
-export([
    keyfind/3,
    keysearch/3,
    member/2,
    reverse/1,
    reverse/2
]).

%
-spec member(T, [T]) -> boolean().
member(_X, []) ->
    false;
member(X, [X | _]) ->
    true;
member(X, [_ | Tail]) ->
    member(X, Tail).

-spec reverse([T]) -> [T].
reverse(List) ->
    reverse(List, []).
-spec reverse([T], [T]) -> [T].
reverse([], Acc) ->
    Acc;
reverse([H | T], Acc) ->
    reverse(T, [H | Acc]).

-spec keyfind(term(), integer(), [tuple()]) -> tuple() | false.
keyfind(_, _, []) ->
    false;
keyfind(Key, N, [Head | Tail]) ->
    case element(N, Head) of
        Key -> Head;
        _ -> keyfind(Key, N, Tail)
    end.

-spec keysearch(term(), integer(), [tuple()]) -> {value, tuple()} | false.
keysearch(Key, N, List) ->
    case keyfind(Key, N, List) of
        false -> false;
        Val -> {value, Val}
    end.
