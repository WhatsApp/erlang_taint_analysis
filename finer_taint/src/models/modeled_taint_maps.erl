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
-module(modeled_taint_maps).
-compile(warn_missing_spec_all).
-wacov(ignore).

% This module should be equivalent to maps module
% https://www.erlang.org/doc/man/maps.html .
% Its used to implement all the functions in maps
% that are otherwise implemented in C.

-export([
    get/2, get/3,
    fold/3,
    without/2,
    iterator/1,
    filter/2,
    new/0,
    filtermap/2,
    next/1,
    merge/2,
    take/2,
    keys/1,
    is_key/2,
    values/1,
    update_with/3,
    update_with/4,
    from_list/1,
    from_keys/2,
    groups_from_list/3,
    with/2,
    foreach/2,
    size/1,
    remove/2,
    to_list/1,
    put/3,
    map/2,
    find/2
]).

% Space to keep line numbers the same so we don't have to update tests, delete
% if adding a small amount of lines instead of updating test fixture
%
%
%
%
%
%
%
%
%
%
%
%
%
%

-spec get(term(), map(), term()) -> term().
get(Key, Map, Default) ->
    try get(Key, Map) of
        Val -> Val
    catch
        error:{badmatch, _} -> Default
    end.

-spec get(term(), map()) -> term().
get(Key, Map) ->
    #{Key := Value} = Map,
    Value.

-spec find(Key, #{Key => Value}) -> {ok, Value} | error.
find(Key, Map) ->
    fold(
        fun
            (K, V, error) when K =:= Key ->
                {ok, V};
            (_K, _V, {ok, Val}) ->
                {ok, Val};
            (_K, _V, error) ->
                error
        end,
        error,
        Map
    ).

-spec put(term(), term(), map()) -> term().
put(Key, Value, Map) ->
    Map#{Key => Value}.

-spec take(term(), map()) -> {term(), map()} | error.
take(Key, Map) ->
    case get(Key, Map, error) of
        error ->
            error;
        Value ->
            NewMap = fold(
                fun
                    (MatchedKey, _, Acc) when MatchedKey =:= Key -> Acc;
                    (NonMatchedKey, NonMatchedValue, Acc) -> Acc#{NonMatchedKey => NonMatchedValue}
                end,
                #{},
                Map
            ),
            {Value, NewMap}
    end.

-spec keys(map()) -> [term()].
keys(Map) ->
    fold(fun(Key, _, Acc) -> [Key | Acc] end, [], Map).

-spec values(#{term() => Values}) -> [Values].
values(Map) ->
    fold(fun(_, Value, Acc) -> [Value | Acc] end, [], Map).

-spec merge(map(), map()) -> map().
merge(Map1, Map2) ->
    fold(fun(Map1Key, Map1Val, Acc) -> Acc#{Map1Key => Map1Val} end, Map2, Map1).

-spec from_list(list()) -> map().
from_list(List) ->
    from_list_impl(List, #{}).

-spec from_list_impl(list(), map()) -> map().
from_list_impl([], Map) ->
    Map;
from_list_impl([{Key, Value} | Tail], Map) ->
    from_list_impl(Tail, Map#{Key => Value}).

-spec with([K], #{term() => V}) -> #{K => V}.
with(Ks, Map) ->
    with_impl(Ks, Map, #{}).

-spec with_impl(list(), map(), map()) -> map().
with_impl([], _Map, Acc) ->
    Acc;
with_impl([Key | Tail], Map, Acc) ->
    case modeled_taint_maps:get(Key, Map, notfound) of
        notfound -> with_impl(Tail, Map, Acc);
        Value -> with_impl(Tail, Map, Acc#{Key => Value})
    end.

-spec size(map()) -> integer().
size(Map) ->
    fold(fun(_, _, Cnt) -> Cnt + 1 end, 0, Map).

-spec remove(term(), map()) -> map().
remove(Key, Map) ->
    fold(
        fun(K, V, Acc) ->
            if
                K =:= Key -> Acc;
                true -> Acc#{K => V}
            end
        end,
        #{},
        Map
    ).

-spec to_list(#{Key => Value}) -> [{Key, Value}].
to_list(Map) ->
    fold(fun(K, V, Acc) -> [{K, V} | Acc] end, [], Map).

-spec map(fun((Key, Value1) -> Value2), #{Key => Value1}) -> #{Key => Value2}.
map(F, Map) ->
    fold(fun(Key, Value, Acc) -> Acc#{Key => F(Key, Value)} end, #{}, Map).

-spec fold(fun((Key, Value, Acc) -> Acc), Acc, #{Key => Value}) -> Acc.
fold(Fun, Acc, Map) when is_map(Map) ->
    Iter = maps:iterator(Map),
    fold_impl(Fun, Acc, Iter, Map).

-spec fold_impl(
    fun((Key, Value, Acc) -> Acc),
    Acc,
    maps:iterator(Key, Value),
    #{Key => Value}
) -> Acc.
fold_impl(Fun, Acc, MapIter, Map) ->
    % maps:next is special cased to never return tainted value
    case maps:next(MapIter) of
        none ->
            Acc;
        {IterKey, _Val, NextIter} ->
            %We need to lookup the key again in order to "catch" the taint
            #{IterKey := Value} = Map,
            fold_impl(Fun, Fun(IterKey, Value, Acc), NextIter, Map)
    end.

-spec is_key(Key, #{Key => term()}) -> boolean().
is_key(Key, Map) ->
    try modeled_taint_maps:get(Key, Map) of
        _ -> true
    catch
        error:{badmatch, _} -> false
    end.

-spec new() -> map().
new() ->
    #{}.

-spec update_with(term(), fun((term()) -> term()), map()) -> map().
update_with(Key, Fun, Map) ->
    Val = modeled_taint_maps:get(Key, Map),
    Map#{Key => Fun(Val)}.

-spec update_with(term(), fun((term()) -> term()), term(), map()) ->
    map().
update_with(Key, Fun, Init, Map) ->
    case modeled_taint_maps:get(Key, Map, notthere) of
        notthere -> Map#{Key => Init};
        Val -> Map#{Key => Fun(Val)}
    end.

-spec iterator(map()) -> {map(), maps:iterator()}.
iterator(Map) ->
    {Map, maps:iterator(Map)}.

-spec next({map(), maps:iterator()}) -> {term(), term(), {map(), maps:iterator()}} | none.
next({Map, Iterator}) ->
    case maps:next(Iterator) of
        none ->
            none;
        {RawKey, _Value, Iterator2} ->
            %We need to lookup the key again in order to "catch" the taint
            #{RawKey := Value} = Map,
            {RawKey, Value, {Map, Iterator2}}
    end.

-spec groups_from_list(fun((Elem) -> Key), fun((Elem) -> ValOut), [Elem]) -> #{Key => [ValOut]}.
groups_from_list(Fun, ValueFun, List) ->
    groups_from_list_impl(Fun, ValueFun, List, #{}).

-spec groups_from_list_impl(fun((Elem) -> Key), fun((Elem) -> ValOut), [Elem], #{Key => [ValOut]}) ->
    #{Key => [ValOut]}.
groups_from_list_impl(KeyFun, ValueFun, [H | T], Acc) ->
    Key = KeyFun(H),
    OldList = maps:get(Key, Acc, []),
    groups_from_list_impl(KeyFun, ValueFun, T, Acc#{Key => OldList ++ [ValueFun(H)]});
groups_from_list_impl(_, _, [], Acc) ->
    Acc.

-spec foreach(fun((term(), term()) -> term()), map()) -> ok.
foreach(Fun, Map) ->
    map(Fun, Map),
    ok.

-spec without(Ks, Map1) -> Map2 when
    Ks :: [K],
    Map1 :: map(),
    Map2 :: map(),
    K :: term().

without(Ks, M) when is_list(Ks), is_map(M) ->
    lists:foldl(fun remove/2, M, Ks).

% Relaxing the spec of filter so that it can be reused for filtermap
-spec filter(Pred, map()) -> map() when
    Pred :: fun((term(), term()) -> boolean() | {true, term()}).
filter(Pred, Map) ->
    fold(
        fun(K, V, Acc) ->
            case Pred(K, V) of
                false -> Acc;
                {true, NewVal} -> Acc#{K => NewVal};
                true -> Acc#{K => V}
            end
        end,
        #{},
        Map
    ).

-spec filtermap(Fun, map()) -> map() when
    Fun :: fun((term(), term()) -> boolean() | {true, term()}).
filtermap(Fun, Map) ->
    filter(Fun, Map).

-spec from_keys(list(), term()) -> map().
from_keys(List, Value) ->
    from_keys_impl(List, Value, #{}).

-spec from_keys_impl(list(), term(), map()) -> map().
from_keys_impl([], _, Map) ->
    Map;
from_keys_impl([Key | Tail], Value, Map) ->
    from_keys_impl(Tail, Value, Map#{Key => Value}).
