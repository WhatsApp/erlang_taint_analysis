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

-module('map_examples').
-export([
    map_values_main/0, opaque_map_main/0,
    map_update_main/0,
    map_keys_main/0,
    map_module_main/0
]).

map_values_main() ->
    PhoneNumber = finer_taint:source(" 123@secret.net"),
    AMap = #{phone_number => PhoneNumber, a_tag => a_tag, not_used => 1},
    finer_taint:sink(AMap),
    #{phone_number := Pn, a_tag := Tag} = AMap,
    finer_taint:sink(Pn),
    finer_taint:sink(Tag).

map_keys_main() ->
    InitialyUntaintedPhoneNumber = "123@secret.net",
    PhoneNumber = finer_taint:source(InitialyUntaintedPhoneNumber),
    AMap = #{PhoneNumber => ok, "Some string" => 2},
    % This should be tainted
    finer_taint:sink(AMap),
    %This should be untainted
    finer_taint:sink(InitialyUntaintedPhoneNumber),
    #{InitialyUntaintedPhoneNumber := Status} = AMap,

    %Looking up a tainted key in a map should "catch" taint
    %This is needed to implement iterations over the map
    %This should be tainted
    finer_taint:sink(InitialyUntaintedPhoneNumber),
    % This should not be tainted
    finer_taint:sink(Status).

map_update_main() ->
    PhoneNumber = finer_taint:source(" 123@secret.net"),
    AMap = #{a_tag => a_tag, not_used => 1},
    finer_taint:sink(AMap),
    ATaintedMap = AMap#{phone_number => PhoneNumber},
    finer_taint:sink(ATaintedMap),
    #{phone_number := Pn, a_tag := Tag} = ATaintedMap,
    finer_taint:sink(Tag),
    finer_taint:sink(Pn).

map_module_main() ->
    PhoneNumber = finer_taint:source(" 123@secret.net"),
    AMap = #{phone_number => PhoneNumber, a_tag => a_tag, not_used => 1},
    finer_taint:sink(maps:get(phone_number, AMap)),
    finer_taint:sink(maps:get(not_in_map, AMap, PhoneNumber)),
    KeyTaintedMap = #{PhoneNumber => a_number, somethingelse => 0},
    {[TheSingleTaintedKey], OtherKeys} = maps:fold(
        fun
            (Key, 0, {Other, Acc}) -> {Other, [Key | Acc]};
            (Num, _, {Acc, Other}) -> {[Num | Acc], Other}
        end,
        {[], []},
        KeyTaintedMap
    ),
    finer_taint:sink(OtherKeys),
    finer_taint:sink(TheSingleTaintedKey).

opaque_map_main() ->
  TaintedMap = finer_taint:source(#{a => ok}),
  TaintedMap1 = TaintedMap#{notainted => nottainted},
  finer_taint:sink(TaintedMap1).
