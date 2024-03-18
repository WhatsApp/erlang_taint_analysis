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

-module('pattern_to_var').
-feature(maybe_expr, enable).
-export([
         pattern_to_var/0, extract_pattern/0, string_plusplus_pattern/0, set_element_main/0, operators_in_pattern_main/0, maybe_expr_main/0
]).
pattern_to_var() ->
  PhoneNumber = finer_taint:source(" 123@secret.net"),
  AString = "123 os a good start of a string ",
  X = {ok, string:strip(PhoneNumber)},
  Y = {ok, string:strip(AString)},
  finer_taint:sink(Y),
  finer_taint:sink(X).

extract_pattern() ->
  PhoneNumber = finer_taint:source("123@secret.net"),
  Tuple = {"A nice string", PhoneNumber},
  {X, Y} = Tuple,
  finer_taint:sink(Y),
  finer_taint:sink(X),
  {ok, T1} = {ok, PhoneNumber},
  {ok, UT1} = {ok, "A nice string"},
  {T2, ok} = {PhoneNumber, ok},
  finer_taint:sink(T1),
  finer_taint:sink(T2),
  finer_taint:sink(UT1).


string_plusplus_pattern() ->
  PhoneNumber = finer_taint:source(" 123@secret.net"),
  " 123" ++ RestOfNumber = PhoneNumber,
  finer_taint:sink(RestOfNumber).


set_element_main() ->
  PhoneNumber = finer_taint:source("123@secret.net"),
  ANumber = finer_taint:source(42),
  Tuple = {"Some string", "Another string", ANumber},
  Tuple1 = erlang:setelement(2, Tuple, PhoneNumber),
  {NotTainted, Tainted, Tainted2} = Tuple1,
  finer_taint:sink(NotTainted),
  finer_taint:sink(Tainted),
  finer_taint:sink(Tainted2).
  

operators_in_pattern_main() ->
  PhoneNumber = finer_taint:source("123@secret.net"),
  % These are illegal patterns
  % Number ++ "@secret.net" = PhoneNumber,
  % -X = -1
  "123" ++ Domain = PhoneNumber,
  finer_taint:sink(Domain),
  -1 = finer_taint:source(-1),
  2 bsl 2 = finer_taint:source(8).


maybe_expr(Match) ->
  maybe
    "123" ++ _ ?= Match,
    it_matches
  end.

maybe_expr_else(Match) ->
  maybe
    "123" ++ _ ?= Match,
    it_matches
  else
    "3" ++ Rest -> Rest ++ finer_taint:source("a new source")
  end.


maybe_expr_main() ->
  PhoneNumber = finer_taint:source("3@secret.net"),
  Tainted =  maybe_expr(PhoneNumber),
  finer_taint:sink(Tainted),
  PhoneNumber1 = finer_taint:source("123@secret.net"),
  NotTainted =  maybe_expr(PhoneNumber1),
  finer_taint:sink(NotTainted),
  Tainted1 =  maybe_expr_else(PhoneNumber),
  finer_taint:sink(Tainted1).

