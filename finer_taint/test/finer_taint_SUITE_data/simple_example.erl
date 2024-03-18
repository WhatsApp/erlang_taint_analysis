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

-module('simple_example').
-export([
         one_clause/0, if_clause/0, lineage_main/0, macro_duplicate_main/0
]).

one_clause() -> 
  PhoneNumber = finer_taint:source("phone_num","123@secret.net"),
  AString = "123 os a good start of a string",
  X = string:slice(PhoneNumber, 0, 3),
  Y = string:slice(AString, 0, 3),
  finer_taint:sink(Y),
  finer_taint:sink(X).

if_clause() -> 
  PhoneNumber = finer_taint:source("123@secret.net"),
  Result = if PhoneNumber =:= "A" -> ok;
              true -> PhoneNumber
           end,
  finer_taint:sink(Result).


pack(Arg) ->
	{Arg, 1}.

unpack({Arg, 1}) ->
	Arg.

lineage_entry(Arg1, Arg2) ->
	PackedArg1 = pack(Arg1),
	pack(unpack(PackedArg1) + Arg2).

lineage_main() ->
	lineage_entry(3,4).


-define(EXPR_DUPLICATOR(A), begin A,A end).

macro_duplicate_main() ->
  Tainted = finer_taint:source(2),
  X = ?EXPR_DUPLICATOR(if is_atom(Tainted) -> 3;
                      true -> Tainted + 1 end),
  finer_taint:sink(X).
