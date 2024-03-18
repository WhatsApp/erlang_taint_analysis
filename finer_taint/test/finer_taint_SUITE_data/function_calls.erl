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

-module('function_calls').
-export([
         calling_convention_main/0, nested_calls_main/0,
         recursion_main/0, lambdas_main/0, lambda_closures_main/0
]).

calling_convention_main() ->
  PhoneNumber = finer_taint:source(" 123@secret.net"),
  Tainted = process_two_lists(PhoneNumber, "String"),
  NoTainted = process_two_lists("AnotherString", "A String"),
  finer_taint:sink(NoTainted),
  finer_taint:sink(Tainted).


append_to_list(L1) ->
  L1 ++ " list suffix".

concat_two_lists(L1, L2) ->
  finer_taint:source("dropped source"),
  L1 ++ L2.
process_two_lists(L1, L2) ->
  L3 = append_to_list(L1),
  concat_two_lists(L2, L3).



recursion_main() ->
  List = generate_list(10),
  TaintedNumber = finer_taint:source(42),
  TaintedList = insert_at(2, TaintedNumber, List),
  NotTaintedList = insert_at(2, 41, List),
  SanitizedList = insert_at(2, 2, List),
  finer_taint:sink(TaintedList),
  finer_taint:sink(NotTaintedList),
  finer_taint:sink(SanitizedList),
  TaintedElem = at(2, TaintedList),
  NotTaintedElem = at(2, SanitizedList),
  finer_taint:sink(TaintedElem),
  finer_taint:sink(NotTaintedElem).


generate_list(0) -> empty;
generate_list(N) -> {N, generate_list(N-1)}.

insert_at(0, Elem, Tail) -> {Elem, Tail};
insert_at(N, Elem, {Head, Tail}) -> 
  NewTail = insert_at(N-1, Elem, Tail),
  {Head, NewTail}.

at(0, {E, _Tail}) -> E;
at(N, {_Head, Tail}) -> at(N-1, Tail).

nested_calls_main() ->
  List = insert_at(0, finer_taint:source(32), generate_list(0)),
  finer_taint:sink(at(0, List)).


lambdas_main() ->
  A = finer_taint:source(42),
  LazyAddOne = fun() -> A + 1 end(),
  finer_taint:sink(LazyAddOne),
  AddOneOrA = fun (A) when A rem 2 =:= 0 -> A + 1;
                (B) -> B + A
              end,
  Map = fun Map(F, [H| T]) -> [F(H) | Map(F,T)] ;
            Map(_, []) -> []
         end,
  [Tainted, NotTainted| _] = Map(AddOneOrA, [1,2,3]),
  finer_taint:sink(Tainted),
  finer_taint:sink(NotTainted).


create_lambda(ArgName) ->
  Untainted = 1,
  fun() -> ArgName + Untainted end.

lambda_closures_main() ->
  A = finer_taint:source(42),
  Func = create_lambda(A),
  finer_taint:sink(Func()),
  % This is a test that makes sure lambdas with only
  % untainted values being captured can create blackholes
  % erlang:fun_info/2 is used as an unmodeled function
  % that creates a blackhole node in the history
  ItemInfo = finer_taint:source(arity),
  {arity, 0} = erlang:fun_info(create_lambda(1), ItemInfo).
