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

-module('case_clauses').
-export([
         case_main/0, case_in_function_args_main/0,
         record_main/0,
         nested_case_with_call_main/0,
         lists_main/0
]).

case_main() ->
  TaintedAtom = finer_taint:source(sanitized),
  SanitizedIsSanitized = big_pattern_extractor(TaintedAtom),
  finer_taint:sink(SanitizedIsSanitized),
  PhoneNumber = finer_taint:source(" 123@secret.net"),
  TaintedPhoneNumber = big_pattern_extractor(PhoneNumber),
  finer_taint:sink(SanitizedIsSanitized),
  finer_taint:sink(TaintedPhoneNumber).


lists_main() ->
  PhoneNumber = finer_taint:source(" 123@secret.net"),
  finer_taint:sink(big_pattern_extractor([])),
  finer_taint:sink(big_pattern_extractor([notsanitized, PhoneNumber, 1.0])),
  finer_taint:sink(big_pattern_extractor([PhoneNumber | [sanitized]])).
  
-record(value, {type :: tainted | nottainted,
                int_value :: integer(),
                history :: list()}).

record_main() ->
  TaintedValue = finer_taint:source(42),
  NotTaintedRecord = #value{type = nottainted, history = [], int_value = TaintedValue},
  TaintedRecord = #value{type = tainted, history = [], int_value = TaintedValue},
  finer_taint:sink(big_pattern_extractor(NotTaintedRecord)),
  finer_taint:sink(big_pattern_extractor(TaintedRecord)),
  finer_taint:sink(big_pattern_extractor([TaintedRecord])).


big_pattern_extractor(X) ->
  case X of
     [] -> finer_taint:source([]);
     [notsanitized, PhoneNumber, 1.0] -> PhoneNumber;
     [_PhoneNumber, sanitized] -> sanitized;
     sanitized -> ok;
     #value{type = nottainted, history = Hist} -> Hist;
     #value{type = tainted, int_value = Val} -> Val;
     [_Record = #value{type = tainted, int_value = IntVal}] -> IntVal;
     _ -> X
  end.


get_ok() -> ok.
nested_case_with_call_main() ->
  TaintedValue = finer_taint:source(42),
  case get_ok() of
    ok -> FourtyThree = TaintedValue + 1,
          case FourtyThree of
            43 -> finer_taint:sink(FourtyThree);
            _ -> ok
          end;
    _ -> ok
  end.

get_1_arg(Arg, _, _) -> Arg.
get_2_arg(_, Arg, _) -> Arg.
get_tuple() -> {finer_taint:source(1),2}.
case_in_function_args_main() ->
  TaintedValue = finer_taint:source(42),
  ARecord =  #value{type = tainted, history = [], int_value = TaintedValue},
  finer_taint:sink(get_2_arg(get_tuple(),ARecord#value.int_value, ARecord#value.type)).

