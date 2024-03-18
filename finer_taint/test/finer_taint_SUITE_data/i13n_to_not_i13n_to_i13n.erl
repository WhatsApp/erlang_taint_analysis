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

-module('i13n_to_not_i13n_to_i13n').
% This module tests the case where instrumented code (this module)
% calls not instrumented code (not_instrumented module) that then
% calls some instrumented code again. i13n_to_not_i13n_to_i13n is short for instrumentation
% to not instrumentation to instrumentation
-export([
         i13n_to_not_i13n_to_i13n_main/0
]).

%We can't trace dataflow through non instrumented code, so we 
%do not attempt to track taint through Arg1 in this test.
%The test only tests if each of the instrumented function can
%track taint independently
call_back_fn(_Arg1, ok, ok, ok, ok) ->
  Number = finer_taint:source(6),
  Number0 = Number + 1,
  finer_taint:sink(Number),
  5.

i13n_to_not_i13n_to_i13n_main() ->
    Number = finer_taint:source(6),
    Return = not_instrumented:call_fn(fun call_back_fn/5, Number),
    finer_taint:sink(Number).
