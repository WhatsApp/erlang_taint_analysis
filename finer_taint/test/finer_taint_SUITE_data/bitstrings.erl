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

-module('bitstrings').
-export([
    bitstring_main/0, integer_constructed_extracted_main/0,
    bitstring_constructed_main/0
]).

bitstring_main() ->
    TaintedBitstring = finer_taint:source(<<"a tainted string">>),
    <<$a:8, Tainted:8, Rest/bitstring>> = TaintedBitstring,
    finer_taint:sink(Tainted).

bitstring_constructed_main() ->
    TaintedBitstring = finer_taint:source(<<"tainted string">>),
    HalfTaintedString = <<<<"not tainted">>/binary, TaintedBitstring/binary>>,
    <<NotTainted:8/binary, SemiTainted:7/binary, FullTainted:5/binary, _/binary>> =
        HalfTaintedString,
    finer_taint:sink(NotTainted),
    finer_taint:sink(SemiTainted),
    finer_taint:sink(FullTainted).

integer_constructed_extracted_main() ->
    TaintedSixBytes = finer_taint:source(<<"123456">>),
    HalfTaintedString = <<<<"ab">>/binary, TaintedSixBytes/binary>>,
    <<NotTainted/integer, _/integer, Tainted:48/integer>> = HalfTaintedString,
    finer_taint:sink(NotTainted),
    finer_taint:sink(Tainted).
