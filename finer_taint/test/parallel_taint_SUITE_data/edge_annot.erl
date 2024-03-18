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

-module('edge_annot').
-export([
         edge_annotations_main/0
]).

to_tuple(Value) ->
  from_tuple({Value, 1}).

from_tuple({Value, {send, Pid}}) ->
	Pid ! Value;
from_tuple({Value, sink}) ->
  finer_taint:sink(Value);
from_tuple({Value, _}) ->
  Value.

edge_annotations_main() ->
    Taint = finer_taint:source(42),
    TaintTuple = to_tuple(Taint),
		from_tuple({TaintTuple, {send, self()}}),

		Taint1 = receive Val -> Val end,
    TaintTuple1 = to_tuple(Taint1),
		from_tuple({TaintTuple1, {send, self()}}),

		Taint2 = receive Val1 -> Val1 end,
    TaintTuple2 = to_tuple(Taint2),
		from_tuple({TaintTuple2, sink}).
		
		

