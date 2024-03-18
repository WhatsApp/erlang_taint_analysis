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

-module(list_comprehension).

-export([basic_main/0,
        cartesian_main/0]).

-record(list_wrap, {a_list :: list()}).

maybe_taint(2) ->
  finer_taint:source(2);
maybe_taint(X) ->
  X.

basic_main() -> 
  ListWrap = #list_wrap{a_list = [1,2,3]},
  [NotTainted1, Tainted, NotTainted2]  = [maybe_taint(X) || X <- ListWrap#list_wrap.a_list, X /= no_pid],
  finer_taint:sink(NotTainted1),
  finer_taint:sink(Tainted),
  finer_taint:sink(NotTainted2).

cartesian_main() -> 
  L = [{X, X} || X <- [1,2,3]],
  [{1, Tainted}] = [{X,maybe_taint(Y)} || {1,X} <- L, {2, Y} <- L],
  finer_taint:sink(Tainted).
