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

-module('shortcircuiting').
-export([safe_shortcircuit/0, unsafe_shortcircuit/0]).

safe_shortcircuit() ->
    Source = finer_taint:source("user-controlled"),
    true orelse finer_taint:sink(Source),
    false andalso finer_taint:sink(Source),
    true andalso ( true orelse finer_taint:sink(Source)).

unsafe_shortcircuit() ->
    Source = finer_taint:source("user-controlled"),
    true andalso finer_taint:sink(Source),
    Val = false orelse flag_set,
    case Val of
      flag_set -> finer_taint:sink(Source);
      _ -> ok
    end,
    true andalso (false orelse foo(Source)).

foo(Source) ->
    X = "str" ++ Source,
    finer_taint:sink(Source),
    true.
