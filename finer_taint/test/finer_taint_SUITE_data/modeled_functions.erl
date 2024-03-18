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

-module('modeled_functions').
-export([
    modeled_functions_main/0, process_dict_main/0,
    joining_model_main/0
]).

modeled_functions_main() ->
    Number = finer_taint:source("123"),
    Domain = finer_taint:source("@secret.net"),
    {ok, Tainted} = definetly_not_modeled:get(Number, Domain),
    finer_taint:sink(Tainted),
    {ok, NotTainted} = definetly_not_modeled:get(1, 2),
    finer_taint:sink(NotTainted).

joining_model_main() ->
    Number = finer_taint:source("123"),
    Domain = finer_taint:source("@secret.net"),
    finer_taint:sink(string:concat(Number, Domain)).

process_dict_main() ->
    Number = finer_taint:source("123"),
    finer_taint:sink(put(notsecret, 1)),
    finer_taint:sink(put(secret, Number)), %ret: undefined -> not tainted
    finer_taint:sink(get(secret)), %tainted
    finer_taint:sink(put(secret, 1)), %ret: Number -> tainted
    finer_taint:sink(get(secret)). % not tainted
