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

%%% % @format
-module(ps_example).
-export([
    local_if_clause/0,
    ps_local_if_clause/0,
    ps_exp_if_clause/0,
    ps_if_clause/0
]).

local_if_clause() ->
    PhoneNumber = finer_taint:source("123@secret.net"),
    Result =
        if
            PhoneNumber =:= "A" -> ok;
            true -> PhoneNumber
        end,
    local_sink(Result).

local_sink(Result) ->
    finer_taint:sink(Result).

ps_local_if_clause() ->
    PhoneNumber = finer_taint:source("123@secret.net"),
    Result =
        if
            PhoneNumber =:= "A" -> ok;
            true -> PhoneNumber
        end,
    power_shell:eval(?MODULE, local_sink, [Result]).

ps_if_clause() ->
    PhoneNumber = finer_taint:source("123@secret.net"),
    Result =
        if
            PhoneNumber =:= "A" -> ok;
            true -> PhoneNumber
        end,
    power_shell:eval(ps_external, local_sink, [Result]).

ps_exp_if_clause() ->
    PhoneNumber = finer_taint:source("123@secret.net"),
    Result =
        if
            PhoneNumber =:= "A" -> ok;
            true -> PhoneNumber
        end,
    power_shell:export(ps_external),
    ps_external:local_sink(Result).
