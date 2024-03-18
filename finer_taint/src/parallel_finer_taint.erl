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
%% Implementation of the finer_taint behaviour that handles parallelism
%% It uses abstract_machine_server to split the instruction streams per
%% "taint_pid". The taint_pid should be very similar to normal pid(),
%% just created via the slf() function.
-module(parallel_finer_taint).
-compile(warn_missing_spec_all).
-behaviour(finer_taint).

%% Finer taint callbacks.
-export([
    write_instruction/1
]).

% Similar to self(), but returns a "taint_pid"
-spec slf() -> abstract_machine_server:tid().
slf() ->
    case get(taint_pid) of
        undefined ->
            put(taint_pid, erlang:unique_integer([positive]) * 100000 + (erlang:system_time(seconds) rem (24 * 3600))),
            abstract_machine_server:write_instruction(
                slf(), {push, {lists:flatten(io_lib:format("% ancestors ~p", [get('$ancestors')]))}}
            ),
            abstract_machine_server:write_instruction(
                slf(), {pop, {}}
            ),
            slf();
        TaintPid ->
            TaintPid
    end.

-spec write_instruction(taint_abstract_machine:instruction()) -> ok.
write_instruction(Instruction) ->
    abstract_machine_server:write_instruction(slf(), Instruction).
