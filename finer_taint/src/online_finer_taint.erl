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
%% in an online mode. That is the finer taint analysis is ran as the
%% program under test is executing and not afterwards.
-module(online_finer_taint).
-compile(warn_missing_spec_all).
-behaviour(finer_taint).

%% Finer taint callbacks.
-export([
    write_instruction/1
]).

% Similar to self(), but returns a pid() of the abstract machine proclet
% shadowing this process
-spec slf() -> pid().
slf() ->
    case get(taint_proclet_pid) of
        undefined ->
            put(taint_proclet_pid, abstract_machine_proclet_sup:new_proclet()),
            slf();
        TaintPid ->
            TaintPid
    end.

-spec write_instruction(taint_abstract_machine:instruction()) -> ok.
write_instruction(Instruction) ->
    case get(is_abs_proclet) of
        true -> error(recursive_call_in_finer_taint);
        undefined -> ok
    end,
    abstract_machine_proclet:execute_instruction(slf(), Instruction).
