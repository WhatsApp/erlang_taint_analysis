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
%%% Runs multiple instructions streams exchanging messages
-module(parallel_abstract_machine).
-compile(warn_missing_spec_all).

-include_lib("kernel/include/logger.hrl").
-export([run/1, run_tracing/1, run_lineage/1, run_tracing_lineage/1, run_lineage_with_line_history/1]).

% Takes a list of filenames containg instruction streams.
% Runs all the instructions and returns a list of leaks it found.
% Leaks are returned in reverse order as they are found, but the
% order might not be deterministic due to scheduling differences
-spec run([string()]) -> taint_abstract_machine:leaks().
run(Filepaths) ->
    run_impl(Filepaths, #{}).

-spec run_tracing([string()]) -> taint_abstract_machine:leaks().
run_tracing(Filepaths) ->
    run_impl(Filepaths, #{tracing => true}).

% Runs lineage analysis in the recommended setting (with function_history).
% Meaning it keeps track of function arguments that a value passed through.
% For more info look at lineage_mode() type.
-spec run_lineage([string()]) -> taint_abstract_machine:leaks().
run_lineage(Filepaths) ->
    run_impl(Filepaths, #{lineage_mode => function_history}).

% Runs  lineage analysis, while keeping track of every line a value has passed through.
% This enables use of -query_arg_lineage in run_finer_taint escript, but it is very
% expensive and unlikely to run on our code. For more info look at lineage_mode() type.
-spec run_lineage_with_line_history([string()]) -> taint_abstract_machine:leaks().
run_lineage_with_line_history(Filepaths) ->
    run_impl(Filepaths, #{lineage_mode => line_history}).

% Runs lineage analysis with function history, while printing the instruction and the complete
% abstract machine state before executing each abstract machine instruction
% very VERBOSE, useful only for debugging small programs to see how an abstract machine executed
-spec run_tracing_lineage([string()]) -> taint_abstract_machine:leaks().
run_tracing_lineage(Filepaths) ->
    run_impl(Filepaths, #{lineage_mode => function_history, tracing => true}).

-spec run_impl([string()], map()) -> taint_abstract_machine:leaks().
run_impl(Filepaths, TaintMachineArgs) ->
    {ok, SupPid} = online_finer_taint_sup:start_link(TaintMachineArgs),
    % Start 1 proclet for each filepath
    Proclets = [abstract_machine_proclet_sup:new_proclet() || _ <- Filepaths],
    % Tell the proclets to start executing the file
    [
        abstract_machine_proclet:run_instructions_file(Pid, Fp)
     || Pid <- Proclets && Fp <- Filepaths
    ],
    % Stop all proclets, thus telling them they won't get any new instructions
    abstract_machine_proclet_sup:stop_all_proclets(),
    Leaks = taint_gatherer:get_gathered_leaks(taint_gatherer, 30000, Proclets),
    Ref = monitor(process, SupPid),
    unlink(SupPid),
    exit(SupPid, shutdown),
    receive
        {'DOWN', Ref, process, SupPid, shutdown} ->
            ok
    after 10000 ->
        ?LOG_WARNING("Failed to shutdown ~p~n", [SupPid])
    end,

    taint_abstract_machine:map_leaks_to_leaks(Leaks).
