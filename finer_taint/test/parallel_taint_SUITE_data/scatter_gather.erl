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

-module('scatter_gather').
-export([
    introduce_taint_function/1,
    add_and_add_one/2,
    scatter_gather_main/0
]).

introduce_taint_function(_Unused) ->
    finer_taint:source("Some val").

add_and_add_one(Value1, Value2) ->
    Value1 + Value2 + 1.

scatter_gather_main() ->
    put(next_taint_pid, [621, 622, 623, 624, 625, 626, 627]),
    TaintedValue = finer_taint:source(42),
    Jobs = [
        {fun ?MODULE:introduce_taint_function/1, [ok]},
        {fun ?MODULE:add_and_add_one/2, [4, 5]},
        {fun ?MODULE:add_and_add_one/2, [TaintedValue, 5]}
    ],
    [IntroducedTaint, NotTainted, Tainted] = scatter_gather(Jobs),
    if
        NotTainted =/= 10 ->
            throw({invalid_computation, NotTainted});
        Tainted =/= 48 ->
            throw({invalid_computation, Tainted});
        true ->
            finer_taint:sink(IntroducedTaint),
            finer_taint:sink(NotTainted),
            finer_taint:sink(Tainted)
    end.

scatter_gather(WorkItems) ->
    % Spawn individual workers, they will send results to gather_proc
    ReplyTo = self(),
    Workers = scatter(ReplyTo, WorkItems),
    gather(Workers).
% Wait for reply from gather_proc

scatter(ReplyTo, WorkItems) ->
    [
        begin
            spawn(fun() -> worker(ReplyTo, WorkItem, Idx) end),
            Idx
        end
     || Idx <- lists:seq(1, length(WorkItems)), WorkItem <- [lists:nth(Idx, WorkItems)]
    ].

gather(Workers) ->
    lists:map(
        fun(WorkerIdx) ->
            receive
                {done, WorkerIdx, Result} -> Result
            end
        end,
        Workers
    ).

worker(ReplyPid, {Fun, Args}, Idx) ->
    Result = erlang:apply(Fun, Args),
    ReplyPid ! {done, Idx, Result},
    ok.
