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

-module(example_gen_server).
-behaviour(gen_server).

-export([
    start_link/0,
    start_link/2,
    store_value/2,
    pop/1,
    stop/1,
    init/1,
    handle_call/3,
    handle_cast/2
]).

-export([gen_server_test_main/0, gen_server_init_test_main/0]).

% ========= TEST ===============

id_function(X) -> X.
other_id_function(X) -> X.

gen_server_test_main() ->
  modeled_erlang:real_put(next_taint_pid, [521, 522, 523]),
  {ok, Pid} = example_gen_server:start_link(),
  modeled_erlang:real_put(next_taint_pid, undefined),
  TaintedVal = finer_taint:source(42),
  finer_taint:sink(example_gen_server:store_value(Pid, TaintedVal)),
  finer_taint:sink(example_gen_server:store_value(Pid, id_function(43))),
  finer_taint:sink(other_id_function(example_gen_server:pop(Pid))),
  finer_taint:sink(example_gen_server:pop(Pid)),
  example_gen_server:stop(Pid).

% This should test if the taint is propagate through gen_server:start_link
gen_server_init_test_main() ->
  TaintedVal = finer_taint:source(42),
  modeled_erlang:real_put(next_taint_pid, [521, 522, 523]),
  {ok, Pid} = example_gen_server:start_link(TaintedVal, notainted),
  modeled_erlang:real_put(next_taint_pid, undefined),
  example_gen_server:stop(Pid).



%% ======= GEN SERVER IMPL =============

start_link() -> 
  gen_server:start_link(?MODULE, [], []).

start_link(TaintedVal, NotTaintedVal) -> 
  gen_server:start_link(?MODULE, [TaintedVal, NotTaintedVal], []).

store_value(Pid, Value) ->
    gen_server:call(Pid, {store, Value}).

pop(Pid) ->
    gen_server:call(Pid, pop).

stop(Pid) ->
    gen_server:call(Pid, terminate).

init([]) -> {ok, []};
init([TaintedVal, NotTaintedVal]) ->
  finer_taint:sink(TaintedVal),
  finer_taint:sink(NotTaintedVal),
  {ok, []}.


handle_call({store, Value}, _From, State) ->
    {reply, Value, [Value | State]};
handle_call(pop, _From, [Head | Tail]) ->
    {reply, Head, Tail};
handle_call(terminate, _From, State) ->
    {stop, normal, ok, State}.

handle_cast(_, State) ->
    {noreply, State}.
