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
-compile(warn_missing_spec_all).
-behaviour(gen_server).

-export([
    gen_server_main/1
]).
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

-type state() :: [term()].

-spec id_function(X) -> X.
id_function(X) -> X.

-spec other_id_function(X) -> X.
other_id_function(X) -> X.

-spec gen_server_main(term()) -> ok.
gen_server_main(String) ->
  io:format("Started ~p ~n", [ok]),
  {ok, Pid} = example_gen_server:start_link(),
  try
    TaintedVal = finer_taint:source(String),
    finer_taint:sink(TaintedVal),
    finer_taint:sink(example_gen_server:store_value(Pid, TaintedVal)),
    finer_taint:sink(example_gen_server:store_value(Pid, id_function(43))),
    finer_taint:sink(other_id_function(example_gen_server:pop(Pid))),
    PoppedValue = example_gen_server:pop(Pid),
    finer_taint:sink(PoppedValue),
    io:format("Gen server returned ~p~n", [PoppedValue])
  after
    example_gen_server:stop(Pid)
  end.


%% ======= GEN SERVER IMPL =============

-spec start_link() -> gen_server:start_ret().
start_link() ->
  gen_server:start_link(?MODULE, [], []).

-spec start_link(term(), term()) -> gen_server:start_ret().
start_link(TaintedVal, NotTaintedVal) ->
  gen_server:start_link(?MODULE, [TaintedVal, NotTaintedVal], []).


-spec store_value(pid(), term()) -> term().
store_value(Pid, Value) ->
    gen_server:call(Pid, {store, Value}).

-spec pop(pid()) -> term().
pop(Pid) ->
    gen_server:call(Pid, pop).

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:call(Pid, terminate).

-spec init([]) -> {ok, state()}.
init([]) -> {ok, []}.

-spec handle_call(Msg, gen_server:from(), state()) -> {reply, term(), state()} | {stop, normal, ok, state()}
  when Msg :: {store, term()} | pop | terminate.
handle_call({store, Value}, _From, State) ->
    {reply, Value, [Value | State]};
handle_call(pop, _From, [Head | Tail]) ->
    {reply, Head, Tail};
handle_call(terminate, _From, State) ->
    {stop, normal, ok, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_, State) ->
    {noreply, State}.
