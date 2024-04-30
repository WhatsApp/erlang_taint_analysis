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
%%% @doc
%%% Taint abstract machine proclet is responsible for executing
%%% a single instruction stream (process) on the taint_abstract_machine.
%%%
%%% In essence this module wraps the taint_abstract_machine, such that
%%% multiple instruction streams can be executed in parallel.
%%%
%%% The found leaks are reported to taint_gatherer once this process
%%% stops.
%%%
%%% The process stops either due to a failure in taint_abstract_machine
%%% or when abstract_machine_proclet:stop/1 is called
%%%
%%% Usually new instances of abstract_machine_proclet can be obtained
%%% via abstract_machine_proclet_sup:new_proc()
%%% @end
-module(abstract_machine_proclet).
-compile(warn_missing_spec_all).
-behaviour(gen_server).

% ======== gen_server / internal ======

-export([init/1, handle_cast/2, handle_call/3, terminate/2, handle_info/2]).

-include_lib("kernel/include/logger.hrl").

-record(proclet_state, {
    state :: taint_abstract_machine:state(),
    % Logs every executed instruction and the state it's executing on
    tracing = false :: boolean(),
    % In coverage mode taint all values in the module with prefix
    coverage_prefix :: string() | false,
    % The taint_gatherer process to which we can report leaks to
    gatherer :: gen_server:server_ref()
}).

-type state() :: #proclet_state{}.

% ======== PUBLIC API ==============
-export([execute_instruction/2, start_link/2, run_instructions_file/2, stop/1]).

% Evolves the internal state of the taint_abstract_machine by executing
% a single instruction on it.
-spec execute_instruction(gen_server:server_ref(), taint_abstract_machine:instruction()) -> ok.
execute_instruction(Pid, Instruction) ->
    gen_server:cast(Pid, {execute_instruction, Instruction}).

% Evolves the internal state of the taint_abstract_machine by executing
% instructions from InstructionsFileName on it
-spec run_instructions_file(gen_server:server_ref(), string()) -> ok.
run_instructions_file(Pid, InstructionsFileName) ->
    gen_server:cast(Pid, {run_instructions_file, InstructionsFileName}).

% Tells the abstract machine proclet there will be no further instructions,
% The proclet will report leaks and exit
-spec stop(gen_server:server_ref()) -> ok.
stop(Pid) ->
    gen_server:cast(Pid, {stop}).

% Starts a new abstract_machine_proclet. InitStateArgs is passed
% to taint_abstract_machine:init_state/2. If InitStateArgs contains
% a tracing key, that is used to set the tracing flag of abstract_machine_proclet
-spec start_link(map(), gen_server:server_ref()) -> term().
start_link(InitStateArgs, Gatherer) ->
    gen_server:start_link(?MODULE, [Gatherer, InitStateArgs], []).

% ========== gen_server / internal ===============
%
-spec init(list()) -> {ok, state()}.
init([Gatherer, InitStateArgs]) ->
    % We trap the exit to ensure the messages in the queue get processed and not discarded
    % when an exit is initiated
    process_flag(trap_exit, true),
    % This is a very important flag. The proclets can accumulate
    % large ammount of messages in the queue, this makes GC of the process
    % very expensive. This flag makes GC of the process with a long queue
    % cheap at the expense of making receiving messages a bit more expensive.
    process_flag(message_queue_data, off_heap),
    put(is_abs_proclet, true),

    {ok, #proclet_state{
        state = taint_abstract_machine:init_state(InitStateArgs),
        tracing = maps:get(tracing, InitStateArgs, false),
        coverage_prefix = maps:get(coverage_prefix, InitStateArgs, false),
        gatherer = Gatherer
    }}.

-spec terminate(term(), state()) -> ok.
terminate(Reason, _State) ->
    {reductions, Reductions} = erlang:process_info(self(), reductions),
    ?LOG_INFO("Terminating abstract machine ~p after ~p reductions with  ~p ~n", [self(), Reductions, Reason]),
    % Don't call stop_impl here, to avoid double adding leaks
    ok.

-spec stop_impl(state()) -> ok.
stop_impl(#proclet_state{state = AmState, gatherer = Gatherer}) ->
    Leaks = taint_abstract_machine:get_leaks_as_map(AmState),
    taint_gatherer:add_leaks(Gatherer, Leaks),
    ok.

-spec handle_call(term(), gen_server:from(), state()) -> {reply, ok, state()}.
handle_call(Msg, _From, State) ->
    ?LOG_WARNING("abstract_machine_proclet doesn't expect a call, got ~p", [Msg]),
    {reply, ok, State}.

-spec handle_cast(
    {run_instructions_file, FileName :: string()}
    | {stop}
    | {execute_instruction, Instruction :: taint_abstract_machine:instruction()},
    state()
) ->
    {noreply, state()}
    | {stop, {shutdown, term()}, state()}.
handle_cast({run_instructions_file, InstructionsFileName}, State) ->
    ?LOG_INFO("[~p] executing instructions file ~p~n", [self(), InstructionsFileName]),
    case run_instructions_file_impl(InstructionsFileName, State) of
        {taint_machine_crash, NewState} ->
            stop_impl(State),
            {stop, {shutdown, taint_machine_crash}, NewState};
        NewState ->
            {noreply, NewState}
    end;
handle_cast({stop}, State) ->
    stop_impl(State),
    {stop, {shutdown, done_processing}, State};
handle_cast({execute_instruction, Instruction}, State) ->
    case execute_instruction_impl(Instruction, State) of
        taint_machine_crash ->
            stop_impl(State),
            {stop, {shutdown, taint_machine_crash}, State};
        NewState ->
            {noreply, NewState}
    end.

-spec handle_info({got_key, term(), term()}, state()) -> {noreply, state()}.
handle_info({got_key, MessageId, _}, State) ->
    ?LOG_INFO("Got message with id ~p after timeout~n", [MessageId]),
    {noreply, State}.

% Execute an instruction on the internal state. Returns taint_machine_crash
% if there was an error when executing the taint_abstract_machine
-spec execute_instruction_impl(taint_abstract_machine:instruction(), state()) ->
    state() | taint_machine_crash.
execute_instruction_impl(Instruction, State) ->
    trace(Instruction, State),
    try propagate(Instruction, State) of
        S -> State#proclet_state{state = S}
    catch
        {abstract_machine_invalid_state, _Inst, _St} ->
            ?LOG_WARNING("~p pid failed on  ~p in state ~n", [self(), Instruction]),
            taint_machine_crash;
        Exception:Reason:StackTrace ->
            ?LOG_WARNING("Proclet ~p crashed with ~p ~p~n~p~n", [
                self(), Exception, Reason, StackTrace
            ]),
            taint_machine_crash
    end.

% Wrapper for taint_abstract_machine propagate
-spec propagate(taint_abstract_machine:instruction(), state()) -> taint_abstract_machine:state().
propagate(Instruction, #proclet_state{state = AmState, coverage_prefix = CoveragePrefix}) when
    is_list(CoveragePrefix)
->
    taint_abstract_machine:propagate_cov(Instruction, AmState, CoveragePrefix);
propagate(Instruction, #proclet_state{state = AmState}) ->
    taint_abstract_machine:propagate(Instruction, AmState).

-spec trace(taint_abstract_machine:instruction(), state()) -> ok.
trace(_, #proclet_state{tracing = false}) ->
    ok;
trace(Instruction, #proclet_state{state = AmState, tracing = true}) ->
    ?LOG_INFO("[~p] executing ~p on~n~p~n", [self(), Instruction, AmState]),
    ok.

-spec instructions_folder(
    taint_abstract_machine:instruction(),
    state() | {taint_machine_crash, state()}
) -> state() | {taint_machine_crash, state()}.
instructions_folder(_Instruction, Acc = {taint_machine_crash, _}) ->
    Acc;
instructions_folder(Instruction, PropagatedState) ->
    case execute_instruction_impl(Instruction, PropagatedState) of
        taint_machine_crash -> {taint_machine_crash, PropagatedState};
        State -> State
    end.

-spec run_instructions_file_impl(string(), state()) -> state() | {taint_machine_crash, state()}.
run_instructions_file_impl(InstructionsFileName, State) ->
    {ok, Instructions} = file:consult(InstructionsFileName),
    lists:foldl(
        fun instructions_folder/2,
        State,
        Instructions
    ).
