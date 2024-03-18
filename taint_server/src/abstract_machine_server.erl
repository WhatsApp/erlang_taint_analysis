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

%% % @format
-module(abstract_machine_server).
-compile(warn_missing_spec_all).
-behaviour(gen_server).

% ======== gen_server / internal ======

-export([init/1, handle_cast/2, handle_call/3, terminate/2]).

-include_lib("taint_server/include/taint_server.hrl").

-record(abstract_machine_server_state, {
    filename :: string(),
    tid_state_map :: #{tid() => per_tid_state()}
}).

%% tid() is similar to pid(), but it represent the id of the abstract machine executing
%% an instruction stream for a particular process. In other words, where real processes
%% are indentfied with pid(), "taint processes" are identfied with tid()
-type tid() :: integer().

-type per_tid_state() :: file:io_device().
-type state() :: #abstract_machine_server_state{}.

-export_type([tid/0]).

% ======== PUBLIC API ==============
-export([write_instruction/2, start_link/2, write_instruction_sync/2]).

-spec write_instruction(tid(), taint_abstract_machine:instruction()) -> ok.
write_instruction(Tid, Instruction) ->
    gen_server:cast(tid_to_global_name(Tid), {write_instruction, Tid, Instruction}).

% Mainly useful for testing, otherwise it is likely too expensive
-spec write_instruction_sync(tid(), taint_abstract_machine:instruction()) -> ok.
write_instruction_sync(Tid, Instruction) ->
    gen_server:call(tid_to_global_name(Tid), {write_instruction, Tid, Instruction}).

-spec start_link(WorkerIdx :: integer(), InstructionsFilePrefix :: string()) -> term().
start_link(WorkerIdx, InstructionsFilePrefix) ->
    gen_server:start_link(tid_to_global_name(WorkerIdx), ?MODULE, [InstructionsFilePrefix], []).

% ========== gen_server / internal ===============
%
-spec init([InstructionsFilePrefix :: string()]) -> {ok, state()}.
init([InstructionsFilePrefix]) ->
    % We trap the exit to ensure the messages in the queue get processed and not discarded
    % when an exit is initiated
    process_flag(trap_exit, true),
    % This process is expected to receive a lot of messages, so this flag is improtant
    % to keep good performance
    process_flag(message_queue_data, off_heap),
    {ok, #abstract_machine_server_state{filename = InstructionsFilePrefix, tid_state_map = #{}}}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, #abstract_machine_server_state{tid_state_map = Map}) ->
    maps:fold(
        fun(_, Fd, ok) ->
            file:close(Fd),
            ok
        end,
        ok,
        Map
    ).

-spec get_or_create_state_for_tid(tid(), state()) -> {state(), per_tid_state()}.
get_or_create_state_for_tid(
    Tid, State = #abstract_machine_server_state{filename = Prefix, tid_state_map = TidMap}
) ->
    case maps:get(Tid, TidMap, undefined) of
        undefined ->
            {ok, Fd} = file:open(io_lib:format("~s-~p", [Prefix, Tid]), [append, raw]),
            {State#abstract_machine_server_state{tid_state_map = TidMap#{Tid => Fd}}, Fd};
        TidState ->
            {State, TidState}
    end.

-spec handle_call(
    {write_instruction, tid(), taint_abstract_machine:instruction()}, gen_server:from(), state()
) ->
    {reply, ok, state()} | {stop, normal, ok, state()}.
handle_call({write_instruction, Tid, Instruction}, _From, State) ->
    {reply, ok, write_instruction(Tid, Instruction, State)}.

-spec handle_cast(
    {write_instruction, Tid :: tid(), Instruction :: taint_abstract_machine:instruction()}, state()
) -> {noreply, state()}.
handle_cast({write_instruction, Tid, Instruction}, State) ->
    {noreply, write_instruction(Tid, Instruction, State)}.

-spec write_instruction(tid(), taint_abstract_machine:instruction(), state()) -> state().
write_instruction(Tid, Instruction, State) ->
    {State1, TidState} = get_or_create_state_for_tid(Tid, State),
    ok = file:write(TidState, io_lib:format("~p.~n", [Instruction])),
    State1.

-spec tid_to_global_name(tid() | integer()) -> gen_server:server_name().
tid_to_global_name(Tid) ->
    {global, {?MODULE, Tid rem ?NUM_WORKERS}}.
