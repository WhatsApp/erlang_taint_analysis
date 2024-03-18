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
%%% This module is used to collect various "leaks" (dataflows) that
%%% are detected while a taint_abstract_machine is executed on an
%%% instruction stream. parallel_abstract_machine is an example
%%% of how this module is meant to be used.
-module(taint_gatherer).

-compile(warn_missing_spec_all).

-behaviour(gen_server).

-export([init/1, handle_cast/2, handle_call/3, handle_info/2]).

% List of pids of proclets that are expected to register leaks
% [notapid] is an atom that will never match a pid and thus wait until timeout
-type proc_pids() :: [pid() | notapid].

-record(gatherer_state, {
    leaks :: taint_abstract_machine:leaks_map(),
    reply_to = noone :: noone | {gen_server:from(), proc_pids()},
    % In native units
    last_added_time :: number(),
    % List of pid() that have added a leak already
    proclet_pids = [] :: proc_pids()
}).
-include_lib("kernel/include/logger.hrl").

-type state() :: #gatherer_state{}.

% ============== PUBLIC API ==============
-export([add_leaks/2, get_gathered_leaks/3, start_link/0]).

% Called by a "proclet" (taint_abstract_machine that is executing an instruction stream)
% to register leaks that it has found.
-spec add_leaks(gen_server:server_ref(), taint_abstract_machine:leaks_map()) -> ok.
add_leaks(Pid, Leaks) ->
    gen_server:cast(Pid, {add_leaks, self(), Leaks}).

% Gets the gathered leaks if all ProcletPids have returned or
% WaitTime seconds has passed since the last added leak.
% ProcletPids is the list of pids that are expected to add leaks
-spec get_gathered_leaks(gen_server:server_ref(), number(), proc_pids()) -> taint_abstract_machine:leaks_map().
get_gathered_leaks(Pid, WaitTime, ProcletPids) ->
    % Timeout is implemented via the check_progress message mechanism
    gen_server:call(Pid, {get_gathered_leaks, WaitTime, ProcletPids}, infinity).

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% ==================== gen_server internal ======
-spec init([]) -> {ok, state()}.
init([]) ->
    {ok, #gatherer_state{leaks = #{}, last_added_time = erlang:monotonic_time()}}.

-spec handle_call({get_gathered_leaks, number(), proc_pids()}, gen_server:from(), state()) ->
    {reply, term(), state()} | {stop, normal, ok, state()} | {noreply, state()}.
handle_call(
    {get_gathered_leaks, WaitTime, RequestedProcletPids},
    From,
    State = #gatherer_state{leaks = Leaks, last_added_time = LastAddTime, proclet_pids = AlreadyAddedProcPids}
) ->
    ?LOG_INFO("Currently have ~p leaks~n", [maps:size(Leaks)]),
    TimeSinceLastAdd = erlang:convert_time_unit(erlang:monotonic_time() - LastAddTime, native, millisecond),
    AllPidsAlreadyAdded = lists:sort(RequestedProcletPids) =:= lists:sort(AlreadyAddedProcPids),
    if
        % More than WaitTime has passed since last leak was added, client does not want to wait more time
        TimeSinceLastAdd > WaitTime orelse AllPidsAlreadyAdded ->
            % Or all requested pids have already added a leak
            % return now, with what is currently gathered.
            {reply, Leaks, State};
        TimeSinceLastAdd =< WaitTime ->
            % The time passed since the last message is less than the WaitTime,
            % we schedule a check_progress message and remember the client to reply to later
            erlang:send_after(
                WaitTime - TimeSinceLastAdd,
                self(),
                {check_progress, WaitTime}
            ),
            {noreply, State#gatherer_state{reply_to = {From, RequestedProcletPids}}}
    end.

-spec handle_info({check_progress, number()}, state()) -> {noreply, state()}.
% The {check_progress, WaitTime} is sent when a client is waiting for leaks to be gathered and is willing
% to tollerate WaitTime milliseconds since the last leak was gathered
handle_info(
    {check_progress, WaitTime},
    State = #gatherer_state{
        leaks = Leaks,
        last_added_time = LastAddTime,
        reply_to = {ReplyTo, RequestedProcletPids},
        proclet_pids = AlreadyAddedProcPids
    }
) ->
    TimeSinceLastAddedLeaks = erlang:convert_time_unit(erlang:monotonic_time() - LastAddTime, native, millisecond),
    AllPidsAlreadyAdded = lists:sort(RequestedProcletPids) =:= lists:sort(AlreadyAddedProcPids),
    if
        TimeSinceLastAddedLeaks > WaitTime ->
            RemainingPids = RequestedProcletPids -- AlreadyAddedProcPids,
            ?LOG_WARNING("Gather_leaks timeout, skipping ~p proclets, dead proclets: ~p~n", [
                length(RemainingPids), [Pid || Pid <- RemainingPids, is_pid(Pid) andalso not is_process_alive(Pid)]
            ]),
            gen_server:reply(ReplyTo, Leaks),
            {noreply, State};
        AllPidsAlreadyAdded ->
            gen_server:reply(ReplyTo, Leaks),
            {noreply, State};
        true ->
            erlang:send_after(
                WaitTime,
                self(),
                {check_progress, WaitTime}
            ),
            {noreply, State}
    end;
handle_info(_, State) ->
    {noreply, State}.

-spec handle_cast(
    {add_leaks, pid(), taint_abstract_machine:leaks_map()}, state()
) -> {noreply, state()}.
handle_cast({add_leaks, AdderPid, Leaks}, State) ->
    {noreply, add_leaks(Leaks, AdderPid, State)}.

-spec add_leaks(taint_abstract_machine:leaks_map(), pid(), state()) -> state().
add_leaks(
    Leaks, AdderPid, State = #gatherer_state{leaks = StoredLeaks, proclet_pids = ProcletPids, reply_to = ReplyTo}
) ->
    ?LOG_INFO("Got ~p leaks from ~p~n", [maps:size(Leaks), AdderPid]),
    NewLeaks = maps:merge(StoredLeaks, Leaks),
    NewProcletPids = [AdderPid | ProcletPids],
    % If there is someone waiting for gathered leaks and this instance is the
    % last pid we are waiting for, return to that client now, instead of later
    % in the check_progress message
    NewReplyTo =
        case ReplyTo of
            noone ->
                noone;
            {From, RequestedProcletPids} ->
                AllPidsAlreadyAdded = lists:sort(RequestedProcletPids) =:= lists:sort(NewProcletPids),
                if
                    AllPidsAlreadyAdded ->
                        gen_server:reply(From, NewLeaks),
                        noone;
                    true ->
                        ReplyTo
                end
        end,

    State#gatherer_state{
        leaks = NewLeaks,
        reply_to = NewReplyTo,
        proclet_pids = NewProcletPids,
        last_added_time = erlang:monotonic_time()
    }.
