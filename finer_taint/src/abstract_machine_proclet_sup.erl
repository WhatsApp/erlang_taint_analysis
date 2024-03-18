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
%% @doc
%% Supervisor for abstract_machine_proclets
%%
%% Used to create new proclets and to tell them to stop
%% @end

-module(abstract_machine_proclet_sup).
-compile(warn_missing_spec_all).

-behaviour(supervisor).

-export([start_link/1, new_proclet/1, new_proclet/0, stop_all_proclets/0]).

-export([init/1]).

-spec start_link(map()) -> supervisor:startlink_ret().
start_link(AbstractMachineArgs) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [AbstractMachineArgs]).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional
%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional
-spec init([map()]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([AbstractMachineArgs]) ->
    SupFlags = #{
        strategy => simple_one_for_one,
        intensity => 0,
        period => 1
    },
    ChildSpecs = [
        #{
            id => abstract_machine_proclet,
            start => {abstract_machine_proclet, start_link, [AbstractMachineArgs]},
            % If the proclet dies, the state is lost, no point restarting, the analysis
            % of the process is dead anyway
            restart => temporary,
            % Short shutdown as this supervisor can have a lot of proclets to shutdown
            shutdown => 500
        }
    ],
    {ok, {SupFlags, ChildSpecs}}.

% Creates a new abstract_machine_proclet, used when
% starting to execute a new instruction stream
-spec new_proclet() -> pid().
new_proclet() ->
    new_proclet(taint_gatherer).
-spec new_proclet(gen_server:server_ref()) -> pid().
new_proclet(TaintGatherer) ->
    case supervisor:start_child(?MODULE, [TaintGatherer]) of
        {ok, Pid} when is_pid(Pid) -> Pid
    end.

% Tell all proclets to stop. This method should be called
% before attempting to get leaks from the taint_gatherer
% as leaks will not be reported before proclets terminate.
-spec stop_all_proclets() -> ok.
stop_all_proclets() ->
    Children = supervisor:which_children(?MODULE),
    [ok = abstract_machine_proclet:stop(Pid) || {_, Pid, _, _} <- Children, is_pid(Pid)],
    ok.
