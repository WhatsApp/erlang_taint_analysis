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
%% A top level supervisor for abstract machines, that starts
%% everything needed for executing multiple taint_abstract_machines
%%
%% NOTE: currently this is missing taint_message_passer initialization
%% @end

-module(online_finer_taint_sup).
-compile(warn_missing_spec_all).

-behaviour(supervisor).

-export([start_link/1, start_link/0]).

-export([init/1]).

-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    start_link(#{}).
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
        strategy => one_for_all,
        intensity => 0,
        period => 1
    },
    ChildSpecs = [
        #{
            id => proclets,
            start => {abstract_machine_proclet_sup, start_link, [AbstractMachineArgs]}
        },
        #{
            id => gatherer,
            start => {taint_gatherer, start_link, []}
        }
    ],
    {ok, {SupFlags, ChildSpecs}}.
