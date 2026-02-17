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

-module(taint_server_sup).

-behaviour(supervisor).
-compile(warn_missing_spec_all).

-export([start_link/0]).

-export([init/1]).
-include_lib("taint_server/include/taint_server.hrl").

-define(SERVER, ?MODULE).

-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional
%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional
-spec init(term()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 0,
        period => 1
    },
    InstructionsStreamsPrefix =
        case application:get_env(taint_server, instructions_stream_prefix) of
            {ok, Prefix} ->
                Prefix;
            undefined ->
                {ok, Prefix} = application:get_env(taint_server, instructions_stream_prefix_default),
                Prefix
        end,
    ChildSpecs =
        [
            #{
                id => Id,
                restart => transient,
                % The workers might take a long time to finish processing all messages
                % and writing instructions to disk, so give a generous timeout to
                % prevent forcefully killing them
                shutdown => 50000,
                start =>
                    {abstract_machine_server, start_link, [
                        Id,
                        InstructionsStreamsPrefix
                    ]}
            }
         || Id <- lists:seq(0, ?NUM_WORKERS - 1)
        ],
    {ok, {SupFlags, ChildSpecs}}.
