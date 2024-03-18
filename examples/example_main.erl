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

-module(example_main).

-export([
    main/1
]).

% This module is the runner of the examples. It sets up the dynamic component of the analysis
% and runs the examples. Note that this file is excluded from being instrumented


main(["non-online-mode" | Args]) ->
	finer_taint_compiler:instrument_known_stdlibs([{finer_taint_module, parallel_finer_taint}]),
  {ok, _} = application:ensure_all_started(taint_server),

  main_impl(Args),
  application:stop(taint_server);
main(Args) ->
  % logger:set_primary_config(level, info), %Uncommenting this and setting tracing => true
  % Will show the execution of the abstract machine (very verbose)
  {ok, SupPid} = online_finer_taint_sup:start_link(
      #{ lineage_mode => false, tracing => false }
  ),
  application:set_env(taint_server, instructions_stream_prefix, "/dev/null"),
  {ok, _} = application:ensure_all_started(taint_server),
	finer_taint_compiler:instrument_known_stdlibs([{finer_taint_module, online_finer_taint}]),

  main_impl(Args),

  io:format("Processing analysis results~n"),
  true = is_process_alive(SupPid),
	% Stop all proclets, thus telling them they won't get any new instructions
  abstract_machine_proclet_sup:stop_all_proclets(),
  io:format("Initiated stopping proclets, gathering (20s timeout) ~n"),
  Dataflows = taint_gatherer:get_gathered_leaks(taint_gatherer, 20000, [notapid]),
  
  io:format("Dataflows found: ~p~n", [Dataflows]),
  Output = taint_abstract_machine:map_leaks_to_leaks(Dataflows),
  io:format("Done gathering~n"),
	io:format("Dataflows found: ~p~n", [Output]).


main_impl(["simple"]) ->
  simple_example:simple_example_main();
main_impl([Arg]) ->
  example_gen_server:gen_server_main(Arg);
main_impl(Args) ->
	% Preamble to setup taint analysis runtime component
  io:format("Unknown arguments ~p running simple example", [Args]),
  main_impl(["simple"]).
