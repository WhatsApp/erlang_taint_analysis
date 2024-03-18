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

-module('two_pids').
-export([
    two_pids_main/0, hibernate_subproc/2, hibernate_main/0,
    not_instrumented_send_main/0
]).

done() ->
  receive 
    done -> ok
  end.

sub_proc(Parent) ->
    Data =
        receive
            {some_info, Var} ->
                io:format("got some info ~p~n", [Var]),
                Var;
            {some_tainted_info, T} ->
                io:format("got some other info~p~n", [T]),
                T
        end,
        finer_taint:sink(Data),
        Parent ! done.

two_pids_main() ->
    Taint = finer_taint:source(42),
    Parent = self(),
    modeled_erlang:real_put(next_taint_pid, 421),
    spawn_link(fun() -> sub_proc(Parent) end) ! {some_tainted_info, Taint},
    modeled_erlang:real_put(next_taint_pid, 422),
    spawn_link(fun() -> sub_proc(Parent) end) ! {some_info, ha},
    done(),
    done(),
    receive 
      never_get_this_msg -> ok
    after
      200 -> finer_taint:sink(Taint)
    end,
    ok.


not_instrumented_send_main() ->
  Parent = self(),
  Taint = finer_taint:source(42),
  modeled_erlang:real_put(next_taint_pid, 431),
  Child = spawn_link(fun() -> sub_proc(Parent) end),
  % This simulates sending a message from uninstrumented code
  erlang:apply(erlang, send, [Child,{some_tainted_info, Taint}]),
  done(),
  ok.

hibernate_subproc(Parent, Tainted) ->
  finer_taint:sink(Tainted),
  receive
    {a_msg, AlsoTainted} -> finer_taint:sink(AlsoTainted)
  end,
  Parent ! done.

hibernate_main() ->
  Parent = self(),
  ParentTaint = finer_taint:source("12344555@phone.net"),
  modeled_erlang:real_put(next_taint_pid, 441),
  Child = spawn(fun() ->
                    Tainted = finer_taint:source(42),
                    erlang:hibernate(?MODULE, hibernate_subproc, [Parent, Tainted])
        end),
  Child ! {a_msg, ParentTaint},
  done(),
  ok.
