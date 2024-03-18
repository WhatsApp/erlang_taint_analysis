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

-module('taint_spawn').
-export([
    spawn_info_transfer_main/0, spawn_info_transfer_via_capture_main/0,
    sub_proc1arg/2,
    sub_proc/3
]).

sub_proc(Parent, TaintedArg, NotTaintedArg) ->
    finer_taint:sink(TaintedArg),
    finer_taint:sink(NotTaintedArg),
    Parent ! done.

sub_proc1arg(Parent, Arg) ->
    finer_taint:sink(Arg),
    Parent ! done.

done() ->
    receive
        done -> ok
    end.

spawn_info_transfer_main() ->
    TaintedVal = finer_taint:source(42),
    modeled_erlang:real_put(next_taint_pid, 421),
    spawn_link(taint_spawn, sub_proc, [self(), TaintedVal, notainted]),
    modeled_erlang:real_put(next_taint_pid, 422),
    spawn_link(taint_spawn, sub_proc1arg, [self(), notainted]),
    modeled_erlang:real_put(next_taint_pid, 423),
    spawn_link(taint_spawn, sub_proc1arg, [self(), TaintedVal]),
    modeled_erlang:real_put(next_taint_pid, undefined),
    done(),
    done(),
    done().

spawn_info_transfer_via_capture_main() ->
    TaintedVal = finer_taint:source(42),
    Parent = self(),
    modeled_erlang:real_put(next_taint_pid, 421),
    spawn_link(fun() -> 
                   finer_taint:sink(TaintedVal),
                   Parent ! done 
               end),
    done().
