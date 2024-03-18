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
%% Implementation of finer_taint behaviour that writes to stdio
%% Used by tests
-module(ct_finer_taint).

-compile(warn_missing_spec_all).
-behaviour(finer_taint).

%% finer_taint callback.
-export([
    write_instruction/1
]).

-spec write_instruction(taint_abstract_machine:instruction()) -> ok.
write_instruction(Instruction) ->
    io:format("~0p.~n", [Instruction]).
