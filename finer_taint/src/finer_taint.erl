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
%% The functions in this file are called by the instrumentation added by the finer_taint_compiler.
%% The main point of this file is that we can change how the instructions are emitted easily
%% by doing in directly in Erlang and not in the abstract forms.
%%
%% The actual writting of the instructions is done by implementing the write_instruction
%% in a behaviour
-module(finer_taint).
-compile(warn_missing_spec_all).

-callback write_instruction(Instruction :: taint_abstract_machine:instruction()) -> ok.

%% marker API
-export([
    source/1, source/2,
    sink/1
]).

%% The emit instruction API.
-export([
    duplicate/2,
    send/2,
    receive_trace/2,
    actual_source/3,
    actual_source/4,
    actual_sink/2,
    push/3,
    pop/2,
    push_scope/5,
    func_ret/3,
    call_fun/5,
    store_var/3,
    get_var/3,
    fun_apply/3,
    construct_pattern/3,
    try_catch/4,
    set_element/5,
    capture_closure/3,
    restore_capture/3,
    deconstruct_pattern/3
]).

-define(INSTRUMENTATION_LOC, "instrumentation").
% SPAWN_FUNCTIONS are a map so we can use is_map_key in guards
-define(SPAWN_FUNCTIONS, #{spawn => ok, spawn_link => ok, spawn_monitor => ok, spawn_opt => ok}).

%% =================== MARKER API  ============================
%% These functions annotate source and sinks and are meant to be
%% placed in the code under analysis by some other method:
%% Either manually or by something like taint_compiler
-spec source(string(), T) -> T.
source(_Tag, X) ->
    X.
-spec source(T) -> T.
source(X) ->
    X.

-spec sink(term()) -> ok.
sink(_Sink) -> ok.

%% =================== EMIT INSTRUCTION API ============================
%%
%% These functions emit the instructions for the abstract machine.  They are
%% the instrumentation inserted by the finer_taint_compiler
%%
%%
%% They take a CallbackModule argument, which is the callback module implementing the
%% write_instruction function.  The finer_taint_compiler should emit
%% instructions with appropriate argument for CallbackModule

-spec actual_source(string(), atom(), term(), T) -> T.
actual_source(Loc, CallbackModule, Tag, X) ->
    pop(Loc, CallbackModule),
    push(Loc, CallbackModule, {Tag, create_taint_value(Loc)}),
    X.
-spec actual_source(string(), atom(), T) -> T.
actual_source(Loc, CallbackModule, X) ->
    pop(Loc, CallbackModule),
    push(Loc, CallbackModule, create_taint_value(Loc)),
    X.

-spec actual_sink(string(), atom()) -> ok.
actual_sink(Loc, CallbackModule) ->
    CallbackModule:write_instruction({sink, {create_taint_value(Loc)}}),
    ok.

-spec push(string(), atom(), string() | {term(), string()}) -> ok.
push(_Loc, CallbackModule, TaintValue) ->
    CallbackModule:write_instruction({push, {TaintValue}}),
    ok.

-spec capture_closure(string(), atom(), [string()]) -> ok.
capture_closure(_Loc, CallbackModule, ClosureVars) ->
    CallbackModule:write_instruction({capture_closure, {ClosureVars}}),
    ok.

-spec restore_capture(string(), atom(), mfa()) -> ok.
restore_capture(Loc, CallbackModule, {Module, Func, Arity}) ->
    CallbackModule:write_instruction({restore_capture, {{Module, Func, Arity}, create_taint_value(Loc)}}),
    ok.

-spec pop(string(), atom()) -> ok.
pop(_Loc, CallbackModule) ->
    CallbackModule:write_instruction({pop, {}}),
    ok.

-spec duplicate(string(), atom()) -> ok.
duplicate(_Loc, CallbackModule) ->
    CallbackModule:write_instruction({duplicate, {}}),
    ok.

%% This is meant to be called just before a send message operation.
%% It needs to "tag" the message, so that we can match it on the receive end.
%% Uses seq_trace, to do the tagging.
-spec send(string(), atom()) -> ok.
send(Loc, CallbackModule) ->
    MessageId = ref_to_list(make_ref()),
    CallbackModule:write_instruction({send, {MessageId, create_taint_value(Loc)}}),
    seq_trace:set_token(label, MessageId),
    ok.

%% Implements the matching of the sent messages on the receive end.
%% Reads the tag set by send() and resets the seq_trace.
-spec receive_trace(string(), atom()) -> ok.
receive_trace(Loc, CallbackModule) ->
    case seq_trace:get_token(label) of
        {label, MessageId} ->
            seq_trace:set_token([]),
            CallbackModule:write_instruction({receive_trace, {MessageId, create_taint_value(Loc)}});
        % Token not set, receiving a message from non instrumented code
        [] ->
            CallbackModule:write_instruction({receive_trace, {nomsg}})
    end,
    ok.

-spec store_var(string(), atom(), string()) -> ok.
store_var(Loc, CallbackModule, VarName) ->
    CallbackModule:write_instruction({store, {VarName, create_taint_value(Loc)}}),
    ok.

-spec get_var(string(), atom(), string()) -> ok.
get_var(Loc, CallbackModule, VarName) ->
    CallbackModule:write_instruction({get, {VarName, create_taint_value(Loc)}}),
    ok.

-spec fun_apply(string(), atom(), {atom(), atom(), integer()}) -> ok.
fun_apply(Loc, CallbackModule, MFA = {erlang, Func, _}) when is_map_key(Func, ?SPAWN_FUNCTIONS) ->
    % push_scope for spawn* functions sets a token, this function is called
    % after spawn returns and must reset the token so the token does not spread further
    seq_trace:set_token([]),
    CallbackModule:write_instruction({apply, {MFA, create_taint_value(Loc)}}),
    ok;
fun_apply(Loc, CallbackModule, MFA) ->
    CallbackModule:write_instruction({apply, {MFA, create_taint_value(Loc)}}),
    ok.

-spec push_scope(string(), atom(), atom(), atom(), integer()) -> ok.
push_scope(Loc, CallbackModule, Module, Function, Arity) ->
    case seq_trace:get_token(label) of
        % Common case, this is a normal function call and not a start of a process
        [] ->
            CallbackModule:write_instruction({push_scope, {{Module, Function, Arity}, create_taint_value(Loc)}}),
            ok;
        % Rare case, this is a start of a process, we need to setup the function arguments
        % Which should have been passed to us as a message with ProcId
        {label, {new_proc, ProcId}} ->
            if
                % Normaly the ProcPid is a string representation of ref()
                % In that case we don't override the taint_pid and let it be randomyl generated
                is_list(ProcId) ->
                    ok;
                % If the parent process set next_taint_pid in process dictonary
                % It will end up in ProcId so we set the taint_pid here
                true ->
                    put(taint_pid, ProcId)
            end,
            % Reset the token so it doesn't spread further
            seq_trace:set_token([]),
            CallbackModule:write_instruction({push_scope, {{Module, Function, Arity}, create_taint_value(Loc)}}),
            % We get the function arguments as tuple of {taint_val(Function), taint_val(Args)}
            CallbackModule:write_instruction({receive_trace, {ProcId, ?INSTRUMENTATION_LOC}}),
            % We deconstruct the tuple to get stack
            % |  taint_val(Args)      |
            % |  taint_val(Function)  | <- Top of the stack
            deconstruct_pattern(Loc, CallbackModule, {tuple, 2}),
            % We use the taint value of the function to restore the potential capture
            % This pushes a scope that is never popped. But in this case that is ok
            % because the only time this scope needs to be popped is then the function
            % getting spawned returns. At that point the process terminates too, so
            % there is no further execution. Therefore we don't have to worry about
            % cleaning this scope
            CallbackModule:write_instruction({restore_capture, {{Module, Function, Arity}, create_taint_value(Loc)}}),
            % We get the function arguments as a list of arguments [Arg1, Arg2, ..., ArgN]
            % waiting for us as a message at ProcId
            % The list should have Arity elements, so we deconstruct it Arity times
            % Cons pattern deconstructs as Head,Tail, so Head is top of the stack
            lists:foreach(
                fun(_) ->
                    CallbackModule:write_instruction({deconstruct_pattern, {{cons}, ?INSTRUMENTATION_LOC}}),
                    %Reverse Head/Tail, so that Tail is top of the stack
                    CallbackModule:write_instruction({store, {"PushScopeTmpHead", ?INSTRUMENTATION_LOC}}),
                    CallbackModule:write_instruction({store, {"PushScopeTmpTail", ?INSTRUMENTATION_LOC}}),
                    CallbackModule:write_instruction({get, {"PushScopeTmpHead", ?INSTRUMENTATION_LOC}}),
                    CallbackModule:write_instruction({get, {"PushScopeTmpTail", ?INSTRUMENTATION_LOC}})
                end,
                lists:seq(1, Arity)
            ),
            % The stack should now be taint_val(Arg1), taint_val(Arg2), ... ,taint_val(ArgN), notaint
            % The notaint either comes from [] or directly from receive_trace if there are no arguments
            % We just pop it off
            CallbackModule:write_instruction({pop, {}}),
            % The function arguments are in the wrong order Arg1 is expected to be on top of the stack
            % we reverse Arity elements
            StoredVars = lists:map(
                fun(Idx) ->
                    TmpVarName = "PushScopeTmp-" ++ integer_to_list(Idx),
                    CallbackModule:write_instruction({store, {TmpVarName, ?INSTRUMENTATION_LOC}}),
                    TmpVarName
                end,
                lists:seq(1, Arity)
            ),
            lists:foreach(
                fun(TmpVarName) ->
                    CallbackModule:write_instruction({get, {TmpVarName, ?INSTRUMENTATION_LOC}})
                end,
                StoredVars
            );
        % {label, Ref} when is_string(Ref) case indicates the process got a message according
        % to the seq_trace mechanism. This is not expected at a start of functions, but it could
        % happen. For example if a message arrived early. It could also indicate the seq_trace
        % passed through uninstrumented code and should not have ended up here.
        % Note: For now we ignore this case
        {label, Ref} when is_list(Ref) ->
            seq_trace:set_token([]),
            CallbackModule:write_instruction({push_scope, {{Module, Function, Arity}, create_taint_value(Loc)}}),
            ok
    end,
    ok.

-spec func_ret(string(), atom(), atom()) -> ok.
func_ret(Loc, CallbackModule, Function) ->
    CallbackModule:write_instruction({func_ret, {Function, create_taint_value(Loc)}}),
    ok.

-spec call_fun(string(), atom(), atom(), atom(), integer()) -> ok.
call_fun(Loc, CallbackModule, erlang, Function, Arity) when is_map_key(Function, ?SPAWN_FUNCTIONS) ->
    TempVarNames = ["CfnArg1", "CfnArg2", "CfnArg3"],

    ImaginaryArity =
        if
            % For spawn function with arity 1 or 2, we only have the taint value for Function arguments
            % and not the args, so we invent a notaint value for the Args to keep the rest of this logic consistent
            Arity == 1 ->
                CallbackModule:write_instruction({store, {"Cfn1Arg0", ?INSTRUMENTATION_LOC}}),
                CallbackModule:write_instruction({push, {notaint}}),
                CallbackModule:write_instruction({get, {"Cfn1Arg0", ?INSTRUMENTATION_LOC}}),
                2;
            Arity == 2 ->
                CallbackModule:write_instruction({store, {"Cfn1Arg0", ?INSTRUMENTATION_LOC}}),
                CallbackModule:write_instruction({store, {"Cfn1Arg1", ?INSTRUMENTATION_LOC}}),
                CallbackModule:write_instruction({push, {notaint}}),
                CallbackModule:write_instruction({get, {"Cfn1Arg1", ?INSTRUMENTATION_LOC}}),
                CallbackModule:write_instruction({get, {"Cfn1Arg0", ?INSTRUMENTATION_LOC}}),
                3;
            true ->
                Arity
        end,
    % Stack looks like
    % |  taint_val(ArgArity)    | ie. taint_val(Args)
    % |  taint_val(ArgArity-1)  | ie. taint_val(Function)
    % |      ....               |
    % |  taint_val(Arg1)        | <- Top of the stack
    %
    %
    % We want the taint_val of ArgArity and ArgArity-1,
    % ArgArity-1 is the `Function` argument, potentially
    % containing the lambda capture taint val
    % ArgArity is the last argument to
    % the spawn function, which contains the arguments
    % for the called function see:
    % https://www.erlang.org/doc/man/erlang.html#spawn-2
    %
    % So we store the taint values Arg1 .. ArgArity-1 to TempVariables

    NumberOfArgsToStore =
        case Function of
            %spawn_opt has second to last argument as Args
            spawn_opt -> max(0, ImaginaryArity - 3);
            %All other spawn function have Args as last argument
            _ -> max(0, ImaginaryArity - 2)
        end,

    {TempVarNames1, _} = lists:split(NumberOfArgsToStore, TempVarNames),
    lists:foreach(
        fun(TmpVarName) ->
            CallbackModule:write_instruction({store, {TmpVarName, ?INSTRUMENTATION_LOC}})
        end,
        TempVarNames1
    ),
    % Stack looks like
    % |  taint_val(Args)      |
    % |  taint_val(Function)  | <- Top of the stack

    % Construct/Destruct pattern reverse the order of elements, so we reverse
    % the order of tuple elements here, so they get deconstructed in the correct
    % order
    CallbackModule:write_instruction({store, {"Cfn1Arg0", ?INSTRUMENTATION_LOC}}),
    CallbackModule:write_instruction({store, {"Cfn1Arg1", ?INSTRUMENTATION_LOC}}),
    CallbackModule:write_instruction({get, {"Cfn1Arg0", ?INSTRUMENTATION_LOC}}),
    CallbackModule:write_instruction({get, {"Cfn1Arg1", ?INSTRUMENTATION_LOC}}),
    % Stack looks like
    % |  taint_val(Function)      |
    % |  taint_val(Args)  | <- Top of the stack
    construct_pattern(Loc, CallbackModule, {tuple, 2}),
    CallbackModule:write_instruction({duplicate, {}}),
    % Stack looks like
    % |taint_val({Function, Args}) |
    % |taint_val({Function, Args}) |
    RestoreVars = TempVarNames1,
    ProcId =
        case get(next_taint_pid) of
            undefined ->
                ref_to_list(make_ref());
            [Pid] ->
                put(next_taint_pid, undefined),
                Pid;
            [FirstPid | Tail] ->
                put(next_taint_pid, Tail),
                FirstPid;
            Pid ->
                Pid
        end,
    CallbackModule:write_instruction({send, {ProcId, ?INSTRUMENTATION_LOC}}),
    deconstruct_pattern(Loc, CallbackModule, {tuple, 2}),
    if
        Arity /= ImaginaryArity ->
            % This is not 100% correct as it should pop the value we made up (the last one)
            % But for the spawn function we ignore all the other taint values so it
            % doesn't matter and there is no need to complicate this more
            CallbackModule:write_instruction({pop, {}});
        true ->
            ok
    end,
    % Stack looks like
    % |  taint_val(Args)      |
    % |  taint_val(Function)  | <- Top of the stack
    lists:foreach(
        fun(TmpVarName) ->
            CallbackModule:write_instruction({get, {TmpVarName, ?INSTRUMENTATION_LOC}})
        end,
        lists:reverse(RestoreVars)
    ),
    CallbackModule:write_instruction({call_fun, {erlang, Function, Arity}, create_taint_value(Loc)}),
    seq_trace:set_token(label, {new_proc, ProcId}),
    ok;
call_fun(Loc, CallbackModule, Module, Function, Arity) ->
    CallbackModule:write_instruction({call_fun, {Module, Function, Arity}, create_taint_value(Loc)}),
    ok.

-spec construct_pattern(string(), atom(), taint_abstract_machine:construct_pattern_types()) -> ok.
construct_pattern(Loc, CallbackModule, {map, Keys}) ->
    FilteredKeys = lists:map(fun pid_to_str/1, Keys),
    CallbackModule:write_instruction({construct_pattern, {{map, FilteredKeys}, create_taint_value(Loc)}}),
    ok;
construct_pattern(Loc, CallbackModule, Pattern) ->
    CallbackModule:write_instruction({construct_pattern, {Pattern, create_taint_value(Loc)}}),
    ok.

-spec deconstruct_pattern(string(), atom(), taint_abstract_machine:deconstruct_pattern_types()) -> ok.
deconstruct_pattern(Loc, CallbackModule, Pattern) ->
    CallbackModule:write_instruction({deconstruct_pattern, {Pattern, create_taint_value(Loc)}}),
    ok.

-spec try_catch(string(), atom(), taint_abstract_machine:try_catch_state(), tuple()) -> ok.
try_catch(Loc, CallbackModule, Status, TryBlockId) ->
    CallbackModule:write_instruction({try_catch, {Status, TryBlockId}, Loc}),
    ok.

-spec set_element(string(), atom(), integer(), tuple(), term()) -> tuple().
set_element(Loc, CallbackModule, Index, Tuple, Value) ->
    CallbackModule:write_instruction({set_element, {Index, erlang:tuple_size(Tuple), create_taint_value(Loc)}}),
    erlang:setelement(Index, Tuple, Value).

%% =================== HELPERS  ============================
-spec create_taint_value(string()) -> string().
create_taint_value(Loc) ->
    Loc.

-spec pid_to_str(pid() | string()) -> string().
pid_to_str(K) when is_pid(K) -> "a pid";
pid_to_str(K) -> K.
