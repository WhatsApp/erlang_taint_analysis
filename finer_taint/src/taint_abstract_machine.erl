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
%%% Runs the instructions emitted by running a program instrumented with finer_taint_compiler to
%%% compute the result of the analysis and find the leaks
-module(taint_abstract_machine).
-compile(warn_missing_spec_all).
-compile({inline, [taint_value/1]}).

-include_lib("kernel/include/logger.hrl").

%% The client API.
-export([
    get_leaks/1,
    get_leaks_as_map/1,
    map_leaks_to_leaks/1,
    get_stack/1,
    is_no_taint/1,
    run_tracing/1,
    init_state/1,
    propagate/2,
    propagate_cov/3,
    get_taint_sources/2
]).
-export_type([
    taint_value/0,
    leaks/0,
    leaks_map/0,
    state/0,
    taint_history/0,
    taint_history_point/0,
    instruction/0,
    construct_pattern_types/0,
    deconstruct_pattern_types/0,
    dataflow_map/0,
    models/0,
    try_catch_state/0
]).

-include_lib("finer_taint/include/non_lineage_modules.hrl").

% lineage_point represents an argument of a function, mfa() identifies the function
% and integer() is the argument number starting with 1
-type lineage_point() :: {mfa(), integer()}.

-type taint_source() ::
    % arg_taint is similar to source, but it is not neccessarly the begining
    % of taint_history. That is multiple arg_taint points can be found
    % in a single history
    {arg_taint, lineage_point()}
    % The source location where this history started.
    | {tagged_source, string(), string()}
    | annot_dataflow_src()
    | {source, string()}.

% taint_history_point() represent a point in the history of a taint value.
% strings() are usually in the format: some_file.erl:<line number>
-type taint_history_point() ::
    % A source location where the taint value was
    {step, string()}
    % Represent a point where multiple taint_values were put
    % in a pattern and therefore multiple histories merge
    | {joined_history, pattern, [taint_history()]}
    | {joined_history, model, [taint_history()]}
    | {joined_history, lambda_closure, [taint_history()]}
    % Represent a point where the value was passed via a message
    | {message_pass, string()}
    % {call_site, MFA, Loc} Represents a point in history where the value was
    % used in a function call to Function/Arity at a source location `Loc`
    % `Loc` is in <module_name>.erl:<line_number> format
    | {call_site, mfa(), string()}
    % {return_site,MFA, Loc} Represents a point in history where the value was
    % returned to source location Loc from MFA function call.
    % The Loc should match the one call_site history point
    | {return_site, mfa(), string()}
    % Represents a point in history of the taint value where the value
    % traveled outside of the instrumented code. Therefore we don't
    % know what happned to it. In order to improve scalablity  we drop
    % the full history and just keep the taint sources that went into it
    % This is probably ok, because the full history is unknown anyway
    | {blackhole, [taint_source()]}
    | taint_source().

-type taint_history() :: [taint_history_point()].
-type taint_value() ::
    % untainted value
    {notaint, []}
    %A normal tainted values
    | {taint, taint_history()}
    % Represents a taint value of a function. The only function that
    % can be tainted are lambdas, because they can containt captured
    % variables. {lambda_closure, Scope} stores all the captured
    % taint variables in the Scope. The scope needs to be restored
    % via restore_capture instruction when the function is called.
    | {lambda_closure, scopes_map()}
    % A taint value of patterns
    % For tuple {Val1, Val2, ..., ValN}, the taint value will look like
    % {pattern_taint, tuple, [ValN, ValN-1, ..., Val1]}
    | {pattern_taint, tuple, [taint_value()]}
    % the elements of the pattern are just put in a list in the same order
    | {pattern_taint, cons, [taint_value()]}
    % The [number()] containts the byte sizes of taint values
    | {pattern_taint, {bitstring, [number()]}, [taint_value()]}
    % For map #{Key => Value} the corresponding taint_value looks like
    % #{Key => Taint(Value), abstract_machine_mapkey_taints => #{Key => Taint(Value)}
    | {pattern_taint, map, #{term() => #{term() => taint_value()} | taint_value()}}.

-type scopes_map() :: #{string() => taint_value()}.

-type function_arity() :: {atom(), integer()}.

% Contains {Size, TSL} tuple, more info on TSL here:
% https://www.erlang.org/doc/apps/erts/absform.html#bitstring-element-type-specifiers
-type bin_pattern_segment() :: {integer() | default, [atom()]}.
-type deconstruct_pattern_types() ::
    % For destructing the bitstring pattern we also have the TSL
    % in addition to size in bin_pattern_segment()
    {bitstring, [bin_pattern_segment()]}
    | pattern_types_shared().
-type construct_pattern_types() ::
    % When constructing the bitstring pattern we pass in the byte sizes of each segment
    {bitstring, [number()]}
    | pattern_types_shared().
-type pattern_types_shared() ::
    % map has a list of Keys
    {map, [string()]}
    % tuple has arity, ie the number of elements in the tuple
    | {tuple, number()}
    % Cons is always just a head and a tail
    | {cons}.

-type try_block_id() :: {module(), integer()}.
-type try_marker() :: {try_enter, try_block_id()}.
-type try_catch_state() ::
    % Indicates try block entry. That is exceptions
    % after this point should be caught by this try/catch expression
    try_enter
    % Indicates try block exit. That is exceptions should no longer
    % be caught by this try/catch block
    | try_exit
    % Indicates catch entry, that is exception was caught by this catch block
    | catch_enter.
% The last argument of instructions is always a source location
-type instruction() ::
    % Push TaintVal instruction - push TaintVal to the stack.
    {push, {notaint | string() | {string(), string()}}}
    % Pop instruction - pop a taint value off the stack
    | {pop, {}}
    % Duplicate instruction - Duplicate the top of the stack
    | {duplicate, {}}
    % Pop a value of the stack and check if it's tainted
    | {sink, {string()}}
    % Get Varname instruction - lookup Varname in the scopes and push its value to the stack
    | {get, {string(), string()}}
    % Pop top of the stack and send it as MessageId
    | {send, {MessageId :: string(), string()}}
    % Receive messageID and push it onto the stack, assume notaint if nomsg
    | {receive_trace, {MessageId :: string(), string()}}
    | {receive_trace, {nomsg}}
    % Apply {M,F,A} - apply M(odule):F(unction)/A(rity) function
    | {apply, {mfa(), string()}}
    % Construct PatternType instruction - Pop values needed by PatternType of the stack
    % and construct a pattern taint value of PatternType
    | {construct_pattern, {construct_pattern_types(), string()}}
    % Deconstruct PatternType - pop a pattern taint value of the stack and
    % push consitutients of PatternType to the stack
    | {deconstruct_pattern, {deconstruct_pattern_types(), string()}}
    % Instruction to handle try/catch blocks
    | {try_catch, {try_catch_state(), try_block_id()}, string()}
    % Expecting to call a function, used to determine if the stack is setup correctly,
    % The stack can be setup incorrectly if the called function is not instrumented,
    % but calls an instrumented function
    | {call_fun, mfa(), string()}
    % Push_Scope FunctionName - push a new scope for the FunctionName function
    | {push_scope, {mfa(), string()}}
    % Func_Ret FunctionName - Return from FunctionName, mostly just pops the scope
    | {func_ret, {string(), string()}}
    % capture/restore_closure functions are used to implement capturing of values
    % by lambdas.
    % Capture_Closure VariableNames - Store all taint values of Variables in VariableNames
    % into a {lambda_closur, Scope} taint value and push it onto the stack
    | {capture_closure, {[string()]}}
    % Pops a value of the stack, if untainted push an empty scope
    % If the value is {lambda_closure, Scope}, push the Scope
    | {restore_capture, {mfa(), string()}}
    % Store VarName - Pop a value of the stack and store it in scope with VarName
    | {store, {string(), string()}}
    | {set_element, {integer(), integer(), string()}}.
-type leak() ::
    % Leak in normal mode  {leak, Sink, History}
    {leak, string(), taint_history()}
    % Leak in coverage mode. Contains a set of all locations the taint value passed through
    | {coverage_leak, string()}
    % Leak in lineage mode to integer() argument of mfa()
    | {arg_leak, {mfa(), integer(), string()}, taint_history()}
    % Similar to arg_leak, but instead of full taint history,
    % it contains a set (dataflow_map) of all the dataflow_src-es
    % that ended up in this argument.
    | {{arg_dataflow, {mfa(), integer(), string()}}, annot_dataflow_src()}
    | {arg_dataflow, {mfa(), integer(), string()}, dataflow_map()}.
-type leaks() :: [leak()].

% Similar to {arg_taint, lineage_point()}, but also containts some taint_history
% that can be used for annotations. The taint history is usually not fully detailed
-type annot_dataflow_src() :: {dataflow_src, lineage_point(), taint_history()}.
% Each key in a map represent some dataflow from lineage_point() via taint_history()
% taint_history() might be reduced. This is a map for dedpulication and efficency
-type dataflow_map() :: #{annot_dataflow_src() => ok}.
-type leaks_map() :: #{leak() => ok}.

-type scopes() :: [scopes_map() | try_marker() | #{mfa() => taint_value()}].
-type stack() :: [taint_value() | try_marker()].
-type models() :: #{{module(), atom()} => sanitize | propagate}.

% false -> don't run in lineage mode
% line_history -> run lineage mode with lineage containing the line_history history (ie. every executed line)
% This is very expensive and not practical for our code
% function_history -> run lineage mode containing only the history of arguments
% Both lineage modes give the same lineage edges, however line_history mode enables
% one to use `-query-arg-lineage' in run_lineage_escript to find the full history of an edge.
% This is useful for debugging why and edge is reported
-type lineage_mode() :: false | line_history | function_history | coverage.
-type lineage_modules_denylist() :: #{module() => ok}.

-record(taint_am_state, {
    stack = [] :: stack(),
    scopes = [#{}] :: scopes(),
    process_dict = {pattern_taint, map, #{}} :: taint_value(),
    instrumented_return = [] :: [function_arity() | true | try_marker()],
    leaks = [] :: leaks(),
    % Lineage is not reported for functions for modules in this map
    lineage_modules_denymap = #{} :: lineage_modules_denylist(),
    lineage_mode = false :: lineage_mode(),
    models = #{} :: models()
}).

-type state() :: #taint_am_state{}.

-define(NOT_TRY_ENTER(TaintValue), element(1, TaintValue) =/= try_enter).

%% Run the abstract machine, printing instructions and state for every step
%% Only useful for debugging. Real users of the taint machine
%% should run it via abstract_machine_proclet gen_server
-spec run_tracing(string()) -> state().
run_tracing(Filepath) ->
    Basename = filename:basename(Filepath),
    run(
        Filepath,
        fun(Instruction, State) ->
            io:format("~s executing ~p~n~p~n==========~n", [
                Basename, Instruction, State
            ]),
            propagate(Instruction, State)
        end,
        #taint_am_state{}
    ).

-spec init_state(map()) -> state().
init_state(Args) when is_map(Args) ->
    Models = maps:get(taint_models, Args, abstract_machine_util:get_priv_models()),
    #taint_am_state{
        models = Models,
        lineage_mode = maps:get(lineage_mode, Args, false),
        lineage_modules_denymap = maps:merge(
            maps:get(
                lineage_modules_denymap,
                Args,
                #{}
            ),
            maps:from_keys(?BASE_NON_LINEAGE_MODULES, ok)
        )
    }.

-spec run(string(), fun((instruction(), state()) -> state()), state()) ->
    state().
run(Filepath, PropagateFunction, InitState) ->
    {ok, Instructions} = file:consult(Filepath),
    lists:foldl(PropagateFunction, InitState, Instructions).

-spec map_leaks_to_leaks(leaks_map()) -> leaks().
map_leaks_to_leaks(MapLeaks) ->
    maps:fold(
        fun
            ({{arg_dataflow, {MFA, N, Loc}}, Src}, ok, Acc) ->
                [{arg_leak, {MFA, N, Loc}, [Src]} | Acc];
            (L = {arg_leak, _, _}, ok, Acc) ->
                [L | Acc];
            (L = {leak, _, _}, ok, Acc) ->
                [L | Acc];
            (L = {coverage_leak, _}, ok, Acc) ->
                [L | Acc]
        end,
        [],
        MapLeaks
    ).

-spec leaks_as_map_folder(leak(), leaks_map()) -> leaks_map().
leaks_as_map_folder({arg_dataflow, {MFA, N, Loc}, TaintedArgs}, LeaksAcc) when is_map(TaintedArgs) ->
    NewDataflows = maps:fold(
        fun(Src = {dataflow_src, _MFAN, _Annotations}, ok, InnerLeaksAcc) ->
            InnerLeaksAcc#{{{arg_dataflow, {MFA, N, Loc}}, Src} => ok}
        end,
        #{},
        TaintedArgs
    ),
    maps:merge(NewDataflows, LeaksAcc);
leaks_as_map_folder(L = {leak, _Sink, _History}, LeaksAcc) ->
    LeaksAcc#{L => ok};
leaks_as_map_folder(L = {arg_leak, _Sink, _History}, LeaksAcc) ->
    LeaksAcc#{L => ok};
leaks_as_map_folder(L = {coverage_leak, _}, LeaksAcc) ->
    LeaksAcc#{L => ok}.

-spec get_leaks_as_map(state()) -> leaks_map().
get_leaks_as_map(#taint_am_state{leaks = Leaks}) ->
    lists:foldl(
        fun leaks_as_map_folder/2,
        #{},
        Leaks
    ).

-spec get_leaks(state()) -> leaks().
get_leaks(#taint_am_state{leaks = Leaks}) ->
    Leaks.

-spec get_stack(state()) -> stack().
get_stack(#taint_am_state{stack = Stack}) -> Stack.

-spec history_folder(term(), #{term() => taint_value()} | taint_value(), [taint_history()]) -> [taint_history()].
history_folder(abstract_machine_mapkey_taints, KeyTaintMap, Acc) when is_map(KeyTaintMap) ->
    maps:fold(
        fun
            (_Key, {notaint, []}, AccInner) -> AccInner;
            (_Key, Value, AccInner) -> [get_history(Value) | AccInner]
        end,
        Acc,
        KeyTaintMap
    );
history_folder(_Key, {notaint, []}, Acc) ->
    Acc;
history_folder(_, Value, Acc) when not is_map(Value) ->
    [get_history(Value) | Acc].

-spec history_filter(taint_value()) -> {true, taint_history()} | false.
history_filter(TaintVal) ->
    case get_history(TaintVal) of
        [] -> false;
        History -> {true, History}
    end.

-spec get_history(taint_value()) -> taint_history().
get_history({lambda_closure, Closure}) ->
    Histories = maps:fold(fun history_folder/3, [], Closure),
    case Histories of
        % Lambdas can capture just untainted values
        [] -> [];
        [OneHistory] -> OneHistory;
        Histories = [_ | _] -> [{joined_history, lambda_closure, Histories}]
    end;
get_history({notaint, []}) ->
    [];
get_history({pattern_taint, map, MapVals}) when is_map(MapVals) ->
    Histories = maps:fold(fun history_folder/3, [], MapVals),
    case Histories of
        % Lambdas can capture just untainted values
        [] -> [];
        [OneHistory] -> OneHistory;
        Histories = [_ | _] -> [{joined_history, pattern, Histories}]
    end;
get_history({pattern_taint, _Type, PatternVals}) ->
    case lists:filtermap(fun history_filter/1, PatternVals) of
        % Lambdas can capture just untainted values
        [] -> [];
        [OneHistory] -> OneHistory;
        Histories = [_ | _] -> [{joined_history, pattern, Histories}]
    end;
get_history({taint, History}) ->
    History.

-spec add_arg_taint(taint_value(), lineage_point(), string()) -> taint_value().
add_arg_taint({notaint, _}, MFAN = {{M, F, A}, _}, Loc) ->
    {taint, [{arg_taint, MFAN}, {call_site, {M, F, A}, Loc}]};
add_arg_taint(TaintValue, MFAN, _) ->
    append_taint_history_base(TaintValue, {arg_taint, MFAN}).

-spec append_taint_history(taint_value(), string()) -> taint_value().
append_taint_history(Value, Loc) ->
    append_taint_history_base(Value, {step, Loc}).

-spec append_taint_history_base(taint_value(), taint_history_point()) -> taint_value().

append_taint_history_base({lambda_closure, ScopesMap}, HistoryPoint) ->
    NewScopesMap = maps:map(
        fun(_K, V) ->
            append_taint_history_base(V, HistoryPoint)
        end,
        ScopesMap
    ),

    {lambda_closure, NewScopesMap};
append_taint_history_base(T = {notaint, _}, _HistoryPoint) ->
    T;
append_taint_history_base({pattern_taint, map, MapVal}, HistoryPoint) when is_map(MapVal) ->
    NewMapVal = maps:filtermap(
        fun
            (abstract_machine_mapkey_taints, KeyTaintMap) when is_map(KeyTaintMap) ->
                {true,
                    maps:filtermap(
                        fun(_K, V) -> {true, append_taint_history_base(V, HistoryPoint)} end, KeyTaintMap
                    )};
            (_K, V) ->
                if
                    not is_map(V) -> {true, append_taint_history_base(V, HistoryPoint)}
                end
        end,
        MapVal
    ),
    {pattern_taint, map, NewMapVal};
append_taint_history_base({pattern_taint, tuple, PatternVals}, HistoryPoint) when is_list(PatternVals) ->
    {pattern_taint, tuple, lists:map(fun(V) -> append_taint_history_base(V, HistoryPoint) end, PatternVals)};
append_taint_history_base({pattern_taint, cons, PatternVals}, HistoryPoint) when is_list(PatternVals) ->
    {pattern_taint, cons, lists:map(fun(V) -> append_taint_history_base(V, HistoryPoint) end, PatternVals)};
append_taint_history_base({pattern_taint, {bitstring, Bs}, PatternVals}, HistoryPoint) when is_list(PatternVals) ->
    {pattern_taint, {bitstring, Bs}, lists:map(fun(V) -> append_taint_history_base(V, HistoryPoint) end, PatternVals)};
append_taint_history_base({taint, History}, HistoryPoint) ->
    {taint, [HistoryPoint | History]}.

-spec map_value_lineage_folder(
    term(),
    #{term() => taint_value()} | taint_value(),
    taint_history()
) -> taint_history().
map_value_lineage_folder(abstract_machine_mapkey_taints, KeyTaintMap, Acc) when is_map(KeyTaintMap) ->
    maps:fold(
        fun(_Key, Value, AccInner) -> get_tainted_args(Value) ++ AccInner end,
        Acc,
        KeyTaintMap
    );
map_value_lineage_folder(_, Value, Acc) when not is_map(Value) ->
    get_tainted_args(Value) ++ Acc.

%% Traverses the history outputs a filtered history
%% that only containts [{arg_taint, _}]
-spec extract_tainted_args(taint_history()) -> taint_history().
extract_tainted_args(History) ->
    lists:filter(
        fun
            ({arg_taint, _}) -> true;
            (_) -> false
        end,
        get_taint_sources(History, [])
    ).

%% Traverses the history of taint_value() and outputs a history
%% that only contains [{arg_taint, _}]
-spec get_tainted_args(taint_value()) -> taint_history().
get_tainted_args({notaint, []}) ->
    [];
get_tainted_args({pattern_taint, map, MapVals}) ->
    lists:flatten(maps:fold(fun map_value_lineage_folder/3, [], MapVals));
get_tainted_args({pattern_taint, _Type, PatternVals}) ->
    lists:flatten(lists:map(fun get_tainted_args/1, PatternVals));
get_tainted_args({lambda_closure, _History}) ->
    [];
get_tainted_args({taint, History}) ->
    extract_tainted_args(History).

-spec is_no_taint(taint_value()) -> boolean().
is_no_taint({notaint, _}) -> true;
is_no_taint(_) -> false.

-spec is_in_scope(mfa() | string(), scopes()) -> boolean().
is_in_scope(_, []) ->
    false;
is_in_scope(VarName, [TopScope | _]) when is_map_key(VarName, TopScope) ->
    true;
is_in_scope(VarName, [_ | Scopes]) ->
    is_in_scope(VarName, Scopes).

-spec find_in_scope(mfa() | string(), scopes()) -> taint_value().
find_in_scope(VarName, [{try_enter, _} | Scopes]) ->
    find_in_scope(VarName, Scopes);
% Assume untainted if not found in scope. This happens
% if a {notaint, []} lambda closure is restored and
% the lambda then lookups up a captured variable.
% One example of lambda closure becoming {notaint, []} is when
% the receive_trace times out and returns {notaint, []}
find_in_scope(_VarName, []) ->
    {notaint, []};
find_in_scope(VarName, [TopScope | Scopes]) when is_map(TopScope) ->
    case maps:get(VarName, TopScope, notfound) of
        notfound -> find_in_scope(VarName, Scopes);
        Value -> Value
    end.
%If there are no scopes left, this crashes because it shouldn't happen
%

-spec insert_in_scope(string(), taint_value(), scopes()) -> scopes().
insert_in_scope(VarName, Value, [Te = {try_enter, _} | Scopes]) ->
    [Te | insert_in_scope(VarName, Value, Scopes)];
insert_in_scope(VarName, Value, [Vars | Scopes]) ->
    % eqwalizer:ignore - we assume that Vars :: scopes_map() here
    [Vars#{VarName => Value} | Scopes].

% Same as propagate, except that for all instructions whose
% location matches Prefix, replace the top of the stack
% with a tainted value if it's not tainted already. This
% is useful to track all taint originating from a module
-spec propagate_cov(instruction(), state(), string()) -> state().
propagate_cov(Inst, State, Prefix) ->
    NewState = propagate(Inst, State),
    Loc =
        case Inst of
            {capture_closure, _} -> "";
            {_, {L}} when is_list(L) -> L;
            {_, {_, L}} when is_list(L) -> L;
            {_, _, L} when is_list(L) -> L;
            _ -> ""
        end,
    case {NewState#taint_am_state.stack, string:prefix(Loc, Prefix)} of
        {[{notaint, []} | Tail], Lc} when is_list(Lc) ->
            NewState#taint_am_state{stack = [{taint, [{source, Loc}]} | Tail]};
        _ ->
            NewState
    end.

-spec propagate(instruction(), state()) -> state().
propagate({duplicate, {}}, State = #taint_am_state{stack = [First | Stack]}) ->
    State#taint_am_state{stack = [First, First | Stack]};
% Push a no taint value to the stack
propagate({push, {notaint}}, State = #taint_am_state{stack = Stack}) ->
    State#taint_am_state{stack = [{notaint, []} | Stack]};
% Push tagged taint value onto the stack in non-lineage mode
propagate({push, {{Tag, SourceLoc}}}, State = #taint_am_state{stack = Stack, lineage_mode = false}) when
    is_list(Tag), is_list(SourceLoc)
->
    State#taint_am_state{stack = [{taint, [{tagged_source, Tag, SourceLoc}]} | Stack]};
% Push a taint value onto the stack in non-lineage mode
propagate({push, {Source}}, State = #taint_am_state{stack = Stack, lineage_mode = false}) when is_list(Source) ->
    State#taint_am_state{stack = [{taint, [{source, Source}]} | Stack]};
% Ignore tainted values in lineage mode
propagate({push, {_}}, State = #taint_am_state{stack = Stack}) ->
    State#taint_am_state{stack = [{notaint, []} | Stack]};
%% Pop a taint value from the stack and discard it
propagate({pop, {}}, State = #taint_am_state{stack = [_ | Stack]}) ->
    State#taint_am_state{stack = Stack};
%% Push the message to the message passer, leave the message on top of the stack
propagate({send, {MsgId, Loc}}, State = #taint_am_state{stack = [MsgTaintVal, _PidTaintVal | Stack]}) ->
    if
        ?NOT_TRY_ENTER(MsgTaintVal) ->
            taint_message_passer:set(MsgId, append_taint_history_base(taint_value(MsgTaintVal), {message_pass, Loc}))
    end,
    %The return value of send operation is the message, so we leave it on top of the stack
    State#taint_am_state{stack = [MsgTaintVal | Stack]};
% Wait until the message becomes available in the message passer, push it onto the stack
propagate({receive_trace, {nomsg}}, State = #taint_am_state{stack = Stack}) ->
    io:format("Not intstrumented message receive~n"),
    State#taint_am_state{stack = [{notaint, []} | Stack]};
propagate({receive_trace, {MsgId, Loc}}, State = #taint_am_state{stack = Stack}) ->
    TaintMsg0 = taint_message_passer:blocking_get(MsgId),
    TaintMsg = append_taint_history(TaintMsg0, Loc),
    State#taint_am_state{stack = [TaintMsg | Stack]};
% Pop a value ofthe stack and push a scope. If the popped value is a {lambda_closure, Scope},
% push Scope as the scope, otherwise push an empty scope. This function should be called
% before a lambda is potentially executed, to setup the variables captured by the lambda
propagate(
    {restore_capture, {{Module, Function, Arity}, Loc}},
    State = #taint_am_state{stack = [Capture | Stack], scopes = Vars}
) when
    ?NOT_TRY_ENTER(Capture)
->
    % Note: maybe add a marker to taint history that it went through restore_capture
    % eqwalizer:fixme handle negative guard above T192344722
    Capture1 = append_taint_history_base(Capture, {call_site, {Module, Function, Arity}, Loc}),
    NewScope =
        case Capture1 of
            {lambda_closure, LambdaCapture} -> [LambdaCapture | Vars];
            % The Capture could be a {taint, ...} value in the lineage case
            _ -> [#{} | Vars]
        end,
    State#taint_am_state{stack = Stack, scopes = NewScope};
% Capture the variables captured by a lambda.
%
% Note that VariableNames contains all the variable names a lambda uses, some
% of which may be arguments or local variables. The capture_closure instruction
% is called in the creator of the lambda, so the variables local to the lambda
% are not in scope, because the lambda scope hasn't been created yet.
% Therefore we only capture variables that are in the scope of the creator, which
% are the variables captured by the lambda due to no shadowing assumption.
% This is done to simplify the process as we don't have to statically determine
% which varibale is captured and which is local to the lambda
propagate({capture_closure, {VariableNames}}, State = #taint_am_state{stack = Stack, scopes = Vars}) ->
    LambdaCapture = lists:foldl(
        fun(VarName, Acc) ->
            case is_in_scope(VarName, Vars) of
                % The variable in a lambda is not in scope, which means
                % it's either a lambda local variable or a lambda's argument
                % We don't have to capture it
                false ->
                    Acc;
                true ->
                    Acc#{VarName => find_in_scope(VarName, Vars)}
            end
        end,
        #{},
        VariableNames
    ),
    State#taint_am_state{stack = [{lambda_closure, LambdaCapture}] ++ Stack};
%% Lookup VarName in the scope and push it onto the stack
propagate({get, {VarName, Loc}}, State = #taint_am_state{stack = Stack, scopes = Vars}) ->
    VarTaint = find_in_scope(VarName, Vars),
    %%  io:format("State ~p~n", [State]),
    VarTaint1 = append_taint_history(VarTaint, Loc),
    %%  io:format("Var taint ~p Var taint 1: ~p ~n", [VarTaint, VarTaint1]),
    State#taint_am_state{stack = [VarTaint1] ++ Stack};
%% Apply (call) the MFA function. If instrumented_return = true, the callee should have executed already
%% in this abstract machine, leaving the stack in the correct state.
%% Therefore there shouldn't be anything to do, but reset the flag
propagate(
    {apply, {MFA = {_Module, _Fun, _Arity}, Loc}},
    State = #taint_am_state{stack = [Top | Stack], instrumented_return = [true | Ir]}
) when ?NOT_TRY_ENTER(Top) ->
    %% The top of the stack should be return value and all argument should be popped in the called functions
    %% so there is nothing to do
    Top1 = append_taint_history_base(taint_value(Top), {return_site, MFA, Loc}),
    State#taint_am_state{stack = [Top1 | Stack], instrumented_return = Ir};
%% If the callee is not instrumented, we have to pop the arguments and push the return value
%% according to a model.
%% Currently the model just propagates taint
propagate(
    {apply, {MFA = {Module, Fun, Arity}, Loc}},
    State = #taint_am_state{stack = Stack, instrumented_return = [{Fun, Arity} | Ir]}
) ->
    {ApplyArgs0, NewStack} = lists:split(Arity, Stack),
    ApplyArgs = is_all_taint_value(ApplyArgs0),
    %%For now we just merge all the taints
    {TaintValue, State1} =
        case model_of(State#taint_am_state.models, MFA, ApplyArgs) of
            get_process_dict ->
                {State#taint_am_state.process_dict, State};
            {put_process_dict, Val} ->
                {{notaint, []}, State#taint_am_state{process_dict = Val}};
            notmodeled ->
                case [Arg || Arg <- ApplyArgs, not is_no_taint(Arg)] of
                    % If there is no tainted args, the return is assumed not tainted too
                    [] ->
                        {{notaint, []}, State};
                    % If there is tainted args, the return is tainted and could have any structure
                    TaintedArgs ->
                        ?LOG_INFO("MFA ~p, ~p at ~p~n", [Module, Fun, Loc]),
                        {create_blackhole(TaintedArgs), State}
                end;
            TaintVal ->
                {TaintVal, State}
        end,
    TaintValue1 =
        if
            not is_tuple(Loc) -> append_taint_history_base(TaintValue, {return_site, MFA, Loc})
        end,

    %%  io:format("Apply taint ~p args: ~p ~n", [TaintValue1, ApplyArgs]),
    State1#taint_am_state{stack = [TaintValue1 | NewStack], instrumented_return = Ir};
%% Pop a value of the stack and check if it's tainted. If it is tainted add it to leaks
propagate({sink, {_Loc}}, State = #taint_am_state{stack = [{notaint, []} | _Stack]}) ->
    State;
propagate({sink, {Loc}}, State = #taint_am_state{stack = [TaintValue | Stack], leaks = Leaks, lineage_mode = false}) ->
    if
        ?NOT_TRY_ENTER(TaintValue) ->
            State#taint_am_state{
                stack = [TaintValue | Stack], leaks = [{leak, Loc, get_history(taint_value(TaintValue))} | Leaks]
            }
    end;
% In lineage mode we are not interested in manally annotated sinks, so we just skip them
propagate({sink, {_Loc}}, State = #taint_am_state{stack = [_ | _Stack]}) ->
    State;
%% Constructs a binary pattern. BinValSizes is a list of runtime sizes (in bytes) of each segment that
%% constitutes the binary pattern being constructed
propagate({construct_pattern, {{bitstring, BinValSizes}, Loc}}, State = #taint_am_state{stack = Stack}) ->
    {BinTaintVals0, NewStack} = lists:split(length(BinValSizes), Stack),
    BinTaintVals = is_all_taint_value(BinTaintVals0),
    BinaryTaintValue =
        case lists:all(fun is_no_taint/1, BinTaintVals) of
            %%If all bin values have no taint, the whole binary has no taint
            true ->
                {notaint, []};
            _ ->
                BinTaintVals1 = lists:map(fun(V) -> append_taint_history(V, Loc) end, lists:reverse(BinTaintVals)),
                {pattern_taint, {bitstring, BinValSizes}, BinTaintVals1}
        end,
    State#taint_am_state{stack = [BinaryTaintValue | NewStack]};
%% Pop 2 values of the stack, put them in a cons pattern and push
%% {pattern_taint, cons, ...} to the stack
propagate({construct_pattern, {{cons}, Loc}}, State = #taint_am_state{stack = Stack}) ->
    {HeadTail, NewStack} = lists:split(2, Stack),
    [Head, Tail] = is_all_taint_value(HeadTail),
    ListValue =
        case {Head, Tail} of
            {{notaint, []}, {notaint, []}} -> {notaint, []};
            _ -> {pattern_taint, cons, [append_taint_history(Head, Loc), append_taint_history(Tail, Loc)]}
        end,
    State#taint_am_state{stack = [ListValue | NewStack]};
% For constructing map_patterns the top of the stack should be
% all the taint value for Values, followed by all the taint values for Keys
%% Therefore we pop one value off the stack for each Key and construct a map Key => taint_value
%% Then we pop one value of the stack for each Key again, which represent the taint-ednes of
%% the Key and construct a map Key => taint_value.
propagate({construct_pattern, {{map, Keys}, Loc}}, State = #taint_am_state{stack = Stack}) ->
    {MapKeyValues0, NewStack} = lists:split(length(Keys) * 2 + 1, Stack),
    MapKeyValues = is_all_taint_value(MapKeyValues0),
    [MapTaint | KeyValuesTaint] = MapKeyValues,
    MapTaintValue =
        case lists:all(fun is_no_taint/1, MapKeyValues) of
            true ->
                {notaint, []};
            _ ->
                BaseTaintMap =
                    case MapTaint of
                        {notaint, []} -> #{};
                        {taint, _} -> #{base_map => MapTaint};
                        {pattern_taint, map, Val} when is_map(Val) -> Val
                    end,
                {MapValues, MapKeys} = lists:split(length(Keys), KeyValuesTaint),
                % maps/merge will overwrite values from BaseTaintMap
                ValueTaintMap = maps:merge(BaseTaintMap, #{K => V || K <- Keys && V <- MapValues}),
                PreviousKeyTaintMap = maps:get(abstract_machine_mapkey_taints, BaseTaintMap, #{}),
                KeyTaintMap =
                    if
                        is_map(PreviousKeyTaintMap) ->
                            maps:merge(
                                PreviousKeyTaintMap,
                                #{K => V || K <- Keys && V <- MapKeys}
                            )
                    end,
                MapValueBody = ValueTaintMap#{abstract_machine_mapkey_taints => KeyTaintMap},
                MapTaintValue1 = {pattern_taint, map, MapValueBody},
                append_taint_history(MapTaintValue1, Loc)
        end,
    State#taint_am_state{stack = [MapTaintValue | NewStack]};
%% Pop Arity values of the stack, put them in the pattern and push {pattern_taint, ...}
%% value onto the stack
propagate({construct_pattern, {{tuple, Arity}, Loc}}, State = #taint_am_state{stack = Stack}) ->
    {TupleValues0, NewStack} = lists:split(Arity, Stack),
    TupleValues = is_all_taint_value(TupleValues0),
    TaintValue =
        case lists:all(fun is_no_taint/1, TupleValues) of
            %%If all tuple values have no taint, tuple has no taint
            true ->
                {notaint, []};
            %%Otherwise we construct the tuple
            _ ->
                TupleValues1 = lists:map(fun(V) -> append_taint_history(V, Loc) end, TupleValues),
                {pattern_taint, tuple, TupleValues1}
        end,
    State#taint_am_state{stack = [TaintValue | NewStack]};
%% Pop a map pattern taint value of the stack, extract Keys from the map and push their values
%% onto the stack
propagate(
    {deconstruct_pattern, {{map, Keys}, Loc}},
    State = #taint_am_state{stack = [{pattern_taint, map, MapValue} | Stack]}
) when is_map(MapValue) ->
    MapValues = is_all_taint_value([maps:get(Key, MapValue, {notaint, []}) || Key <- Keys]),
    KeyTaintMap = maps:get(abstract_machine_mapkey_taints, MapValue),
    MapKeys =
        if
            is_map(KeyTaintMap) -> [maps:get(Key, KeyTaintMap, {notaint, []}) || Key <- Keys]
        end,
    DeconstructedValues = is_all_taint_value(MapValues ++ MapKeys),
    DeconstructedValues1 = [append_taint_history(V, Loc) || V <- DeconstructedValues],
    State#taint_am_state{stack = DeconstructedValues1 ++ Stack};
%% To deconstruct a map pattern of an untainted value, just push
%% enough notaint values back onto the stack
propagate(
    {deconstruct_pattern, {{map, Keys}, _Loc}},
    State = #taint_am_state{stack = [{notaint, []} | Stack]}
) ->
    %Push taint values for both keys and values
    MapValues = [{notaint, []} || _ <- lists:seq(1, 2 * length(Keys))],
    State#taint_am_state{stack = MapValues ++ Stack};
% This clause deconstructs pattern of an opaque taint value. That
% is a tainted value that is either {taint, _} or {blackhole, ...}
% In this case we just duplicate the value for each Key/Value
% in the requested deconstruction
propagate(
    {deconstruct_pattern, {{map, Keys}, Loc}},
    State = #taint_am_state{stack = [TaintVal | Stack]}
) ->
    %Push taint values for both keys and values
    MapValues =
        if
            ?NOT_TRY_ENTER(TaintVal) ->
                [append_taint_history(taint_value(TaintVal), Loc) || _ <- lists:seq(1, 2 * length(Keys))]
        end,
    State#taint_am_state{stack = MapValues ++ Stack};
%% Pop a pattern value of the stack and deconstruct it into the pattern to pattern match
%% Deconstructing a tuple  pattern when top of stack is tainted
propagate(
    {deconstruct_pattern, {{tuple, Arity}, Loc}},
    State = #taint_am_state{stack = [{pattern_taint, tuple, TupleValues} | Stack]}
) when Arity == length(TupleValues) ->
    TupleValues1 = lists:map(fun(V) -> append_taint_history(V, Loc) end, TupleValues),
    State#taint_am_state{stack = lists:reverse(TupleValues1, Stack)};
%% Deconstructing a tuple  pattern when top of stack is tainted
propagate(
    {deconstruct_pattern, {{cons}, Loc}},
    State = #taint_am_state{stack = [{pattern_taint, cons, ListValues} | Stack]}
) ->
    [Head, Tail] = lists:map(fun(V) when ?NOT_TRY_ENTER(V) -> append_taint_history(V, Loc) end, ListValues),
    State#taint_am_state{stack = [Head, Tail] ++ Stack};
%% Deconstructing pattern when top of stack is not tained
%% Or is tainted directly meaning the whole list is marked as tainted
%% not the individual elements.
%%
%% That can happen if a string (or any list is marked as source), ie.
%% finer_taint:source("some string")
%%
%% In this case we just duplicate the taint value
propagate(
    {deconstruct_pattern, {{cons}, _Loc}},
    State = #taint_am_state{stack = [H = {TaintValueType, _} | Stack]}
) when TaintValueType =:= taint; TaintValueType =:= notaint ->
    State#taint_am_state{stack = [H, H] ++ Stack};
%% Deconstructs a binary pattern. BinPattern is a list of Size/Tsl expressions
%% that can be used to infer the segment size. Most of the heavy lifting
%% is done by match_binary_pattern function
propagate(
    {deconstruct_pattern, {{bitstring, BinPattern}, Loc}},
    State = #taint_am_state{stack = [TopStack | Stack]}
) ->
    NewTopStack =
        case TopStack of
            {notaint, []} ->
                lists:map(fun(_) -> {notaint, []} end, BinPattern);
            {pattern_taint, {bitstring, Sizes}, BinVals} ->
                [append_taint_history(Val, Loc) || Val <- match_binary_pattern({Sizes, BinVals}, BinPattern)];
            {try_enter, _} ->
                error(bad_taint_value);
            Val = {_Source, _History} ->
                NewTaint = append_taint_history(taint_value(Val), Loc),
                lists:map(fun(_) -> NewTaint end, BinPattern)
        end,
    State#taint_am_state{stack = lists:reverse(NewTopStack, Stack)};
propagate(
    {deconstruct_pattern, {{tuple, Arity}, _Loc}},
    State = #taint_am_state{stack = [{notaint, []} | Stack]}
) ->
    State#taint_am_state{stack = [{notaint, []} || _ <- lists:seq(1, Arity)] ++ Stack};
propagate(
    {deconstruct_pattern, {{tuple, Arity}, Loc}},
    State = #taint_am_state{stack = [Val = {_, _History} | Stack]}
) ->
    NewVal = append_taint_history(taint_value(Val), Loc),
    State#taint_am_state{stack = [NewVal || _ <- lists:seq(1, Arity)] ++ Stack};
propagate(
    {set_element, {Index, TupleSize, _Loc}},
    State = #taint_am_state{stack = [IndexTaint, TupleTaint, ValueTaint | Stack]}
) ->
    ValueTaintV = taint_value(ValueTaint),
    NewTupleTaint =
        case TupleTaint of
            {notaint, []} ->
                case ValueTaintV of
                    {notaint, []} ->
                        {notaint, []};
                    _ ->
                        TupleValues0 = [{notaint, []} || _ <- lists:seq(1, TupleSize)],
                        TupleValues1 = setnth(Index, TupleValues0, ValueTaintV),
                        % The tuple pattern has taint values in reverse order
                        {pattern_taint, tuple, lists:reverse(TupleValues1)}
                end;
            {taint, _} ->
                {taint, [{joined_history, pattern, lists:map(fun get_history/1, [TupleTaint, ValueTaintV])}]};
            {pattern_taint, tuple, TupleValues} ->
                TupleValues1 = setnth(Index, lists:reverse(TupleValues), ValueTaintV),
                {pattern_taint, tuple, lists:reverse(TupleValues1)}
        end,

    State#taint_am_state{stack = [IndexTaint, NewTupleTaint, ValueTaintV] ++ Stack};
% When we enter a try statement we push a marker on the stack and scope
propagate(
    {try_catch, EnterMark = {try_enter, _TryBlockId}, _Loc},
    State = #taint_am_state{stack = Stack, scopes = Scopes, instrumented_return = Ir}
) ->
    State#taint_am_state{
        stack = [EnterMark | Stack], scopes = [EnterMark | Scopes], instrumented_return = [EnterMark | Ir]
    };
% Happy case where nothing was thrown so we clean up the markers
propagate(
    {try_catch, {try_exit, TryBlockId}, _Loc},
    State = #taint_am_state{
        stack = [RetVar | Stack],
        scopes = [{try_enter, TryBlockId} | Scopes],
        instrumented_return = [{try_enter, TryBlockId} | Ir]
    }
) ->
    [{try_enter, TryBlockId} | NewStack] = lists:dropwhile(
        try_enter_predicate(TryBlockId),
        Stack
    ),
    State#taint_am_state{stack = [RetVar | NewStack], scopes = Scopes, instrumented_return = Ir};
% Something was thrown, we clean up to the closest try_enter marker
propagate(
    {try_catch, {catch_enter, TryBlockId}, _Loc}, State = #taint_am_state{stack = [ThrownVal | Stack], scopes = Scopes}
) ->
    [{try_enter, _} | NewScopes] = lists:dropwhile(try_enter_predicate(TryBlockId), Scopes),
    [{try_enter, _} | NewStack] = lists:dropwhile(try_enter_predicate(TryBlockId), Stack),
    [{try_enter, _} | NewIr] = lists:dropwhile(
        try_enter_predicate(TryBlockId), State#taint_am_state.instrumented_return
    ),
    State#taint_am_state{stack = [ThrownVal | NewStack], scopes = NewScopes, instrumented_return = NewIr};
% Model for erlang:hibernate/3, this resets the state as if it were a new process
propagate(
    {call_fun, {erlang, hibernate, 3}, _Loc}, State = #taint_am_state{stack = Stack0}
) ->
    % hibernate should be only called inside modeled_erlang:mhibernate/3.
    % Args for hibernate are ?MODULE, mapply, [M, F, Args],
    % we transform this in M, F, Args
    {[_, _, ArgsList], _RestOfStack} = lists:split(3, Stack0),
    {MArg, FArg, ArgsArg} =
        case ArgsList of
            {pattern_taint, cons, [
                MA,
                {pattern_taint, cons, [
                    FA,
                    {pattern_taint, cons, [AA, _Nil]}
                ]}
            ]} ->
                {MA, FA, AA};
            {notaint, []} ->
                {{notaint, []}, {notaint, []}, {notaint, []}}
        end,

    State#taint_am_state{stack = [MArg, FArg, ArgsArg], scopes = [#{}], instrumented_return = [{mapply, 3}]};
% Normal call_fun
propagate(
    {call_fun, {Module, Function, Arity}, Loc}, State = #taint_am_state{stack = Stack0, instrumented_return = Ir}
) ->
    {Args0, RestOfStack} = lists:split(Arity, Stack0),
    Args = is_all_taint_value(Args0),
    Args1 = [append_taint_history_base(Arg, {call_site, {Module, Function, Arity}, Loc}) || Arg <- Args],
    State#taint_am_state{stack = Args1 ++ RestOfStack, instrumented_return = [{Function, Arity} | Ir]};
%% Denotes function entry, it pushes a new scope for variables to avoid name clashes
%% coverage analysis core
propagate(
    {push_scope, {_MFA = {Module, PushedFunction, Arity}, _Loc}},
    State = #taint_am_state{
        stack = Stack0,
        scopes = Scope0,
        instrumented_return = [{CalledFunction, Arity} | Ir],
        leaks = Leaks,
        lineage_modules_denymap = LineageModulesDenyMap,
        lineage_mode = coverage
    }
) when
    PushedFunction == CalledFunction orelse CalledFunction == lambda_func orelse CalledFunction == variable_func,
    length(Stack0) >= Arity,
    not is_map_key(Module, LineageModulesDenyMap)
->
    {Args, RestOfStack} = lists:split(Arity, Stack0),
    ArgLeaks = [
        begin
            TaintValue = taint_value(TVal),
            abstract_machine_util:get_covered_inst(get_history(TaintValue))
        end
     || TVal <- Args
    ],
    NewCoverage = maps:fold(
        fun(L, ok, Acc) -> [{coverage_leak, L} | Acc] end,
        Leaks,
        lists:foldl(fun maps:merge/2, #{}, ArgLeaks)
    ),

    State#taint_am_state{
        scopes = [#{} | Scope0],
        stack = Args ++ RestOfStack,
        instrumented_return = [true | Ir],
        leaks = NewCoverage
    };
% Lineage analaysis core
propagate(
    {push_scope, {MFA = {Module, PushedFunction, Arity}, Loc}},
    State = #taint_am_state{
        stack = Stack0,
        scopes = Scope0,
        instrumented_return = [{CalledFunction, Arity} | Ir],
        leaks = Leaks,
        lineage_modules_denymap = LineageModulesDenyMap,
        lineage_mode = LineageMode
    }
) when
    PushedFunction == CalledFunction orelse CalledFunction == lambda_func orelse CalledFunction == variable_func,
    length(Stack0) >= Arity,
    LineageMode == line_history orelse LineageMode == function_history,
    not is_map_key(Module, LineageModulesDenyMap)
->
    {Args, RestOfStack} = lists:split(Arity, Stack0),
    EnumArgs = lists:enumerate(Args),
    ArgLeaks = [
        begin
            TaintValue = taint_value(TVal),
            % Storing the line_history history for each arg_leak is prohibitvely expensive
            % In that case, we only want to store the tainted arguments in the history
            case LineageMode of
                line_history ->
                    {arg_dataflow, {MFA, N, Loc}, abstract_machine_util:get_dataflows(get_history(TaintValue))};
                function_history ->
                    {arg_leak, {MFA, N, Loc}, lists:usort(get_tainted_args(TaintValue))}
            end
        end
     || {N, TVal} <- EnumArgs
    ],
    {Stack, Scope} =
        case is_in_scope(MFA, Scope0) of
            %If the args of this function haven't been tainted in this scope yet, we taint them
            false ->
                Args1 = [
                    if
                        ?NOT_TRY_ENTER(Arg) -> add_arg_taint(taint_value(Arg), {MFA, N}, "unknown")
                    end
                 || {N, Arg} <- EnumArgs
                ],
                {Args1 ++ RestOfStack, [#{MFA => {taint, []}} | Scope0]};
            _ ->
                {Args ++ RestOfStack, [#{} | Scope0]}
        end,
    State#taint_am_state{
        scopes = Scope,
        stack = Stack,
        instrumented_return = [true | Ir],
        leaks = ArgLeaks ++ Leaks
    };
propagate(
    {push_scope, {{Module, PushedFunction, Arity}, _Loc}},
    State = #taint_am_state{
        stack = Stack,
        scopes = Scope,
        instrumented_return = [{CalledFunction, Arity} | Ir],
        lineage_mode = LineageMode,
        lineage_modules_denymap = LineageModulesDenyMap
    }
) when
    PushedFunction == CalledFunction orelse CalledFunction == lambda_func orelse CalledFunction == variable_func,
    LineageMode == false orelse is_map_key(Module, LineageModulesDenyMap)
->
    State#taint_am_state{
        scopes = [#{} | Scope],
        stack = Stack,
        instrumented_return = [true | Ir]
    };
propagate(
    {push_scope, {{_Module, PushedFunction, Arity}, _Loc}},
    State = #taint_am_state{scopes = Scope, instrumented_return = [{CalledFunction, _} | _], stack = Stack}
) ->
    io:format("Expected ~p, but got into ~p, assuming ~p is uninstrumented and it called ~p~n", [
        CalledFunction, PushedFunction, CalledFunction, PushedFunction
    ]),
    %Note lineage mode
    State#taint_am_state{
        scopes = [#{} | Scope],
        stack = [{notaint, []} || _ <- lists:seq(1, Arity)] ++ Stack
    };
propagate(
    {push_scope, {MFA = {Module, _Function, Arity}, _Loc}},
    State = #taint_am_state{
        stack = Stack,
        scopes = Scope,
        lineage_modules_denymap = LineageModulesDenyMap
    }
) ->
    ?LOG_INFO("Setting up new stack at ~p~n", [_Loc]),
    StartingStack =
        case State#taint_am_state.lineage_mode of
            false -> [{notaint, []} || _ <- lists:seq(1, Arity)];
            coverage -> [{notaint, []} || _ <- lists:seq(1, Arity)];
            % Make sure non lineage modules don't get tainted
            _LineageMode when is_map_key(Module, LineageModulesDenyMap) -> [{notaint, []} || _ <- lists:seq(1, Arity)];
            _ -> [add_arg_taint({notaint, []}, {MFA, N}, "unknown") || N <- lists:seq(1, Arity)]
        end,

    State#taint_am_state{scopes = [#{} | Scope], stack = StartingStack ++ Stack};
%% Denotes function return. The top value ofhe stack should be the return value.
%% This function only destroys the current scope as it is not needed anymore.
%% sets the instrumented_return flag to be used by the {apply, ...} instruction
propagate(
    {func_ret, {Function, _Loc}},
    State = #taint_am_state{
        stack = [_DroppedReturn | Stack],
        scopes = [_DropedScope | Others],
        instrumented_return = [{CalledFunction, _} | _]
    }
) when
    Function =/= CalledFunction, Function =/= true, Function =/= dropping_lambda_capture
->
    State#taint_am_state{scopes = Others, stack = Stack};
propagate({func_ret, {_Function, _Loc}}, State = #taint_am_state{scopes = [_DropedScope | Others]}) ->
    State#taint_am_state{scopes = Others};
%% Pops a value of the stack and stores it in the scope with VarName
propagate({store, {VarName, Loc}}, State = #taint_am_state{stack = [First | Stack], scopes = Scopes}) ->
    case First of
        {try_enter, _} -> throw({"Trying to store a try_enter marker, stack in non-sense state", VarName, Loc, State});
        First1 -> State#taint_am_state{stack = Stack, scopes = insert_in_scope(VarName, First1, Scopes)}
    end;
propagate(Instruction, State) ->
    %    io:format("Cannot apply instruction ~p~nto state:~n~p~n", [Instruction, State]),
    throw({abstract_machine_invalid_state, Instruction, State}).

% Note: bit_pattern_take_value currently assumes all the bit patterns are binary
% There are many other options: https://www.erlang.org/doc/programming_examples/bit_syntax.html#segments
-spec bit_pattern_take_value([bin_pattern_segment()], [taint_value()], [taint_value()]) ->
    [taint_value()].
% There are no bytes left, we are done and return all the values matched
bit_pattern_take_value([{Size, [binary]}], [], CurrentTaintValues) when Size =:= 0 orelse Size =:= default ->
    CurrentTaintValues;
bit_pattern_take_value([], [], CurrentTaintValues) ->
    CurrentTaintValues;
% Default segment is integer, default integer size is 8 (bits)
bit_pattern_take_value([{default, [default]} | PatternTail], TaintValuesAtByte, CurrentTaintValues) ->
    bit_pattern_take_value([{8, [integer]} | PatternTail], TaintValuesAtByte, CurrentTaintValues);
bit_pattern_take_value([{default, [integer]} | PatternTail], TaintValuesAtByte, CurrentTaintValues) ->
    bit_pattern_take_value([{8, [integer]} | PatternTail], TaintValuesAtByte, CurrentTaintValues);
bit_pattern_take_value([{Size0, [integer]} | PatternTail], TaintValuesAtByte, CurrentTaintValues) when
    is_integer(Size0)
->
    % integers have size in bits
    Size = Size0 div 8,
    {IntegerTaintValueBytes, OtherBytes} = lists:split(Size, TaintValuesAtByte),
    NewCurrentTaintValue =
        case lists:usort(IntegerTaintValueBytes) of
            [AllSameTaintValues] -> AllSameTaintValues
        end,
    bit_pattern_take_value(PatternTail, OtherBytes, [NewCurrentTaintValue | CurrentTaintValues]);
% If the current pattern has no bytes left, we move to the next pattern
bit_pattern_take_value([{0, [binary]} | PatternTail], TaintValuesAtByte, CurrentTaintValues) ->
    bit_pattern_take_value(PatternTail, TaintValuesAtByte, [{notaint, []} | CurrentTaintValues]);
% The current pattern has some bytes left, we look at the next byte (HeadByteTaintValue) and
% compare it to the CurrentTaintValues for this pattern.
bit_pattern_take_value(Pattern = [{_, [binary]} | _], TaintValues, []) ->
    bit_pattern_take_value(Pattern, TaintValues, [{notaint, []}]);
bit_pattern_take_value([{Size, [binary]} | PatternTail], [HeadByteTaintValue | Tail], [CurrentTaintValue | Others]) ->
    NewCurrentTaintValue =
        case {HeadByteTaintValue, CurrentTaintValue} of
            {Same, Same} -> Same;
            % Note: this should return binary pattern vals with the right offsets
            {Head, {notaint, []}} -> Head;
            {{notaint, []}, Current} -> Current;
            % Note: join two different taint values
            {Val1, Val2} -> throw({todo, Val1, Val2})
        end,
    % default Size means the remainder of this pattern should be matched
    NewSize =
        case Size of
            default -> default;
            _ -> Size - 1
        end,
    bit_pattern_take_value([{NewSize, [binary]} | PatternTail], Tail, [NewCurrentTaintValue | Others]).

% This function crashes if the list doesn't containt only taint values
-spec is_all_taint_value([taint_value() | try_marker() | map()]) -> [taint_value()].
is_all_taint_value([H = {lambda_closure, _} | T]) ->
    [H | is_all_taint_value(T)];
is_all_taint_value([H = {notaint, _} | T]) ->
    [H | is_all_taint_value(T)];
is_all_taint_value([H = {taint, _} | T]) ->
    [H | is_all_taint_value(T)];
is_all_taint_value([H = {pattern_taint, _, _} | T]) ->
    [H | is_all_taint_value(T)];
is_all_taint_value([]) ->
    [].

-spec get_taint_sources(taint_history(), [taint_source()]) -> [taint_source()].
get_taint_sources([], Acc) ->
    Acc;
get_taint_sources([{step, _} | Tail], Acc) ->
    get_taint_sources(Tail, Acc);
get_taint_sources([{message_pass, _} | Tail], Acc) ->
    get_taint_sources(Tail, Acc);
get_taint_sources([{return_site, _, _} | Tail], Acc) ->
    get_taint_sources(Tail, Acc);
get_taint_sources([{call_site, _, _} | Tail], Acc) ->
    get_taint_sources(Tail, Acc);
get_taint_sources([T = {arg_taint, _} | Tail], Acc) ->
    get_taint_sources(Tail, [T | Acc]);
get_taint_sources([T = {source, _} | Tail], Acc) ->
    get_taint_sources(Tail, [T | Acc]);
get_taint_sources([T = {tagged_source, _, _} | Tail], Acc) ->
    get_taint_sources(Tail, [T | Acc]);
get_taint_sources([{blackhole, Sources} | Tail], Acc) ->
    get_taint_sources(Tail, Sources ++ Acc);
get_taint_sources([{joined_history, _, History} | Tail], Acc) ->
    get_taint_sources(Tail, lists:foldl(fun get_taint_sources/2, Acc, History)).

-spec create_blackhole([taint_value()]) -> taint_value().
create_blackhole(TaintValues) when is_list(TaintValues) ->
    Sources = [get_taint_sources(get_history(TVal), []) || TVal <- TaintValues],
    {taint, [{blackhole, lists:usort(lists:foldl(fun lists:append/2, [], Sources))}]}.

-spec try_enter_predicate(try_block_id()) -> fun((taint_value() | dynamic()) -> boolean()).
try_enter_predicate(TryBlockId) ->
    fun
        ({try_enter, TBlockId}) when TryBlockId =:= TBlockId -> false;
        (_) -> true
    end.

% Matches a binary patterns to the tainted vals.
% It first constructs a byte-level view of the tainted values (TaintValuesAtByte).
% For example if {Sizes, BinVals} is {[1,2], [taintA, taintB]},
% TaintValuesAtByte would be [taintA, taintB, taintB].
% bit_pattern_take_value then consumes bytes in TaintValuesAtByte
% according to the BinPattern
-spec match_binary_pattern({[integer()], [taint_value()]}, [bin_pattern_segment()]) ->
    [taint_value()].
match_binary_pattern({Sizes, BinVals}, BinPatterns) ->
    TaintValuesAtByte = lists:append(
        lists:map(
            fun({Size, BinVal}) -> [BinVal || _ <- lists:seq(1, Size)] end,
            lists:zip(Sizes, BinVals)
        )
    ),
    bit_pattern_take_value(BinPatterns, TaintValuesAtByte, []).

-spec propagate_taints_for_models([taint_value()]) -> taint_value().
propagate_taints_for_models(Args) ->
    case [T || T <- Args, not is_no_taint(T)] of
        [] ->
            {notaint, []};
        [OneTaintedArg] ->
            OneTaintedArg;
        TaintedArgs ->
            {taint, [{joined_history, model, lists:map(fun get_history/1, TaintedArgs)}]}
    end.

-spec setnth(non_neg_integer(), [A], A) -> [A].
setnth(1, [_ | Rest], New) -> [New | Rest];
setnth(I, [E | Rest], New) -> [E | setnth(I - 1, Rest, New)].

% This function forces the type into a taint_value() to make
% eqWAlizer happy
-spec taint_value(taint_value() | try_marker()) -> taint_value().
taint_value({try_enter, _}) -> error(bad_taint_value);
taint_value(X) -> X.

-spec maybe_to_opaque_taint(taint_value()) -> taint_value().
maybe_to_opaque_taint({notaint, []}) -> {notaint, []};
maybe_to_opaque_taint(Val) -> {taint, get_history(Val)}.

-spec model_of(models(), {atom(), atom(), integer()}, [taint_value()]) ->
    taint_value() | notmodeled | get_process_dict | {put_process_dict, taint_value()}.
model_of(_, {persistent_term, _, _}, _) -> {notaint, []};
model_of(_, {supervisor, start_child, _}, _) -> {notaint, []};
model_of(_, {operators, '+', 2}, Args) -> propagate_taints_for_models(Args);
model_of(_, {operators, '*', 2}, Args) -> propagate_taints_for_models(Args);
model_of(_, {operators, '++', 2}, Args) -> propagate_taints_for_models(Args);
model_of(_, {operators, '/', 2}, Args) -> propagate_taints_for_models(Args);
model_of(_, {operators, '-', 2}, Args) -> propagate_taints_for_models(Args);
model_of(_, {operators, 'rem', 2}, Args) -> propagate_taints_for_models(Args);
model_of(_, {operators, 'div', 2}, Args) -> propagate_taints_for_models(Args);
model_of(_, {operators, '==', 2}, _Args) -> {notaint, []};
model_of(_, {operators, '=/=', 2}, _Args) -> {notaint, []};
model_of(_, {operators, '/=', 2}, _Args) -> {notaint, []};
model_of(_, {operators, '=:=', 2}, _Args) -> {notaint, []};
model_of(_, {operators, '<', 2}, _Args) -> {notaint, []};
model_of(_, {operators, '>', 2}, _Args) -> {notaint, []};
model_of(_, {operators, '>=', 2}, _Args) -> {notaint, []};
model_of(_, {operators, '=<', 2}, _Args) -> {notaint, []};
model_of(_, {operators, 'andalso', 2}, _Args) -> {notaint, []};
model_of(_, {operators, 'orelse', 2}, _Args) -> {notaint, []};
model_of(_, {string, 'slice', 3}, [String, _Start, _Length]) -> propagate_taints_for_models([String]);
model_of(_, {string, 'concat', 2}, [String1, String2]) -> propagate_taints_for_models([String1, String2]);
% maps:next/1 maps:iterator/1 should only be called in modeled_taint_maps, where the taint
% is propagated manually, so the return value of maps needs to be untainted to destruct
% into any tuple and be effecitvely discarded
model_of(_, {maps, 'next', 1}, [_MapIterator]) -> {notaint, []};
model_of(_, {maps, 'iterator', 1}, [_MapIterator]) -> {notaint, []};
model_of(_, {crypto, 'hash', _}, _) -> {notaint, []};
% erlang:monitor gives a new ref which is always untainted
model_of(_, {erlang, 'monitor', _}, _) -> {notaint, []};
model_of(_, {erlang, 'function_exported', _}, _) -> {notaint, []};
model_of(_, {erlang, 'length', _}, _) -> {notaint, []};
model_of(_, {erlang, 'binary_to_integer', _}, Args) -> propagate_taints_for_models(Args);
model_of(_, {erlang, 'phash2', _}, _) -> {notaint, []};
model_of(_, {erlang, 'put', _}, _) -> {notaint, []};
model_of(_, {erlang, 'whereis', _}, _) -> {notaint, []};
model_of(_, {erlang, 'is_pid', _}, _) -> {notaint, []};
model_of(_, {erlang, 'persistent_term', _}, _) -> {notaint, []};
model_of(_, {erlang, 'spawn_opt', _}, _) -> {notaint, []};
model_of(_, {erlang, 'list_to_binary', _}, [Val | _]) -> maybe_to_opaque_taint(Val);
model_of(_, {erlang, 'list_to_atom', _}, [Val | _]) -> maybe_to_opaque_taint(Val);
model_of(_, {erlang, 'io_list_to_binary', _}, [Val | _]) -> maybe_to_opaque_taint(Val);
model_of(_, {erlang, 'integer_to_list', _}, [Val | _]) -> maybe_to_opaque_taint(Val);
model_of(_, {erlang, 'atom_to_binary', _}, [Val | _]) -> Val;
model_of(_, {erlang, 'integer_to_binary', _}, [Val | _]) -> Val;
model_of(_, {erlang, 'term_to_binary', _}, [Val | _]) -> Val;
model_of(_, {erlang, 'binary_to_term', _}, [Val | _]) -> Val;
model_of(_, {modeled_erlang, 'process_dict', _}, []) -> get_process_dict;
model_of(_, {modeled_erlang, 'process_dict', _}, [Val]) -> {put_process_dict, Val};
model_of(_, {finer_taint, set_element, 3}, [_, Tuple, _]) -> Tuple;
model_of(Ms, {M, F, _}, _) when map_get({M, F}, Ms) =:= sanitize -> {notaint, []};
model_of(Ms, {M, F, _}, Args) when map_get({M, F}, Ms) =:= propagate -> propagate_taints_for_models(Args);
model_of(Ms, {M, _, _}, _) when map_get({M, '_any'}, Ms) =:= sanitize -> {notaint, []};
model_of(Ms, {M, _, _}, Args) when map_get({M, '_any'}, Ms) =:= propagate -> propagate_taints_for_models(Args);
model_of(_, _, _) -> notmodeled.
