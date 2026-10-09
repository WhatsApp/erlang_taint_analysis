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
-module(taint_types).
-moduledoc """
Instructions emitted by code instrumented with finer_taint_compiler, as stored by
`abstract_machine_server` and run by `taint_abstract_machine`, and the taint values
`taint_abstract_machine` computes and passes between processes through `taint_message_passer`.
""".
-compile(warn_missing_spec_all).

-export_type([
    lineage_point/0,
    taint_source/0,
    taint_history_point/0,
    taint_history/0,
    taint_value/0,
    scopes_map/0,
    bin_pattern_segment/0,
    deconstruct_pattern_types/0,
    construct_pattern_types/0,
    try_block_id/0,
    try_catch_state/0,
    instruction/0,
    annot_dataflow_src/0
]).

% lineage_point represents an argument of a function, mfa() identifies the function
% and integer() is the argument number starting with 1
-type lineage_point() :: {mfa(), integer()}.

-type taint_source() ::
    % arg_taint is similar to source, but it is not necessarily the beginning
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
    % know what happened to it. In order to improve scalability we drop
    % the full history and just keep the taint sources that went into it
    % This is probably ok, because the full history is unknown anyway
    | {blackhole, [taint_source()]}
    | taint_source().

-type taint_history() :: [taint_history_point()].

-type taint_value() ::
    % untainted value
    {notaint, []}
    % A normal tainted value
    | {taint, taint_history()}
    % Represents a taint value of a function. The only functions that
    % can be tainted are lambdas, because they can contain captured
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
    % The [number()] contains the byte sizes of taint values
    | {pattern_taint, {bitstring, [integer()]}, [taint_value()]}
    % For map #{Key => Value} the corresponding taint_value looks like
    % #{Key => Taint(Value), abstract_machine_mapkey_taints => #{Key => Taint(Value)}
    | {pattern_taint, map, #{term() => #{term() => taint_value()} | taint_value()}}.

-type scopes_map() :: #{string() => taint_value()}.

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
    {bitstring, [integer()]}
    | pattern_types_shared().

-type pattern_types_shared() ::
    % map has a list of Keys
    {map, [string()]}
    % tuple has arity, ie the number of elements in the tuple
    | {tuple, integer()}
    % Cons is always just a head and a tail
    | {cons}.

-type try_block_id() :: {module(), integer()}.

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
    % into a {lambda_closure, Scope} taint value and push it onto the stack
    | {capture_closure, {[string()]}}
    % Pops a value of the stack, if untainted push an empty scope
    % If the value is {lambda_closure, Scope}, push the Scope
    | {restore_capture, {mfa(), string()}}
    % Store VarName - Pop a value of the stack and store it in scope with VarName
    | {store, {string(), string()}}
    | {set_element, {integer(), integer(), string()}}.

% Similar to {arg_taint, lineage_point()}, but also contains some taint_history
% that can be used for annotations. The taint history is usually not fully detailed
-type annot_dataflow_src() :: {dataflow_src, lineage_point(), taint_history()}.
