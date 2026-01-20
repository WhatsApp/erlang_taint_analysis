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
-module(finer_taint_compiler).
-compile(warn_missing_spec_all).
-eqwalizer({unlimited_refinement, instrument_expression/2}).

%%====================================================================
%% API
%%====================================================================
-export([
    parse_transform/2,
    instrument_with_sinks/1,
    compile_helper/2,
    rewrite_comprehension/1,
    instrument_and_load_modules/2,
    instrument_with_sinks/2,
    instrument_known_stdlibs/1,
    instrument_loaded_module/2
]).

-record(rewrite_state, {
    source :: file:filename_all(),
    finer_taint_module :: module(),
    renamed_modules :: #{module() => module()},
    module :: module()
}).
-define(RENAMED_MODULES, #{
    queue => modeled_queue,
    maps => modeled_taint_maps,
    lists => modeled_lists,
    gen => modeled_gen,
    proc_lib => modeled_proc_lib,
    gen_server => modeled_gen_server
}).

% functions in this map will not be instrumented, this is useful
% if they need to be modeled in the taint_abstract_machine, but we
% still need some dynamic instrumentation
-define(DO_NOT_INSTRUMENT, #{
    {modeled_erlang, real_put} => ok,
    {modeled_erlang, process_dict} => ok
}).

-type forms() :: [erl_parse:abstract_form()].
-type options() :: [compile:option()].
-type expr() :: erl_parse:abstract_expr().
-type clause() :: erl_parse:abstract_clause().

% Like a Hoare Triple, but completely different. It's a triple because you
% have {Pre, Expr, Post}, where Expr is the original expr and Pre/Post are
% instructions that need to be executed before and after the original to
% perform the analysis
-type triple() :: {[expr()], expr(), [expr()]}.

-spec instrument_known_stdlibs(options()) -> ok.
instrument_known_stdlibs(FinerTaintOptions) ->
    % This is a list we know that need to be instrumented for finer taint to work well
    InstrumentedStdLibs = [gen_server, gen, lists, proc_lib, queue, modeled_erlang],
    lists:foreach(
        fun(Module) ->
            instrument_loaded_module(Module, FinerTaintOptions)
        end,
        InstrumentedStdLibs
    ).

%% instrument_loaded_module finds the object code of Module
%% instruments it and loads the instrumented code back
-spec instrument_loaded_module(module(), options()) -> {module, module()}.
instrument_loaded_module(Module, FinerTaintOptions) ->
    {Module, Binary, _} = code:get_object_code(Module),
    {Module, Forms} = load_forms(Binary),
    InstrumentedForms = instrument_with_sinks(Forms, [{finer_taint_do_checks, false}] ++ FinerTaintOptions),
    {NewModuleName, Binary1} = compile_forms(InstrumentedForms),
    {module, NewModuleName} = code:load_binary(NewModuleName, "/fake/module/path", Binary1).

-spec instrument_and_load_modules([{module(), Path :: string()}], options()) -> ok.
instrument_and_load_modules([], _) ->
    ok;
instrument_and_load_modules([{M, Path} | Tail], Options) ->
    Binary = compile_helper(Path, [{finer_taint_do_checks, false} | Options]),
    {module, M} = code:load_binary(M, Path, Binary),
    instrument_and_load_modules(Tail, Options).

-spec compile_helper(string(), options()) -> binary().
compile_helper(ModPath, Options) ->
    CompileOptions = [debug_info, binary] ++ proplists:get_value(compile_options, Options, []),
    {Mod, Binary} = compile_file(ModPath, CompileOptions),
    {Mod, Forms} = load_forms(Binary),
    InstrumentedForms = instrument_with_sinks(Forms, Options),
    {Mod, Binary1} = compile_forms(InstrumentedForms),
    Binary1.

-spec get_finer_taint_cfg(string()) -> [dynamic()].
get_finer_taint_cfg(CfgFileName) ->
    %% buck2 use resource/ dir
    BeamFile = code:where_is_file("finer_taint_compiler.beam"),
    BeamFile =/= non_existing orelse error({missing_beam, "finer_taint_compiler.beam"}),
    FtConfig = filename:join(
        [
            filename:dirname(BeamFile),
            "resources",
            CfgFileName
        ]
    ),
    case filelib:is_regular(FtConfig) of
        true ->
            {ok, CfgModules} = file:consult(FtConfig),
            CfgModules;
        false ->
            []
    end.

%%====================================================================
%% API Implementation
%%====================================================================

-spec parse_transform(forms(), options()) -> forms().
parse_transform(Forms, Options) ->
    instrument_with_sinks(Forms, Options).

-spec instrument_with_sinks(forms()) -> forms().
instrument_with_sinks(Forms) ->
    instrument_with_sinks(Forms, []).
-spec instrument_with_sinks(forms(), options()) -> forms().
instrument_with_sinks(Forms, Options) ->
    Source = get_source(Forms),
    Module = get_module(Forms),
    DoChecks = proplists:get_value(finer_taint_do_checks, Options, true),
    AdditionalRenames = proplists:get_value(finer_taint_renames, Options, #{}),

    CfgModules = get_finer_taint_cfg("finer_taint.cfg"),
    WhiteListedModule = lists:member(Module, CfgModules),

    IgnoredModules = get_finer_taint_cfg("instrument_ignorelist.cfg"),
    WhiteListedSource = string:find(Source, "taint_SUITE_data"),
    FinerTaintModule = proplists:get_value(finer_taint_module, Options, ct_finer_taint),
    BlacklistedModules = lists:any(
        fun(Name) ->
            string:find(Source, Name) =/= nomatch
        end,
        IgnoredModules
    ),
    Checks = {WhiteListedModule, WhiteListedSource, DoChecks, BlacklistedModules},
    case Checks of
        {false, nomatch, true, _} ->
            io:format(standard_error, "finer_taint skip compile ~s not allowlisted ~p~n", [Source, Checks]),
            Forms;
        {false, _, _, true} ->
            io:format(standard_error, "finer_taint skip compile ~s blocklisted ~p~n", [Source, Checks]),
            Forms;
        _ ->
            io:format(standard_error, "[finer_taint] ~s compiling ~n", [Source]),
            % The expression inside ets:fun2ms might not be valid AST before ms_transform
            % This can break other passes (erl_expand_records). Here we ensure ms_transform
            % is ran beforehand: https://www.erlang.org/doc/man/ms_transform.html#description
            Forms0 =
                case has_ms_transform(Forms) of
                    false -> Forms;
                    true -> ms_transform(Forms, Options)
                end,
            Forms1 = erl_expand_records:module(Forms0, [debug_info]),
            rewrite(
                Forms1,
                #rewrite_state{
                    source = Source,
                    finer_taint_module = FinerTaintModule,
                    renamed_modules = maps:merge(?RENAMED_MODULES, AdditionalRenames),
                    module = Module
                },
                []
            )
    end.

%%====================================================================
%% internal functions
%%====================================================================
-spec get_source(forms()) -> file:filename_all().
get_source([]) ->
    error(taint_unknown_module);
get_source([{attribute, _, file, {Source, _}} | _]) ->
    Source;
get_source([_ | Rest]) ->
    get_source(Rest).

-spec get_module(forms()) -> module().
get_module([]) -> error(taint_unknown_module);
get_module([{attribute, _, module, Mod} | _]) when is_atom(Mod) -> Mod;
get_module([_ | Rest]) -> get_module(Rest).

-spec has_ms_transform(forms()) -> boolean().
has_ms_transform([{attribute, _, file, {Path, _Line}} | Tail]) ->
    case string:find(Path, "ms_transform.hrl") of
        nomatch -> has_ms_transform(Tail);
        _ -> true
    end;
has_ms_transform([]) ->
    false;
has_ms_transform([_ | Tail]) ->
    has_ms_transform(Tail).

%%====================================================================
%% abstract forms rewrite:
%%   see: http://www.erlang.org/doc/apps/erts/absform.html
%%
%%====================================================================
-spec rewrite(forms(), #rewrite_state{}, forms()) -> forms().
rewrite(Rest = [{attribute, _, finer_taint_compiled, _} | _], _, Acc) ->
    lists:reverse(Acc, Rest);
rewrite([], _, Acc) ->
    %% all input has been processed
    Forms = lists:reverse(Acc),
    [
        erl_parse:map_anno(fun(Anno) -> erl_anno:set_generated(true, Anno) end, Form)
     || Form <- Forms
    ];
rewrite(
    [{attribute, Anno, module, Module} | Tail],
    State = #rewrite_state{renamed_modules = Renames},
    Acc
) ->
    CompiledTag = {attribute, erl_anno:new({1, 1}), finer_taint_compiled, []},
    rewrite(Tail, State, [CompiledTag, {attribute, Anno, module, maps:get(Module, Renames, Module)} | Acc]);
rewrite([{attribute, _, record, {message_stats, _}} | Tail], State, Acc) ->
    rewrite(Tail, State, Acc);
rewrite(
    [{function, L, Function, Arity, Clauses0} | Rest],
    State,
    Acc
) when not is_map_key({State#rewrite_state.module, Function}, ?DO_NOT_INSTRUMENT) ->
    Clauses1 = lists:map(fun(Clause) -> instrument_function_clause(Clause, Function, State) end, Clauses0),
    FunctionForm = {function, L, Function, Arity, Clauses1},
    rewrite(
        Rest,
        State,
        [FunctionForm | Acc]
    );
rewrite([H | T], State, Acc) ->
    rewrite(T, State, [H | Acc]).

-define(EMIT_INSTR(Loc, Func, Args),
    {call, Loc, {remote, Loc, {atom, Loc, finer_taint}, {atom, Loc, Func}}, [
        {string, Loc,
            atom_to_list(State#rewrite_state.module) ++ ".erl:" ++
                integer_to_list(erl_anno:line(Loc))},
        {atom, Loc, State#rewrite_state.finer_taint_module}
        | Args
    ]}
).
-define(NILL(Loc), {atom, Loc, notaint}).

%%These assume Anno is defined for location
-define(ATOM(Atom), {atom, Anno, Atom}).
-define(INT(Int), {integer, Anno, Int}).
-define(TUPLE(Values), {tuple, Anno, Values}).

-define(SSA_PREFIX, "SSAify_").

% Returns a hash of the passed Expr
% Useful for creating unique identifiers somwehre in the abstract tree
-spec expr_hash(term()) -> string().
expr_hash(Expr) ->
    <<IntHash:256>> = crypto:hash(sha256, io_lib:format("~p", [Expr])),
    lists:sublist(integer_to_list(IntHash, 36), 8).

-spec get_temp_varname_for_expr(expr(), string()) -> string().
get_temp_varname_for_expr(Expr, Prefix) ->
    Prefix ++ expr_hash(Expr).

-spec unzip_flatten([{[T1], T2, [T3]}]) -> {[T1], [T2], [T3]}.
unzip_flatten(List) ->
    unzip_flatten_impl(List, {[], [], []}).

-spec unzip_flatten_impl([{[T1], T2, [T3]}], {[T1 | [T1]], [T2], [T3 | [T3]]}) -> {[T1], [T2], [T3]}.
unzip_flatten_impl([], {Pres, Exprs, Posts}) ->
    {lists:flatten(lists:reverse(Pres)), lists:reverse(Exprs), lists:flatten(lists:reverse(Posts))};
unzip_flatten_impl([{Pres, Expr, Posts} | Tail], {AccPres, AccExpr, AccPosts}) ->
    unzip_flatten_impl(Tail, {[Pres | AccPres], [Expr | AccExpr], [Posts | AccPosts]}).

-spec concat([[T]]) -> [T].
concat([]) -> [];
concat([H | T]) -> H ++ concat(T).

% Converts a list (ie. [1]) into the Ast of the list (ie. {cons, Anno, 1, {nil, Anno}})
% This is useful when passing multiple values to instrumentation in a single argument
-spec list_to_list_ast(erl_anno:anno(), list()) -> expr().
list_to_list_ast(Anno, []) ->
    {nil, Anno};
list_to_list_ast(Anno, [H | T]) ->
    {cons, Anno, H, list_to_list_ast(Anno, T)}.

-spec string_list_to_ast(erl_anno:anno(), list()) -> expr().
string_list_to_ast(Anno, List) ->
    ListOfStrings = lists:map(fun(String) -> {string, Anno, lists:flatten(io_lib:format("~s", [String]))} end, List),
    list_to_list_ast(Anno, ListOfStrings).

-spec map_to_map_ast(erl_anno:anno(), map()) -> expr().
map_to_map_ast(Anno, Map) ->
    Assocs = maps:fold(
        fun(K, V, Acc) when is_atom(K) andalso is_atom(V) ->
            [{map_field_assoc, Anno, ?ATOM(K), ?ATOM(V)} | Acc]
        end,
        [],
        Map
    ),
    {map, Anno, Assocs}.
-spec name_has_been_used(string()) -> string().
name_has_been_used(TempName) ->
    % Note: refactor this to not use process dict, but pass a state around
    Dict =
        case get(used_ssa_vars) of
            undefined -> #{};
            X -> X
        end,
    case maps:get(TempName, Dict, false) of
        false ->
            put(used_ssa_vars, Dict#{TempName => ok}),
            TempName;
        _ ->
            <<IntHash:256>> = crypto:hash(sha256, io_lib:format("~s", [TempName])),
            Suffix = lists:sublist(integer_to_list(IntHash, 36), 8),
            name_has_been_used("Rehashed" ++ Suffix)
    end.

%% Converts Expr
%% to SSAify_<somerandom hash> = Expr,
%%    SSAify_<somerandom hash>.
-spec expr_to_var(expr()) -> {expr(), expr()}.
expr_to_var(Expr) ->
    [_ | [Anno | _]] = tuple_to_list(Expr),
    TempName = name_has_been_used(get_temp_varname_for_expr(Expr, ?SSA_PREFIX)),
    TempVar = {var, Anno, list_to_atom(TempName)},

    NewExpr = {match, Anno, TempVar, Expr},
    {TempVar, NewExpr}.

%% The purpose of ssa_iffy is to deal with the following problem. Consider:
%%
%% A = func_a(func_b(42)).
%%
%% Our instrumentation needs to be executed after func_b returns, but before func_a
%% is called. This is not possible to do within this expression. So ssa_iffy
%% transforms the above expression into:
%%
%% ATempVariableXyz = func_b(42),
%% DoImportantInstrumentationStuff(),
%% A = func_a(ATempVariableXyz).
%%
%% This kind of looks like transforming the code into some form of single static assigment (SSA),
%% thus the name. It only does this when we need to insert some "post" instrumentation.
-spec ssa_iffy(triple()) -> triple().
ssa_iffy({Pre, Expr, []}) ->
    {Pre, Expr, []};
ssa_iffy({Pre, Expr, Post}) ->
    {TempVar, NewExpr} = expr_to_var(Expr),
    {Pre ++ [NewExpr] ++ Post, TempVar, []}.

-spec instrument_body([expr()], [expr()], #rewrite_state{}) -> {expr(), [expr(), ...]}.
instrument_body([Expr | []], Acc, State) ->
    {Pre, Expr1, []} = ssa_iffy(instrument_expression(Expr, State)),
    {Expr1, Acc ++ Pre};
instrument_body([Expr | Tail], Acc, State) ->
    [_ | [Anno | _]] = tuple_to_list(Expr),
    {Pre, Expr1, Post} = instrument_expression(Expr, State),
    NewExprs = Pre ++ [Expr1 | Post] ++ [?EMIT_INSTR(erl_anno:set_generated(true, Anno), pop, [])],
    instrument_body(Tail, Acc ++ NewExprs, State).

-spec instrument_function_expressions([expr()], [expr()], #rewrite_state{}) -> {expr(), [expr()]}.
instrument_function_expressions([Expr | []], Acc, State) ->
    {Pre, Expr1, Post} = instrument_expression(Expr, State),
    [_ | [Anno | _]] = tuple_to_list(Expr),
    TempName = "TaintCompReturnVarSuperSpecial",
    ReturnVar = {var, Anno, list_to_atom(TempName)},
    NewExpr = {match, Anno, ReturnVar, Expr1},
    {ReturnVar, Acc ++ Pre ++ [NewExpr] ++ Post};
instrument_function_expressions([Expr | Tail], Acc, State) ->
    [_ | [Anno | _]] = tuple_to_list(Expr),
    {Pre, Expr1, Post} = instrument_expression(Expr, State),
    NewExprs = Pre ++ [Expr1 | Post] ++ [?EMIT_INSTR(erl_anno:set_generated(true, Anno), pop, [])],
    instrument_function_expressions(Tail, Acc ++ NewExprs, State).

-spec instrument_function_clause(clause(), atom(), #rewrite_state{}) -> clause().
instrument_function_clause({clause, Anno, Pattern, Guard, Body}, Function, State) ->
    {LastExpr, Body3} = instrument_function_expressions(Body, [], State),
    FunctionPrequel = [
        ?EMIT_INSTR(Anno, push_scope, [?ATOM(State#rewrite_state.module), ?ATOM(Function), ?INT(length(Pattern))])
        | lists:flatten([instrument_pattern(P, State) || P <- Pattern])
    ],
    FunctionSequel = [?EMIT_INSTR(Anno, func_ret, [?ATOM(Function)]), LastExpr],
    {clause, Anno, Pattern, Guard, FunctionPrequel ++ Body3 ++ FunctionSequel}.

-spec instrument_case_clause(clause(), [expr()], #rewrite_state{}) -> clause().
instrument_case_clause({clause, Anno, [Pattern], Guard, Body}, PostClauseExpr, State) ->
    {LastExpr, Body1} = instrument_body(Body, [], State),
    PatternPrequel = instrument_pattern(Pattern, State),
    {clause, Anno, [Pattern], Guard, PostClauseExpr ++ PatternPrequel ++ Body1 ++ [LastExpr]}.

-spec instrument_catch_clause(clause(), #rewrite_state{}, expr()) -> clause().
instrument_catch_clause({clause, Anno, [?TUPLE([ExceptionClass, Pattern, Stack])], Guard, Body}, State, TryBlockId) ->
    {LastExpr, Body1} = instrument_body(Body, [], State),
    PatternPrequel = instrument_pattern(Pattern, State),
    RuntimeErrorTaintVal =
        case ExceptionClass of
            %For runtime errors, the thrown value is assumed untainted
            %So we pop the value that is supposedly thrown (done by taint_abstract_machine)
            %and push a new no taint value
            ?ATOM(error) ->
                [?EMIT_INSTR(Anno, pop, []), ?EMIT_INSTR(Anno, push, [?NILL(Anno)])];
            {var, _, '_'} ->
                [];
            {var, _, Name} ->
                [
                    ?EMIT_INSTR(Anno, push, [?NILL(Anno)]),
                    ?EMIT_INSTR(Anno, store_var, [{string, Anno, atom_to_list(Name)}])
                ];
            _ ->
                []
        end,
    RuntimeErrorTaintVal1 =
        case Stack of
            {var, _, '_'} ->
                [];
            {var, _, StackVarName} ->
                [
                    ?EMIT_INSTR(Anno, push, [?NILL(Anno)]),
                    ?EMIT_INSTR(Anno, store_var, [{string, Anno, atom_to_list(StackVarName)}])
                ];
            _ ->
                []
        end ++ RuntimeErrorTaintVal,

    {clause, Anno, [?TUPLE([ExceptionClass, Pattern, Stack])], Guard,
        [?EMIT_INSTR(Anno, try_catch, [?ATOM(catch_enter), TryBlockId]) | RuntimeErrorTaintVal1] ++ PatternPrequel ++
            Body1 ++
            [LastExpr]}.

-spec instrument_if_clause(clause(), #rewrite_state{}) -> clause().
instrument_if_clause({clause, Anno, [], Guards, Body}, State) ->
    {LastExpr, Body1} = instrument_body(Body, [], State),
    {clause, Anno, [], Guards, Body1 ++ [LastExpr]}.

-spec instrument_expression(expr() | erl_parse:af_binelement(expr()), #rewrite_state{}) -> triple().
instrument_expression({match, Anno, Pattern, RHS}, State) ->
    {Pre, RHS1, []} = ssa_iffy(instrument_expression(RHS, State)),
    Post = instrument_pattern(Pattern, State),
    {Pre, {match, Anno, Pattern, RHS1}, [?EMIT_INSTR(Anno, duplicate, [])] ++ Post};
% If E is a conditional match operator expression P ?= E_0, where P is a pattern, then Rep(E) = {maybe_match,ANNO,Rep(P),Rep(E_0)}.
instrument_expression({maybe_match, Anno, Pattern, RHS}, State) ->
    {Pre, RHS1, []} = ssa_iffy(instrument_expression(RHS, State)),
    Post = instrument_pattern(Pattern, State),
    {Pre, {maybe_match, Anno, Pattern, RHS1}, [?EMIT_INSTR(Anno, duplicate, [])] ++ Post};
instrument_expression({'receive', Anno, ReceiveCaseClauses, AfterExpr, AfterBody}, State) ->
    ReceiveInstr = [?EMIT_INSTR(Anno, receive_trace, [])],
    InstrumentedClauses = [instrument_case_clause(C, ReceiveInstr, State) || C <- ReceiveCaseClauses],
    {LastAfterExpr, AfterBody1} = instrument_body(AfterBody, [], State),
    {AfterExprPre0, AfterExpr1, []} = ssa_iffy(instrument_expression(AfterExpr, State)),
    % The taint value of AfterExpr is not interesting (unless we want to detect some weird timing attacks)
    % So we just pop it off the stack.
    AfterExprPre1 = AfterExprPre0 ++ [?EMIT_INSTR(Anno, pop, [])],
    {TempVar, NewExpr} = expr_to_var({'receive', Anno, InstrumentedClauses, AfterExpr1, AfterBody1 ++ [LastAfterExpr]}),
    {AfterExprPre1 ++ [NewExpr], TempVar, []};
instrument_expression({'receive', Anno, ReceiveCaseClauses}, State) ->
    ReceiveInstr = [?EMIT_INSTR(Anno, receive_trace, [])],
    InstrumentedClauses = [instrument_case_clause(C, ReceiveInstr, State) || C <- ReceiveCaseClauses],
    {TempVar, NewExpr} = expr_to_var({'receive', Anno, InstrumentedClauses}),
    {[NewExpr], TempVar, []};
instrument_expression({'case', Anno, Expr, CaseClauses}, State) ->
    {PreExpr, Expr1, []} = ssa_iffy(instrument_expression(Expr, State)),
    InstrumentedClauses = [instrument_case_clause(C, [], State) || C <- CaseClauses],
    % Since case has a body, it can't be executed at an arbirary point in expr tree,
    % because stack isn't in a proper state. Therefore we replace it with a temp variable
    {TempVar, NewExpr} = expr_to_var({'case', Anno, Expr1, InstrumentedClauses}),
    {PreExpr ++ [NewExpr], TempVar, []};
instrument_expression({'if', Anno, IfClauses}, State) ->
    InstrumentedClauses = [instrument_if_clause(C, State) || C <- IfClauses],
    % Contains body, extracting a temp var
    {TempVar, NewExpr} = expr_to_var({'if', Anno, InstrumentedClauses}),
    {[NewExpr], TempVar, []};
instrument_expression({'maybe', Anno, Body}, State) ->
    {LastExpr, Body1} = instrument_body(Body, [], State),
    {TempVar, NewExpr} = expr_to_var({'maybe', Anno, Body1 ++ [LastExpr]}),
    {[NewExpr], TempVar, []};
% If E is a maybe expression maybe B else Ec_1 ; ... ; Ec_k end, where B is a body and each Ec_i is an else clause then Rep(E) = {'maybe',ANNO,Rep(B),{'else',ANNO,[Rep(Ec_1), ..., Rep(Tc_k)]}}:w
instrument_expression({'maybe', Anno, Body, {'else', AnnoElse, ElseClauses}}, State) ->
    {_LastExpr, Body1} = instrument_body(Body, [], State),
    InstrumentedClauses = [instrument_case_clause(C, [], State) || C <- ElseClauses],
    % Since maybe has a body, it can't be executed at an arbirary point in expr tree,
    % because stack isn't in a proper state. Therefore we replace it with a temp variable
    {TempVar, NewExpr} = expr_to_var({'maybe', Anno, Body1, {'else', AnnoElse, InstrumentedClauses}}),
    {[NewExpr], TempVar, []};
instrument_expression({block, Anno, Body}, State) ->
    {LastExpr, Body1} = instrument_body(Body, [], State),
    % Contains body, extracting a temp var
    {TempVar, NewExpr} = expr_to_var({block, Anno, Body1 ++ [LastExpr]}),
    {[NewExpr], TempVar, []};
instrument_expression({'catch', Anno, Expr}, State) ->
    {PreExpr, Expr1, []} = ssa_iffy(instrument_expression(Expr, State)),
    {[], {'catch', Anno, {'block', Anno, PreExpr ++ [Expr1]}}, []};
instrument_expression({call, Anno, {remote, _, {atom, _, finer_taint}, {atom, _, source}}, Args}, State) when
    length(Args) == 2; length(Args) == 1
->
    ArgToTaint =
        case Args of
            [Arg] -> Arg;
            [_Tag, Arg] -> Arg
        end,
    {Pre, ArgToTaint1, []} = ssa_iffy(instrument_expression(ArgToTaint, State)),
    ActualSourceArgs =
        case Args of
            [_] -> [ArgToTaint1];
            [Tag, _] -> [Tag, ArgToTaint1]
        end,
    {Pre, ?EMIT_INSTR(Anno, actual_source, ActualSourceArgs),
        % The source instruction needs to be ssa-ffied, so we insert a noop (push/pop pair) in the Post Instructions
        [?EMIT_INSTR(Anno, push, [?NILL(Anno)]), ?EMIT_INSTR(Anno, pop, [])]};
% Note: skip ets function, by assuming return value is always untainted
instrument_expression(Call = {call, Anno, {remote, _, {atom, _, ets}, _}, _}, State) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], Call, []};
instrument_expression({call, Anno, {remote, _, {atom, _, finer_taint}, {atom, _, sink}}, [Arg]}, State) ->
    {Pre, Arg1, []} = ssa_iffy(instrument_expression(Arg, State)),
    {Pre, Arg1, [?EMIT_INSTR(Anno, actual_sink, [])]};
% Skip put(enabled_taint, _) calls
instrument_expression(
    Expr = {call, Anno, {remote, _, {atom, _, erlang}, {atom, _, put}}, [{atom, _, enabled_taint} | _Args]},
    State
) ->
    {[], Expr, [?EMIT_INSTR(Anno, push, [?NILL(Anno)])]};
% Same as send, because we do not want to worry about timing in the taint world
% Note: refactor implemntation to reuse the send code
instrument_expression(
    {call, Anno, {remote, _, {atom, _, erlang}, {atom, _, send_after}}, [Interval, Pid, Message | Tail]}, State
) ->
    {IntervalPreInstrument, IntervalE, []} = ssa_iffy(instrument_expression(Interval, State)),
    {PidPreInstrument, PidE, []} = ssa_iffy(instrument_expression(Pid, State)),
    {MessagePreInstrument, MessageE, []} = ssa_iffy(instrument_expression(Message, State)),
    {Pre, _TailE} =
        case Tail of
            [] ->
                {[], []};
            [Expr] ->
                {P, E, []} = ssa_iffy(instrument_expression(Expr, State)),
                {P, E}
        end,
    {
        IntervalPreInstrument ++ PidPreInstrument ++ MessagePreInstrument ++
            [
                ?EMIT_INSTR(Anno, send, [])
            ] ++ Pre,
        {call, Anno, {remote, Anno, {atom, Anno, erlang}, {atom, Anno, send_after}}, [IntervalE, PidE, MessageE | Tail]},
        [{call, Anno, {remote, Anno, ?ATOM(seq_trace), ?ATOM(set_token)}, [{nil, Anno}]}]
    };
instrument_expression({call, Anno, {remote, _, {atom, _, erlang}, {atom, _, send}}, [Pid, Message | Tail]}, State) ->
    {PidPreInstrument, PidE, []} = ssa_iffy(instrument_expression(Pid, State)),
    {MessagePreInstrument, MessageE, []} = ssa_iffy(instrument_expression(Message, State)),
    {Pre, _TailE} =
        case Tail of
            [] ->
                {[], []};
            [Expr] ->
                {P, E, []} = ssa_iffy(instrument_expression(Expr, State)),
                {P, E}
        end,
    {
        PidPreInstrument ++ MessagePreInstrument ++
            [
                ?EMIT_INSTR(Anno, send, [])
            ] ++ Pre,
        {call, Anno, {remote, Anno, {atom, Anno, erlang}, {atom, Anno, send}}, [PidE, MessageE | Tail]},
        [{call, Anno, {remote, Anno, ?ATOM(seq_trace), ?ATOM(set_token)}, [{nil, Anno}]}]
    };
%% Note deal with indirect functioncalls
instrument_expression({call, Anno, {remote, _, Module, Func}, Args}, State) ->
    {PreInstruments, ReverseInstrumentedArgs, []} = unzip_flatten(
        [ssa_iffy(instrument_expression(A, State)) || A <- lists:reverse(Args)]
    ),
    {PreFunc, Func1, []} = ssa_iffy(instrument_expression(Func, State)),
    %% We assume the dynamic functions can't be tainted so we just discard the taint value of Func
    %% Lambdas can't be called with this method as they aren't exported from a module.
    %% Therefore we just pop the taint value of the function off the stack
    PreFunc1 = PreFunc ++ [?EMIT_INSTR(Anno, pop, [])],
    {Module1, Func2} = intercepted_functions(Module, Func1, State),
    ReverseInstrumentedArgs1 =
        case Module1 of
            % finer_taint:* function expect the first argument to be a CallbackModule, which we add here
            % It's added at the end, because ReverseInstrumentedArgs list is in the reverse order
            {atom, _, finer_taint} ->
                ReverseInstrumentedArgs ++
                    [
                        {atom, Anno, State#rewrite_state.finer_taint_module},
                        {string, Anno,
                            atom_to_list(State#rewrite_state.module) ++ ".erl:" ++ integer_to_list(erl_anno:line(Anno))}
                    ];
            _ ->
                ReverseInstrumentedArgs
        end,
    % The call_fun/fun_apply instructions need arity of length(Args) (and NOT ReverseInstrumentedArgs1)
    % This is because length(Args) number of arguments was put on the stack, so fun_apply needs to pop
    % length(Args) of arguments off it.
    %
    % In other words the only case where length(ReverseInstrumentedArgs1) =/= length(Args) is in the
    % intrsinsic function case, where an erlang function is replaced by an abstract machine instruction.
    % In that case the instrinsic should behave excatly the same as the original function. The fact that
    % it also takes an additional CallbackModule arguments should be completly transparent.
    {
        PreFunc1 ++ PreInstruments ++ [?EMIT_INSTR(Anno, call_fun, [Module1, Func2, ?INT(length(Args))])],
        {call, Anno, {remote, Anno, Module1, Func2}, lists:reverse(ReverseInstrumentedArgs1)},
        [?EMIT_INSTR(Anno, fun_apply, [?TUPLE([Module1, Func2, ?INT(length(Args))])])]
    };
instrument_expression({call, Anno, Func, Args}, State) ->
    {PreInstruments, ReverseInstrumentedArgs, []} = unzip_flatten(
        [ssa_iffy(instrument_expression(A, State)) || A <- lists:reverse(Args)]
    ),
    {PreFunc, Func1, []} = ssa_iffy(instrument_expression(Func, State)),
    CurrentModule = ?ATOM(State#rewrite_state.module),
    FuncName =
        case Func1 of
            Atm = {atom, _, _} -> Atm;
            {var, _, _} -> ?ATOM(variable_func);
            _ -> ?ATOM(lambda_func)
        end,
    PreFunc1 =
        PreFunc ++
            [?EMIT_INSTR(Anno, restore_capture, [?TUPLE([CurrentModule, FuncName, ?INT(length(Args))])])],
    {
        PreFunc1 ++ PreInstruments ++
            [?EMIT_INSTR(Anno, call_fun, [CurrentModule, FuncName, ?INT(length(Args))])],
        {call, Anno, Func1, lists:reverse(ReverseInstrumentedArgs)},
        [
            ?EMIT_INSTR(Anno, fun_apply, [?TUPLE([CurrentModule, FuncName, ?INT(length(Args))])]),
            % Need to cleanup the scope we introdcued with restore_capture,
            % reusing func_ret for this because it only drops the scope
            ?EMIT_INSTR(Anno, func_ret, [?ATOM(dropping_lambda_capture)])
        ]
    };
instrument_expression({tuple, Anno, TupleValues}, State) ->
    {PreInstruments, TupleValues1, []} = unzip_flatten(
        [ssa_iffy(instrument_expression(V, State)) || V <- TupleValues]
    ),
    TupleInstr = [?EMIT_INSTR(Anno, construct_pattern, [?TUPLE([?ATOM(tuple), ?INT(length(TupleValues))])])],
    {PreInstruments, {tuple, Anno, TupleValues1}, TupleInstr};
% Note: do this for erlang:send too, consider erlang:apply(erlang, send, ..) too
instrument_expression({op, Anno, '!', Pid, Message}, State) ->
    {PidPreInstrument, PidE, []} = ssa_iffy(instrument_expression(Pid, State)),
    {MessagePreInstrument, MessageE, []} = ssa_iffy(instrument_expression(Message, State)),
    {
        PidPreInstrument ++ MessagePreInstrument ++
            [
                ?EMIT_INSTR(Anno, send, [])
            ],
        {op, Anno, '!', PidE, MessageE},
        [{call, Anno, {remote, Anno, ?ATOM(seq_trace), ?ATOM(set_token)}, [{nil, Anno}]}]
    };
instrument_expression({op, Anno, Op, Arg}, State) ->
    {PreInstrument, RHS, []} = ssa_iffy(instrument_expression(Arg, State)),
    OpPreInstrument = ?EMIT_INSTR(Anno, call_fun, [?ATOM(operators), ?ATOM(Op), ?INT(1)]),
    OpInstrument = ?EMIT_INSTR(Anno, fun_apply, [?TUPLE([?ATOM(operators), ?ATOM(Op), ?INT(1)])]),
    {PreInstrument ++ [OpPreInstrument], {op, Anno, Op, RHS}, [OpInstrument]};
instrument_expression({op, Anno, Op, LeftArg, RightArg}, State) ->
    {LeftPreInstrument, LHS, []} = ssa_iffy(instrument_expression(LeftArg, State)),
    {RightPreInstrument, RHS, []} = ssa_iffy(instrument_expression(RightArg, State)),
    OpPreInstrument = ?EMIT_INSTR(Anno, call_fun, [?ATOM(operators), ?ATOM(Op), ?INT(2)]),
    OpInstrument = ?EMIT_INSTR(Anno, fun_apply, [?TUPLE([?ATOM(operators), ?ATOM(Op), ?INT(2)])]),
    if
        (Op == 'andalso' orelse Op == 'orelse') ->
            {RHSTempVar, NewRHS} = expr_to_var(RHS),
            {
                LeftPreInstrument,
                {op, Anno, Op, LHS,
                    {block, Anno, RightPreInstrument ++ [OpPreInstrument, NewRHS, OpInstrument, RHSTempVar]}},
                []
            };
        true ->
            {
                LeftPreInstrument ++ RightPreInstrument ++ [OpPreInstrument],
                {op, Anno, Op, LHS, RHS},
                [OpInstrument]
            }
    end;
instrument_expression({cons, Anno, HeadE, TailE}, State) ->
    {PreH, HeadExpr, []} = ssa_iffy(instrument_expression(HeadE, State)),
    {PreT, TailExpr, []} = ssa_iffy(instrument_expression(TailE, State)),
    {
        PreT ++ PreH ++ [?EMIT_INSTR(Anno, construct_pattern, [?TUPLE([?ATOM(cons)])])],
        {cons, Anno, HeadExpr, TailExpr},
        []
    };
instrument_expression(Try = {'try', Anno, TryBody, CaseClauses, CatchClauses, AfterBody}, State) ->
    TryBlockId = ?TUPLE([?ATOM(State#rewrite_state.module), ?INT(erl_anno:line(Anno)), ?INT(erlang:phash2(Try))]),
    {TryLastBodyExpr, TryBody1} = instrument_body(TryBody, [], State),
    {TryLastExpr, TryLastBodyExpr1} = expr_to_var(TryLastBodyExpr),
    TryBody2 = TryBody1 ++ [TryLastBodyExpr1],
    InstrumentedCaseClauses = [instrument_case_clause(C, [], State) || C <- CaseClauses],
    InstrumentedCatchClauses = [instrument_catch_clause(C, State, TryBlockId) || C <- CatchClauses],
    AfterBody2 =
        case AfterBody of
            [] ->
                [];
            _ ->
                {AfterLastExpr, AfterBody1} = instrument_body(AfterBody, [], State),
                AfterBody1 ++ [AfterLastExpr, ?EMIT_INSTR(Anno, pop, [])]
        end,
    TryEnter = [?EMIT_INSTR(Anno, try_catch, [?ATOM(try_enter), TryBlockId])],
    TryBody3 = TryEnter ++ TryBody2 ++ [?EMIT_INSTR(Anno, try_catch, [?ATOM(try_exit), TryBlockId]), TryLastExpr],
    {[], {'try', Anno, TryBody3, InstrumentedCaseClauses, InstrumentedCatchClauses, AfterBody2}, []};
instrument_expression({'fun', Anno, {clauses, FuncClauses}}, State) ->
    {L, Col} = erl_anno:location(Anno),
    Function = list_to_atom(
        lists:flatten(io_lib:format("lambda_~p_~p_~p_anon", [State#rewrite_state.module, L, Col]))
    ),
    VarsInLambda = get_all_variable_names(FuncClauses),
    Clauses1 = lists:map(fun(Clause) -> instrument_function_clause(Clause, Function, State) end, FuncClauses),
    {
        [?EMIT_INSTR(Anno, capture_closure, [string_list_to_ast(Anno, VarsInLambda)])],
        {'fun', Anno, {clauses, Clauses1}},
        []
    };
instrument_expression({'fun', Anno, {function, Name, Arity}}, State) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], {'fun', Anno, {function, Name, Arity}}, []};
instrument_expression(F = {'fun', Anno, {function, _Module, _Name, _Arity}}, State) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], F, []};
instrument_expression({named_fun, Anno, Name, FuncClauses}, State) ->
    {L, Col} = erl_anno:location(Anno),
    Function = list_to_atom(
        lists:flatten(
            io_lib:format("lambda_~p_~p_~p_named_~s", [State#rewrite_state.module, L, Col, atom_to_list(Name)])
        )
    ),
    Clauses1 = lists:map(fun(Clause) -> instrument_function_clause(Clause, Function, State) end, FuncClauses),
    VarsInLambda = get_all_variable_names(FuncClauses),
    {
        [
            ?EMIT_INSTR(Anno, capture_closure, [string_list_to_ast(Anno, VarsInLambda)]),
            % Here we store the closure of the recursive function under the name of the recursive function
            ?EMIT_INSTR(Anno, duplicate, []),
            ?EMIT_INSTR(Anno, store_var, [{string, Anno, lists:flatten(io_lib:format("~s", [Name]))}])
        ],
        {'named_fun', Anno, Name, Clauses1},
        []
    };
instrument_expression({bin, Anno, BinValues}, State) ->
    {PreInstruments, BinValues1, []} = unzip_flatten(
        [instrument_binelement(V, State) || V <- BinValues]
    ),
    % This computes the runtime byte sizes of each bin_element
    % Currently if there is a function call in the bin_element
    % it will be called twice. If this becomes a problem we
    % can introduce a temp variable.
    Sizes = lists:map(
        fun(Expr = {bin_element, _, _, _, _}) ->
            Args = [{bin, Anno, [Expr]}],
            % Do byte precision for now, we can change to bit when needed
            {call, Anno, {remote, Anno, ?ATOM(erlang), ?ATOM(byte_size)}, Args}
        end,
        BinValues
    ),
    Sizes1 = list_to_list_ast(Anno, Sizes),
    {
        PreInstruments ++ [?EMIT_INSTR(Anno, construct_pattern, [?TUPLE([?ATOM(bitstring), Sizes1])])],
        {bin, Anno, BinValues1},
        []
    };
%An empty map constructor (#{}) is untainted
instrument_expression({map, Anno, []}, State) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], {map, Anno, []}, []};
%When constructing a map, we pretend we are updating an empty map
instrument_expression({map, Anno, Associations}, State) ->
    instrument_expression({map, Anno, {map, Anno, []}, Associations}, State);
%For updating a map we push onto the stack:
% 1) taint values for all the keys
% 2) taint values for all the values
% 3) taint value for the map being updated
% 4) construct pattern instruction with the value of keys evaluated at runtime in
% the same order as taint keys/values were pushed onto the stack
instrument_expression({map, Anno, MapToUpdate, Associations}, State) ->
    {MapInstruments, MapToUpdate1, []} = ssa_iffy(instrument_expression(MapToUpdate, State)),
    {KeyInstruments, ValueInstruments} = lists:unzip(
        lists:map(
            %AssocType can be map_field_assoc or map_field_exact, we don't care which one it is)
            fun({_AssocType, _Anno, Key, Value}) ->
                {ssa_iffy(instrument_expression(Key, State)), ssa_iffy(instrument_expression(Value, State))}
            end,
            Associations
        )
    ),
    {PreKeyInstruments, NewKeys, []} = unzip_flatten(KeyInstruments),
    {PreValueInstruments, NewValues, []} = unzip_flatten(ValueInstruments),
    Associations1 = [
        {AssocType, AnnoAssoc, Key, Value}
     || {{AssocType, AnnoAssoc, _OldKey, _OldValue}, {Key, Value}} <-
            lists:zip(Associations, lists:zip(NewKeys, NewValues))
    ],
    Expr = {map, Anno, MapToUpdate1, Associations1},
    PreInstruments = PreKeyInstruments ++ PreValueInstruments ++ MapInstruments,
    %The right most Key in the expression is top of the stack, so we reverse the list of match the order
    ListOfKeys = list_to_list_ast(Anno, lists:reverse(NewKeys)),
    {PreInstruments ++ [?EMIT_INSTR(Anno, construct_pattern, [?TUPLE([?ATOM(map), ListOfKeys])])], Expr, []};
instrument_expression(Expr = {var, Anno, Var}, State) ->
    {[?EMIT_INSTR(Anno, get_var, [{string, Anno, atom_to_list(Var)}])], Expr, []};
instrument_expression(Expr = {integer, Anno, _}, State) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], Expr, []};
instrument_expression(Expr = {string, Anno, _}, State) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], Expr, []};
% This is a workaround to fix ?MODULE macro in modules we rename
% The ?MODULE macro is expanded before this instrumentation so we have
% to change all atoms that match the original module name
% This is needed to handle code like in proc_lib like:
% https://github.com/erlang/otp/blob/master/lib/stdlib/src/proc_lib.erl#L189
instrument_expression({atom, Anno, Module}, State = #rewrite_state{module = Module, renamed_modules = Renames}) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], ?ATOM(maps:get(Module, Renames, Module)), []};
% gen_server atom is used outside of gen_server too, so we have to always rename it
instrument_expression({atom, Anno, gen_server}, State = #rewrite_state{renamed_modules = Renames}) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], ?ATOM(maps:get(gen_server, Renames)), []};
instrument_expression(Expr = {atom, Anno, _}, State) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], Expr, []};
instrument_expression(Expr = {char, Anno, _}, State) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], Expr, []};
instrument_expression(Expr = {float, Anno, _}, State) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], Expr, []};
instrument_expression(Expr = {nil, Anno}, State) ->
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], Expr, []};
instrument_expression(Comprehension = {lc, _, _, _}, State) ->
    instrument_expression(rewrite_comprehension(Comprehension), State);
instrument_expression(Comprehension = {mc, _, _, _}, State) ->
    instrument_expression(rewrite_comprehension(Comprehension), State);
instrument_expression(Comprehension = {bc, Anno, _, _}, State) ->
    % Note: implement binary comprehension
    %For now we just pretend it's not tainted and don't do anything.
    {[?EMIT_INSTR(Anno, push, [?NILL(Anno)])], Comprehension, []}.

-spec instrument_binelement(erl_parse:af_binelement(expr()), #rewrite_state{}) ->
    {[expr()], erl_parse:af_binelement(expr()), [expr()]}.
instrument_binelement({bin_element, Anno, Expr, Size, Tsl}, State) ->
    {Pre, NewExpr, []} = ssa_iffy(instrument_expression(Expr, State)),
    {Pre, {bin_element, Anno, NewExpr, Size, Tsl}, []}.

-spec instrument_pattern(expr() | erl_parse:af_binelement(expr()), #rewrite_state{}) -> [expr()].
% If P is a universal pattern _, then Rep(P) = {var,ANNO,'_'}.
instrument_pattern({var, Anno, '_'}, State) ->
    [?EMIT_INSTR(Anno, pop, [])];
% If P is a variable pattern V, then Rep(P) = {var,ANNO,A}, where A is an atom
instrument_pattern({var, Anno, Var}, State) ->
    [?EMIT_INSTR(Anno, store_var, [{string, Anno, atom_to_list(Var)}])];
% If P is a compound pattern P_1 = P_2, then Rep(P) = {match,ANNO,Rep(P_1),Rep(P_2)}
instrument_pattern(Expr = {match, Anno, Lhs, Rhs}, State) ->
    RhsInstr = instrument_pattern(Rhs, State),
    LhsInstr = instrument_pattern(Lhs, State),
    TempName = get_temp_varname_for_expr(Expr, "PatternTmpVar_"),
    %% We store what we are matching against
    [?EMIT_INSTR(Anno, store_var, [{string, Anno, TempName}])] ++
        %% Then we put it back on top of the stack
        [?EMIT_INSTR(Anno, get_var, [{string, Anno, TempName}])] ++
        %% Then pattern match the RHS
        RhsInstr ++
        %% Then we get the original expression again and match against LHS
        [?EMIT_INSTR(Anno, get_var, [{string, Anno, TempName}])] ++
        LhsInstr;
% Very simple handling of "a constant string" ++ AVar pattern
instrument_pattern({'op', _Anno, '++', {string, _, _}, RHS}, State) ->
    instrument_pattern(RHS, State);
% Patterns over literals, ie. -1, 1 bsl 0
% Note that using variables (-X = -1) is not legal
% so these will always be constants and we can just
% pop the respective taint value, same as the other constants
instrument_pattern({op, Anno, _Op, _}, State) ->
    [?EMIT_INSTR(Anno, pop, [])];
instrument_pattern({op, Anno, _Op, _, _}, State) ->
    [?EMIT_INSTR(Anno, pop, [])];
% If L is an integer literal, then Rep(L) = {integer,ANNO,L}.
instrument_pattern({integer, Anno, _}, State) ->
    [?EMIT_INSTR(Anno, pop, [])];
% If L is a character literal, then Rep(L) = {char,ANNO,L}.
instrument_pattern({char, Anno, _}, State) ->
    [?EMIT_INSTR(Anno, pop, [])];
% If L is a string literal consisting of the characters C_1, ..., C_k, then Rep(L) = {string,ANNO,[C_1, ..., C_k]}
instrument_pattern({string, Anno, _}, State) ->
    [?EMIT_INSTR(Anno, pop, [])];
% If L is an atom literal, then Rep(L) = {atom,ANNO,L}.
instrument_pattern({atom, Anno, _}, State) ->
    [?EMIT_INSTR(Anno, pop, [])];
instrument_pattern({float, Anno, _}, State) ->
    [?EMIT_INSTR(Anno, pop, [])];
% If P is a nil pattern [], then Rep(P) = {nil,ANNO}
instrument_pattern({nil, Anno}, State) ->
    [?EMIT_INSTR(Anno, pop, [])];
% If E is a bitstring constructor <<E_1:Size_1/TSL_1, ..., E_k:Size_k/TSL_k>>,
% where each Size_i is an expression and each TSL_i is a type specificer list,
% then Rep(E) = {bin,ANNO,[{bin_element,ANNO,Rep(E_1),Rep(Size_1),Rep(TSL_1)}, ..., {bin_element,ANNO,Rep(E_k),Rep(Size_k),Rep(TSL_k)}]}
instrument_pattern({bin_element, _Anno, Expr, _Size, _Tsl}, State) ->
    instrument_pattern(Expr, State);
instrument_pattern({bin, Anno, BinValues}, State) ->
    % GatherSizeTsl walks the bin_elements of the bin expression
    % and puts all the Sizes and Tsl into a list. The sizes and Tsl
    % can be used to infer the required bit offsets in the bitstrings
    % https://www.erlang.org/doc/programming_examples/bit_syntax.html#segments
    TslToAst = fun
        (X) when is_atom(X) -> ?ATOM(X);
        ({X, I}) -> ?TUPLE([?ATOM(X), ?INT(I)])
    end,

    GatherSizeTsl = fun
        GatherSizeTsl([], Acc) ->
            Acc;
        GatherSizeTsl([Expr = {bin_element, _Anno, _Expr, Size, Tsl} | Tail], {AccExpr, AccSizes}) ->
            ExprInstr = instrument_pattern(Expr, State),
            Size1 =
                case {Size, Tsl} of
                    {default, default} ->
                        ?TUPLE([?ATOM(default), ?ATOM(default)]);
                    {default, _} ->
                        ?TUPLE([
                            ?ATOM(default),
                            list_to_list_ast(Anno, lists:map(TslToAst, Tsl))
                        ]);
                    {_, default} ->
                        ?TUPLE([Size, ?ATOM(default)]);
                    {_Size, _Tsl} ->
                        ?TUPLE([Size, list_to_list_ast(Anno, lists:map(TslToAst, Tsl))])
                end,
            GatherSizeTsl(Tail, {AccExpr ++ ExprInstr, AccSizes ++ [Size1]})
    end,

    {Instruments, Sizes} = GatherSizeTsl(BinValues, {[], []}),
    [?EMIT_INSTR(Anno, deconstruct_pattern, [?TUPLE([?ATOM(bitstring), list_to_list_ast(Anno, Sizes)])]) | Instruments];
% If P is a map pattern #{A_1, ..., A_k}, where each A_i is an association P_i_1 := P_i_2,
% then Rep(P) = {map,ANNO,[Rep(A_1), ..., Rep(A_k)]}
% If A is an association K => V, then Rep(A) = {map_field_assoc,ANNO,Rep(K),Rep(V)}.
% If A is an association K := V, then Rep(A) = {map_field_exact,ANNO,Rep(K),Rep(V)}
instrument_pattern({map, Anno, Associations}, State) ->
    {KeyInstrumentPair, ValueInstruments} = lists:unzip(
        lists:map(
            % AssocType can be map_field_assoc or map_field_exact, we don't care which one it is)
            fun({_AssocType, _Anno, Key, Value}) ->
                {{Key, instrument_pattern(Key, State)}, instrument_pattern(Value, State)}
            end,
            Associations
        )
    ),
    {Keys, KeyInstruments} = lists:unzip(KeyInstrumentPair),
    ListOfKeys = list_to_list_ast(Anno, Keys),
    [?EMIT_INSTR(Anno, deconstruct_pattern, [?TUPLE([?ATOM(map), ListOfKeys])])] ++
        concat(ValueInstruments) ++
        concat(KeyInstruments);
% If P is a cons pattern [P_h | P_t], then Rep(P) = {cons,ANNO,Rep(P_h),Rep(P_t)}
instrument_pattern({cons, Anno, Head, Tail}, State) ->
    TailPattern = instrument_pattern(Tail, State),
    HeadPattern = instrument_pattern(Head, State),
    [?EMIT_INSTR(Anno, deconstruct_pattern, [?TUPLE([?ATOM(cons)])]) | (HeadPattern ++ TailPattern)];
% If P is a tuple pattern {P_1, ..., P_k}, then Rep(P) = {tuple,ANNO,[Rep(P_1), ..., Rep(P_k)]}
instrument_pattern({tuple, Anno, TuplePatterns}, State) ->
    Instruments = lists:flatten([instrument_pattern(P, State) || P <- TuplePatterns]),
    [?EMIT_INSTR(Anno, deconstruct_pattern, [?TUPLE([?ATOM(tuple), ?INT(length(TuplePatterns))])]) | Instruments].

% intercepted_functions/2 lets us replace some function implementation
% with ones specified in our own modules. This is mainly useful for
% intercepting stdlib functions.
-spec intercepted_functions(T, T, #rewrite_state{}) -> {T, T} when
    T :: expr().
intercepted_functions(M = {atom, _, maps}, F = {atom, _, iterator}, #rewrite_state{module = modeled_taint_maps}) ->
    {M, F};
intercepted_functions(M = {atom, _, maps}, F = {atom, _, next}, #rewrite_state{module = modeled_taint_maps}) ->
    {M, F};
intercepted_functions({atom, Anno, erlang}, {atom, _, setelement}, _State) ->
    {?ATOM(finer_taint), ?ATOM(set_element)};
intercepted_functions({atom, Anno, lists}, F = {atom, _, member}, _State) ->
    {?ATOM(modeled_taint_lists), F};
intercepted_functions({atom, Anno, lists}, F = {atom, _, keyfind}, _State) ->
    {?ATOM(modeled_taint_lists), F};
intercepted_functions({atom, Anno, lists}, F = {atom, _, reverse}, _State) ->
    {?ATOM(modeled_taint_lists), F};
intercepted_functions({atom, Anno, erlang}, {atom, _, apply}, _State) ->
    {?ATOM(modeled_erlang), ?ATOM(mapply)};
intercepted_functions({atom, Anno, erlang}, {atom, _, is_map_key}, _State) ->
    {?ATOM(modeled_erlang), ?ATOM(is_map_key)};
% Do not rewrite put/get inside modeled_erlang
intercepted_functions({atom, Anno, erlang}, {atom, _, hibernate}, #rewrite_state{module = M}) when
    M =/= modeled_erlang
->
    {?ATOM(modeled_erlang), ?ATOM(mhibernate)};
intercepted_functions({atom, Anno, erlang}, {atom, _, put}, #rewrite_state{module = M}) when M =/= modeled_erlang ->
    {?ATOM(modeled_erlang), ?ATOM(mput)};
intercepted_functions({atom, Anno, erlang}, {atom, _, get}, #rewrite_state{module = M}) when M =/= modeled_erlang ->
    {?ATOM(modeled_erlang), ?ATOM(mget)};
intercepted_functions({atom, Anno, erlang}, {atom, _, element}, _State) ->
    {?ATOM(modeled_erlang), ?ATOM(elemnt)};
intercepted_functions({atom, Anno, ModuleName}, Func, #rewrite_state{renamed_modules = Renames}) ->
    {?ATOM(maps:get(ModuleName, Renames, ModuleName)), Func};
% Module can be any expression
intercepted_functions(Module, Func, #rewrite_state{renamed_modules = Renames}) when is_tuple(Module) ->
    Anno = element(2, Module),
    ModuleExpr =
        {call, Anno, {remote, Anno, ?ATOM(maps), ?ATOM(get)}, [Module, map_to_map_ast(Anno, Renames), Module]},
    {ModuleExpr, Func}.

% If all types were exported this should be
% split_to_next_qualifier(af_qualifier_seq(), [expr() | af_guard()]) -> {[expr()| af_guard()], af_qualifier_seq()}.
-spec split_to_next_qualifier([expr() | erl_parse:af_generator()], [expr() | dynamic()]) ->
    {dynamic(), [expr() | erl_parse:af_generator()]}.
split_to_next_qualifier([], Filters) ->
    {lists:reverse(Filters), []};
split_to_next_qualifier(Rest = [Head | Tail], Filters) ->
    case Head of
        {generate, _, _, _} ->
            {lists:reverse(Filters), Rest};
        {b_generate, _, _, _} ->
            {lists:reverse(Filters), Rest};
        {m_generate, _, _, _} ->
            {lists:reverse(Filters), Rest};
        _ ->
            % eqwalizer:ignore incompatible_types needs a deeper fix for otp 28
            case erl_lint:is_guard_test(Head) of
                true -> split_to_next_qualifier(Tail, [[Head] | Filters]);
                _ -> {Filters, [Head | Tail]}
            end
    end.

-spec rewrite_qualifier([expr() | erl_parse:af_generator()], erl_parse:abstract_expr(), [expr()]) -> expr().
rewrite_qualifier([], Body, [RecursiveCall]) ->
    Anno = element(2, RecursiveCall),
    {cons, Anno, Body, RecursiveCall};
rewrite_qualifier([Head = {generate, Anno, Pattern, ListExpr} | Tail0], Body, EmptyClauseBody) ->
    {Guards, Tail} = split_to_next_qualifier(Tail0, []),
    Suffix = expr_hash(Head),
    GenLc = list_to_atom("GenLc" ++ Suffix),
    GenLcVar = {var, Anno, GenLc},
    TailVar = {var, Anno, list_to_atom("GenlcTail" ++ Suffix)},
    % GenLc([]) -> <BackClause>;
    EmptyClause = {clause, Anno, [{nil, Anno}], [], EmptyClauseBody},
    % GenLc([Pattern | TailVar]) -> <rewrite_qualifier(Tail, GenLc(TailVar))>;
    MainClause =
        {clause, Anno, [{cons, Anno, Pattern, TailVar}], Guards, [
            rewrite_qualifier(Tail, Body, [{call, Anno, GenLcVar, [TailVar]}])
        ]},
    % GenLc([_ | TailVar]) -> GenLc(TailVar);
    FallbackClause = {clause, Anno, [{cons, Anno, {var, Anno, '_'}, TailVar}], [], [{call, Anno, GenLcVar, [TailVar]}]},
    Clauses = [EmptyClause, MainClause, FallbackClause],
    {call, Anno, {named_fun, Anno, GenLc, Clauses}, [ListExpr]};
rewrite_qualifier(
    [
        {m_generate, Anno, {map_field_exact, _Anno, K, V}, MapExpr}
        | Tail0
    ],
    Body,
    EmptyClauseBody
) ->
    ToListExpr = {call, Anno, {remote, Anno, ?ATOM(modeled_taint_maps), ?ATOM(to_list)}, [MapExpr]},
    TuplePattern = ?TUPLE([K, V]),
    rewrite_qualifier([{generate, Anno, TuplePattern, ToListExpr} | Tail0], Body, EmptyClauseBody);
rewrite_qualifier([Head = {b_generate, Anno, Pattern, BinaryExpr} | Tail0], Body, EmptyClauseBody) ->
    {Guards, Tail} = split_to_next_qualifier(Tail0, []),
    Suffix = expr_hash(Head),
    BinGenLc = list_to_atom("BinGenLc" ++ Suffix),
    BinGenLcVar = {var, Anno, BinGenLc},
    TailVar = {var, Anno, list_to_atom("BinGenLcTail" ++ Suffix)},
    TailSegment = {bin_element, Anno, TailVar, default, [binary, {unit, 1}]},
    % GenLc(<<Pattern,TailVar>>) -> <rewrite_qualifier(Tail, GenLc(TailVar))>;
    {bin, _, Segments} = Pattern,
    MainPattern = {bin, Anno, lists:append(Segments, [TailSegment])},
    MainClause =
        {clause, Anno, [MainPattern], Guards, [
            rewrite_qualifier(Tail, Body, [{call, Anno, BinGenLcVar, [TailVar]}])
        ]},
    % GenLc(<<_ | TailVar>>) -> GenLc(TailVar);
    FallbackClause = {clause, Anno, [MainPattern], [], [{call, Anno, BinGenLcVar, [TailVar]}]},
    % GenLc(<<_>>) -> <EmptyClauseBody>;
    EmptyClause = {clause, Anno, [{bin, Anno, [TailSegment]}], [], EmptyClauseBody},
    Clauses = [MainClause, FallbackClause, EmptyClause],
    {call, Anno, {named_fun, Anno, BinGenLc, Clauses}, [BinaryExpr]};
rewrite_qualifier([BoolExpr | Tail], Body, EmptyClauseBody) ->
    Anno = element(2, lists:nth(1, EmptyClauseBody)),
    TrueClause = {clause, Anno, [?ATOM(true)], [], [rewrite_qualifier(Tail, Body, EmptyClauseBody)]},
    FalseClause = {clause, Anno, [?ATOM(false)], [], EmptyClauseBody},
    % Eqwalizer cannot figure out BoolExpr is just expr() and not af_generator()
    % eqwalizer:ignore This should be cast_dynamic, but can't import eqwalizer module here because parse transform
    {'case', Anno, BoolExpr, [TrueClause, FalseClause]}.

% Reverse engineered from core erlang transforms
-spec rewrite_comprehension(expr()) -> expr().
rewrite_comprehension({lc, Anno, ExprBody, Qualifiers}) ->
    rewrite_qualifier(Qualifiers, ExprBody, [{nil, Anno}]);
rewrite_comprehension({mc, Anno, {map_field_assoc, _Anno, K, V}, Qualifiers}) ->
    TupleExpr = ?TUPLE([K, V]),
    ListExpr = rewrite_qualifier(Qualifiers, TupleExpr, [{nil, Anno}]),
    {call, Anno, {remote, Anno, ?ATOM(modeled_taint_maps), ?ATOM(from_list)}, [ListExpr]}.

-spec get_all_variable_names([expr() | clause()]) -> [atom()].
get_all_variable_names(Forms) ->
    AllVars = lists:foldl(
        fun(Form, ListAcc) ->
            erl_syntax_lib:fold(
                fun
                    ({var, _Anno, Name}, Acc) ->
                        [Name | Acc];
                    (_, Acc) ->
                        Acc
                end,
                ListAcc,
                Form
            )
        end,
        [],
        Forms
    ),
    lists:usort(AllVars).

-spec compile_file(file:filename(), options()) -> {module(), binary()}.
compile_file(Forms, Options) ->
    {ok, Module, <<Binary/binary>>} = compile:file(Forms, Options),
    {Module, Binary}.

-spec compile_forms(forms()) -> {module(), binary()}.
compile_forms(Forms) ->
    {ok, Module, <<Binary/binary>>} = compile:forms(Forms, [debug_info]),
    {Module, Binary}.

-spec load_forms(binary()) -> {module(), forms()}.
load_forms(Binary) ->
    {ok, {Module, [{abstract_code, {_, Forms}} | _]}} = beam_lib:chunks(Binary, [abstract_code, compile_info]),
    {Module, Forms}.

-spec ms_transform(forms(), options()) -> forms().
ms_transform(Forms, Options) ->
    Result = ms_transform:parse_transform(Forms, Options),
    is_list(Result) orelse error(ms_transform),
    Result.
