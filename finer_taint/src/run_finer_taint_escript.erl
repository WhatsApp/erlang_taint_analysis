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

-module(run_finer_taint_escript).
-compile(warn_missing_spec_all).

%% API exports
-export([main/1]).

%%====================================================================
%% Escript that runs the finer taint abstract machine and
%% produces useable outputs
%%====================================================================
-type stack() :: list(mfa()).

%% escript Entry point
-spec main([string()]) -> ok.
main(["infer-traceview", Path]) ->
    main(infer, Path);
main(["dot", Path]) ->
    main(dot, Path);
main(["run-lineage" | Tail]) ->
    run_subcommand(run_lineage, Tail);
main(["run-line-lineage" | Tail]) ->
    run_subcommand(run_lineage_with_line_history, Tail);
main(["run-tracing-lineage" | Tail]) ->
    run_subcommand(run_tracing_lineage, Tail);
main(["run" | Tail]) ->
    run_subcommand(run, Tail);
main(["run-tracing" | Tail]) ->
    run_subcommand(run_tracing, Tail);
main(["flamegraph" | Tail]) ->
    run_subcommand(flamegraph, Tail);
main(_) ->
    SubCommandHelp =
        "\n"
        "<subcommand_mode> is of the form\n"
        "\n"
        "<subcommand> [analysis_instruction_files]+ <processing commands>\n"
        "\n"
        "SUBCOMMAND\n"
        "\n"
        "<subcommand> chooses which function to use to process [analysis_instruction_files]\n"
        "flamegraph                generate a flamegraph of finer_taint instructions\n"
        "run-lineage               run parallel_abstract_machine:run_lineage on  [analysis_instruction_files]\n"
        "run-tracing-lineage       run parallel_abstract_machine:run_tracing_lineage on  [analysis_instruction_files]\n"
        "run                       run parallel_abstract_machine:run on  [analysis_instruction_files]\n"
        "                          This runs the analysis in non-lineage mode\n"
        "\n"
        "PROCESSING COMMANDS\n"
        "\n"
        "<processing commands> apply a function the output of <subcommand> or previous <processing command>\n"
        "-print                         Print using io:format(~~s)\n"
        "-pprint                        Print using io:format(~~p)\n"
        "-to-file FILE                  Write to FILE\n"
        "-count                         Get number of elements\n"
        "-arg-lineage-hr                Get arg lineage in human_readable form\n"
        "-arg-lineage-csv               Get arg lineage in csv form\n"
        "-query-arg-lineage QUERY       Query full arg lineage for QUERY\n"
        "\n"
        "\n"
        "QUERY has the same format as one line in the human_readable form, ie.\n"
        "example_gen_server:store_value/2-Arg1 -> example_gen_server:handle_call/3-Arg2\n"
        "\n"
        "\n"
        "EXMAPLES:\n"
        "\n"
        "run_finer_taint run-lineage finer_taint/test/parallel_taint_SUITE_data/test_gen_server_an*  -query-arg-lineage \"example_gen_server:store_value/2-Arg1 -> example_gen_server:handle_call/3-Arg2\" -pprint\n"
        "\n"
        "Runs parallel_abstract_machine:run_lineage on all files matching the wildcard, finds\n"
        "all the paths that had a flow between store_value/2 argument 1 and handle_Call/3 argument2\n"
        "and prints them with ~~p.\n"
        "\n"
        "\n"
        "\n"
        "run_finer_taint run-lineage /tmp/abstr_instr-* -arg-lineage-csv -to-file /tmp/some_lineage.csv\n"
        "\n"
        "Gets the lineage from all files in /tmp/abstr_inst* , get the lineage in CSV format and writes it to /tmp/some_lineage.csv\n",
    io:format("Usage: ~n~n"),
    io:format("\trun_finer_taint dot path/to/abstract_machine_instructions~n"),
    io:format("\trun_finer_taint infer-traceview path/to/abstract_machine_instructions~n"),
    io:format("\trun_finer_taint dynamic_lineage path/to/dynamic_lineage.cfg <processing commands>~n", []),
    io:format("\trun_finer_taint detect_leaks path/to/dynamic_lineage.cfg <processing commands>~n", []),
    io:format("\trun_finer_taint <subcommand_mode>~n~n~s", [SubCommandHelp]).

-spec run_subcommand(atom(), list(string())) -> ok.
run_subcommand(flamegraph, Tail) ->
    {Paths, Commands} = lists:splitwith(
        fun
            ([$- | _]) -> false;
            (_) -> true
        end,
        Tail
    ),
    Flamegraph = flamegraph(Paths),
    extract_from_state_subcommand(Flamegraph, Commands);
run_subcommand(RunFunction, Tail) ->
    Handler = default,
    ok = logger:set_primary_config(level, info),
    ok = logger:update_formatter_config(Handler, template, [msg]),
    ok = logger:update_proxy_config(#{burst_limit_enable => false, overload_kill_qlen => 200000}),
    ok = logger:update_handler_config(Handler, config, #{burst_limit_enable => false}),
    logger:add_handler_filter(Handler, no_progress, {fun logger_filters:progress/2, stop}),
    {Paths, Commands} = lists:splitwith(
        fun
            ([$- | _]) -> false;
            (_) -> true
        end,
        Tail
    ),

    io:format("Running on ~p~n", [Paths]),
    application:ensure_all_started(taint_server),
    Leaks = parallel_abstract_machine:RunFunction(Paths),
    io:format("Done running abstract machine~n"),
    extract_from_state_subcommand(Leaks, Commands).

-spec flamegraph(list(file:filename())) -> list(string()).
flamegraph(Paths) ->
    StackMap = lists:foldl(
        fun(Path, Acc) ->
            {ok, Instructions} = file:consult(Path),
            flamegraph(Instructions, [], Acc)
        end,
        #{},
        Paths
    ),
    maps:fold(
        fun(Stack, Count, Acc) ->
            StringStack = [lists:flatten(io_lib:format("~p:~p/~p", [M, F, A])) || {M, F, A} <- lists:reverse(Stack)],
            Stck = string:join(StringStack, ";"),
            [Stck, " ", integer_to_list(Count), "\n" | Acc]
        end,
        [],
        StackMap
    ).

-define(TWO_RECURSIVE_LOOP,
    {M1, F1, A1},
    {M2, F2, A2}
).

-define(THREE_RECURSIVE_LOOP,
    ?TWO_RECURSIVE_LOOP,
    {M3, F3, A3}
).

-define(FOUR_RECURSIVE_LOOP,
    ?THREE_RECURSIVE_LOOP,
    {M4, F4, A4}
).

-spec remove_recursive_loops(stack()) -> stack().
remove_recursive_loops([?FOUR_RECURSIVE_LOOP, ?FOUR_RECURSIVE_LOOP | Stack]) ->
    remove_recursive_loops([?FOUR_RECURSIVE_LOOP | remove_recursive_loops(Stack)]);
remove_recursive_loops([?THREE_RECURSIVE_LOOP, ?THREE_RECURSIVE_LOOP | Stack]) ->
    remove_recursive_loops([?THREE_RECURSIVE_LOOP | remove_recursive_loops(Stack)]);
remove_recursive_loops([?TWO_RECURSIVE_LOOP, ?TWO_RECURSIVE_LOOP | Stack]) ->
    remove_recursive_loops([?TWO_RECURSIVE_LOOP | remove_recursive_loops(Stack)]);
remove_recursive_loops([{M, F, A}, {M, F, A} | Stack]) ->
    [{M, F, A} | remove_recursive_loops(Stack)];
remove_recursive_loops([]) ->
    [];
remove_recursive_loops([H | T]) ->
    [H | remove_recursive_loops(T)].

-spec flamegraph(list(), list(), T) -> T when T :: #{stack() => integer()}.
flamegraph([], [], State) ->
    io:format("Done on one file\n"),
    State;
flamegraph([], Stack, State) ->
    io:format("WARNING: leftover stack ~p~n", [Stack]),
    State;
flamegraph([{try_catch, {try_enter, TryId}, _Loc} | OtherInstructions], CurrentStack, State) ->
    flamegraph(OtherInstructions, [TryId | CurrentStack], State);
flamegraph([{try_catch, {try_exit, TryId}, _Loc} | OtherInstructions], [TryId | CurrentStack], State) ->
    flamegraph(OtherInstructions, CurrentStack, State);
flamegraph([{try_catch, {catch_enter, TryId}, _Loc} | OtherInstructions], CurrentStack, State) ->
    [TryId | NewStack] = lists:dropwhile(fun(TryId1) -> TryId =/= TryId1 end, CurrentStack),
    flamegraph(OtherInstructions, NewStack, State);
flamegraph([{call_fun, MFA, _Loc} | OtherInstructions], CurrentStack, State) ->
    flamegraph(OtherInstructions, [MFA | CurrentStack], State);
flamegraph([{apply, {MFA, _Loc}} | OtherInstructions], [MFA | NewStack], State) ->
    flamegraph(OtherInstructions, NewStack, State);
flamegraph([_SomeInstruction | OtherInstructions], Stack, State) ->
    flamegraph(OtherInstructions, Stack, maps:update_with(remove_recursive_loops(Stack), fun add_one/1, 1, State)).

-spec add_one(integer()) -> integer().
add_one(Value) -> Value + 1.

-spec extract_from_state_subcommand(taint_abstract_machine:leaks() | iodata(), list(string())) -> ok.
extract_from_state_subcommand(Leaks, ["-query-arg-lineage", Query | Tail]) ->
    [FromM, FromF, FromA, FromArgN, ToM, ToF, ToA, ToArgN] = split_query(Query),
    FromMFA = {list_to_atom(FromM), list_to_atom(FromF), list_to_integer(FromA)},
    ToMFA = {list_to_atom(ToM), list_to_atom(ToF), list_to_integer(ToA)},
    Query1 = {FromMFA, list_to_integer(FromArgN), ToMFA, list_to_integer(ToArgN)},
    % eqwalizer:ignore Assume Leaks is of taint_abstract_machine:leak() type
    Result = abstract_machine_util:query_arg_lineage(Leaks, Query1),
    extract_from_state_subcommand(Result, Tail);
extract_from_state_subcommand(Leaks, ["-arg-lineage-hr" | Tail]) ->
    % eqwalizer:ignore Assume Leaks is of taint_abstract_machine:leak() type
    Lineage = abstract_machine_util:get_arg_lineage(Leaks, human_readable),
    extract_from_state_subcommand(Lineage, Tail);
extract_from_state_subcommand(Leaks, ["-arg-lineage-csv" | Tail]) when is_list(Leaks) ->
    io:format("Converting to CSV~n"),
    % eqwalizer:ignore Assume Leaks is of taint_abstract_machine:leak() type
    Lineage = abstract_machine_util:get_arg_lineage(Leaks, csv),
    io:format("Done converting to CSV~n"),
    extract_from_state_subcommand(Lineage, Tail);
extract_from_state_subcommand(_, []) ->
    ok;
extract_from_state_subcommand(Lineage, ["-count" | Tail]) when is_list(Lineage) ->
    io:format("Counted ~p~n", [length(Lineage)]),
    extract_from_state_subcommand(Lineage, Tail);
extract_from_state_subcommand(Lineage, ["-to-file", OutputFile | Tail]) ->
    % eqwalizer:ignore
    file:write_file(OutputFile, Lineage),
    extract_from_state_subcommand(Lineage, Tail);
extract_from_state_subcommand(Lineage, ["-pprint" | Tail]) ->
    Printed = io_lib:format("~p", [Lineage]),
    extract_from_state_subcommand(Printed, Tail);
extract_from_state_subcommand(Lineage, ["-print" | Tail]) ->
    io:format("~s~n", [Lineage]),
    extract_from_state_subcommand(Lineage, Tail).

-spec split_query(Query) -> [string()] when Query :: iodata() | unicode:charlist().
split_query(Query) ->
    % eqwalizer:ignore - {return, list} in options forces the result to be a list of strings
    re:split(Query, ":|/|-Arg| -> ", [{return, list}]).

-spec main(infer | dot, string()) -> ok.
main(ReportType, Path) ->
    AmState =
        try taint_abstract_machine:run_tracing(Path) of
            S -> S
        catch
            {abstract_machine_invalid_state, _Instruction, State} ->
                io:format("Abstract machine exited with errors, analysis incomplete~n"),
                State
        end,
    Leaks = taint_abstract_machine:get_leaks(AmState),
    io:format("Found ~p leaks~n", [length(Leaks)]),
    Output =
        case ReportType of
            infer -> abstract_machine_util:to_infer_report(Leaks);
            dot -> abstract_machine_util:graphviz_leaks(Leaks, [pastry])
        end,
    io:format("~s~n", [Output]).
