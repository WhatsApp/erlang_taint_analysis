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
%%% Contains functions that analyze the output of taint_abstract_machine
-module(abstract_machine_util).
-compile(warn_missing_spec_all).

%% The client API.
-export([
    get_priv_models/0,
    get_sources/1,
    get_arg_lineage/2,
    query_arg_lineage/2,
    get_arg_lineage_raw/1,
    get_graph/1,
    to_dot/1,
    print_leaks/1,
    to_infer_report/1,
    get_dataflows/1,
    filter_message_pass/1,
    get_covered_inst/1,
    graphviz_leaks/2
]).

-type nodes_ty() :: #{string() => sink | source | step}.
-type edges_ty() :: [{string(), string()}].
-type leak_evidence() :: #{
    sink => binary(),
    field => binary(),
    source => binary(),
    trace => binary()
}.
-type infer_report() :: map().
% The n-th parameter of MFA
-type mfan() :: {mfa(), non_neg_integer()}.

% Url where files can be found
-define(SOURCE_URL, "https//none.com/files/").

-spec history_to_leakeage_evidence(string(), taint_abstract_machine:taint_history()) -> leak_evidence().
history_to_leakeage_evidence(Sink, History) ->
    Source =
        case taint_abstract_machine:get_taint_sources(History, []) of
            [OneSource] ->
                OneSource;
            [AnotherSource | Other] ->
                io:format(
                    "History should be linear, expecting only a single source.~n" ++
                        "Picking only one source, droping: ~p~n",
                    [Other]
                ),
                AnotherSource
        end,

    {Field, Location} =
        case Source of
            {tagged_source, Tag, Loc} -> {Tag, Loc};
            {source, Loc} -> {"unknown", Loc}
        end,
    #{
        sink => list_to_binary(Sink),
        field => list_to_binary(Field),
        source => list_to_binary(Location),
        trace => list_to_binary(io_lib:format("~p", [History]))
    }.

-spec get_priv_models() -> taint_abstract_machine:models().
get_priv_models() ->
    File = filename:join([code:priv_dir(finer_taint), "taint_models"]),
    % Check atleast one element
    [H | T] =
        case file:consult(File) of
            {ok, Terms} ->
                Terms;
            % Likely an escript run
            {error, enotdir} ->
                Filename = "finer_taint/priv/taint_models",
                {ok, Escript} = escript:extract(escript:script_name(), []),
                {archive, Archive} = lists:keyfind(archive, 1, Escript),
                {ok, Zip} = zip:zip_open(Archive, [memory]),
                {ok, {Filename, ModelsBin}} = zip:zip_get(Filename, Zip),
                % Intentionally don't close the zip, because this terminates a process
                % which might send an {exit} message to the parent gen_server
                % (abstract_machine_proclet)
                %ok = zip:zip_close(Zip),
                Models = consult_from_string(binary_to_list(ModelsBin)),
                Models
        end,
    maps:from_list([H | T]).

-spec consult_from_string(string()) -> [{{module(), atom()}, propagate | sanitize}].
consult_from_string(StringOfTerms) when is_list(StringOfTerms) ->
    consult_from_string_impl(erl_scan:tokens([], StringOfTerms, 0)).

-spec consult_from_string_impl({more, erl_scan:return_cont()} | {done, erl_scan:tokens_result(), string() | eof}) ->
    [{{module(), atom()}, propagate | sanitize}].
consult_from_string_impl({more, _}) ->
    [];
consult_from_string_impl({done, Result, LeftOverChars}) ->
    case Result of
        {ok, Tokens, EndLocation} ->
            {ok, Term} = erl_parse:parse_term(Tokens),
            [Term | consult_from_string_impl(erl_scan:tokens([], LeftOverChars, EndLocation))];
        {eof, _} ->
            []
    end.

% Prints sinks and sources of leaks passed in
-spec print_leaks(taint_abstract_machine:leaks()) -> binary().
print_leaks(Leaks) ->
    print_leaks(Leaks, []).
-spec print_leaks(taint_abstract_machine:leaks(), [leak_evidence()]) -> binary().
print_leaks([], Acc) ->
    iolist_to_binary(json:encode(Acc));
print_leaks([{leak, Sink, History} | Tail], Acc) ->
    Histories = linearize_history(History),
    Leaks = [history_to_leakeage_evidence(Sink, Hist) || Hist <- Histories],
    print_leaks(Tail, Leaks ++ Acc).

% Write the leaks to /tmp dir in the DOT format,
% If second argument containt pastry, also upload it to pastry.
%
% Example usage:
% abstract_machine_util:graphviz_leaks(Leak, [pastry]).
% abstract_machine_util:graphviz_leaks(Leak, []).
-spec graphviz_leaks(taint_abstract_machine:leaks(), list()) -> ok.
graphviz_leaks([], _) ->
    ok;
graphviz_leaks([Leak = {leak, Sink, _History} | Tail], Options) ->
    Graph = get_graph(Leak),
    DotFilename = "/tmp/leak_" ++ Sink ++ ".dot",
    ok = file:write_file(DotFilename, to_dot(Graph)),
    io:format("Wrote ~s~n", [DotFilename]),
    case lists:member(pastry, Options) of
        true ->
            io:format("Writing to pastry: "),
            Paste = os:cmd("pastry < " ++ DotFilename),
            io:format("~s~n", [Paste]);
        _ ->
            ok
    end,
    graphviz_leaks(Tail, Options).

-spec get_dataflows(taint_abstract_machine:taint_history()) -> taint_abstract_machine:dataflow_map().
get_dataflows(History) ->
    Output = get_dataflows(History, [], [], #{}),
    Output.
%    lists:reverse(CallStack ++ Output).

% Remove balanced call and return site
-spec get_dataflows(
    taint_abstract_machine:taint_history(),
    taint_abstract_machine:taint_history(),
    taint_abstract_machine:taint_history(),
    Dataflows
) -> Dataflows when Dataflows :: taint_abstract_machine:dataflow_map().
get_dataflows(
    [{call_site, {M, F, A}, CallSite1} | Tail],
    [{return_site, {M, F, A}, CallSite2} | ReturnStackTail],
    Output,
    ArgTaints
) when CallSite1 =:= CallSite2; CallSite1 =:= "unknown"; CallSite2 =:= "unknown" ->
    get_dataflows(Tail, ReturnStackTail, Output, ArgTaints);
% Push a call site onto the call stack
get_dataflows([H = {call_site, _, _} | Tail], ReturnStack, Output, ArgTaints) ->
    get_dataflows(Tail, ReturnStack, [H | Output], ArgTaints);
% Unmatched return site, it's part of our output
get_dataflows([H = {return_site, _, _} | Tail], ReturnStack, Output, ArgTaints) ->
    get_dataflows(Tail, [H | ReturnStack], Output, ArgTaints);
get_dataflows([_H = {arg_taint, MFAN} | Tail], ReturnStack, Output, ArgTaints) ->
    get_dataflows(Tail, ReturnStack, Output, ArgTaints#{{dataflow_src, MFAN, ReturnStack ++ Output} => ok});
% Filter out step in history, because they are not interesting for lineage and it keeps
% histories smaller
get_dataflows([_H = {step, _} | Tail], ReturnStack, Output, ArgTaints) ->
    get_dataflows(Tail, ReturnStack, Output, ArgTaints);
get_dataflows([H = {blackhole, _} | Tail], ReturnStack, Output, ArgTaints) ->
    get_dataflows(Tail, ReturnStack, [H | Output], ArgTaints);
% When Message passing, we go to another process so ReturnStack is reset
get_dataflows([H = {message_pass, _} | Tail], ReturnStack, Output, ArgTaints) ->
    get_dataflows(Tail, [], [H | ReturnStack] ++ Output, ArgTaints);
get_dataflows([_H = {joined_history, _Type, Histories}], ReturnStack, Output, ArgTaints) ->
    NewArgTaints = [get_dataflows(Hist, ReturnStack, Output, #{}) || Hist <- Histories],
    NewArgTaints1 = lists:foldl(fun maps:merge/2, ArgTaints, NewArgTaints),
    get_dataflows([], ReturnStack, Output, NewArgTaints1);
%Done, put remaning call stack in Output and return
get_dataflows([], _CallStack, _Output, ArgTaints) ->
    ArgTaints.

-spec get_covered_inst(taint_abstract_machine:taint_history()) -> map().
get_covered_inst(History) ->
    get_covered_inst(History, #{}).

-spec get_covered_inst(taint_abstract_machine:taint_history(), map()) -> map().
get_covered_inst([{joined_history, _Type, Histories}], Output) ->
    HistoryOutputs = [get_covered_inst(Hist, #{}) || Hist <- Histories],
    lists:foldl(fun maps:merge/2, Output, HistoryOutputs);
get_covered_inst([{blackhole, _} | Tail], Output) ->
    get_covered_inst(Tail, Output);
get_covered_inst([{Type, _, Loc} | Tail], Output) when is_atom(Type), is_list(Loc) ->
    get_covered_inst(Tail, Output#{Loc => ok});
get_covered_inst([{T, Loc} | Tail], Output) when is_list(Loc), is_atom(T) ->
    get_covered_inst(Tail, Output#{Loc => ok});
get_covered_inst([], Output) ->
    Output.

% Pretty print the annotations.
-spec annotations_impl(taint_abstract_machine:taint_history()) -> [string()].
annotations_impl([]) ->
    [];
annotations_impl([{blackhole, _} | Tail]) ->
    ["blackhole" | annotations_impl(Tail)];
annotations_impl([{step, _} | Tail]) ->
    annotations_impl(Tail);
annotations_impl([{call_site, _MFA, Loc} | Tail]) ->
    ["call@" ++ Loc | annotations_impl(Tail)];
annotations_impl([{return_site, _MFA, Loc} | Tail]) ->
    ["ret@" ++ Loc | annotations_impl(Tail)];
annotations_impl([{message_pass, Loc} | Tail]) ->
    ["mp@" ++ Loc | annotations_impl(Tail)].

% Pretty print all the annotations.
-spec annotations(#{list() => ok}) -> [string()].
annotations(Map) when is_map(Map) ->
    [string:join(annotations_impl(Annot), ";") || Annot := _ <- Map].

% Filters out redudant message passes in a taint history For example
% step1->step2->message_pass->step->message_pass->step3 would become
% step1->step2->message_pass->step3 as the steps between message passing can be
% skipped for the lineage use case. To illustrate that consider an edge A -> B.
%
%
% For lineage we add some annotation to it as to what call/return sites the
% dataflow on edge A -> B passed through.
%
% Assume the annotation is `returnFromFoo, callBar`.
%
% What this annotation means is that our edge A -> B can only connect on the
% left, with edges that have a callFoo annotation (or no annoatation).
% Similarly A -> B can only connect to the right with edges that have
% returnFromBar annotation (or no annotation).
%
% The effect on message passing on this is that it resets the stack.  If there
% is an annotation like returnFromFoo, callBar, message-pass the requirement
% that edges connecting on the right, have to returnFromBar is no longer valid,
% because we passed a message so we are in some other process with a different
% stack.
%
% Note that the annotations to the left of the message pass are still useful.
% However if there two message passes, the annotations between them are not
% useful for connecting with any other edges and are therefore not
% interesting and dropped by `filter_message_pass/1`

-spec filter_message_pass(list()) -> list().
filter_message_pass(Input) ->
    filter_message_pass(Input, [], []).
-spec filter_message_pass(list(), list(), list()) -> list().
filter_message_pass([{message_pass, _} | T], MaybeAfterFirstMessagePass, []) ->
    filter_message_pass(T, [], MaybeAfterFirstMessagePass);
filter_message_pass([{message_pass, _} | T], _MaybeAfterFirstMessagePass, BeforeFirstMessagePass) ->
    filter_message_pass(T, [], BeforeFirstMessagePass);
filter_message_pass([H | T], MaybeAfterFirstMessagePass, BeforeFirstMessagePass) ->
    filter_message_pass(T, [H | MaybeAfterFirstMessagePass], BeforeFirstMessagePass);
filter_message_pass([], MaybeAfterFirstMessagePass, []) ->
    lists:reverse(MaybeAfterFirstMessagePass);
filter_message_pass([], MaybeAfterFirstMessagePass, BeforeFirstMessagePass) ->
    lists:reverse(
        MaybeAfterFirstMessagePass ++ [{message_pass, "skipped-steps-between-message-passing"}] ++
            BeforeFirstMessagePass
    ).

% Apply filter_message_pass to the Lineage obtained from get_arg_lineage_impl
-spec fold_message_passes(#{tuple() => #{list() => ok}}) -> #{tuple() => #{list() => ok}}.
fold_message_passes(AnnotatedLineage) ->
    #{
        K => #{filter_message_pass(Annot) => ok || Annot := _ <- Annotation}
     || K := Annotation <- AnnotatedLineage
    }.

% Takes a list of leaks() produced in the lineage mode
% and gives all unique edges between function arguments in it
-spec get_arg_lineage(taint_abstract_machine:leaks(), atom()) -> string().
get_arg_lineage(Leaks, OutputFormat) ->
    AnnotatedLineage = get_arg_lineage_impl(Leaks, #{}),
    FoldedMessagesLineage = fold_message_passes(AnnotatedLineage),
    case OutputFormat of
        human_readable ->
            lists:flatten(
                lists:sort(
                    [
                        io_lib:format(
                            "~p:~p/~p-Arg~p -> ~p:~p/~p-Arg~p~n",
                            [FromM, FromF, FromA, FromArgN, ToM, ToF, ToA, ToArgN]
                        )
                     || {{{FromM, FromF, FromA}, FromArgN}, {{ToM, ToF, ToA}, ToArgN}} := _ <- FoldedMessagesLineage
                    ]
                )
            );
        human_readable_annotated ->
            lists:flatten(
                lists:sort(
                    [
                        io_lib:format(
                            "~p:~p/~p-Arg~p -> ~p:~p/~p-Arg~p~n  ~s~n",
                            [
                                FromM,
                                FromF,
                                FromA,
                                FromArgN,
                                ToM,
                                ToF,
                                ToA,
                                ToArgN,
                                string:join(annotations(maps:get(K, AnnotatedLineage)), "\n  ")
                            ]
                        )
                     || K = {{{FromM, FromF, FromA}, FromArgN}, {{ToM, ToF, ToA}, ToArgN}} := _ <- FoldedMessagesLineage
                    ]
                )
            );
        csv ->
            lists:flatten([
                "FromM,FromF,FromA,FromArgN,ToM,ToF,ToA,ToArgN,Annot\n"
                | [
                    [
                        io_lib:format("~p,~p,~p,~p,~p,~p,~p,~p,~s~n", [
                            FromM, FromF, FromA, FromArgN, ToM, ToF, ToA, ToArgN, Annot
                        ])
                     || Annot <- annotations(maps:get(K, FoldedMessagesLineage))
                    ]
                 || K = {{{FromM, FromF, FromA}, FromArgN}, {{ToM, ToF, ToA}, ToArgN}} := _ <- FoldedMessagesLineage
                ]
            ])
    end.

-spec get_arg_lineage_raw(taint_abstract_machine:leaks()) -> [tuple()].
get_arg_lineage_raw(Leaks) ->
    AnnotatedLineage = get_arg_lineage_impl(Leaks, #{}),
    FoldedMessagesLineage = fold_message_passes(AnnotatedLineage),
    maps:keys(FoldedMessagesLineage).
-spec get_arg_lineage_impl(taint_abstract_machine:leaks(), Acc) -> Acc when
    Acc :: #{{mfan(), mfan()} => map()}.
get_arg_lineage_impl([_L = {arg_leak, {ToMFA, ToArgN, _Loc}, Froms} | Tail], MapAcc) ->
    Acc1 = lists:foldl(
        history_folder(ToMFA, ToArgN),
        MapAcc,
        Froms
    ),
    get_arg_lineage_impl(Tail, Acc1);
get_arg_lineage_impl([], Acc) ->
    Acc.

-spec history_folder(erlang:mfa(), integer()) ->
    fun((taint_abstract_machine:taint_history_point() | [taint_abstract_machine:taint_history()], Acc) -> Acc)
when
    Acc :: #{{mfan(), mfan()} => map()}.
history_folder(ToMFA, ToArgN) ->
    fun
        HistoryFolder({dataflow_src, {FromMFA, FromArgN}, Annotation}, FoldAcc) ->
            Key = {{FromMFA, FromArgN}, {ToMFA, ToArgN}},
            Value = maps:get(Key, FoldAcc, #{}),
            NewValue = Value#{Annotation => ok},
            FoldAcc#{Key => NewValue};
        HistoryFolder({arg_taint, {FromMFA, FromArgN}}, FoldAcc) ->
            Key = {{FromMFA, FromArgN}, {ToMFA, ToArgN}},
            Value = maps:get(Key, FoldAcc, #{}),
            % arg_taint doesn't have an annotation
            NewValue = Value#{[] => ok},
            FoldAcc#{Key => NewValue};
        HistoryFolder({step, _}, FoldAcc) ->
            FoldAcc;
        HistoryFolder({message_pass, _}, FoldAcc) ->
            FoldAcc;
        HistoryFolder({call_site, _, _}, FoldAcc) ->
            FoldAcc;
        HistoryFolder({return_site, _, _}, FoldAcc) ->
            FoldAcc;
        HistoryFolder({joined_history, _, Histories}, FoldAcc) ->
            HistoryFolder(Histories, FoldAcc);
        HistoryFolder({blackhole, Sources}, FoldAcc) ->
            HistoryFolder([Sources], FoldAcc);
        HistoryFolder(HistoriesList, FoldAcc) when is_list(HistoriesList) ->
            EachHistoryFolded = [
                lists:foldl(HistoryFolder, #{}, Hist)
             || Hist <- HistoriesList
            ],
            NewFoldAcc = lists:foldl(
                fun(FoldAcclet, Acc) ->
                    maps:merge_with(
                        fun(_, Val1, Val2) when is_map(Val1), is_map(Val2) ->
                            maps:merge_with(fun(_, ok, ok) -> ok end, Val1, Val2)
                        end,
                        Acc,
                        FoldAcclet
                    )
                end,
                FoldAcc,
                EachHistoryFolded
            ),
            NewFoldAcc
    end.

% Takes a list of leaks() produced in the lineage mode and a query
% in the form of {FromMFA, FromArgN, ToMFA, ToArgN} and returns
% all the paths from FromMFA-ArgN to ToMFA-ArgN contained in the leaks().
%
% Useful for debugging why the analysis reported an edge between two arguments.
-spec query_arg_lineage(taint_abstract_machine:leaks(), {mfa(), integer(), mfa(), integer()}) -> list().
query_arg_lineage(Leaks, QueryLineage) ->
    query_arg_lineage_impl(Leaks, [], QueryLineage).

-spec query_arg_lineage_impl(taint_abstract_machine:leaks(), list(), {mfa(), integer(), mfa(), integer()}) -> list().
query_arg_lineage_impl(
    [{arg_leak, {ToMFA, ToArgN, _Loc}, Froms} | Tail], Acc, Query = {FromMFA, FromArgN, ToMFA, ToArgN}
) ->
    ThisArgLeakPaths = fun
        HistoryFolder([Step = {arg_taint, {FromMFA1, FromArgN1}}, CallSite = {call_site, _, _} | _], PathTo) when
            FromMFA1 == FromMFA, FromArgN1 == FromArgN
        ->
            [Step, CallSite | PathTo];
        HistoryFolder([Step = {dataflow_src, {FromMFA1, FromArgN1}, _} | _], PathTo) when
            FromMFA1 == FromMFA, FromArgN1 == FromArgN
        ->
            [Step | PathTo];
        HistoryFolder([], _) ->
            [];
        HistoryFolder([Step = {_, _} | Tail1], PathTo) ->
            HistoryFolder(Tail1, [Step | PathTo]);
        HistoryFolder([Step = {Type, _, _} | Tail1], PathTo) when Type =/= joined_history ->
            HistoryFolder(Tail1, [Step | PathTo]);
        HistoryFolder([{joined_history, _, Histories}], PathTo) ->
            lists:concat([HistoryFolder(Hist, PathTo) || Hist <:- Histories])
    end(
        Froms, [{arg_leak, {ToMFA, ToArgN}}]
    ),
    case ThisArgLeakPaths of
        [] ->
            query_arg_lineage_impl(Tail, Acc, Query);
        _ ->
            query_arg_lineage_impl(Tail, [ThisArgLeakPaths | Acc], Query)
    end;
query_arg_lineage_impl([_ | Tail], Acc, Query) ->
    query_arg_lineage_impl(Tail, Acc, Query);
query_arg_lineage_impl([], Acc, _) ->
    Acc.

% Traverses taint_history to find all the sources
-spec get_sources(taint_abstract_machine:taint_history()) -> [string()].
get_sources(History) ->
    lists:filtermap(
        fun
            ({source, Loc}) -> {true, Loc};
            ({tagged_source, Tag, Loc}) -> {true, Tag ++ "@" ++ Loc};
            (_) -> false
        end,
        taint_abstract_machine:get_taint_sources(History, [])
    ).
%
% Builds a graph representation of a Leak. Use to_dot/0 to print it in the DOT format.
% This graph is not equivalent to a trace. Namely it can containt cycles.
-spec get_graph({leak, string(), taint_abstract_machine:taint_history()}) ->
    {nodes_ty(), edges_ty()}.
get_graph({leak, Sink, History}) ->
    {Nodes, Edges} = get_graph_impl(Sink, History, {#{Sink => sink}, []}),
    {Nodes, lists:usort(Edges)}.

-spec get_graph_impl(string(), taint_abstract_machine:taint_history(), Acc) -> Acc when
    Acc ::
        {nodes_ty(), edges_ty()}.
get_graph_impl(To, [{source, From}], {AccNode, AccEdges}) ->
    {AccNode#{From => source}, [{From, To} | AccEdges]};
get_graph_impl(To, [{step, From} | Tail], {AccNode, AccEdges}) ->
    % Don't overwrite source/sink nodes
    Type = maps:get(From, AccNode, step),
    get_graph_impl(From, Tail, {AccNode#{From => Type}, [{From, To} | AccEdges]});
get_graph_impl(To, [{joined_history, _Type, Histories}], Acc) ->
    lists:foldl(fun(History, FoldAcc) -> get_graph_impl(To, History, FoldAcc) end, Acc, Histories).

% Given a source_filename.erl:<lineNumber>
% this function returns the path to source_filename.erl and the line number
-spec get_file_path(string()) -> {file:filename(), string()} | not_found.
get_file_path(Node) ->
    case get({filepath_cache, Node}) of
        undefined ->
            Return =
                case string:split(Node, ":") of
                    [Filename, Line] ->
                        case filelib:wildcard("[a-z]*/**/" ++ Filename) of
                            [Filepath] ->
                                {Filepath, Line};
                            [] ->
                                not_found;
                            [Head | Tail] ->
                                io:format("Ambiguous wildcard head: ~p, tail: ~p, picking head~n", [Head, Tail]),
                                {Head, Line}
                        end;
                    _ ->
                        not_found
                end,
            put({filepath_cache, Node}, Return),
            Return;
        X ->
            X
    end.

-spec linearize_history(taint_abstract_machine:taint_history()) -> [taint_abstract_machine:taint_history()].
linearize_history([]) ->
    [];
linearize_history(X = [{tagged_source, _Tag, _Location}]) ->
    [X];
linearize_history(X = [{source, _Location}]) ->
    [X];
linearize_history([Item | Tail]) when
    is_map_key(element(1, Item), #{
        step => 1,
        call_site => 1,
        return_site => 1,
        message_pass => 1,
        blackhole => 1
    })
->
    [[Item | H] || H <- linearize_history(Tail)];
linearize_history([{joined_history, _, Histories}]) ->
    [X || H <- Histories, X <- linearize_history(H)].

-spec to_infer_bug_report(taint_abstract_machine:taint_history(), string()) -> infer_report().
to_infer_bug_report(History, Sink) ->
    [{source, Source} | OtherSteps] = lists:reverse(History),
    {Filename, Line} =
        case get_file_path(Source) of
            Ret = {_Filepath, _Line} -> Ret;
            _ -> {Source, "-1"}
        end,
    Report = #{
        bug_type => <<"TAINT">>,
        qualifier => list_to_binary(io_lib:format("Found dataflow from ~s to ~s", [Source, Sink])),
        severity => <<"INFO">>,
        file => list_to_binary(Filename),
        line => list_to_integer(Line),
        procedure => <<"unknown">>,
        procedure_start_line => list_to_integer(Line),
        bug_trace => [to_infer_bug_trace(S) || S <- OtherSteps],
        key => list_to_binary(io_lib:format("~p->~s", [Source, Sink]))
    },
    Report#{hash => base64:encode(crypto:hash(sha256, io_lib:format("~p", [Report])))}.

-spec to_infer_report(taint_abstract_machine:leaks()) -> binary().
to_infer_report(Leaks) ->
    Reports = to_infer_report(Leaks, []),
    iolist_to_binary(json:encode(Reports)).

-spec to_infer_report(taint_abstract_machine:leaks(), [infer_report()]) -> [infer_report()].
to_infer_report([], Acc) ->
    Acc;
to_infer_report([{leak, Sink, History} | Tail], Acc) ->
    LinearHistories = linearize_history(History),
    BugReports = [to_infer_bug_report(Hist, Sink) || Hist <:- LinearHistories],
    to_infer_report(Tail, BugReports ++ Acc).

-spec to_infer_bug_trace(taint_abstract_machine:taint_history_point()) ->
    #{level := 0, filename := binary(), line_number := integer(), column_number := -1, description := binary()}.
to_infer_bug_trace({step, Location}) ->
    {Filename, Line} =
        case get_file_path(Location) of
            not_found -> {Location, "-1"};
            X -> X
        end,
    #{
        level => 0,
        filename => list_to_binary(Filename),
        line_number => list_to_integer(Line),
        column_number => -1,
        description => <<"Taint point">>
    }.

% Returns a DOT representation of the graph obtained via get_graph/1.
-spec to_dot({nodes_ty(), edges_ty()}) -> string().
to_dot({Nodes, Edges}) ->
    F = fun(Node, Type, {Map, NodeDecl}) ->
        GraphLabel = string:replace(string:replace(Node, ".erl", ""), ":", ""),
        Colour =
            case Type of
                sink -> ",color=blue";
                source -> ",color=green";
                _ -> ""
            end,
        Href =
            case get_file_path(Node) of
                {Filepath, Line} ->
                    ",href=\"" ++ ?SOURCE_URL ++ Filepath ++ "?lines=" ++ Line ++
                        "\",target=\"_blank\"";
                _ ->
                    ""
            end,
        DotNodeDecl = io_lib:format("~s [label=\"~s\"~s~s];~n", [GraphLabel, Node, Href, Colour]),
        {Map#{Node => GraphLabel}, io_lib:format("~s~s", [DotNodeDecl, NodeDecl])}
    end,
    {NodeToLabel, NodeDecls} = maps:fold(F, {#{}, ""}, Nodes),

    Body = [
        io_lib:format("~s -> ~s;~n", [maps:get(From, NodeToLabel), maps:get(To, NodeToLabel)])
     || {From, To} <:- Edges
    ],
    lists:flatten(io_lib:format("digraph taintflow {~s~s}", [NodeDecls, Body])).
