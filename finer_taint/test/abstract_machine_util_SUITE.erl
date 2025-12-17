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
%%%-------------------------------------------------------------------
%%% @doc
%%%     Unit tests for abstract_machine_util.erl
%%% @end
%%% -------------------------------------------------------------------
-module(abstract_machine_util_SUITE).

-include_lib("stdlib/include/assert.hrl").

%% Test server callbacks
-export([
    all/0
]).

%% Test cases
-export([
    models_cfg_is_correct/1,
    can_balance_call_ret_with_joined_history/1,
    can_get_dataflows/1,
    can_balance_call_ret_with_joined_message_pass/1
]).

all() ->
    [
        models_cfg_is_correct,
        can_balance_call_ret_with_joined_history,
        can_get_dataflows,
        can_balance_call_ret_with_joined_message_pass
    ].

%%--------------------------------------------------------------------
%% TEST CASES
%%

models_cfg_is_correct(_Config) ->
    Models = abstract_machine_util:get_priv_models(),
    ?assertMatch(#{{'operators', 'div'} := propagate}, Models),
    maps:foreach(
        fun(MF, Action) ->
            ?assertMatch({M, F} when is_atom(M) and is_atom(F), MF),
            ?assert(Action =:= propagate orelse Action =:= sanitize)
        end,
        Models
    ).

can_get_dataflows(_Config) ->
    TaintHistory = [
        {call_site, {current_module, pack, 1}, "simple_example.erl:30"},
        {return_site, {operators, '+', 2}, "simple_example.erl:30"},
        {joined_history, model, [
            [
                {call_site, {operators, '+', 2}, "simple_example.erl:30"},
                {arg_taint, {{simple_example, lineage_entry, 2}, 2}},
                {call_site, {current_module, lineage_entry, 2}, "unknown"}
            ],
            [
                {call_site, {operators, '+', 2}, "simple_example.erl:30"},
                {return_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {arg_taint, {{simple_example, unpack, 1}, 1}},
                {call_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {return_site, {current_module, pack, 1}, "simple_example.erl:29"},
                {arg_taint, {{simple_example, pack, 1}, 1}},
                {call_site, {current_module, pack, 1}, "simple_example.erl:29"},
                {arg_taint, {{simple_example, lineage_entry, 2}, 1}},
                {call_site, {current_module, lineage_entry, 2}, "unknown"}
            ]
        ]}
    ],
    ?assertEqual(
        [
            {dataflow_src, {{simple_example, lineage_entry, 2}, 1}, [
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]},
            {dataflow_src, {{simple_example, lineage_entry, 2}, 2}, [
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]},
            {dataflow_src, {{simple_example, pack, 1}, 1}, [
                {return_site, {current_module, pack, 1}, "simple_example.erl:29"},
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]},
            {dataflow_src, {{simple_example, unpack, 1}, 1}, [
                {return_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]}
        ],
        maps:keys(abstract_machine_util:get_dataflows(TaintHistory))
    ).

can_balance_call_ret_with_joined_history(_Config) ->
    TaintHistory = [
        {call_site, {current_module, pack, 1}, "simple_example.erl:30"},
        {return_site, {operators, '+', 2}, "simple_example.erl:30"},
        {joined_history, model, [
            [
                {call_site, {operators, '+', 2}, "simple_example.erl:30"},
                {arg_taint, {{simple_example, lineage_entry, 2}, 2}},
                {call_site, {current_module, lineage_entry, 2}, "unknown"}
            ],
            [
                {call_site, {operators, '+', 2}, "simple_example.erl:30"},
                {return_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {arg_taint, {{simple_example, unpack, 1}, 1}},
                {call_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {return_site, {current_module, pack, 1}, "simple_example.erl:29"},
                {arg_taint, {{simple_example, pack, 1}, 1}},
                {call_site, {current_module, pack, 1}, "simple_example.erl:29"},
                {arg_taint, {{simple_example, lineage_entry, 2}, 1}},
                {call_site, {current_module, lineage_entry, 2}, "unknown"}
            ]
        ]}
    ],
    ?assertEqual(
        [
            {dataflow_src, {{simple_example, lineage_entry, 2}, 1}, [
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]},
            {dataflow_src, {{simple_example, lineage_entry, 2}, 2}, [
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]},
            {dataflow_src, {{simple_example, pack, 1}, 1}, [
                {return_site, {current_module, pack, 1}, "simple_example.erl:29"},
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]},
            {dataflow_src, {{simple_example, unpack, 1}, 1}, [
                {return_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]}
        ],
        maps:keys(abstract_machine_util:get_dataflows(TaintHistory))
    ).

can_balance_call_ret_with_joined_message_pass(_Config) ->
    TaintHistory = [
        {call_site, {current_module, pack, 1}, "simple_example.erl:30"},
        {return_site, {operators, '+', 2}, "simple_example.erl:30"},
        {joined_history, model, [
            [
                {call_site, {operators, '+', 2}, "simple_example.erl:30"},
                {arg_taint, {{simple_example, lineage_entry, 2}, 2}},
                {call_site, {current_module, lineage_entry, 2}, "unknown"}
            ],
            [
                {call_site, {operators, '+', 2}, "simple_example.erl:30"},
                {return_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {message_pass, "some messagepass"},
                {arg_taint, {{simple_example, unpack, 1}, 1}},
                {call_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {return_site, {current_module, pack, 1}, "simple_example.erl:29"},
                {arg_taint, {{simple_example, pack, 1}, 1}},
                {call_site, {current_module, pack, 1}, "simple_example.erl:29"},
                {arg_taint, {{simple_example, lineage_entry, 2}, 1}},
                {call_site, {current_module, lineage_entry, 2}, "unknown"}
            ]
        ]}
    ],
    ?assertEqual(
        [
            {dataflow_src, {{simple_example, lineage_entry, 2}, 1}, [
                {call_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {message_pass, "some messagepass"},
                {return_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]},
            {dataflow_src, {{simple_example, lineage_entry, 2}, 2}, [
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]},
            {dataflow_src, {{simple_example, pack, 1}, 1}, [
                {return_site, {current_module, pack, 1}, "simple_example.erl:29"},
                {call_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {message_pass, "some messagepass"},
                {return_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]},
            {dataflow_src, {{simple_example, unpack, 1}, 1}, [
                {message_pass, "some messagepass"},
                {return_site, {current_module, unpack, 1}, "simple_example.erl:30"},
                {call_site, {current_module, pack, 1}, "simple_example.erl:30"}
            ]}
        ],
        maps:keys(abstract_machine_util:get_dataflows(TaintHistory))
    ).
