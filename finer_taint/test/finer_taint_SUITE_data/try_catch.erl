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

-module('try_catch').
-export([
         try_main/0, try_after_main/0,
         try_catch_nested_main/0,
         try_catch_define_main/0,
         try_catch_crs_main/0,
         try_catch_main2/0
]).
-include_lib("stdlib/include/ms_transform.hrl").


throwing_function(X) when X =:= 0 ->
  throw({foo, X});
throwing_function(1) ->
  1 / finer_taint:source(0);
throwing_function(X) when X > 0 andalso X rem 2 =:= 1 ->
  {odd, X + 1};
throwing_function(_)  ->
  {even, 2}.
  

try_main() ->
  TaintedOdd = finer_taint:source(5),
  NotTainted = try throwing_function(TaintedOdd + 1) of
                 {even, X} -> X
               catch
                 doesntmatch -> ok
               end,
 finer_taint:sink(NotTainted),
 Tainted = try throwing_function(TaintedOdd) of
                 {odd, Y} -> Y
               catch
                   doesntmatch -> ok
               end,
 finer_taint:sink(Tainted),
 finer_taint:sink(try throwing_function(1) catch
                    error:Error -> Error
                  end),
 finer_taint:sink(try throwing_function(TaintedOdd - 5) of
                    doesntmatch -> ok
                  catch
                    {foo, Z} -> Z
                  end).

helper_function() ->
  TaintedVal = finer_taint:source(42),
  Val = try ok of
          ok -> TaintedVal
        catch
          _ -> ok
        end.

try_catch_main2() ->
  TaintedValue = helper_function(),
  finer_taint:sink(TaintedValue).


inner_catch() ->
  TaintedVal = finer_taint:source(0),
  try throwing_function(TaintedVal) 
  catch
    not_the_throw_value -> neverhappens
  end.

try_catch_nested_main() ->
  try inner_catch()
  catch
    {foo, X} -> finer_taint:sink(X)
  end,
  Caught = catch inner_catch(),
  finer_taint:sink(Caught).


-define(TRY_CATCH(Body, Catch), try Body catch Catch -> Catch end).

try_catch_define_main() ->
  TaintedVal = finer_taint:source(0),
  try ?TRY_CATCH(?TRY_CATCH(throwing_function(TaintedVal), ok), ok)
  catch
    {foo, X}  -> finer_taint:sink(X)
  end.


try_catch_crs_main() ->
  Tainted = finer_taint:source(0),
  try
    throwing_function(Tainted)
  catch Class:Reason:Stacktrace ->
          finer_taint:sink(Class),
          finer_taint:sink(Reason),
          finer_taint:sink(Stacktrace)
  end,

  Tainted1 = try ets:next(nonon_existent, ok)
  catch
      error:_ -> finer_taint:source(42);
      % Needs to be transformed with ms_transform, otherwise it's invalid AST
      never_matches -> ets:fun2ms(fun({_, #{ts => Ts}} ) when 1 > Ts -> ok end)
  end,
  finer_taint:sink(Tainted1).

try_after_main() ->
  Tainted = try
              finer_taint:source(0)
            after
              ok
            end,
  finer_taint:sink(Tainted).
