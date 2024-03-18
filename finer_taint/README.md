
# Instrumentation for finer-taint analysis

This analysis is capable of tracking taint precisely through data transformations
and is able to provide lineage data. 

## Short guide to the code

[finer\_taint\_compiler.erl](https://github.com/WhatsApp/erlang_taint_analysis/blob/main/finer_taint/src/finer_taint_compiler.erl)
is a parse transform the inserts instrumentation that emits abstract machine
instructions. The instrumentation calls into [finer\_taint.erl](https://github.com/WhatsApp/erlang_taint_analysis/blob/main/finer_taint/src/finer_taint.erl)
that performs the actual emitting of instructions.

The [taint\_abstract\_machine.erl](https://github.com/WhatsApp/erlang_taint_analysis/blob/main/finer_taint/src/taint_abstract_machine.erl)
implements the abstract machine that executes the emitted instructions to produce analysis results.

```
buck2 run :script
```

Is an escript that provides a nicer interface to run the abstract machine on the emitted instructions.

[finer\_taint\_SUITE.erl](https://github.com/WhatsApp/erlang_taint_analysis/blob/main/finer_taint/test/finer_taint_SUITE.erl)
is a test suite showing how analysis works on simple (non message passing related) erlang constructs. It can be useful
to see how the analysis behaves on some easily degistable code. For example running [simple\_example.erl](https://github.com/WhatsApp/erlang_taint_analysis/blob/main/finer_taint/test/finer_taint_SUITE_data/simple_example.erl?lines=1)
produces [these instructions](https://github.com/WhatsApp/erlang_taint_analysis/blob/main/finer_taint/test/finer_taint_SUITE_data/one_clause_analysis_instr).



## Technical Details


The analysis is based on [a
paper](https://people.eecs.berkeley.edu/~ksen/papers/jtaint.pdf), where the
idea is to shadow the real execution by an execution of an abstract-machine
operating on taint values.  The analysis is performed in three steps:

1. Instrument the program under test with instrumentation that emits instructions (via a side channel) for the abstract machine.
2. Run the program under test.  This results in a trace of the execution in the form of a sequence of instructions for the abstract machine.
3. Execute the abstract machine instructions on the abstract machine to get the taint analysis result.


Intuitively, each value in the program execution has an associated taint value
in the abstract-machine execution. The taint value has one of two values:
tainted or not-tainted. The goal of instructions emitted by the instrumentation
during execution of the program under test is to keep a relation between
program and abstract machine executions. The two executions are essentially
synchronise, with the abstract machine execution significantly simplified and
only concerned about taint values. 

This analysis has two good properties:

* The instrumentation doesn’t have expensive lookups, it just emits instructions. This means the instrumented program should only have a constant overhead due to instrumentation.
* It doesn’t rely on equality to determine if a value is tainted or not. This is useful for Erlang, because we cannot distinguish values that have the same representation, but one is tainted while the other is not.

Next, we first describe the instructions for the abstract machine, then we show
how we instrument the program and finally we show how the abstract machine is
run to produce the taint analysis result.

## Abstract machine

The abstract machine is a stack machine operating on taint values. It has a
stack of taint values and a variable store associating variable names to taint
values.  

```
type taint_value(): notaint | {taint, history()}
```

A `taint_value` can either represent a value not tainted, or a tainted value with some history of where the value has been.
For example a `{taint, ["sourcel.erl:2", "source.erl:1"]}` would indicate a tainted value was part of computation on line 1 in `source.erl` followed by some computation at line 2. 

We are going to represent the abstract machine as a list representing the stack
and a map representing the variable store ( `[], {}`). So an abstract machine
`[notaint, {taint, ...}], {X: notaint}` has `notaint` value on top of the stack
followed by a `taint` value. There is only variable X in the variable store
having a `notaint` value.

A subset of instructions for the abstract machine:

* `push(TaintValue)`: push the TaintValue to the stack
* `get(VarName)`: get the taint value of VarName and push it to the stack
* `store(VarName)`: pop a value of the stack and store it in VarName
* `apply(Module:Function/Arity)`: pop Arity arguments of the stack and push the result of applying MFA to the stack
* `sink()`: pop value of the stack and report data-flow if it’s tainted

## Instrumentation

The instrumentation is currently implemented as an AST transformation. The
instrumentation inserts appropriate abstract machine instruction emitters in
the program under test. Consider two simple assignments

```
AString = "123 is a good start of a string",
PhoneNumber = finer_taint:source("123@secret.net"),
```

We look at each expression in [a
clause](https://www.erlang.org/doc/apps/erts/absform.html#clauses) individually
and insert instrumentation between them.  The above example is a clause with 2
match expressions. For a match expression we insert instrumentation for the
right hand side (RHS) before the match. In the `AString` case the RHS is a
constant string, which cannot be tainted. Therefore we insert an emitter for
`push(notaint)` instruction. For `PhoneNumber` the RHS is a source so we add an
emitter for `push({taint, ["l2"]})`, where `l2` indicates source line 2. In
both cases the left hand side (LHS) is a simple variable pattern, so we can
store the values directly. In the case of pattern matching we would need to
emit additional instructions,  but that’s outside the scope of this note. The
final instrumented snippet looks like:

```
push(notaint),
AString = "123 is a good start of a string",
store("AString"),
push({taint, ["exampler.erl:2"]}),
PhoneNumber = finer_taint:source("123@secret.net"),
store("PhoneNumber")
```

As another example, consider a function call `X = string:slice(PhoneNumber, 0,
3)`, which is also a match expression, where the RHS is a function call.
Therefore we first traverse the arguments of the function call. Constant
integers can’t be tainted so we need to emit `push(notaint)`, `PhoneNumber` is
a variable, which we need to look-up via  `get("PhoneNumber")` instruction.
Finally we emit the `apply(string:slice/3)` after the actual function call
returns. Finally we store the result into `X`.


```
push(notaint),
push(notaint),
get("PhoneNumber"),
X = string:slice(PhoneNumber, 0, 3),
apply(string:slice/3),
store("X")`
```

In this case `string:slice/3` is “non-instrumented” function, which means we
haven’t instrumented the body of the function. This means we have to model the
behaviour of `string:slice/3`. The analysis supports writing specific models
for functions, but we also have a default model that considers the return value
of a function tainted if any of the function arguments are tainted. 

For the cases where the body of the called functions is instrumented, the
`apply` instruction is essentially a noop as the calling convention specifies
that the arguments are popped off the stack and the return value of the
function is on top of the stack.


## Running the abstract machine

Consider we have instrumented and ran the following program:

```
AString = "123 is ...",
Number = source("123@..."),
X = slice(Number, 0, 3),
Y = slice(AString, 0, 3),
finer_taint:sink(Y),
finer_taint:sink(X).
```

Below we show the trace of emitted instructions. The original executed lines
are shown as comments (prefixed with `%`). The comments at the right side of
the emitted instructions represent the state of the abstract machine after
executing that instruction.

```
% AString = "123 is ...", 
push(notaint), % [notaint], {}
store("AString"), % [], {AString: notaint}

% Number = source("123@..."),
push({taint, ["l2"]}), % [{taint, ["l2"]}], {AString: notaint}
store("Number"), % [], {AString: notaint, Number: {taint, ["l2"]}}

% X = slice(Number, 0, 3),
push(notaint), % [notaint], {AString: notaint, Number: {taint, ["l2"]}} 
push(notaint), % [notaint,notaint], {AString: notaint, Number: {taint, ["l2"]}}
get("Number"), % [{taint, ["l2"]}, notaint,notaint], {AString: notaint, Number: {taint, ["l2"]}}
apply(string:slice/3), % [{taint, ["l3", "l2"]}], {AString: notaint, Number: {taint, ["l2"]}}
store("X"), % [], {X:{taint, ["l3", "l2"]}, AString: notaint, Number: {taint, ["l2"]}}

% Y = slice(AString, 0, 3),
push(notaint), % [notaint], {X:{taint, ["l3", "l2"]}, AString: notaint, Number: {taint, ["l2"]}}
push(notaint), % [notaint,notaint], {X:{taint, ["l3", "l2"]}, AString: notaint, Number: {taint, ["l2"]}}
get("AString"), % [notaint,notaint,notaint], {X:{taint, ["l3", "l2"]}, AString: notaint, Number: {taint, ["l2"]}}
 apply(string:slice/3), %[notaint], {X:{taint, ["l3", "l2"]}, AString: notaint, Number: {taint, ["l2"]}}
store("Y"), % [], {Y: notaint, X:{taint, ["l3", "l2"]}, AString: notaint, Number: {taint, ["l2"]}}

% finer_taint:sink(Y),
get("Y"), % [notaint], {Y: notaint, X:{taint, ["l3", "l2"]}, AString: notaint, Number: {taint, ["l2"]}}
sink(), % [], {Y: notaint, X:{taint, ["l3", "l2"]}, AString: notaint, Number: {taint, ["l2"]}}

% finer_taint:sink(X).
get("X"), % [{taint, ["l3", "l2"]}], {Y: notaint, X:{taint, ["l3", "l2"]}, AString: notaint, Number: {taint, ["l2"]}}
sink(), %Report data-flow! line2 -> line3 -> line6
```

We start off by pushing `notaint` to top of the stack and storing it into
variable `AString`, resulting in the abstract machine state `[], {AString:
notaint}`. The same is done for storing the tainted value into `Number`. 

Then we move on executing instructions that were emitted during execution of `X
= slice(Number, 0, 3)`. We first push all the arguments to the stack, resulting
in abstract machine `[{taint, ["l2"]}, notaint,notaint], {...}`. The
`apply(string:slice/3)` instruction is then executed. Since this is a modelled
function call, it pops 3 arguments of the stack and applies the model for them.
There is one value that is tainted so the result of the function call should
also be tainted according to the default model we use. The resulting taint
value, should also indicate the value passed through line 3, so `l3` is added
to the history and taint value is pushed onto the stack, resulting in `[{taint,
["l3", "l2"]}]` stack.  This value is then popped of the stack and stored into
`X` by the store instruction.

Similar steps are followed for the Y case, except that there are no tainted
values in the arguments of `string:slice`, therefore `Y` is also not tainted.

Finally X and Y are checked (sunk) for taint. Firstly, taint value of Y is
pushed onto the stack and `sink()` checks whether the top of the stack is
tainted. In this case it is not. Then, the value of X is pushed onto the stack
and `sink()` checks if it’s tainted. In this case the top of the stack is
tainted and therefore a data-flow is reported along with the value and flow of how
it got there.

## Sources of imprecision

Sources of imprecision should be documented in this section. It aims to be comprehensive covering all
cases, but it's a work in progress so please add them here if you find any not mentioned here.


### Control-flow data-flows

Finer taint analysis does not consider control flow based data flows. For example in

```
is_member(PII, [PII | _] ) ->
  true;
is_member(PII, [_, Tail]) ->
  is_member(Pii, Tail);
is_member(_, []) ->
  false.
```

finer taint analysis would not report a dataflow from arguments of `is_member` to the return
value. This is because both return values `true` and `false` are new values created inside the function.

If this is an issue for a particular function, it can be mitigated, by adding an explicit model
for that function, which propagates the taints of its arguments.

### Timeouts

For message passing we have some timeouts for how long to wait for a message. This is to ensure we do
not need the analysis to be 100% to get some results. If a timeout is hit, the message is assumed untainted,
which can introduce a false positive.

### Binary comprehension

Binary comprehension are not supported at this time. They are assumed untainted


### Sockets

Sockets are not supported, so they assume the default model. The arguments to the socket functions are likely untainted so
the data read from the socket would be marked as not tainted. 


### Try catch

Try/catch handling does not deal with catch clauses that are skipped (because they don't match). Also the catch clause
does not deal with error handling.


### binary()

`binary()` patterns are poorly supported and likely don't work for the general
case. They have only been somewhat tested on bitstrings. This is subject to future work
when it becomes a problem. [See comment](https://github.com/WhatsApp/erlang_taint_analysis/blob/main/finer_taint/src/taint_abstract_machine.erl?lines=555)



## Models

Wrong or imprecise models impact the results of the analysis. There are three kinds of models:

* *uninstrumented models*, that is models for functions whose body is not
  instrumented by the finer taint analysis. For example arithmetic operators
  are modeled this way as we do not instrument the implementation of arithmetic
  operators.
  [model\_of](https://github.com/WhatsApp/erlang_taint_analysis/blob/main/finer_taint/src/taint_abstract_machine.erl?lines=619)
  function is used to model these sort of models. If a function does not have a
  specific case in `model_of/2`, we use the default model. The default model
  assumes the output of the function is tainted iff any arguments are tainted.
* *special uninstrumented models*, that is models whose body is not
  instrumented, but they are not handled as described above. Prime example of
  this is `erlang:spawn*` familiy of functions, where taint is propagated in a
  special way due to process creation. These are special cased in
  finer\_taint\_compiler.erl.
* *instrumented_models*, that is functions that we model by writting a simple
  erlang implementation of their body, which is then instrumented with
  finer\_taint instrumentation. The most common case of this is NIFs, which we
  can't instrument directly, but it is easy to write their code in Erlang and
  instrument that, which gives as their preciose behaviour. These models are
  located unders `src/models`. Some implementation of functions are swapped by our
  instrumentation, which happens in [`intercepted_functions/1`](https://github.com/WhatsApp/erlang_taint_analysis/blob/main/finer_taint/src/finer_taint_compiler.erl?lines=662)


### Uninstrumented models

For *uninstrumented models* we have the following considerations when deciding if they
should propagate taint or not:

1. Do the function arguments flow into its return value. If they do it's propagate\_taints.
2. Does the function mostly affect control flow (ie. returns a boolean)
2. Does it make the analysis cheaper by killing taint, without compromising the result


The first point is the most obivous/easy to justify as it just assumes an
over-approximation. These models could also be dervied from static analysis.
For example for erlang:monitor, it's easy to see that its arguments do not flow
into the return (it returns a random reference), but for string:concat it's
obvious that all arguments form its output.

For some functions the distinction from 1) technically holds, but is not very
useful. For example with `>` operator, the RHS and LHS technically flow into the
return value, but it's just a boolean for control flow.

Because finer\_taint doesn't do control flow taint flows, it's okay to assume
boolean operators essentially sanitize the taint values.

erlang:length is similar, the output of erlang:length is only tainted if you
account for control flow.

Finally another consideration is performance. Sanitising a taint value (by just
returning notaint), makes the analysis cheaper, because it doesn't have to keep
track of some history any more.

For example with erlang:function\_exported. There is a dataflow from its
arguments (the module) to list of functions that are exported, but that will
never be interesting to us, so it's just easier/faster to assume it's not
tainted.


