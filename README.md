# A taint analysis for Erlang

This repo contains a taint analysis for Erlang. It does not contain an
off-the-shelf integration to use it. The analysis is setup to run on the
examples, from which an inspiration for integration can be gained. For example
the analysis could be run as part of running test by setting up hooks before
and after running tests.

To read the basic concepts behind the analysis check [finer_taint/README](./finer_taint/README.md).

## Getting started

### Install prerequisties

* [Install erlang](https://www.erlang.org/downloads), namely make sure [toolchains/local/erl](./toolchains/local/erl) scripts work
* This project is built with [Buck2](https://github.com/facebook/buck2).
Please [install Buck2](https://github.com/facebook/buck2?tab=readme-ov-file#installing-buck2) first.
* Init submodules: `git submodule update --init --recursive`

### Run the simple example

```
$ buck2 run @//mode/online_finer_taint :examples  simple
...
Done gathering
Dataflows found: [{leak,"simple_example.erl:23",
                        [{step,"simple_example.erl:23"},
                         {source,"simple_example.erl:22"}]}]
```

The printed list, tells us of a dataflow from `simple_example.erl` line 22 to line 23. Check the [simple_example.erl](./examples/simple_example.erl) to confirm the dataflow manually.



## How to run examples

We provide two ways of running the examples:

1. `@//mode/online_finer_taint` where the analysis is run alongside the program under test
2. `@//mode/finer_taint` where the analysis writes instructions to a file, that needs to be post-processed to get the results


To run the more complicated gen_server_example in the online mode, try:

```
$ buck2 run @mode/online_finer_taint :examples some_string
...
{leak,"example_gen_server.erl:41",
      [{step,"example_gen_server.erl:41"},
       {source,"example_gen_server.erl:40"}]}]
```



To run the simple example in the second mode, run the commands below. This might be useful should you want to manually
inspect the instructions for the abstract machine.

```
# Clean up files that might be left over from previous runs
rm /tmp/default_instr_prefix-*

# Run the program under test with the taint mode, which will compile the target with the parse transform
./buck2 run  @//mode/finer_taint :examples non-online-mode simple

# Extract the analysis results
./buck2 run  :script -- run /tmp/default_instr*   -pprint -print
Running on ["/tmp/default_instr_prefix-441874"]
[<0.110.0>] executing instructions file "/tmp/default_instr_prefix-441874"
Currently have 0 leaks
Setting up new stack at "simple_example.erl:21"
Done running abstract machine
Got 1 leaks from <0.110.0>
Terminating abstract machine <0.110.0> after 13405 reductions with  {shutdown,
done_processing}
[{leak,"simple_example.erl:23",
       [{step,"simple_example.erl:23"},{source,"simple_example.erl:22"}]}]
```


## How to run via test

Another way to try the analysis works is by running the test suite and inspecting the outputs.

For example:

```
buck2 test :finer_taint_SUITE
```

## License

erlang taint analysis is [Apache licensed](./LICENSE).
