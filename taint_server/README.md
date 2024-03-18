# A server supporting the taint analysis

This app is responsible for writing instructions for the abstract machine to a
file during the execution of the program under test.


### Important env variables

* `instructions_stream_prefix` - Filepath prefix where the instruction traces
  will be written too. For example `/tmp/default-`. The actual files written
  will have thread ids appended to the end. Defaults to
  `instructions_stream_prefix_default` (`/tmp/default_instr_prefix`).
                            

