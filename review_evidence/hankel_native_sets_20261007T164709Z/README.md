# Native C implementation, all three parameter sets (October 7, 2026)

Evidence for the per-set template (WH-640, WH-936, WH-1208; paper, Section 8 and Appendix D):

- `make_test.txt`: the full `make test` run, including the C and Python tests of every set, the static
  audit of 25 functions and the known-answer tests of all three sets;
- `bench_native.txt`: latencies of every set (5,000 calls), with three further runs and a regression check
  of WH-640 against the earlier build;
- `tvla_repeat.py` -> `tvla_repeat.txt`: repeated fixed-versus-random timing tests, which showed that
  drawing random inputs just before each timed call biased the test (|t| up to 8.8), and that drawing
  them in advance removes the bias; the timing test has done so since;
- `source_sha256.txt`: hashes of the sources measured.
