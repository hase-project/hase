# Set up benchmarks
+ Source the shrc file under the speccpu folder.
```
    . shrc
```
+ Create a configuration file under the config folder.
+ Build the benchmarks and set up the run folders. We specifically focus on
the speed benchmarks with base optimization. If you want to run the benchmark without
hase, you can drop `--loose`, and `--action setup`. Use `test` for test and ref for
measurement.
```
    runcpu [--loose] [--size {test, train, ref}] [--config <config_file>] [--tune {base, peak}] [--threads <N>] [--action setup] <benchmark(s)>
```
# Measure overhead
+ Configure `config.py` to edit the paths.
+ Run the benchmark wrapper. Record Path is the path to hold the result.
```
    sudo python3 benchmark.py [--run <N>] [--record-path <path>] {all, int, float, xxx}
```
+ Aggregate the result(s).
```
    python3 aggregate.py [-m <result_to_merge>] [-f {auto, xxx}]  <result_file>
```
