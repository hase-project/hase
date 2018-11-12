# Install spec

```console
$ mkdir /tmp/spec-iso
$ sudo mount cpu2017-1.0.1.iso /tmp/spec-iso
# on nixos:
$ nix-shell tests/speccpu/shell.nix
$ cd /tmp/spec-iso
$ ./install.sh -d /home/joerg/git/hase/spec
$ cd /home/joerg/git/hase/spec
$ cp tests/speccpu/default.cfg /home/joerg/git/hase/spec
$ . shrc
$ runcpu --size test --action setup intspeed
$ runcpu --size test --action setup fpspeed
```

# Set up benchmarks

+ Source the shrc file under the speccpu folder.

```
$ . shrc
```

+ Create a configuration file under the config folder.
+ Build the benchmarks and set up the run folders. We specifically focus on
the speed benchmarks with base optimization. If you want to run the benchmark without
hase, you can drop `--loose`, and `--action setup`. Use `test` for test and ref for
measurement.
```console
$ runcpu [--loose] [--size {test, train, ref}] [--config <config_file>] [--tune {base, peak}] [--threads <N>] [--action setup] <benchmark(s)>
```
# Measure overhead
+ Configure `config.py` to edit the paths.
+ Run the benchmark wrapper. Record Path is the path to hold the result.
```console
$ sudo python3 benchmark.py [--run <N>] [--record-path <path>] {all, int, float, xxx}
```
+ Aggregate the result(s).
```console
$ python3 aggregate.py [-m <result_to_merge>] [-f {auto, xxx}]  <result_file>
```
