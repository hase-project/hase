"""
    Benchmarking SPECCPU with and without recording.
    Results written into a json(python dictionary) file.
"""
import argparse
import json
import sys
import logging
import os
import shlex
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, Dict, Any

from config import *
from hase.record import record


class BenchCommand:
    def __init__(self, args: List[str], stdout_file: str, stderr_file: str) -> None:
        self.args = args
        self.stdout_file = stdout_file
        self.stderr_file = stderr_file


def parse_shell_command(cmdline: str) -> BenchCommand:
    args = []
    parts = shlex.split(cmdline)
    stdout_file = None
    stderr_file = None
    idx = 0

    while idx < len(parts):
        if parts[idx].startswith(">"):
            stdout_file = parts[idx + 1]
            idx += 2
        elif parts[idx].startswith("2>"):
            stderr_file = parts[idx + 1]
            idx += 2
        else:
            args.append(parts[idx])
            idx += 1

    assert stdout_file is not None and stderr_file is not None

    return BenchCommand(args, stdout_file, stderr_file)


def measure(benchmark: str) -> Dict[str, Any]:
    result: Dict[str, Any] = dict(original=[], hase=[])
    bench_path = SUITE_PATH + SUITE[benchmark]["name"] + RUN_PATH # type: ignore
    os.chdir(bench_path)

    # Get run commands
    run_commands = []
    output = subprocess.getoutput(f"{SPEC_PATH.joinpath('bin')}/specinvoke -n")
    for line in output.split("\n"):
        if line.startswith(".."):
            run_commands.append(parse_shell_command(line))

    # Get validate commands
    validate_commands = []
    output = subprocess.getoutput(
        f"{SPEC_PATH.joinpath('bin')}/specinvoke -n compare.cmd"
    )
    for line in output.split("\n"):
        if line.startswith("#") or line.startswith("specinvoke"):
            continue
        if "specdiff" not in line:
            validate_commands.append(line)
        else:
            redirect_index = line.find(" > ")
            if redirect_index != -1:
                validate_commands.append(line[:redirect_index])
    # print(validate_commands)

    for run in range(args.run):
        result["hase"].append(dict(run= run, result=[], valid=True))
        if args.group in ("both", "hase"):
            for i, command in enumerate(run_commands):
                LOGGER.info(
                    f"Benchmark: {benchmark}, Run: {run}, Command: {i}, with hase"
                )
                LOGGER.debug(f"{' '.join(command.args)}")
                with TemporaryDirectory() as tempdir, \
                    open(command.stdout_file, "w+") as stdout, \
                    open(command.stderr_file, "w+") as stderr:
                    temppath = Path(tempdir)
                    recording = record(
                        temppath,
                        temppath.joinpath("logs"),
                        limit=1,
                        command=command.args,
                        rusage=True,
                        stdout=stdout,
                        stderr=stderr
                    )
                    rusage = recording.rusage
                    result["hase"][run]["result"].append(list(rusage))

            for validate_command in validate_commands:
                validation = subprocess.getoutput(validate_command).split("\n")
                LOGGER.debug(f"Validation command:{validate_command}")
                LOGGER.debug(f"Results:\n{validation}")
                if len(validation) != 1 or not (
                    validation[0] == "" or "specdiff run completed" in validation[0]
                ):
                    LOGGER.error(f"Wrong result!")
                    result["hase"][run]["valid"] = False
                    break

        result["original"].append({"run": run, "result": [], "valid": True})

        if args.group in ("both", "original"):
            for i, command in enumerate(run_commands):
                LOGGER.info(
                    f"Benchmark: {benchmark}, Run: {run}, Command: {i}, without hase"
                )
                LOGGER.debug(f"{' '.join(command.args)}")

                with open(command.stdout_file, "w+") as stdout, \
                    open(command.stderr_file, "w+") as stderr:
                    process = subprocess.Popen(command.args, stdout=stdout, stderr=stderr)
                _, _, rusage = os.wait4(process.pid, 0)
                result["original"][run]["result"].append(list(rusage))

            for validate_command in validate_commands:
                validation = subprocess.getoutput(validate_command).split("\n")
                LOGGER.debug(f"Validation command:{validate_command}")
                LOGGER.debug(f"Results:\n{validation}")
                if len(validation) != 1 or not (
                    validation[0] == "" or "specdiff run completed" in validation[0]
                ):
                    LOGGER.error(f"Wrong result!")
                    result["original"][run]["valid"] = False
                    break

    return result


def main() -> None:
    benchmarks: List[str] = []

    if args.benchmark in SUITE:
        benchmarks = [args.benchmark]
    elif args.benchmark == "all":
        benchmarks = list(SUITE.keys())
    elif args.benchmark == "int":
        benchmarks = INT_SPEED
    elif args.benchmark == "float":
        benchmarks = FLOAT_SPEED
    else:
        print(f"invalid benchmark '{args.benchmark}' given as argument")
        sys.exit(1)

    results: Dict[str, Any] = {}
    result_file = Path(args.record_path).joinpath(args.name + ".json").resolve()
    #import pdb; pdb.set_trace()
    if result_file.exists():
        with open(result_file, "r") as f:
            results = json.load(f)

    skip_benchmarks = set(benchmarks) & results.keys()
    run_benchmarks = set(benchmarks) - results.keys()

    if len(skip_benchmarks) > 0:
        print(f"skip benchmarks: {' '.join(skip_benchmarks)}")

    if len(run_benchmarks) > 0:
        print(f"run benchmarks: {' '.join(run_benchmarks)}")

    for benchmark in run_benchmarks:
        results[benchmark] = measure(benchmark)
        # write result benchmark after each run in case we have an error
        result_file.parent.mkdir(parents=True, exist_ok=True)
        with open(result_file, "w") as file:
            json.dump(results, file, sort_keys=True, indent=4, separators=(',', ': '))
            file.write("\n")
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("benchmark", type=str, help="The benchmark (suite) to run")
    parser.add_argument("--run", type=int, default=3, help="The number of runs")
    parser.add_argument(
        "--group",
        type=str,
        default="both",
        choices=["both", "hase", "original", "neither"],
        help="Select which group to record (hase, original, or both)",
    )
    parser.add_argument("--log", type=str, default="INFO", help="Select logging level")
    parser.add_argument(
        "--name", type=str, default="result", help="The name of the result file"
    )
    parser.add_argument(
        "--record-path",
        "-p",
        type=str,
        required=True,
        help="The name of the record folder",
    )
    args = parser.parse_args()
    numeric_level = getattr(logging, args.log.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: %s" % args.log)

    logging.basicConfig(
        format="%(asctime)s: %(levelname)s: %(message)s", level=numeric_level
    )
    LOGGER = logging.getLogger(__name__)

    main()
