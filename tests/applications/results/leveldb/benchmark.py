"""
Record leveldb benchmark.
"""
import argparse
import subprocess
import json
import os
from typing import Dict, Any

from pathlib import Path
from tempfile import TemporaryDirectory

from hase.record import record


def main() -> None:

    result_file = Path(args.outdir).joinpath("result.json").resolve()
    results: Dict[str, Any] = {args.name: {"original": [], "hase": []}}

    for i in range(args.n):
        results[args.name]["hase"].append(dict(run=i, result=[], valid=True))
        with TemporaryDirectory() as tempdir:
            temppath = Path(tempdir)
            recording = record(
                target=args.args,
                record_path=temppath,
                log_path=temppath.joinpath("logs"),
                stdout=open(f"{args.outdir}/{args.name}_hase_{i}.out", "w"),
                limit=1,
            )
            if recording:
                rusage = recording.rusage
                if rusage:
                    results[args.name]["hase"][i]["result"].append(list(rusage))

        results[args.name]["original"].append(dict(run=i, result=[], valid=True))

        process = subprocess.Popen(
            args.args, stdout=open(f"{args.outdir}/{args.name}_{i}.out", "w")
        )
        _, _, rusage = os.wait4(process.pid, 0)
        if rusage:
            results[args.name]["original"][i]["result"].append(list(rusage))

    with open(result_file, "w") as file:
        json.dump(results, file, sort_keys=True, indent=4, separators=(",", ": "))
        file.write("\n")

    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--outdir", default=".", type=str, help="The output directory")
    parser.add_argument("-n", default=3, type=int, help="The number of runs")
    parser.add_argument(
        "--name", default="benchmark", type=str, help="The name of the benchmark"
    )
    parser.add_argument(
        "args", nargs="*", help="Executable and arguments for benchmarking"
    )

    args = parser.parse_args()

    main()
