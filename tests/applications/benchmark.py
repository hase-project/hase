"""
    Benchmarking SPECCPU with and without recording.
    Results written into a json(python dictionary) file.
"""
import argparse

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, Dict, Any

from hase.record import record_pid




def main() -> None:
    with TemporaryDirectory() as tempdir:
        temppath = Path(tempdir)
        recording = record_pid(
            temppath,
            temppath.joinpath("logs"),
            args.pid,
        )
        rusage = recording.rusage

        if args.file:
            with open(args.file, 'w') as file:
                file.write(rusage)
        else:
            print(rusage.strip())
            rusage = rusage.strip().split()
            print(float(rusage[13]) + float(rusage[14]))

    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="The pid to monitor usage")
    parser.add_argument(
        "-f", "--file", default=None, help="The file to output the result"
    )
    args = parser.parse_args()

    main()
