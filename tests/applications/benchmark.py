"""
Benchmarking SPECCPU with and without recording.
Results written into a json(python dictionary) file.
"""
import argparse
import subprocess

from pathlib import Path
from tempfile import TemporaryDirectory

from hase.record import record


def main() -> None:
    if args.n:
        while True:
            output = subprocess.getoutput(f"pgrep {args.n}")
            if output.strip():
                break
        args.p = int(output.strip())

    print(f"Recording {args.p}.")
    with TemporaryDirectory() as tempdir:
        temppath = Path(tempdir)
        record(
            target=args.p, record_path=temppath, log_path=temppath.joinpath("logs")
        )

    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", default=0, type=int, help="The pid to monitor")
    parser.add_argument("-n", type=str, help="The name of the process to monitor")
    args = parser.parse_args()

    main()
