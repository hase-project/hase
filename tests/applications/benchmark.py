"""
Benchmarking SPECCPU with and without recording.
Results written into a json(python dictionary) file.
"""
import argparse
from pathlib import Path
from tempfile import TemporaryDirectory

from hase.record import record


def main() -> None:
    with TemporaryDirectory() as tempdir:
        temppath = Path(tempdir)
        record(
            target=args.pid, record_path=temppath, log_path=temppath.joinpath("logs")
        )
        __import__('pdb').set_trace()
        print("foo")
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="The pid to monitor usage")
    args = parser.parse_args()

    main()
