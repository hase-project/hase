"""
Benchmarking sqlite
"""
import argparse
import subprocess

from pathlib import Path


def main() -> None:
    # if args.n:
    #     while True:
    #         output = subprocess.getoutput(f"pgrep {args.n}")
    #         if output.strip():
    #             break
    #     args.p = int(output.strip())
    #
    # print(f"Recording {args.p}.")
    # with TemporaryDirectory() as tempdir:
    #     temppath = Path(tempdir)
    #     record(
    #         target=args.p, record_path=temppath, log_path=temppath.joinpath("logs")
    #     )

    for i in range(args.r):
        hase_name = "_hase" if args.hase else ""
        subprocess.run(
            ["wrk", "-t", args.t, "-d", args.d, "-c", args.c, args.url],
            stdout=(Path(args.outdir) / f"{args.name}{hase_name}_{i}.out").open("w"),
        )

    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", default=3, type=int, help="The number of runs")
    parser.add_argument(
        "--url", default="http://localhost/", type=str, help="The url to access"
    )
    parser.add_argument("-t", default="1", type=str, help="The number of threads")
    parser.add_argument("-c", default="10", type=str, help="The number of connections")
    parser.add_argument("-d", default="10", type=str, help="The duration in seconds")
    parser.add_argument("--outdir", default=".", type=str, help="The output directory")
    parser.add_argument(
        "--name", type=str, default="nginx", help="The name of the benchmark"
    )
    parser.add_argument(
        "--hase",
        action="store_true",
        help="If you are currently running hase to record",
    )
    args = parser.parse_args()

    main()
