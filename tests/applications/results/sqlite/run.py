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
        subprocess.run(["rm", args.db])
        subprocess.run(
            ["sqlite3", args.db],
            input=(
                b"CREATE TABLE usertable (YCSB_KEY VARCHAR(255) PRIMARY KEY, "
                b"FIELD0 TEXT, FIELD1 TEXT, FIELD2 TEXT, FIELD3 TEXT, FIELD4 TEXT, "
                b"FIELD5 TEXT, FIELD6 TEXT, FIELD7 TEXT, FIELD8 TEXT, FIELD9 TEXT);\n"
                b".quit"
            ),
        )

        print("bin/ycsb load jdbc -P workloads/workloada -P <conf>")
        print("sudo python benchmark.py -n java")
        print("bin/ycsb run jdbc -P workloads/workloada -P <conf>")

        # FIXME: got an error about about "path doesn't exists" when it does.

        # subprocess.run(
        #     [
        #         "bin/ycsb",
        #         "load",
        #         "jdbc",
        #         "-P",
        #         f"workloads/workload{args.b}",
        #         "-p",
        #         "db.driver=org.sqlite.JDBC",
        #         "-p",
        #         f"db.url=jdbc:sqlite::{args.db}",
        #     ],
        #     cwd=args.cwd,
        #     stdout=open(f"ycsb_{args.b}/load_{i}.out", "w")
        # )
        # subprocess.run(
        #     [
        #         "bin/ycsb",
        #         "run",
        #         "jdbc",
        #         "-P",
        #         f"workloads/workload{args.b}",
        #         "-p",
        #         "db.driver=org.sqlite.JDBC",
        #         "-p",
        #         f"db.url=jdbc:sqlite::{args.db}",
        #     ],
        #     cwd=args.cwd,
        #     stdout=open(f"ycsb_{args.b}/run_{i}.out", "w")
        # )

    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", default=1, type=int, help="The number of runs")
    parser.add_argument("db", type=str, help="The path to the db")
    # parser.add_argument("cwd", type=str, help="The path of YCSB home")
    parser.add_argument("-b", default="a", type=str, help="YCSB benchmark")
    args = parser.parse_args()

    main()
