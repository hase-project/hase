from __future__ import absolute_import, division, print_function
import sys
import pandas

from typing import List


def main(argv):
    # type: (List[str]) -> None
    if len(sys.argv) < 2:
        print("USAGE: %s syscall.tsv" % argv[0], file=sys.stderr)
        sys.exit(1)

    tsv = argv[1]
    df = pandas.read_csv(tsv, sep="\t")
    print(df.groupby([df.Name, df.Type]).describe())
    for t in df.Type.unique():
        df_by_type = df[df.Type == t]
        df_perf = df_by_type[df_by_type.Name == "bpf"]
        df_no_perf = df_by_type[df_by_type.Name == "no-bpf"]
        overhead = df_no_perf["Req/s"].mean() / df_perf["Req/s"].mean() * 100
        print("Overhead %s: %.2f%%" % (t, overhead))


if __name__ == "__main__":
    main(sys.argv)
