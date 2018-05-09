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


if __name__ == "__main__":
    main(sys.argv)
