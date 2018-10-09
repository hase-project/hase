from __future__ import absolute_import, division, print_function
from .cli import parse_arguments
import sys

from typing import List


def main(argv=sys.argv):
    # type: (List[str]) -> None
    args = parse_arguments(argv)
    if args.debug:
        import pry

        with pry:
            return args.func(args)
    return args.func(args)
