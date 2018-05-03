from __future__ import absolute_import, division, print_function
from .cli import parse_arguments
import sys


def main(argv=sys.argv):
    args = parse_arguments(argv)
    if args.debug:
        import pry
        with pry:
            return args.func(args)
    else:
            return args.func(args)
