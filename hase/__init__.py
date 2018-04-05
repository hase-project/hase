from hase.exceptions import *
from .app import parse_arguments
import sys


def main(argv=sys.argv):
    args = parse_arguments(argv)
    if args.debug:
        from . import pry
        with pry:
            return args.func(args)
    else:
            return args.func(args)
