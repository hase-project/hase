from __future__ import absolute_import, division, print_function

import sys
from typing import Any, List

from .cli import parse_arguments


def main(argv: List[str] = sys.argv) -> Any:
    args = parse_arguments(argv)
    if args.debug:
        import pry

        with pry:
            return args.func(args)
    return args.func(args)
