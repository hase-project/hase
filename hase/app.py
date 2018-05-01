from __future__ import absolute_import, division, print_function

import argparse

from .record import record_command, DEFAULT_LOG_DIR

try:
    from typing import List
except ImportError:
    pass


def parse_arguments(argv):
    # List[str] -> argeparse.Namespace
    parser = argparse.ArgumentParser(
        prog=argv[0], description="process crashes")
    parser.add_argument(
        "--debug",
        action='store_true',
        help="jump into ipdb post mortem debugger")
    subparsers = parser.add_subparsers(
        title='subcommands',
        description='valid subcommands',
        help='additional help')

    # TODO, make angr working on coredumps
    record = subparsers.add_parser('record')
    record.set_defaults(func=record_command)
    record.add_argument(
        "--log-dir",
        default=str(DEFAULT_LOG_DIR),
        type=str,
        help="where to store crash reports")

    replay = subparsers.add_parser('replay')
    replay.add_argument("report-archive")

    def lazy_import_replay_command(args):
        from .replay import replay_command
        replay_command(args)

    replay.set_defaults(func=lazy_import_replay_command)
    return parser.parse_args(argv[1:])
