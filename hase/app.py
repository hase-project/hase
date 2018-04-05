import argparse
from .record import record_command
from .replay import replay_command


def parse_arguments(argv):
    parser = argparse.ArgumentParser(prog=argv[0], description="process crashes")
    parser.add_argument("--debug", action='store_true', help="jump into ipdb post mortem debugger")
    subparsers = parser.add_subparsers(
        title='subcommands',
        description='valid subcommands',
        help='additional help')

    # TODO, make angr working on coredumps
    record = subparsers.add_parser('record')
    record.add_argument("executable")
    record.add_argument("arguments", nargs="*", default=[])
    record.add_argument("--output", nargs="?", default="", help="output prefix [executable-yymmdd]")
    record.set_defaults(func=record_command)

    replay = subparsers.add_parser('replay')
    replay.add_argument("executable")
    replay.add_argument("trace", help="example proc-$date.tsv")
    replay.add_argument("coredump")
    replay.set_defaults(func=replay_command)
    return parser.parse_args(argv[1:])
