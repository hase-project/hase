from __future__ import absolute_import, division, print_function

import os
import sys
import shutil
import errno
import json
import datetime
from collections import OrderedDict, defaultdict
from typing import List, Any, IO, DefaultDict, Dict

from . import timestamp

RECV_MESSAGE = "GOT COREDUMP"

EXTRA_CORE_DUMP_PARAMETER = OrderedDict([
    ("executable", "%E"),  # path of executable
    ("uid", "%u"),  # user id
    ("gid", "%g"),  # group id
    ("containerized_tid", "%i"),  # thread id in process's PID namespace
    ("global_tid", "%I"),  # thread id in global PID namespace
    ("containerized_pid", "%p"),  # process id in process's PID namespace
    ("global_pid", "%P"),  # process id in global PID namespace
    ("signal", "%s"),  # signal causing dump
    ("time", "%t"),  # time of core dump
])


def process_coredump(os_args, core_file, manifest_file):
    # type: (List[str], IO[Any], IO[Any]) -> None
    shutil.copyfileobj(sys.stdin, core_file)

    metadata = defaultdict(dict)  # type: DefaultDict[str, Any]
    coredump = metadata["coredump"]

    for name, arg in zip(EXTRA_CORE_DUMP_PARAMETER.keys(), os_args):
        if name == "executable":
            # strip trailing slash and unescape
            coredump[name] = arg[1:].replace("!", "/")
        elif name == "time":
            coredump[name] = timestamp.from_unix_time(int(arg))
        else:
            coredump[name] = int(arg)
    json.dump(metadata, manifest_file, indent=4, sort_keys=True)


def creat(path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    return os.fdopen(os.open(path, flags), "w")


def main(args):
    # type: (List[str]) -> None
    nargs = 1  # argv[0]
    nargs += len(EXTRA_CORE_DUMP_PARAMETER)
    nargs += 3  # arguments from our self
    msg = "Expected %d arguments, got %d: %s" % (nargs, len(sys.argv),
                                                 sys.argv)
    assert len(sys.argv) == nargs, msg

    fifo_path = args[1]
    core_dump_path = args[2]
    manifest_path = args[3]

    write_response = True
    try:
        with creat(manifest_path) as manifest_file, \
                creat(core_dump_path) as core_file:
            process_coredump(args[4:], core_file, manifest_file)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
        # a second exception was thrown while we are still busy collecting the
        # current one, ignore this one
        msg = "%s already exists, this means another coredump was generated while we are processing the first one!"
        print(msg % core_dump_path, file=sys.stderr)
        write_response = False
    finally:
        if write_response:
            with open(fifo_path, "w") as f:
                f.write(RECV_MESSAGE)


if __name__ == "__main__":
    print(sys.argv)
    main(sys.argv)
