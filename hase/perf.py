from __future__ import absolute_import, division, print_function

import subprocess
import os
from typing import List, Tuple, Any, Union, Callable, Optional

from .path import APP_ROOT


def parse_row(row):
    # type: (str) -> Tuple[int, int]
    return (int(row[0], 16), int(row[1], 16))


class Branch(object):
    def __init__(self, ip, addr):
        # type: (int, int) -> None
        self.ip = ip
        self.addr = addr

    def trace_end(self):
        # () -> bool
        return self is LastBranch

    def __repr__(self):
        # () -> str
        if self.addr == 0:
            return "Branch(Start -> 0x%x)" % (self.ip)
        else:
            return "Branch(0x%x -> 0x%x)" % (self.addr, self.ip)


class LastBranch(Branch):
    def __init__(self, branch):
        # type: (Branch) -> None
        self.ip = branch.ip
        self.addr = branch.addr


# current format:
#    .perf-wrapped 0 =>     7f478672bb57\n


def read_trace(perf_data, thread_id, command, executable_root=None):
    # type: (str, int, str, Optional[str]) -> List[Branch]

    args = [
        "perf", "script",
        "--input=%s" % perf_data, "--tid",
        str(thread_id), "--itrace=b", "--fields", "comm,ip,addr", "-s",
        str(APP_ROOT.join("perf_script.py")), command
    ]

    if executable_root is not None:
        args.append("--symfs")
        args.append(executable_root)
    cmd = subprocess.Popen(args, stdout=subprocess.PIPE)
    branches = []  # type: List[Branch]

    assert cmd.stdout is not None
    for line in cmd.stdout:
        columns = line.strip().split()

        branch = Branch(int(columns[0]), int(columns[1]))
        # skip syscalls until we support it in tracer

        if (branch.addr == 0 or branch.ip == 0) and len(branches) != 0:
            continue
        branches.append(branch)

    # also append last instruction, if it was a syscall
    if branch.ip == 0:
        branches.append(LastBranch(branch))

    return branches
