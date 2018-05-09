from __future__ import absolute_import, division, print_function

import subprocess
import os
from typing import List, Tuple, Any, Union, Callable

from .path import APP_ROOT

TRACE_END = -1


class PTSnapshot():
    def __init__(self, perf_file="perf.data", cmds=None):
        # type: (str) -> None

        cmd = [
            "perf",
            "record",
            "--no-buildid-cache",
            "--output",
            perf_file,
            "-m",
            "512,10000",
            "-a",
            "--snapshot",
            "-e",
            "intel_pt//u",
        ]

        if cmds:
            cmds_process = cmds
        else:
            cmds_process = [
                "sh", "-c", "echo ready; while true; do sleep 999999; done"
            ]
        self.perf_file = perf_file
        self.process = subprocess.Popen(
            cmd + cmds_process, stdout=subprocess.PIPE)
        line = self.process.stdout.readline().strip()
        assert line == "ready", "expected perf to return 'ready', got '%s'" % (
            line)

    def get(self):
        # type: () -> PerfData
        self.process.wait()
        return PerfData(self.perf_file)

    def __enter__(self):
        # type: () -> PTSnapshot
        return self

    def __exit__(self, type, value, traceback):
        # type: (Any, Any, Any) -> bool
        self.stop()
        return False

    def stop(self):
        # type: () -> None
        try:
            self.process.terminate()
        except OSError:
            pass

    @property
    def perf_pid(self):
        # type: () -> int
        return self.process.pid


class IncreasePerfBuffer():
    PATH = "/proc/sys/kernel/perf_event_mlock_kb"

    def __init__(self, size):
        # type: (int) -> None
        self.new_size = size
        self.old_size = None  # type: Union[None, int]

    def update(self, value):
        # type: (int) -> None
        with open(self.PATH, "w") as f:
            f.write(str(value))

    def __enter__(self):
        # type: () -> None
        self.old_size = int(open(self.PATH).read())
        self.update(self.new_size)

    def __exit__(self, type, value, traceback):
        # type: (Any, Any, Any) -> bool
        if self.old_size is not None:
            self.update(self.old_size)
        return False


def parse_row(row):
    # type: (str) -> Tuple[int, int]
    return (int(row[0], 16), int(row[1], 16))


class Branch():
    def __init__(self, ip, addr):
        # type: (int, int) -> None
        self.ip = ip
        self.addr = addr

    def trace_end(self):
        # () -> bool
        return self.ip == TRACE_END

    def __repr__(self):
        # () -> str
        if self.addr == 0:
            return "Branch(Start -> 0x%x)" % (self.ip)
        elif self.ip == TRACE_END:
            return "Branch(0x%x -> End)" % (self.addr)
        else:
            return "Branch(0x%x -> 0x%x)" % (self.addr, self.ip)

# current format:
#    .perf-wrapped 0 =>     7f478672bb57\n


def read_trace(perf_data, thread_id, command, executable_root=None):
    # type: (str, int, str, str) -> List[Branch]

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
    branches = []
    for line in cmd.stdout:
        columns = line.strip().split()

        branch = Branch(int(columns[0]), int(columns[1]))
        # skip syscalls until we support it in tracer

        if branch.addr == 0 or branch.ip == 0:
            continue
        branches.append(branch)

    # also append last instruction, if it was a syscall
    if branch.ip == 0:
        branch.ip = TRACE_END
        branches.append(branch)

    return branches


class PerfData():
    def __init__(self, path):
        # type: (str) -> None
        self.path = path

    def remove(self):
        # type: () -> None
        os.unlink(self.path)
