from __future__ import absolute_import, division, print_function

import csv
import subprocess
import sys
import os

try:
    from typing import List, Tuple, Any, Union
except ImportError:
    pass

TRACE_END = -1


def perf_command(build_id_dir):
    # type: (str) -> List[str]
    return ["perf"]


class PTSnapshot():
    def __init__(self, perf_file="perf.data", build_id_path="~/.debug"):
        # type: (str, str) -> None
        
        self.perf_command = perf_command(os.path.expanduser(build_id_path))
        cmd = self.perf_command + [
            "record", "--no-buildid-cache", "--output",
            perf_file, "-m", "512,100000", "-a", "--snapshot", "-e",
            "intel_pt//u"
        ]
        self.perf_file = perf_file
        self.process = subprocess.Popen(cmd)

    def get(self):
        # type: () -> PerfData
        self.process.wait()
        return PerfData(self.perf_file, self.perf_command)

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
        return True


def parse_row(row):
    # type: (str) -> Tuple[int, int]
    return (int(row[0], 16), int(row[1], 16))


def read_trace(sample_path, loader):
    with open(sample_path) as f:
        reader = csv.reader(f, delimiter='\t')
        branches = []

        # record the entrypoint
        try:
            line = next(reader)
            branches.append(parse_row(line))
        except StopIteration:
            return

        for row in reader:
            (address, ip) = parse_row(row)
            # skip syscalls until we support it in tracer
            if address == 0 or ip == 0:
                continue
            branches.append((address, ip))
    # also append last instruction, if it was a syscall
    if ip == 0:
        branches.append((address, TRACE_END))
    return branches


class PerfData():
    def __init__(self, path, perf_command):
        # type: (str, List[str]) -> None
        self.path = path
        self.perf_command = perf_command

    def get_build_ids(self):
        # type: () -> List[str]
        cmd = self.perf_command + ["buildid-list", "-i", self.path, "--with-hits"]
        output = subprocess.check_output(cmd)
        libs = []
        for line in output.split("\n"):
            columns = line.split(" ", 1)
            if len(columns) < 2:
                continue

            build_id, shared_object = columns
            if not shared_object.startswith("/"):
                # ignore kernel modules for the moment
                continue

            if os.access(shared_object, os.R_OK):
                libs.append(build_id)
        return libs

    def remove(self):
        # type: () -> None
        os.unlink(self.path)


def dump_trace(perf_data, tsv_path):
    # type: (str, str) -> None
    args = [
        "perf", "script",
        "--input=%s" % perf_data, "--itrace=b", "--fields", "ip,addr"
    ]
    cmd = subprocess.Popen(args, stdout=subprocess.PIPE)
    with open(tsv_path, "w") as tsv_file:
        tsv_writer = csv.writer(tsv_file, delimiter='\t')
        for line in cmd.stdout:
            address = line.split()[0]
            ip = line.split()[2]
            tsv_writer.writerow((address, ip))


if __name__ == '__main__':
    sample_file = sys.argv[1] if len(sys.argv) > 1 else "perf.data"
    dump_trace(sample_file, "trace.tsv")
