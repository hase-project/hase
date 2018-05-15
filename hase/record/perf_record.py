from __future__ import absolute_import, division, print_function

import subprocess
import os
from typing import List, Optional, Union, Any

from .processor_trace import check_features
from ..exceptions import HaseException


def optional_args(flag, value):
    if flag:
        return value
    else:
        return []


class PTSnapshot(object):
    def __init__(self, perf_file="perf.data", command=None):
        # type: (str, Optional[List[str]]) -> None
        features = check_features()

        if not features.supported:
            raise HaseException(
                "Processor trace is not supported on your hardware or kernel")

        trace_all = optional_args(command is None, ["-a"])

        record_size = optional_args(features.large_record_buffer,
                                    ["-m", "512,10000"])
        perf_cmd = [
            "perf",
            "record",
            "--no-buildid",
            "--no-buildid-cache",
            "--snapshot",
            "-e",
            "intel_pt//u",
            "--output",
            perf_file,
        ] + record_size + trace_all

        if command is not None:
            perf_cmd += command
        else:
            perf_cmd += [
                "sh", "-c", "echo ready; while true; do sleep 999999; done"
            ]

        self.perf_file = perf_file
        self.process = subprocess.Popen(perf_cmd, stdout=subprocess.PIPE)

        if command is None and self.process.stdout:
            # check that perf is initialized
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


class IncreasePerfBuffer(object):
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


class PerfData(object):
    def __init__(self, path):
        # type: (str) -> None
        self.path = path

    def remove(self):
        # type: () -> None
        os.unlink(self.path)
