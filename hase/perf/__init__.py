from __future__ import absolute_import, division, print_function

import os
import ctypes as ct
from typing import List, Any, Union

from .snapshot import Snapshot, TscConversion, CpuId

from .consts import PerfRecord


class CpuTrace(object):
    def __init__(self, idx, event_path, trace_path, start_time, start_pid,
                 start_tid):
        # type: (int, str, str, int, int, int) -> None
        self.idx = idx
        self.start_time = start_time
        self.start_pid = start_pid
        self.start_tid = start_tid
        self.event_path = event_path
        self.trace_path = trace_path


class Trace(object):
    def __init__(self, tsc_conversion, cpuid, sample_type, cpus):
        # type: (TscConversion, CpuId, int, List[CpuTrace]) -> None
        self.time_mult = tsc_conversion.time_mult
        self.time_shift = tsc_conversion.time_shift
        self.time_zero = tsc_conversion.time_zero

        self.cpu_family = cpuid.family
        self.cpu_model = cpuid.model
        self.cpu_stepping = cpuid.stepping
        self.cpuid_0x15_eax = cpuid.cpuid_0x15_eax
        self.cpuid_0x15_ebx = cpuid.cpuid_0x15_ebx

        self.sample_type = sample_type

        self.cpus = cpus


class Perf(object):
    def __init__(self, pid=-1):
        # type: (int) -> None
        self.snapshot = Snapshot(pid)  # type: Snapshot

    def __enter__(self):
        # type: () -> Perf
        return self

    def __exit__(self, type, value, traceback):
        # only cleanup unless the user has successfully stopped
        self.close()

    def write(self, directory):
        # type: (str) -> Trace
        self.snapshot.stop()

        cpus = []
        for i, cpu in enumerate(self.snapshot.cpus):
            event_path = os.path.join(directory,
                                      "cpu-%d.perf-events" % cpu.idx)
            count = 0
            with open(event_path, "wb") as event_file:
                for ev in cpu.events():
                    if ev.type == PerfRecord.PERF_RECORD_MMAP2:
                        if not ev.filename.startswith(
                                "/") or ev.filename == "//anon":
                            continue
                    event_file.write(bytearray(ev))
                    count += 1
            # if we don't have sideband events, we cannot decode the trace as well
            if count == 0:
                os.remove(event_path)
                continue
            trace_path = os.path.join(directory, "cpu-%d.trace" % cpu.idx)
            with open(trace_path, "wb") as trace_file:
                for trace in cpu.traces():
                    trace_file.write(trace)

            itrace = cpu.itrace_start_event()
            cpu_trace = CpuTrace(
                cpu.idx,
                event_path,
                trace_path,
                start_time=itrace.sample_id.time,
                start_pid=itrace.pid,
                start_tid=itrace.tid)
            cpus.append(cpu_trace)

        conversion = self.snapshot.tsc_conversion()
        cpuid = self.snapshot.cpuid()
        sample_type = self.snapshot.sample_type()
        return Trace(conversion, cpuid, sample_type, cpus)

    def close(self):
        # type: () -> None
        self.snapshot.close()


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
