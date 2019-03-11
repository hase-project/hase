import os
from typing import Any, List, Union

from .consts import PerfRecord
from .snapshot import CpuId, Snapshot, TscConversion
import logging

l = logging.getLogger(__name__)


class CpuTrace:
    def __init__(
        self,
        idx: int,
        event_path: str,
        trace_path: str,
        start_time: int,
        start_pid: int,
        start_tid: int,
    ) -> None:
        self.idx = idx
        self.start_time = start_time
        self.start_pid = start_pid
        self.start_tid = start_tid
        self.event_path = event_path
        self.trace_path = trace_path


class Trace:
    def __init__(
        self,
        tsc_conversion: TscConversion,
        cpuid: CpuId,
        sample_type: int,
        cpus: List[CpuTrace],
    ) -> None:
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


class Perf:
    def __init__(self, pid: int = -1) -> None:
        self.snapshot = Snapshot(pid)

    def __enter__(self) -> "Perf":
        return self

    def __exit__(self, type: Any, value: Any, traceback: Any) -> bool:
        # only cleanup unless the user has successfully stopped
        self.close()
        return False

    def write(self, directory: str) -> Trace:
        self.snapshot.stop()

        cpus = []
        for i, cpu in enumerate(self.snapshot.cpus):
            event_path = os.path.join(directory, "cpu-%d.perf-events" % cpu.idx)
            count = 0
            with open(event_path, "wb") as event_file:
                for ev in cpu.events():
                    if ev.type == PerfRecord.PERF_RECORD_MMAP2:
                        if not ev.filename.startswith("/") or ev.filename == "//anon":
                            continue
                    event_file.write(bytearray(ev))
                    count += 1
            # if we don't have sideband events, we cannot decode the trace as well
            if count == 0:
                os.remove(event_path)
                continue
            trace_path = os.path.join(directory, "cpu-%d.trace" % cpu.idx)
            with open(trace_path, "wb") as trace_file:
                trace_file.write(cpu.traces())

            itrace = cpu.itrace_start_event()
            cpu_trace = CpuTrace(
                cpu.idx,
                event_path,
                trace_path,
                start_time=itrace.sample_id.time,
                start_pid=itrace.pid,
                start_tid=itrace.tid,
            )
            cpus.append(cpu_trace)

        if len(cpus) == 0:
            l.warning("No cpu traces were recorded")

        conversion = self.snapshot.tsc_conversion()
        cpuid = self.snapshot.cpuid()
        sample_type = self.snapshot.sample_type()
        return Trace(conversion, cpuid, sample_type, cpus)

    def close(self) -> None:
        self.snapshot.close()


class IncreasePerfBuffer:
    PATH = "/proc/sys/kernel/perf_event_mlock_kb"

    def __init__(self, size: int) -> None:
        self.new_size = size
        self.old_size = None  # type: Union[None, int]

    def update(self, value: int) -> None:
        with open(self.PATH, "w") as f:
            f.write(str(value))

    def __enter__(self) -> None:
        self.old_size = int(open(self.PATH).read())
        self.update(self.new_size)

    def __exit__(self, type: Any, value: Any, traceback: Any) -> bool:
        if self.old_size is not None:
            self.update(self.old_size)
        return False
