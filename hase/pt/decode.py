from __future__ import absolute_import, division, print_function

import ctypes as ct
import os
from io import BytesIO
from tempfile import NamedTemporaryFile
from typing import List, Union, Any
import shutil
import bisect

from ..pwn_wrapper import Mapping, ELF
from .. import _pt  # type: ignore
from ..path import Path
from .events import *
from ..perf.reader import perf_events
from ..perf.consts import PerfRecord


class ScheduleEntry(object):
    def __init__(self, core, pid, tid, start, stop):
        # type: (int, int, int, int, Optional[int]) -> None
        self.core = core
        self.pid = pid
        self.tid = tid
        self.start = start
        # Can be none at the end of a trace
        self.stop = stop

    def is_main_thread(self):
        # type: () -> bool
        """
        The initial process started.
        """
        return self.pid == self.tid

    def __lt__(self, other):
        # type: (ScheduleEntry) -> bool
        if self.start >= other.start:
            return False
        else:
            # make sure we do not overlap in schedule
            assert self.stop is not None and self.stop <= other.start
            return True

    def __repr__(self):
        # type: () -> str
        start = "%x" % self.start
        if self.stop is None:
            stop = ""
        else:
            stop = "%x" % self.stop
        return '<%s core#%d time: %s..%s' % (self.__class__.__name__,
                                             self.core, start, stop)

def copy_struct(struct):
    # type: (ct.Structure) -> ct.Structure
    copy = struct.__class__()
    ct.memmove(
        ct.addressof(copy), ct.addressof(struct),
        ct.sizeof(struct))
    return copy


def get_thread_schedule(perf_event_paths, start_thread_ids, start_times):
    # type: (List[str], List[int], List[int]) -> List[ScheduleEntry]
    schedule = []  # type: List[ScheduleEntry]

    for (core, cpu_events) in enumerate(perf_event_paths):
        first_event = True
        schedule_in_event = None  # type: Optional[ct.Structure]

        for ev in perf_events(cpu_events):
            if ev.type != PerfRecord.PERF_RECORD_SWITCH:
                pass

            if ev.is_switch_out():
                if first_event:
                    assert start_thread_ids[core] == ev.tid, \
                            "the thread from pt does not match with the thread de-scheduled by the OS"
                    start_time = start_times[core]
                else:
                    assert schedule_in_event, "we saw two continuous schedule-out events"
                    assert schedule_in_event.sample_id.tid == ev.sample_id.tid, \
                            "thread id of schedule-in does not match schedule-out"
                    start_time = schedule_in_event.sample_id.time

                end_time = ev.sample_id.time
                entry = ScheduleEntry(core, ev.sample_id.pid, ev.sample_id.tid,
                                      start_time, end_time)
                bisect.insort(schedule, entry)
                schedule_in_event = None
            else:
                assert schedule_in_event is None or first_event, \
                        "we saw a two schedule-in events without a schedule-out event"
                # we use schedule_in_event beyond the MMAP allocation of `perf_events()`
                schedule_in_event = copy_struct(ev)

            first_event = False

        if schedule_in_event is not None:
            sample_id = schedule_in_event.sample_id
            bisect.insort(schedule,
                          ScheduleEntry(core, sample_id.pid, sample_id.tid,
                                        sample_id.time, None))
            schedule_in_event = None

    return schedule

def dataframe(traces):
    # List[List[Union[TraceEvent, Instruction]]] -> Any
    import pandas as pd
    from collections import defaultdict

    data = defaultdict(list)

    for (i, trace) in traces:
        for ev in trace:
            data["core"].append(i)
            if isinstance(ev, Instruction):
                data["ip"].append(ev.ip)
                data["size"].append(ev.size)
                data["time"].append(None)
            else:
                data["ip"].append(None)
                data["size"].append(None)
                data["time"].append(ev.time)

    import pdb; pdb.set_trace()
    return pd.DataFrame(data)

def correlate_traces(_traces, schedule, pid, tid):
    # type: (List[List[Union[TraceEvent, Instruction]]], List[ScheduleEntry], int, int) -> List[Instruction]
    instructions = []

    # make a copy so we do not assign new slides in the original
    traces = _traces[:]

    n_instructions = 0
    for core in traces:
        for instr in core:
            if isinstance(instr, Instruction):
                n_instructions += 1

    for (i, entry) in enumerate(schedule):
        assert pid == entry.pid
        trace = traces[entry.core]
        for (j, event) in enumerate(trace):
            if isinstance(event, TraceEvent):
                assert event.time is not None
                if entry.stop is not None and event.time > entry.stop:
                    traces[entry.core] = trace[j:]
                    break
            else:
                instructions.append(event)
        if j == len(trace) - 1:
            traces[entry.core] = []

    #if n_instructions != len(instructions):
    #    import pdb; pdb.set_trace()
    assert n_instructions == len(instructions)

    return instructions


# TODO multiple threads
def decode(
        trace_paths,  # type: List[str]
        perf_event_paths,  # type: List[str]
        start_thread_ids,  # type: List[int]
        start_times,  # type: List[int]
        pid,  # type: int
        tid,  # type: int
        mappings,  # type: List[Mapping]
        cpu_family,  # type: int
        cpu_model,  # type: int
        cpu_stepping,  # type: int
        cpuid_0x15_eax,  # type: int
        cpuid_0x15_ebx,  # type: int
        sample_type,  # type: int
        time_zero,  # type: int
        time_shift,  # type: int
        time_mult,  # type: int
        sysroot,  # type: str
        vdso_x64  # type: str
):
    # type: (...) -> List[Instruction]

    assert len(trace_paths) > 0

    traces = []  # type: List[List[Union[TraceEvent, Instruction]]]

    shared_objects = []

    root = Path(sysroot)

    for m in mappings:
        if m.path.startswith("/"):
            path = str(root.join(m.path[1:]))
            page_size = 4096
            shared_objects.append((path, m.page_offset * page_size,
                                   m.stop - m.start, m.start))

    for trace_path in trace_paths:
        traces.append(
            _pt.decode(
                trace_path=trace_path,
                cpu_family=cpu_family,
                cpu_model=cpu_model,
                cpu_stepping=cpu_stepping,
                cpuid_0x15_eax=cpuid_0x15_eax,
                cpuid_0x15_ebx=cpuid_0x15_ebx,
                time_zero=time_zero,
                time_mult=time_mult,
                time_shift=time_shift,
                shared_objects=shared_objects))

    schedule = get_thread_schedule(perf_event_paths, start_thread_ids,
                                   start_times)

    import pdb; pdb.set_trace()
    return correlate_traces(traces, schedule, pid, tid)
