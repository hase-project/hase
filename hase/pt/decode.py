from __future__ import absolute_import, division, print_function

import bisect
import ctypes as ct
import logging
from pathlib import Path
from typing import List, Optional, Union

from .. import _pt  # type: ignore
from ..perf.consts import PerfRecord
from ..perf.reader import perf_events
from ..pwn_wrapper import Mapping
from .events import (AsyncDisableEvent, DisableEvent, EnableEvent, Instruction,
                     InstructionClass, TraceEvent)

l = logging.getLogger(__name__)


class ScheduleEntry(object):
    def __init__(self, core, pid, tid, start, stop):
        # type: (int, int, int, int, Optional[int]) -> None
        self.core = core
        self.pid = pid
        self.tid = tid
        self.start = start
        # Can be none at the end of a trace
        self.stop = stop
        self.chunks: List[Chunk] = []
        self.count = 1

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
        return "<%s core#%d time: %s..%s>" % (
            self.__class__.__name__,
            self.core,
            start,
            stop,
        )


def copy_struct(struct):
    # type: (ct.Structure) -> ct.Structure
    copy = struct.__class__()
    ct.memmove(ct.addressof(copy), ct.addressof(struct), ct.sizeof(struct))
    return copy


def get_thread_schedule(perf_event_paths, start_thread_ids, start_times):
    # type: (List[str], List[int], List[int]) -> List[ScheduleEntry]
    schedule: List[ScheduleEntry] = []

    for (core, cpu_events) in enumerate(perf_event_paths):
        first_event = True
        schedule_in_event: Optional[ct.Structure] = None

        for ev in perf_events(cpu_events):
            if ev.type != PerfRecord.PERF_RECORD_SWITCH:
                pass

            if ev.is_switch_out():
                if first_event:
                    assert (
                        start_thread_ids[core] == ev.tid
                    ), "the thread from pt does not match with the thread de-scheduled by the OS"
                    start_time = start_times[core]
                else:
                    assert (
                        schedule_in_event
                    ), "we saw two continuous schedule-out events"
                    assert (
                        schedule_in_event.sample_id.tid == ev.sample_id.tid
                    ), "thread id of schedule-in does not match schedule-out"
                    start_time = schedule_in_event.sample_id.time

                end_time = ev.sample_id.time

                entry = ScheduleEntry(
                    core, ev.sample_id.pid, ev.sample_id.tid, start_time, end_time
                )
                bisect.insort(schedule, entry)
                schedule_in_event = None
            else:
                assert (
                    schedule_in_event is None or first_event
                ), "we saw a two schedule-in events without a schedule-out event"
                # we use schedule_in_event beyond the MMAP allocation of `perf_events()`
                schedule_in_event = copy_struct(ev)

            first_event = False

        if schedule_in_event is not None:
            sample_id = schedule_in_event.sample_id
            bisect.insort(
                schedule,
                ScheduleEntry(core, sample_id.pid, sample_id.tid, sample_id.time, None),
            )
            schedule_in_event = None

    return schedule


# In future this should become a warning, since bugs can smash the stack! For
# now we rely on this to figure out if we re-assemble the trace incorrectly
def sanity_check_order(instructions):
    # type: (List[Instruction]) -> None
    """
    Check that calls matches returns and that syscalls and non-jumps do not change the control flow.
    """
    stack: List[int] = []
    for (i, instruction) in enumerate(instructions):
        if i > 0:
            previous = instructions[i - 1]
            if previous.iclass == InstructionClass.ptic_return:
                if len(stack) != 0:
                    return_ip = stack.pop()
                    assert return_ip == instruction.ip
            elif previous.iclass in (
                InstructionClass.ptic_far_call,
                InstructionClass.ptic_other,
            ):
                assert instruction.ip == previous.ip + previous.size

        if instruction.iclass == InstructionClass.ptic_call:
            return_ip = instruction.ip + instruction.size
            stack.append(return_ip)


def correlate_traces(traces, schedule, pid, tid):
    # type: (List[List[Chunk]], List[ScheduleEntry], int, int) -> List[Instruction]

    schedule_per_core: List[List[ScheduleEntry]] = []
    for _ in range(len(traces)):
        schedule_per_core.append([])

    for entry in schedule:
        schedule_per_core[entry.core].append(entry)

    instruction_count = 0
    for (core, trace) in enumerate(traces):
        for chunk in trace:
            instruction_count += len(chunk.instructions)

    for (core, trace) in enumerate(traces):
        if len(trace) == 0:
            continue
        per_core = schedule_per_core[core]

        for (idx, entry) in enumerate(per_core):
            if (idx + 1) < len(per_core):
                next_entry: Optional[ScheduleEntry] = per_core[idx + 1]
            else:
                next_entry = None

            i = 0
            for chunk in trace:
                # TODO: timer is not accurate between kernel and hardware?
                if (
                    entry.stop is None
                    or next_entry is None
                    or abs(chunk.stop - entry.stop) < abs(chunk.stop - next_entry.start)
                ):

                    entry.chunks.append(chunk)
                    i += 1
                else:
                    break
            trace = trace[i:]

            if len(entry.chunks) == 0:
                l.warning(
                    f"no instructions could be correlated with this event {entry.start} -> {entry.stop} on {entry.core}?"
                )
        assert len(trace) == 0
    instructions = []

    for entry in schedule:
        for i, chunk in enumerate(entry.chunks):
            instructions.extend(chunk.instructions)

    assert len(instructions) == instruction_count
    return instructions


def merge_same_core_switches(schedule):
    # type: (List[ScheduleEntry]) -> List[ScheduleEntry]
    if len(schedule) == 0:
        return []

    new_schedule = [schedule[0]]

    for (i, entry) in enumerate(schedule[1:]):
        if new_schedule[-1].core == entry.core and new_schedule[-1].tid == entry.tid:
            new_schedule[-1].stop = entry.stop
            new_schedule[-1].count += 1
        else:
            new_schedule.append(entry)

    return new_schedule


class Chunk(object):
    def __init__(self, start, stop, instructions):
        # type: (int, int, List[Instruction]) -> None
        self.start = start
        self.stop = stop
        self.instructions = instructions

    def saw_tsc_update(self):
        # type: () -> bool
        return self.start != self.stop

    def __repr__(self):
        # type: () -> str
        return "<%s time: 0x%x..0x%x [%d instructions]>" % (
            self.__class__.__name__,
            self.start,
            self.stop,
            len(self.instructions),
        )


# def is_context_switch(event, instruction):
#    # type: (TraceEvent, Instruction) -> bool
#    if isinstance(event, DisableEvent) and \
#            instruction.iclass == InstructionClass.ptic_far_call:
#        # syscall
#        return event.ip != (instruction.ip + instruction.size)
#    elif instruction.iclass == InstructionClass.ptic_other:
#        if not isinstance(event, AsyncDisableEvent):
#            import pdb; pdb.set_trace()
#        assert isinstance(event, AsyncDisableEvent)
#        return instruction.ip != event.ip
#    return False


def chunk_trace(core: int, trace: List[Union[TraceEvent, Instruction]]) -> List[Chunk]:
    chunks: List[Chunk] = []

    enable_event = None
    # switch_detected = False
    instructions: List[Instruction] = []
    for (idx, ev) in enumerate(trace):
        if isinstance(ev, TraceEvent):
            latest_time = ev.time
            if isinstance(ev, EnableEvent):
                enable_event = ev
                # switch_detected = False
            elif isinstance(ev, DisableEvent) or isinstance(ev, AsyncDisableEvent):
                assert enable_event is not None

                if len(instructions) == 0:
                    enable_event = None
                    # switch_detected = False
                    continue

                # if len(chunks) != 0:
                #    last_instruction = chunks[-1].instructions[-1]
                #    switch_detected = is_context_switch(ev, last_instruction)

                assert enable_event.time and ev.time
                for instruction in instructions:
                    instruction.core = core
                    instruction.chunk = idx

                # chunk = Chunk(enable_event.time, ev.time, switch_detected,
                #              instructions)
                chunk = Chunk(enable_event.time, ev.time, instructions)
                chunks.append(chunk)
                instructions = []
                enable_event = None
        else:
            assert enable_event is not None
            latest_time = enable_event.time
            instructions.append(ev)

    if len(instructions) != 0:
        assert (
            enable_event is not None
            and enable_event.time is not None
            and latest_time is not None
        )
        l.warning(
            "no final disable pt event found in stream, was the stream truncated?"
        )
        chunk = Chunk(enable_event.time, latest_time, instructions)
        chunks.append(chunk)

    return chunks


# TODO multiple threads
def decode(
    trace_paths: List[str],
    perf_event_paths: List[str],
    start_thread_ids: List[int],
    start_times: List[int],
    pid: int,
    tid: int,
    mappings: List[Mapping],
    cpu_family: int,
    cpu_model: int,
    cpu_stepping: int,
    cpuid_0x15_eax: int,
    cpuid_0x15_ebx: int,
    sample_type: int,
    time_zero: int,
    time_shift: int,
    time_mult: int,
    sysroot: str,
    vdso_x64: str,
) -> List[Instruction]:

    assert len(trace_paths) > 0

    traces: List[List[Chunk]] = []
    raw_trace = []

    shared_objects = []

    root = Path(sysroot)

    for m in mappings:
        if m.path.startswith("/"):
            path = str(root.joinpath(m.path[1:]))
            page_size = 4096
            shared_objects.append(
                (path, m.page_offset * page_size, m.stop - m.start, m.start)
            )

    for (core, trace_path) in enumerate(trace_paths):
        trace = _pt.decode(
            trace_path=trace_path,
            cpu_family=cpu_family,
            cpu_model=cpu_model,
            cpu_stepping=cpu_stepping,
            cpuid_0x15_eax=cpuid_0x15_eax,
            cpuid_0x15_ebx=cpuid_0x15_ebx,
            time_zero=time_zero,
            time_mult=time_mult,
            time_shift=time_shift,
            shared_objects=shared_objects,
        )
        raw_trace.append(trace)
        traces.append(chunk_trace(core, trace))

    schedule = get_thread_schedule(perf_event_paths, start_thread_ids, start_times)

    schedule = merge_same_core_switches(schedule)

    instructions = correlate_traces(traces, schedule, pid, tid)
    sanity_check_order(instructions)
    return instructions
