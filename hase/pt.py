import bisect
import ctypes as ct
import logging
from contextlib import contextmanager
from enum import IntEnum
from typing import Generator, List, Optional

from ._pt import ffi, lib
from .errors import PtError
from .loader import Loader
from .perf.consts import PerfRecord
from .perf.reader import perf_events
from .perf.tsc import TscConversion


class InstructionClass(IntEnum):
    # Needs to be in sync with:
    # https://github.com/01org/processor-trace/blob/0ff8b29b2fd2ebfcc47a747862e948e8b638a020/libipt/include/intel-pt.h.in#L1889
    # The instruction could not be classified.
    ptic_error = 0
    # The instruction is something not listed below.
    ptic_other = 1
    # The instruction is a near (function) call.
    ptic_call = 2
    # The instruction is a near (function) return.
    ptic_return = 3
    # The instruction is a near unconditional jump.
    ptic_jump = 4
    # The instruction is a near conditional jump.
    ptic_cond_jump = 5
    # The instruction is a call-like far transfer.
    # E.g. SYSCALL, SYSENTER, or FAR CALL.
    ptic_far_call = 6
    # The instruction is a return-like far transfer.
    # E.g. SYSRET, SYSEXIT, IRET, or FAR RET.
    ptic_far_return = 7
    # The instruction is a jump-like far transfer.
    # E.g. FAR JMP.
    ptic_far_jump = 8
    # The instruction is a PTWRITE.
    ptic_ptwrite = 9


class Instruction:
    __slots__ = ["ip", "size", "iclass"]

    def __init__(self, ip: int, size: int, iclass: InstructionClass) -> None:
        self.ip = ip
        self.size = size
        self.iclass = iclass

    def __repr__(self) -> str:
        return "<Instruction[%s] @ %x>" % (self.iclass.name, self.ip)


l = logging.getLogger(__name__)


class ScheduleEntry:
    def __init__(
        self, core: int, pid: int, tid: int, start: int, stop: Optional[int]
    ) -> None:
        self.core = core
        self.pid = pid
        self.tid = tid
        self.start = start
        # Can be none at the end of a trace
        self.stop = stop
        self.chunks = []  # type: List[Chunk]
        self.count = 1

    def is_main_thread(self) -> bool:
        """
        The initial process started.
        """
        return self.pid == self.tid

    def __lt__(self, other: "ScheduleEntry") -> bool:
        if self.start >= other.start:
            return False
        else:
            # make sure we do not overlap in schedule
            assert self.stop is not None and self.stop <= other.start
            return True

    def __repr__(self) -> str:
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


def copy_struct(struct: ct.Structure) -> ct.Structure:
    copy = struct.__class__()
    ct.memmove(ct.addressof(copy), ct.addressof(struct), ct.sizeof(struct))
    return copy


def get_thread_schedule(
    perf_event_paths: List[str], start_thread_ids: List[int], start_times: List[int]
) -> List[ScheduleEntry]:
    schedule = []  # type: List[ScheduleEntry]

    for (core, cpu_events) in enumerate(perf_event_paths):
        first_event = True
        schedule_in_event = None  # type: Optional[ct.Structure]

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
def sanity_check_order(instructions: List[Instruction], loader: Loader) -> None:
    """
    Check that calls matches returns and that syscalls and non-jumps do not change the control flow.
    """
    stack = []  # type: List[int]
    for (i, instruction) in enumerate(instructions):
        if i > 0:
            previous = instructions[i - 1]
            if previous.iclass == InstructionClass.ptic_return:
                if len(stack) != 0:
                    return_ip = stack.pop()
                    if return_ip != instruction.ip:
                        previous_loc = loader.find_location(instructions[i - 1].ip)
                        instruction_loc = loader.find_location(instruction.ip)
                        return_loc = loader.find_location(return_ip)
                        l.warning(
                            "unexpected call return {} from {} found: expected {}".format(
                                instruction_loc, previous_loc, return_loc
                            )
                        )
                        stack = []

        if instruction.iclass == InstructionClass.ptic_call:
            return_ip = instruction.ip + instruction.size
            stack.append(return_ip)


def merge_same_core_switches(schedule: List[ScheduleEntry]) -> List[ScheduleEntry]:
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


class Chunk:
    def __init__(self, start: int, stop: int, instructions: List[Instruction]) -> None:
        self.start = start
        self.stop = stop
        self.instructions = instructions

    def saw_tsc_update(self) -> bool:
        return self.start != self.stop

    def __repr__(self) -> str:
        return "<%s time: 0x%x..0x%x [%d instructions]>" % (
            self.__class__.__name__,
            self.start,
            self.stop,
            len(self.instructions),
        )


def correlate_traces(
    traces: List[List[Chunk]], schedule: List[ScheduleEntry], pid: int, tid: int
) -> List[Instruction]:
    schedule_per_core = []  # type: List[List[ScheduleEntry]]
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
                next_entry = per_core[idx + 1]  # type: Optional[ScheduleEntry]
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
                    "no instructions could be correlated with this event {} -> {} on {}?".format(
                        entry.start, entry.stop, entry.core
                    )
                )
        assert len(trace) == 0
    instructions = []

    for entry in schedule:
        for i, chunk in enumerate(entry.chunks):
            instructions.extend(chunk.instructions)

    assert len(instructions) == instruction_count
    return instructions


def _check_error(status: int) -> int:
    if status < 0 and status != -lib.pts_eos:
        msg = lib.decoder_get_error(status)
        raise PtError("decoding failed: %s" % ffi.string(msg).decode("utf-8"))
    return status


class Chunker:
    def __init__(self, decoder: ffi.CData, conversion: TscConversion) -> None:
        self._decoder = decoder
        self._conversion = conversion
        self._event = ffi.new("struct pt_event *")
        self._instruction = ffi.new("struct pt_insn *")
        self._status = 0

    def _events(self) -> Generator[ffi.CData, None, None]:
        while self._status & lib.pts_event_pending:
            self._status = _check_error(
                lib.decoder_next_event(self._decoder, self._event)
            )
            if self._status & lib.pts_eos:
                self._status = -lib.pts_eos
            yield self._event

    def _fetch_instruction(self) -> ffi.CData:
        self._status = _check_error(
            lib.decoder_next_instruction(self._decoder, self._instruction)
        )
        return self._instruction

    def _sync_forward(self) -> Generator[None, None, None]:
        self._status = _check_error(lib.decoder_sync_forward(self._decoder))
        if self._status != -lib.pts_eos:
            yield

    def _append_chunk(
        self,
        chunks: List[Chunk],
        enable_tsc: int,
        disable_tsc: int,
        instructions: List[Instruction],
    ) -> None:
        chunks.append(
            Chunk(
                self._conversion.tsc_to_perf_time(enable_tsc),
                self._conversion.tsc_to_perf_time(disable_tsc),
                instructions,
            )
        )

    def chunks(self) -> List[Chunk]:
        chunks = []  # type: List[Chunk]

        enable_tsc = None  # type: Optional[int]
        latest_tsc = None  # type: Optional[int]

        instructions = []  # type: List[Instruction]

        for _ in self._sync_forward():
            while self._status != lib.pts_eos:
                for event in self._events():
                    latest_tsc = event.tsc
                    if event.type == lib.ptev_enabled:
                        enable_tsc = event.tsc
                    elif (
                        event.type == lib.ptev_async_disabled
                        or event.type == lib.ptev_disabled
                    ):
                        if len(instructions) == 0:
                            enable_tsc = None
                            continue
                        assert enable_tsc and event.tsc
                        self._append_chunk(chunks, enable_tsc, event.tsc, instructions)
                        instructions = []
                        enable_tsc = None
                if self._status == -lib.pts_eos:
                    break

                pt_instr = self._fetch_instruction()
                if pt_instr.iclass != lib.ptic_error:
                    if enable_tsc is None:
                        enable_tsc = latest_tsc
                    instructions.append(
                        Instruction(
                            int(pt_instr.ip),
                            int(pt_instr.size),
                            InstructionClass(pt_instr.iclass),
                        )
                    )

        if len(instructions) != 0:
            assert enable_tsc is not None and latest_tsc is not None
            l.warning(
                "no final disable pt event found in stream, was the stream truncated?"
            )
            self._append_chunk(chunks, enable_tsc, latest_tsc, instructions)
        return chunks


@contextmanager
def decoder(decoder_config: ffi.CData) -> Generator[ffi.CData, None, None]:
    handle = ffi.new("struct decoder **")
    _check_error(lib.decoder_new(decoder_config, handle))
    try:
        yield handle[0]
    finally:
        lib.decoder_free(handle[0])


# TODO multiple threads
def decode(
    trace_paths: List[str],
    perf_event_paths: List[str],
    start_thread_ids: List[int],
    start_times: List[int],
    pid: int,
    tid: int,
    loader: Loader,
    cpu_family: int,
    cpu_model: int,
    cpu_stepping: int,
    cpuid_0x15_eax: int,
    cpuid_0x15_ebx: int,
    sample_type: int,
    time_zero: int,
    time_shift: int,
    time_mult: int,
) -> List[Instruction]:

    assert len(trace_paths) > 0

    traces = []  # type: List[List[Chunk]]

    decoder_config = ffi.new("struct decoder_config *")
    decoder_config.cpu_family = cpu_family
    decoder_config.cpu_model = cpu_model
    decoder_config.cpu_stepping = cpu_stepping
    decoder_config.cpuid_0x15_eax = cpuid_0x15_eax
    decoder_config.cpuid_0x15_ebx = cpuid_0x15_ebx
    decoder_config.shared_object_count = len(loader.shared_objects)
    shared_objects = []
    for i, m in enumerate(loader.shared_objects):
        page_size = 4096
        shared_object = (
            ffi.new("char[]", m.path.encode("utf-8")),
            m.page_offset * page_size,
            m.stop - m.start,
            m.start,
        )
        shared_objects.append(shared_object)
    shared_objects_array = ffi.new("struct decoder_shared_object[]", shared_objects)
    decoder_config.shared_objects = ffi.cast(
        "struct decoder_shared_object*", shared_objects_array
    )

    tsc_conversion = TscConversion(
        time_mult=time_mult, time_shift=time_shift, time_zero=time_zero
    )

    for (core, trace_path) in enumerate(trace_paths):
        c_trace_path = ffi.new("char[]", trace_path.encode("utf-8"))
        decoder_config.trace_path = c_trace_path
        with decoder(decoder_config) as d:
            c = Chunker(d, tsc_conversion)
            traces.append(c.chunks())

    schedule = get_thread_schedule(perf_event_paths, start_thread_ids, start_times)

    schedule = merge_same_core_switches(schedule)

    instructions = correlate_traces(traces, schedule, pid, tid)
    sanity_check_order(instructions, loader)
    return instructions
