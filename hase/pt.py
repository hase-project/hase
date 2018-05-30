from __future__ import absolute_import, division, print_function

import ctypes as ct
import os
import mmap
from io import BytesIO
from typing import List, Tuple
from tempfile import NamedTemporaryFile
import shutil

from .perf.consts import (perf_event_header, PerfRecord, RecordMisc, Libc)
from .perf.snapshot import EVENTS
from .pwn_wrapper import Mapping, ELF
from . import _pt  # type: ignore
from .instruction import Instruction
from .mmap import MMap


def string_size(path):
    return ((len(path) + 1 + 7) & ~7)


def comm_event(tid, command):
    # type: (int, str) -> bytearray
    event_type = EVENTS[PerfRecord.PERF_RECORD_COMM]
    base_size = ct.sizeof(event_type(-1))
    size = base_size + string_size(command)
    event = event_type(size)()
    event.size = size
    # by setting this to zero, it should be applied immediately
    event.type = PerfRecord.PERF_RECORD_COMM
    event.misc = RecordMisc.PERF_RECORD_MISC_COMM_EXEC
    event.sample_id.time = 0
    event.sample_id.pid = tid
    event.sample_id.tid = tid
    event.pid = tid
    event.tid = tid
    event.comm = command
    return bytearray(event)


def switch_event(tid):
    # type: (int) -> bytearray
    event_type = EVENTS[PerfRecord.PERF_RECORD_SWITCH]
    event = event_type(-1)()
    event.size = ct.sizeof(event)
    # by setting this to zero, it should be applied immediately
    event.type = PerfRecord.PERF_RECORD_SWITCH
    event.misc = 0
    event.sample_id.time = 0
    event.sample_id.pid = tid
    event.sample_id.tid = tid
    return bytearray(event)


def mmap2_event(tid, path, start, stop, page_offset):
    # type: (int, str, int, int, int) -> bytearray
    event_type = EVENTS[PerfRecord.PERF_RECORD_MMAP2]
    base_size = ct.sizeof(event_type(-1))
    size = base_size + string_size(path)
    event = event_type(size)()
    event.size = size
    event.type = PerfRecord.PERF_RECORD_MMAP2
    # by setting this to zero, it should be applied immediately
    event.sample_id.time = 0
    event.sample_id.pid = tid
    event.sample_id.tid = tid
    event.pid = tid
    event.tid = tid
    event.addr = start
    event.filename = path
    event.pgoff = page_offset
    event.len = stop - start
    #event.misc = RecordMisc.PERF_RECORD_MISC_KERNEL
    # Unused by decoder library at the moment
    event.maj = 0
    event.min = 0
    event.ino = 0
    event.ino_generation = 0
    event.prot = 0
    event.flags = 0
    assert len(event.filename) > 0
    return bytearray(event)


class TracePostProcessor(object):
    """
    We modify the trace so that our thread appears to be a single-threaded
    process, so we can distinguish it using the processor trace library. We also
    prepend mmap events for in one trace, for all mappings we see in the
    coredump but not in our traces.
    """

    def __init__(self, final_mappings, exec_wrapper, pid, tid):
        # type: (List[Mapping], str, int, int) -> None
        self.remaining_mappings = final_mappings[:]
        self.exec_wrapper = exec_wrapper
        self.pid = pid
        self.tid = tid

    def apply(self, event):
        # type: (ct.Structure) -> ct.Structure
        if event.type == PerfRecord.PERF_RECORD_MMAP or \
                event.type == PerfRecord.PERF_RECORD_MMAP2:
            if event.sample_id.pid != self.pid:
                return event
            for idx, m in enumerate(self.remaining_mappings):
                if m.path == event.filename and \
                        m.start == event.addr:
                    del self.remaining_mappings[idx]
                    break
            # Rewrite all mmap events to match our thread context. Since
            # threads are globally unique on Linux, we will not collide with
            # other threads.
            event.sample_id.pid = self.tid
        elif event.sample_id.pid == self.pid:
            # For all other events we pretend them to be processes.
            event.sample_id.pid = event.sample_id.tid
        return event

    def events_for_exec_wrapper(self):
        # type: () -> str
        """
        Prepend memory events for execution wrapper that is executed before the exec
        """
        elf = ELF(self.exec_wrapper)
        assert elf.statically_linked
        address = 0
        buf = BytesIO()
        buf.write(switch_event(self.tid))
        buf.write(comm_event(self.tid, self.exec_wrapper))
        for seg in elf.iter_segments_by_type('PT_LOAD'):
            h = seg.header
            buf.write(
                mmap2_event(self.tid, self.exec_wrapper, h.p_vaddr,
                            h.p_vaddr + h.p_memsz, h.p_offset))
        return buf.getvalue()

    def mmap_events_from_coredump(self):
        # type: () -> str
        """
        Synthesize mmap events for executables/libraries that we have not seen in the traces, but in the coredump.
        """
        buf = BytesIO()
        for i, m in enumerate(self.remaining_mappings):
            if not m.path != '':
                continue
            buf.write(
                mmap2_event(self.tid, m.path, m.start, m.stop, m.page_offset))
        return buf.getvalue()

    def rewrite(self, event_path):
        # type: (str) -> None
        with open(event_path, "ab+") as f:
            fd = f.fileno()
            size = os.fstat(fd).st_size

            with MMap(fd, size, mmap.PROT_WRITE | mmap.PROT_READ,
                      mmap.MAP_SHARED) as mm:
                header_size = ct.sizeof(perf_event_header)
                i = 0
                while i != size:
                    assert (size - i) >= header_size
                    ev = perf_event_header.from_address(mm.addr + i)
                    struct_factory = EVENTS.get(ev.type)
                    if struct_factory is None:
                        raise Exception("unexpeced perf_event type: %d",
                                        ev.type)
                    struct_type = struct_factory(ev.size)
                    struct_size = ct.sizeof(struct_type)
                    assert (size - i) >= struct_size
                    struct = struct_type.from_address(mm.addr + i)
                    self.apply(struct)
                    i += ev.size


def decode(
        trace_per_cpu,  # type: List[Tuple[str, str]]
        exec_wrapper,  # type: str
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
    processor = TracePostProcessor(mappings, exec_wrapper[len(sysroot):], pid,
                                   tid)

    assert len(trace_per_cpu) > 0

    for i, cpu in enumerate(trace_per_cpu):
        processor.rewrite(cpu[0])

    def switch_callback(this_pid):
        if this_pid == pid:
            print("decoding starts")

    for (idx, cpu) in enumerate(trace_per_cpu):
        with NamedTemporaryFile() as extended_trace:
            extended_trace.write(processor.events_for_exec_wrapper())
            #extended_trace.write(processor.mmap_events_from_coredump())

            with open(trace_per_cpu[0][0], "rb") as f:
                shutil.copyfileobj(f, extended_trace)

            extended_trace.flush()
            perf_events_per_cpu = []
            perf_events_per_cpu.append(extended_trace.name)

            for (other_idx, other_cpu) in enumerate(trace_per_cpu):
                if other_idx != idx:
                    perf_events_per_cpu.append(other_cpu[0])
            try:
                print("""ptxed  \\
  --pevent:sample-type {sample_type} \\
  --pevent:sysroot trace/binaries \\
  --pevent:time-zero {time_zero} \\
  --pevent:time-shift {time_shift} \\
  --pevent:time-mult {time_mult} \\
  --cpu {cpu_family}/{cpu_model}/{cpu_stepping} \\
  --cpuid-0x15.eax {cpuid_0x15_eax} \\
  --cpuid-0x15.ebx {cpuid_0x15_ebx} \\
  --pevent:vdso-x64 trace/vdso \\
  --pevent:primary {primary} \\
  --pevent:secondary trace/cpu-0.perf-events \\
  --pevent:secondary trace/cpu-1.perf-events \\
  --pevent:secondary trace/cpu-3.perf-events \\
  --pt {trace}""".format(
                    sample_type=sample_type,
                    time_zero=time_zero,
                    time_shift=time_shift,
                    time_mult=time_mult,
                    cpuid_0x15_eax=cpuid_0x15_eax,
                    cpuid_0x15_ebx=cpuid_0x15_ebx,
                    cpu_family=cpu_family,
                    cpu_model=cpu_model,
                    cpu_stepping=cpu_stepping,
                    trace=cpu[1],
                    primary=perf_events_per_cpu[0]))

                print(
                    dict(
                        switch_callback=switch_callback,
                        trace_filename=cpu[1],
                        cpu_family=cpu_family,
                        cpu_model=cpu_model,
                        cpu_stepping=cpu_stepping,
                        cpuid_0x15_eax=cpuid_0x15_eax,
                        cpuid_0x15_ebx=cpuid_0x15_ebx,
                        sample_type=sample_type,
                        time_zero=time_zero,
                        time_shift=time_shift,
                        time_mult=time_mult,
                        sysroot=sysroot + "/",
                        vdso_x64=vdso_x64,
                        perf_events_per_cpu=perf_events_per_cpu))

                res = _pt.decode(
                    switch_callback=switch_callback,
                    trace_filename=cpu[1],
                    cpu_family=cpu_family,
                    cpu_model=cpu_model,
                    cpu_stepping=cpu_stepping,
                    cpuid_0x15_eax=cpuid_0x15_eax,
                    cpuid_0x15_ebx=cpuid_0x15_ebx,
                    sample_type=sample_type,
                    time_zero=time_zero,
                    time_shift=time_shift,
                    time_mult=time_mult,
                    sysroot=sysroot + "/",
                    vdso_x64=vdso_x64,
                    perf_events_per_cpu=perf_events_per_cpu)
                import pdb
                pdb.set_trace()
            except Exception as e:
                print(e)
    return []
