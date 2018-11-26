import ctypes as ct

from .consts import PerfRecord, RecordMisc
from .snapshot import EVENTS


def string_size(path: str) -> int:
    return (len(path) + 1 + 7) & ~7


def comm_event(tid: int, command: str) -> bytearray:
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


def switch_event(tid: int) -> bytearray:
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


def mmap2_event(
    tid: int, path: str, start: int, stop: int, page_offset: int
) -> bytearray:
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
    # event.misc = RecordMisc.PERF_RECORD_MISC_KERNEL
    # Unused by decoder library at the moment
    event.maj = 0
    event.min = 0
    event.ino = 0
    event.ino_generation = 0
    event.prot = 0
    event.flags = 0
    assert len(event.filename) > 0
    return bytearray(event)
