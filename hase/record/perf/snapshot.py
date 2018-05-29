from __future__ import absolute_import, division, print_function

import ctypes as ct
import mmap
import fcntl
import os
import resource
import sys
import select
from threading import Thread

from typing import List, Iterator, Any


class Libc(object):
    libc = ct.CDLL('libc.so.6', use_errno=True)

    MAP_FAILED = ct.c_void_p(-1)
    mmap = libc.mmap
    mmap.restype = ct.c_void_p
    mmap.argtypes = [
        ct.c_void_p, ct.c_size_t, ct.c_int, ct.c_int, ct.c_int, ct.c_long
    ]

    munmap = libc.munmap
    munmap.restype = ct.c_int
    munmap.argtypes = [ct.c_void_p, ct.c_size_t]

    syscall = libc.syscall
    ioctl = libc.ioctl


class perf_event_header(ct.Structure):
    _fields_ = [
        ('type', ct.c_uint),  #
        ('misc', ct.c_ushort),  #
        ('size', ct.c_ushort),  #
    ]


class itrace_start_event(ct.Structure):
    _fields_ = perf_event_header._fields_ + [
        ('pid', ct.c_uint),  #
        ('tid', ct.c_int),  #
    ]

class perf_aux_event(ct.Structure):
    _fields_ = perf_event_header._fields_ + [
        ('aux_offset', ct.c_ulong),  #
        ('aux_size', ct.c_ulong),  #
        ('flags', ct.c_ulong),  #
    ]


class perf_event_attr(ct.Structure):
    _fields_ = [
        ('type', ct.c_uint),  #
        ('size', ct.c_uint),  #
        ('config', ct.c_ulong),  #
        ('sample_period', ct.c_ulong),  #
        ('sample_type', ct.c_ulong),  #
        ('read_format', ct.c_ulong),  #
        ('flags', ct.c_ulong),  #
        ('wakeup_events', ct.c_uint),  #
        ('bp_type', ct.c_uint),  #
        ('config1', ct.c_ulong),  #
        ('config2', ct.c_ulong),  #
        ('branch_sample_type', ct.c_ulong),  #
        ('sample_regs_user', ct.c_ulong),  #
        ('sample_stack_user', ct.c_uint),  #
        ('clockid', ct.c_int),  #
        ('sample_regs_intr', ct.c_ulong),  #
        ('aux_watermark', ct.c_uint),  #
        ('sample_max_stack', ct.c_ushort),  #
        ('__reserved_2', ct.c_ushort)
    ]


class perf_event_mmap_page(ct.Structure):
    _fields_ = [
        ('version', ct.c_uint),  #
        ('compat_version', ct.c_uint),  #
        ('lock', ct.c_uint),  #
        ('index', ct.c_uint),  #
        ('offset', ct.c_long),  #
        ('time_enabled', ct.c_ulong),  #
        ('time_running', ct.c_ulong),  #
        ('capabilities', ct.c_ulong),  #
        ('pmc_width', ct.c_ushort),  #
        ('time_shift', ct.c_ushort),  #
        ('time_mult', ct.c_uint),  #
        ('time_offset', ct.c_ulong),  #
        ('time_zero', ct.c_ulong),  #
        ('time_size', ct.c_uint),  #
        ('reserved', ct.c_byte * (118 * 8 + 4)),  #
        ('data_head', ct.c_ulong),  #
        ('data_tail', ct.c_ulong),  #
        ('data_offset', ct.c_ulong),  #
        ('data_size', ct.c_ulong),  #
        ('aux_head', ct.c_ulong),  #
        ('aux_tail', ct.c_ulong),  #
        ('aux_offset', ct.c_ulong),  #
        ('aux_size', ct.c_ulong),  #
    ]


class Ioctls(object):
    # source: https://github.com/golang/sys/blob/7c87d13f8e835d2fb3a70a2912c811ed0c1d241b/unix/zerrors_linux_amd64.go#L1205
    PERF_EVENT_IOC_DISABLE = 0x2401
    PERF_EVENT_IOC_ENABLE = 0x2400
    PERF_EVENT_IOC_ID = 0x80082407
    PERF_EVENT_IOC_PAUSE_OUTPUT = 0x40042409
    PERF_EVENT_IOC_PERIOD = 0x40082404
    PERF_EVENT_IOC_REFRESH = 0x2402
    PERF_EVENT_IOC_RESET = 0x2403
    PERF_EVENT_IOC_SET_BPF = 0x40042408
    PERF_EVENT_IOC_SET_FILTER = 0x40082406
    PERF_EVENT_IOC_SET_OUTPUT = 0x2405


class PerfRecord(object):
    PERF_RECORD_MMAP = 1
    PERF_RECORD_LOST = 2
    PERF_RECORD_COMM = 2
    PERF_RECORD_EXIT = 4
    PERF_RECORD_THROTTLE = 5
    PERF_RECORD_UNTHROTTLE = 6
    PERF_RECORD_FORK = 7
    PERF_RECORD_READ = 8
    PERF_RECORD_SAMPLE = 9
    PERF_RECORD_MMAP2 = 10
    PERF_RECORD_AUX = 11
    PERF_RECORD_ITRACE_START = 12
    PERF_RECORD_LOST_SAMPLES = 13
    PERF_RECORD_SWITCH = 14
    PERF_RECORD_SWITCH_CPU_WIDE = 15
    PERF_RECORD_NAMESPACES = 16


class SampleFlags:
    PERF_SAMPLE_IP = 1 << 0
    PERF_SAMPLE_TID = 1 << 1
    PERF_SAMPLE_TIME = 1 << 2
    PERF_SAMPLE_ADDR = 1 << 3
    PERF_SAMPLE_READ = 1 << 4
    PERF_SAMPLE_CALLCHAIN = 1 << 5
    PERF_SAMPLE_ID = 1 << 6
    PERF_SAMPLE_CPU = 1 << 7
    PERF_SAMPLE_PERIOD = 1 << 8
    PERF_SAMPLE_STREAM_ID = 1 << 9
    PERF_SAMPLE_RAW = 1 << 10
    PERF_SAMPLE_BRANCH_STACK = 1 << 11
    PERF_SAMPLE_REGS_USER = 1 << 12
    PERF_SAMPLE_STACK_USER = 1 << 13
    PERF_SAMPLE_WEIGHT = 1 << 14
    PERF_SAMPLE_DATA_SRC = 1 << 15
    PERF_SAMPLE_IDENTIFIER = 1 << 16
    PERF_SAMPLE_TRANSACTION = 1 << 17
    PERF_SAMPLE_REGS_INTR = 1 << 18
    PERF_SAMPLE_PHYS_ADDR = 1 << 19

    PERF_SAMPLE_MASK = PERF_SAMPLE_IP | \
        PERF_SAMPLE_TID | \
        PERF_SAMPLE_TIME | \
        PERF_SAMPLE_ADDR | \
        PERF_SAMPLE_ID | \
        PERF_SAMPLE_STREAM_ID | \
        PERF_SAMPLE_CPU | \
        PERF_SAMPLE_PERIOD | \
        PERF_SAMPLE_IDENTIFIER


class PerfFlags(object):
    DISABLED = 1 << 0
    INHERIT = 1 << 1
    PINNED = 1 << 2
    EXCLUSIVE = 1 << 3
    EXCLUDE_USER = 1 << 4
    EXCLUDE_KERNEL = 1 << 5
    EXCLUDE_HV = 1 << 6
    EXCLUDE_IDLE = 1 << 7
    MMAP = 1 << 8
    COMM = 1 << 9
    FREQ = 1 << 10
    INHERIT_STAT = 1 << 11
    ENABLE_ON_EXEC = 1 << 12
    TASK = 1 << 13
    WATERMARK = 1 << 14
    PRECISE_IP_1 = 1 << 15
    PRECISE_IP_2 = 1 << 16
    MMAP_DATA = 1 << 17
    SAMPLE_ID_ALL = 1 << 18
    EXECLUDE_HOST = 1 << 19
    EXECLUDE_GUEST = 1 << 20
    EXCLUDE_CALLCHAIN_KERNEL = 1 << 21
    EXCLUDE_CALLCHAIN_USER = 1 << 22
    MMAP2 = 1 << 23
    COMM_EXEC = 1 << 24
    USE_CLOCKID = 1 << 25
    CONTEXT_SWITCH = 1 << 26
    WRITE_BACKWARD = 1 << 27
    NAMESPACES = 1 << 28


PERF_FLAG_FD_CLOEXEC = 8
SYS_perf_event_open = 298

PERF_TYPE_SOFTWARE = 1
PERF_COUNT_SW_DUMMY = 9
CAP_USER_TIME_ZERO = 4


def cpus_online():
    # type: () -> List[int]

    # Accepted parameters:
    # 0  - core 0
    # 0,1,2,3  - cores 0,1,2,3
    # 0-12,13-15,18,19

    with open("/sys/devices/system/cpu/online") as f:
        cores = f.read().strip()

    result = set()
    sequences = cores.split(',')
    for seq in sequences:
        if '-' not in seq:
            if not seq.isdigit():
                raise ValueError('%s is not digital' % seq)
            result.add(int(seq))
        else:
            core_range = seq.split('-')
            if len(core_range) != 2 or not core_range[0].isdigit() \
                    or not core_range[1].isdigit():
                raise ValueError('Core Range Error')
            result.update(range(int(core_range[0]), int(core_range[1]) + 1))
    return list(result)


def intel_pt_type():
    # type: () -> int
    with open("/sys/bus/event_source/devices/intel_pt/type") as f:
        return int(f.read())


class PMU(object):
    def __init__(self, perf_attr, cpu):
        # type: (perf_event_attr, int) -> None
        self.fd = Libc.syscall(SYS_perf_event_open, ct.byref(perf_attr), -1,
                               cpu, -1, PERF_FLAG_FD_CLOEXEC)
        fcntl.fcntl(self.fd, fcntl.F_SETFL, os.O_RDONLY | os.O_NONBLOCK)
        assert self.fd != 0

    def __enter__(self):
        # type: () -> PMU
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def _ioctl(self, cmd, arg):
        # type: (int, Any) -> int
        res = Libc.ioctl(self.fd, cmd, arg)
        assert res == 0
        return res

    def set_output(self, pmu):
        # type: (PMU) -> int
        return self._ioctl(Ioctls.PERF_EVENT_IOC_SET_OUTPUT, pmu.fd)

    def pause(self):
        # type: () -> int
        return self._ioctl(Ioctls.PERF_EVENT_IOC_PAUSE_OUTPUT, 1)

    def disable(self):
        # type: () -> int
        return self._ioctl(Ioctls.PERF_EVENT_IOC_DISABLE, 0)

    def enable(self):
        # type: () -> int
        return self._ioctl(Ioctls.PERF_EVENT_IOC_ENABLE, 0)

    def close(self):
        # type: () -> None
        os.close(self.fd)

    def event_id(self):
        # type: () -> int
        id = ct.c_ulong()
        self._ioctl(Ioctls.PERF_EVENT_IOC_ID, ct.byref(id))
        return id.value


def open_pt_event(cpu):
    # type: (int) -> PMU
    attr = perf_event_attr()
    attr.size = ct.sizeof(attr)
    attr.type = intel_pt_type()
    # FIXME: find out how config works,
    # currenty copied from strace output
    attr.config = 0x300e601
    attr.sample_type = SampleFlags.PERF_SAMPLE_MASK
    attr.sample_period = 1
    attr.clockid = 1
    attr.flags = PerfFlags.DISABLED | \
        PerfFlags.EXCLUDE_KERNEL | \
        PerfFlags.EXCLUDE_HV | \
        PerfFlags.SAMPLE_ID_ALL | \
        PerfFlags.WRITE_BACKWARD

    return PMU(attr, cpu)


def open_dummy_event(cpu):
    # type: (int) -> PMU
    attr = perf_event_attr()
    attr.size = ct.sizeof(attr)
    attr.type = PERF_TYPE_SOFTWARE
    attr.config = PERF_COUNT_SW_DUMMY
    attr.sample_type = SampleFlags.PERF_SAMPLE_MASK
    attr.sample_period = 1
    attr.clockid = 1

    attr.flags = PerfFlags.EXCLUDE_KERNEL | \
        PerfFlags.EXCLUDE_HV | \
        PerfFlags.SAMPLE_ID_ALL | \
        PerfFlags.MMAP | \
        PerfFlags.COMM | \
        PerfFlags.TASK | \
        PerfFlags.MMAP2 | \
        PerfFlags.COMM_EXEC | \
        PerfFlags.CONTEXT_SWITCH | \
        PerfFlags.WRITE_BACKWARD

    return PMU(attr, cpu)


class MMap(object):
    def __init__(self, fd, size, protection, flags, offset=0):
        # type: (int, int, int, int, int) -> None
        # ctypes does not support pythons mmap module, so we use the libc
        # version
        self.addr = Libc.mmap(None, size, protection, flags, fd, offset)
        assert self.addr != Libc.MAP_FAILED.value
        self.size = size

    def close(self):
        # type: () -> None
        if self.addr:
            res = Libc.munmap(self.addr, self.size)
            assert res == 0


PAGESIZE = resource.getpagesize()


class TscConversion(object):
    def __init__(self, time_mult, time_shift, time_zero):
        # type: (int, int, int) -> None
        self.time_mult = time_mult
        self.time_shift = time_shift
        self.time_zero = time_zero


class MmapHeader(object):
    def __init__(self, addr, data_size):
        # type: (int, int) -> None
        self._header = perf_event_mmap_page.from_address(addr)
        self.data_addr = addr + self._header.data_offset
        self.data_size = data_size

    # From kernel commit 9ecda41acb971ebd07c8fb35faf24005c0baea12 introducing
    # overwritable ring buffer:
    #
    # Following figure demonstrates the state of the overwritable ring buffer
    # when 'write_backward' is set before overwriting:
    #
    #        head
    #         |
    #         V
    #     +---+------+----------+-------+------+
    #     |   |D....D|C........C|B.....B|A....A|
    #     +---+------+----------+-------+------+
    #
    # and after overwriting:
    #                                      head
    #                                       |
    #                                       V
    #     +---+------+----------+-------+---+--+
    #     |..E|D....D|C........C|B.....B|A..|E.|
    #     +---+------+----------+-------+---+--+
    #
    # In each situation, 'head' points to the beginning of the newest record.
    # From this record, tooling can iterate over the full ring buffer and fetch
    # records one by one.
    def events(self):
        # () -> List[bytearray]
        data_head = self._header.data_head
        events = []  # type: List[str]
        #if data_head == 0:
        #    return events

        data_size = self.data_size
        offset = data_head + data_size

        first = True

        while True:
            begin = self.data_addr + offset % data_size
            ev = perf_event_header.from_address(begin)
            if ev.size == 0:
                break
            end = self.data_addr + (offset + ev.size) % data_size

            if first:
                first_begin = begin
                first_end = end
            elif begin <= first_begin and end >= first_end:
                break

            py_buf = bytearray(ev.size)
            buf_type = (ct.c_byte * ev.size)
            buf = buf_type.from_buffer(py_buf)
            if end < begin:
                # event wraps around into ring buffer start
                length = self.data_addr + data_size - begin
                ct.memmove(buf, begin, length)
                ct.memmove(
                    ct.addressof(buf) + length, self.data_addr,
                    ev.size - length)
            else:
                ct.memmove(buf, begin, ct.sizeof(buf))
            events.append(py_buf)
            first = False
            offset += ev.size
        return reversed(events)

    def tsc_conversion(self):
        # () -> TscConversion
        i = 0
        while True:
            seq = self._header.lock
            conversion = TscConversion(self._header.time_mult,
                                       self._header.time_shift,
                                       self._header.time_zero)
            cap_user_time_zero = self._header.capabilities & 1 << CAP_USER_TIME_ZERO
            if self._header.lock == seq and (seq & 1) == 0:
                assert cap_user_time_zero != 0
                return conversion
            i += 1
            if i > 10000:
                raise Exception("failed to get perf_event_mmap_page lock")

    @property
    def aux_offset(self):
        # type: () -> int
        return self._header.aux_offset

    @property
    def aux_size(self):
        # type: () -> int
        return self._header.aux_size

    @aux_size.setter
    def aux_size(self, size):
        # type: (int) -> None
        self._header.aux_offset = self._header.data_offset + self._header.data_size
        self._header.aux_size = size

    def advance(self):
        # type: () -> None
        self._header.data_tail = self._header.data_head


class BackwardRingbuffer(object):
    def __init__(self, cpu):
        # type: (int) -> None
        """
        Implements ring buffer described here: https://lwn.net/Articles/688338/
        """
        # data and aux area must be a multiply of two
        self.pmu = open_dummy_event(cpu)
        header_size = PAGESIZE
        data_size = 2**9 * PAGESIZE  # == 2097152

        self.buf = MMap(self.pmu.fd, header_size + data_size, mmap.PROT_READ,
                        mmap.MAP_SHARED)

        self.header = MmapHeader(self.buf.addr, data_size)

    def stop(self):
        # type: () -> None
        self.pmu.pause()

    def close(self):
        # type: () -> None
        if self.buf:
            self.buf.close()
        self.pmu.close()

    def events(self):
        # () -> List[bytearray]
        return self.header.events()

    def tsc_conversion(self):
        # () -> TscConversion
        return self.header.tsc_conversion()


class AuxRingbuffer(object):
    def __init__(self, cpu):
        # type: (int) -> None
        # data area must be a multiply of two
        data_size = 2**9 * PAGESIZE  # == 2097152
        #data_size = 2 * PAGESIZE  # == 2097152
        self.pmu = open_pt_event(cpu)
        header_size = PAGESIZE

        self.buf = MMap(self.pmu.fd, header_size + data_size,
                        mmap.PROT_READ | mmap.PROT_WRITE, mmap.MAP_SHARED)

        self.header = MmapHeader(self.buf.addr, data_size)

        # aux area must be a multiply of two
        self.header.aux_size = PAGESIZE * (2**14)  # == 67108864
        self.aux_buf = MMap(
            self.pmu.fd,
            self.header.aux_size,
            mmap.PROT_READ,
            mmap.MAP_SHARED,
            offset=self.header.aux_offset)

        self.pmu.enable()

    def mark_as_read(self):
        # type: () -> None
        self.header.advance()

    def close(self):
        # type: () -> None
        if self.aux_buf:
            self.aux_buf.close()

        if self.buf:
            self.buf.close()

        self.pmu.close()

    def stop(self):
        # type: () -> None
        self.pmu.disable()

    def events(self):
        # () -> List[bytearray]
        return self.header.events()


class PerfEvents():
    def __init__(self, tsc_conversion):
        self.tsc_conversion = tsc_conversion


class Cpu():
    def __init__(self, idx, event_buffer, pt_buffer):
        # type: (int, BackwardRingbuffer, AuxRingbuffer) -> None
        self.idx = idx
        self.event_buffer = event_buffer
        self.pt_buffer = pt_buffer

    def events(self):
        # type: () -> Iterator[bytearray]
        return iter(self.event_buffer.events())

    def traces(self):
        # type: () -> Iterator[bytearray]
        for ev in self.pt_buffer.events():
            event = perf_aux_event.from_buffer(ev)
            print(event.type)
            yield ev
            #begin = self.pt_buffer.aux_buf.addr + event.aux_offset
            #end = begin + event.aux_size
            #assert end < self.pt_buffer.aux_buf.addr + self.pt_buffer.aux_buf.size
            #self.pt_buffer.aux_buf[]

    def stop(self):
        # type: () -> None
        self.pt_buffer.stop()

        self.event_buffer.stop()

    def close(self):
        # type: () -> None
        self.pt_buffer.close()
        self.event_buffer.close()


# Because the interface for aux events is brain dead we need to poll for
# all PERF_RECORD_AUX events to get the latest ones.
# The last event in the buffer is the offset in our aux buffer.
def poll_aux_events(pt_buffers, stop_fd):
    return
    # type: (List[AuxRingbuffer], int) -> None
    poll_obj = select.poll()
    for buf in pt_buffers:
        poll_obj.register(buf.pmu.fd, select.POLLIN)
    poll_obj.register(stop_fd, select.POLLERR)
    while True:
        fds = []
        for (fd, event) in poll_obj.poll():
            fds.append(fd)
            if fd == stop_fd:
                return
        for buf in pt_buffers:
            buf.mark_as_read()


class PtSnapshot(object):
    def __init__(self):
        # type: () -> None
        self.stopped = False
        self.cpus = []  # type: List[Cpu]

        try:
            self.start()
        except Exception:
            self.close()
            raise

    def start_polling(self, pt_buffers):
        # type: (List[AuxRingbuffer]) -> None
        stop_fds = os.pipe()
        self.stop_polling_fd = stop_fds[0]
        self.polling_thread = Thread(
            target=poll_aux_events, args=(pt_buffers, stop_fds[1]))
        self.polling_thread.start()

    def stop_polling(self):
        # type: () -> None
        if self.polling_thread is None or not self.polling_thread.is_alive():
            return
        os.close(self.stop_polling_fd)
        self.polling_thread.join()

    def start(self):
        # type: () -> None
        assert not self.stopped
        event_buffers = []  # type: List[BackwardRingbuffer]
        pt_buffers = []  # type: List[AuxRingbuffer]

        cpu_idx = cpus_online()
        for idx in cpu_idx:
            event_buffers.append(BackwardRingbuffer(idx))

        # gather dummy events before pt events
        for idx in cpu_idx:
            pt_buffers.append(AuxRingbuffer(idx))

        for idx in cpu_idx:
            self.cpus.append(Cpu(idx, event_buffers[idx], pt_buffers[idx]))

        self.start_polling(pt_buffers)

    def __enter__(self):
        # type: () -> PtSnapshot
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def stop(self):
        # type: () -> None
        print("stop")
        for cpu in self.cpus:
            cpu.stop()
        self.stop_polling()
        self.stopped = True

    def tsc_conversion(self):
        # type: () -> TscConversion
        return self.cpus[0].event_buffer.tsc_conversion()

    def close(self):
        # type: () -> None
        self.stop_polling()
        for cpu in self.cpus:
            cpu.close()
