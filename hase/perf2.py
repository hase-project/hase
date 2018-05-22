from __future__ import absolute_import, division, print_function

import ctypes as ct
import mmap
import fcntl
import os
import resource
import sys

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
    def __init__(self, perf_attr, pid, cpu):
        # type: (perf_event_attr, int, int) -> None
        self.fd = Libc.syscall(SYS_perf_event_open, ct.byref(perf_attr), pid,
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

    def close(self):
        # type: () -> None
        os.close(self.fd)

    def event_id(self):
        # type: () -> int
        id = ct.c_ulong()
        self._ioctl(Ioctls.PERF_EVENT_IOC_ID, ct.byref(id))
        return id.value


def open_pt_event(pid, cpu):
    # type: (int, int) -> PMU
    attr = perf_event_attr()
    attr.size = ct.sizeof(attr)
    attr.type = intel_pt_type()
    # FIXME: find out how config works,
    # currenty copied from strace output
    attr.config = 0x300e601
    attr.sample_type = SampleFlags.PERF_SAMPLE_MASK
    attr.sample_period = 1
    attr.clockid = 1
    attr.flags = PerfFlags.INHERIT | \
        PerfFlags.EXCLUDE_KERNEL | \
        PerfFlags.EXCLUDE_HV | \
        PerfFlags.SAMPLE_ID_ALL | \
        PerfFlags.WRITE_BACKWARD

    return PMU(attr, pid, cpu)


def open_dummy_event(pid, cpu):
    # type: (int, int) -> PMU
    attr = perf_event_attr()
    attr.size = ct.sizeof(attr)
    attr.type = PERF_TYPE_SOFTWARE
    attr.config = PERF_COUNT_SW_DUMMY
    attr.sample_type = SampleFlags.PERF_SAMPLE_MASK
    attr.sample_period = 1
    attr.clockid = 1

    attr.flags = PerfFlags.INHERIT | \
        PerfFlags.EXCLUDE_KERNEL | \
        PerfFlags.EXCLUDE_HV | \
        PerfFlags.SAMPLE_ID_ALL | \
        PerfFlags.MMAP | \
        PerfFlags.COMM | \
        PerfFlags.TASK | \
        PerfFlags.MMAP2 | \
        PerfFlags.COMM_EXEC | \
        PerfFlags.CONTEXT_SWITCH | \
        PerfFlags.WRITE_BACKWARD

    return PMU(attr, pid, cpu)


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
        # () -> List[perf_event_header]
        data_head = ct.c_int(self._header.data_head).value
        events = []
        if data_head == 0:
            return events

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

            buf = (ct.c_char * ev.size)()
            if end < begin:
                # event wraps around into ring buffer start
                length = self.data_addr + data_size - begin
                ct.memmove(buf, begin, length)
                ct.memmove(
                    ct.addressof(buf) + length, self.data_addr,
                    ev.size - length)
            else:
                ct.memmove(buf, begin, ct.sizeof(buf))
            events.append(perf_event_header.from_buffer(buf))
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


class BackwardRingbuffer(object):
    def __init__(self, pmu):
        # type: (PMU) -> None
        """
        Implements ring buffer described here: https://lwn.net/Articles/688338/
        """
        # data and aux area must be a multiply of two
        self.pmu = pmu
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
        return self.header.events()

    def tsc_conversion(self):
        return self.header.tsc_conversion()


class AuxRingbuffer(object):
    def __init__(self, pmu):
        # type: (PMU) -> None
        # data and aux area must be a multiply of two
        data_size = 2**9 * PAGESIZE  # == 2097152
        self.pmu = pmu
        header_size = PAGESIZE

        self.buf = MMap(self.pmu.fd, header_size + data_size,
                        mmap.PROT_READ | mmap.PROT_WRITE, mmap.MAP_SHARED)

        self.header = MmapHeader(self.buf.addr, data_size)

        self.header.aux_size = PAGESIZE * (2**14)  # == 67108864
        self.aux_buf = MMap(
            self.pmu.fd,
            self.header.aux_size,
            mmap.PROT_READ,
            mmap.MAP_SHARED,
            offset=self.header.aux_offset)

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
        return self.header.events()


class PerfEvents():
    def __init__(self, tsc_conversion):
        self.tsc_conversion = tsc_conversion


class PtSnapshot(object):
    def __init__(self, pid):
        # type: (int) -> None
        self.event_buffers = []  # type: List[BackwardRingbuffer]
        self.pt_buffers = []  # type: List[AuxRingbuffer]

        try:
            self.start(pid)
        except Exception:
            self.close()
            raise

    def start(self, pid):
        # type: (int) -> None
        for cpu in cpus_online():
            self.event_buffers.append(
                BackwardRingbuffer(open_dummy_event(pid, cpu)))

        # gather dummy events before pt events
        for cpu in cpus_online():
            self.pt_buffers.append(AuxRingbuffer(open_pt_event(pid, cpu)))

    def __enter__(self):
        # type: () -> PtSnapshot
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def take(self):
        # type: () -> Iterator[perf_event_header]
        for r in self.pt_buffers:
            r.stop()

        for r2 in self.event_buffers:
            r2.stop()

        for b in self.event_buffers:
            for e in b.events():
                yield e

        for b2 in self.pt_buffers:
            for e in b2.events():
                yield e

    def tsc_conversion(self):
        return self.event_buffers[0].tsc_conversion()

    def close(self):
        # type: () -> None
        for r in self.pt_buffers:
            r.close()

        for r2 in self.event_buffers:
            r2.close()


if __name__ == "__main__":
    import pry
    with pry:
        with PtSnapshot(os.getpid()) as snapshot:
            # produce some events
            for i in range(10):
                sys.stderr.write(".")
            sys.stderr.write("\n")
            # wait for events to appear in log
            snapshot.take()
            snapshot.tsc_conversion()
