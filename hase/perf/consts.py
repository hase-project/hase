import ctypes as ct
import resource
from typing import Any, Callable, Dict, List, Tuple, Type


class Libc:
    libc = ct.CDLL("libc.so.6", use_errno=True)

    MAP_FAILED = ct.c_void_p(-1)
    PAGESIZE = resource.getpagesize()

    syscall = libc.syscall
    ioctl = libc.ioctl


class perf_event_header(ct.Structure):
    _fields_ = [
        ("type", ct.c_uint),  #
        ("misc", ct.c_ushort),  #
        ("size", ct.c_ushort),  #
    ]


class perf_event_attr(ct.Structure):
    _fields_ = [
        ("type", ct.c_uint),  #
        ("size", ct.c_uint),  #
        ("config", ct.c_ulong),  #
        ("sample_period", ct.c_ulong),  #
        ("sample_type", ct.c_ulong),  #
        ("read_format", ct.c_ulong),  #
        ("flags", ct.c_ulong),  #
        ("wakeup_events", ct.c_uint),  #
        ("bp_type", ct.c_uint),  #
        ("config1", ct.c_ulong),  #
        ("config2", ct.c_ulong),  #
        ("branch_sample_type", ct.c_ulong),  #
        ("sample_regs_user", ct.c_ulong),  #
        ("sample_stack_user", ct.c_uint),  #
        ("clockid", ct.c_int),  #
        ("sample_regs_intr", ct.c_ulong),  #
        ("aux_watermark", ct.c_uint),  #
        ("sample_max_stack", ct.c_ushort),  #
        ("__reserved_2", ct.c_ushort),
    ]


class perf_event_mmap_page(ct.Structure):
    _fields_ = [
        ("version", ct.c_uint),  #
        ("compat_version", ct.c_uint),  #
        ("lock", ct.c_uint),  #
        ("index", ct.c_uint),  #
        ("offset", ct.c_long),  #
        ("time_enabled", ct.c_ulong),  #
        ("time_running", ct.c_ulong),  #
        ("capabilities", ct.c_ulong),  #
        ("pmc_width", ct.c_ushort),  #
        ("time_shift", ct.c_ushort),  #
        ("time_mult", ct.c_uint),  #
        ("time_offset", ct.c_ulong),  #
        ("time_zero", ct.c_ulong),  #
        ("time_size", ct.c_uint),  #
        ("reserved", ct.c_byte * (118 * 8 + 4)),  #
        ("data_head", ct.c_ulong),  #
        ("data_tail", ct.c_ulong),  #
        ("data_offset", ct.c_ulong),  #
        ("data_size", ct.c_ulong),  #
        ("aux_head", ct.c_ulong),  #
        ("aux_tail", ct.c_ulong),  #
        ("aux_offset", ct.c_ulong),  #
        ("aux_size", ct.c_ulong),  #
    ]


class Ioctls:
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


class PerfRecord:
    PERF_RECORD_MMAP = 1
    PERF_RECORD_LOST = 2
    PERF_RECORD_COMM = 3
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


def sample_id_struct(sample_flags: int) -> Type[Any]:
    fields = []  # type: List[Tuple[str, Any]]
    if sample_flags & SampleFlags.PERF_SAMPLE_TID != 0:
        fields.append(("pid", ct.c_uint))
        fields.append(("tid", ct.c_uint))

    if sample_flags & SampleFlags.PERF_SAMPLE_TIME != 0:
        fields.append(("time", ct.c_ulong))

    if sample_flags & SampleFlags.PERF_SAMPLE_ID != 0:
        fields.append(("id", ct.c_ulong))

    if sample_flags & SampleFlags.PERF_SAMPLE_STREAM_ID != 0:
        fields.append(("id", ct.c_ulong))

    if sample_flags & SampleFlags.PERF_SAMPLE_CPU != 0:
        fields.append(("cpu", ct.c_uint))
        fields.append(("res", ct.c_uint))

    if sample_flags & SampleFlags.PERF_SAMPLE_IDENTIFIER != 0:
        fields.append(("id", ct.c_uint))

    class sample_id(ct.Structure):
        _fields_ = fields

    return sample_id


def compute_string_size(
    fn: Callable[["EventStructs", int], Type[ct.Structure]]
) -> Callable[["EventStructs", int], Type[ct.Structure]]:
    memo = {}  # type: Dict[int, Type[ct.Structure]]

    def wrapper(self: "EventStructs", size: int) -> Type[ct.Structure]:
        if size == -1:
            base_type = memo.get(0)
            if base_type:
                return base_type
            memo[0] = fn(self, 0)
            return memo[0]

        if size not in memo:
            base_type = fn(self, 0)
            minimum_size = ct.sizeof(base_type)
            assert size >= minimum_size
            if size == minimum_size:
                memo[size] = base_type
            else:
                memo[size] = fn(self, size - minimum_size)
        return memo[size]

    return wrapper


class EventStructs:
    def __init__(self, sample_flags: int) -> None:
        self.sample_id = sample_id_struct(sample_flags)  # type: Type[Any]

    def _event_header(self, event_fields: List[Tuple[str, Any]]) -> Type[ct.Structure]:
        class event(ct.Structure):
            _fields_ = (
                perf_event_header._fields_
                + event_fields
                + [("sample_id", self.sample_id)]
            )

        return event

    @compute_string_size
    def mmap_event(self, size: int) -> Type[ct.Structure]:
        return self._event_header(
            [
                ("pid", ct.c_uint),  #
                ("tid", ct.c_uint),  #
                ("addr", ct.c_ulong),  #
                ("tid", ct.c_ulong),  #
                ("pgoff", ct.c_ulong),  #
                ("filename", ct.c_char * size),  #
            ]
        )

    @compute_string_size
    def lost_event(self, _size: int) -> Type[ct.Structure]:
        return self._event_header([("id", ct.c_ulong), ("lost", ct.c_ulong)])

    @compute_string_size
    def comm_event(self, size: int) -> Type[ct.Structure]:
        return self._event_header(
            [
                ("pid", ct.c_uint),  #
                ("tid", ct.c_uint),  #
                ("comm", ct.c_char * size),  #
            ]
        )

    @compute_string_size
    def exit_event(self, _size: int) -> Type[ct.Structure]:
        return self._event_header(
            [
                ("pid", ct.c_uint),  #
                ("ppid", ct.c_uint),  #
                ("tid", ct.c_uint),  #
                ("ptid", ct.c_uint),  #
                ("time", ct.c_long),  #
            ]
        )

    @compute_string_size
    def throttle_event(self, _size: int) -> Type[ct.Structure]:
        return self._event_header(
            [
                ("time", ct.c_ulong),  #
                ("id", ct.c_ulong),  #
                ("stream_id", ct.c_long),  #
            ]
        )

    unthrottle_event = throttle_event

    fork_event = exit_event

    @compute_string_size
    def mmap2_event(self, size: int) -> Type[ct.Structure]:
        return self._event_header(
            [
                ("pid", ct.c_uint),  #
                ("tid", ct.c_uint),  #
                ("addr", ct.c_ulong),  #
                ("len", ct.c_ulong),  #
                ("pgoff", ct.c_ulong),  #
                ("maj", ct.c_uint),  #
                ("min", ct.c_uint),  #
                ("ino", ct.c_ulong),  #
                ("ino_generation", ct.c_ulong),  #
                ("prot", ct.c_uint),  #
                ("flags", ct.c_uint),  #
                ("filename", ct.c_char * size),  #
            ]
        )

    @compute_string_size
    def aux_event(self, size: int) -> Type[ct.Structure]:
        return self._event_header(
            [
                ("aux_offset", ct.c_ulong),  #
                ("aux_size", ct.c_ulong),  #
                ("flags", ct.c_ulong),  #
            ]
        )

    @compute_string_size
    def itrace_start_event(self, size: int) -> Type[ct.Structure]:
        return self._event_header([("pid", ct.c_uint), ("tid", ct.c_uint)])

    @compute_string_size
    def lost_samples_event(self, size: int) -> Type[ct.Structure]:
        return self._event_header([("lost", ct.c_ulong)])  #

    @compute_string_size
    def record_switch_event(self, size: int) -> Type[ct.Structure]:
        base = self._event_header([])  # type: Any

        class RecordSwitch(base):
            def is_switch_out(self) -> bool:
                # otherwise switch in
                return (self.misc & RecordMisc.PERF_RECORD_MISC_SWITCH_OUT) != 0

        return RecordSwitch

    @compute_string_size
    def record_switch_cpu_wide_event(self, size: int) -> Type[ct.Structure]:
        return self._event_header(
            [("next_prev_pid", ct.c_uint), ("next_prev_tid", ct.c_uint)]
        )


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

    PERF_SAMPLE_MASK = (
        PERF_SAMPLE_IP
        | PERF_SAMPLE_TID
        | PERF_SAMPLE_TIME
        | PERF_SAMPLE_ADDR
        | PERF_SAMPLE_ID
        | PERF_SAMPLE_STREAM_ID
        | PERF_SAMPLE_CPU
        | PERF_SAMPLE_PERIOD
        | PERF_SAMPLE_IDENTIFIER
    )


class AttrFlags:
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


class RecordMisc:
    PERF_RECORD_MISC_CPUMODE_UNKNOWN = 0
    PERF_RECORD_MISC_CPUMODE_MASK = 7
    PERF_RECORD_MISC_KERNEL = 1
    PERF_RECORD_MISC_USER = 2
    PERF_RECORD_MISC_HYPERVISOR = 3
    PERF_RECORD_MISC_GUEST_KERNEL = 4
    PERF_RECORD_MISC_GUEST_USER = 5
    PERF_RECORD_MISC_MMAP_DATA = 1 << 13
    PERF_RECORD_MISC_COMM_EXEC = 1 << 13
    PERF_RECORD_MISC_SWITCH_OUT = 1 << 13
