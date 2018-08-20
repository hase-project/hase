from __future__ import absolute_import, division, print_function

from typing import Optional
from enum import IntEnum

class TraceEvent(object):
    """
    This class is used by the C extension _pt
    """

    def __init__(self, pos, time):
        # type: (int, Optional[int]) -> None
        self.pos = pos
        self.time = time

    def __repr__(self):
        time = ""
        if self.time is not None:
            time = ", time: 0x%x" % self.time
        return '<%s @ 0x%x%s>' % (self.__class__.__name__, self.pos, time)


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


class Instruction(object):
    def __init__(self, ip, size, iclass):
        # type: (int, int, InstructionClass) -> None
        self.ip = ip
        self.size = size
        self.iclass = iclass

    def __repr__(self):
        return '<Instruction[%s] @ %x>' % (self.iclass.name, self.ip)


class EnableEvent(TraceEvent):
    def __init__(self, pos, time, ip, resumed):
        # type: (int, Optional[int], int, bool) -> None
        self.ip = ip
        self.resumed = resumed
        super(EnableEvent, self).__init__(pos, time)


class DisableEvent(TraceEvent):
    def __init__(self, pos, time, ip):
        # type: (int, Optional[int], Optional[int]) -> None
        self.ip = ip
        super(DisableEvent, self).__init__(pos, time)


class AsyncDisableEvent(TraceEvent):
    def __init__(self, pos, time, ip, at):
        # type: (int, Optional[int], Optional[int], int) -> None
        self.ip = ip
        self.at = at
        super(AsyncDisableEvent, self).__init__(pos, time)


class AsyncBranchEvent(TraceEvent):
    def __init__(self, pos, time, from_addr):
        # type: (int, Optional[int], int) -> None
        self.from_addr = from_addr
        super(AsyncBranchEvent, self).__init__(pos, time)


class PagingEvent(TraceEvent):
    def __init__(self, pos, time, cr3, non_root):
        # type: (int, Optional[int], int, bool) -> None
        self.cr3 = cr3
        self.non_root = non_root
        super(PagingEvent, self).__init__(pos, time)


class AsyncPagingEvent(TraceEvent):
    def __init__(self, pos, time, ip, cr3, non_root):
        # type: (int, Optional[int], int, int, bool) -> None
        self.cr3 = cr3
        self.non_root = non_root
        self.ip = ip
        super(AsyncPagingEvent, self).__init__(pos, time)


class OverflowEvent(TraceEvent):
    def __init__(self, pos, time, ip):
        # type: (int, Optional[int], Optional[int]) -> None
        self.ip = ip
        super(OverflowEvent, self).__init__(pos, time)


class ExecModeEvent(TraceEvent):
    def __init__(self, pos, time, ip, mode):
        # type: (int, Optional[int], Optional[int], int) -> None
        self.mode = mode
        super(ExecModeEvent, self).__init__(pos, time)


class TsxEvent(TraceEvent):
    def __init__(self, pos, time, ip, aborted, speculative):
        # type: (int, Optional[int], Optional[int], bool, bool) -> None
        self.ip = ip
        self.aborted = aborted
        self.speculative = speculative
        super(TsxEvent, self).__init__(pos, time)


class StopEvent(TraceEvent):
    def __init__(self, pos, time):
        # type: (int, Optional[int]) -> None
        super(StopEvent, self).__init__(pos, time)


class VmcsEvent(TraceEvent):
    def __init__(self, pos, time, base):
        # type: (int, Optional[int], int) -> None
        self.base = base
        super(VmcsEvent, self).__init__(pos, time)


class AsyncVmcsEvent(TraceEvent):
    def __init__(self, pos, time, ip, base):
        # type: (int, Optional[int], int, int) -> None
        self.base = base
        self.ip = ip
        super(AsyncVmcsEvent, self).__init__(pos, time)


class ExstopEvent(TraceEvent):
    def __init__(self, pos, time, ip):
        # type: (int, Optional[int], Optional[int]) -> None
        self.ip = ip
        super(ExstopEvent, self).__init__(pos, time)


class MwaitEvent(TraceEvent):
    def __init__(self, pos, time, ip, hints, ext):
        # type: (int, Optional[int], Optional[int], int, int) -> None
        self.ip = ip
        self.hints = hints
        self.ext = ext
        super(MwaitEvent, self).__init__(pos, time)


class PwreEvent(TraceEvent):
    def __init__(self, pos, time, state, sub_state, hw):
        # type: (int, Optional[int], int, int, bool) -> None
        self.state = state
        self.sub_state = sub_state
        self.hw = hw
        super(PwreEvent, self).__init__(pos, time)


class PwrxEvent(TraceEvent):
    def __init__(self, pos, time, interrupt, store, autonomous, last, deepest):
        # type: (int, Optional[int], bool, bool, bool, int, int) -> None
        self.interrupt = interrupt
        self.store = store
        self.autonomous = autonomous
        self.last = last
        self.deepest = deepest
        super(PwrxEvent, self).__init__(pos, time)


class PtWriteEvent(TraceEvent):
    def __init__(self, pos, time, ip, payload):
        # type: (int, Optional[int], Optional[int], int) -> None
        self.ip = ip
        self.payload = payload
        super(PtWriteEvent, self).__init__(pos, time)


class TickEvent(TraceEvent):
    def __init__(self, pos, time, ip):
        # type: (int, Optional[int], Optional[int]) -> None
        self.ip = ip
        super(TickEvent, self).__init__(pos, time)


class CbrEvent(TraceEvent):
    def __init__(self, pos, time, ratio):
        # type: (int, Optional[int], int) -> None
        self.ratio = ratio
        super(CbrEvent, self).__init__(pos, time)


class MntEvent(TraceEvent):
    def __init__(self, pos, time, payload):
        # type: (int, Optional[int], int) -> None
        self.payload = payload
        super(MntEvent, self).__init__(pos, time)
