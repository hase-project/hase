from __future__ import absolute_import, division, print_function

from enum import IntEnum
from typing import Optional


class TraceEvent:
    """
    This class is used by the C extension _pt
    """

    def __init__(self, pos: int, time: Optional[int]) -> None:
        self.pos = pos
        self.time = time

    def __repr__(self):
        time = ""
        if self.time is not None:
            time = ", time: 0x%x" % self.time
        return "<%s @ 0x%x%s>" % (self.__class__.__name__, self.pos, time)


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

    def __repr__(self):
        return "<Instruction[%s] @ %x>" % (self.iclass.name, self.ip)


class EnableEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], ip: int, resumed: bool) -> None:
        self.ip = ip
        self.resumed = resumed
        super().__init__(pos, time)


class DisableEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], ip: Optional[int]) -> None:
        self.ip = ip
        super().__init__(pos, time)


class AsyncDisableEvent(TraceEvent):
    def __init__(
        self, pos: int, time: Optional[int], ip: Optional[int], at: int
    ) -> None:
        self.ip = ip
        self.at = at
        super().__init__(pos, time)


class AsyncBranchEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], from_addr: int) -> None:
        self.from_addr = from_addr
        super().__init__(pos, time)


class PagingEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], cr3: int, non_root: bool) -> None:
        self.cr3 = cr3
        self.non_root = non_root
        super().__init__(pos, time)


class AsyncPagingEvent(TraceEvent):
    def __init__(
        self, pos: int, time: Optional[int], ip: int, cr3: int, non_root: bool
    ) -> None:
        self.cr3 = cr3
        self.non_root = non_root
        self.ip = ip
        super().__init__(pos, time)


class OverflowEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], ip: Optional[int]) -> None:
        self.ip = ip
        super().__init__(pos, time)


class ExecModeEvent(TraceEvent):
    def __init__(
        self, pos: int, time: Optional[int], ip: Optional[int], mode: int
    ) -> None:
        self.mode = mode
        super().__init__(pos, time)


class TsxEvent(TraceEvent):
    def __init__(
        self,
        pos: int,
        time: Optional[int],
        ip: Optional[int],
        aborted: bool,
        speculative: bool,
    ) -> None:
        self.ip = ip
        self.aborted = aborted
        self.speculative = speculative
        super().__init__(pos, time)


class StopEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int]) -> None:
        super().__init__(pos, time)


class VmcsEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], base: int) -> None:
        self.base = base
        super().__init__(pos, time)


class AsyncVmcsEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], ip: int, base: int) -> None:
        self.base = base
        self.ip = ip
        super().__init__(pos, time)


class ExstopEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], ip: Optional[int]) -> None:
        self.ip = ip
        super().__init__(pos, time)


class MwaitEvent(TraceEvent):
    def __init__(
        self, pos: int, time: Optional[int], ip: Optional[int], hints: int, ext: int
    ) -> None:
        self.ip = ip
        self.hints = hints
        self.ext = ext
        super().__init__(pos, time)


class PwreEvent(TraceEvent):
    def __init__(
        self, pos: int, time: Optional[int], state: int, sub_state: int, hw: bool
    ) -> None:
        self.state = state
        self.sub_state = sub_state
        self.hw = hw
        super().__init__(pos, time)


class PwrxEvent(TraceEvent):
    def __init__(
        self,
        pos: int,
        time: Optional[int],
        interrupt: bool,
        store: bool,
        autonomous: bool,
        last: int,
        deepest: int,
    ) -> None:
        self.interrupt = interrupt
        self.store = store
        self.autonomous = autonomous
        self.last = last
        self.deepest = deepest
        super().__init__(pos, time)


class PtWriteEvent(TraceEvent):
    def __init__(
        self, pos: int, time: Optional[int], ip: Optional[int], payload: int
    ) -> None:
        self.ip = ip
        self.payload = payload
        super().__init__(pos, time)


class TickEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], ip: Optional[int]) -> None:
        self.ip = ip
        super().__init__(pos, time)


class CbrEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], ratio: int) -> None:
        self.ratio = ratio
        super().__init__(pos, time)


class MntEvent(TraceEvent):
    def __init__(self, pos: int, time: Optional[int], payload: int) -> None:
        self.payload = payload
        super().__init__(pos, time)
