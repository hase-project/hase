from __future__ import absolute_import, division, print_function
from angr import SimState
from cle import ELF
from typing import Dict, Tuple

from ..perf import TRACE_END
from ..annotate import Addr2line


class Register():
    def __init__(self, name, value, size):
        # type: (str, int, int) -> None
        self.name = name
        self.value = value
        self.size = size


class RegisterSet():
    def __init__(self, state):
        # type: (State) -> None
        self.state = state

    def __getitem__(self, name):
        # type: (str) -> Register
        reg = getattr(self.state.simstate.regs, name)
        value = self.state.simstate.solver.eval(reg)
        return Register(name, value, reg.size())

class Memory():
    def __init__(self, state):
        # type: (State) -> None
        self.state = state

    def __getitem__(self, addr):
        # type: (int) -> int
        # good idea?
        byte = self.state.simstate.mem[addr].byte
        try:
            return self.state.simstate.solver.eval(byte)
        except Exception:
            return None


class State():
    def __init__(self, branch, simstate):
        # type: (Tuple[int, int], SimState) -> None
        self.branch = branch
        self.simstate = simstate

    def __repr__(self):
        # () -> str
        if self.branch[0] == 0:
            return "State(Start -> 0x%x)" % (self.branch[1])
        elif self.branch[1] == TRACE_END:
            return "State(0x%x -> End)" % (self.branch[0])
        else:
            return "State(0x%x -> 0x%x)" % (self.branch[0], self.branch[1])

    @property
    def registers(self):
        # () -> Registers
        return RegisterSet(self)

    @property
    def memory(self):
        # () -> Memory
        return Memory(self)

    def object(self):
        # () -> ELF
        return self.simstate.project.loader.find_object_containing(self.simstate.addr)

    def address(self):
        # () -> int
        return self.simstate.addr

    def location(self):
        """
        Binary of current state
        """
        # () -> Dict[str, int]
        obj = self.object()
        a = Addr2line()
        a.add_addr(obj, self.simstate.addr)
        return a.compute()[self.simstate.addr]
