from __future__ import absolute_import, division, print_function
from angr import SimState
from cle import ELF
from typing import Dict, Tuple, Optional, List, Union

from ..perf import TRACE_END, Branch
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
        # type: (int) -> Optional[int]
        # good idea?
        byte = self.state.simstate.mem[addr].byte
        try:
            return self.state.simstate.solver.eval(byte)
        except Exception:
            return None


class State():
    def __init__(self, branch, simstate):
        # type: (Branch, SimState) -> None
        self.branch = branch
        self.simstate = simstate

    def __repr__(self):
        # () -> str
        if self.branch.addr == 0:
            return "State(Start -> 0x%x)" % (self.branch.ip)
        elif self.branch.ip == TRACE_END:
            return "State(0x%x -> End)" % (self.branch.addr)
        else:
            return "State(0x%x -> 0x%x)" % (self.branch.addr, self.branch.ip)

    @property
    def registers(self):
        # type: () -> RegisterSet
        return RegisterSet(self)

    @property
    def memory(self):
        # type: () -> Memory
        return Memory(self)

    def object(self):
        # type: () -> ELF
        return self.simstate.project.loader.find_object_containing(self.simstate.addr)

    def address(self):
        # type: () -> int
        return self.simstate.addr

    def location(self):
        # type: () -> List[Union[str, int]]
        """
        Binary of current state
        """
        obj = self.object()
        a = Addr2line()
        a.add_addr(obj, self.simstate.addr)
        return a.compute()[self.simstate.addr]
