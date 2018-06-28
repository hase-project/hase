from __future__ import absolute_import, division, print_function
import bisect
from angr import SimState
from cle import ELF
from typing import Dict, Tuple, Optional, List, Union, Any
from claripy.ast.bv import BV

from ..perf import Branch
from ..annotate import Addr2line


class Register(object):
    def __init__(self, state, name, simreg):
        # type: (State, str, BV) -> None
        self.state = state
        self.name = name
        self.simreg = simreg

    @property
    def size(self):
        # type: () -> int
        return self.simreg.size()

    @property
    def value(self):
        # type: () -> int
        return self.state.eval(self.simreg)


class RegisterSet(object):
    def __init__(self, state):
        # type: (State) -> None
        self.state = state

    def __getitem__(self, name):
        # type: (str) -> Register
        reg = getattr(self.state.simstate.regs, name)
        return Register(self.state, name, reg)

    def __setitem__(self, name, value):
        # type: (str, int) -> None
        setattr(self.state.simstate.regs, name, value)


class Memory(object):
    def __init__(self, state):
        # type: (State) -> None
        self.state = state

    def __getitem__(self, addr):
        # type: (int) -> Optional[int]
        # good idea?
        byte = self.state.simstate.mem[addr].byte
        try:
            return self.state.eval(byte)
        except Exception:
            return None


class State(object):
    def __init__(self, index, branch, from_simstate, to_simstate):
        # type: (int, Branch, SimState, SimState) -> None
        self.index = index
        self.branch = branch
        self.from_simstate = from_simstate
        self.to_simstate = to_simstate
        self.simstate = to_simstate

    def eval(self, expression):
        # type: (BV) -> Any
        return self.simstate.solver.eval(expression)

    def __repr__(self):
        # () -> str
        if self.branch.addr == 0:
            return "State(Start -> 0x%x)" % (self.branch.ip)
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
        return self.simstate.project.loader.find_object_containing(
            self.simstate.addr)

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


class StateManager(object):
    def __init__(self, length):
        self.index_to_state = [None] * length
        self.ordered_index = []
    
    def add(self, state):
        self.index_to_state[state.index] = state
        bisect.insort_left(self.ordered_index, state.index)
    
    def __getitem__(self, index):
        pos = bisect.bisect_left(self.ordered_index, index)
        if self.ordered_index[pos] == index:
            return self.index_to_state[index]
        else:
            # TODO: recompute from last
            start_pos = self.ordered_index[pos]
            start_state = self.index_to_state[start_pos]
            return None