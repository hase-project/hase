from __future__ import absolute_import, division, print_function

import bisect
from typing import Any, Dict, List, Optional, Tuple

from angr import SimState
from claripy.ast.bv import BV
from cle import ELF

from ..annotate import Addr2line
from ..pt.events import Instruction


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
        return self.state.eval(byte)


class State(object):
    def __init__(
        self, index, from_instruction, to_instruction, from_simstate, to_simstate
    ):
        # type: (int, Optional[Instruction], Instruction, Optional[SimState], SimState) -> None
        self.index = index
        self.from_instruction = from_instruction
        self.to_instruction = to_instruction
        self.from_simstate = from_simstate
        self.to_simstate = to_simstate
        self.is_to_simstate = True

    @property
    def simstate(self):
        # type: () -> SimState
        if self.is_to_simstate:
            return self.to_simstate
        assert self.from_simstate is not None
        return self.from_simstate

    def eval(self, expression):
        # type: (BV) -> Any
        return self.simstate.solver.eval(expression)

    def __repr__(self):
        # type: () -> str
        if self.from_instruction is None:
            return "State(Start -> 0x%x)" % (self.to_instruction.ip)
        else:
            return "State(0x%x -> 0x%x)" % (
                self.from_instruction.ip,
                self.to_instruction.ip,
            )

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
        # type: () -> Tuple[str, int]
        """
        Binary of current state
        """
        obj = self.object()
        a = Addr2line()
        a.add_addr(obj, self.simstate.addr)
        return a.compute()[self.simstate.addr]


class StateManager(object):
    def __init__(self, tracer, length):
        # type: (Any, int) -> None
        self.tracer = tracer
        self.index_to_state = [None] * length  # type: List[Optional[State]]
        # Better have something like skip-table
        self.ordered_index = []  # type: List[int]
        self.major_index = []  # type: List[int]

    def add(self, state):
        # type: (State) -> None
        self.index_to_state[state.index] = state
        bisect.insort_left(self.ordered_index, state.index)

    def add_major(self, state):
        # type: (State) -> None
        # NOTE: major means the interval stubs
        self.add(state)
        bisect.insort_left(self.major_index, state.index)

    @property
    def major_states(self):
        return [self.index_to_state[i] for i in self.major_index]

    def get_major(self, index):
        # type: (int) -> State
        return self.index_to_state[self.major_index[index]]  # type: ignore

    @property
    def len_major(self):
        return len(self.major_index)

    def __len__(self):
        # type: () -> int
        return len(self.ordered_index)

    def __getitem__(self, index):
        # type: (int) -> Tuple[State, bool]
        is_new = False
        pos = bisect.bisect_left(self.ordered_index, index)
        if self.ordered_index[pos] != index:
            print("Computing new states")
            is_new = True
            start_pos = self.ordered_index[pos - 1]
            simstate = self.index_to_state[start_pos].simstate  # type: ignore
            diff = index - start_pos
            for i in range(diff):
                from_instruction = self.tracer.trace[start_pos + i]
                to_instruction = self.tracer.trace[start_pos + i + 1]
                from_simstate, simstate = self.tracer.execute(
                    simstate, from_instruction, to_instruction, index
                )
                if diff - i < 15:
                    self.add(
                        State(
                            start_pos + i + 1,
                            from_instruction,
                            to_instruction,
                            from_simstate,
                            simstate,
                        )
                    )
        return self.index_to_state[index], is_new  # type: ignore
