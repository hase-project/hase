import bisect
from typing import Any, List, Optional, Tuple

from angr import SimState
from claripy.ast.bv import BV
from cle import ELF

from ..annotate import Addr2line
from ..pt import Instruction


class Register:
    def __init__(self, state: "State", name: str, simreg: BV) -> None:
        self.state = state
        self.name = name
        self.simreg = simreg

    @property
    def size(self) -> int:
        return self.simreg.size()

    @property
    def value(self) -> int:
        return self.state.eval(self.simreg)


class RegisterSet:
    def __init__(self, state: "State") -> None:
        self.state = state

    def __getitem__(self, name: str) -> Register:
        reg = getattr(self.state.simstate.regs, name)
        return Register(self.state, name, reg)

    def __setitem__(self, name: str, value: int) -> None:
        setattr(self.state.simstate.regs, name, value)


class Memory:
    def __init__(self, state: "State") -> None:
        self.state = state

    def __getitem__(self, addr: int) -> Optional[int]:
        try:
            byte = self.state.simstate.mem[addr].byte
            return self.state.eval(byte)
        except Exception:
            return None


class State:
    def __init__(
        self,
        index: int,
        from_instruction: Optional[Instruction],
        to_instruction: Instruction,
        from_simstate: Optional[SimState],
        to_simstate: SimState,
    ) -> None:
        self.index = index
        self.from_instruction = from_instruction
        self.to_instruction = to_instruction
        self.from_simstate = from_simstate
        self.to_simstate = to_simstate
        self.is_to_simstate = True
        self.had_coredump_constraints = False

    @property
    def simstate(self) -> SimState:
        if self.is_to_simstate:
            return self.to_simstate
        assert self.from_simstate is not None
        return self.from_simstate

    def eval(self, expression: BV) -> Any:
        return self.simstate.solver.eval(expression)

    def __repr__(self) -> str:
        if self.from_instruction is None:
            return "State(Start -> 0x%x)" % (self.to_instruction.ip)
        else:
            return "State(0x%x -> 0x%x)" % (
                self.from_instruction.ip,
                self.to_instruction.ip,
            )

    @property
    def registers(self) -> RegisterSet:
        return RegisterSet(self)

    @property
    def memory(self) -> Memory:
        return Memory(self)

    def object(self) -> ELF:
        return self.simstate.project.loader.find_object_containing(self.simstate.addr)

    def address(self) -> int:
        return self.simstate.addr

    def location(self) -> Tuple[str, int]:
        """
        Binary of current state
        """
        obj = self.object()
        a = Addr2line()
        a.add_addr(obj, self.simstate.addr)
        return a.compute()[self.simstate.addr]


class StateManager:
    def __init__(self, tracer: Any, length: int) -> None:
        self.tracer = tracer
        self.index_to_state: List[Optional[State]] = [None] * length
        # Better have something like skip-table
        self.ordered_index: List[int] = []
        self.major_index: List[int] = []
        self.last_main_state: Optional[State] = None

    def add(self, state: State) -> None:
        self.index_to_state[state.index] = state
        bisect.insort_left(self.ordered_index, state.index)

    def add_major(self, state: State) -> None:
        # NOTE: major means the interval stubs
        self.add(state)
        bisect.insort_left(self.major_index, state.index)

    @property
    def major_states(self) -> List[State]:
        states = []
        for i in self.major_index:
            state = self.index_to_state[i]
            assert state is not None
            states.append(state)
        return states

    def get_major(self, index: int) -> State:
        state = self.index_to_state[self.major_index[index]]
        assert state is not None
        return state

    @property
    def len_major(self) -> int:
        return len(self.major_index)

    def __len__(self) -> int:
        return len(self.ordered_index)

    def __getitem__(self, index: int) -> Tuple[State, bool]:
        is_new = False
        pos = bisect.bisect_left(self.ordered_index, index)
        if self.ordered_index[pos] != index:
            print("Computing new states")
            is_new = True
            start_pos = self.ordered_index[pos - 1]
            state = self.index_to_state[start_pos]
            assert state is not None
            simstate = state.simstate
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
        state = self.index_to_state[index]
        assert state is not None
        return state, is_new
