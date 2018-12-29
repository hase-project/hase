import ctypes as ct
from typing import List

from angr import Project, SimState
from angr import sim_options as so
from archinfo import Endness

from ..pt import Instruction, InstructionClass
from ..pwn_wrapper import Coredump
from .cdanalyzer import CoredumpAnalyzer
from .rspsolver import solve_rsp

ADD_OPTIONS = {
    so.TRACK_JMP_ACTIONS,
    so.CONSERVATIVE_READ_STRATEGY,
    so.CONSERVATIVE_WRITE_STRATEGY,
    so.BYPASS_UNSUPPORTED_IRCCALL,
    so.BYPASS_UNSUPPORTED_IRDIRTY,
    so.CONSTRAINT_TRACKING_IN_SOLVER,
    so.COPY_STATES,
    so.BYPASS_UNSUPPORTED_IROP,
    so.BYPASS_UNSUPPORTED_IREXPR,
    so.BYPASS_UNSUPPORTED_IRSTMT,
    so.BYPASS_UNSUPPORTED_SYSCALL,
    so.BYPASS_ERRORED_IROP,
    so.BYPASS_ERRORED_IRCCALL,
    # so.DOWNSIZE_Z3,
}

REMOVE_SIMPLIFICATIONS = {
    so.LAZY_SOLVES,
    so.EFFICIENT_STATE_MERGING,
    so.TRACK_CONSTRAINT_ACTIONS,
    # so.ALL_FILES_EXIST, # the problem is, when having this, simfd either None or exist, no If
} | so.simplification


def _setup_argv(state: SimState, coredump: Coredump) -> SimState:
    # argv follows argc
    argv_addr = coredump.argc_address + ct.sizeof(ct.c_int)
    # TODO: if argv is modified by users, this won't help
    for i, arg in enumerate(coredump.argv):
        state.memory.store(argv_addr + i * 8, arg, endness=Endness.LE)
        state.memory.store(arg, coredump.string(arg)[::-1], endness=Endness.LE)


def create_start_state(
    project: Project, trace: List[Instruction], cdanalyzer: CoredumpAnalyzer
) -> SimState:
    start_address = trace[0].ip

    coredump = cdanalyzer.coredump
    args = [coredump.argc]
    args += [coredump.string(argv) for argv in coredump.argv]
    state = project.factory.call_state(
        start_address,
        *args,
        add_options=ADD_OPTIONS,
        remove_options=REMOVE_SIMPLIFICATIONS
    )
    rsp, _ = solve_rsp(state, cdanalyzer)
    state.regs.rsp = rsp
    _setup_argv(state, coredump)
    return state
