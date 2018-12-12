from typing import Any, List, Tuple

from claripy.ast.bool import Bool

from ..pwn_wrapper import Coredump
from .state import SimState, State, StateManager
from .tracer import Tracer


def add_stack_constraints(
    state: "SimState", coredump: "Coredump", init_rsp: int, final_rsp: int
) -> List[Bool]:
    coredump_constraints: List[Bool] = []

    for addr in range(final_rsp, init_rsp + 1):
        value = state.memory.load(addr, 1, endness="Iend_LE")
        if value.variables == frozenset():
            continue
        cmem = coredump.stack[addr]
        coredump_constraints.append(value == cmem)
    return coredump_constraints


def calculate_rsp(
    start_state: "SimState", final_state: "SimState", coredump: "Coredump"
) -> Tuple[int, int]:
    low_v = coredump.registers["rsp"]
    high_v = start_state.reg_concrete("rsp")
    return low_v, high_v


def calc_constraints(
    start_state: "SimState", final_state: "SimState", coredump: "Coredump"
) -> List[Bool]:
    final_rsp, init_rsp = calculate_rsp(start_state, final_state, coredump)
    return add_stack_constraints(final_state, coredump, init_rsp, final_rsp)


def apply_constraints(state: "State", constraints: List[Bool]) -> None:
    if not state.had_coredump_constraints:
        for c in constraints:
            old_solver = state.simstate.solver._solver.branch()
            state.simstate.solver.add(c)
            if not state.simstate.solver.satisfiable():
                print("Unsatisfiable coredump constraints: {}".format(c))
                state.simstate.solver._stored_solver = old_solver
        state.had_coredump_constraints = True


def general_apply(tracer: Tracer, states: StateManager) -> None:
    start_state = tracer.start_state
    final_state = states.major_states[-1].simstate
    apply_state = states.last_main_state
    assert apply_state is not None
    coredump = tracer.coredump
    constraints = calc_constraints(start_state, final_state, coredump)
    apply_constraints(apply_state, constraints)
