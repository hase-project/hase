from __future__ import absolute_import, division, print_function

from typing import Any, Dict, List, Optional, Tuple


def add_stack_constraints(
    state : "SimState", coredump : "Coredump",
    init_rsp: str, final_rsp : str):
    coredump_constraints: List[Any] = []

    for addr in range(final_rsp, init_rsp + 1):
        value = state.memory.load(addr, 1, endness="Iend_LE")
        if value.variables == frozenset():
            continue
        cmem = coredump.stack[addr]
        coredump_constraints.append(value == cmem)
    return coredump_constraints


def calculate_rsp(
    start_state : "SimState",
    final_state : "SimState",
    coredump : "Coredump") -> Tuple[int, int]:
    try:
        low_v = final_state.reg_concrete('rsp')
    except Exception:
        low_v = coredump.stack.start
    try:
        high_v = start_state.reg_concrete('rsp')
    except Exception:
        high_v = coredump.stack.stop
    return low_v, high_v


def calc_constraints(
    start_state : "SimState", final_state : "SimState",
    coredump : "Coredump"):
    final_rsp, init_rsp = calculate_rsp(start_state, final_state, coredump)
    return add_stack_constraints(final_state, coredump, init_rsp, final_rsp)


def apply_constraints(state : "SimState", constraints):
    if not state.had_coredump_constraints:
        for c in constraints:
            old_solver = state.simstate.solver._solver.branch()
            state.simstate.se.add(c)
            if not state.simstate.se.satisfiable():
                print(f"Unsatisfiable coredump constraints: {c}")
                state.simstate.solver._stored_solver = old_solver
        state.had_coredump_constraints = True
