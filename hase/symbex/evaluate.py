from .state import SimState
from ..gdb import GdbServer
from typing import Any, Dict, Tuple


def eval_value(state: SimState, value: Any) -> str:
    if value.uninitialized:
        return "uninitialized"
    try:
        v = hex(state.solver.eval(value))
    except Exception:
        v = "symbolic"
    return v


def eval_variable(state: SimState, loc: int, addr: Any, size: int) -> Tuple[str, str]:

    if loc == 1:
        mem = state.memory.load(addr, size, endness="Iend_LE")
    elif loc == 2:
        mem = getattr(state.regs, addr)
    elif loc == -1:
        return "optimized", "unknown"
    else:
        return "gdb error", "unknown"

    if mem.uninitialized and mem.variables != frozenset() and loc == 1:
        result = ""
        for i in range(size):
            value = state.memory.load(addr + i, 1, endness="Iend_LE")
            if value.uninitialized:
                result += "** "
                continue
            try:
                v = hex(state.solver.eval(value))[2:]
                if len(v) == 1:
                    v = "0" + v
            except Exception:
                v = "Er"
            result += v + " "
        result = result[:-1]
        return result, "array"
    else:
        v = eval_value(state, mem)
        if v == "uninitialized" or v == "symbolic":
            return v, "unknown"
        return v, "hex"


def report_variable(gdbs: GdbServer) -> Dict[str, Tuple[Any, str]]:
    variables = gdbs.read_variables()
    var_dict = {}
    state = gdbs.active_state.simstate
    for var in variables:
        value, value_t = eval_variable(state, var["loc"], var["addr"], var["size"])
        var_dict[var["name"]] = (value, value_t)
    return var_dict
