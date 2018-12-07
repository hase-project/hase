import logging

from typing import Tuple
from .state import SimState
from .cdanalyzer import CoredumpAnalyzer


l = logging.getLogger(__name__)


def call_init_offset(state: "SimState") -> int:
    # heuristically calculate until sub rsp, imm
    """
        push rbp
        mov rbp, rsp
        ...
        sub rsp, imm

        Thus, rbp = rsp - 8, rsp = rsp - 8n - imm
    """
    blk = state.block()
    insns = blk.capstone.insns
    rsp_offset = 0
    for inst in insns:
        if inst.mnemonic == "push":
            rsp_offset += 8
        elif inst.mnemonic == "pop":
            rsp_offset -= 8
        elif inst.mnemonic == "sub" and inst.operands[0].type == 1:
            reg_name = inst.reg_name(inst.operands[0].reg)
            if "sp" in reg_name and inst.operands[1].type == 2:
                # sub rsp, xxx
                rsp_offset += inst.operands[1].value.imm
                break
    return rsp_offset


def solve_rsp(state: "SimState", cdanalyzer: "CoredumpAnalyzer") -> Tuple[int, int]:
    rsp, rbp = cdanalyzer.stack_base("main")
    if not rsp:
        l.warning("solve_rsp_coredump: failed to fetch rsp value")
        rsp = 0x7FFC68A29900  # input() ???
    rsp_offset = call_init_offset(state)
    return rsp + rsp_offset, 0
