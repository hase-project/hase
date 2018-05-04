from __future__ import absolute_import, division, print_function

import nose

from hase import main

from .helper import TEST_BIN


def argc(simstate):
    """
    argc is on the stack in main/_start for both programs:
    """
    # equivalent (uint64_t)*rsp
    s = simstate
    return s.mem[s.solver.eval(s.regs.rsp)].uint64_t.concrete


def test_control_loopy():
    control_flow = TEST_BIN.join("loopy")
    exe = str(control_flow.join("loopy"))
    trace = str(control_flow.join("loopy-20180404T162955.trace"))
    core = str(control_flow.join("loopy-20180404T162955.coredump"))

    state = main(["hase", "replay", exe, trace, core])
    last_state = state[-1]
    # We called loopy with 6 arguments:
    # ./loopy a b c d e
    nose.tools.eq_(argc(last_state.simstate), 6)


def test_control_flow():
    control_flow = TEST_BIN.join("control_flow")
    exe = str(control_flow.join("control_flow"))
    core = str(control_flow.join("control_flow-20180404T163033.coredump"))
    trace = str(control_flow.join("control_flow-20180404T163033.trace"))

    state = main(["hase", "replay", exe, trace, core])
    last_state = state[-1]
    nose.tools.eq_(last_state.simstate.solver.eval(last_state.simstate.regs.rip), 0x400a05)
