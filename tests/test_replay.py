# FIXME: Inconsistent interface for replay
from __future__ import absolute_import, division, print_function

import nose

from hase import main

import logging

from .helper import TEST_BIN


def argc(simstate):
    """
    argc is on the stack in main/_start for both programs:
    """
    # equivalent (uint64_t)*rsp
    s = simstate
    return s.mem[s.solver.eval(s.regs.rsp)].uint64_t.concrete


def test_loopy():
    state = main([
        "hase", "replay",
        str(TEST_BIN.join("loopy", "loopy-20180514T145114.tar.gz"))
    ])
    last_state = state[-1]
    # We called loopy with 6 arguments:
    # ./loopy a b c d e
    nose.tools.eq_(argc(last_state.simstate), 6)


#def test_control_flow():
#    control_flow = TEST_BIN.join("control_flow")
#    exe = str(control_flow.join("control_flow"))
#    core = str(control_flow.join("control_flow-20180404T163033.coredump"))
#    trace = str(control_flow.join("control_flow-20180404T163033.trace"))
#
#    state = main(["hase", "replay", exe, trace, core])
#    last_state = state[-1]
#    nose.tools.eq_(
#        last_state.simstate.solver.eval(last_state.simstate.regs.rip),
#        0x400a05)
