from __future__ import absolute_import, division, print_function

import logging

import nose

from hase import main

from .helper import TEST_TRACES


def test_loopy() -> None:
    state = main(
        ["hase", "replay", str(TEST_TRACES.joinpath("loopy-20181009T182008.tar.gz"))]
    )
    (last_state, is_new) = state[len(state) - 2]
    # We called loopy with 6 arguments:
    # ./loopy a b c d e
    s = last_state.simstate
    # loopy does not touch rsp so we can get the location of argc by dereferencing
    # the top of the stack
    argc = s.mem[s.solver.eval(s.regs.rsp)].uint64_t.concrete
    nose.tools.eq_(argc, 6)


def test_control_flow() -> None:
    state = main(
        [
            "hase",
            "replay",
            str(TEST_TRACES.joinpath("control_flow-20181003T145029.tar.gz")),
        ]
    )

def test_vdso() -> None:
    state = main(
        [
            "hase",
            "replay",
            str(TEST_TRACES.joinpath("vdso-20190122T125134.tar.gz")),
        ]
    )
