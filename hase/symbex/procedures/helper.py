from __future__ import absolute_import, division, print_function

from ... import errors

# Need to resymbolize hooks

import angr


def test_concrete_value(proc, sym, value):
    if not proc.state.se.symbolic(sym):
        if proc.state.se.eval(sym) == value:
            return True
    return False


def errno_success(proc):
    return proc.state.se.If(
        proc.state.se.BoolS('errno'),
        proc.state.se.BVV(0, proc.state.arch.bits),
        proc.state.se.BVV(-1, proc.state.arch.bits)
    )


def null_success(proc, sym):
    return proc.state.se.If(
        proc.state.se.BoolS('errno'),
        sym,
        proc.state.se.BVV(0, proc.state.arch.bits)
    )


def minmax(proc, sym, upper=None):
    try:
        min_v = proc.state.se.min(sym)
        max_v = proc.state.se.max(sym)
        if upper:
            return max(min_v, min(max_v, upper))
        return max_v
    except angr.SimUnsatError:
        if upper:
            return upper
        else:
            raise errors.HaseError("Cannot eval value")
