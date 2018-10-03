from __future__ import absolute_import, division, print_function

import claripy
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES

from .helper import errno_success


# NOTE: since angr SimProcedure check arguments, we cannot directly hook with *args
def generate_run(lib, name, ret_size=32, ret_expr=None):
    def func(proc, *args, **kwargs):
        try:
            fn = SIM_PROCEDURES[lib][name]
            return proc.inline_call(fn, *args, **kwargs).ret_expr
        except Exception:
            if ret_expr:
                return ret_expr
            else:
                return proc.state.se.Unconstrained(name, ret_size, uninitialized=False)
    return func


class atoi(SimProcedure):
    def run(self, s):
        return self.state.se.Unconstrained('atoi', 32, uninitialized=False)



