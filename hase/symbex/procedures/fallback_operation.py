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
        except:
            if ret_expr:
                return ret_expr
            else:
                return proc.state.se.BVS(name, ret_size)
    return func


class atoi(SimProcedure):
    def run(self, s):
        return self.state.se.BVS('atoi', 32)



