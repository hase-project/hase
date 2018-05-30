from angr.sim_type import *
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES

all_hookable_symbols = {}
for lib, funcs in SIM_PROCEDURES.items():
    if not lib.startswith("win"):
        for name, proc in funcs.items():
            all_hookable_symbols[name] = [proc]


class setlocale(SimProcedure):
    def run(self, category, locale):
        self.argument_types = {
            0: SimTypeInt(32, True),
            1: self.ty_ptr(SimTypeString())
        }
        self.return_type = self.ty_ptr(SimTypeString())
        # FIXME: should have better solution
        addr = self.state.libc.heap_location
        self.state.libc.heap_location += 1
        self.state.memory.store(addr, "\x00")
        return addr

all_hookable_symbols['setlocale'] = [setlocale]