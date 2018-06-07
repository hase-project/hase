from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES


# TODO: getenv, atexit?


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


# FIXME: do real things
# NOTE: angr sigaction does nothing now
class sigaction(SimProcedure):
    def run(self, signum, act, oact):
        return self.state.se.BVV(0, self.state.arch.bits)


# FIXME: do real things
class atexit(SimProcedure):
    def run(self, func_ptr):
        return self.state.se.BVV(0, self.state.arch.bits)


class __cxa_atexit(SimProcedure):
    def run(self, func_ptr, arg, dso_handle):
        return self.state.se.BVV(0, self.state.arch.bits)