import claripy
from angr import SimProcedure


class atof(SimProcedure):
    def run(self, ptr) -> claripy.BVV:
        return self.state.solver.FPS("atof", self.state.solver.fp.FSORT_DOUBLE)


class strtof(SimProcedure):
    def run(self, nptr, endptr) -> claripy.BVV:
        return self.state.solver.FPS("strtof", self.state.solver.fp.FSORT_FLOAT)


class strtof_l(SimProcedure):
    def run(self, nptr, endptr, locale) -> claripy.BVV:
        return self.state.solver.FPS("strtof_l", self.state.solver.fp.FSORT_FLOAT)


class strtod(SimProcedure):
    def run(self, nptr, endptr) -> claripy.BVV:
        return self.state.solver.FPS("strtod", self.state.solver.fp.FSORT_DOUBLE)


class strtod_l(SimProcedure):
    def run(self, nptr, endptr, locale) -> claripy.BVV:
        return self.state.solver.FPS("strtod_l", self.state.solver.fp.FSORT_DOUBLE)


# FIXME: no long double in claripy.fp now
class strtold(SimProcedure):
    def run(self, nptr, endptr) -> claripy.BVV:
        return self.state.solver.FPS("strtold", self.state.solver.fp.FSORT_DOUBLE)


class strtold_l(SimProcedure):
    def run(self, nptr, endptr, locale) -> claripy.BVV:
        return self.state.solver.FPS("strtold_l", self.state.solver.fp.FSORT_DOUBLE)


class strspn(SimProcedure):
    def run(self, str1, str2) -> claripy.BVV:
        return self.state.solver.Unconstrained(
            "strspn", self.state.arch.bits, uninitialized=False
        )


class strcspn(SimProcedure):
    def run(self, str1, str2) -> claripy.BVV:
        return self.state.solver.Unconstrained(
            "strspn", self.state.arch.bits, uninitialized=False
        )
