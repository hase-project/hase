import claripy
from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
from angr.errors import SimProcedureError


# TODO: memmove, memccpy, strndup


class mempcpy(SimProcedure):
    def run(self, dst_addr, src_addr, limit):
        memcpy = SIM_PROCEDURES['libc']['memcpy']
        _ = self.inline_call(memcpy, dst_addr, src_addr, limit).ret_expr
        return dst_addr + limit


# FIXME: overlap problem?
class memmove(SimProcedure):
    def run(self, dst_addr, src_addr, limit):
        memcpy = SIM_PROCEDURES['libc']['memcpy']
        return self.inline_call(memcpy, dst_addr, src_addr, limit).ret_expr


class stpcpy(SimProcedure):
    def run(self, dst, src):
        strlen = SIM_PROCEDURES['libc']['strlen']
        strcpy = SIM_PROCEDURES['libc']['strcpy']
        src_len_expr = self.inline_call(strlen, src).ret_expr
        ret_expr = self.inline_call(strcpy, dst, src).ret_expr
        return ret_expr + src_len_expr


class stpncpy(SimProcedure):
    def run(self, dst, src, n):
        strlen = SIM_PROCEDURES['libc']['strlen']
        strncpy = SIM_PROCEDURES['libc']['strncpy']
        src_len_expr = self.inline_call(strlen, src).ret_expr
        ret_expr = self.inline_call(strncpy, dst, src, n, src_len=src_len_expr).ret_expr
        ret_size = self.state.se.If(self.state.se.ULE(n, src_len_expr), n, src_len_expr)
        return ret_expr + ret_size



