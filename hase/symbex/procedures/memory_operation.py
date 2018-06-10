import claripy
from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
from angr.errors import SimProcedureError


# TODO: memccpy, strndup, strncat


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


class __memcpy_chk(SimProcedure):
    def run(self, dest, src, len, destlen):
        memcpy = SIM_PROCEDURES['libc']['memcpy']
        return self.inline_call(memcpy, desr, src, len).ret_expr


class __memmove_chk(SimProcedure):
    def run(self, dest, src, len, destlen):
        return self.inline_call(memmove, dest, src, len).ret_expr


class __mempcpy_chk(SimProcedure):
    def run(self, dest, src, len, destlen):
        return self.inline_call(mempcpy, dest, src, len).ret_expr


class __memset_chk(SimProcedure):
    def run(self, dest, c, len, destlen):
        memset = SIM_PROCEDURES['libc']['memset']
        return self.inline_call(memset, dest, c, len).ret_expr


class __stpcpy_chk(SimProcedure):
    def run(self, dest, src, destlen):
        return self.inline_call(stpcpy, dest, src).ret_expr


class __stpncpy_chk(SimProcedure):
    def run(self, dest, src, n, destlen):
        return self.inline_call(stpncpy, dest, src, n).ret_expr


class __strcat_chk(SimProcedure):
    def run(self, dest, src, destlen):
        strcat = SIM_PROCEDURES['libc']['strcat']
        return self.inline_call(strcat, dest, src).ret_expr


class __strcpy_chk(SimProcedure):
    def run(self, dest, src, destlen):
        strcpy = SIM_PROCEDURES['libc']['strcpy']
        return self.inline_call(strcpy, dest, src).ret_expr


class __strncpy_chk(SimProcedure):
    def run(self, s1, s2, n, s1len):
        strncpy = SIM_PROCEDURES['libc']['strncpy']
        return self.inline_call(strncpy, s1, s2, n).ret_expr


