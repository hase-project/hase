from __future__ import absolute_import, division, print_function

import claripy
from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
from angr.errors import SimProcedureError


# TODO: memccpy, strndup, strncat
class strnlen(SimProcedure):
    def run(self, s, maxlen):
        strlen = SIM_PROCEDURES['libc']['strlen']
        len_expr = self.inline_call(strlen, s).ret_expr
        return self.state.se.If(
            len_expr > maxlen,
            maxlen,
            len_expr
        )


class mempcpy(SimProcedure):
    def run(self, dst_addr, src_addr, limit):
        memcpy = SIM_PROCEDURES['libc']['memcpy']
        _ = self.inline_call(memcpy, dst_addr, src_addr, limit).ret_expr
        return dst_addr + limit


"""
# FIXME: overlap problem?
class memmove(SimProcedure):
    def run(self, dst_addr, src_addr, limit):
        print(dst_addr, src_addr, limit)
        memcpy = SIM_PROCEDURES['libc']['memcpy']
        _ = self.inline_call(memcpy, dst_addr, src_addr, limit).ret_expr
        return dst_addr
"""


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
        return self.inline_call(memcpy, dest, src, len).ret_expr


class __memmove_chk(SimProcedure):
    def run(self, dest, src, len, destlen):
        memcpy = SIM_PROCEDURES['libc']['memcpy']
        return self.inline_call(memcpy, dest, src, len).ret_expr


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


'''
class printf(FormatParser):
    ARGS_MISMATCH = True
    def run(self):
        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1

        fmt_str = self._parse(0)
        if fmt_str:
            for i, c in enumerate(fmt_str.components):
                if c.spec_type == 'n':
                    self.state.memory.store(self.args(i), self.state.se.Unconstrained('format_%n', 32, uninitialized=False))
        return self.state.se.Unconstrained('printf', 32, uninitialized=False)
'''


class isalnum(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('isalnum', 32, uninitialized=False)


class iswalnum(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswalnum', 32, uninitialized=False)


class isalpha(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('isalpha', 32, uninitialized=False)


class iswalpha(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswalpha', 32, uninitialized=False)


class islower(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('islower', 32, uninitialized=False)


class iswlower(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswlower', 32, uninitialized=False)


class isupper(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('isupper', 32, uninitialized=False)


class iswupper(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswupper', 32, uninitialized=False)


class isdigit(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('isdigit', 32, uninitialized=False)


class iswdigit(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswdigit', 32, uninitialized=False)


class isxdigit(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('isxdigit', 32, uninitialized=False)


class iswxdigit(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswxdigit', 32, uninitialized=False)


class iscntrl(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iscntrl', 32, uninitialized=False)


class iswcntrl(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswcntrl', 32, uninitialized=False)


class isgraph(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('isgraph', 32, uninitialized=False)


class iswgraph(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswgraph', 32, uninitialized=False)


class isspace(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('isspace', 32, uninitialized=False)


class iswspace(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswspace', 32, uninitialized=False)


class isblank(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('isblank', 32, uninitialized=False)


class iswblank(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswblank', 32, uninitialized=False)


class isprint(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('isprint', 32, uninitialized=False)


class iswprint(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswprint', 32, uninitialized=False)


class ispunct(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('ispunct', 32, uninitialized=False)


class iswpunct(SimProcedure):
    def run(self, c):
        return self.state.se.Unconstrained('iswpunct', 32, uninitialized=False)


class strncasecmp(SimProcedure):
    def run(self, a_addr, b_addr, limit):
        return self.state.se.Unconstrained('strncasecmp', self.state.arch.bits, uninitialized=False)


class strspn(SimProcedure):
    def run(self, str1, str2):
        return self.state.se.Unconstrained('strspn', self.state.arch.bits, uninitialized=False)


class memchr(SimProcedure):
    def run(self, ptr, ch, count):
        strchr = SIM_PROCEDURES['libc']['strchr']
        ret_expr = self.inline_call(strchr, ptr, ch).ret_expr
        return self.state.se.If(
            'exceed_count',
            ret_expr,
            self.state.se.BVV(0, self.state.arch.bits)
        )


# TODO: add strrchr and memrchr?

class malloc_usable_size(SimProcedure):
    def run(self, ptr):
        # FIXME: should have a heap tracking system
        # incur memset exception, then libc.max_buffer_size
        return self.state.se.Unconstrained('malloc_useable_size', self.state.arch.bits)


class strchrnul(SimProcedure):
    def run(self, ptr, ch):
        strchr = SIM_PROCEDURES['libc']['strchr']
        strlen = SIM_PROCEDURES['libc']['strlen']
        ret_expr = self.inline_call(strchr, ptr, ch).ret_expr
        len_expr = self.inline_call(strlen, ptr).ret_expr
        return self.state.se.If(
            ret_expr == 0,
            ptr + len_expr,
            ret_expr
        )
