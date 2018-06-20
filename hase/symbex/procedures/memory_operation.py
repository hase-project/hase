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
                    self.state.memory.store(self.args(i), self.state.se.BVS('format_%n', 32))
        return self.state.se.BVS('printf', 32)
'''


class isalnum(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('isalnum', 32)


class iswalnum(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswalnum', 32)


class isalpha(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('isalpha', 32)


class iswalpha(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswalpha', 32)


class islower(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('islower', 32)


class iswlower(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswlower', 32)


class isupper(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('isupper', 32)


class iswupper(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswupper', 32)


class isdigit(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('isdigit', 32)


class iswdigit(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswdigit', 32)


class isxdigit(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('isxdigit', 32)


class iswxdigit(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswxdigit', 32)


class iscntrl(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iscntrl', 32)


class iswcntrl(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswcntrl', 32)


class isgraph(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('isgraph', 32)


class iswgraph(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswgraph', 32)


class isspace(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('isspace', 32)


class iswspace(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswspace', 32)


class isblank(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('isblank', 32)


class iswblank(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswblank', 32)


class isprint(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('isprint', 32)


class iswprint(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswprint', 32)


class ispunct(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('ispunct', 32)


class iswpunct(SimProcedure):
    def run(self, c):
        return self.state.se.BVS('iswpunct', 32)


class strncasecmp(SimProcedure):
    def run(self, a_addr, b_addr, limit):
        return self.state.se.BVS('strncasecmp', self.state.arch.bits)


class strspn(SimProcedure):
    def run(self, str1, str2):
        return self.state.se.BVS('strspn', self.state.arch.bits)


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