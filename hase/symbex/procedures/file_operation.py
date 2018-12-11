import claripy
from angr import SimProcedure
from angr.errors import SimUnsatError
from angr.procedures import SIM_PROCEDURES
from cle.backends.externs.simdata.io_file import io_file_data_for_arch
from angr.procedures.stubs.format_parser import FormatParser

from .helper import minmax
from .syscall import lstat, stat

# NOTE: if we hook one of the file operation, we need to hook all of these
# Or the FILE struct will be inconsistent. But if we don't use them, angr's IO operations will have wrong branch
# TODO: fsetpos, fgetpos, statfs, fstatfs
# freopen, openat, __fbufsize, __fpending, flushlbf, fpurge
# vprintf, vfprintf, vsprintf, vsnprintf
# TODO: maybe load concrete file?


class vfprintf(SimProcedure):
    ARGS_MISMATCH = True

    # mov rsp, [rbp+xx]
    def run(self, file_ptr, fmt, ap) -> claripy.BVV:
        return self.state.solver.Unconstrained("vfprintf_ret", 32, uninitialized=False)


class ferror(SimProcedure):
    def run(self, file_ptr) -> claripy.BVV:
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fileno = self.state.mem[file_ptr + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return None
        # FIXME: no error concept in SimFile
        return 0


# NOTE: invoked by putchar (while inlined)
# FIXME: no overflow concept in SimFile, low-fieldity simulation then
class __overflow(SimProcedure):
    def run(self, file_ptr, ch) -> claripy.BVV:
        fputc = SIM_PROCEDURES["libc"]["fputc"]
        ret_expr = self.inline_call(fputc, ch, file_ptr).ret_expr
        return ret_expr


class __underflow(SimProcedure):
    def run(self, file_ptr) -> claripy.BVV:
        return self.state.solver.Unconstrained("__underflow", 32, uninitialized=False)


# NOTE: invoked by getc
# TODO: https://code.woboq.org/userspace/glibc/libio/genops.c.html
class __uflow(SimProcedure):
    def run(self, file_ptr) -> claripy.BVV:
        return self.state.solver.Unconstrained("__uflow", 32, uninitialized=False)


class ftello(SimProcedure):
    def run(self, file_ptr) -> claripy.BVV:
        ftell = SIM_PROCEDURES["libc"]["ftell"]
        ret_expr = self.inline_call(ftell, file_ptr).ret_expr
        # FIXME: Acutally off_t
        return ret_expr


class fseeko(SimProcedure):
    def run(self, fp, offset, whence) -> claripy.BVV:
        fseek = SIM_PROCEDURES["libc"]["fseek"]
        # FIXME: Actually offset: off_t
        ret_expr = self.inline_call(fseek, fp, offset, whence).ret_expr
        return ret_expr


# FIXME: complete this
class freopen(SimProcedure):
    INCOMPLETE = True

    def run(self, file_ptr, mode_ptr, stream_ptr) -> claripy.BVV:
        pass


# NOTE: posix extra
# http://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/baselib-xstat-1.html
class __xstat(SimProcedure):
    def run(self, ver, file_path, stat_buf) -> claripy.BVV:
        ret_expr = self.inline_call(stat, file_path, stat_buf).ret_expr
        return ret_expr


class __fxstat(SimProcedure):
    def run(self, ver, fd, stat_buf) -> claripy.BVV:
        fstat = SIM_PROCEDURES["linux_kernel"]["fstat"]
        ret_expr = self.inline_call(fstat, fd, stat_buf).ret_expr
        return ret_expr


class __lxstat(SimProcedure):
    def run(self, ver, file_path, stat_buf) -> claripy.BVV:
        ret_expr = self.inline_call(lstat, file_path, stat_buf).ret_expr
        return ret_expr


# TODO: how to handle with va_list?
class vprintf(SimProcedure):
    INCOMPLETE = True

    def run(self, fmt, va_list) -> claripy.BVV:
        return None


"""
FIXME: pwd maybe different
NOTE:
    In GNU, if BUF is NULL,
    an array is allocated with `malloc'; the array is SIZE
    bytes long, unless SIZE == 0, in which case it is as
    big as necessary.
"""


class getcwd(SimProcedure):
    def run(self, buf, size) -> claripy.BVV:
        _getcwd = SIM_PROCEDURES["linux_kernel"]["getcwd"]
        malloc = SIM_PROCEDURES["libc"]["malloc"]
        if not self.state.solver.symbolic(buf):
            buf_v = self.state.solver.eval(buf)
            if buf_v == 0:
                cwd = self.state.fs.cwd
                new_size = self.state.solver.If(size - 1 > len(cwd), len(cwd), size - 1)
                buf = self.inline_call(malloc, new_size).ret_expr
        return self.inline_call(_getcwd, buf, size).ret_expr


# NOTE: if allow-read
class __freadable(SimProcedure):
    def run(self, file_ptr) -> claripy.BVV:
        return self.state.solver.If(
            self.state.solver.BoolS("file_readable"), self.state.solver.BVV(1, 32), 0
        )


# NOTE: if allow-write
class __fwritable(SimProcedure):
    def run(self, file_ptr) -> claripy.BVV:
        return self.state.solver.If(
            self.state.solver.BoolS("file_writable"), self.state.solver.BVV(1, 32), 0
        )


# NOTE: if read-only or last operation read
class __freading(SimProcedure):
    def run(self, file_ptr) -> claripy.BVV:
        return self.state.solver.If(
            self.state.solver.BoolS("file_reading"), self.state.solver.BVV(1, 32), 0
        )


# NOTE: if write-only or last operation write
class __fwriting(SimProcedure):
    def run(self, file_ptr) -> claripy.BVV:
        return self.state.solver.If(
            self.state.solver.BoolS("file_writing"), self.state.solver.BVV(1, 32), 0
        )


# NOTE: If line-buffered
class __flbf(SimProcedure):
    def run(self, file_ptr) -> claripy.BVV:
        return self.state.solver.If(
            self.state.solver.BoolS("file_bf"), self.state.solver.BVV(1, 32), 0
        )


# NOTE: assume it's not fail
class __fgets_chk(SimProcedure):
    def run(self, buf, size, n, fp) -> claripy.BVV:
        fgets = SIM_PROCEDURES["libc"]["fgets"]
        return self.inline_call(fgets, buf, n, fp).ret_expr


class __fgets_unlocked_chk(SimProcedure):
    def run(self, buf, size, n, fp) -> claripy.BVV:
        fgets = SIM_PROCEDURES["libc"]["fgets"]
        return self.inline_call(fgets, buf, n, fp).ret_expr


class __fprintf_chk(SimProcedure):
    def run(self, fp, flag, fmt) -> claripy.BVV:
        fprintf = SIM_PROCEDURES["libc"]["fprintf"]
        return self.inline_call(fprintf, fp, fmt).ret_expr


class __getcwd_chk(SimProcedure):
    def run(self, buf, len, buflen) -> claripy.BVV:
        return self.inline_call(getcwd, buf, len)


class __snprintf_chk(FormatParser):
    ARGS_MISMATCH = True

    # FIXME: check maxlen
    def run(self, dst_ptr: int, maxlen: int, flag: int, strlen: int) -> claripy.BVV:
        try:
            fmt_str = self._parse(4)
            out_str = fmt_str.replace(5, self.arg)
            self.state.memory.store(dst_ptr, out_str)
            self.state.memory.store(
                dst_ptr + (out_str.size() / 8), self.state.solver.BVV(0, 8)
            )
            return self.state.solver.BVV(out_str.size() / 8, self.state.arch.bits)
        except SimUnsatError:
            if self.state.solver.symbolic(maxlen):
                l = minmax(self, maxlen, self.state.libc.max_buffer_size)
            else:
                l = self.state.solver.eval(maxlen)
            self.state.memory.store(
                dst_ptr,
                self.state.solver.Unconstrained("snprintf", l * 8, uninitialized=False),
            )
            return self.state.solver.Unconstrained(
                "length", self.state.arch.bits, uninitialized=False
            )


class __sprintf_chk(FormatParser):
    ARGS_MISMATCH = True

    def run(self, dst_ptr, flag, strlen) -> claripy.BVV:
        """
        fmt_str = self._parse(3)
        out_str = fmt_str.replace(4, self.arg)
        self.state.memory.store(dst_ptr, out_str)
        self.state.memory.store(dst_ptr + (out_str.size() / 8), self.state.solver.BVV(0, 8))
        return self.state.solver.BVV(out_str.size() / 8, self.state.arch.bits)
        """
        return self.inline_call(
            __snprintf_chk, dst_ptr, self.state.libc.max_buffer_size, flag, strlen
        )


class __read_chk(SimProcedure):
    def run(self, fd, buf, nbytes, buflen) -> claripy.BVV:
        read = SIM_PROCEDURES["posix"]["read"]
        return self.inline_call(read, fd, buf, nbytes).ret_expr


class posix_fadvise(SimProcedure):
    def run(self, fd, offset, len, advise) -> claripy.BVV:
        return self.state.solver.Unconstrained("posiv_fadvise", 32, uninitialized=False)


class getdelim(SimProcedure):
    def run(self, lineptr, n, delimiter, stream) -> claripy.BVV:
        malloc = SIM_PROCEDURES["libc"]["malloc"]
        # Actually a realloc(*lineptr, size)
        a_addr = self.inline_call(malloc, self.state.libc.max_buffer_size).ret_expr
        self.state.memory.store(
            a_addr,
            self.state.solver.Unconstrained(
                "getdelim", self.state.libc.max_buffer_size * 8, uninitialized=False
            ),
        )
        self.state.memory.store(lineptr, a_addr)
        self.state.memory.store(
            n,
            self.state.solver.Unconstrained(
                "getdelim", self.state.arch.bits, uninitialized=False
            ),
        )
        return self.state.solver.Unconstrained(
            "getdelim", self.state.arch.bits, uninitialized=False
        )


class getline(SimProcedure):
    def run(self, lineptr, n, stream) -> claripy.BVV:
        return self.inline_call(getdelim, lineptr, n, "\n", stream).ret_expr


class isatty(SimProcedure):
    def run(self, fd) -> claripy.BVV:
        return self.state.solver.If("isatty", 1, self.state.solver.BVV(0, 32))
