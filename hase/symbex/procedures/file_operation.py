import claripy
from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
from angr.procedures.libc import io_file_data_for_arch, fopen
from angr.errors import SimProcedureError
from angr.storage.file import Flags


# NOTE: if we hook one of the file operation, we need to hook all of these
# Or the FILE struct will be inconsistent. But if we don't use them, angr's IO operations will have wrong branch
# TODO: fsetpos, fgetpos, xstat, fxstat, fxstatat
# freopen, openat 


class ferror(SimProcedure):
    def run(self, file_ptr):
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return None
        # FIXME: no error concept in SimFile
        return 0


# NOTE: invoked by putchar (while inlined)
# FIXME: no overflow concept in SimFile, low-fieldity simulation then
class __overflow(SimProcedure):
    def run(self, file_ptr, ch):
        fputc = SIM_PROCEDURES['libc']['fputc']
        ret_expr = self.inline_call(fputc, ch, file_ptr).ret_expr
        return ret_expr


class __underflow(SimProcedure):
    def run(self, file_ptr, ch):
        fputc = SIM_PROCEDURES['libc']['fputc']
        ret_expr = self.inline_call(fputc, ch, file_ptr).ret_expr
        return ret_expr


# NOTE: invoked by getc
# TODO: https://code.woboq.org/userspace/glibc/libio/genops.c.html
class __uflow(SimProcedure):
    def run(self, file_ptr):
        fgetc = SIM_PROCEDURES['libc']['fgetc']
        ret_expr = self.inline_call(fgetc, file_ptr).ret_expr
        return ret_expr


class ftello(SimProcedure):
    def run(self, file_ptr):
        ftell = SIM_PROCEDURES['libc']['ftell']
        ret_expr = self.inline_call(ftell, file_ptr).ret_expr
        # FIXME: Acutally off_t
        return ret_expr


class fseeko(SimProcedure):
    def run(self, fp, offset, whence):
        fseek = SIM_PROCEDURES['libc']['fseek']
        # FIXME: Actually offset: off_t
        ret_expr = self.inline_call(fseek, fp, offset, whence).ret_expr
        return ret_expr
        

# FIXME: complete this
class freopen(SimProcedure):
    def run(self, file_ptr, mode_ptr, stream_ptr):
        pass


# FIXME: current angr stat is useless, posix.fstat is also not working
# https://github.com/angr/angr/blob/d6f248d115dd9a7fcf6e1e3bf370e6ebce12a5dd/angr/procedures/linux_kernel/stat.py
# https://github.com/angr/angr/blob/4549e20355c5a60c918ab5169753dd2d3c73e66d/angr/state_plugins/posix.py#L329
class stat(SimProcedure):
    IS_SYSCALL = True

    def run(self, file_path, stat_buf):
        # FIXME: how to convert file_path to SimTypeFd?
        # Just make st_mode symbolic
        stat = self.state.posix.fstat(3)
        print(stat.st_mode)
        self._store_amd64(stat_buf, stat)
        return self.state.se.BVV(0, 64)

    def _store_amd64(self, stat_buf, stat):
        store = lambda offset, val: self.state.memory.store(stat_buf + offset, val)

        store(0x00, stat.st_dev)
        store(0x08, stat.st_ino)
        store(0x10, stat.st_nlink)
        store(0x18, stat.st_mode)
        store(0x1c, stat.st_uid)
        store(0x20, stat.st_gid)
        store(0x24, self.state.se.BVV(0, 32))
        store(0x28, stat.st_rdev)
        store(0x30, stat.st_size)
        store(0x38, stat.st_blksize)
        store(0x40, stat.st_blocks)
        store(0x48, stat.st_atime)
        store(0x50, stat.st_atimensec)
        store(0x58, stat.st_mtime)
        store(0x60, stat.st_mtimensec)
        store(0x68, stat.st_ctime)
        store(0x70, stat.st_ctimensec)
        store(0x78, self.state.se.BVV(0, 64))
        store(0x80, self.state.se.BVV(0, 64))
        store(0x88, self.state.se.BVV(0, 64))


# NOTE: posix extra
# http://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/baselib-xstat-1.html
class __xstat(SimProcedure):
    def run(self, ver, file_path, stat_buf):
        ret_expr = self.inline_call(stat, file_path, stat_buf).ret_expr
        return ret_expr


class __fxstat(SimProcedure):
    def run(self, ver, fd, stat_buf):
        fstat = SIM_PROCEDURES['linux_kernel']['fstat']
        ret_expr = self.inline_call(fstat, fd, stat_buf).ret_expr
        return ret_expr


class lstat(SimProcedure):
    def run(self, file_path, stat_buf):
        ret_expr = self.inline_call(stat, file_path, stat_buf).ret_expr
        return ret_expr


# TODO: how to handle with va_list?
class vprintf(SimProcedure):
    def run(self, fmt, va_list):
        return None 


'''
FIXME: pwd maybe different
NOTE: 
    In GNU, if BUF is NULL,
    an array is allocated with `malloc'; the array is SIZE
    bytes long, unless SIZE == 0, in which case it is as
    big as necessary.
'''
class getcwd(SimProcedure):
    def run(self, buf, size):
        _getcwd = SIM_PROCEDURES['linux_kernel']['getcwd']
        malloc = SIM_PROCEDURES['libc']['malloc']
        if not self.state.se.symbolic(buf):
            buf_v = self.state.se.eval(buf)
            if buf_v == 0:
                cwd = self.state.fs.cwd
                new_size = self.state.solver.If(size-1 > len(cwd), len(cwd), size-1)
                buf = self.inline_call(malloc, new_size).ret_expr
        return self.inline_call(_getcwd, buf, size).ret_expr
                