import claripy
from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
from angr.procedures.libc import io_file_data_for_arch, fopen
from angr.procedures.stubs.format_parser import FormatParser
from angr.errors import SimProcedureError
from angr.storage.file import Flags


# NOTE: if we hook one of the file operation, we need to hook all of these
# Or the FILE struct will be inconsistent. But if we don't use them, angr's IO operations will have wrong branch
# TODO: fsetpos, fgetpos, statfs, fstatfs
# freopen, openat, __fbufsize, __fpending, flushlbf, fpurge
# vprintf, vfprintf, vsprintf, vsnprintf
# TODO: maybe load concrete file?


class openat(SimProcedure):
    IS_SYSCALL = True

    def run(self, dirfd, pathname, flags, mode=0644):
        xopen = SIM_PROCEDURES['posix']['open']
        # XXX: Actually name is useless, we just want to open a SimFile
        return self.inline_call(xopen, pathname, flags, mode).ret_expr


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
    INCOMPLETE = True
    def run(self, file_ptr, mode_ptr, stream_ptr):
        pass


# FIXME: current angr stat is useless, posix.fstat is also not working
# https://github.com/angr/angr/blob/d6f248d115dd9a7fcf6e1e3bf370e6ebce12a5dd/angr/procedures/linux_kernel/stat.py
# https://github.com/angr/angr/blob/4549e20355c5a60c918ab5169753dd2d3c73e66d/angr/state_plugins/posix.py#L329
class stat(SimProcedure):
    IS_SYSCALL = True

    def run(self, file_path, stat_buf):
        # NOTE: make everything symbolic now
        self._store_amd64(stat_buf)
        return self.state.se.BVV(0, 64)

    def _store_amd64(self, stat_buf):
        store = lambda offset, sym, bits: self.state.memory.store(
            stat_buf + offset,
            self.state.se.BVS(sym, bits)
        )
        # https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/x86/bits/stat.h.html#stat
        store(0x00, "st_dev", 64)
        store(0x08, "st_ino", 64)
        store(0x10, "st_nlink", 64)
        store(0x18, "st_mode", 32)
        store(0x1c, "st_uid", 32)
        store(0x20, "st_gid", 32)
        store(0x24, "__pad0" ,32)
        store(0x28, "st_rdev", 64)
        store(0x30, "st_size", 64)
        store(0x38, "st_blksize", 64)
        store(0x40, "st_blocks", 64)
        store(0x48, "st_atime", 64)
        store(0x50, "st_atimensec", 64)
        store(0x58, "st_mtime", 64)
        store(0x60, "st_mtimensec", 64)
        store(0x68, "st_ctime", 64)
        store(0x70, "st_ctimensec", 64)
        store(0x78, "glibc_reserved[3]", 64*3)


class lstat(SimProcedure):
    IS_SYSCALL = True

    def run(self, file_path, stat_buf):
        ret_expr = self.inline_call(stat, file_path, stat_buf).ret_expr
        return ret_expr


class fstat(SimProcedure):
    IS_SYSCALL = True

    def run(self, fd, stat_buf):
        # NOTE: since file_path doesn't matter
        return self.inline_call(stat, fd, stat_buf).ret_expr


class fstatat(SimProcedure):
    IS_SYSCALL = True

    def run(self, dirfd, pathname, stat_buf, flags):
        return self.inline_call(stat, pathname, stat_buf).ret_expr


class newfstatat(SimProcedure):
    IS_SYSCALL = True

    def run(self, dirfd, pathname, stat_buf, flags):
        return self.inline_call(stat, pathname, stat_buf).ret_expr


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


class __lxstat(SimProcedure):
    def run(self, ver, file_path, stat_buf):
        ret_expr = self.inline_call(lstat, file_path, stat_buf).ret_expr
        return ret_expr


# TODO: how to handle with va_list?
class vprintf(SimProcedure):
    INCOMPLETE = True
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
                

# NOTE: if allow-read
class __freadable(SimProcedure):
    def run(self, file_ptr):
        return self.state.se.If(
            self.state.se.BoolS("file_readable"),
            self.state.se.BVV(1, 32),
            0
        )


# NOTE: if allow-write
class __fwritable(SimProcedure):
    def run(self, file_ptr):
        return self.state.se.If(
            self.state.se.BoolS("file_writable"),
            self.state.se.BVV(1, 32),
            0
        )


# NOTE: if read-only or last operation read
class __freading(SimProcedure):
    def run(self, file_ptr):
        return self.state.se.If(
            self.state.se.BoolS("file_reading"),
            self.state.se.BVV(1, 32),
            0
        )


# NOTE: if write-only or last operation write
class __fwriting(SimProcedure):
    def run(self, file_ptr):
        return self.state.se.If(
            self.state.se.BoolS("file_writing"),
            self.state.se.BVV(1, 32),
            0
        )


# NOTE: If line-buffered
class __flbf(SimProcedure):
    def run(self, file_ptr):
        return self.state.se.If(
            self.state.se.BoolS("file_bf"),
            self.state.se.BVV(1, 32),
            0
        )


# NOTE: assume it's not fail
class __fgets_chk(SimProcedure):
    def run(self, buf, size, n, fp):
        fgets = SIM_PROCEDURES['libc']['fgets']
        return self.inline_call(fgets, buf, n, fp).ret_expr


class __fgets_unlocked_chk(SimProcedure):
    def run(self, buf, size, n, fp):
        fgets = SIM_PROCEDURES['libc']['fgets']
        return self.inline_call(fgets, buf, n, fp).ret_expr


class __fprintf_chk(SimProcedure):
    def run(self, fp, flag, fmt):
        fprintf = SIM_PROCEDURES['libc']['fprintf']
        return self.inline_call(fprintf, fp, fmt).ret_expr


class __getcwd_chk(SimProcedure):
    def run(self, buf, len, buflen):
        return self.inline_call(getcwd, buf, len)


class __snprintf_chk(FormatParser):
    ARGS_MISMATCH = True
    # FIXME: check maxlen
    def run(self, dst_ptr, maxlen, flag, strlen):
        fmt_str = self._parse(4)
        out_str = fmt_str.replace(5, self.arg)
        self.state.memory.store(dst_ptr, out_str)
        self.state.memory.store(dst_ptr + (out_str.size() / 8), self.state.se.BVV(0, 8))
        return self.state.se.BVV(out_str.size() / 8, self.state.arch.bits)


class __sprintf_chk(FormatParser):
    ARGS_MISMATCH = True
    def run(self, dst_ptr, flag, strlen):
        fmt_str = self._parse(3)
        out_str = fmt_str.replace(4, self.arg)
        self.state.memory.store(dst_ptr, out_str)
        self.state.memory.store(dst_ptr + (out_str.size() / 8), self.state.se.BVV(0, 8))
        return self.state.se.BVV(out_str.size() / 8, self.state.arch.bits)


class __read_chk(SimProcedure):
    def run(self, fd, buf, nbytes, buflen):
        read = SIM_PROCEDURES['posix']['read']
        return self.inline_call(read, fd, buf, nbytes).ret_expr


class fcntl(SimProcedure):
    ARGS_MISMATCH = True
    IS_SYSCALL = True
    def run(self, fd, cmd):
        return self.state.se.BVS('fcntl', 32)


class posix_fadvise(SimProcedure):
    def run(self, fd, offset, len, advise):
        return 0


class fadvise64(SimProcedure):
    IS_SYSCALL = True
    def run(self, fd, offset, len, advise):
        return 0


class statfs(SimProcedure):
    IS_SYSCALL = True
    
    def run(self, path, statfs_buf):
        # NOTE: make everything symbolic now
        self._store_amd64(statfs_buf)
        return self.state.se.BVV(0, 64)

    def _store_amd64(self, statfs_buf):
        store = lambda offset, sym, bits: self.state.memory.store(
            statfs_buf + offset,
            self.state.se.BVS(sym, bits)
        )
        # https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/bits/statfs.h.html#statfs
        store(0x00, "f_type", 64)
        store(0x08, "f_bsize", 64)
        store(0x10, "f_blocks", 32)
        store(0x14, "f_bfree", 32)
        store(0x18, "f_bavail", 32)
        store(0x1c, "f_files", 32)
        store(0x20, "f_ffree" ,32)
        store(0x28, "f_fsid", 64)
        store(0x30, "f_namelen", 64)
        store(0x38, "f_frsize", 64)
        store(0x40, "f_flags", 64)
        store(0x48, "f_spare[4]", 64 * 4)
        

class fstatfs(SimProcedure):
    IS_SYSCALL = True

    def run(self, fd, stat_buf):
        return self.inline_call(statfs, fd, stat_buf).ret_expr


class dup(SimProcedure):
    IS_SYSCALL = True

    def run(self, oldfd):
        return self.state.se.BVS('dup', 32)


class dup2(SimProcedure):
    IS_SYSCALL = True

    def run(self, oldfd, newfd):
        return self.state.se.BVS('dup', 32)


class dup3(SimProcedure):
    IS_SYSCALL = True

    def run(self, oldfd, newfd, flags):
        return self.state.se.BVS('dup', 32)


