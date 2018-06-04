import claripy
from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
from angr.procedures.libc import io_file_data_for_arch, fopen
from angr.errors import SimProcedureError
from angr.storage.file import Flags


# NOTE: if we hook one of the file operation, we need to hook all of these
# Or the FILE struct will be inconsistent. But if we don't use them, angr's IO operations will have wrong branch
# TODO: lstat, fsetpos, fgetpos, xstat, fxstat


class ferror(SimProcedure):
    def run(self, file_ptr):
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return None
        # FIXME: no error concept in SimFile
        return claripy.false


# NOTE: invoked by putchar (while inlined)
# FIXME: no overflow concept in SimFile
class __overflow(SimProcedure):
    def run(self, file_ptr, ch):
        fputc = SIM_PROCEDURES['libc']['fputc']
        ret_expr = self.inline_call(fputc, ch, file_ptr).ret_expr
        return ret_expr


# NOTE: missing a optional version (no mode) of open
# https://github.com/angr/angr/blob/master/angr/procedures/posix/open.py#L11
class new_open(SimProcedure):
    def run(self, p_addr, flags, mode=0644):
        openf = SIM_PROCEDURES['posix']['open']
        ret_expr = self.inline_call(openf, p_addr, flags, mode).ret_expr
        return ret_expr


# NOTE: non-standard c/e flag for fopen
# http://man7.org/linux/man-pages/man3/fopen.3.html#NOTES
# https://github.com/angr/angr/blob/d6f248d115dd9a7fcf6e1e3bf370e6ebce12a5dd/angr/procedures/libc/fopen.py
def patched_mode_to_flag(mode):
    mode = mode.replace('c', '')
    mode = mode.replace('e', '')
    if mode[-1] == 'b': # lol who uses windows
        mode = mode[:-1]
    all_modes = {
        "r"  : Flags.O_RDONLY,
        "r+" : Flags.O_RDWR,
        "w"  : Flags.O_WRONLY | Flags.O_CREAT,
        "w+" : Flags.O_RDWR | Flags.O_CREAT,
        "a"  : Flags.O_WRONLY | Flags.O_CREAT | Flags.O_APPEND,
        "a+" : Flags.O_RDWR | Flags.O_CREAT | Flags.O_APPEND
        }
    if mode not in all_modes:
        raise SimProcedureError('unsupported file open mode %s' % mode)

    return all_modes[mode]

fopen.mode_to_flag = patched_mode_to_flag


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
        ret_expr = self.inline_call(stat, file_path, stat_buf)
        return ret_expr


class __fxstat(SimProcedure):
    def run(self, ver, fd, stat_buf):
        fstat = SIM_PROCEDURES['linux_kernel']['fstat']
        ret_expr = self.inline_call(fstat, fd, stat_buf)
        return ret_expr
