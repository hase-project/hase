import claripy
from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
from angr.procedures.libc import io_file_data_for_arch, fopen
from angr.errors import SimProcedureError
from angr.storage.file import Flags


# NOTE: if we hook one of the file operation, we need to hook all of these
# Or the FILE struct will be inconsistent
# TODO: lstat, fsetpos, fgetpos, fseeko, ftello


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
