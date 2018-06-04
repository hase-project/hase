from angr.simos.linux import SimLinux
from angr.errors import AngrSyscallError
from angr.storage.file import SimFileDescriptorDuplex
import claripy


# FIXME: bug from angr https://github.com/angr/angr/issues/971
# TODO: add other vex ir? https://github.com/smparkes/valgrind-vex/blob/master/pub/libvex_ir.h
def patched_syscall_abi(self, state):
    if state.arch.name != 'AMD64':
        return None
    if state.history.jumpkind == 'Ijk_Sys_int128':
        return 'i386'
    elif state.history.jumpkind == 'Ijk_Sys_syscall':
        return 'amd64'
    elif state.history.jumpkind == 'Ijk_EmWarn':
        return 'amd64'
    else:
        raise AngrSyscallError("Unknown syscall jumpkind %s" % state.history.jumpkind)


SimLinux.syscall_abi = patched_syscall_abi


# FIXME: feof(stdin) should return true or false
# https://github.com/angr/angr/blob/4549e20355c5a60c918ab5169753dd2d3c73e66d/angr/storage/file.py#L871
# TODO: not working for here
def patched_duplex_eof(self):
    pos = self._read_pos
    data, _ = self.read_data(1)
    self._read_pos = pos
    return data == 0xFF


SimFileDescriptorDuplex.eof = patched_duplex_eof
