from angr.simos.linux import SimLinux
from angr.errors import AngrSyscallError, SimProcedureError
from angr.storage.file import SimFileDescriptorDuplex
from angr.procedures import linux_kernel, SIM_LIBRARIES
from angr.calling_conventions import DEFAULT_CC
from angr import sim_type
from angr.procedures.stubs import format_parser
from .procedures.file_operation import new_open
import claripy
import string


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


# FIXME: syscall -> open -> mode default
# https://github.com/angr/angr/blob/master/angr/procedures/linux_kernel/open.py
# https://github.com/angr/angr/blob/d6f248d115dd9a7fcf6e1e3bf370e6ebce12a5dd/angr/procedures/definitions/linux_kernel.py#L275
# Or use interface to update: https://github.com/angr/angr/blob/d6f248d115dd9a7fcf6e1e3bf370e6ebce12a5dd/angr/procedures/definitions/__init__.py
new_open.cc = None
new_open.display_name = 'open'
new_open.is_syscall = True
new_open.NO_RET = False
new_open.ADDS_EXITS = False
SIM_LIBRARIES['linux'].procedures['open'] = new_open()


# FIXME: _parse with %*.%d%s (actually %%*.%d%s)
# https://github.com/angr/angr/blob/c420d2368753635c7293374fce8c179b984268a6/angr/procedures/stubs/format_parser.py
# TODO: change this
def patched_match_spec(self, nugget):
    """
    match the string `nugget` to a format specifier.
    """
    # TODO: handle positional modifiers and other similar format string tricks.
    all_spec = self._all_spec

    # iterate through nugget throwing away anything which is an int
    # TODO store this in a size variable

    original_nugget = nugget
    length_str = [ ]
    length_spec = None

    for j, c in enumerate(nugget):
        if (c in string.digits):
            length_str.append(c)
        else:
            nugget = nugget[j:]
            length_spec = None if len(length_str) == 0 else int(''.join(length_str))
            break

    # we need the length of the format's length specifier to extract the format and nothing else
    length_spec_str_len = 0 if length_spec is None else len(length_str)
    # is it an actual format?
    for spec in all_spec:
        if nugget.startswith(spec):
            # this is gross coz sim_type is gross..
            nugget = nugget[:len(spec)]
            original_nugget = original_nugget[:(length_spec_str_len + len(spec))]
            nugtype = all_spec[nugget]
            try:
                typeobj = sim_type.parse_type(nugtype).with_arch(self.state.arch)
            except:
                raise SimProcedureError("format specifier uses unknown type '%s'" % repr(nugtype))
            return format_parser.FormatSpecifier(original_nugget, length_spec, typeobj.size / 8, typeobj.signed)

    return None

format_parser.FormatParser._match_spec = patched_match_spec