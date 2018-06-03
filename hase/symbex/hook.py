import claripy
from angr.sim_type import SimTypeInt, SimTypeString
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
from angr.procedures.libc import io_file_data_for_arch


# NOTE: if we hook one of the file operation, we need to hook all of these
# Or the FILE struct will be inconsistent
# TODO: getenv
# FIXME: what about relative path passed as argv?


unsupported_symbols = [
    ('__new_exitfn', 'atexit', 'no simulation'),
    ('getenv', 'getenv', 'wrong branch'),
    # ('_IO_do_allocate', 'fread_unlocked', 'wrong branch'),
    # ('feof', 'feof', 'wrong branch'),
    # ('__overflow', 'putchar_unlocked', 'no simulation')
]

questionable_hook = [
]


all_hookable_symbols = {}
for lib, funcs in SIM_PROCEDURES.items():
    if not lib.startswith("win"):
        for name, proc in funcs.items():
            if name not in questionable_hook:
                all_hookable_symbols[name] = proc


class ferror(SimProcedure):
    def run(self, file_ptr):
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return None
        # FIXME: no error concept in angr.storage.file.SimFile
        return claripy.false


class __overflow(SimProcedure):
    def run(self, file_ptr, ch):
        fputc = all_hookable_symbols['fputc']
        ret_expr = self.inline_call(fputc, ch, file_ptr).ret_expr
        return ret_expr


all_hookable_symbols['ferror'] = ferror
# NOTE: invoked by putchar (while inlined)
# NOTE: no overflow concept in SimFile
all_hookable_symbols['__overflow'] = __overflow


class setlocale(SimProcedure):
    def run(self, category, locale):
        self.argument_types = {
            0: SimTypeInt(32, True),
            1: self.ty_ptr(SimTypeString())
        }
        self.return_type = self.ty_ptr(SimTypeString())
        # FIXME: should have better solution
        addr = self.state.libc.heap_location
        self.state.libc.heap_location += 1
        self.state.memory.store(addr, "\x00")
        return addr

all_hookable_symbols['setlocale'] = setlocale


unlocked_symbols = [
    'getchar', 'putchar',
    'feof', 'ferror',
    'putc', 'fflush',
    'fread', 'fwrite',
    'fgets', 'fputs',
]
for sym in unlocked_symbols:
    unlocked_sym = sym + '_unlocked'
    all_hookable_symbols[unlocked_sym] = all_hookable_symbols[sym]

