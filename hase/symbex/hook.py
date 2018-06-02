from angr.sim_type import SimTypeInt, SimTypeString
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES

unsupported_symbols = [
    ('__new_exitfn', 'atexit', 'no simulation'),
    ('getenv', 'getenv', 'wrong branch'),
    # ('_IO_do_allocate', 'fread_unlocked', 'wrong branch'),
]


all_hookable_symbols = {}
for lib, funcs in SIM_PROCEDURES.items():
    if not lib.startswith("win"):
        for name, proc in funcs.items():
            all_hookable_symbols[name] = proc


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
    'putc',
    'feof', 'fflush',
    'fread', 'fwrite',
    'fgets', 'fputs',
]
for sym in unlocked_symbols:
    unlocked_sym = sym + '_unlocked'
    all_hookable_symbols[unlocked_sym] = SIM_PROCEDURES['libc'][sym]

# TODO: https://github.com/angr/angr/blob/4549e20355c5a60c918ab5169753dd2d3c73e66d/angr/storage/file.py#L871