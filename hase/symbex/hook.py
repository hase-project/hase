from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES
import procedures

from typing import Dict, List, Any

# TODO: How to deal with overload function hook?
# TODO: wchar functions support?
# TODO: rearrange this


unsupported_symbols = [
    ('__new_exitfn', 'atexit', 'no simulation'),
    ('getenv', 'getenv', 'wrong branch'),
    # ('_IO_do_allocate', 'fread_unlocked', 'wrong branch'),
]

skip_hook = [
] # type: List[str]


def hook_angr_procedures(dct, libs, skip_hook, hook_IO = True):
    for lib in libs:
        funcs = SIM_PROCEDURES[lib]
        for name, proc in funcs.items():
            if name in skip_hook:
                continue
            if hook_IO or name not in procedures.all_IO_hook:
                dct[name] = proc


def hook_user_procedures(dct, hook_IO = True):
    for name in procedures.__all__:
        if not hook_IO and name == 'file_operation':
            continue
        module = getattr(procedures, name)
        for op in dir(module):
            obj = getattr(module, op)
            if isinstance(obj, type) and SimProcedure in obj.__mro__:
                if not getattr(obj, 'INCOMPLETE', False):
                    dct[op] = obj


def hook_alias_procedures(dct):
    alias_sym = procedures.alias_symbols
    for decr_sym, sym in alias_sym.items():
        if sym in dct.keys():
            dct[decr_sym] = dct[sym]


all_hookable_symbols = {} # type: Dict[str, Any]

libs = [
    'libc', 'glibc', 
    'linux_kernel', 'posix',
    'linux_loader'
]


hook_angr_procedures(all_hookable_symbols, libs, skip_hook, True)
hook_user_procedures(all_hookable_symbols, True)
hook_alias_procedures(all_hookable_symbols)




