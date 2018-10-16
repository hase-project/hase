from __future__ import absolute_import, division, print_function

from typing import Any, Dict, List, Tuple

from angr import SimProcedure
from angr.procedures import SIM_LIBRARIES, SIM_PROCEDURES

from .procedures import (alias_symbols, all_IO_hook, file_operation,
                         group_operation, memory_operation, miscs,
                         socket_operation, string_operation, syscall,
                         time_operation)

# TODO: How to deal with overload function hook?
# TODO: wchar functions support?
# TODO: rearrange this


addr_symbols = [
    "__strcmp_sse2",
    "__strchr_sse2",
    "__strncpy_sse2",
    "__memcpy_sse2",
    "__memcpy_sse2_unaligned",
    "__memset_sse2",
    "__strncasecmp_l_avx",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "memalign",
]


unsupported_symbols: List[Tuple[str]] = []

skip_hook: List[str] = []


def hook_angr_procedures(dct, libs, skip_hook, hook_IO=True):
    # type: (Dict[str, Any], List[str], List[str], bool) -> None
    for lib in libs:
        funcs = SIM_PROCEDURES[lib]
        for name, proc in funcs.items():
            if name in skip_hook:
                continue
            if hook_IO or name not in all_IO_hook:
                dct[name] = proc


def hook_user_procedures(dct, hook_IO=True):
    # type: (Dict[str, Any], bool) -> None
    procedures = [
        memory_operation,
        group_operation,
        miscs,
        socket_operation,
        string_operation,
        time_operation,
        syscall,
    ]
    if hook_IO:
        procedures.append(file_operation)

    for module in procedures:
        for op in dir(module):
            obj = getattr(module, op)
            if isinstance(obj, type) and SimProcedure in obj.__mro__:
                if not getattr(obj, "INCOMPLETE", False):
                    dct[op] = obj
                if getattr(obj, "IS_SYSCALL", False):
                    ins = obj(display_name=op)
                    ins.cc = None
                    ins.is_syscall = True
                    ins.NO_RET = False
                    ins.ADDS_EXITS = False
                    SIM_LIBRARIES["linux"].procedures[op] = ins


def hook_alias_procedures(dct):
    # type: (Dict[str, Any]) -> None
    alias_sym = alias_symbols
    for decr_sym, sym in alias_sym.items():
        candidates = [sym]
        while sym in alias_sym.keys():
            candidates.append(alias_sym[sym])
            sym = alias_sym[sym]
        for sym in candidates:
            if sym in dct.keys():
                dct[decr_sym] = dct[sym]
                obj = dct[sym]
                if getattr(obj, "IS_SYSCALL", False):
                    ins = obj(display_name=decr_sym)
                    ins.cc = None
                    ins.is_syscall = True
                    ins.NO_RET = False
                    ins.ADDS_EXITS = False
                    SIM_LIBRARIES["linux"].procedures[decr_sym] = ins
                break


# FIXME: it would be too hack to use inspect or something to generate
# Simprocedure, but the argument may have weird case
def hook_fallback_procedures(dct):
    # type: (Dict[str, Any]) -> None
    pass


all_hookable_symbols: Dict[str, Any] = {}

libs = ["libc", "glibc", "linux_kernel", "posix", "linux_loader"]


hook_angr_procedures(all_hookable_symbols, libs, skip_hook, True)
hook_user_procedures(all_hookable_symbols, True)
hook_alias_procedures(all_hookable_symbols)
