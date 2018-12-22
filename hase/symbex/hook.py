from copy import deepcopy
from typing import Any, Dict, List, Tuple

from angr import SimProcedure
from angr.procedures import SIM_LIBRARIES, SIM_PROCEDURES

from .cdanalyzer import CoredumpGDB
from .procedures import (
    alias_symbols,
    all_IO_hook,
    common_prefix,
    common_suffix,
    file_operation,
    group_operation,
    memory_operation,
    miscs,
    socket_operation,
    string_operation,
    syscall,
    time_operation,
)

# TODO: How to deal with overload function hook?
# TODO: wchar functions support?
# TODO: rearrange this


addr_symbols = ["malloc", "calloc", "realloc", "free", "memalign"]


unsupported_symbols = []  # type: List[Tuple[str]]

skip_hook = []  # type: List[str]


def hook_angr_procedures(
    dct: Dict[str, Any], libs: List[str], skip_hook: List[str], hook_IO: bool = True
) -> None:
    for lib in libs:
        funcs = SIM_PROCEDURES[lib]
        for name, proc in funcs.items():
            if name in skip_hook:
                continue
            if hook_IO or name not in all_IO_hook:
                dct[name] = proc


def hook_user_procedures(dct: Dict[str, Any], hook_IO: bool = True) -> None:
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


def hook_alias_procedures(dct: Dict[str, Any]) -> None:
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


all_hookable_symbols = {}  # type: Dict[str, Any]

libs = ["libc", "glibc", "linux_kernel", "posix", "linux_loader"]


hook_angr_procedures(all_hookable_symbols, libs, skip_hook, True)
hook_user_procedures(all_hookable_symbols, True)
hook_alias_procedures(all_hookable_symbols)


def setup_project_hook(
    project: Any, gdb: "CoredumpGDB", omit_hook: List[str] = []
) -> Tuple[Dict[str, Any], List[List[int]]]:
    hooked_syms = deepcopy(all_hookable_symbols)
    for symname in omit_hook:
        hooked_syms.pop(symname, None)

    deadend_syms = ["kill", "raise", "abort", "__assert_fail", "__stack_chk_fail"]
    for symname in deadend_syms:
        hooked_syms.pop(symname, None)
        try:
            project.loader.find_symbol(symname).rebased_addr
            project._sim_procedures.pop(symname, None)
        except Exception:
            pass

    omitted_section = []
    for symname, func in hooked_syms.items():
        project.hook_symbol(symname, func())

    for symname in addr_symbols:
        if symname in hooked_syms.keys():
            r = gdb.get_func_range(symname)
            func = hooked_syms[symname]
            if r != [0, 0]:
                project.hook(r[0], func(), length=r[1])
                omitted_section.append(r)

    return hooked_syms, omitted_section
