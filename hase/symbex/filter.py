from __future__ import absolute_import, division, print_function

import logging
from bisect import bisect
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from angr import Project, SimProcedure
from angr.analyses.cfg import CFGFast

from ..pt.events import Instruction
from .hook import unsupported_symbols
from .tracer import CoredumpGDB

l = logging.getLogger(__name__)


class FakeSymbol:
    def __init__(self, name: str, addr: int) -> None:
        self.name = name
        self.rebased_addr = addr

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, FakeSymbol):
            return False
        return self.name == other.name and self.rebased_addr == other.rebased_addr

    def __hash__(self) -> int:
        return hash((self.name, self.rebased_addr))

    def __repr__(self) -> str:
        # () -> str
        return "FakeSymbol '{}' at {}".format(self.name, hex(self.rebased_addr))


class FilterBase:
    def __init__(
        self,
        project: Project,
        cfg: CFGFast,
        trace: List[Instruction],
        hooked_symbol: Dict[str, SimProcedure],
        gdb: CoredumpGDB,
    ) -> None:
        self.project = project
        self.main_cfg = cfg
        self.main_object = project.loader.main_object
        self.trace = trace
        self.hooked_symbol = hooked_symbol
        self.gdb = gdb
        self.new_trace: List[Instruction] = []
        self.omitted_section: List[List[int]] = []
        self.analyze_unsupported()

    def analyze_unsupported(self) -> None:
        for l in unsupported_symbols:
            self.omitted_section.append(self.gdb.get_func_range(l[0]))

    def test_plt(self, addr: int) -> bool:
        # NOTE: .plt or .plt.got
        section = self.project.loader.find_section_containing(addr)
        return section.name.startswith(".plt")

    def test_ld(self, addr: int) -> bool:
        o = self.project.loader.find_object_containing(addr)
        return o == self.project.loader.linux_loader_object

    def test_omit(self, addr: int) -> bool:
        for sec in self.omitted_section:
            if sec[0] <= addr < sec[0] + sec[1]:
                return True
        return False


class FilterTrace:
    def __init__(
        self,
        project: Project,
        cfg: CFGFast,
        trace: List[Instruction],
        hooked_symbol: Dict[str, SimProcedure],
        gdb: CoredumpGDB,
        omitted_section: List[List[int]],
        from_initial: bool,
        static_link: bool,
        backtrace: List[Dict[str, Any]],
    ) -> None:
        self.project = project
        self.main_cfg = cfg
        self.main_object = project.loader.main_object
        self.trace = trace
        self.hooked_symbol = hooked_symbol
        self.new_trace: List[Instruction] = []
        self.trace_idx: List[int] = []
        self.hook_target: Dict[int, int] = {}
        self.gdb = gdb
        self.omitted_section: List[List[int]] = omitted_section
        self.analyze_unsupported()
        self.from_initial = from_initial
        self.static_link = static_link
        self.gdb_backtrace = backtrace

        self.hooked_symname = list(self.hooked_symbol.keys())
        assert self.main_cfg.kb is not None
        self.callgraph = self.main_cfg.kb.functions.callgraph
        # HACK: angr currently solve symbols by legacy name
        # Actually only solve strchr/strrchr to index/rindex
        self.libc_legacy_map = {
            "memcmp": "bcmp",
            "memmove": "bmove",
            "memset": "bzero",
            "strchr": "index",
            "strrchr": "rindex",
        }

        for name, sub in self.libc_legacy_map.items():
            if name in self.hooked_symname:
                self.hooked_symname.append(sub)

        self.syms: Dict[Any, List[int]] = {}
        # NOTE: just copy the dict, or it would be slow to access by lib property
        self.syms_dict: Dict[Any, Dict[int, Any]] = {}
        for lib in self.project.loader.all_elf_objects:
            self.syms_dict[lib] = lib.symbols_by_addr.copy()
            self.syms[lib] = list(self.syms_dict[lib].keys())
            self.syms[lib].sort()
        self.analyze_trace()

    def analyze_unsupported(self) -> None:
        for l in unsupported_symbols:
            try:
                r = self.gdb.get_func_range(l[0])
            except Exception:
                print("Unable to fetch {} range by gdb".format(l[0]))
                r = [0, 0]
            self.omitted_section.append(r)

    def test_plt_vdso(self, addr: int) -> bool:
        # NOTE: .plt or .plt.got
        section = self.project.loader.find_section_containing(addr)
        if section:
            return section.name.startswith(".plt")
        else:
            # NOTE: unrecognizable section, regard as vDSO
            return True

    def test_ld(self, addr: int) -> bool:
        o = self.project.loader.find_object_containing(addr)
        return o == self.project.loader.linux_loader_object

    def test_omit(self, addr: int) -> bool:
        for sec in self.omitted_section:
            if sec[0] <= addr < sec[0] + sec[1]:
                return True
        return False

    def test_hook_name(self, fname: str) -> bool:
        for name in self.hooked_symname:
            # _IO_fopen@@xxx
            if fname == name or (fname.startswith(name + "@")):
                return True
        return False

    def solve_name_plt(self, addr: int) -> str:
        for lib in self.project.loader.all_elf_objects:
            if addr in lib.reverse_plt.keys():
                return lib.reverse_plt[addr]
        return ""

    # FIXME return type should be a union of the actual type and FakeSymbol
    def find_function(self, addr: int) -> Optional[FakeSymbol]:
        for lib, symx in self.syms.items():
            if lib.contains_addr(addr):
                # NOTE: angr cannot solve plt symbol name
                if self.test_plt_vdso(addr):
                    name = self.solve_name_plt(addr)
                    if name:
                        sym = FakeSymbol(name, addr)
                        return sym
                idx = bisect(symx, addr) - 1
                entry = symx[idx]
                return self.syms_dict[lib][entry]
        return None

    def test_function_entry(self, addr: int) -> Tuple[bool, str]:
        sym = self.find_function(addr)
        if sym and sym.rebased_addr == addr:
            symname = sym.name
            return True, symname
        return False, ""

    def analyze_start(
        self, least_reserve: int = 2000, most_reserve: int = 1500
    ) -> Tuple[List[Instruction], int]:
        # FIXME: not working if atexit register a function which is the problem
        # FIXME: this last occurence method will cause rare division from push ebp | mov ebp esp | sub esp XX
        # FIXME: what if A -> B -> A calling chain?
        last_occurence_idx = {}
        is_last_passed = {}
        all_backtrace_name = []
        for frame in self.gdb_backtrace:
            all_backtrace_name.append(frame["func"])
            last_occurence_idx[frame["func"]] = -1
            is_last_passed[frame["func"]] = False

        start_idx = -1
        self.is_main = False
        self.start_idx = start_idx
        if len(self.trace) < least_reserve or self.from_initial:
            start_idx = 0
        else:
            if len(self.trace) < most_reserve:
                most_reserve = len(self.trace) - 1
            # NOTE: only record index for function before packet.ip == entry_addr
            for idx in range(-least_reserve, -most_reserve, -1):
                instruction = self.trace[idx]
                if not self.test_plt_vdso(instruction.ip):
                    func = self.find_function(instruction.ip)
                    if func:
                        if (
                            func.name in all_backtrace_name
                            and not is_last_passed[func.name]
                        ):
                            last_occurence_idx[func.name] = idx + len(self.trace)
                            start_idx = idx
                    flg, symname = self.test_function_entry(instruction.ip)
                    if flg and symname in all_backtrace_name:
                        is_last_passed[symname] = True
        if start_idx == -1:
            raise Exception("Unable to find suitable start instruction")
        self.start_idx = (len(self.trace) + start_idx) % len(self.trace)
        self.is_start_entry, _ = self.test_function_entry(self.trace[start_idx].ip)
        function = self.find_function(self.trace[start_idx].ip)
        assert function is not None
        self.start_funcname = function.name
        return self.trace[self.start_idx :], self.start_idx

    def analyze_trace(self) -> None:
        # NOTE: assume the hooked function should have return
        self.new_trace = []
        self.call_parent: defaultdict = defaultdict(lambda: None)
        cut_trace, _ = self.analyze_start()
        hooked_parent = None
        is_current_hooked = False
        hook_idx = 0
        first_meet = False
        hook_fname = None
        # FIXME: seems dso object not always this one
        dso_sym = FakeSymbol("plt-ld", 0)
        plt_sym = None
        previous_instr = None
        for (idx, instruction) in enumerate(cut_trace):
            if idx > 0:
                previous_instr = cut_trace[idx - 1]

            present = True
            if (
                self.test_plt_vdso(instruction.ip)
                or self.test_ld(instruction.ip)
                or self.test_omit(instruction.ip)
            ):
                present = False
            # NOTE: if already in hooked function, leaving to parent
            # FIXME: gcc optimization will lead to main->func1->(set rbp)func2->main
            # A better solution is to record callstack,
            # which means we need to get jumpkind of every address,
            # but I cannot find it now. large recursive_level could slow down filter a lot
            # Or find scope outside hooked_libs
            if is_current_hooked:
                if present:
                    sym = self.find_function(instruction.ip)
                    recursive_level = 4
                    if sym == hooked_parent:
                        is_current_hooked = False
                        l.warning(" ->(back) " + sym.name)
                        hooked_parent = None
                        present = True
                        self.hook_target[hook_idx] = instruction.ip
                    else:
                        present = False
                        cur_func = hooked_parent
                        for _ in range(recursive_level):
                            parent = self.call_parent[cur_func]
                            if parent:
                                if sym == parent:
                                    is_current_hooked = False
                                    hooked_parent = None
                                    self.call_parent[cur_func] = None
                                    self.hook_target[hook_idx] = instruction.ip
                                    l.warning(" ->(back) " + sym.name)
                                    break
                                else:
                                    cur_func = parent
                            else:
                                break
                # At least when we get back to main object, it should be unhooked
                # NOTE: that doesn't work for static compiled object
                if not self.static_link:
                    if (
                        is_current_hooked
                        and not self.test_plt_vdso(instruction.ip)
                        and not self.test_ld(instruction.ip)
                        and self.project.loader.find_object_containing(instruction.ip)
                        == self.main_object
                    ):
                        is_current_hooked = False
                        hooked_parent = None
                        self.hook_target[hook_idx] = instruction.ip
                        l.warning(" ->(back) main_object")

            else:
                flg, fname = self.test_function_entry(instruction.ip)
                if flg and previous_instr is not None:
                    # NOTE: function entry, testing is hooked
                    sym = self.find_function(instruction.ip)
                    parent = self.find_function(previous_instr.ip)
                    # NOTE: plt -> dso -> libc
                    if self.test_plt_vdso(instruction.ip):
                        plt_sym = sym
                        self.call_parent[plt_sym] = parent
                    if self.test_ld(previous_instr.ip) and not self.test_ld(
                        instruction.ip
                    ):
                        self.call_parent[parent] = plt_sym
                    self.call_parent[sym] = parent
                    if self.test_hook_name(fname) and not self.test_ld(instruction.ip):
                        assert parent is not None and sym is not None
                        l.warning(parent.name + " ->(hook) " + sym.name)
                        is_current_hooked = True
                        first_meet = False
                        hooked_parent = parent
                        hook_fname = fname
                        hook_idx = idx + self.start_idx
                else:
                    if self.test_omit(instruction.ip):
                        is_current_hooked = True
                        first_meet = False
                        assert previous_instr is not None
                        hooked_parent = self.find_function(previous_instr.ip)
                        hook_idx = idx + self.start_idx
                        hook_fname = "omit"
            flg, fname = self.test_function_entry(instruction.ip)
            if (
                is_current_hooked
                and not first_meet
                and not self.test_plt_vdso(instruction.ip)
                and not self.test_ld(instruction.ip)
                and not self.test_omit(instruction.ip)
            ):
                present = True
                first_meet = True
                l.warning("entry: " + fname + " " + hex(instruction.ip))
            if present:
                self.new_trace.append(instruction)
                self.trace_idx.append(idx + self.start_idx)

    def filtered_trace(
        self, update: bool = False
    ) -> Tuple[List[Instruction], List[int], Dict[int, int]]:
        if self.new_trace and not update:
            return self.new_trace, self.trace_idx, self.hook_target
        self.analyze_trace()
        return self.new_trace, self.trace_idx, self.hook_target
