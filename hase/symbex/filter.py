import logging
from bisect import bisect
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from angr import Project, SimProcedure

from ..pt.events import Instruction
from .hook import common_prefix, common_suffix, unsupported_symbols

if False:  # for mypy
    from .cdanalyzer import CoredumpGDB

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


def symbol_name(symbol: Optional[FakeSymbol]) -> str:
    if symbol is None:
        return "unknown"
    else:
        return symbol.name


class FilterBase:
    def __init__(
        self,
        project: Project,
        trace: List[Instruction],
        hooked_symbol: Dict[str, SimProcedure],
        gdb: "CoredumpGDB",
        omitted_section: List[List[int]],
    ) -> None:

        self.project = project
        self.main_cfg = self.project.analyses.CFGFast(show_progressbar=True)
        self.main_object = project.loader.main_object
        self.trace = trace
        self.hooked_symbol = hooked_symbol
        self.gdb = gdb
        self.new_trace: List[Instruction] = []
        self.omitted_section = omitted_section
        self.hooked_symname = list(self.hooked_symbol.keys())
        self.hooked_addon: List[Tuple[str, int]] = []

        self.analyze_unsupported()

        self.syms: Dict[Any, List[int]] = {}
        self.syms_dict: Dict[Any, Dict[int, Any]] = {}
        for lib in self.project.loader.all_elf_objects:
            self.syms_dict[lib] = lib.symbols_by_addr.copy()
            self.syms[lib] = list(self.syms_dict[lib].keys())
            self.syms[lib].sort()

    def add_hook_omit_symbol(self, fname: str, name: str, ip: int) -> None:
        l.info(f"Adding new hook: {fname} with old hook {name}")
        func = self.hooked_symbol[name]
        self.project.hook(ip, func(), length=4)
        self.hooked_addon.append((fname, ip))

    def analyze_unsupported(self) -> None:
        for lsym in unsupported_symbols:
            try:
                r = self.gdb.get_func_range(lsym[0])
            except Exception:
                l.warning("Unable to fetch {} range by gdb".format(lsym[0]))
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

    def test_hook_name(self, fname: str, ip: int) -> bool:
        if fname in self.hooked_addon:
            return True
        is_new, name = self.find_matching_name(fname)
        if name is None:
            return False
        if is_new:
            self.add_hook_omit_symbol(fname, name, ip)
        return True

    def solve_name_plt(self, addr: int) -> str:
        for lib in self.project.loader.all_elf_objects:
            if addr in lib.reverse_plt.keys():
                return lib.reverse_plt[addr]
        return ""

    def find_matching_name(self, fname: str) -> Tuple[bool, Optional[str]]:
        for name in self.hooked_symname:
            if fname == name:
                return False, name
            for prefix in common_prefix:
                if prefix + name in fname:
                    return True, name
            for suffix in common_suffix:
                if name + suffix in fname:
                    return True, name
        return False, None

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


class FilterTrace(FilterBase):
    def __init__(
        self,
        project: Project,
        trace: List[Instruction],
        hooked_symbol: Dict[str, SimProcedure],
        gdb: "CoredumpGDB",
        omitted_section: List[List[int]],
        static_link: bool,
    ) -> None:
        super().__init__(project, trace, hooked_symbol, gdb, omitted_section)

        self.trace_idx: List[int] = []
        self.hook_target: Dict[int, int] = {}
        self.hook_entry: List[Tuple[int, Instruction, str]] = []
        self.static_link = static_link
        self.analyze_trace()

    def entry_check(self) -> None:
        for idx, entry, fname in self.hook_entry:
            if not self.project.is_hooked(entry.ip):
                print(idx, entry, fname)
                _, name = self.find_matching_name(fname)
                if name is not None:
                    self.add_hook_omit_symbol(fname, name, entry.ip)

    def desc_call_parent(self) -> None:
        for k, v in self.call_parent.items():
            if v is not None:
                name = v.name
                if isinstance(v, FakeSymbol):
                    name = "fake_" + name
                chain = [name]
                while v in self.call_parent.keys():
                    v = self.call_parent[v]
                    if v is not None:
                        name = v.name
                        if isinstance(v, FakeSymbol):
                            name = "fake_" + name
                        chain.append(name)
                    else:
                        break
                print(k, chain)
            print(k, "None")

    def analyze_trace(self) -> None:
        # NOTE: assume the hooked function should have return
        self.new_trace = []
        self.call_parent: defaultdict = defaultdict(lambda: None)
        hooked_parent = None
        is_current_hooked = False
        hook_idx = 0
        first_meet = False
        plt_sym = FakeSymbol("all-plt-entry", 0)
        previous_instr = None
        for (idx, instruction) in enumerate(self.trace):
            if idx > 0:
                previous_instr = self.trace[idx - 1]

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
                        l.debug(" ->(back) " + sym.name)
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
                                    l.debug(" ->(back) " + sym.name)
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
                        l.debug(" ->(back) main_object")

            else:
                flg, fname = self.test_function_entry(instruction.ip)
                if flg and previous_instr is not None:
                    # NOTE: function entry, testing is hooked
                    sym = self.find_function(instruction.ip)
                    parent = self.find_function(previous_instr.ip)
                    self.call_parent[sym] = parent
                    # NOTE: main -> plt -> dso -> libc
                    if self.test_plt_vdso(instruction.ip):
                        if not self.test_plt_vdso(previous_instr.ip):
                            self.call_parent[plt_sym] = parent
                            self.call_parent[sym] = plt_sym
                        else:
                            self.call_parent[parent] = plt_sym
                    if self.test_ld(previous_instr.ip) and not self.test_ld(
                        instruction.ip
                    ):
                        self.call_parent[sym] = plt_sym
                    # NOTE: plt.jumptable (non-entry) -> libc (in libc)
                    if (
                        not self.test_plt_vdso(instruction.ip)
                        and not self.test_ld(instruction.ip)
                        and self.test_plt_vdso(previous_instr.ip)
                        and not self.test_function_entry(previous_instr.ip)[0]
                    ):
                        self.call_parent[sym] = self.find_function(
                            self.trace[idx - 2].ip
                        )
                    real_parent = self.call_parent[sym]
                    if self.test_hook_name(fname, instruction.ip) and not self.test_ld(
                        instruction.ip
                    ):
                        l.debug(
                            f"{symbol_name(parent)} -> {symbol_name(real_parent)} ->(hook) {symbol_name(sym)}"
                        )
                        is_current_hooked = True
                        first_meet = False
                        hooked_parent = real_parent
                        hook_idx = idx
                else:
                    if self.test_omit(instruction.ip):
                        is_current_hooked = True
                        first_meet = False
                        assert previous_instr is not None
                        hooked_parent = self.find_function(previous_instr.ip)
                        hook_idx = idx
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
                l.debug("entry: " + fname + " " + hex(instruction.ip))
                self.hook_entry.append((idx, instruction, fname))
            if present:
                self.new_trace.append(instruction)
                self.trace_idx.append(idx)

    def filtered_trace(
        self, update: bool = False
    ) -> Tuple[List[Instruction], List[int], Dict[int, int]]:
        if self.new_trace and not update:
            return self.new_trace, self.trace_idx, self.hook_target
        self.analyze_trace()
        return self.new_trace, self.trace_idx, self.hook_target
