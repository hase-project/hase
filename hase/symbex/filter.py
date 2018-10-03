from __future__ import absolute_import, division, print_function

from bisect import bisect
from collections import defaultdict

from angr import Project
from angr.analyses.cfg import CFGFast
from angr.knowledge_plugins.functions.function import Function
from angr import SimProcedure
from cle import ELF

from typing import List, Optional, Dict, Any, Tuple

from ..pt.events import Instruction
from .hook import unsupported_symbols
from .symbex.tracer import CoredumpGDB
from ..errors import HaseError


class FakeSymbol(object):
    def __init__(self, name, addr):
        # type: (str, int) -> None
        self.name = name
        self.rebased_addr = addr

    def __eq__(self, other):
        # (FakeSymbol) -> bool
        if other is None:
            return False
        return self.name == other.name and self.rebased_addr == other.rebased_addr

    def __hash__(self):
        return hash((self.name, self.rebased_addr))

    def __repr__(self):
        # () -> str
        return "FakeSymbol '{}' at {}".format(self.name, hex(self.rebased_addr))


class FilterBase(object):
    def __init__(self, project, cfg, trace, hooked_symbol, gdb):
        # type: (Project, CFGFast, List[Instruction], Dict[str, SimProcedure], CoredumpGDB) -> None
        self.project = project
        self.main_cfg = cfg
        self.main_object = project.loader.main_object
        self.trace = trace
        self.hooked_symbol = hooked_symbol
        self.gdb = gdb
        self.new_trace = [] # type: List[Instruction]
        self.gdb = gdb
        self.omitted_section = [] # type: List[List[int]]
        self.analyze_unsupported()

    def analyze_unsupported(self):
        # type: () -> None
        for l in unsupported_symbols:
            self.omitted_section.append(
                self.gdb.get_func_range(l[0])
            )

    def test_plt(self, addr):
        # type: (int) -> bool
        # NOTE: .plt or .plt.got
        section = self.project.loader.find_section_containing(addr)
        return section.name.startswith('.plt')

    def test_ld(self, addr):
        # type: (int) -> bool
        o = self.project.loader.find_object_containing(addr)
        return o == self.project.loader.linux_loader_object

    def test_omit(self, addr):
        # type: (int) -> bool
        for sec in self.omitted_section:
            if sec[0] <= addr < sec[0] + sec[1]:
                return True
        return False


class FilterTrace(object):
    def __init__(self, project, cfg, trace, \
        hooked_symbol, gdb, omitted_section, \
        from_initial, static_link, backtrace):
        # type: (Project, CFGFast, List[Instruction], Dict[str, SimProcedure], Any, List[List[int]], bool, bool, List[Dict[str, Any]]) -> None
        self.project = project
        self.main_cfg = cfg
        self.main_object = project.loader.main_object
        self.trace = trace
        self.hooked_symbol = hooked_symbol
        self.new_trace = [] # type: List[Instruction]
        self.trace_idx = [] # type: List[int]
        self.hook_target = {} # type: Dict[int, int]
        self.gdb = gdb
        self.omitted_section = omitted_section # type: List[List[int]]
        self.analyze_unsupported()
        self.from_initial = from_initial
        self.static_link = static_link
        self.gdb_backtrace = backtrace

        self.hooked_symname = self.hooked_symbol.keys()
        self.callgraph = self.main_cfg.kb.functions.callgraph
        # HACK: angr currently solve symbols by legacy name
        # Actually only solve strchr/strrchr to index/rindex
        self.libc_legacy_map = {
            'memcmp': 'bcmp',
            'memmove': 'bmove',
            'memset': 'bzero',
            'strchr': 'index',
            'strrchr': 'rindex',
        }

        for name, sub in self.libc_legacy_map.items():
            if name in self.hooked_symname:
                self.hooked_symname.append(sub)

        self.syms = {} # type: Dict[Any, List[int]]
        # NOTE: just copy the dict, or it would be slow to access by lib property
        self.syms_dict = {} # type: Dict[Any, Dict[int, Any]]
        for lib in self.project.loader.all_elf_objects:
            self.syms_dict[lib] = lib.symbols_by_addr.copy()
            self.syms[lib] = self.syms_dict[lib].keys()
            self.syms[lib].sort()
        self.analyze_trace()

    def analyze_unsupported(self):
        # type: () -> None
        for l in unsupported_symbols:
            try:
                r = self.gdb.get_func_range(l[0])
            except Exception:
                print("Unable to fetch {} range by gdb".format(l[0]))
                r = [0, 0]
            self.omitted_section.append(r)

    def test_plt_vdso(self, addr):
        # type: (int) -> bool
        # NOTE: .plt or .plt.got
        section = self.project.loader.find_section_containing(addr)
        if section:
            return section.name.startswith('.plt')
        else:
            # NOTE: unrecognizable section, regard as vDSO
            return True

    def test_ld(self, addr):
        # type: (int) -> bool
        o = self.project.loader.find_object_containing(addr)
        return o == self.project.loader.linux_loader_object

    def test_omit(self, addr):
        # type: (int) -> bool
        for sec in self.omitted_section:
            if sec[0] <= addr < sec[0] + sec[1]:
                return True
        return False

    def solve_name_plt(self, addr):
        # type: (int) -> str
        for lib in self.project.loader.all_elf_objects:
            if addr in lib.reverse_plt.keys():
                return lib.reverse_plt[addr]
        return ''

    def find_function(self, addr):
        # type: (int) -> Optional[Any]
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

    def test_function_entry(self, addr):
        # type: (int) -> Tuple[bool, str]
        sym = self.find_function(addr)
        if sym and sym.rebased_addr == addr:
            symname = sym.name
            return True, symname
        return False, ''

    def analyze_start(self, least_reserve=2000, most_reserve=1500):
        # type: (int, int) -> Tuple[List[Instruction], int]
        # FIXME: not working if atexit register a function which is the problem
        # FIXME: this last occurence method will cause rare division from push ebp | mov ebp esp | sub esp XX
        # FIXME: what if A -> B -> A calling chain?
        last_occurence_idx = {}
        is_last_passed = {}
        all_backtrace_name = []
        for frame in self.gdb_backtrace:
            all_backtrace_name.append(frame['func'])
            last_occurence_idx[frame['func']] = -1
            is_last_passed[frame['func']] = False

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
                        if func.name in all_backtrace_name and not is_last_passed[func.name]:
                            last_occurence_idx[func.name] = idx + len(self.trace)
                            start_idx = idx
                    flg, symname = self.test_function_entry(instruction.ip)
                    if flg and symname in all_backtrace_name:
                        is_last_passed[symname] = True                    
        if start_idx == -1:
            raise Exception("Unable to find suitable start instruction")
        self.start_idx = len(self.trace) + start_idx
        self.is_start_entry, _ = self.test_function_entry(self.trace[start_idx].ip)
        self.start_funcname = self.find_function(self.trace[start_idx].ip).name # type: ignore
        return self.trace[start_idx:], start_idx

    def analyze_trace(self):
        # type: () -> None
        # NOTE: assume the hooked function should have return
        self.new_trace = []
        self.call_parent = defaultdict(lambda: None)  # type: defaultdict
        cut_trace, _ = self.analyze_start()
        hooked_parent = None
        is_current_hooked = False
        hook_idx = 0
        # FIXME: seems dso object not always this one
        dso_sym = self.project.loader.find_symbol('_dl_find_dso_for_object')
        plt_sym = None
        previous_instr = None
        for (idx, instruction) in enumerate(cut_trace):
            if idx > 0:
                previous_instr = cut_trace[idx - 1]

            present = True
            if self.test_plt_vdso(instruction.ip) or \
                self.test_ld(instruction.ip) or \
                self.test_omit(instruction.ip):
                present = False
            # NOTE: if already in hooked function, leaving to parent
            # FIXME: gcc optimization will lead to main->func1->(set rbp)func2->main
            # A better solution is to record callstack,
            # which means we need to get jumpkind of every address,
            # but I cannot find it now. large recursive_level could slow down filter a lot
            # Or find scope outside hooked_libs
            if is_current_hooked:
                sym = self.find_function(instruction.ip)
                recursive_level = 4
                if sym == hooked_parent:
                    is_current_hooked = False
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
                                break
                            else:
                                cur_func = parent
                        else:
                            break
                # At least when we get back to main object, it should be unhooked
                # NOTE: that doesn't work for static compiled object
                if not self.static_link:
                    if is_current_hooked and \
                        not self.test_plt_vdso(instruction.ip) and \
                        self.project.loader.find_object_containing(instruction.ip) == self.main_object:
                        is_current_hooked = False
                        hooked_parent = None
                        self.hook_target[hook_idx] = instruction.ip

            else:
                flg, fname = self.test_function_entry(instruction.ip)
                if flg and previous_instr is not None:
                    # NOTE: function entry, testing is hooked
                    sym = self.find_function(instruction.ip)
                    parent = self.find_function(previous_instr.ip)
                    # NOTE: plt -> dso -> libc
                    if isinstance(sym, FakeSymbol):
                        plt_sym = sym
                    if parent == dso_sym:
                        self.call_parent[dso_sym] = plt_sym
                    self.call_parent[sym] = parent
                    if fname in self.hooked_symname:
                        is_current_hooked = True
                        hooked_parent = parent
                        hook_idx = idx + self.start_idx
                else:
                    if self.test_omit(instruction.ip):
                        is_current_hooked = True
                        hooked_parent = self.find_function(instruction.ip)
                        hook_idx = idx + self.start_idx
            if present:
                self.new_trace.append(instruction)
                self.trace_idx.append(idx + self.start_idx)

    def filtered_trace(self, update=False):
        # type: (bool) -> Tuple[List[Instruction], List[int], Dict[int, int]]
        if self.new_trace and not update:
            return self.new_trace, self.trace_idx, self.hook_target
        self.analyze_trace()
        return self.new_trace, self.trace_idx, self.hook_target


# Not test yet, must be slow
class FilterCFG(object):
    def __init__(self, project, cfg, trace, hooked_symbol, gdb):
        # type: (Project, CFGFast, List[Instruction], Dict[str, SimProcedure], Any) -> None
        self.project = project
        self.main_cfg = cfg.copy()
        self.main_object = project.loader.main_object
        self.trace = trace
        self.hooked_symbol = hooked_symbol
        self.new_trace = [] # type: List[Instruction]
        self.gdb = gdb
        self.omitted_symbol = hooked_symbol
        self.omitted_section = [] # type: List[Tuple[int, int]]
        # self.analyze_unsupported()

        self.cfgs = {} # type: Dict[Any, CFGFast]
        self.libc_object = None # type: Optional[ELF]
        for lib in self.project.loader.all_elf_objects:
            # FIXME: not a good way
            if lib.get_symbol('__libc_memalign'):
                self.libc_object = lib
            if lib != self.project.loader.main_object:
                self.cfgs[lib] = Project(
                    lib.binary,
                    load_options={"auto_load_libs": False},
                    show_progressbar=True
                ).analyses.CFGFast()
            else:
                self.cfgs[lib] = self.main_cfg
        # HACK: weirdly, these functions in glibc are plt stubs resolved to self
        self.libc_special_name = {
            'malloc': ('__libc_malloc', 0x484130),
            'calloc': ('__libc_calloc', 0x484d10),
            'realloc': ('__libc_realloc', 0x4846c0),
            'free': ('__libc_free', 0x4844f0),
            'memalign': ('__libc_memalign', 0x1019e00)
        }
        self.analyze_hook()

    def test_plt(self, addr):
        # type: (int) -> bool
        # NOTE: .plt or .plt.got
        section = self.project.loader.find_section_containing(addr)
        return section.name.startswith('.plt')

    def test_ld(self, addr):
        # type: (int) -> bool
        o = self.project.loader.find_object_containing(addr)
        return o == self.project.loader.linux_loader_object

    def test_omit(self, addr):
        # type: (int) -> bool
        for _, l in self.omitted_symbol.items():
            if l[0] <= addr < l[0] + l[1]:
                return True
        return False

    def get_func_range(self, lib, cfg, func):
        # type: (ELF, CFGFast, Function) -> List[int]
        return [
            lib.offset_to_addr(func.addr - cfg.project.loader.min_addr),
            func.size
        ]

    def find_function(self, symname):
        # type: (str) -> Tuple[ELF, CFGFast, Function]
        if symname in self.libc_special_name.keys():
            self.collect_subfunc(
                self.libc_object,
                self.cfgs[self.libc_object],
                self.cfgs[self.libc_object].functions.function(
                    addr=self.libc_special_name[symname][1]
                )
            )
        for lib, cfg in self.cfgs.items():
            func = cfg.functions.function(name=symname)
            if func and not func.is_plt:
                return lib, cfg, func
        raise HaseError("Function {} not found".format(symname))

    def collect_subfunc(self, lib, cfg, func):
        # type: (ELF, CFGFast, Function) -> None
        self.omitted_symbol[func.name] = self.get_func_range(lib, cfg, func)
        for nodel in func.nodes.items():
            node = nodel[0]
            if isinstance(node, Function) and \
                node.name not in self.omitted_symbol.keys():
                lib, cfg, func = self.find_function(node.name)
                self.collect_subfunc(lib, cfg, func)

    def analyze_hook(self):
        # type: () -> None
        for symname in self.hooked_symbol.keys():
            lib, cfg, func = self.find_function(symname)
            self.collect_subfunc(lib, cfg, func)

    def filtered_trace(self, update=False):
        # type: (bool) -> List[Instruction]
        if self.new_trace and not update:
            return self.new_trace
        self.new_trace = []
        for instruction in self.trace:
            if self.test_plt(instruction.ip) or \
                self.test_ld(instruction.ip) or \
                self.test_omit(instruction.ip):
                continue
            self.new_trace.append(instruction)
        return self.new_trace
