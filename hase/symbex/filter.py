from bisect import bisect
from collections import defaultdict

from angr import Project
from angr.analyses.cfg import CFGFast
from angr.knowledge_plugins.functions.function import Function
from typing import List, Optional, Dict, Any

from .state import Branch
from .hook import unsupported_symbols
from .symbex.tracer import CoredumpGDB


class FakeSymbol():
    def __init__(self, name, addr):
        self.name = name
        self.rebased_addr = addr

    def __eq__(self, other):
        if other == None:
            return False
        return self.name == other.name and self.rebased_addr == other.rebased_addr

    def __hash__(self):
        return hash((self.name, self.rebased_addr))


class FilterBase(object):
    def __init__(self, project, cfg, trace, hooked_symbol, gdb):
        # type: (Project, CFGFast, List[Branch], Dict[str, SimProcedure], CoredumpGDB) -> None
        self.project = project
        self.main_cfg = cfg
        self.main_object = project.loader.main_object
        self.trace = trace
        self.hooked_symbol = hooked_symbol
        self.gdb = gdb
        self.new_trace = []
        self.gdb = gdb
        self.omitted_section = []
        self.analyze_unsupported()

    def analyze_unsupported(self):
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


class FilterTrace():
    def __init__(self, project, cfg, trace, hooked_symbol, gdb):
        # type: (Project, CFGFast, List[Branch], Dict[str, SimProcedure], CoredumpGDB) -> None
        # FIXME: super cannot work for reload
        # super(FilterTrace, self).__init__(project, cfg, trace, hooked_symbol)
        self.project = project
        # FIXME: actually a copy should be better to preserve unhooked state
        # however, cfg.copy() don't copy kb...
        self.main_cfg = cfg
        self.main_object = project.loader.main_object
        self.trace = trace
        self.hooked_symbol = hooked_symbol
        self.new_trace = []
        self.gdb = gdb
        self.omitted_section = []
        self.analyze_unsupported()

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

        self.syms = {}
        for lib in self.project.loader.all_elf_objects:
            self.syms[lib] = lib.symbols_by_addr.keys()
            self.syms[lib].sort()
        self.resolve_plt_section = []
        self.analyze_trace()
    
    def analyze_unsupported(self):
        for l in unsupported_symbols:
            self.omitted_section.append(
                self.gdb.get_func_range(l[0])
            )

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
        for lib, sym in self.syms.items():
            if lib.contains_addr(addr):
                # FIXME: angr cannot solve plt symbol name
                if self.test_plt_vdso(addr):
                    name = self.solve_name_plt(addr)
                    if name:
                        sym = FakeSymbol(name, addr)
                        return sym
                idx = bisect(sym, addr) - 1
                entry = sym[idx]
                return lib.symbols_by_addr[entry]
        return None

    def test_function_entry(self, addr):
        # type: (int) -> (bool, str)
        sym = self.find_function(addr)
        if sym.rebased_addr == addr:
            symname = sym.name
            return True, symname
        return False, None

    def analyze_trace(self):
        # type: () -> None
        # NOTE: assume the hooked function should have return
        self.new_trace = []
        call_parent = defaultdict(lambda: None)
        hooked_parent = None # last 2 unhooked
        is_current_hooked = False
        for event in self.trace:
            present = True
            if self.test_plt_vdso(event.addr) or \
                self.test_ld(event.addr) or \
                self.test_omit(event.addr):
                present = False
            # NOTE: if already in hooked function, leaving to parent
            # FIXME: -O2 optimization will lead to main->func1->(set rbp)func2->main
            # A better solution is to record callstack, 
            # which means we need to get jumpkind of every address,
            # cannot find it now.
            if is_current_hooked:
                present = False
                sym = self.find_function(event.ip)
                if sym == hooked_parent:
                    is_current_hooked = False
                    hooked_parent = None
                else:
                    if hooked_parent in call_parent.keys() and \
                        sym == call_parent[hooked_parent]:
                        is_current_hooked = False
                        hooked_parent = None
                        call_parent[hooked_parent] = None
            else:
                flg, fname = self.test_function_entry(event.ip)
                if flg:                    
                    # NOTE: function entry, testing is hooked
                    sym = self.find_function(event.ip)
                    parent = self.find_function(event.addr)
                    call_parent[sym] = parent
                    if fname in self.hooked_symname:
                        is_current_hooked = True
                        hooked_parent = parent
                        print(fname, call_parent[hooked_parent], hooked_parent)
                else:
                    if self.test_omit(event.ip):
                        is_current_hooked = True
                        hooked_parent = self.find_function(event.addr)
            if present:
                self.new_trace.append(event)
        
    def filtered_trace(self, update=False):
        if self.new_trace and not update:
            return self.new_trace
        self.analyze_trace()
        return self.new_trace


class FilterCFG():
    def __init__(self, project, cfg, trace, hooked_symbol):
        # type: (Project, CFGFast, List[Branch], Dict[str, SimProcedure]) -> None
        # FIXME: super cannot work for reload
        # super(FilterCFG, self).__init__(project, cfg, trace, hooked_symbol)
        self.project = project
        self.main_cfg = cfg.copy()
        self.main_object = project.loader.main_object
        self.trace = trace
        self.hooked_symbol = hooked_symbol
        self.new_trace = []
        self.omitted_symbol = {}
        self.cfgs = {}
        self.libc_object = None
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
        return [
            lib.offset_to_addr(func.addr - cfg.project.loader.min_addr),
            func.size
        ]

    def find_function(self, symname):
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
        raise Exception("Function {} not found".format(symname))

    def collect_subfunc(self, lib, cfg, func):
        self.omitted_symbol[func.name] = self.get_func_range(lib, cfg, func)
        for nodel in func.nodes.items():
            node = nodel[0]
            if isinstance(node, Function) and \
                node.name not in self.omitted_symbol.keys():
                lib, cfg, func = self.find_function(node.name)
                self.collect_subfunc(lib, cfg, func)

    def analyze_hook(self):
        for symname in self.hooked_symbol.keys():
            lib, cfg, func = self.find_function(symname)
            self.collect_subfunc(lib, cfg, func)

    def filtered_trace(self, update=False):
        # type: (bool) -> List[Branch]
        if self.new_trace and not update:
            return self.new_trace
        self.new_trace = []
        for event in self.trace:
            if self.test_plt(event.addr) or \
                self.test_ld(event.addr) or \
                self.test_omit(event.addr):
                continue
            self.new_trace.append(event)
        return self.new_trace
