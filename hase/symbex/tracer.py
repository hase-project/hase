from __future__ import absolute_import, division, print_function

import angr
import logging
import os
import struct
import archinfo
from angr import sim_options as so
from angr.state_plugins.sim_action import SimActionExit
from angr.knowledge_plugins.functions.function import Function
from angr import SimState, SimProcedure, PointerWrapper, SIM_PROCEDURES
from angr.sim_type import SimTypeString, SimTypeInt
from typing import List, Any, Dict, Tuple, Optional
from pygdbmi.gdbcontroller import GdbController

from ..perf import read_trace, Branch
from ..pwn_wrapper import ELF, Coredump
from ..mapping import Mapping

from .state import State
from .hook import all_hookable_symbols

l = logging.getLogger(__name__)
hdlr = logging.FileHandler("../replay.log")
l.addHandler(hdlr)

ELF_MAGIC = b"\x7fELF"


class CoredumpGDB():
        
    def __init__(self, elf, coredump):
        self.coredump = coredump
        self.elf = elf
        self.corefile = self.coredump.file.name
        self.execfile = self.elf.file.name
        # XXX: use --nx will let manually set debug-file-directory 
        # and unknown cause for not showing libc_start_main and argv
        self.gdb = GdbController(gdb_args=['--quiet', '--interpreter=mi2'])
        self.setup_gdb()

    def setup_gdb(self):
        self.write_request("file {}".format(self.execfile))
        self.write_request("core {}".format(self.corefile))

    def write_request(self, req, **kwargs):
        timeout_sec = kwargs.pop('timeout_sec', 1)
        kwargs['read_response'] = False
        self.gdb.write(req, timeout_sec=timeout_sec, **kwargs)
        resp = []
        while True:
            try:
                resp += self.gdb.get_gdb_response()
            except:
                break
        return resp

    def parse_frame(self, r):
        # type: (str) -> Dict[str, Any]
        attrs = {}
        # NOTE: #n  addr in func (args=args[ <name>][@entry=v]) at source_code[:line]\n
        r = r.replace('\\n', '')
        attrs['index'] = r.partition(' ')[0][1:]
        r = r.partition(' ')[2][1:]
        attrs['addr'] = r.partition(' ')[0]
        r = r.partition(' ')[2]
        r = r.partition(' ')[2]
        attrs['func'] = r.partition(' ')[0]
        r = r.partition(' ')[2]
        args = r.partition(')')[0][1:].split(', ')
        args_list = []

        # NOTE: remove <xxx>
        def remove_comment(arg):
            if arg.find('<') != -1:
                arg = arg.partition('<')[0]
                arg = arg.replace(' ', '')
            return arg

        for arg in args:
            if arg.find('@') != -1:
                name, _, entry_ = arg.partition('@')
            else:
                name = arg
                entry_ = None
            name, _, value = name.partition('=')
            value = remove_comment(value)
            if entry_:
                _, _, entry = entry_.partition('=')
                entry = remove_comment(entry)
                args_list.append([name, value, entry])
            else:
                args_list.append([name, value, None])
        attrs['args'] = args_list
        r = r.partition(')')[2]
        r = r.partition(' ')[2]
        r = r.partition(' ')[2]
        if r.find(':') != -1:
            source, _, line = r.partition(':')
        else:
            source = r
            line = '?'
        attrs['file'] = source
        attrs['line'] = line
        return attrs

    def parse_addr(self, r):
        # $n = (...) 0xaddr <name>
        l = r.split(' ')
        for blk in l:
            if blk.startswith('0x'):
                return int(blk, 16)
        return 0

    def parse_offset(self, r):
        # addr <+offset>:  inst
        l = r.split(' ')
        for blk in l:
            if blk.startswith('<+'):
                idx = blk.find('>')
                return int(blk[2:idx])
        return 0

    def backtrace(self):
        resp = self.write_request("where")
        bt = []
        for r in resp:
            payload = r['payload']
            if payload and payload[0] == '#':
                print(payload)
                bt.append(self.parse_frame(payload))
        return bt

    def get_symbol(self, addr):
        # type: (int) -> str
        resp = self.write_request("info symbol {}".format(addr))
        return resp[1]['payload']

    def get_rbp(self, n):
        # type: (int) -> str
        resp = self.write_request("info frame {}".format(n))
        idx = resp[8]['payload'].find('rbp at')
        value = int(resp[8]['payload'][idx+7:].partition(',')[0], 16)
        return value

    def get_func_range(self, name):
        # type: (str) -> List[int]
        # FIXME: Not a good idea. Maybe some gdb extension?
        r1 = self.write_request("print &{}".format(name))
        addr = self.parse_addr(r1[1]['payload'])
        r2 = self.write_request("disass {}".format(name))
        size = self.parse_offset(r2[-3]['payload'])
        return [addr, size + 1]


class CoredumpAnalyzer():
    def __init__(self, elf, coredump):
        # type: (Coredump, int, int) -> None
        self.coredump = coredump
        self.elf = elf
        self.gdb = CoredumpGDB(elf, coredump)
        self.backtrace = self.gdb.backtrace()
        self.argc = self.coredump.argc
        self.argv = [self.read_argv(i) for i in range(self.argc)]
        self.argv_addr = [self.read_argv_addr(i) for i in range(self.argc)]
    
    def read_stack(self, addr, length=0x1):
        # type: (int, int) -> str
        assert self.coredump.stack.start <= addr < self.coredump.stack.stop
        offset = addr - self.coredump.stack.start
        return self.coredump.stack.data[offset:offset+length]

    def read_argv(self, n):
        # type: (int) -> str
        assert 0 <= n < self.coredump.argc
        return self.coredump.string(self.coredump.argv[n])

    def read_argv_addr(self, n):
        # type: (int) -> int
        assert 0 <= n < self.coredump.argc
        return self.coredump.argv[n]

    @property
    def env(self):
        return self.coredump.env

    @property
    def registers(self):
        return self.coredump.registers

    @property
    def stack_start(self):
        return self.coredump.stack.start
    
    @property
    def stack_stop(self):
        return self.coredump.stack.stop
    
    def call_argv(self, name):
        for bt in self.backtrace:
            if bt['func'] == name:
                args = []
                for _, value, entry in bt['args']:
                    if entry:
                        args.append(int(entry, 16))
                    else:
                        if value != '':
                            args.append(int(value, 16))
                        else:
                            args.append(None)
                return args
        raise Exception("Unknown function {} in backtrace".format(name))

    def frame_rbp(self, name):
        for bt in self.backtrace:
            if bt['func'] == name:
                return self.gdb.get_rbp(int(bt['index']))


def build_load_options(mappings):
    # type: (List[Mapping]) -> dict
    """
    Extract shared object memory mapping from coredump
    """
    main = mappings[0]
    lib_opts = {}  # type: dict
    force_load_libs = []
    for m in mappings[1:]:
        if not m.path.startswith("/") or m.path in lib_opts:
            continue
        with open(m.path, "rb") as f:
            magic = f.read(len(ELF_MAGIC))
            if magic != ELF_MAGIC:
                continue
        lib_opts[m.path] = dict(custom_base_addr=m.start)
        force_load_libs.append(m.path)

    # TODO: extract libraries from core dump instead ?
    return dict(
        main_opts={"custom_base_addr": main.start},
        force_load_libs=force_load_libs,
        lib_opts=lib_opts,
        load_options={"except_missing_libs": True})


class Tracer(object):
    def __init__(self,
                 executable,
                 thread_id,
                 trace_path,
                 coredump,
                 mappings,
                 executable_root=None):
        # type: (str, int, str, str, List[Mapping], Optional[str]) -> None
        self.executable = executable
        self.mappings = mappings
        options = build_load_options(mappings)
        self.project = angr.Project(executable, **options)

        self.coredump = Coredump(coredump)

        command = os.path.basename(self.coredump.string(self.coredump.argv[0]))

        trace = read_trace(
            trace_path, thread_id, command, executable_root=executable_root)
        self.trace = trace

        if self.trace[-1].ip == 0:  # trace last ends in syscall
            self.trace[-1].ip = self.coredump.registers["rip"]

        assert self.project.loader.main_object.os.startswith('UNIX')

        self.elf = ELF(executable)

        start = self.elf.symbols.get('_start')
        main = self.elf.symbols.get('main')

        self.cdanalyzer = CoredumpAnalyzer(
            self.elf, self.coredump)

        for (idx, event) in enumerate(self.trace):
            if event.addr == start or event.addr == main or \
                    event.ip == start or event.ip == main:
                self.trace = trace[idx:]

        remove_simplications = {
            so.LAZY_SOLVES, so.EFFICIENT_STATE_MERGING,
            so.TRACK_CONSTRAINT_ACTIONS
        } | so.simplification

        # workaround for main, should not be required in future
        if self.trace[0].addr == 0 or self.trace[0].ip == main:
            start_address = self.trace[0].ip
        else:
            start_address = self.trace[0].addr

        assert start_address != 0

        self.cfg = self.project.analyses.CFGFast(show_progressbar=True)

        self.hooked_symbol = all_hookable_symbols.copy()
        self.omitted_symbol = {}
        # XXX: collected from testing coreutils
        self.unsupported_symbol = [
            '__strncmp_sse42',
            '__strncmp_sse2',
            '__strcmp_sse2',
            '__strcmp_sse2_unaligned',
            '__strchr_sse2',
            '__memcpy_sse2',
            '__mempcpy_sse2',
            '__new_exitfn',
            '_nl_find_locale',
            '_nl_find_locale',
            '_nl_load_locale_from_archive',
            '_nl_normalize_codeset',
            '_nl_intern_locale_data',
            '_nl_postload_ctype',
            'new_composite_name',
            'sbrk',
            'malloc_hook_ini',
            'ptmalloc_init',
            '_int_malloc',
            '_int_free',
            'malloc_consolidate',
            'sysmalloc',
            '__default_morecore',
            'memmem',
        ]
        self.setup_hook()

        args = self.cdanalyzer.call_argv('main')

        self.start_state = self.project.factory.call_state(
            start_address,
            *args,
            stack_base=self.cdanalyzer.frame_rbp('main'),
            add_options=set([so.TRACK_JMP_ACTIONS]),
            remove_options=remove_simplications)

        self.setup_argv()

        self.simgr = self.project.factory.simgr(
            self.start_state,
            save_unsat=True,
            hierarchy=False,
            save_unconstrained=True)

        # HACK: brute-force idea of ripping plt stubs / ld functions (like _dl_load_xxx)
        self.no_plt_trace = []
        for event in self.trace:
            if self.test_plt(event.addr) or \
                self.test_ld(event.addr) or \
                self.test_hook(event.addr) or \
                self.test_omit(event.addr):
                continue
            self.no_plt_trace.append(event)

        self.old_trace = self.trace
        self.trace = self.no_plt_trace

        # For debugging
        # self.project.pt = self


    def test_plt(self, addr):
        # NOTE: .plt or .plt.got
        return self.project.loader.find_section_containing(addr).name.startswith('.plt')

    def test_ld(self, addr):
        o = self.project.loader.find_object_containing(addr)
        return o == self.project.loader.linux_loader_object

    def test_hook(self, addr):
        # FIXME: use angr.project.loader.describe_addr cannot find
        for _, l in self.hooked_symbol.items():
            if l[1] <= addr < l[1] + l[2]:
                return True
        return False

    def test_omit(self, addr):
        for _, l in self.omitted_symbol.items():
            if l[0] <= addr < l[0] + l[1]:
                return True
        return False

    def setup_argv(self):
        args = self.cdanalyzer.call_argv('main')
        argv_addr = args[1]
        for i in range(len(self.coredump.argv)):
            self.start_state.memory.store(
                argv_addr + i * 8, 
                self.coredump.argv[i],
                endness=archinfo.Endness.LE)
            self.start_state.memory.store(
                self.coredump.argv[i],
                self.coredump.string(self.coredump.argv[i]),
                endness=archinfo.Endness.LE)

    def setup_hook(self):
        fm = self.cfg.kb.functions
        for symname in self.unsupported_symbol:
            self.omitted_symbol[symname] = self.get_func_range(symname, True)
            func = fm.function(name=symname)
            if func:
                self.collect_subfunc(func)
        for symname, l in self.hooked_symbol.items():
            self.hooked_symbol[symname] += self.get_func_range(symname)
            func = fm.function(name=symname)
            if func:
                self.collect_subfunc(func)
        for symname, l in self.hooked_symbol.items():
            self.project.hook_symbol(
                symname, l[0]
            )
        
    def get_func_range(self, symname, by_gdb=False):
        res = [None, None]
        print(symname)
        if by_gdb:
            return self.cdanalyzer.gdb.get_func_range(symname)
        else:
            sym = self.project.loader.find_symbol(symname)
            if not sym:
                return [0, 0]
            res[0] = sym.rebased_addr
            if sym.size:
                res[1] = sym.size
            else:
                func = self.cfg.kb.functions.function(name=symname)
                if func:
                    res[1] = func.size
                else:
                    res[1] = 0
        return res

    def collect_subfunc(self, func):
        for nodel in func.nodes.items():
            node = nodel[0]
            if isinstance(node, Function) and \
                node.name not in self.omitted_symbol.keys():
                self.omitted_symbol[node.name] = self.get_func_range(node.name)
                self.collect_subfunc(node)

    def register_omit(self, symname, by_gdb=False):
        self.omitted_symbol[symname] = \
            self.get_func_range(symname, by_gdb)

    def jump_was_not_taken(self, old_state, new_state):
        # was the last control flow change an exit vs call/jump?
        ev = new_state.events[-1]
        instructions = old_state.block().capstone.insns
        assert isinstance(ev, SimActionExit) and len(instructions) == 1
        size = instructions[0].insn.size
        return (new_state.addr - size) == old_state.addr

    def find_next_branch(self, state, branch):
        # type: (SimState, Branch) -> SimState
        cnt = 0
        while cnt < 2000:
            cnt += 1
            l.debug("0x%x", state.addr)
            # FIXME: current stuck at various places
            choices = self.project.factory.successors(
                state, num_inst=1).successors
            old_state = state
            print(state, cnt, branch)
            if choices == []:
                print(choices, state, branch)
                raise Exception("Unable to continue")
            if len(choices) <= 2:
                for choice in choices:
                    if old_state.addr == branch.addr and choice.addr == branch.ip:
                        l.debug("jump 0%x -> 0%x", old_state.addr, choice.addr)
                        return choice
                    if len(choices) == 1 or self.jump_was_not_taken(
                            old_state, choice):
                        state = choice
            else:
                # There should be never more then dot!
                import pry
                pry.set_trace()
        print(choices, state, branch)
        raise Exception("Unable to continue")

    def valid_address(self, address):
        # type: (int) -> bool
        return self.project.loader.find_object_containing(address)

    def constrain_registers(self, state):
        # type: (State) -> None
        # FIXME: if exception caught is omitted by hook?
        assert state.registers['rip'].value == self.coredump.registers['rip']
        registers = [
            "gs", "rip", "rdx", "r15", "rax", "rsi", "rcx", "r14", "fs", "r12",
            "r13", "r10", "r11", "rbx", "r8", "r9", "rbp", "eflags", "rdi"
        ]
        # TODO: constrain $rsp when we switch to CallState
        for name in registers:
            state.registers[name] = self.coredump.registers[name]

    def run(self):
        # type: () -> List[State]
        simstate = self.simgr.active[0]
        states = []
        states.append(State(self.trace[0], simstate))
        for event in self.trace[1:]:
            l.debug("look for jump: 0x%x -> 0x%x" % (event.addr, event.ip))
            assert self.valid_address(event.addr) and self.valid_address(
                event.ip)
            new_simstate = self.find_next_branch(simstate, event)
            simstate = new_simstate
            states.append(State(event, new_simstate))
        self.constrain_registers(states[-1])

        return states
