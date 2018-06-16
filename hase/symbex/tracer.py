from __future__ import absolute_import, division, print_function

import angr
import logging
import os
import sys
import struct
import archinfo
import claripy
from angr import sim_options as so
from angr.state_plugins.sim_action import SimActionExit
from angr.knowledge_plugins.functions.function import Function
from angr import SimState, SimProcedure, PointerWrapper, SIM_PROCEDURES
from typing import List, Any, Dict, Tuple, Optional
from pygdbmi.gdbcontroller import GdbController
from collections import deque

from ..perf import read_trace, Branch
from ..pwn_wrapper import ELF, Coredump
from ..mapping import Mapping

from .state import State
from .hook import all_hookable_symbols, addr_symbols
from .filter import FilterTrace

l = logging.getLogger("hase")

ELF_MAGIC = b"\x7fELF"


class CoredumpGDB():
        
    def __init__(self, elf, coredump):
        self.coredump = coredump
        self.elf = elf
        self.corefile = self.coredump.file.name
        self.execfile = self.elf.file.name
        # XXX: use --nx will let manually set debug-file-directory 
        # and unknown cause for not showing libc_start_main and argv
        # FIXME: get all response and retry if failed
        self.gdb = GdbController(gdb_args=['--quiet', '--interpreter=mi2'])
        # pwnlibs response
        self.get_response()
        self.setup_gdb()

    def setup_gdb(self):
        self.write_request("file {}".format(self.execfile))
        self.write_request("core {}".format(self.corefile))

    def get_response(self):
        resp = []
        while True:
            try:
                resp += self.gdb.get_gdb_response()
            except:
                break
        return resp
        
    def write_request(self, req, **kwargs):
        timeout_sec = kwargs.pop('timeout_sec', 1)
        kwargs['read_response'] = False
        self.gdb.write(req, timeout_sec=timeout_sec, **kwargs)
        resp = self.get_response()
        return resp

    def parse_frame(self, r):
        # type: (str) -> Dict[str, Any]
        attrs = {} # Dict[str, Any]
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
                entry_ = ''
            name, _, value = name.partition('=')
            value = remove_comment(value)
            if entry_:
                _, _, entry = entry_.partition('=')
                entry = remove_comment(entry)
                args_list.append([name, value, entry])
            else:
                args_list.append([name, value, ''])
        attrs['args'] = args_list # type: ignore
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
        # type: (int) -> int
        resp = self.write_request("info frame {}".format(n))
        idx = resp[8]['payload'].find('rbp at')
        if idx == -1:
            return 0
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
        # type: ignore
        # NOTE: a op b op c will invoke weird typing
        assert self.coredump.stack.start <= addr < self.coredump.stack.stop
        offset = addr - self.coredump.stack.start
        return self.coredump.stack.data[offset:offset+length]

    def read_argv(self, n):
        # type: ignore
        assert 0 <= n < self.coredump.argc
        return self.coredump.string(self.coredump.argv[n])

    def read_argv_addr(self, n):
        # type: ignore
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
    # FIXME: actually this library path different will cause 
    # simulation path different? need re-record if original 
    # executable is recompiled
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

        args = self.cdanalyzer.call_argv('main')
        # NOTE: gdb sometimes take this wrong
        args[0] = self.coredump.argc

        rbp = self.cdanalyzer.frame_rbp('main')

        if not rbp:
            rbp = 0x7fffffffcf00

        for (idx, event) in enumerate(self.trace):
            if event.addr == start or event.addr == main or \
                    event.ip == start or event.ip == main:
                self.trace = trace[idx:]

        remove_simplications = {
            so.LAZY_SOLVES, so.EFFICIENT_STATE_MERGING,
            so.TRACK_CONSTRAINT_ACTIONS,
            so.ALL_FILES_EXIST,
        } | so.simplification

        # workaround for main, should not be required in future
        if self.trace[0].addr == 0 or self.trace[0].ip == main:
            start_address = self.trace[0].ip
        else:
            start_address = self.trace[0].addr

        assert start_address != 0

        self.cfg = self.project.analyses.CFGFast(
            show_progressbar=True
        )

        self.use_hook = False
        self.omitted_section = []

        if self.use_hook:
            self.hooked_symbols = all_hookable_symbols.copy()
            self.setup_hook()
        else:
            self.hooked_symbols = {}
            self.project._sim_procedures = {}

        self.filter = FilterTrace(
            self.project, 
            self.cfg, 
            self.trace,
            self.hooked_symbols,
            self.cdanalyzer.gdb,
            self.omitted_section
        )

        self.use_callstate = True

        # NOTE: weird, angr invokes SimMemoryAddressException when use concrete value to read
        
        if self.use_callstate:
            self.start_state = self.project.factory.call_state(
                start_address,
                *args,
                stack_base=rbp,
                add_options=set([
                    so.TRACK_JMP_ACTIONS,
                    so.CONSERVATIVE_READ_STRATEGY,
                    so.CONSERVATIVE_WRITE_STRATEGY,
                ]),
                remove_options=remove_simplications)

            self.setup_argv()
        else:
            self.start_state = self.project.factory.blank_state(
                add_options=set([
                    so.TRACK_JMP_ACTIONS,
                    so.CONSERVATIVE_READ_STRATEGY,
                ]),
                remove_options=remove_simplications)

        self.simgr = self.project.factory.simgr(
            self.start_state,
            save_unsat=True,
            hierarchy=False,
            save_unconstrained=True)

        self.old_trace = self.trace
        self.trace = self.filter.filtered_trace()

        # For debugging
        # self.project.pt = self

    def setup_argv(self):
        args = self.cdanalyzer.call_argv('main')
        argv_addr = args[1]
        for i in range(len(self.coredump.argv)):
            self.start_state.memory.store(
                argv_addr + i * 8, 
                self.coredump.argv[i],
                endness=archinfo.Endness.LE
            )
            self.start_state.memory.store(
                self.coredump.argv[i],
                self.coredump.string(self.coredump.argv[i])[::-1],
                endness=archinfo.Endness.LE
            )

    def setup_hook(self):
        for symname, func in self.hooked_symbols.items():
            self.project.hook_symbol(
                symname, func()
            )
        for symname in addr_symbols:
            if symname in self.hooked_symbols.keys():
                r = self.cdanalyzer.gdb.get_func_range(symname)
                func = self.hooked_symbols[symname]
                if r != [0, 0]:
                    self.project.hook(
                        r[0], func(), length=r[1]
                    )
                    self.omitted_section.append(r)

    def test_rep_ins(self, state):
        capstone = state.block().capstone
        first_ins = capstone.insns[0].insn
        # NOTE: maybe better way is use prefix == 0xf2, 0xf3 (crc32 exception)
        ins_repr = first_ins.mnemonic
        return ins_repr.startswith('rep')

    def jump_match(self, old_state, choice, branch):
        if old_state.addr == branch.addr and choice.addr == branch.ip:
            l.debug("jump 0%x -> 0%x", old_state.addr, choice.addr)
            return True
        return False        

    def jump_was_not_taken(self, old_state, new_state):
        # was the last control flow change an exit vs call/jump?
        ev = new_state.events[-1]
        instructions = old_state.block().capstone.insns
        if not isinstance(ev, SimActionExit): # and len(instructions) == 1
            return False
        size = instructions[0].insn.size
        return (new_state.addr - size) == old_state.addr

    def find_next_branch(self, state, branch):
        # type: (SimState, Branch) -> SimState
        CNT_LIMIT = 200
        REP_LIMIT = 128
        cnt = 0
        rep_cnt = 0
        while cnt < CNT_LIMIT:
            cnt += 1
            self.debug_state.append(state)
            try:
                step = self.project.factory.successors(
                    state, 
                    num_inst=1)
            except:
                # weird syscall ip issue
                # currently just try to repair ip
                state._ip = self.debug_state[-2].addr
                step = self.project.factory.successors(
                    state, 
                    num_inst=1)
            # weird stpcpy -> IFuncResolver issue
            artifacts = getattr(step, 'artifacts', None)
            if artifacts and 'procedure' in artifacts.keys() \
                and artifacts['name'] == 'IFuncResolver':
                func = self.filter.find_function(self.debug_state[-2].addr)
                if func:
                    addr = self.project.loader.find_symbol(func.name).rebased_addr
                    step = self.project.factory.successors(
                        state,
                        num_inst=1,
                        force_addr=addr
                    )
                else:
                    raise Exception("Cannot resolve function")
            # l.debug("0x%x", state.addr)
            all_choices = {
                'sat': step.successors,
                'unsat': step.unsat_successors,
                'unconstrained': step.unconstrained_successors,
            }
            # lookup sequence: sat, unsat, unconstrained
            choices = [] # type: List[Any]
            choices += all_choices['sat']
            choices += all_choices['unsat']
            # choices += all_choices['unconstrained']
            old_state = state
            l.warning(
                repr(cnt) + ' ' +
                repr(state) + ' ' +
                # repr(all_choices) + ' ' +
                repr(branch) + '\n'
            )
            if choices == []:
                raise Exception("Unable to continue")
            try:
                if choices[0].addr == branch.addr:
                    self.current_state = choices[0]
            except:
                pass
            for choice in choices:
                if old_state.addr == branch.addr:
                    if self.jump_match(old_state, choice, branch):
                        return choice
            # NOTE: need to consider repz here, if repz repeats for less than N times, 
            # then, it should still be on sat path
            if self.test_rep_ins(state):
                rep_cnt += 1
                if rep_cnt < REP_LIMIT and len(all_choices['sat']) == 1:
                    state = all_choices['sat'][0]
                    continue
            else:
                rep_cnt = 0
            for choice in choices:
                if self.jump_was_not_taken(
                    old_state, choice):
                    state = choice
                    break
            else:
                if len(all_choices['sat']) == 1:
                    state = all_choices['sat'][0]
                elif len(choices) == 1:
                    state = choices[0]
                else:
                    raise Exception("Unable to continue")
            if not state.solver.satisfiable(): # type: ignore
                sat_constraints = old_state.solver._solver.constraints
                unsat_constraints = state.solver._solver.constraints
                sat_uuid = map(lambda c: c.uuid, sat_constraints)
                for i, c in enumerate(unsat_constraints):
                    if c.uuid in sat_uuid:
                        unsat_constraints[i] = claripy.Not(c)
                state.solver._solver._cached_satness = True
                state.solver._solver.constraints = old_state.solver._solver.constraints
                if not self.debug_unsat:
                    self.debug_sat = old_state
                    self.debug_unsat = state
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
        self.debug_unsat = None
        self.debug_state = deque(maxlen=100) # type: deque
        for event in self.trace[1:]:
            l.debug("look for jump: 0x%x -> 0x%x" % (event.addr, event.ip))
            assert self.valid_address(event.addr) and self.valid_address(
                event.ip)
            self.current_branch = event
            new_simstate = self.find_next_branch(simstate, event)
            simstate = new_simstate
            states.append(State(event, new_simstate))
        self.constrain_registers(states[-1])

        return states
