from __future__ import absolute_import, division, print_function

import angr
import logging
import os
from angr import sim_options as so
from angr.state_plugins.sim_action import SimActionExit
from angr import SimState
from typing import List, Any, Dict, Tuple, Optional

from ..perf import read_trace, Branch
from ..pwn_wrapper import ELF, Coredump
from ..mapping import Mapping

from .state import State

l = logging.getLogger(__name__)

ELF_MAGIC = b"\x7fELF"


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

        self.start_state = self.project.factory.blank_state(
            addr=start_address,
            add_options=set([so.TRACK_JMP_ACTIONS]),
            remove_options=remove_simplications)

        self.simgr = self.project.factory.simgr(
            self.start_state,
            save_unsat=True,
            hierarchy=False,
            save_unconstrained=True)

        # For debugging
        # self.project.pt = self

    def jump_was_not_taken(self, old_state, new_state):
        # was the last control flow change an exit vs call/jump?
        ev = new_state.events[-1]
        instructions = old_state.block().capstone.insns
        assert isinstance(ev, SimActionExit) and len(instructions) == 1
        size = instructions[0].insn.size
        return (new_state.addr - size) == old_state.addr

    def find_next_branch(self, state, branch):
        # type: (SimState, Branch) -> SimState
        while True:
            l.debug("0x%x", state.addr)
            choices = self.project.factory.successors(
                state, num_inst=1).successors
            old_state = state

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

    def valid_address(self, address):
        # type: (int) -> bool
        return self.project.loader.find_object_containing(address)

    def constrain_registers(self, state):
        # type: (State) -> None
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
