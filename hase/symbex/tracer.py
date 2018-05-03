from __future__ import absolute_import, division, print_function

import angr
import logging
from angr import sim_options as so
from angr.state_plugins.sim_action import SimActionExit
from angr import SimState
from typing import List, Any, Dict, Tuple

from ..perf import TRACE_END, read_trace
from ..pwn_wrapper import ELF
from ..mapping import Mapping

from .state import State

try:
    import r2pipe
except ImportError:
    r2pipe = None


l = logging.getLogger(__name__)


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
        lib_opts[m.path] = dict(custom_base_addr=m.start)
        force_load_libs.append(m.path)

    # TODO: extract libraries from core dump instead ?
    return dict(
        main_opts={"custom_base_addr": main.start},
        force_load_libs=force_load_libs,
        lib_opts=lib_opts,
        load_options={"except_missing_libs": True})


class Tracer():
    def __init__(self, executable, trace_path, mappings):
        # type: (str, str, List[Mapping]) -> None
        self.executable = executable
        self.mappings = mappings
        options = build_load_options(mappings)
        self.project = angr.Project(executable, **options)
        trace = read_trace(trace_path, self.project.loader)
        self.trace = trace

        assert self.project.loader.main_object.os.startswith('UNIX')

        self.elf = ELF(executable)

        start = self.elf.symbols.get('_start')
        main = self.elf.symbols.get('main')

        for (idx, event) in enumerate(self.trace):
            if event[1] == start or event[1] == main:
                self.trace = trace[idx:]

        remove_simplications = {
            so.LAZY_SOLVES, so.EFFICIENT_STATE_MERGING,
            so.TRACK_CONSTRAINT_ACTIONS
        } | so.simplification
        self.start_state = self.project.factory.blank_state(
            addr=self.trace[0][1],
            add_options=set([so.TRACK_JMP_ACTIONS]),
            remove_options=remove_simplications)

        self.simgr = self.project.factory.simgr(
            self.start_state,
            save_unsat=True,
            hierarchy=False,
            save_unconstrained=True)
     
        # only for interactive debugging
        if r2pipe is not None:
            self.r2 = r2pipe.open(executable)
        # For debugging
        #self.project.pt = self

    def print_addr(self, addr):
        print(self.r2.cmd("pd -2 @ %s; pd 2 @ %s" % (addr, addr)))

    def jump_was_not_taken(self, old_state, new_state):
        # was the last control flow change an exit vs call/jump?
        ev = new_state.events[-1]
        instructions = old_state.block().capstone.insns
        assert isinstance(ev, SimActionExit) and len(instructions) == 1
        size = instructions[0].insn.size
        return (new_state.addr - size) == old_state.addr

    def find_next_branch(self, state, branch):
        # type: (SimState, Tuple[int,int]) -> SimState
        while True:
            l.debug("0x%x", state.addr)
            choices = self.project.factory.successors(
                state, num_inst=1).successors
            old_state = state

            if branch[1] == TRACE_END:
                for choice in choices:
                    if choice.addr == branch[0]:
                        return choice

            if len(choices) <= 2:
                for choice in choices:
                    if old_state.addr == branch[0] and choice.addr == branch[1]:
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
        return address == TRACE_END or self.project.loader.find_object_containing(
            address)

    def run(self):
        # type: () -> List[State]
        state = self.simgr.active[0]
        states = []
        states.append(State(self.trace[0], state))
        for event in self.trace[1:]:
            l.debug("look for jump: 0x%x -> 0x%x" % (event[0], event[1]))
            assert self.valid_address(event[0]) and self.valid_address(
                event[1])
            state = self.find_next_branch(state, event)
            states.append(State(event, state))
        return states
