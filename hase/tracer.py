import r2pipe
import angr
import monkeyhex
import logging
from angr import sim_options as so
from angr.state_plugins.sim_action import SimActionExit

from .perf import TRACE_END, read_trace
from .annotate import Addr2line

from pwn_wrapper import ELF

l = logging.getLogger(__name__)


class Register():
    def __init__(self, name, value, size):
        self.name = name
        self.value = value
        self.size = size


class Registers():
    def __init__(self, state):
        self.state = state

    def __getitem__(self, name):
        reg = getattr(self.state.simstate.regs, name)
        value = self.state.simstate.solver.eval(reg)
        return Register(name, value, reg.size())


class Memory():
    def __init__(self, state):
        self.state = state

    def __getitem__(self, addr):
        # good idea?
        byte = self.state.simstate.mem[addr].byte
        try:
            return self.state.simstate.solver.eval(byte)
        except:
            return None


class State():
    def __init__(self, branch, simstate):
        self.branch = branch
        self.simstate = simstate

    def __repr__(self):
        if self.branch[0] == 0:
            return "State(Start -> 0x%x)" % (self.branch[1])
        elif self.branch[1] == TRACE_END:
            return "State(0x%x -> End)" % (self.branch[0])
        else:
            return "State(0x%x -> 0x%x)" % (self.branch[0], self.branch[1])

    @property
    def registers(self):
        return Registers(self)

    @property
    def memory(self):
        return Memory(self)

    def object(self):
        return self.simstate.project.loader.find_object_containing(self.simstate.addr)

    def address(self):
        return self.simstate.addr

    def location(self):
        """
        Binary of current state
        """
        obj = self.object()
        a = Addr2line()
        a.add_addr(obj, self.simstate.addr)
        return a.compute()[self.simstate.addr]


class Tracer():
    def __init__(self, executable, trace_path, coredump, dso_offsets):
        self.executable = executable
        self.coredump = coredump
        self.dso_offsets = dso_offsets
        self.project = angr.Project(executable, **dso_offsets)
        trace = read_trace(trace_path, self.project.loader)
        self.trace = trace
        self.states = {}

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
        self.r2 = r2pipe.open(executable)
        # For debugging
        self.project.pt = self

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
                import ipdb
                ipdb.set_trace()

    def valid_address(self, address):
        return address == TRACE_END or self.project.loader.find_object_containing(
            address)

    def run(self):
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
