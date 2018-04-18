from IPython.core.magic import (magics_class, line_magic, Magics)

from hase.annotate import Addr2line
from shlex import split as shsplit
from hase.replay import replay


@magics_class
class HaseMagics(Magics):
    def __init__(self, shell, app, window):
        super(HaseMagics, self).__init__(shell)
        self.app = app
        self.window = window

    @line_magic("load")
    def load(self, query):
        args = shsplit(query)
        if len(args) < 3:
            print("USAGE: load <executable> <coredump> <trace>")
            return
        executable, coredump, trace = args
        states = replay(executable, coredump, trace)

        user_ns = self.shell.user_ns
        addr2line = Addr2line()
        for s in states:
            addr2line.add_addr(s.object(), s.address())

        addr_map = addr2line.compute()
        self.active_state = states[-1]
        user_ns["addr_map"] = addr_map
        user_ns["states"] = states
        user_ns["active_state"] = self.active_state

        self.window.set_location(*addr_map[self.active_state.address()])

    @line_magic("p")
    def print_value(self, query):
        """
        open current breakpoint in editor.
        """
        return 10

    @line_magic("backtrace")
    def backtrace(self, query):
        """
        open current breakpoint in editor.
        """
        print(self.active_state.simstate.callstack)
