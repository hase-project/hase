from IPython.core.magic import (magics_class, line_magic, Magics)
import sys
import os
import imp
from types import ModuleType
from shlex import split as shsplit

import hase


@magics_class
class HaseMagics(Magics):
    def __init__(self, shell):
        if shell is not None:
            self.user_ns = shell.user_ns
        else:
            # happens during initialisation of ipython
            self.user_ns = None
        self.shell = shell
        super(HaseMagics, self).__init__(shell)

    @property
    def app(self):
        return self.user_ns["app"]

    @property
    def window(self):
        return self.user_ns["window"]

    @line_magic("reload_hase")
    def reload_hase(self, query):
        module_path = os.path.dirname(__file__)
        for name, m in sys.modules.items():
            if isinstance(m, ModuleType) and hasattr(m, "__file__") and m.__file__.startswith(module_path):
                #if m.__file__ == __file__:
                #    continue
                print("reload %s" % name)
                try:
                    imp.reload(m)
                except Exception:
                    pass
            else:
                pass
                #print("skip %s" % name)
        self.shell.extension_manager.reload_extension("hase.ipython_extension")

    @line_magic("load")
    def load(self, query):
        args = shsplit(query)
        if len(args) < 3:
            print("USAGE: load <executable> <coredump> <trace>")
            return
        executable, coredump, trace = args
        states = hase.replay_trace(executable, coredump, trace)

        user_ns = self.shell.user_ns
        addr2line = hase.annotate.Addr2line()
        for s in states:
            addr2line.add_addr(s.object(), s.address())

        addr_map = addr2line.compute()
        self.active_state = states[-1]
        user_ns["addr_map"] = addr_map
        user_ns["states"] = states
        user_ns["gdb"] = hase.gdb.GdbServer(self.active_state, executable)

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


# get_ipython will be magically set by ipython
ip = get_ipython() # NOQA
hase_magics = HaseMagics(ip)
ip.register_magics(hase_magics)
