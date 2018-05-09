from __future__ import absolute_import, division, print_function

from IPython.core.magic import (magics_class, line_magic, Magics)
from IPython import get_ipython
from PyQt5 import QtWidgets
from . import MainWindow, EXIT_REBOOT, EXIT_NORMAL
import sys
import os
import imp
from types import ModuleType
from shlex import split as shsplit

from .. import gdb, annotate
from ..replay import replay_trace

# only for function in Magics class
# FIXME: inherit documentation (maybe by functools.wraps)
# TODO: is there same way to get line_magic name instead of manually setting?
def args(*param_names, **kwargs):
    def func_wrapper(func):
        name = kwargs.pop('name', func.__name__)
        def recv_args(inst, query):
            param = shsplit(query)
            if len(param) != len(param_names):
                print("USAGE: {} {}".format(name, ''.join(param_names)))
                return
            func(inst, query)
        recv_args.__name__ = func.__wrapped__.__name__
        recv_args.__doc__ = func.__wrapped__.__doc__
        return recv_args
    return func_wrapper


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
        # type: () -> QtWidgets.QApplication
        return self.user_ns["app"]

    @property
    def window(self):
        # type: () -> MainWindow
        return self.user_ns["window"]

    @args("<source_code>", name="show")
    @line_magic("show")
    def show_source(self, query):
        self.window.set_location(query, 0)

    @args()
    @line_magic("reload_hase")
    def reload_hase(self, query):
        module_path = os.path.dirname(os.path.dirname(__file__))
        for name, m in sys.modules.items():
            if isinstance(m, ModuleType) and hasattr(m, "__file__") and m.__file__.startswith(module_path):
                print("reload %s" % name)
                try:
                    imp.reload(m)
                except Exception as e:
                    print("error while loading %s" % e)
        self.shell.extension_manager.reload_extension(__name__)

    @args("<report_archive>")
    @line_magic("load")
    def load(self, query):
        states = replay_trace(query)
        user_ns = self.shell.user_ns
        addr2line = annotate.Addr2line()
        for s in states:
            addr2line.add_addr(s.object(), s.address())

        addr_map = addr2line.compute()
        self.active_state = states[-1]
        user_ns["addr_map"] = addr_map
        user_ns["states"] = states
        # FIXME later
        #user_ns["gdb"] = gdb.GdbServer(self.active_state, executable)

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
ip = get_ipython()
hase_magics = HaseMagics(ip)
ip.register_magics(hase_magics)
