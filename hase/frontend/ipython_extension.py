from __future__ import absolute_import, division, print_function

from IPython.core.magic import (magics_class, line_magic, Magics)
from IPython import get_ipython
from PyQt5 import QtWidgets
from . import MainWindow, EXIT_REBOOT, EXIT_NORMAL
import sys
import os
import os.path
import imp
import json
import subprocess
from types import ModuleType
from shlex import split as shsplit

from .. import annotate
from .. import gdb
from ..replay import replay_trace
from ..record import DEFAULT_LOG_DIR
from ..path import Tempdir, Path


class HaseFrontEndException(Exception):
    pass


def op_restrict(low=0, high=65536):
    def comp(actual, given):
        return low <= actual <= high

    return comp


def op_eq(actual, given):
    return actual == given


# only for function in Magics class
# FIXME: inherit documentation (maybe by functools.wraps)
# TODO: is there same way to get line_magic name instead of manually setting?
def args(*param_names, **kwargs):
    def func_wrapper(func):
        name = kwargs.pop('name', func.__name__)
        comp = kwargs.pop('comp', op_eq)
        info = kwargs.pop('usage', None)

        def recv_args(inst, query):
            param = shsplit(query)
            if not comp(len(param), len(param_names)):
                if not info:
                    print("USAGE: {} {}".format(name, ''.join(param_names)))
                else:
                    print("USAGE: {}".format(info))
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
    @line_magic("refresh")
    def refresh(self, query):
        self.window.clear_viewer()
        self.window.append_archive()

    @args()
    @line_magic("reload_hase")
    def reload_hase(self, query):
        module_path = os.path.dirname(os.path.dirname(__file__))
        for name, m in sys.modules.items():
            if isinstance(m, ModuleType) and hasattr(
                    m, "__file__") and m.__file__.startswith(module_path):
                print("reload %s" % name)
                try:
                    imp.reload(m)
                except Exception as e:
                    print("error while loading %s" % e)
        self.shell.extension_manager.reload_extension(__name__)

    @args("<report_archive>")
    @line_magic("load")
    def load(self, query):
        user_ns = self.shell.user_ns
        if not Path(query).exists():
            query = str(DEFAULT_LOG_DIR.join(query))
        if not Path(query).exists():
            raise HaseFrontEndException("Report archive not exist")
        with replay_trace(query) as rep:
            user_ns["coredump"] = rep.tracer.coredump
            user_ns["elf"] = rep.tracer.elf
            user_ns["cda"] = rep.tracer.cdanalyzer
            executable = rep.executable
            states = rep.run()
            addr2line = annotate.Addr2line()
            for s in states:
                # XXX: ExternSegment has offset as str (even its repr is broken)
                if s.object() in rep.tracer.project.loader.all_elf_objects:
                    addr2line.add_addr(s.object(), s.address())
            addr_map = addr2line.compute()

        self.active_state = states[-1]
        user_ns["addr_map"] = addr_map
        user_ns["states"] = states
        user_ns['executable'] = executable
        user_ns['active_state'] = self.active_state

        for k, v in addr_map.items():
            if not Path(v[0]).exists():
                origin_f = v[0]
                print("\nCannot resolve filename: {} at {}".format(origin_f, hex(k)))
                d = raw_input("Try to manually set file path for {}: ".format(
                    os.path.basename(origin_f)))
                if d == 'pass-all':
                    break
                new_f = Path.find_in_path(origin_f, [d])

                for i, p in addr_map.items():
                    if not Path(p[0]).exists():
                        if p[0] == origin_f and i != k:
                            addr_map[i][0] = new_f
                addr_map[k][0] = new_f

        user_ns["gdbs"] = gdb.GdbServer(self.active_state, executable)
        user_ns["gdbs"].write_request("dir {}".format(
            ':'.join([os.path.dirname(str(p)) for p, _ in addr_map.values()])
        ))
        user_ns["gdbs"].write_request("info sharedlibrary")
        user_ns["gdbs"].write_request("info sharedlibrary")
        for lib in user_ns["gdbs"].libs.libs:
            libname = os.path.basename(lib.binary)
            print("Loading: {}".format(libname))
            user_ns["gdbs"].write_request("sharedlibrary {}".format(libname))

        self.window.set_slider(user_ns["addr_map"], user_ns["states"])
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

    @args(comp=op_restrict(1), info="USAGE: gdb ...")
    @line_magic("gdb")
    def gdb(self, query):
        try:
            resp = self.shell.user_ns['gdbs'].write_request(query)
            for r in resp:
                if r['payload']:
                    print(r['payload'].replace('\\n', '\n').replace(
                        '\\t', '\t'))
        except Exception:
            pass


# get_ipython will be magically set by ipython
ip = get_ipython()
hase_magics = HaseMagics(ip)
ip.register_magics(hase_magics)
