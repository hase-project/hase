from __future__ import absolute_import, division, print_function

import sys
import logging
from PyQt5 import QtWidgets
from PyQt5.uic import loadUiType
from PyQt5.QtCore import QSize
from PyQt5.QtGui import QTextCursor, QIcon, QPixmap, QPainter
import pygments
import pygments.lexers
import pygments.formatters
from qtconsole.inprocess import QtInProcessKernelManager
from typing import Tuple, Any, List, Union

from .callgraph import CallGraphManager, CallGraphView
from ..path import APP_ROOT
from ..record import DEFAULT_LOG_DIR

EXIT_NORMAL = 0
EXIT_REBOOT = 1
l = logging.getLogger("hase")


form_class, base_class = loadUiType(
    str(APP_ROOT.join('frontend', 'mainwindow.ui')))  # type: Tuple[Any, Any]

code_template = """
<html>
<head>
<style>
{}
</style>
</head>
<body>
{}
</body>
</html>
"""


class MainWindow(form_class, QtWidgets.QMainWindow):
    def __init__(self, *args):
        super(MainWindow, self).__init__(*args)
        self.setupUi(self)
        self.kernel_manager = QtInProcessKernelManager()
        self.kernel_manager.start_kernel()

        self.kernel_client = self.kernel_manager.client()
        self.kernel_client.start_channels()
        self.jupiter_widget.kernel_manager = self.kernel_manager
        self.jupiter_widget.kernel_client = self.kernel_client
        self.jupiter_widget.reset()


        self.reg_view.setColumnCount(2)
        self.reg_view.setHorizontalHeaderLabels(['Name', 'Value'])

        self.var_view.setColumnCount(4)
        self.var_view.setHorizontalHeaderLabels(['Name', 'Type', 'Address', 'Value'])

        # NOTE: icons are from Google Material Design
        self.up_button.setIcon(QIcon(str(APP_ROOT.join('frontend/icon/up.png'))))
        self.up_button.setIconSize(QSize(15, 15))
        self.up_button.clicked.connect(self.push_up)
        self.up_button.setEnabled(False)
        
        self.upto_button.setIcon(QIcon(str(APP_ROOT.join('frontend/icon/upto.png'))))
        self.upto_button.setIconSize(QSize(15, 15))
        self.upto_button.clicked.connect(self.push_upto)
        self.upto_button.setEnabled(False)
        
        self.down_button.setIcon(QIcon(str(APP_ROOT.join('frontend/icon/down.png'))))
        self.down_button.setIconSize(QSize(15, 15))
        self.down_button.clicked.connect(self.push_down)
        self.down_button.setEnabled(False)
        
        self.downto_button.setIcon(QIcon(str(APP_ROOT.join('frontend/icon/downto.png'))))
        self.downto_button.setIconSize(QSize(15, 15))
        self.downto_button.clicked.connect(self.push_downto)
        self.downto_button.setEnabled(False)

        self.cg_button.clicked.connect(self.push_callgraph)
        self.cg_button.setEnabled(False)

        self.info_button.clicked.connect(self.push_info)
        self.info_button.setEnabled(False)

        self.switch_button.clicked.connect(self.push_switch)
        self.switch_button.setEnabled(False)

        self.time_slider.setEnabled(False)

        self.file_cache = {}
        self.callgraph = CallGraphManager()

        self.coredump_constraints = []

    def cache_coredump_constraints(self):
        user_ns = self.kernel_client.kernel.shell.user_ns
        tracer = user_ns['tracer']
        start_state = tracer.start_state
        active_state = self.states.major_states[-1]
        coredump = user_ns['coredump']
        low = active_state.simstate.regs.rsp
        
        if start_state.regs.rbp.uninitialized:
            high = start_state.regs.rsp
        else:
            high = start_state.regs.rbp + 1
        
        try:
            low_v = active_state.simstate.se.eval(low)
        except:
            # very large range
            low_v = coredump.stack.start
        try:
            high_v = start_state.se.eval(high)
        except:
            high_v = coredump.stack.stop
        
        for addr in range(low_v, high_v):
            value = active_state.simstate.memory.load(addr, 1, endness='Iend_LE')
            if value.uninitialized or value.variables == frozenset():
                continue
            cmem = coredump.stack[addr]
            self.coredump_constraints.append(
                value == cmem
            )

    def eval_variable(self, active_state, addr, size):
        # type: (Any, int, int) -> Tuple[str, str]
        # NOTE: * -> uninitialized / 'E' -> symbolic
        if not getattr(active_state, 'had_coredump_constraints', False):
            for c in self.coredump_constraints:
                old_con = active_state.simstate.se.constraints
                active_state.simstate.se.add(c)
                if not active_state.simstate.se.satisfiable():
                    print('Unsatisfiable coredump constraints: ' + str(c))
                    active_state.simstate.solver._solver._cached_satness = True
                    active_state.simstate.solver._solver.constraints = old_con
            active_state.had_coredump_constraints = True
        mem = active_state.simstate.memory.load(addr, size, endness='Iend_LE')
        if mem.uninitialized and mem.variables != frozenset():
            result = ''
            for i in range(size):
                value = active_state.simstate.memory.load(addr + i, 1, endness='Iend_LE')
                if value.uninitialized:
                    result += '** '
                    continue
                try:
                    v = hex(active_state.simstate.se.eval(value))[2:]
                    if len(v) == 1:
                        v = '0' + v
                except:
                    v = 'Er'
                result += v + ' '
            result = result[:-1]
            return result, 'array'
        else:
            v = self.eval_value(active_state, mem)
            if v == 'uninitialized' or v == 'symbolic':
                return v, 'unknown'
            return v, 'hex'

    def eval_value(self, active_state, value):
        # type: (Any, Any) -> str
        if value.uninitialized:
            return 'uninitialized'
        try:
            v = hex(active_state.simstate.se.eval(value))
        except:
            v = 'symbolic'
        return v

    def update_active(self, new_active):
        # type: (Any) -> None
        user_ns = self.kernel_client.kernel.shell.user_ns
        user_ns['active_state'] = new_active
        user_ns['gdbs'].active_state = new_active
        # NOTE: gdb c for every operation is slow
        # user_ns['gdbs'].update_active()
        addr = new_active.address()
        self.set_location(*self.addr_map[addr])

    def update_active_index(self, active_index):
        # type: (int) -> None
        new_state, is_new = self.states[active_index]
        user_ns = self.kernel_client.kernel.shell.user_ns
        if is_new:
            self.callgraph.add_node(new_state, user_ns['tracer'])
        major_index = self.states.major_index
        if active_index in major_index:
            slider_index = len(major_index) - major_index.index(active_index) - 1
            self.time_slider.setValue(slider_index)
        self.update_active(new_state)

    def push_upto(self):
        # type: () -> None
        v = self.time_slider.value()
        self.time_slider.setValue(min(self.time_slider.maximum(), v + 1))
        self.slider_change()

    def push_downto(self):
        # type: () -> None
        v = self.time_slider.value()
        self.time_slider.setValue(max(self.time_slider.minimum(), v - 1))
        self.slider_change()

    def push_up(self):
        # type: () -> None
        user_ns = self.kernel_client.kernel.shell.user_ns
        active_state = user_ns['active_state']
        state_index = max(0, active_state.index - 1)
        self.update_active_index(state_index)
        
    def push_down(self):
        # type: () -> None
        user_ns = self.kernel_client.kernel.shell.user_ns
        active_state = user_ns['active_state']
        tracer = user_ns['tracer']
        state_index = min(len(tracer.trace) - 1, active_state.index + 1)
        self.update_active_index(state_index)

    def push_callgraph(self):
        # type: () -> None
        self.view = CallGraphView(self.callgraph, self)

    def push_info(self):
        # type: () -> None
        user_ns = self.kernel_client.kernel.shell.user_ns
        active_state = user_ns['active_state']
        self.set_regs()
        user_ns['gdbs'].update_active()
        if self.addr_map[active_state.address()][0] != '??':
            user_ns['gdbs'].write_request('bt')
            self.set_variable()
        else:
            print("Cannot retrieve variables on unresolvable source code")        

    def push_switch(self):
        # type: () -> None
        user_ns = self.kernel_client.kernel.shell.user_ns
        active_state = user_ns['active_state']
        active_state.is_to_simstate = not active_state.is_to_simstate
        self.update_active(active_state)

    def slider_change(self):
        # type: () -> None
        v = self.time_slider.value()
        new_active = self.states.get_major(-(v+1))
        self.update_active(new_active)

    def set_slider(self, addr_map, states):
        # type: (List[Union[str, int]], Any) -> None
        # NOTE: slider is for major states
        self.addr_map = addr_map
        self.states = states
        self.time_slider.setEnabled(True)
        self.time_slider.setMinimum(0)
        self.time_slider.setMaximum(states.len_major - 1)
        self.time_slider.setTickPosition(QtWidgets.QSlider.TicksLeft)
        self.time_slider.setTickInterval(states.len_major - 1)
        self.time_slider.setValue(0)
        self.time_slider.valueChanged.connect(self.slider_change)

    def set_location(self, source_file, line):
        # type: (str, int) -> None
        shell = self.kernel_client.kernel.shell
        user_ns = shell.user_ns
        active_state = user_ns['active_state']
        insns = active_state.simstate.block().capstone.insns
        if source_file != '??':
            css, source = self.file_cache[source_file][line]
            if css:
                self.code_view.setHtml(code_template.format(css, source.encode('utf-8')))
                cursor = self.code_view.textCursor()
                cursor.movePosition(QTextCursor.Start)
                cursor.movePosition(QTextCursor.Down, n=line - 1)
                cursor.movePosition(QTextCursor.EndOfLine)
                cursor.insertText('\t' + str(insns[0]))
                self.code_view.scrollToAnchor("line-%d" % max(0, line - 10))
            else:
                self.code_view.clear()
                self.code_view.append("{}:{}".format(source_file, line))
        else:
            self.code_view.clear()
            self.code_view.append("Unresolved source code")
            for insn in insns:
                self.code_view.append('\t' + str(insn))

    def set_variable(self):
        # type: () -> None
        shell = self.kernel_client.kernel.shell
        user_ns = shell.user_ns
        var = user_ns['gdbs'].read_variables()
        self.var_view.setRowCount(0)
        self.var_view.setRowCount(len(var))
        for i, v in enumerate(var):
            value, value_type = self.eval_variable(
                user_ns['active_state'],
                v['addr'], v['size'])
            self.var_view.set_var(i, v, value, value_type)
        self.var_view.resizeColumnsToContents()        

    def set_regs(self):
        # type: () -> None
        shell = self.kernel_client.kernel.shell
        user_ns = shell.user_ns
        active_state = user_ns['active_state']
        insns = active_state.simstate.block().capstone.insns
        insn = insns[0].insn
        self.reg_view.setRowCount(0)
        for op in insn.operands:
            # OP_REG
            if op.type == 1:
                rname = insn.reg_name(op.value.reg)
                value = self.eval_value(
                    active_state,
                    getattr(active_state.simstate.regs, rname))
                self.reg_view.append_reg(rname, value)
            # OP_MEM
            elif op.type == 3:
                if op.value.mem.base:
                    rname = insn.reg_name(op.value.mem.base)
                    value = self.eval_value(
                        active_state,
                        getattr(active_state.simstate.regs, rname))
                    self.reg_view.append_reg(rname, value)
                if op.value.mem.index:
                    rname = insn.reg_name(op.value.mem.index)
                    value = self.eval_value(
                        active_state,
                        getattr(active_state.simstate.regs, rname))
                    self.reg_view.append_reg(rname, value)
        self.reg_view.resizeColumnsToContents()

    def setup_ipython(self, app, window):
        # type: (QtWidgets.QApplication, MainWindow) -> None
        """
        Might break with future versions of IPython, but nobody got time for
        this!
        """
        shell = self.kernel_client.kernel.shell
        shell.magic("clear")
        user_ns = shell.user_ns
        user_ns["app"] = app
        user_ns["window"] = self
        config = shell.config
        config.TerminalIPythonApp.display_banner = ""
        from . import ipython_extension
        shell.extension_manager.load_extension(ipython_extension.__name__)

    def cache_tokens(self, addr_map):
        for filename, line in addr_map.values():
            if filename != '??':
                if filename not in self.file_cache.keys():
                    self.file_cache[filename] = {}
                try:
                    lexer = pygments.lexers.get_lexer_for_filename(str(filename))
                    formatter_opts = dict(
                        linenos="inline", linespans="line", hl_lines=[line])
                    html_formatter = pygments.formatters.get_formatter_by_name(
                        "html", **formatter_opts)
                    css = html_formatter.get_style_defs('.highlight')
                    with open(str(filename)) as f:
                        tokens = lexer.get_tokens(f.read())
                    source = pygments.format(tokens, html_formatter)
                    self.file_cache[filename][line] = (css, source)
                except:
                    self.file_cache[filename][line] = (None, None)

    def add_states(self, states, tracer):
        # type: (Any, Any) -> None
        for s in states.major_states[1:]:
            self.callgraph.add_node(s, tracer)

    def clear_viewer(self):
        # type: () -> None
        self.code_view.clear()

    def append_archive(self):
        # type: () -> None
        files = DEFAULT_LOG_DIR.listdir()
        files.sort()
        self.code_view.append("\nAvailable files:")
        for f in files:
            if str(f.basename()).endswith(".tar.gz"):
                self.code_view.append(str(f.basename()))

    def enable_buttons(self):
        # type: () -> None
        # TODO: maintain a button list
        self.up_button.setEnabled(True)
        self.upto_button.setEnabled(True)
        self.down_button.setEnabled(True)
        self.downto_button.setEnabled(True)
        self.cg_button.setEnabled(True)
        self.info_button.setEnabled(True)
        self.switch_button.setEnabled(True)

    def clear_cache(self):
        self.file_cache = {}
        self.coredump_constraints = []
        self.callgraph.clear_cache()

    def shutdown_kernel(self):
        # type: () -> None
        print('Shutting down kernel...')
        self.kernel_client.stop_channels()
        self.kernel_manager.shutdown_kernel()


def start_window():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    app.aboutToQuit.connect(window.shutdown_kernel)
    window.show()
    window.setup_ipython(app, window)
    window.append_archive()
    return app.exec_()


def main():
    while start_window() == EXIT_REBOOT:
        pass
