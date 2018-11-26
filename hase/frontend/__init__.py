import logging
import os
import sys
from typing import Any, Dict, List, Tuple

import pygments
import pygments.formatters
import pygments.lexers
from PyQt5 import QtWidgets
from PyQt5.QtCore import QSize
from PyQt5.QtGui import QIcon, QTextCursor
from PyQt5.uic import loadUiType
from qtconsole.inprocess import QtInProcessKernelManager

from ..path import APP_ROOT
from ..record import DEFAULT_LOG_DIR
from ..symbex.state import State, StateManager
from ..symbex.tracer import Tracer

# from .callgraph import CallGraphManager, CallGraphView

EXIT_NORMAL = 0
EXIT_REBOOT = 1
l = logging.getLogger(__name__)


ui_types: Tuple[Any, Any] = loadUiType(
    str(APP_ROOT.joinpath("frontend", "mainwindow.ui"))
)
form_class: Any = ui_types[0]

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
        self.reg_view.setHorizontalHeaderLabels(["Name", "Value"])

        self.var_view.setColumnCount(4)
        self.var_view.setHorizontalHeaderLabels(["Name", "Type", "Address", "Value"])

        # NOTE: icons are from Google Material Design
        self.up_button.setIcon(QIcon(str(APP_ROOT.joinpath("frontend/icon/up.png"))))
        self.up_button.setIconSize(QSize(15, 15))
        self.up_button.clicked.connect(self.push_up)
        self.up_button.setEnabled(False)

        self.upto_button.setIcon(
            QIcon(str(APP_ROOT.joinpath("frontend/icon/upto.png")))
        )
        self.upto_button.setIconSize(QSize(15, 15))
        self.upto_button.clicked.connect(self.push_upto)
        self.upto_button.setEnabled(False)

        self.down_button.setIcon(
            QIcon(str(APP_ROOT.joinpath("frontend/icon/down.png")))
        )
        self.down_button.setIconSize(QSize(15, 15))
        self.down_button.clicked.connect(self.push_down)
        self.down_button.setEnabled(False)

        self.downto_button.setIcon(
            QIcon(str(APP_ROOT.joinpath("frontend/icon/downto.png")))
        )
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
        self.file_read_cache = {}
        # self.callgraph = CallGraphManager()

        self.coredump_constraints = []

    def cache_coredump_constraints(self) -> None:
        user_ns = self.kernel_client.kernel.shell.user_ns
        tracer = user_ns["tracer"]
        start_state = tracer.start_state
        active_state = self.states.major_states[-1]
        coredump = user_ns["coredump"]
        low = active_state.simstate.regs.rsp
        MAX_FUNC_FRAME = 0x200
        high = start_state.regs.rsp + MAX_FUNC_FRAME

        try:
            low_v = active_state.simstate.solver.eval(low)
        except Exception:
            # very large range
            low_v = coredump.stack.start
        try:
            high_v = start_state.solver.eval(high)
        except Exception:
            high_v = coredump.stack.stop

        for addr in range(low_v, high_v):
            value = active_state.simstate.memory.load(addr, 1, endness="Iend_LE")
            if value.variables == frozenset():
                continue
            cmem = coredump.stack[addr]
            self.coredump_constraints.append(value == cmem)

    def eval_variable(
        self, active_state: State, loc: int, addr: Any, size: int
    ) -> Tuple[str, str]:
        # NOTE: * -> uninitialized / 'E' -> symbolic
        if not active_state.had_coredump_constraints:
            for c in self.coredump_constraints:
                old_solver = active_state.simstate.solver._solver.branch()
                active_state.simstate.solver.add(c)
                if not active_state.simstate.solver.satisfiable():
                    print(f"Unsatisfiable coredump constraints: {c}")
                    active_state.simstate.solver._stored_solver = old_solver
            active_state.had_coredump_constraints = True

        if loc == 1:
            mem = active_state.simstate.memory.load(addr, size, endness="Iend_LE")
        elif loc == 2:
            mem = getattr(active_state.simstate.regs, addr)
        elif loc == -1:
            return "optimized", "unknown"
        else:
            return "gdb error", "unknown"
        if mem.uninitialized and mem.variables != frozenset() and loc == 1:
            result = ""
            for i in range(size):
                value = active_state.simstate.memory.load(
                    addr + i, 1, endness="Iend_LE"
                )
                if value.uninitialized:
                    result += "** "
                    continue
                try:
                    v = hex(active_state.simstate.solver.eval(value))[2:]
                    if len(v) == 1:
                        v = "0" + v
                except Exception:
                    v = "Er"
                result += v + " "
            result = result[:-1]
            return result, "array"
        else:
            v = self.eval_value(active_state, mem)
            if v == "uninitialized" or v == "symbolic":
                return v, "unknown"
            return v, "hex"

    def eval_value(self, active_state: State, value: Any) -> str:
        if value.uninitialized:
            return "uninitialized"
        try:
            v = hex(active_state.simstate.solver.eval(value))
        except Exception:
            v = "symbolic"
        return v

    def update_active(self, new_active: State) -> None:
        user_ns = self.kernel_client.kernel.shell.user_ns
        user_ns["active_state"] = new_active
        user_ns["gdbs"].active_state = new_active
        # NOTE: gdb c for every operation is slow
        # user_ns['gdbs'].update_active()
        addr = new_active.address()
        source_file, line = self.addr_map[addr]
        self.set_location(source_file, line)

    def update_active_index(self, active_index: int) -> None:
        new_state, is_new = self.states[active_index]
        # user_ns = self.kernel_client.kernel.shell.user_ns
        if is_new:
            # self.callgraph.add_node(new_state, user_ns['tracer'])
            pass
        major_index = self.states.major_index
        if active_index in major_index:
            slider_index = len(major_index) - major_index.index(active_index) - 1
            self.time_slider.setValue(slider_index)
        self.update_active(new_state)

    def push_upto(self) -> None:
        v = self.time_slider.value()
        self.time_slider.setValue(min(self.time_slider.maximum(), v + 1))
        self.slider_change()

    def push_downto(self) -> None:
        v = self.time_slider.value()
        self.time_slider.setValue(max(self.time_slider.minimum(), v - 1))
        self.slider_change()

    def push_up(self) -> None:
        user_ns = self.kernel_client.kernel.shell.user_ns
        active_state = user_ns["active_state"]
        state_index = max(0, active_state.index - 1)
        self.update_active_index(state_index)

    def push_down(self) -> None:
        user_ns = self.kernel_client.kernel.shell.user_ns
        active_state = user_ns["active_state"]
        tracer = user_ns["tracer"]
        state_index = min(len(tracer.trace) - 1, active_state.index + 1)
        self.update_active_index(state_index)

    def push_callgraph(self) -> None:
        pass
        # self.view = CallGraphView(self.callgraph, self)

    def push_info(self) -> None:
        user_ns = self.kernel_client.kernel.shell.user_ns
        active_state = user_ns["active_state"]
        self.set_regs()
        user_ns["gdbs"].update_active()
        if self.addr_map[active_state.address()][0] != "??":
            user_ns["gdbs"].write_request("bt")
            self.set_variable()
        else:
            print("Cannot retrieve variables on unresolvable source code")

    def push_switch(self) -> None:
        user_ns = self.kernel_client.kernel.shell.user_ns
        active_state = user_ns["active_state"]
        active_state.is_to_simstate = not active_state.is_to_simstate
        self.update_active(active_state)

    def slider_change(self) -> None:
        v = self.time_slider.value()
        new_active = self.states.get_major(-(v + 1))
        self.update_active(new_active)

    def set_slider(self, addr_map: List[Tuple[str, int]], states: StateManager) -> None:
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

    def set_location(self, source_file: str, line: int) -> None:
        shell = self.kernel_client.kernel.shell
        user_ns = shell.user_ns
        active_state = user_ns["active_state"]
        insns = active_state.simstate.block().capstone.insns
        # fmt = QTextCharFormat()
        # fmt.setUnderlineStyle(QTextCharFormat.SingleUnderline)
        if source_file != "??":
            css, source = self.file_cache[source_file][line]
            if css:
                self.code_view.setHtml(
                    code_template.format(css, source.encode("utf-8"))
                )
                cursor = self.code_view.textCursor()
                cursor.movePosition(QTextCursor.Start)
                minl = max(0, line - 30)
                if self.file_read_cache[source_file][2]:
                    cursor.movePosition(QTextCursor.Down, n=line - minl - 1)
                else:
                    cursor.movePosition(QTextCursor.Down, n=line - 1)
                cursor.movePosition(QTextCursor.EndOfLine)
                cursor.insertText("\t" + str(insns[0]))
                if not self.file_read_cache[source_file][2]:
                    self.code_view.scrollToAnchor("line-%d" % max(0, line - 10))
                else:
                    self.code_view.scrollToAnchor("line-%d" % max(0, line - minl - 10))
            else:
                self.code_view.clear()
                self.code_view.append("{}:{}".format(source_file, line))
        else:
            self.code_view.clear()
            self.code_view.append("Unresolved source code")
            for insn in insns:
                self.code_view.append("\t" + str(insn))

    def set_variable(self) -> None:
        shell = self.kernel_client.kernel.shell
        user_ns = shell.user_ns
        var = user_ns["gdbs"].read_variables()
        self.var_view.setRowCount(0)
        i = 0
        for v in var:
            if v["loc"] != -2:
                self.var_view.insertRow(i)
                value, value_type = self.eval_variable(
                    user_ns["active_state"], v["loc"], v["addr"], v["size"]
                )
                self.var_view.set_var(i, v, value, value_type)
                i += 1
        self.var_view.resizeColumnsToContents()

    def set_regs(self) -> None:
        def fix_new_regname(rname: str):
            # HACK: angr has no access to register like r9w, r8d, r15b
            for i in range(8, 16):
                if "r" + str(i) in rname:
                    return "r" + str(i)
            return rname

        shell = self.kernel_client.kernel.shell
        user_ns = shell.user_ns
        active_state = user_ns["active_state"]
        insns = active_state.simstate.block().capstone.insns
        insn = insns[0].insn
        self.reg_view.setRowCount(0)
        for op in insn.operands:
            # OP_REG
            if op.type == 1:
                rname = insn.reg_name(op.value.reg)
                rname = fix_new_regname(rname)
                value = self.eval_value(
                    active_state, getattr(active_state.simstate.regs, rname)
                )
                self.reg_view.append_reg(rname, value)
            # OP_MEM
            elif op.type == 3:
                if op.value.mem.base:
                    rname = insn.reg_name(op.value.mem.base)
                    rname = fix_new_regname(rname)
                    value = self.eval_value(
                        active_state, getattr(active_state.simstate.regs, rname)
                    )
                    self.reg_view.append_reg(rname, value)
                if op.value.mem.index:
                    rname = insn.reg_name(op.value.mem.index)
                    rname = fix_new_regname(rname)
                    value = self.eval_value(
                        active_state, getattr(active_state.simstate.regs, rname)
                    )
                    self.reg_view.append_reg(rname, value)
        self.reg_view.resizeColumnsToContents()

    def setup_ipython(self, app: QtWidgets.QApplication, window: "MainWindow") -> None:
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

    def cache_tokens(self, addr_map: Dict[int, Tuple[str, int]]):
        for filename, line in addr_map.values():
            l.info("caching file: " + str(filename) + " at line: " + str(line))
            if filename != "??":
                if filename not in self.file_read_cache.keys():
                    self.file_cache[filename] = {}
                    self.file_read_cache[filename] = {}
                    try:
                        lexer = pygments.lexers.get_lexer_for_filename(str(filename))
                        formatter_opts = dict(
                            linenos="inline", linespans="line", hl_lines=[line]
                        )
                        html_formatter = pygments.formatters.get_formatter_by_name(
                            "html", **formatter_opts
                        )
                        css = html_formatter.get_style_defs(".highlight")
                        with open(str(filename)) as f:
                            lines = f.readlines()
                        if len(lines) < 1000:
                            content = "".join(lines)
                            tokens = lexer.get_tokens(content)
                            source = pygments.format(tokens, html_formatter)
                            self.file_cache[filename][line] = (css, source)
                            self.file_read_cache[filename] = (lexer, content, False)
                        else:
                            minl = max(0, line - 30)
                            maxl = min(len(lines), line + 30)
                            formatter_opts = dict(
                                linenos="inline", linespans="line", hl_lines=[line]
                            )
                            html_formatter = pygments.formatters.get_formatter_by_name(
                                "html", **formatter_opts
                            )
                            css = html_formatter.get_style_defs(".highlight")
                            source = pygments.format(
                                lexer.get_tokens("".join(lines[minl:maxl])),
                                html_formatter,
                            )
                            self.file_cache[filename][line] = (css, source)
                            self.file_read_cache[filename] = (lexer, lines, True)
                    except Exception as e:
                        print(e)
                        self.file_cache[filename][line] = (None, None)
                        self.file_read_cache[filename] = (None, None, False)
                else:
                    lexer, content, is_largefile = self.file_read_cache[filename]
                    if content:
                        try:
                            if not is_largefile:
                                formatter_opts = dict(
                                    linenos="inline", linespans="line", hl_lines=[line]
                                )
                                html_formatter = pygments.formatters.get_formatter_by_name(
                                    "html", **formatter_opts
                                )
                                css = html_formatter.get_style_defs(".highlight")
                                source = pygments.format(
                                    lexer.get_tokens(content), html_formatter
                                )
                                self.file_cache[filename][line] = (css, source)
                            else:
                                minl = max(0, line - 30)
                                maxl = min(len(content), line + 30)
                                formatter_opts = dict(
                                    linenos="inline",
                                    linespans="line",
                                    hl_lines=[line - minl],
                                )
                                html_formatter = pygments.formatters.get_formatter_by_name(
                                    "html", **formatter_opts
                                )
                                css = html_formatter.get_style_defs(".highlight")
                                source = pygments.format(
                                    lexer.get_tokens("".join(content[minl:maxl])),
                                    html_formatter,
                                )
                                self.file_cache[filename][line] = (css, source)
                        except Exception as e:
                            print(e)
                            self.file_cache[filename][line] = (None, None)
                    else:
                        self.file_cache[filename][line] = (None, None)

    def add_states(self, states: StateManager, tracer: Tracer) -> None:
        for s in states.major_states[1:]:
            pass
            # self.callgraph.add_node(s, tracer)

    def clear_viewer(self) -> None:
        self.code_view.clear()

    def append_archive(self) -> None:
        files = list(DEFAULT_LOG_DIR.glob("*.tar.gz"))
        files.sort()
        self.code_view.append("\nAvailable files:")
        for f in files:
            self.code_view.append(os.path.basename(f))

    def enable_buttons(self) -> None:
        # TODO: maintain a button list
        self.up_button.setEnabled(True)
        self.upto_button.setEnabled(True)
        self.down_button.setEnabled(True)
        self.downto_button.setEnabled(True)
        # self.cg_button.setEnabled(True)
        self.info_button.setEnabled(True)
        self.switch_button.setEnabled(True)

    def clear_cache(self) -> None:
        self.file_cache = {}
        self.coredump_constraints = []
        # self.callgraph.clear_cache()

    def shutdown_kernel(self) -> None:
        print("Shutting down kernel...")
        self.kernel_client.stop_channels()
        self.kernel_manager.shutdown_kernel()


def start_window() -> int:
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    app.aboutToQuit.connect(window.shutdown_kernel)
    window.show()
    window.setup_ipython(app, window)
    window.append_archive()
    return app.exec_()


def main() -> None:
    while start_window() == EXIT_REBOOT:
        pass
