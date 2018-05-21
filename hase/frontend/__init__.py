from __future__ import absolute_import, division, print_function

import sys
from PyQt5 import QtWidgets
from PyQt5.uic import loadUiType
import pygments
import pygments.lexers
import pygments.formatters
from qtconsole.inprocess import QtInProcessKernelManager
from typing import Tuple, Any, List, Union

from ..path import APP_ROOT
from ..record import DEFAULT_LOG_DIR

EXIT_REBOOT = -1
EXIT_NORMAL = 0

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

    def slider_change(self):
        v = self.time_slider.value()
        addr = self.states[-(v+1)].address()
        self.set_location(self.addr_map[addr][0], self.addr_map[addr][1])

    def set_slider(self, addr_map, states):
        # type: (List[Union[str, int]], List[Any]) -> None
        self.addr_map = addr_map
        self.states = states
        self.time_slider.setMinimum(0)
        self.time_slider.setMaximum(len(states))
        self.time_slider.setTickPosition(QtWidgets.QSlider.TicksLeft)
        self.time_slider.setTickInterval(len(states))
        self.time_slider.valueChanged.connect(self.slider_change)

    def set_location(self, source_file, line):
        # type: (str, int) -> None
        if source_file != '??':
            lexer = pygments.lexers.get_lexer_for_filename(str(source_file))
            formatter_opts = dict(
                linenos="inline", linespans="line", hl_lines=[line])
            html_formatter = pygments.formatters.get_formatter_by_name(
                "html", **formatter_opts)
            css = html_formatter.get_style_defs('.highlight')
            with open(str(source_file)) as f:
                tokens = lexer.get_tokens(f.read())
            source = pygments.format(tokens, html_formatter)
            self.code_view.setHtml(code_template.format(css, source))
            self.code_view.scrollToAnchor("line-%d" % max(0, line - 10))

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

    def clear_viewer(self):
        self.code_view.clear()

    def append_archive(self):
        # type: () -> None
        files = DEFAULT_LOG_DIR.listdir()
        files.sort()
        self.code_view.append("\nAvailable files:")
        for f in files:
            if str(f.basename()).endswith(".tar.gz"):
                self.code_view.append(str(f.basename()))

    def shutdown_kernel(self):
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
