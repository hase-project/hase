from __future__ import absolute_import, division, print_function

import sys
from PyQt5 import QtWidgets
from PyQt5.uic import loadUiType
import pygments
import pygments.lexers
import pygments.formatters
from qtconsole.inprocess import QtInProcessKernelManager
from typing import Tuple, Any

from ..path import APP_ROOT


form_class, base_class = loadUiType(str(APP_ROOT.join('frontend', 'mainwindow.ui')))  # type: Tuple[Any, Any]

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

    def set_location(self, source_file, line):
        # type: (str, int) -> None
        lexer = pygments.lexers.get_lexer_for_filename(source_file)
        html_formatter = pygments.formatters.get_formatter_by_name("html")
        formatter = html_formatter(linenos="inline", linespans="line", hl_lines=[line])
        css = formatter.get_style_defs('.highlight')
        with open(source_file) as f:
            tokens = lexer.get_tokens(f.read())
        source = pygments.format(tokens, formatter)
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
    return app.exec_()

def main():
    sys.exit(start_window())
