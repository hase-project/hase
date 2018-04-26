from __future__ import absolute_import
import sys
from PyQt5 import QtWidgets
from PyQt5.uic import loadUiType
import pygments
import pygments.lexers
import pygments.formatters

from qtconsole.inprocess import QtInProcessKernelManager

from hase.path import APP_ROOT

form_class, base_class = loadUiType(APP_ROOT.join('mainwindow.ui'))

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


def commands(shell, app, window):
    from .ipython_extension import HaseMagics
    return HaseMagics(shell, app, window)


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
        lexer = pygments.lexers.CppLexer()
        formatter = pygments.formatters.HtmlFormatter(
            linenos="inline", linespans="line", hl_lines=[line])
        css = formatter.get_style_defs('.highlight')
        with open(source_file) as f:
            tokens = lexer.get_tokens(f.read())
        source = pygments.format(tokens, formatter)
        self.code_view.setHtml(code_template.format(css, source))
        self.code_view.scrollToAnchor("line-%d" % max(0, line - 10))

    def setup_ipython(self, app, window):
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
        shell.extension_manager.load_extension("hase.ipython_extension")

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


if __name__ == "__main__":
    sys.exit(start_window())
