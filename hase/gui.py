from __future__ import absolute_import
import sys
from PyQt5 import QtWidgets
from PyQt5.uic import loadUiType

from qtconsole.inprocess import QtInProcessKernelManager

from .path import APP_ROOT

form_class, base_class = loadUiType(APP_ROOT.join('mainwindow.ui'))


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

    def setup_ipython(self, app):
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

    def shutdown_kernel(self):
        print('Shutting down kernel...')
        self.kernel_client.stop_channels()
        self.kernel_manager.shutdown_kernel()


def start_window():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    app.aboutToQuit.connect(window.shutdown_kernel)
    window.show()
    window.setup_ipython(app)
    return app.exec_()


if __name__ == "__main__":
    sys.exit(start_window())
