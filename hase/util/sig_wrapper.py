import signal, os

from typing import Any

class RegisterSig():
    def __init__(self, signum, handler = signal.SIG_IGN):
        # type: (int, Any) -> None
        self.signum = signum
        self.handler = handler
        self.original_handler = signal.getsignal(signum)

    def __enter__(self):
        # type: () -> RegisterSig
        signal.signal(self.signum, self.handler)
        return self

    def __exit__(self, type, value, traceback):
        signal.signal(self.signum, self.original_handler)