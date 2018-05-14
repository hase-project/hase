import signal

from types import FrameType
from typing import Callable, Union

# from typeshed/stdlib/2/signal.pyi
HandlerFunc = Union[Callable[[int, FrameType], None], int, None]


class SignalHandler():
    def __init__(self, signum, handler=signal.SIG_IGN):
        # type: (int, HandlerFunc) -> None
        self.signum = signum
        self.handler = handler
        self.original_handler = signal.getsignal(signum)

    def __enter__(self):
        # type: () -> SignalHandler
        signal.signal(self.signum, self.handler)
        return self

    def __exit__(self, type, value, traceback):
        signal.signal(self.signum, self.original_handler)
