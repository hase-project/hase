import signal
from types import FrameType
from typing import Callable, Union, Any

# from typeshed/stdlib/2/signal.pyi
HandlerFunc = Union[Callable[[int, FrameType], None], int, None]


class SignalHandler:
    def __init__(self, signum: int, handler: HandlerFunc = signal.SIG_IGN) -> None:
        self.signum = signum
        self.handler = handler
        self.original_handler = signal.getsignal(signum)

    def __enter__(self) -> "SignalHandler":
        signal.signal(self.signum, self.handler)
        return self

    def __exit__(self, type: Any, value: Any, traceback: Any) -> None:
        signal.signal(self.signum, self.original_handler)
