from __future__ import absolute_import, division, print_function

import ctypes as ct

libc = ct.CDLL('libc.so.6', use_errno=True)
PTRACE = libc.ptrace
PTRACE_TRACEME = 0
PTRACE_DETACH = 17


def ptrace(request, pid, addr, data):
    # type: (int, int, int, int) -> int
    res = PTRACE(request, pid, addr, data)
    assert res != 1
    return res


def ptrace_me():
    # type: () -> None
    ptrace(PTRACE_TRACEME, 0, 0, 0)


def ptrace_detach(pid):
    # type: (int) -> None
    ptrace(PTRACE_DETACH, pid, 0, 0)

