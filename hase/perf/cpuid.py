# -*- coding: utf-8 -*-
#
#     Copyright (c) 2018 Anders Høst
#
# source: https://github.com/flababah/cpuid.py
# license: MIT

import ctypes
import os
import platform
from ctypes import CFUNCTYPE, POINTER, c_int, c_size_t, c_uint32, c_void_p
from typing import Iterator, Tuple

# Posix x86_64:
# Three first call registers : RDI, RSI, RDX
# Volatile registers         : RAX, RCX, RDX, RSI, RDI, R8-11

# Windows x86_64:
# Three first call registers : RCX, RDX, R8
# Volatile registers         : RAX, RCX, RDX, R8-11

# cdecl 32 bit:
# Three first call registers : Stack (%esp)
# Volatile registers         : EAX, ECX, EDX

_POSIX_64_OPC = [
    0x53,  # push   %rbx
    0x89,
    0xF0,  # mov    %esi,%eax
    0x89,
    0xD1,  # mov    %edx,%ecx
    0x0F,
    0xA2,  # cpuid
    0x89,
    0x07,  # mov    %eax,(%rdi)
    0x89,
    0x5F,
    0x04,  # mov    %ebx,0x4(%rdi)
    0x89,
    0x4F,
    0x08,  # mov    %ecx,0x8(%rdi)
    0x89,
    0x57,
    0x0C,  # mov    %edx,0xc(%rdi)
    0x5B,  # pop    %rbx
    0xC3,  # retq
]

_WINDOWS_64_OPC = [
    0x53,  # push   %rbx
    0x89,
    0xD0,  # mov    %edx,%eax
    0x41,
    0x89,
    0xC9,  # mov    %ecx,%r9d
    0x44,
    0x89,
    0xC1,  # mov    %r8d,%ecx
    0x0F,
    0xA2,  # cpuid
    0x41,
    0x89,
    0x01,  # mov    %eax,(%r9)
    0x41,
    0x89,
    0x59,
    0x04,  # mov    %ebx,0x4(%r9)
    0x41,
    0x89,
    0x49,
    0x08,  # mov    %ecx,0x8(%r9)
    0x41,
    0x89,
    0x51,
    0x0C,  # mov    %edx,0xc(%r9)
    0x5B,  # pop    %rbx
    0xC3,  # retq
]

_CDECL_32_OPC = [
    0x53,  # push   %ebx
    0x57,  # push   %edi
    0x8B,
    0x7C,
    0x24,
    0x0C,  # mov    0xc(%esp),%edi
    0x8B,
    0x44,
    0x24,
    0x10,  # mov    0x10(%esp),%eax
    0x8B,
    0x4C,
    0x24,
    0x14,  # mov    0x14(%esp),%ecx
    0x0F,
    0xA2,  # cpuid
    0x89,
    0x07,  # mov    %eax,(%edi)
    0x89,
    0x5F,
    0x04,  # mov    %ebx,0x4(%edi)
    0x89,
    0x4F,
    0x08,  # mov    %ecx,0x8(%edi)
    0x89,
    0x57,
    0x0C,  # mov    %edx,0xc(%edi)
    0x5F,  # pop    %edi
    0x5B,  # pop    %ebx
    0xC3,  # ret
]

is_windows = os.name == "nt"
is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8


class CPUID_struct(ctypes.Structure):
    _fields_ = [(r, c_uint32) for r in ("eax", "ebx", "ecx", "edx")]


class CPUID:
    def __init__(self) -> None:
        machine = platform.machine()  # type: ignore
        if machine not in ("AMD64", "x86_64", "x86", "i686"):
            raise SystemError("Only available for x86")

        opc = _POSIX_64_OPC if is_64bit else _CDECL_32_OPC

        size = len(opc)
        # bug in mypy:
        # https://github.com/python/mypy/pull/4869/commits/7e804feaac6be96bde5d27027192ba24155e495d#diff-b4c2ac9ec8ee99d26b77000717c1f572R93
        # cannot be detected correctly at the moment
        code = (ctypes.c_ubyte * size)(*opc)  # type: ignore

        self.libc = ctypes.cdll.LoadLibrary("libc.so.6")
        self.libc.valloc.restype = ctypes.c_void_p
        self.libc.valloc.argtypes = [ctypes.c_size_t]
        self.addr = self.libc.valloc(size)
        if not self.addr:
            raise MemoryError("Could not allocate memory")

        self.libc.mprotect.restype = c_int
        self.libc.mprotect.argtypes = [c_void_p, c_size_t, c_int]
        ret = self.libc.mprotect(self.addr, size, 1 | 2 | 4)
        if ret != 0:
            raise OSError("Failed to set RWX")

        ctypes.memmove(self.addr, code, size)

        func_type = CFUNCTYPE(None, POINTER(CPUID_struct), c_uint32, c_uint32)
        self.func_ptr = func_type(self.addr)

    def __call__(self, eax: int, ecx: int = 0) -> Tuple[int, int, int, int]:
        struct = CPUID_struct()
        self.func_ptr(struct, eax, ecx)
        return struct.eax, struct.ebx, struct.ecx, struct.edx

    def __del__(self) -> None:
        # Seems to throw exception when the program ends and
        # libc is cleaned up before the object?
        self.libc.free.restype = None
        self.libc.free.argtypes = [c_void_p]
        self.libc.free(self.addr)


if __name__ == "__main__":

    def valid_inputs() -> Iterator[Tuple[int, Tuple[int, int, int, int]]]:
        cpuid = CPUID()
        for eax in (0x0, 0x80000000):
            highest, _, _, _ = cpuid(eax)
            while eax <= highest:
                regs = cpuid(eax)
                yield (eax, regs)
                eax += 1

    print(" ".join(x.ljust(8) for x in ("CPUID", "A", "B", "C", "D")).strip())
    for eax, regs in valid_inputs():
        print("%08x" % eax, " ".join("%08x" % reg for reg in regs))
