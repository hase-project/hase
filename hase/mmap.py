import ctypes as ct

libc = ct.CDLL("libc.so.6", use_errno=True)

MAP_FAILED = ct.c_void_p(-1)
mmap = libc.mmap
mmap.restype = ct.c_void_p
mmap.argtypes = [ct.c_void_p, ct.c_size_t, ct.c_int, ct.c_int, ct.c_int, ct.c_long]

munmap = libc.munmap
munmap.restype = ct.c_int
munmap.argtypes = [ct.c_void_p, ct.c_size_t]


class MMap(object):
    def __init__(self, fd, size, protection, flags, offset=0):
        # type: (int, int, int, int, int) -> None
        # ctypes does not support pythons mmap module, so we use the libc
        # version
        self.addr = mmap(None, size, protection, flags, fd, offset)
        assert self.addr != MAP_FAILED.value
        self.size = size

    def close(self):
        # type: () -> None
        if self.addr:
            res = munmap(self.addr, self.size)
            assert res == 0

    def __enter__(self):
        # type: () -> MMap
        return self

    def __exit__(self, type, value, traceback):
        self.close()
