# pylint: disable=E1101
from claripy import BVS
from ctypes import * # noqa # pylint: disable=W0614


def SPOINTER(cls):
    return POINTER(cls.c_cls)


class SymbolicMeta(type):
    def __new__(cls, name, base, attrs):
        if '_fields_' not in attrs.keys():
            raise Exception("Need _fields_")
        fields = attrs['_fields_']
        for i, f in enumerate(fields):
            if getattr(f[1], 'is_symstruct', False):
                fields[i][1] = f[1].c_cls

        class CTypeStruct(Structure):
            _fields_ = fields

        attrs['is_symstruct'] = True
        attrs['c_cls'] = CTypeStruct
        attrs['size'] = sizeof(CTypeStruct)

        new_cls = super(SymbolicMeta, cls).__new__(name, base, attrs)
        return new_cls


# disable pylint error
class SymStruct():
    def __init__(self, buf):
        self.buf = buf        

    def read(self, proc, sym):
        sym_list = sym.partition('.')
        sym = sym_list[0]
        member = getattr(self.c_cls, sym, None)
        if member:
            ty = getattr(self._fields_, sym)
            if getattr(ty, 'is_symstruct', False):
                ins = ty(self.buf + member.offset)
                if sym_list[1] == '':
                    return ins.read_all(proc)
                else:
                    return ins.read(proc, sym_list[2])
            return proc.state.memory.load(
                self.buf + member.offset,
                member.size
            )

    def read_all(self, proc):
        res = []
        for sym, _ in self.c_cls._fields_:
            res.append((sym, self.read(proc, sym)))
        return res

    def store(self, proc, sym, value_=None):
        sym_list = sym.partition('.')
        sym = sym_list[0]
        member = getattr(self.c_cls, sym, None)
        if member:
            ty = getattr(self._fields_, sym)
            if getattr(ty, 'is_symstruct', False):
                ins = ty(self.buf + member.offset)
                if sym_list[1] == '':
                    ins.store_all(proc)
                else:
                    ins.store(proc, sym_list[2], value_)
            else:
                value = value_ if value_ else proc.state.se.BVS(sym, member.size * 8)
                proc.state.memory.store(
                    self.buf + member.offset,
                    value,
                    size=member.size
                )

    def store_all(self, proc):
        for sym, _ in self.c_cls._fields_:
            self.store(proc, sym)
    


# https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/bits/types/__sigset_t.h.html
class sigset_t(SymStruct):
    __metaclass__ = SymbolicMeta
    _fields_ = [
        ('__bits', c_ulong * 128 / sizeof(c_long))
    ]


class sigaction(SymStruct):
    __metaclass__ = SymbolicMeta
    _fields_ = [
        ('sa_handler', POINTER(CFUNCTYPE(None, c_int))),
        # void (*sa_sigaction)(int, siginfo_t*, void*)
        ('sa_sigaction', POINTER(CFUNCTYPE(None, int, c_void_p, c_void_p))),
        ('sa_mask', sigset_t),
        ('sa_flags', c_int),
        ('sa_restorer', POINTER(CFUNCTYPE(None, None)))
    ]


class linux_dirent(SymStruct):
    __metaclass__ = SymbolicMeta
    _fields_ = [
        ('d_ino', c_ulong),
        ('d_off', c_ulong),
        ('d_reclen', c_ushort),
        ('d_name', c_char_p),
        ('pad', c_char),
        ('d_type', c_char)
    ]


class linux_dirent64(SymStruct):
    __metaclass__ = SymbolicMeta
    _fields_ = [
        # ino64_t d_ino
        ('d_ino', c_ulong),
        # off64_t d_off
        ('d_off', c_ulong),
        ('d_reclen', c_ushort),
        ('d_type', c_char),
        ('d_name', c_char_p)
    ]


class robust_list_head(SymStruct):
    __metaclass__ = SymbolicMeta
    _fields_ = [
        ('list', c_void_p),
        ('futex_offset', c_long),
        ('list_op_pending', c_void_p)
    ]


class timespec(SymStruct):
    __metaclass__ = SymbolicMeta
    _fields_ = [
        # time_t tv_sec
        ('tv_sec', c_ulong),
        ('tv_nsec', c_long),
    ]


class sysinfo_t(SymStruct):
    __metaclass__ = SymbolicMeta
    _fields_ = [
        ('uptime', c_long),
        ('loads', c_ulong * 3),
        ('totalram', c_ulong),
        ('freeram', c_ulong),
        ('sharedram', c_ulong),
        ('bufferram', c_ulong),
        ('totalswap', c_ulong),
        ('freeswap', c_ulong),
        ('procs', c_ushort),
        ('totalhigh', c_ulong),
        ('freehigh', c_ulong),
        ('mem_unit', c_uint),
        ('_f', c_char * 2)
    ]