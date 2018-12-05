from collections import OrderedDict
from typing import Callable, Dict, List

# TODO: make a general resymbolic wrapper for may-raise exception procedures

all_IO_hook = [
    "fclose",
    "feof",
    "fflush",
    "fgetc",
    "fgets",
    "fopen",
    "fprintf",
    "fputc",
    "fputs",
    "fread",
    "fseek",
    "ftell",
    "fwrite",
    "getchar",
    "printf",
    "putc",
    "putchar",
    "puts",
    "scanf",
    "sscanf",
    "snprintf",
    "sprintf",
    "ungetc",
    "vsnprintf",
    "close",
    "fstat",
    "lseek",
    "open",
    "read",
    "stat",
    "unlink",
    "write",
    "closedir",
    "fdopen",
    "fileno",
    "opendir",
    "readdir",
    "getc",
    "__printf_chk",
]


def add_alias(
    dct: Dict[str, str], nlist: List[str], decr: Callable[[str], str] = lambda x: x
) -> None:
    for sym in nlist:
        decr_sym = decr(sym)
        dct[decr_sym] = sym


def add_alias_s(dct: Dict[str, str], sym: str, *args: str) -> None:
    for decr_sym in args:
        dct[decr_sym] = sym


alias_symbols: Dict[str, str] = OrderedDict()


unlocked_IO_symbols = [
    "getchar",
    "putchar",
    "feof",
    "ferror",
    "putc",
    "fflush",
    "fread",
    "fwrite",
    "fgets",
    "fputs",
    "fileno",
    "getc",
    "fputc",
    "fgetc",
    "clearerr",
]
add_alias(alias_symbols, unlocked_IO_symbols, lambda s: s + "_unlocked")


add_alias(
    alias_symbols,
    [
        "getpagesize",
        "stpcpy",
        "strdup",
        "strtok_r",
        "register_atfork",
        "sigaction",
        "stat",
        "fstat",
        "lstat",
        "fcntl",
        "getpid",
        "open",
        "open64",
        "openat",
        "openat64",
        "read",
        "write",
        "close",
        "socket",
        "gettext",
        "dgettext",
        "dcgettext",
        "connect",
        "getdelim",
    ],
    lambda s: "__" + s,
)


posix64_IO_symbols = [
    "fopen",
    "fdopen",
    "ftello",
    "fseeko",
    "open",
    "fstat",
    "stat" "__xstat",
    "__lxstat",
    "__fxstat",
    "statfs",
    "fstatfs",
    "readdir",
    "opendir",
    "lseek",
    "lstat",
    "fgetpos",
    "fsetpos",
    "pread",
    "pwrite",
    "fxstatat",
    "telldir",
    "seekdir",
    "rewinddir",
    "closedir",
]
add_alias(alias_symbols, posix64_IO_symbols, lambda s: s + "64")


nocancel_symbols = [
    "open",
    "open64",
    "openat",
    "openat64",
    "read",
    "write",
    "close",
    "connect",
]
add_alias(alias_symbols, nocancel_symbols, lambda s: "__" + s + "_nocancel")


libc_general_symbols = ["malloc", "calloc", "realloc", "free", "memalign"]
add_alias(alias_symbols, libc_general_symbols, lambda s: "__libc_" + s)


# TODO: https://github.com/lattera/glibc/blob/a2f34833b1042d5d8eeb263b4cf4caaea138c4ad/libio/Versions
add_alias(
    alias_symbols,
    [
        "feof",
        "getc",
        "putc",
        "puts",
        "ferrof",
        "peekc_unlocked",
        "vfscanf",
        "vfprintf",
        "seekoff",
        "seekpos",
        "padn",
        "sgetn",
        "fwide",
        "fwrite",
        "fread",
        "fclose",
        "fdopen",
        "fflush",
        "fgetpos",
        "fgetpos64",
        "fprintf" "fgets",
        "fopen",
        "fopen64",
        "fputs",
        "printf",
        "fsetpos",
        "fsetpos64",
        "ftell",
        "fwide",
        "seekoff",
        "seekpos",
        "setbuffer",
        "setvbuf",
        "ungetc",
        "vsprintf",
        "vdprintf",
        "vsscanf",
    ],
    lambda s: "_IO_" + s,
)


sse2_symbols = ["memcpy", "memset", "strcmp", "strchr", "strncpy", "strnlen", "strlen"]
add_alias(alias_symbols, sse2_symbols, lambda s: "__" + s + "_sse2")


add_alias_s(alias_symbols, "strtol", "__strtol_internal")
add_alias_s(alias_symbols, "strncasecmp", "__strncasecmp_l_avx")
# add_alias_s(alias_symbols, 'abort', '__assert_fail', '__stack_chk_fail')
add_alias_s(alias_symbols, "memcpy", "memmove", "bcopy", "bmove")
add_alias_s(alias_symbols, "memcmp", "bcmp")
add_alias_s(alias_symbols, "memset", "bzero")
add_alias_s(alias_symbols, "strchr", "index")
add_alias_s(alias_symbols, "strrchr", "rindex")
add_alias_s(alias_symbols, "exit", "exit_group")
add_alias_s(alias_symbols, "getuid", "geteuid")
add_alias_s(alias_symbols, "getgid", "getegid")
add_alias_s(alias_symbols, "vfprintf", "buffered_vfprintf")
add_alias_s(alias_symbols, "free", "cfree")


# TODO: add all sse2 symbols
add_alias_s(alias_symbols, "memcpy", "__memcpy_sse2_unaligned")


# Arch-dependent functions
common_prefix = ["__GI_", "__interceptor___", "__interceptor_"]
common_suffix = [
    "_sse",
    "_avx",
    "@",
    "_l_avx",
    "_l_sse",
    "_l_internal",
    "_unaligned",
    "_ssse",
]
