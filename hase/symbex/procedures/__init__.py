import os
import file_operation
import memory_operation
import group_operation
import miscs
import socket_operation

from typing import Dict

__all__ = [
    'file_operation',
    'memory_operation',
    'group_operation',
    'miscs',
    'socket_operation',
]


all_IO_hook = [
    'fclose', 'feof', 'fflush', 'fgetc',
    'fgets', 'fopen', 'fprintf', 'fputc',
    'fputs', 'fread', 'fseek', 'ftell',
    'fwrite', 'getchar', 'printf', 'putc',
    'putchar', 'puts', 'scanf', 'sscanf', 
    'snprintf', 'sprintf', 'ungetc', 'vsnprintf',
    'close', 'fstat', 'lseek', 'open',
    'read', 'stat', 'unlink', 'write',
    'closedir', 'fdopen', 'fileno', 'opendir',
    'readdir', 'getc', '__printf_chk'
]


def add_alias(dct, nlist, decr = lambda x: x):
    for sym in nlist:
        decr_sym = decr(sym)
        dct[decr_sym] = sym


def add_alias_s(dct, sym, *args):
    for decr_sym in args:
        dct[decr_sym] = sym


alias_symbols = {} # type: Dict[str, str]


unlocked_IO_symbols = [
    'getchar', 'putchar',
    'feof', 'ferror',
    'putc', 'fflush',
    'fread', 'fwrite',
    'fgets', 'fputs',
    'fileno', 'getc',
    'fputc', 'fgetc',
    'clearerr'
]
add_alias(alias_symbols, unlocked_IO_symbols, lambda s: s + '_unlocked')


posix64_IO_symbols = [
    'fopen', 'fdopen',
    'ftello', 'fseeko',
    'open', 'fstat', 'stat'
    '__xstat', '__lxstat', '__fxstat',
    'readdir', 'opendir',
    'lseek', 'lstat',
    'fgetpos', 'fsetpos', 
    'pread', 'pwrite', 'fxstatat',
    'telldir', 'seekdir', 'rewinddir', 'closedir'
]
add_alias(alias_symbols, posix64_IO_symbols, lambda s: s + '64')


libc_general_symbols = [
    'malloc', 'calloc',
    'realloc', 'free',
    'memalign'
]
add_alias(alias_symbols, libc_general_symbols, lambda s: '__libc_' + s)


add_alias(alias_symbols,
    ['feof', 'getc', 'putc', 'puts'],
    lambda s: '_IO_' + s
)


add_alias(alias_symbols,
    [
        'getpagesize', 'stpcpy', 'strdup',
        'strtok_r', '__register_atfork' 
    ],
    lambda s: '__' + s
)


add_alias(alias_symbols, ['strtol'], lambda s: '__' + s + '_internal')


add_alias_s(alias_symbols, 'abort', '__assert_fail', '__stack_chk_fail')
add_alias_s(alias_symbols, 'memcpy', 'bcopy', 'bmove')
add_alias_s(alias_symbols, 'memcmp', 'bcmp')
add_alias_s(alias_symbols, 'memset', 'bzero')
add_alias_s(alias_symbols, 'strchr', 'index')
add_alias_s(alias_symbols, 'strrchr', 'rindex')
add_alias_s(alias_symbols, 'exit', 'exit_group')
add_alias_s(alias_symbols, 'getuid', 'geteuid')
add_alias_s(alias_symbols, 'getgid', 'getegid')

