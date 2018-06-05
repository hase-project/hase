from angr.procedures import SIM_PROCEDURES

from .procedures.file_operation import (
    new_open, opendir,
    __overflow, __underflow, __uflow,
    ftello, fseeko, ferror,
    stat, lstat, __xstat, __fxstat)
from .procedures.miscs import setlocale
from .procedures.memory_operation import mempcpy, stpcpy, stpncpy

from typing import List, Any

# TODO: How to deal with overload function hook?
# TODO: wchar functions support?


unsupported_symbols = [
    ('__new_exitfn', 'atexit', 'no simulation'),
    ('getenv', 'getenv', 'wrong branch'),
    # ('_IO_do_allocate', 'fread_unlocked', 'wrong branch'),
    # ('feof', 'feof', 'wrong branch'),
    # ('__overflow', 'putchar_unlocked', 'no simulation')
]

all_hookable_symbols = {}

libs = [
    'libc', 'glibc', 
    'linux_kernel', 'posix',
    'linux_loader'
]

questionable_hook = [
] # type: List[str]

IO_USE_SIMFILE = True

# NOTE: all glibc IO: https://github.com/angr/angr/blob/b561ad9a313d0fd73503e9d0eaefd023192a56c1/angr/procedures/definitions/glibc.py#L3336
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
    'readdir', 'getc'
]
unlocked_IO_symbols = [
    'getchar', 'putchar',
    'feof', 'ferror',
    'putc', 'fflush',
    'fread', 'fwrite',
    'fgets', 'fputs',
    'fileno', 'getc',
    # 'clearerr'
]
posix64_IO_symbols = [
    'fopen', 'fdopen',
    'ftello', 'fseeko',
    'open', 'fstat', '__fxstat',
    'readdir', 'opendir',
    'lseek', 'lstat',
    # 'fgetpos', 'fsetpos', 
    # 'pread', 'pwrite', 'fxstatat',
    # 'telldir', 'seekdir', 'rewinddir', 'closedir'
]
# NOTE: http://refspecs.linux-foundation.org/LSB_4.0.0/LSB-Core-generic/LSB-Core-generic/libcman.html
chk_IO_symbols = [
    'fgets', 'fgets_unlocked',
    'fprintf', 'printf',
    'read', 'snprintf', 
    'sprintf', 'vsnprintf', 
    # 'vfprintf', 'vsprintf', 'vprintf',
    # 'pread', 'pread64',
    # 'readlink'
]
chk_general_symbols = [
    'getcwd', 'memcpy',
    'mempcpy', 'memset',
    'recv', 'recvfrom',
    'strcat', 'strcpy',
    # 'memmove', 'stpcpy', 'stpncpy', 'realpath',
]
libc_general_symbols = [
    'malloc', 'calloc',
    'realloc', 'free',
    'memalign'
]


for lib in libs:
    funcs = SIM_PROCEDURES[lib]
    for name, proc in funcs.items():
        if name in questionable_hook:
            continue
        if IO_USE_SIMFILE or name not in all_IO_hook:
            all_hookable_symbols[name] = proc


all_hookable_symbols['setlocale'] = setlocale
all_hookable_symbols['mempcpy'] = mempcpy
all_hookable_symbols['stpcpy'] = stpcpy
all_hookable_symbols['stpncpy'] = stpncpy
# weird case
all_hookable_symbols['__sigaction'] = all_hookable_symbols['sigaction']


for sym in chk_general_symbols:
    chk_sym = '__' + sym + '_chk'
    all_hookable_symbols[chk_sym] = all_hookable_symbols[sym]

for sym in libc_general_symbols:
    libc_sym = '__libc_' + sym
    all_hookable_symbols[libc_sym] = all_hookable_symbols[sym]

if IO_USE_SIMFILE:

    all_hookable_symbols['open'] = new_open
    all_hookable_symbols['opendir'] = opendir

    all_hookable_symbols['__overflow'] = __overflow
    all_hookable_symbols['__underflow'] = __underflow
    all_hookable_symbols['__uflow'] = __uflow

    all_hookable_symbols['ferror'] = ferror
    all_hookable_symbols['ftello'] = ftello
    all_hookable_symbols['fseeko'] = fseeko

    all_hookable_symbols['stat'] = stat    
    all_hookable_symbols['lstat'] = lstat    
    all_hookable_symbols['__xstat'] = __xstat    
    all_hookable_symbols['__fxstat'] = __fxstat    

    for sym in unlocked_IO_symbols:
        unlocked_sym = sym + '_unlocked'
        all_hookable_symbols[unlocked_sym] = all_hookable_symbols[sym]


    for sym in posix64_IO_symbols:
        posix64_sym = sym + '64'
        all_hookable_symbols[posix64_sym] = all_hookable_symbols[sym]

    for sym in chk_IO_symbols:
        chk_sym = '__' + sym + '_chk'
        all_hookable_symbols[chk_sym] = all_hookable_symbols[sym]





