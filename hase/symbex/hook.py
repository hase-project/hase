from angr.procedures import SIM_PROCEDURES

from .procedures.file_operation import new_open, ferror, __overflow, ftello, fseeko, stat, __xstat, __fxstat
from .procedures.setlocale import setlocale

from typing import List, Any

# TODO: How to deal with overload function hook?
# TODO: getenv


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
    'fileno',
    # 'clearerr'
]
posix64_IO_symbols = [
    'fopen', 'fdopen',
    'ftello', 'fseeko',
    'open', 'fstat', '__fxstat',
    # 'lstat', 'lseek', fgetpos', 'fsetpos', 'pread', 'pwrite'
]


for lib in libs:
    funcs = SIM_PROCEDURES[lib]
    for name, proc in funcs.items():
        if name in questionable_hook:
            continue
        if IO_USE_SIMFILE or name not in all_IO_hook:
            all_hookable_symbols[name] = proc


all_hookable_symbols['setlocale'] = setlocale


if IO_USE_SIMFILE:

    all_hookable_symbols['open'] = new_open
    all_hookable_symbols['ferror'] = ferror
    all_hookable_symbols['__overflow'] = __overflow
    all_hookable_symbols['ftello'] = ftello
    all_hookable_symbols['fseeko'] = fseeko
    all_hookable_symbols['stat'] = stat    
    all_hookable_symbols['__xstat'] = __xstat    
    all_hookable_symbols['__fxstat'] = __fxstat    

    for sym in unlocked_IO_symbols:
        unlocked_sym = sym + '_unlocked'
        all_hookable_symbols[unlocked_sym] = all_hookable_symbols[sym]


    for sym in posix64_IO_symbols:
        posix64_sym = sym + '64'
        all_hookable_symbols[posix64_sym] = all_hookable_symbols[sym]






