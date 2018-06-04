from angr.procedures import SIM_PROCEDURES

from .procedures.file_operation import new_open, ferror, __overflow
from .procedures.setlocale import setlocale


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
]

IO_USE_SIMFILE = True

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
    'readdir'
]
unlocked_symbols = [
    'getchar', 'putchar',
    'feof', 'ferror',
    'putc', 'fflush',
    'fread', 'fwrite',
    'fgets', 'fputs',
]
amd64_symbols = [
    'fopen', 'fdopen',
    'ftello', 'fseeko',
    'open', 'fstat',
    # 'lstat',
]


for lib in libs:
    funcs = SIM_PROCEDURES[lib]
    for name, proc in funcs.items():
        if name in questionable_hook:
            continue
        if IO_USE_SIMFILE or name not in all_IO_hook:
            all_hookable_symbols[name] = proc



if IO_USE_SIMFILE:

    all_hookable_symbols['open'] = new_open
    all_hookable_symbols['ferror'] = ferror
    all_hookable_symbols['__overflow'] = __overflow

    for sym in unlocked_symbols:
        unlocked_sym = sym + '_unlocked'
        all_hookable_symbols[unlocked_sym] = all_hookable_symbols[sym]


    for sym in amd64_symbols:
        amd64_sym = sym + '64'
        all_hookable_symbols[amd64_sym] = all_hookable_symbols[sym]






