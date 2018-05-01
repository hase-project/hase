from __future__ import absolute_import, division, print_function

import os
# stop pwnlib from doing fancy things
os.environ["PWNLIB_NOTERM"] = "1"
from pwn import Coredump, ELF # NOQA
