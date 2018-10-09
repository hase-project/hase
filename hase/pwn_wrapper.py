from __future__ import absolute_import, division, print_function

import os

from pwnlib.elf.corefile import Coredump, Mapping
from pwnlib.elf.elf import ELF

# stop pwnlib from doing fancy things
os.environ["PWNLIB_NOTERM"] = "1"
