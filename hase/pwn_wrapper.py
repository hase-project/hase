import os
# stop pwnlib from doing fancy things
os.environ["PWNLIB_NOTERM"] = "1"
from pwn import Coredump, ELF
