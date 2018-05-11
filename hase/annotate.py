from __future__ import absolute_import, division, print_function

import subprocess
from collections import defaultdict
from typing import Dict, Tuple
from cle import ELF

from .exceptions import HaseException


class Addr2line():
    def __init__(self):
        self.dsos = defaultdict(set)

    def _relative_addr(self, dso, addr):
        if dso.is_main_bin:
            return addr
        else:
            return dso.address_to_offset(addr)

    def add_addr(self, dso, absolute_addr):
        # type: (ELF, int) -> None
        self.dsos[dso].add(absolute_addr)

    def compute(self):
        # type: () -> Dict[int, Tuple[str, int]]
        addr_map = {}
        for dso, addresses in self.dsos.items():
            relative_addrs = []

            for addr in addresses:
                relative_addrs.append("0x%x" % self._relative_addr(dso, addr))

            # FIXME: relative path with -s (strip directory names)
            subproc = subprocess.Popen(
                ["addr2line", '-e', dso.binary],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
            (stdoutdata, _) = subproc.communicate('\n'.join(relative_addrs))
            lines = stdoutdata.strip().split('\n')
            if len(lines) < len(addresses):
                raise HaseException("addr2line didn't output enough lines")

            for addr, line in zip(addresses, lines):
                file, line = line.split(":")
                # TODO: file:line (discriminator n)
                # TODO: file:?
                print(file, line)
                line = line.split(" ")[0]
                if line == "?":
                    line = 0
                addr_map[addr] = (file, int(line))
        return addr_map
