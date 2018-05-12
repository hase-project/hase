from __future__ import absolute_import, division, print_function

import subprocess
import os.path
import sys
from collections import defaultdict
from typing import Dict, Tuple, List, Optional, Union
from cle import ELF

from .exceptions import HaseException
from .path import Path

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

    def find_in_path(self, filename, relative_root=None):
        # type: (str, Optional[List[str]]) -> str
        basename = os.path.basename(filename)
        if relative_root:
            search_path = relative_root + os.environ['HASESRC'].split(':')
        else:
            search_path = os.environ['HASESRC'].split(':')
        collected_root = ['']
        for path in search_path:
            for root, dirs, files in os.walk(path):
                if basename in files:
                    collected_root.append(root)

        def intersect_judge(root):
            elems_f = filename.split('/')
            elems_r = os.path.join(root, basename).split('/')
            return len([v for v in elems_f if v in elems_r])

        return os.path.join(max(collected_root, key=intersect_judge), basename)

    def compute(self):
        # type: () -> Dict[int, List[Union[str, int]]]
        addr_map = {}
        for dso, addresses in self.dsos.items():
            relative_addrs = []

            for addr in addresses:
                relative_addrs.append("0x%x" % self._relative_addr(dso, addr))

            subproc = subprocess.Popen(
                ["addr2line", '-e', dso.binary],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
            (stdoutdata, _) = subproc.communicate('\n'.join(relative_addrs))
            lines = stdoutdata.strip().split('\n')
            if len(lines) < len(addresses):
                raise HaseException("addr2line didn't output enough lines")

            relative_root = []

            for addr, line in zip(addresses, lines):
                file, line = line.split(":")
                if file != '??':
                    relative_root.append(os.path.dirname(file))

            for addr, line in zip(addresses, lines):
                file, line = line.split(":")
                # TODO: file:line (discriminator n)
                # TODO: file:?
                line = line.split(" ")[0]
                if not os.path.exists(file):
                    new_file = self.find_in_path(file, relative_root)
                    print("Redirect: {} -> {}".format(file, new_file))
                    file = new_file
                print(file, line)
                if line == '?':
                    line = 0
                addr_map[addr] = [file, int(line)]
        return addr_map
