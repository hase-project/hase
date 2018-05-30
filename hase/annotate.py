from __future__ import absolute_import, division, print_function

import subprocess
import os.path
import sys
from collections import defaultdict
from typing import Dict, Tuple, List, Optional, Union
from cle import ELF

from .errors import HaseError
from .path import Path


class Addr2line(object):
    def __init__(self):
        self.dsos = defaultdict(set)

    def _relative_addr(self, dso, addr):
        if dso.is_main_bin:
            return addr
        else:
            return dso.addr_to_offset(addr)

    def add_addr(self, dso, absolute_addr):
        # type: (ELF, int) -> None
        self.dsos[dso].add(absolute_addr)

    def read_addr2line(self, dso, relative_addrs):
        subproc = subprocess.Popen(
            ["addr2line", '-e', dso.binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        (stdoutdata, _) = subproc.communicate('\n'.join(relative_addrs))
        lines = stdoutdata.strip().split('\n')
        if len(lines) < len(relative_addrs):
            raise HaseException("addr2line didn't output enough lines")
        return lines

    def get_addr_map(self, addresses, lines):
        relative_root = os.environ['HASESRC'].split(':')
        addr_map = {}
        for addr, line in zip(addresses, lines):
            if line:
                file, line = line.split(":")
                if file != '??':
                    relative_root.append(os.path.dirname(file))

        for addr, line in zip(addresses, lines):
            if line:
                file, line = line.split(":")
                # TODO: file:line (discriminator n)
                # TODO: file:?
                line = line.split(" ")[0]
                if not os.path.exists(file):
                    new_file = Path.find_in_path(file, relative_root)
                    # print("Redirect: {} -> {}".format(file, new_file))
                    file = new_file
                if line == '?':
                    line = 0
                addr_map[addr] = [file, int(line)]
        return addr_map

    '''
    # NOTE: not working if dso.binary is deleted
    def compute_single(self, state):
        dso = state.object()
        addr = state.address()
        # binary not exists here
        line = self.read_addr2line(dso, ["0x%x" % self._relative_addr(dso, addr)])
        addr_map = self.get_addr_map([addr], line)
        return addr_map
    '''

    def compute(self):
        # type: () -> Dict[int, List[Union[str, int]]]
        addr_map = {} # type: Dict[int, List[Union[str, int]]]
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
                raise HaseError("addr2line didn't output enough lines")

            relative_root = os.environ['HASESRC'].split(':')

            for addr, line in zip(addresses, lines):
                if line:
                    file, line = line.split(":")
                    if file != '??':
                        relative_root.append(os.path.dirname(file))

            for addr, line in zip(addresses, lines):
                if line:
                    file, line = line.split(":")
                    # TODO: file:line (discriminator n)
                    # TODO: file:?
                    line = line.split(" ")[0]
                    if not os.path.exists(file):
                        new_file = Path.find_in_path(file, relative_root)
                        # print("Redirect: {} -> {}".format(file, new_file))
                        file = new_file
                    if line == '?':
                        line = 0
                    addr_map[addr] = [file, int(line)]
        return addr_map
