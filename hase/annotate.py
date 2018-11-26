import os.path
import subprocess
from typing import DefaultDict, Dict, Set, Tuple

from cle import ELF

from .errors import HaseError
from .path import find_in_path


class Addr2line:
    def __init__(self) -> None:
        self.dsos: DefaultDict[ELF, Set[int]] = DefaultDict(set)

    def _relative_addr(self, dso: ELF, addr: int) -> int:
        if dso.is_main_bin:
            return addr
        else:
            return dso.addr_to_offset(addr)

    def add_addr(self, dso: ELF, absolute_addr: int) -> None:
        self.dsos[dso].add(absolute_addr)

    def compute(self) -> Dict[int, Tuple[str, int]]:
        addr_map: Dict[int, Tuple[str, int]] = {}
        for dso, addresses in self.dsos.items():
            relative_addrs = []

            for addr in addresses:
                relative_addrs.append("0x%x" % self._relative_addr(dso, addr))

            subproc = subprocess.Popen(
                ["addr2line", "-e", dso.binary],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            (stdoutdata, _) = subproc.communicate("\n".join(relative_addrs))
            lines = stdoutdata.strip().split("\n")
            if len(lines) < len(addresses):
                raise HaseError("addr2line didn't output enough lines")

            relative_root = os.environ["HASESRC"].split(":")

            for addr, line in zip(addresses, lines):
                if line:
                    file, line = line.split(":")
                    if file != "??":
                        relative_root.append(os.path.dirname(file))

            for addr, line in zip(addresses, lines):
                if line:
                    file, line = line.split(":")
                    # TODO: file:line (discriminator n)
                    # TODO: file:?
                    line = line.split(" ")[0]
                    if not os.path.exists(file):
                        new_file = find_in_path(file, relative_root)
                        # print("Redirect: {} -> {}".format(file, new_file))
                        file = new_file
                    if line == "?":
                        line = 0
                    addr_map[addr] = (file, int(line))
        return addr_map
