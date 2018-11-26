from pathlib import Path
from typing import Any, Dict, List
import copy

from .pwn_wrapper import ELF, Coredump, Mapping

ELF_MAGIC = b"\x7fELF"


def filter_mappings(mappings: List[Mapping], sysroot: Path) -> List[Mapping]:
    shared_objects = []
    for mapping in mappings:
        if not mapping.path.startswith("/"):
            continue
        binary = sysroot.joinpath(str(mapping.path)[1:])
        if not binary.exists():
            continue

        with open(binary, "rb") as f:
            magic = f.read(len(ELF_MAGIC))
            if magic != ELF_MAGIC:
                continue

        shared_object = copy.copy(mapping)
        shared_object.name = str(binary)
        shared_objects.append(shared_object)
    return shared_objects


class Loader:
    def __init__(self, mappings: List[Mapping], sysroot: Path):
        self.shared_objects = filter_mappings(mappings, sysroot)

    def load_options(self) -> Dict[str, Any]:
        """
        Extract shared object memory mapping from coredump
        """
        main = self.shared_objects[0]
        lib_opts: Dict[str, Dict[str, int]] = {}
        force_load_libs = []
        for m in self.shared_objects[1:]:
            if m.path in lib_opts:
                continue
            lib_opts[m.path] = dict(custom_base_addr=m.start)
            force_load_libs.append(m.path)

        return dict(
            main_opts={"custom_base_addr": main.start},
            force_load_libs=force_load_libs,
            lib_opts=lib_opts,
            load_options={"except_missing_libs": True},
        )
