import copy
from pathlib import Path
from typing import Any, Dict, List, Optional

from .pwn_wrapper import ELF, Coredump, Mapping

ELF_MAGIC = b"\x7fELF"
PERM_EXEC = 1
PERM_WRITE = 2
PERM_READ = 4


def filter_mappings(
    mappings: List[Mapping], sysroot: Path, vdso: Path
) -> List[Mapping]:
    shared_objects = []
    for mapping in mappings:
        if mapping.path == "[vdso]":
            binary = vdso
        elif not mapping.path.startswith("/"):
            continue
        else:
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
    def __init__(self, mappings: List[Mapping], sysroot: Path, vdso_x64: Path):
        self.shared_objects = filter_mappings(mappings, sysroot, vdso_x64)

    def find_mapping(self, ip: int) -> Optional[Mapping]:
        for mapping in self.shared_objects:
            if mapping.start <= ip and ip < mapping.stop:
                return mapping
        return None

    def find_location(self, ip: int) -> str:
        mapping = self.find_mapping(ip)
        if mapping is None:
            return "0x{:x} (umapped)".format(ip)
        else:
            offset = ip - mapping.start + mapping.page_offset * 4096
            return "0x{:x} ({}+{})".format(ip, mapping.name, offset)

    def load_options(self) -> Dict[str, Any]:
        """
        Extract shared object memory mapping from coredump
        """
        main = self.shared_objects[0]
        lib_opts: Dict[str, Dict[str, int]] = {}
        force_load_libs = []
        for m in self.shared_objects[1:]:
            # the linker puts libraries with executable bit first,
            # we ignore other mmaps as those might be loaded by other
            # libraries such as libasan
            if m.path in lib_opts or (m.flags & PERM_EXEC) == 0:
                continue
            lib_opts[m.path] = dict(base_addr=m.start)
            force_load_libs.append(m.path)

        return dict(
            main_opts=dict(base_addr=main.start),
            use_system_libs=False,
            auto_load_libs=False,
            force_load_libs=force_load_libs,
            lib_opts=lib_opts,
            load_options=dict(except_missing_libs=True),
        )
