import copy
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from angr import Project
import cle
from cle.backends.externs import KernelObject

from .pwn_wrapper import Coredump, Mapping

ELF_MAGIC = b"\x7fELF"
PERM_EXEC = 1
PERM_WRITE = 2
PERM_READ = 4


def filter_mappings(mappings: List[Mapping], sysroot: Path) -> List[Mapping]:
    shared_objects = []
    for mapping in mappings:
        if not mapping.path.startswith("/"):
            continue
        binary = sysroot.joinpath(str(mapping.path)[1:])
        if not binary.exists():
            continue

        with open(str(binary), "rb") as f:
            magic = f.read(len(ELF_MAGIC))
            if magic != ELF_MAGIC:
                continue

        shared_object = copy.copy(mapping)
        shared_object.name = str(binary)
        shared_objects.append(shared_object)
    return shared_objects


def find_vdso(mappings: List[Mapping], vdso: Path) -> Mapping:
    for mapping in mappings:
        if mapping.path == "[vdso]":
            mapping.name = str(vdso)
            return mapping
    raise Exception("vdso not found")


class Loader:
    def __init__(
        self, executable: str, mappings: List[Mapping], sysroot: Path, vdso_x64: Path
    ):
        shared_objects = filter_mappings(mappings, sysroot)
        self.vdso = find_vdso(mappings, vdso_x64)
        self.executable = shared_objects[0]
        assert self.executable.name == executable

        self.libraries = []  # type: List[Mapping]
        seen = set() # type: Set[str]
        for m in shared_objects[1:]:
            # the linker puts libraries with executable bit first,
            # we ignore other mmaps as those might be loaded by other
            # libraries such as libasan
            if m.path in seen or (m.flags & PERM_EXEC) == 0:
                continue
            self.libraries.append(m)
            seen.add(m.path)

    def find_mapping(self, ip: int) -> Optional[Mapping]:
        for mapping in self.libraries:
            if mapping.start <= ip < mapping.stop:
                return mapping
        if self.vdso.start <= ip < self.vdso.stop:
            return self.vdso
        if self.executable.start <= ip < self.executable.stop:
            return self.executable
        return None

    def find_location(self, ip: int) -> str:
        mapping = self.find_mapping(ip)
        if mapping is None:
            return "0x{:x} (umapped)".format(ip)
        else:
            offset = ip - mapping.start + mapping.page_offset * 4096
            return "0x{:x} ({}+{})".format(ip, mapping.name, offset)

    def radare2(self, ip: int) -> None:
        mapping = self.find_mapping(ip)
        if mapping is None:
            print("Could not mapped code for memory")
            return
        if mapping.name != self.executable:
            ip = ip - mapping.start + mapping.page_offset * 4096
        cmd = ["r2", "-s", str(ip), mapping.name]

        assert ip > 0
        print(" ".join(cmd))
        subprocess.run(cmd)

    def create_vdso(self, loader: cle.Loader) -> KernelObject:
        elf = cle.ELF(self.vdso.path, loader=loader)
        kobject = KernelObject(loader=loader, map_size=self.vdso.stop - self.vdso.start)
        kobject.memory = elf.memory
        kobject._custom_base_addr = self.vdso.start
        return kobject

    def cle_loader(self) -> cle.Loader:
        force_load_libs = []
        lib_opts = {}  # type: Dict[str, Dict[str, int]]
        for m in self.libraries:
            lib_opts[m.path] = dict(base_addr=m.start)
            force_load_libs.append(m.path)

        loader = cle.Loader(self.executable.name,
                            main_opts=dict(base_addr=self.executable.start),
                            use_system_libs=False,
                            auto_load_libs=False,
                            force_load_libs=force_load_libs,
                            except_missing_libs=True,
                            lib_opts=lib_opts)
        loader._kernel_object = self.create_vdso(loader)
        loader._map_object(loader._kernel_object)
        return loader

    def angr_project(self) -> Project:
        return Project(self.cle_loader())
