from __future__ import absolute_import, division, print_function

import argparse
import subprocess
import json
import shutil
import sys
from typing import List, Any, Dict
from .pwn_wrapper import Coredump

from .symbex.tracer import Tracer, State, StateManager
from .mapping import Mapping
from .path import Tempdir
from . import pt


def decode_trace(manifest, mappings, vdso_x64, executable_root):
    # type: (Dict[str, Any], List[Mapping], str, str) -> List[pt.Instruction]
    trace_per_cpu = []

    coredump = manifest["coredump"]
    trace = manifest["trace"]

    for cpu in trace["cpus"]:
        trace_per_cpu.append((cpu["event_path"], cpu["trace_path"]))

    return pt.decode(
        trace_per_cpu=trace_per_cpu,
        mappings=mappings,
        exec_wrapper=manifest["exec_wrapper"],
        pid=coredump["global_pid"],
        tid=coredump["global_tid"],
        cpu_family=trace["cpu_family"],
        cpu_model=trace["cpu_model"],
        cpu_stepping=trace["cpu_stepping"],
        cpuid_0x15_eax=trace["cpuid_0x15_eax"],
        cpuid_0x15_ebx=trace["cpuid_0x15_ebx"],
        time_zero=trace["time_zero"],
        time_shift=trace["time_shift"],
        time_mult=trace["time_mult"],
        sample_type=trace["sample_type"],
        sysroot=executable_root,
        vdso_x64=vdso_x64)


class Replay(object):
    def __init__(self, report):
        # type: (str) -> None
        self.report = report
        self.tempdir = Tempdir()

    def __enter__(self):
        # type: () -> Replay
        self.prepare_tracer()
        return self

    def __exit__(self, type, value, traceback):
        self.cleanup()

    def prepare_tracer(self):
        # type: () -> None
        manifest = self.unpack()


        coredump = Coredump(manifest["coredump"]["file"])

        vdso_x64 = self.tempdir.join("vdso")

        with open(str(vdso_x64), "w+") as f:
            f.write(coredump.vdso.data)

        binaries = self.tempdir.join("binaries")
        trace = decode_trace(manifest, coredump.mappings, str(vdso_x64), str(binaries))

        for obj in coredump.mappings:
            binary = binaries.join(obj.path)
            if not binary.exists():
                continue
            obj.name = str(binary)

        self.tracer = Tracer(coredump["coredump"]["executable"], trace,
                             coredump)

    def run(self):
        # type: () -> StateManager
        if not self.tracer:
            self.prepare_tracer()
        return self.tracer.run()

    def cleanup(self):
        # type: () -> None
        shutil.rmtree(str(self.tempdir))

    def unpack(self):
        # type: () -> Dict[str, Any]
        archive_root = self.tempdir
        subprocess.check_call(
            ["tar", "-xzf", self.report, "-C",
             str(archive_root)])

        manifest_path = archive_root.join("manifest.json")
        with open(str(manifest_path)) as f:
            manifest = json.load(f)

        for cpu in manifest['trace']['cpus']:
            cpu["event_path"] = str(archive_root.join(cpu["event_path"]))
            cpu["trace_path"] = str(archive_root.join(cpu["trace_path"]))

        coredump = manifest["coredump"]
        coredump["executable"] = str(archive_root.join(coredump["executable"]))
        coredump["file"] = str(archive_root.join(coredump["file"]))
        manifest["exec_wrapper"] = str(archive_root.join(manifest["exec_wrapper"]))

        return manifest


def replay_trace(report):
    # type: (str) -> Replay
    return Replay(report)


def replay_command(args):
    # type: (argparse.Namespace) -> StateManager
    with replay_trace(args.report) as rt:
        return rt.run()


def unpack_command(args):
    manifest = Replay(args.report).unpack()
    json.dump(manifest, sys.stdout, sort_keys=True, indent=4)
