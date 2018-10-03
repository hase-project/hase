from __future__ import absolute_import, division, print_function

import argparse
import subprocess
import json
import shutil
import sys
from typing import List, Any, Dict
from .pwn_wrapper import Coredump, Mapping

from .symbex.tracer import Tracer, State, StateManager
from .path import Tempdir
from . import pt


def decode_trace(manifest, mappings, vdso_x64, executable_root):
    # type: (Dict[str, Any], List[Mapping], str, str) -> List[pt.events.Instruction]
    coredump = manifest["coredump"]
    trace = manifest["trace"]

    trace_paths = []
    perf_event_paths = []
    start_thread_ids = []
    start_times = []

    pid = coredump["global_pid"]
    tid = coredump["global_tid"]

    for cpu in trace["cpus"]:
        assert pid == cpu["start_pid"], "only one pid is allowed at the moment"
        trace_paths.append(cpu["trace_path"])
        perf_event_paths.append(cpu["event_path"])
        start_thread_ids.append(cpu["start_tid"])
        start_times.append(cpu["start_time"])

    return pt.decode(
        trace_paths=trace_paths,
        perf_event_paths=perf_event_paths,
        start_thread_ids=start_thread_ids,
        start_times=start_times,
        mappings=mappings,
        pid=pid,
        tid=tid,
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
            if obj.path == "":
                continue
            binary = binaries.join(obj.path)
            if not binary.exists():
                continue
            obj.name = str(binary)

        self.executable = manifest["coredump"]["executable"]
        self.tracer = Tracer(self.executable, trace, coredump)

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
