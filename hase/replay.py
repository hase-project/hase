from __future__ import absolute_import, division, print_function

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Tuple

from .gdb import GdbServer
from .loader import Loader
from .pt.decode import decode
from .pt.events import Instruction
from .pwn_wrapper import Coredump
from .symbex.cdconstraint import general_apply
from .symbex.evaluate import report_variable
from .symbex.tracer import State, StateManager, Tracer

l = logging.getLogger(__name__)


def decode_trace(
    manifest: Dict[str, Any], loader: Loader, vdso_x64: str
) -> List[Instruction]:
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

    return decode(
        trace_paths=trace_paths,
        perf_event_paths=perf_event_paths,
        start_thread_ids=start_thread_ids,
        start_times=start_times,
        loader=loader,
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
        vdso_x64=vdso_x64,
    )


def unpack(report: str, archive_root: Path) -> Dict[str, Any]:
    subprocess.check_call(["tar", "-xzf", report, "-C", str(archive_root)])

    manifest_path = archive_root.joinpath("manifest.json")
    with open(str(manifest_path)) as f:
        manifest = json.load(f)

    for cpu in manifest["trace"]["cpus"]:
        cpu["event_path"] = str(archive_root.joinpath(cpu["event_path"]))
        cpu["trace_path"] = str(archive_root.joinpath(cpu["trace_path"]))

    coredump = manifest["coredump"]
    coredump["executable"] = str(archive_root.joinpath(coredump["executable"]))
    coredump["file"] = str(archive_root.joinpath(coredump["file"]))

    return manifest


def create_tracer(report: str, archive_root: Path) -> Tracer:
    manifest = unpack(report, archive_root)

    coredump = Coredump(manifest["coredump"]["file"])
    vdso_x64 = archive_root.joinpath("vdso")

    with open(str(vdso_x64), "wb+") as f:
        f.write(coredump.vdso.data)
    sysroot = archive_root.joinpath("binaries")
    loader = Loader(coredump.mappings, sysroot)
    trace = decode_trace(manifest, loader, str(vdso_x64))

    executable = manifest["coredump"]["executable"]
    return Tracer(executable, trace, coredump, loader.load_options())


class Replay:
    def __init__(self, report: str) -> None:
        self.report = report
        self._tempdir = TemporaryDirectory()
        self.tempdir = Path(self._tempdir.name)

    def __enter__(self) -> "Replay":
        self.tracer = create_tracer(self.report, self.tempdir)
        return self

    def __exit__(self, type, value, traceback):
        self.cleanup()

    @property
    def executable(self) -> str:
        return self.tracer.executable

    def run(self) -> Tuple[StateManager, List[Any]]:
        if self.tracer is None:
            self.tracer = create_tracer(self.report, self.tempdir)
        states = self.tracer.run()
        final_state = states.major_states[-1].simstate
        assert final_state is not None
        return states, []

    def cleanup(self) -> None:
        self._tempdir.cleanup()


def replay_trace(report: str) -> Replay:
    return Replay(report)


def replay_command(args: argparse.Namespace, debug_cli: bool = True) -> StateManager:
    with replay_trace(args.report) as rt:
        states, constraints = rt.run()
        if debug_cli:
            if (
                states.major_states[-1].simstate.reg_concrete("rsp")
                == rt.tracer.coredump.registers["rsp"]
            ):
                general_apply(rt.tracer, states)
            gdbs = GdbServer(
                states,
                rt.tracer.executable,
                rt.tracer.cdanalyzer,
                states.major_states[-1],
            )
            assert states.last_main_state is not None
            gdbs.active_state = states.last_main_state
            gdbs.update_active()

            import pry

            pry()
        return states


def unpack_command(args):
    replay = Replay(args.report)
    manifest = replay.unpack()
    json.dump(manifest, sys.stdout, sort_keys=True, indent=4)
