from __future__ import absolute_import, division, print_function

import argparse
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Tuple

from .gdb import GdbServer
from .pt import decode
from .pt.events import Instruction
from .pwn_wrapper import Coredump, Mapping
from .symbex.tracer import State, StateManager, Tracer


def decode_trace(
    manifest: Dict[str, Any],
    mappings: List[Mapping],
    vdso_x64: str,
    executable_root: str,
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
        vdso_x64=vdso_x64,
    )


class Replay(object):
    def __init__(self, report):
        # type: (str) -> None
        self.report = report
        self._tempdir = TemporaryDirectory()
        self.tempdir = Path(self._tempdir.name)

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
        vdso_x64 = self.tempdir.joinpath("vdso")

        with open(str(vdso_x64), "wb+") as f:
            f.write(coredump.vdso.data)

        binaries = self.tempdir.joinpath("binaries")
        trace = decode_trace(manifest, coredump.mappings, str(vdso_x64), str(binaries))

        for obj in coredump.mappings:
            if not obj.path.startswith("/"):
                continue
            binary = binaries.joinpath(str(obj.path)[1:])
            if not binary.exists():
                continue
            obj.name = str(binary)

        self.executable = manifest["coredump"]["executable"]
        self.tracer = Tracer(self.executable, trace, coredump)

    def run(self) -> Tuple[StateManager, List[Any]]:
        if not self.tracer:
            self.prepare_tracer()
        states = self.tracer.run()
        start_state = self.tracer.start_state
        active_state = states.major_states[-1]
        coredump = self.tracer.coredump
        arip = active_state.simstate.regs.rip
        crip = hex(coredump.registers["rip"])
        arsp = active_state.simstate.regs.rsp
        crsp = hex(coredump.registers["rsp"])
        import logging

        l = logging.getLogger("hase")
        l.warning(f"{arip} {crip} {arsp} {crsp}")
        low = active_state.simstate.regs.rsp
        high = start_state.regs.rsp
        try:
            low_v = active_state.simstate.solver.eval(low)
        except Exception:
            low_v = coredump.stack.start
        try:
            high_v = start_state.solver.eval(high)
        except Exception:
            high_v = coredump.stack.stop
        coredump_constraints: List[Any] = []
        """
        for addr in range(low_v, high_v):
            value = active_state.simstate.memory.load(addr, 1, endness="Iend_LE")
            if value.variables == frozenset():
                continue
            cmem = coredump.stack[addr]
            coredump_constraints.append(value == cmem)
        """
        return states, coredump_constraints

    def cleanup(self):
        # type: () -> None
        self._tempdir.cleanup()

    def unpack(self):
        # type: () -> Dict[str, Any]
        archive_root = self.tempdir
        subprocess.check_call(["tar", "-xzf", self.report, "-C", str(archive_root)])

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


def replay_trace(report: str) -> Replay:
    return Replay(report)


def replay_command(args: argparse.Namespace, debug_cli: bool = False) -> StateManager:
    with replay_trace(args.report) as rt:
        states, constraints = rt.run()
        if debug_cli:
            gdbs = GdbServer(
                states,
                rt.tracer.executable,
                rt.tracer.cdanalyzer,
                states.major_states[-1],
            )

            def add_constraint(state: State) -> None:
                active_state = state.simstate
                if not getattr(active_state, "had_coredump_constraints", False):
                    for c in constraints:
                        old_solver = active_state.simstate.solver._solver.branch()
                        active_state.simstate.se.add(c)
                        if not active_state.simstate.se.satisfiable():
                            print("Unsatisfiable coredump constraints: " + str(c))
                            active_state.simstate.solver._stored_solver = old_solver
                    active_state.had_coredump_constraints = True

            import pry

            pry()
        return states


def unpack_command(args):
    manifest = Replay(args.report).unpack()
    json.dump(manifest, sys.stdout, sort_keys=True, indent=4)
