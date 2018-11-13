from __future__ import absolute_import, division, print_function

import argparse
import errno
import fcntl
import json
import logging
import os
import resource
import shutil
import subprocess
from pathlib import Path
from queue import Queue
from signal import SIGUSR2
from tempfile import NamedTemporaryFile, TemporaryDirectory
from threading import Condition, Thread
from types import FrameType
from typing import IO, Any, Dict, List, Optional, Tuple, Union

from . import coredumps
from .. import pwn_wrapper
from ..errors import HaseError
from ..path import APP_ROOT
from ..perf import IncreasePerfBuffer, Perf, Trace
from .ptrace import ptrace_detach, ptrace_me
from .signal_handler import SignalHandler

l = logging.getLogger(__name__)

DEFAULT_LOG_DIR = Path("/var/lib/hase")

PROT_EXEC = 4


class Recording:
    def __init__(
        self,
        coredump: Optional[coredumps.Coredump],
        trace: Trace,
        exit_status: int,
        rusage: Optional[Tuple[Any, ...]] = None,
    ) -> None:
        self.coredump = coredump
        self.trace = trace
        self.exit_status = exit_status
        self.rusage = rusage
        # set by the report_worker atm, should be refactored
        self.report_path: Optional[str] = None


def record_process(
    process: subprocess.Popen,
    record_paths: "RecordPaths",
    timeout: Optional[int] = None,
    rusage: bool = False,
) -> Recording:
    handler = coredumps.Handler(
        str(record_paths.coredump),
        str(record_paths.fifo),
        str(record_paths.manifest),
        log_path=str(record_paths.log_path.joinpath("coredump.log")),
    )

    # work around missing nonlocal keyword in python2 with a list
    got_coredump = [False]

    def received_coredump(signum, frame_type):
        # type: (int, FrameType) -> None
        got_coredump[0] = True

    with IncreasePerfBuffer(100 * 1024), Perf(
        process.pid
    ) as perf, handler as _coredump, SignalHandler(SIGUSR2, received_coredump):
        write_pid_file(record_paths.pid_file)

        ptrace_detach(process.pid)
        rusage_result = None
        if rusage is not None:
            _, exit_code, _rusage = os.wait4(process.pid, 0)
            rusage_result = tuple(_rusage)
        else:
            exit_code = process.wait(timeout)

        if not got_coredump[0]:
            coredump = None
        else:
            coredump = _coredump

        record_paths.perf_directory.mkdir(parents=True, exist_ok=True)
        trace = perf.write(str(record_paths.perf_directory))

        return Recording(coredump, trace, exit_code, rusage_result)


def _record(
    record_paths: "RecordPaths",
    command: List[str],
    stdin: Optional[IO[Any]] = None,
    stdout: Optional[IO[Any]] = None,
    stderr: Optional[IO[Any]] = None,
    working_directory: Optional[Path] = None,
    timeout: Optional[int] = None,
    extra_env: Optional[Dict[str, str]] = None,
    rusage: bool = False,
) -> Recording:

    env = None
    if extra_env is not None:
        env = os.environ.copy()
        env.update(extra_env)

    proc = subprocess.Popen(
        command,
        preexec_fn=ptrace_me,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        cwd=working_directory,
        env=extra_env,
    )
    return record_process(proc, record_paths, timeout, rusage=rusage)


def write_pid_file(pid_file):
    # type: (Optional[str]) -> None
    if pid_file is not None:
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))


class ExitEvent:
    pass


class Job:
    def __init__(self, recording: Recording, record_paths: "RecordPaths") -> None:
        self.recording = recording
        self.record_paths = record_paths

    def core_file(self) -> Optional[str]:
        if self.recording.coredump is None:
            return None
        else:
            return self.recording.coredump.get()

    def remove(self) -> None:
        try:
            if self.recording.coredump is not None:
                self.recording.coredump.remove()
        except OSError:
            pass

        shutil.rmtree(str(self.record_paths.perf_directory), ignore_errors=True)


class RecordPaths:
    def __init__(self, path, id, log_path, pid_file):
        # type: (Path, int, Path, Optional[str]) -> None
        self.path = path
        self.log_path = log_path
        self.pid_file = pid_file
        self.id = id

        self.state_dir = self.path
        self.perf_directory = self.path.joinpath("traces-%d" % self.id)
        self.coredump = self.path.joinpath("core.%d" % self.id)

        self.fifo = self.path.joinpath("fifo.%d" % self.id)
        self.manifest = self.path.joinpath("manifest.json")

    def report_archive(self, executable, timestamp):
        # type: (str, str) -> Path
        return self.log_path.joinpath(
            "%s-%s.tar.gz" % (os.path.basename(executable), timestamp)
        )


def serialize_trace(trace: Trace, state_dir: Path) -> Dict[str, Any]:
    cpus = []
    for cpu in trace.cpus:
        event_path = str(Path(cpu.event_path).relative_to(state_dir))
        trace_path = str(Path(cpu.trace_path).relative_to(state_dir))

        c = dict(
            idx=cpu.idx,
            event_path=event_path,
            trace_path=trace_path,
            start_time=cpu.start_time,
            start_pid=cpu.start_pid,
            start_tid=cpu.start_tid,
        )
        cpus.append(c)

    return dict(
        cpus=cpus,
        time_mult=trace.time_mult,
        time_shift=trace.time_shift,
        time_zero=trace.time_zero,
        sample_type=trace.sample_type,
        cpu_family=trace.cpu_family,
        cpu_model=trace.cpu_model,
        cpu_stepping=trace.cpu_stepping,
        cpuid_0x15_eax=trace.cpuid_0x15_eax,
        cpuid_0x15_ebx=trace.cpuid_0x15_ebx,
    )


def store_report(recording: Recording, record_paths: "RecordPaths") -> str:
    assert recording.coredump is not None
    core_file = recording.coredump.get()
    state_dir = record_paths.state_dir
    manifest_path = str(record_paths.manifest)

    with NamedTemporaryFile() as template:

        def append(path):
            # type: (str) -> None
            template.write(str(Path(path).relative_to(state_dir)).encode("utf-8"))
            template.write(b"\0")

        append(manifest_path)

        if Path(manifest_path).exists():
            manifest = json.load(open(manifest_path))
        else:
            manifest = {}

        binaries = manifest["binaries"] = []

        paths = set()
        for obj in pwn_wrapper.Coredump(str(core_file)).mappings:
            if (
                (obj.flags & PROT_EXEC)
                and obj.path.startswith("/")
                and os.path.exists(obj.path)
            ):
                paths.add(obj.path)

        for path in paths:
            # FIXME check if elf, only create parent directory once
            archive_path = state_dir.joinpath("binaries", path[1:])
            archive_path.parent.mkdir(parents=True, exist_ok=True)

            shutil.copyfile(path, str(archive_path))

            binaries.append(str(archive_path.relative_to(state_dir)))
            append(str(archive_path))

        if core_file is not None:
            coredump = manifest["coredump"]
            coredump["executable"] = os.path.join("binaries", coredump["executable"])
            coredump["file"] = str(Path(core_file).relative_to(state_dir))
            append(core_file)

        trace = serialize_trace(recording.trace, state_dir)

        for cpu in trace["cpus"]:
            append(str(state_dir.joinpath(cpu["event_path"])))
            append(str(state_dir.joinpath(cpu["trace_path"])))

        manifest["trace"] = trace

        with open(manifest_path, "w") as manifest_file:
            json.dump(manifest, manifest_file, indent=4)

        template.flush()

        archive_path = record_paths.report_archive(
            coredump["executable"], coredump["time"]
        )

        l.info("creating archive %s", archive_path)
        subprocess.check_call(
            [
                "tar",
                "--null",
                "-C",
                str(record_paths.state_dir),
                "-T",
                str(template.name),
                "-czf",
                str(archive_path),
            ]
        )
        l.info("built archive %s", archive_path)
        os.unlink(manifest_path)
        return str(archive_path)


def record(
    record_path: Path,
    log_path: Path,
    command: List[str],
    pid_file: Optional[str] = None,
    limit: int = 0,
    stdin: Optional[IO[Any]] = None,
    stdout: Optional[IO[Any]] = None,
    stderr: Optional[IO[Any]] = None,
    working_directory: Optional[Path] = None,
    timeout: Optional[int] = None,
    extra_env: Optional[Dict[str, str]] = None,
    rusage: bool = True,
) -> Optional[Recording]:
    try:
        i = 1
        record_paths = RecordPaths(record_path, i, log_path, pid_file)
        recording = _record(
            record_paths,
            command,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            working_directory=working_directory,
            timeout=timeout,
            extra_env=extra_env,
            rusage=rusage,
        )
        if recording.coredump is None:
            return recording
        recording.report_path = store_report(recording, record_paths)

        return recording
    except KeyboardInterrupt:
        pass
    finally:
        l.info("execution was interrupted by user")

    return None


def record_command(args: argparse.Namespace) -> None:

    log_path = Path(args.log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(filename=str(log_path.joinpath("hase.log")), level=logging.INFO)

    command = args.args

    with TemporaryDirectory() as tempdir:
        record(
            command=command,
            record_path=Path(tempdir),
            log_path=log_path,
            pid_file=args.pid_file,
            limit=args.limit,
        )

    if args.rusage_file is not None:
        usage = tuple(resource.getrusage(resource.RUSAGE_CHILDREN))
        with open(args.rusage_file, "w") as usage_file:
            usage_file.write(", ".join([str(x) for x in usage]))
            usage_file.write("\n")
