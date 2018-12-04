import argparse
import json
import logging
import os
import resource
import shutil
import subprocess
import time
from contextlib import ExitStack
from pathlib import Path
from signal import SIGUSR2
from tempfile import NamedTemporaryFile, TemporaryDirectory
from types import FrameType
from typing import IO, Any, Dict, List, Optional, Tuple, Union

from .. import pwn_wrapper
from ..perf import IncreasePerfBuffer, Perf, Trace
from .coredumps import Coredump, Handler
from .ptrace import ptrace_detach, ptrace_me
from .signal_handler import SignalHandler

l = logging.getLogger(__name__)

DEFAULT_LOG_DIR = Path("/var/lib/hase")

PROT_EXEC = 4


class TimeoutExpired(Exception):
    pass


class Recording:
    def __init__(
        self,
        coredump: Optional[Coredump],
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


class RecordProcess(ExitStack):
    def __init__(self, pid: int, record_paths: "RecordPaths"):
        super().__init__()
        self._coredump_handler = Handler(
            str(record_paths.coredump),
            str(record_paths.fifo),
            str(record_paths.manifest),
            log_path=str(record_paths.log_path.joinpath("coredump.log")),
        )
        self._increase_buffer = IncreasePerfBuffer(100 * 1024)
        self._perf = Perf(pid)
        self._signal_handler = SignalHandler(SIGUSR2, self.received_coredump)

        # work around missing nonlocal keyword in python2 with a list
        self._got_coredump = [False]
        self._record_paths = record_paths

    def received_coredump(self, signum: int, frame_type: FrameType) -> None:
        self._got_coredump[0] = True

    def __enter__(self) -> "RecordProcess":
        super().__enter__()
        self._coredump = self.enter_context(self._coredump_handler)
        self.enter_context(self._increase_buffer)
        self.enter_context(self._signal_handler)
        self.enter_context(self._perf)
        write_pid_file(self._record_paths.pid_file)
        return self

    def result(self) -> Tuple[Optional[Coredump], Trace]:
        if not self._got_coredump[0]:
            coredump = None
        else:
            coredump = self._coredump

        self._record_paths.perf_directory.mkdir(parents=True, exist_ok=True)
        trace = self._perf.write(str(self._record_paths.perf_directory))

        return (coredump, trace)


def record_child_pid(
    pid: int, record_paths: "RecordPaths", timeout: Optional[int] = None
) -> Recording:

    if timeout is None:
        options = 0
    else:
        options = os.WNOHANG

    record = RecordProcess(pid, record_paths)

    with record:
        ptrace_detach(pid)
        start = time.time()

        while True:
            pid, exit_code, rusage = os.wait4(pid, options)
            if pid != 0:
                break
            elif timeout is not None and time.time() - start <= 0:
                raise TimeoutExpired(f"process did not finish within {timeout} seconds")
            time.sleep(0.10)
        coredump, trace = record.result()
        return Recording(coredump, trace, exit_code, rusage)


def record_other_pid(pid: int, record_paths: "RecordPaths") -> Recording:
    record = RecordProcess(pid, record_paths)
    with record:
        print("recording started")
        while True:
            try:
                os.kill(pid, 0)
                time.sleep(0.10)
            except OSError:
                break
            except KeyboardInterrupt:
                break
        coredump, trace = record.result()
        return Recording(coredump, trace, 0, None)


def _record(
    record_paths: "RecordPaths",
    target: Union[List[str], int],
    stdin: Optional[IO[Any]] = None,
    stdout: Optional[IO[Any]] = None,
    stderr: Optional[IO[Any]] = None,
    working_directory: Optional[Path] = None,
    timeout: Optional[int] = None,
    extra_env: Optional[Dict[str, str]] = None,
) -> Recording:

    env = None
    if extra_env is not None:
        env = os.environ.copy()
        env.update(extra_env)

    if isinstance(target, list):
        proc = subprocess.Popen(
            target,
            preexec_fn=ptrace_me,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            cwd=working_directory,
            env=extra_env,
        )
        return record_child_pid(proc.pid, record_paths, timeout)
    else:
        return record_other_pid(target, record_paths)

def write_pid_file(pid_file: Optional[str]) -> None:
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
    def __init__(self, path: Path, log_path: Path, pid_file: Optional[str]) -> None:
        self.path = path
        self.log_path = log_path
        self.pid_file = pid_file

        self.state_dir = self.path
        self.perf_directory = self.path.joinpath("traces")
        self.coredump = self.path.joinpath("core")

        self.fifo = self.path.joinpath("fifo")
        self.manifest = self.path.joinpath("manifest.json")

    def report_archive(self, executable: str, timestamp: str) -> Path:
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

        def append(path: str) -> None:
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
    target: Union[List[str], int],
    pid_file: Optional[str] = None,
    limit: int = 0,
    stdin: Optional[IO[Any]] = None,
    stdout: Optional[IO[Any]] = None,
    stderr: Optional[IO[Any]] = None,
    working_directory: Optional[Path] = None,
    timeout: Optional[int] = None,
    extra_env: Optional[Dict[str, str]] = None,
) -> Optional[Recording]:
    try:
        record_paths = RecordPaths(record_path, log_path, pid_file)
        recording = _record(
            record_paths,
            target,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            working_directory=working_directory,
            timeout=timeout,
            extra_env=extra_env,
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
            target=command,
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
