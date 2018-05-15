from __future__ import absolute_import, division, print_function

import shutil
import json
from tempfile import NamedTemporaryFile
from threading import Thread
import subprocess
import logging
from Queue import Queue
import os
import argparse  # NOQA
from types import FrameType
from signal import SIGUSR2
from typing import Optional, IO, Any, Tuple, List

from . import coredumps, processor_trace
from ..path import Path, Tempdir
from ..mapping import Mapping
from .signal_handler import SignalHandler
from .. import pwn_wrapper
from .perf_record import PerfData, PTSnapshot, IncreasePerfBuffer

l = logging.getLogger(__name__)

DEFAULT_LOG_DIR = Path("/var/lib/hase")

PROT_EXEC = 4


def record(record_paths, command=None):
    # type: (RecordPaths, Optional[List[str]]) -> Optional[Tuple[coredumps.Coredump, PerfData]]

    with PTSnapshot(perf_file=str(record_paths.perf), command=command) as snapshot:
        handler = coredumps.Handler(
            snapshot.perf_pid,
            str(record_paths.coredump),
            str(record_paths.fifo),
            str(record_paths.manifest),
            log_path=str(record_paths.log_path.join("coredump.log")))

        # work around missing nonlocal keyword in python2 with a list
        got_coredump = [False]

        def received_coredump(signum, frame_type):
            # Type (int FrameType) -> None
            # Relying on receiving the SIGUSR2 in time is potentially buggy,
            # since we sent the signal first to perf. This is however not very
            # likely. In the worst case this will make us miss events.
            got_coredump[0] = True

        with handler as coredump, \
                IncreasePerfBuffer(100 * 1024), \
                SignalHandler(SIGUSR2, received_coredump):
            if record_paths.pid_file is not None:
                with open(record_paths.pid_file, "w") as f:
                    f.write(str(os.getpid()))
            c = coredump  # type: coredumps.Coredump
            perf_data = snapshot.get()
            if got_coredump[0]:
                return (c, perf_data)
            else:
                return None


class Job(object):
    def __init__(
            self,
            coredump=None,  # type: Optional[coredumps.Coredump]
            perf_data=None,  # type: Optional[PerfData]
            record_paths=None,  # type: Optional[RecordPaths]
            exit=False  # type: bool
    ):
        # type: (...) -> None
        self.coredump = coredump
        self._perf_data = perf_data
        self._record_paths = record_paths
        self.exit = exit

    @property
    def perf_data(self):
        # type: () -> PerfData
        assert self._perf_data is not None
        return self._perf_data

    @property
    def record_paths(self):
        # type: () -> RecordPaths
        assert self._record_paths is not None
        return self._record_paths

    def core_file(self):
        # type: () -> str
        assert self.coredump is not None
        return self.coredump.get()

    def remove(self):
        # type: () -> None
        try:
            if self.coredump:
                l.info("remove coredump %s", self.coredump.fifo_path)
                self.coredump.remove()
        except OSError:
            pass

        try:
            if self.perf_data:
                self.perf_data.remove()
        except OSError:
            pass


class RecordPaths(object):
    def __init__(self, path, id, log_path, pid_file):
        # type: (Path, int, Path, Optional[str]) -> None
        self.path = path
        self.log_path = log_path
        self.pid_file = pid_file
        self.id = id

    @property
    def state_dir(self):
        # type: () -> Path
        return self.path

    @property
    def perf(self):
        # type: () -> Path
        return self.path.join("perf.data.%d" % self.id)

    @property
    def coredump(self):
        # type: () -> Path
        return self.path.join("core.%d" % self.id)

    @property
    def fifo(self):
        # type: () -> Path
        return self.path.join("fifo.%d" % self.id)

    @property
    def manifest(self):
        # type: () -> Path
        return self.path.join("manifest.json")

    def report_archive(self, executable, timestamp):
        # type: (str, str) -> Path
        return self.log_path.join("%s-%s.tar.gz" %
                                  (os.path.basename(executable), timestamp))


def store_report(job):
    # type: (Job) -> None
    core_file = job.core_file()
    record_paths = job.record_paths
    state_dir = record_paths.state_dir
    manifest_path = str(record_paths.manifest)

    with NamedTemporaryFile() as template:

        def append(path):
            # type: (str) -> None
            template.write(str(state_dir.relpath(path)))
            template.write("\0")

        append(manifest_path)

        manifest = json.load(open(manifest_path))
        mappings = manifest["mappings"] = []
        binaries = manifest["binaries"] = []

        paths = set()
        for obj in pwn_wrapper.Coredump(str(core_file)).mappings:
            path = obj.path
            if (obj.flags & PROT_EXEC
                ) and path.startswith("/") and os.path.exists(path):
                paths.add(path)
                path = os.path.join("binaries", path[1:])

            mappings.append(
                vars(
                    Mapping(
                        start=obj.start,
                        stop=obj.stop,
                        path=path,
                        flags=obj.flags)))

        for path in paths:
            # FIXME check if elf, only create parent directory once
            archive_path = state_dir.join("binaries", path[1:])
            archive_path.dirname().mkdir_p()

            shutil.copyfile(path, str(archive_path))

            binaries.append(str(state_dir.relpath(str(archive_path))))
            append(str(archive_path))

        coredump = manifest["coredump"]
        coredump["executable"] = os.path.join("binaries",
                                              coredump["executable"])
        coredump["file"] = str(state_dir.relpath(core_file))
        append(core_file)

        manifest["perf_data"] = str(state_dir.relpath(job.perf_data.path))
        append(job.perf_data.path)

        with open(manifest_path, "w") as manifest_file:
            json.dump(manifest, manifest_file, indent=4)

        template.flush()

        archive_path = record_paths.report_archive(coredump["executable"],
                                                   coredump["time"])

        l.info("creating archive %s", archive_path)
        subprocess.check_call([
            "tar",
            "--null",
            "-C",
            str(record_paths.state_dir),
            "-T",
            str(template.name),
            "-czf",
            str(archive_path),
        ])
        l.info("built archive %s", archive_path)
        os.unlink(manifest_path)


def report_worker(queue):
    # type: (Queue) -> None
    l.info("start worker")
    while True:
        job = queue.get()  # type: Job
        if job.exit:
            return

        try:
            store_report(job)
            l.info("processed job")
        except OSError:
            l.exception("Error while creating report")
        finally:
            l.info("remove job")
            job.remove()


def record_loop(record_path, log_path, pid_file=None, limit=0, command=None):
    # type: (Path, Path, Optional[str], int, Optional[List[str]]) -> None

    job_queue = Queue()  # type: Queue
    post_process_thread = Thread(target=report_worker, args=(job_queue, ))
    post_process_thread.start()

    try:
        i = 0
        while limit == 0 or limit > i:
            i += 1
            # TODO ratelimit
            record_paths = RecordPaths(record_path, i, log_path, pid_file)
            result = record(record_paths, command)
            if result is None:
                # Perf exited without coredump:
                # This either means we have started it with a command, which
                # exited or perf failed to setup processor trace/process.
                break
            (coredump, perf_data) = result
            job_queue.put(Job(coredump, perf_data, record_paths))
            if command is not None:
                # if we record a single command we do not go into a loop
                break
    except KeyboardInterrupt:
        pass
    finally:
        job_queue.put(Job(exit=True))
        l.info("Wait for child")
        post_process_thread.join()


def record_command(args):
    # type: (argparse.Namespace) -> None

    log_path = Path(args.log_dir)
    log_path.mkdir_p()

    logging.basicConfig(
        filename=str(log_path.join("hase.log")), level=logging.INFO)

    command = None if len(args.args) == 0 else args.args

    with Tempdir() as tempdir:
        record_loop(
            tempdir,
            log_path,
            pid_file=args.pid_file,
            limit=args.limit,
            command=command)
