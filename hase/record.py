from __future__ import absolute_import, division, print_function

import shutil
import json
from tempfile import NamedTemporaryFile
from threading import Thread
import subprocess
import logging
from datetime import datetime
from Queue import Queue
import os
import argparse  # NOQA

from . import coredumps, perf
from .path import Path, Tempdir
from .mapping import Mapping

from . import pwn_wrapper

from typing import Optional, IO, Any, Tuple

l = logging.getLogger(__name__)

DEFAULT_LOG_DIR = Path("/var/lib/hase")

PROT_EXEC = 4


def record(record_paths):
    # type: (RecordPaths) -> Tuple[coredumps.Coredump, perf.PerfData]

    with perf.PTSnapshot(perf_file=str(record_paths.perf)) as snapshot:
        handler = coredumps.Handler(snapshot.perf_pid,
                                    str(record_paths.coredump),
                                    str(record_paths.fifo),
                                    str(record_paths.manifest),
                                    log_path=str(record_paths.log_path.join("coredump.log")))
        with handler as coredump, \
                perf.IncreasePerfBuffer(100 * 1024 * 1024):
            c = coredump  # type: coredumps.Coredump
            return (c, snapshot.get())


class Job():
    def __init__(
            self,
            coredump=None,  # type: Optional[coredumps.Coredump]
            perf_data=None,  # type: Optional[perf.PerfData]
            record_paths=None,  # type: Optional[RecordPaths]
            exit=False  # type: bool
    ):
        # type: (...) -> None
        self.coredump = coredump
        self.perf_data = perf_data
        self.record_paths = record_paths
        self.exit = exit

    def core_file(self):
        # type: () -> str
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


class RecordPaths():
    def __init__(self, path, id, log_path):
        # type: (Path, int, Path) -> None
        self.path = path
        self.log_path = log_path
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
        return self.log_path.join("%s-%s.tar.gz" % (os.path.basename(executable), timestamp))


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
            if (obj.flags & PROT_EXEC) and path.startswith("/") and os.path.exists(path):
                paths.add(path)
            mappings.append(Mapping(start=obj.start, stop=obj.stop, path=obj.path, flags=obj.flags))

        for path in paths:
            # FIXME check if elf, only create parent directory once
            archive_path = state_dir.join("binaries", path[1:])
            archive_path.dirname().mkdir_p()

            shutil.copyfile(path, str(archive_path))

            binaries.append(str(state_dir.relpath(str(archive_path))))
            append(str(archive_path))

        coredump = manifest["coredump"]
        coredump["path"] = str(state_dir.relpath(core_file))
        append(core_file)

        manifest["perf_data"] = str(state_dir.relpath(job.perf_data.path))
        append(job.perf_data.path)

        with open(manifest_path, "w") as manifest_file:
            json.dump(manifest, manifest_file, indent=4)

        template.flush()

        archive_path = record_paths.report_archive(coredump["executable"], coredump["time"])

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


def record_loop(record_path, log_path):
    # type: (Path, Path) -> None

    job_queue = Queue()  # type: Queue
    post_process_thread = Thread(target=report_worker, args=(job_queue, ))
    post_process_thread.start()

    try:
        i = 0
        while True:
            i += 1
            # TODO ratelimit
            record_paths = RecordPaths(record_path, i, log_path)
            (coredump, perf_data) = record(record_paths)
            job_queue.put(Job(coredump, perf_data, record_paths))
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

    logging.basicConfig(filename=str(log_path.join("hase.log")), level=logging.INFO)

    with Tempdir() as tempdir:
        record_loop(tempdir, log_path)
