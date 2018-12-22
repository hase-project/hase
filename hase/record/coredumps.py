import logging
import os
import resource
import sys

# TODO python3
from pipes import quote
from tempfile import NamedTemporaryFile
from typing import Any, Optional, Tuple

from ..path import which
from .coredump_handler import EXTRA_CORE_DUMP_PARAMETER, RECV_MESSAGE

l = logging.getLogger(__name__)

HANDLER_PATH = "/proc/sys/kernel/core_pattern"

COREDUMP_FILTER_PATH = "/proc/self/coredump_filter"

# core(5) on coredump filter
# bit 0  Dump anonymous private mappings.
# bit 1  Dump anonymous shared mappings.
# bit 2  Dump file-backed private mappings.
# bit 3  Dump file-backed shared mappings.
# bit 4 (since Linux 2.6.24)
#        Dump ELF headers.
# bit 5 (since Linux 2.6.28)
#        Dump private huge pages.
# bit 6 (since Linux 2.6.28)
#        Dump shared huge pages.
# bit 7 (since Linux 4.4)
#        Dump private DAX pages.
# bit 8 (since Linux 4.4)
#        Dump shared DAX pages.


class Coredump:
    def __init__(self, core_file: str, result_path: str) -> None:
        self.core_file = core_file
        self.result_path = result_path

    def get(self) -> str:
        l.info("check for result %s", self.result_path)
        self.result_file = open(self.result_path)
        msg = self.result_file.read(len(RECV_MESSAGE))
        assert msg == RECV_MESSAGE, "got '%s' from fifo, expected: '%s'" % (
            msg,
            RECV_MESSAGE,
        )
        return self.core_file

    def remove(self) -> None:
        os.unlink(self.core_file)
        if self.result_file is not None:
            self.result_file.close()
        os.unlink(self.result_path)


class Handler:
    def __init__(
        self,
        core_file: str,
        fifo_path: str,
        manifest_path: str,
        log_path: str = "/tmp/coredump.log",
    ) -> None:
        self.previous_pattern = None  # type: Optional[str]
        self.old_core_rlimit = None  # type: Optional[Tuple[int, int]]
        self.handler_script = None  # type: Optional[Any]
        self.core_file = core_file
        self.fifo_path = fifo_path
        self.manifest_path = manifest_path
        self.log_path = log_path

    def __enter__(self) -> Coredump:
        kill_command = which("kill")
        assert kill_command is not None

        self.handler_script = NamedTemporaryFile(
            prefix="core_handler", delete=False, mode="w+"
        )
        os.chmod(self.handler_script.name, 0o755)
        assert len(self.handler_script.name) < 128

        script_template = """#!/bin/sh
exec 1>>{log_path}
exec 2>&1

{kill} -SIGUSR2 "{pid}"

export PYTHONPATH={pythonpath}

exec {python} -m hase.record.coredump_handler {fifo_path} {core_file} {manifest_path} "$@"
"""

        script_content = script_template.format(
            kill=kill_command,
            pid=os.getpid(),
            python=quote(sys.executable),
            pythonpath=":".join(sys.path),
            fifo_path=quote(self.fifo_path),
            core_file=quote(self.core_file),
            log_path=quote(self.log_path),
            manifest_path=quote(self.manifest_path),
        )

        self.handler_script.write(script_content)
        self.handler_script.close()

        inf = resource.RLIM_INFINITY
        self.old_core_rlimit = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (inf, inf))

        with open(HANDLER_PATH, "r+") as f, open(
            COREDUMP_FILTER_PATH, "w+"
        ) as filter_file:
            self.previous_pattern = f.read()
            f.seek(0)
            extra_args = " ".join(EXTRA_CORE_DUMP_PARAMETER.values())
            f.write("|{} {}".format(self.handler_script.name, extra_args))

            # just dump everything into core dumps and worry later
            filter_file.write("0xff\n")
            filter_file.flush()

            return Coredump(self.core_file, self.fifo_path)

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        assert self.previous_pattern is not None
        with open(HANDLER_PATH, "w") as f:
            f.write(self.previous_pattern)
        if self.old_core_rlimit is not None:
            resource.setrlimit(resource.RLIMIT_CORE, self.old_core_rlimit)
        if self.handler_script is not None:
            os.unlink(self.handler_script.name)
