import sys
import os
import shutil
import tempfile
import resource
# TODO python3
from pipes import quote

HANDLER_PATH = "/proc/sys/kernel/core_pattern"
RECV_MESSAGE = "GOT COREDUMP"

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


class Coredump():
    def __init__(self, core_file, fifo_path):
        self.core_file = core_file
        self.fifo_path = fifo_path

    def get(self):
        with open(self.fifo_path) as f:
            assert f.read(len(RECV_MESSAGE)) == RECV_MESSAGE
        return self.core_file


def write_script(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o700)
    f = os.fdopen(fd, "w")
    f.write(content)
    f.close()


class Handler():
    def __init__(self, expected_executable, core_file):
        self.previous_pattern = None
        self.fifo_dir = None
        self.old_core_rlimit = None
        self.expected_executable = expected_executable
        self.core_file = core_file

    def __enter__(self):
        self.fifo_dir = tempfile.mkdtemp()
        fifo_path = os.path.join(self.fifo_dir, "fifo")
        os.mkfifo(fifo_path)

        handler_script = os.path.join(self.fifo_dir, "core_handler")
        assert len(handler_script) < 128

        script_template = """#!/bin/sh
exec 1>/tmp/coredump-log
exec 2>&1

exec {} {} {} {} {} "$@"
"""
        script_content = script_template.format(
            quote(sys.executable), quote(__file__), quote(fifo_path),
            quote(self.core_file), quote(self.expected_executable))
        write_script(handler_script, script_content)

        inf = resource.RLIM_INFINITY
        self.old_core_rlimit = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (inf, inf))

        with open(HANDLER_PATH, "rb+") as f,\
                open(COREDUMP_FILTER_PATH, "w+") as filter_file:
            self.previous_pattern = f.read()
            f.seek(0)
            f.write('|{} %E'.format(handler_script))

            # just dump everything into core dumps and worry later
            filter_file.write("0xff\n")
            filter_file.flush()

            return Coredump(self.core_file, fifo_path)

    def __exit__(self, type, value, traceback):
        with open(HANDLER_PATH, "w") as f:
            f.write(self.previous_pattern)
        if self.fifo_dir is not None:
            shutil.rmtree(self.fifo_dir)
        if self.old_core_rlimit is not None:
            resource.setrlimit(resource.RLIMIT_CORE, self.old_core_rlimit)


def main(args):
    fifo_path = args[0]
    core_dump_path = args[1]
    expected_executable = args[2]
    actual_executable = args[3].replace("!", "/")

    sys.stderr.write("actual_executable: %s" % actual_executable)
    sys.stderr.write("expected_executable: %s" % expected_executable)

    if not expected_executable == actual_executable:
        return

    try:
        shutil.copyfileobj(sys.stdin, open(core_dump_path, "wb"))
    finally:
        with open(fifo_path, "w") as f:
            f.write(RECV_MESSAGE)


if __name__ == "__main__":
    assert len(sys.argv) == 5, \
            "Expected 5 arguments, got %d: %s" % (len(sys.argv), sys.argv)
    main(sys.argv[1:])
