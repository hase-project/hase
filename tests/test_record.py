from __future__ import absolute_import, division, print_function

import os
import shutil
import subprocess
import sys
import time
from glob import glob
from multiprocessing import Process
from time import sleep
from tempfile import TemporaryDirectory
from typing import List
from pathlib import Path

import nose
from nose.plugins.skip import SkipTest

from hase import main

from .helper import TEST_BIN

process = None


def stop_hase():
    global process
    if process is not None and process.is_alive():
        process.terminate()


@nose.tools.with_setup(teardown=stop_hase)
def test_record_command() -> None:
    """
    Full integration test
    """
    if os.geteuid() != 0:
        raise SkipTest("Requires root")
    with TemporaryDirectory() as tempdir:
        temppath = Path(tempdir)
        pid_file = str(temppath.joinpath("record.pid"))
        # generate coredump
        loopy = str(TEST_BIN.joinpath("loopy"))
        argv = [
            "hase",
            "record",
            "--log-dir",
            str(tempdir),
            "--limit",
            "1",
            "--pid-file",
            pid_file,
            loopy,
            "a",
            "b",
            "c",
            "d",
            "e",
        ]
        global process

        # python replaces stdin with /dev/null in the child process...
        # we want stdin for pdb
        stdin_copy = open("/proc/self/fd/0")

        def mymain(args):
            # type: (List[str]) -> None
            sys.stdin = stdin_copy
            main(args)

        process = Process(target=mymain, args=(argv,))
        process.start()

        while not os.path.exists(pid_file):
            nose.tools.assert_true(process.is_alive())
            sleep(0.1)

        process.join()

        archives = list(temppath.glob("*.tar.gz"))
        nose.tools.assert_equal(len(archives), 1)

        states = main(["hase", "replay", str(archives[0])])
        nose.tools.assert_true(len(states) > 10)
