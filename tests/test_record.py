from __future__ import absolute_import, division, print_function

import os
import subprocess
import nose
from glob import glob
from nose.plugins.skip import SkipTest
from time import sleep
from multiprocessing import Process
import time

from hase import main
from hase.path import Tempdir

from .helper import TEST_BIN


process = None


def stop_hase():
    global process
    if process is not None and process.is_alive():
        process.terminate()


@nose.tools.with_setup(teardown=stop_hase)
def test_record_command():
    """
    Full integration test
    """
    if os.geteuid() != 0:
        raise SkipTest("Requires root")
    with Tempdir() as tempdir:
        pid_file = str(tempdir.join("record.pid"))
        # generate coredump
        loopy = str(TEST_BIN.join("loopy/loopy"))
        argv = [
            "hase", "record", "--log-dir",
            str(tempdir), "--limit", "1", "--pid-file", pid_file, loopy
        ]
        global process
        process = Process(target=main, args=(argv, ))
        process.start()

        while not os.path.exists(pid_file):
            nose.tools.assert_true(process.is_alive())
            sleep(0.1)

        process.join()

        archives = glob(str(tempdir.join("*.tar.gz")))
        nose.tools.assert_equal(len(archives), 1)

        states = main(["hase", "replay", archives[0]])
        nose.tools.assert_equal(len(states), 3)
