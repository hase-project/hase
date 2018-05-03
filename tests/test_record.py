from __future__ import absolute_import, division, print_function

import os
import subprocess
import nose
import tempfile
from nose.plugins.skip import SkipTest
from time import sleep
from multiprocessing import Process

from hase import main
from hase.path import Tempdir, which


def stop_hase():
    global process
    if process is not None and process.is_alive():
        process.terminate()


def test_record_command():
    if os.geteuid() != 0:
        raise SkipTest("Requires root")
    with Tempdir() as tempdir:
        pid_file = str(tempdir.join("record.pid"))
        argv = ["hase", "record", "--log-dir", str(tempdir), "--limit", "1",
                "--pid-file", pid_file]
        global process
        process = Process(target=main, args=(argv,))
        process.start()

        while not os.path.exists(pid_file):
            nose.tools.assert_true(process.is_alive())
            sleep(0.1)

        nose.tools.assert_true(process.is_alive())

        # coredump
        subprocess.call([str(which("sh")), "-c", "kill -ABRT $$"])

        process.join()

test_record_command.teardown = stop_hase
