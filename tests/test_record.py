from __future__ import absolute_import, division, print_function

import os
import sys
import subprocess
import nose
import shutil
from glob import glob
from nose.plugins.skip import SkipTest
from time import sleep
from multiprocessing import Process
from typing import List
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
        #loopy = str(TEST_BIN.join("long_trace"))
        loopy = str(TEST_BIN.join("loopy"))
        #loopy = str(TEST_BIN.join("cpu_switch"))
        #loopy = str(TEST_BIN.join("indirect-jump"))
        argv = [
            "hase", "record", "--log-dir",
            #str(tempdir), "--limit", "1", "--pid-file", pid_file, loopy, "1000", "0"
            str(tempdir), "--limit", "1", "--pid-file", pid_file, loopy, "a", "b", "c", "d", "e"
        ]
        global process

        # python replaces stdin with /dev/null in the child process...
        # we want stdin for pdb
        stdin_copy = open("/proc/self/fd/0")

        def mymain(args):
            # type: (List[str]) -> None
            sys.stdin = stdin_copy
            main(args)

        #del os.environ["LD_PRELOAD"]
        process = Process(target=mymain, args=(argv, ))
        process.start()

        while not os.path.exists(pid_file):
            nose.tools.assert_true(process.is_alive())
            sleep(0.1)

        process.join()

        archives = glob(str(tempdir.join("*.tar.gz")))
        nose.tools.assert_equal(len(archives), 1)

        #states = main(["hase", "replay", archives[0]])
        ##nose.tools.assert_equal(len(states), 3)

        ##del os.environ['LD_PRELOAD']

        shutil.copyfile(archives[0], "/tmp/loopy-20180619T100257.tar.gz")
        states = main(["hase", "replay", "/tmp/loopy-20180619T100257.tar.gz"])
