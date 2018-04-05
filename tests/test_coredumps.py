import os
import subprocess
import nose
import tempfile
from hase.coredumps import Handler
from nose.plugins.skip import SkipTest


def test_coredump_handler():
    if os.geteuid() != 0:
        raise SkipTest("Requires root")
    shell_exe = os.path.realpath(os.popen("echo -n $0").read())
    f = tempfile.NamedTemporaryFile()
    with Handler(shell_exe, f.name) as coredump:
        subprocess.call([shell_exe, "-c", "kill -ABRT $$"])
        nose.tools.assert_equal(f.name, coredump.get())
