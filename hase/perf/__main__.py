from __future__ import absolute_import, division, print_function

import pry
import os
import time
from ..path import Tempdir

from . import Perf

if __name__ == "__main__":
    with pry:
        with Tempdir() as t, Perf() as perf:
            time.sleep(3)
            pid = os.getpid()
            perf.write(str(t))
