from __future__ import absolute_import, division, print_function

import sys
import os

sys.path.append(os.environ['PERF_EXEC_PATH'] + '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')
expected_command = sys.argv[1]


def process_event(params):

    if params["comm"] != expected_command:
        return

    sample = params["sample"]
    print("%d\t%d" % (sample["addr"], sample["ip"]))
