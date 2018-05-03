from __future__ import absolute_import, division, print_function

import os
import argparse
import subprocess
import json
from typing import List

from .symbex.tracer import Tracer, State, Any, Dict
from .mapping import Mapping
from .path import Tempdir


def load_manifest(path):
    # type: (str) -> Dict[str, Any]
    with open(path) as f:
        return json.load(f)


def replay_trace(report):
    # type: (str) -> List[State]

    with Tempdir() as tempdir:
        subprocess.check_call(["tar", "-xzf", report, "-C", str(tempdir)])

        manifest = load_manifest(str(tempdir.join("manifest.json")))

        coredump = manifest["coredump"]
        executable = str(tempdir.join(coredump["executable"]))
        trace = manifest["perf_data"]

        mappings = []
        for m in manifest["mappings"]:
            mappings.append(
                Mapping(
                    path=m["path"],
                    start=m["start"],
                    stop=m["stop"],
                    flags=m["flags"]))

        t = Tracer(executable, trace, mappings)
    return t.run()


def replay_command(args):
    # type: (argparse.Namespace) -> List[State]
    return replay_trace(args.report)
