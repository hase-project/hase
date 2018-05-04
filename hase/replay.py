from __future__ import absolute_import, division, print_function

import os
import argparse
import subprocess
import json
from typing import List

from .symbex.tracer import Tracer, State, Any, Dict
from .mapping import Mapping
from .path import Tempdir, Path


def load_manifest(archive_root):
    # type: (Path) -> Dict[str, Any]
    manifest_path = archive_root.join("manifest.json")
    with open(str(manifest_path)) as f:
        manifest = json.load(f)

    mappings = []
    for m in manifest["mappings"]:
        if m["path"] != "":
            path = archive_root.join(m["path"])
            if path.exists():
                m["path"] = str(path)
        m = Mapping(**m)
        mappings.append(m)
    manifest["mappings"] = mappings
    manifest["perf_data"] = str(archive_root.join(manifest["perf_data"]))

    coredump = manifest["coredump"]
    coredump["executable"] = str(archive_root.join(coredump["executable"]))
    coredump["file"] = str(archive_root.join(coredump["file"]))

    return manifest


def replay_trace(report):
    # type: (str) -> List[State]

    with Tempdir() as tempdir:
        subprocess.check_call(["tar", "-xzf", report, "-C", str(tempdir)])

        manifest = load_manifest(tempdir)

        coredump = manifest["coredump"]

        t = Tracer(
            coredump["executable"],
            coredump["global_tid"],
            manifest["perf_data"],
            coredump["file"],
            manifest["mappings"],
            executable_root=str(tempdir.join("binaries")))
        return t.run()


def replay_command(args):
    # type: (argparse.Namespace) -> List[State]
    return replay_trace(args.report)
