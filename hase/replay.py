from __future__ import absolute_import, division, print_function

import os
import argparse

from .pwn_wrapper import Coredump
from .tracer import Tracer, State

try:
    from typing import List
except ImportError:
    pass


def dso_offsets_from_coredump(coredump):
    # type: (Coredump) -> dict
    """
    Extract shared object memory mapping from coredump
    """
    main = coredump.mappings[0]
    lib_opts = {}  # type: dict
    force_load_libs = []
    for mapping in coredump.mappings[1:]:
        if not mapping.name.startswith("/") or mapping.name in lib_opts:
            continue
        lib_opts[mapping.name] = dict(custom_base_addr=mapping.start)
        force_load_libs.append(mapping.name)

    # TODO: extract libraries from core dump instead ?
    return dict(
        main_opts={"custom_base_addr": main.start},
        force_load_libs=force_load_libs,
        lib_opts=lib_opts,
        load_options={"except_missing_libs": True})


def replay_trace(executable, coredump, trace):
    # type: (str, str, str) -> List[State]
    coredump = Coredump(os.path.realpath(coredump))

    t = Tracer(executable, trace, coredump,
               dso_offsets_from_coredump(coredump))
    return t.run()


def replay_command(args):
    # type: (argparse.Namespace) -> List[State]
    return replay_trace(args.executable, args.coredump, args.trace)
