import os
from pwn_wrapper import Coredump

from .tracer import Tracer


def dso_offsets_from_coredump(coredump):
    """
    Extract shared object memory mapping from coredump
    """
    main = coredump.mappings[0]
    lib_opts = {}
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
    coredump = Coredump(os.path.realpath(coredump))

    t = Tracer(executable, trace, coredump,
               dso_offsets_from_coredump(coredump))
    return t.run()


def replay_command(args):
    return replay_trace(args.executable, args.coredump, args.trace)
