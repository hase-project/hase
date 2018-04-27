import subprocess
from .coredumps import Handler
import os
from datetime import datetime
from .perf import dump_trace


def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return os.path.abspath(program)
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


def record_command(args):
    path = which(args.executable)
    if path is None:
        raise OSError("command not found: %s" % args.executable)

    now = datetime.now().replace(microsecond=0).strftime("%Y%m%dT%H%M%S")
    prefix = "%s-%s" % (os.path.basename(args.executable), now)

    coredump_path = "%s.coredump" % prefix
    with Handler(path, os.path.realpath(coredump_path)) as coredump:
        perf = "%s.perf" % prefix
        cmd = ["perf", "record", "-a", "--snapshot", "--output=%s" % perf, "-v", "-e", "intel_pt//u", path] + args.arguments
        subprocess.call(cmd)
        coredump.get()
        tsv_path = "%s.trace" % prefix
        dump_trace(perf, tsv_path)
 
        print("%s\t%s\t%s" % (tsv_path, coredump_path, perf))
