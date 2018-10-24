#!/usr/bin/env python
"""
    Use this script to run the original benchmark without recording.
"""
import subprocess
import resource

import argparse

from config import *

def main():
    subprocess.run(args.args, shell=True)
    rusage = tuple(resource.getrusage(resource.RUSAGE_CHILDREN))
    with open(USAGE, 'w') as file:
        file.write(', '.join([str(x) for x in rusage]))
        file.write('\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "args", nargs="*", help="Executable and arguments for perf tracing")
    args = parser.parse_args()
    main()
