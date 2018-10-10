import os
import subprocess
import resource

import argparse

COMMANDS = {
    
}

def measure(benchmard):
    pass

def main(args):
    if args.benchmark in COMMANDS:
        measure(benchmark)
    else:
        for benchmark in COMMANDS:
            measure(benchmark)
    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "benchmark",
        type=str,
        help="The benchmark (suite) to run"
    )
    parser.add_argument(
        "--hase-bin",
        type=str,
        default="../../bin/hase",
        help="The path to the hase script"
    )
    args = parser.parse_args()
    main(args)
