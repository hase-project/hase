"""
    Use this script to aggregate and analyze the data
"""

import argparse
import json
import re
from pprint import pprint
from typing import List, Tuple, Any

import numpy as np


def get_float(measure_string):
    r = re.compile(r"\d+(\.\d*)?")
    b = re.search(r, measure_string)
    if b:
        return float(b.group(0))


def parse(file: Any) -> Tuple[List[str], List[float]]:
    benchmarks = []
    throughputs = []
    for i, line in enumerate(file.readlines()):
        if i <= 2:
            continue
        if i <= 4:
            splitted = line.strip().split()
            benchmarks.append(splitted[0])
            throughputs.append(get_float(splitted[1]))
        elif i == 5:
            splitted = line.strip().split()
            benchmarks.append(splitted[1])
            throughputs.append(float(splitted[0]))
        else:
            splitted = line.strip().split(": ")
            benchmarks.append(splitted[0])
            throughputs.append(get_float(splitted[1]))

    return benchmarks, throughputs


def main() -> None:
    throughputs_hase = []
    throughputs_original = []
    for i in range(args.n):
        with open(f'{args.name}_{i}.out') as file:
            benchmarks, throughput = parse(file)
            throughputs_original.append(throughput)
        with open(f'{args.name}_hase_{i}.out') as file:
            benchmarks, throughput = parse(file)
            throughputs_hase.append(throughput)

    throughputs_hase = np.array(throughputs_hase)
    throughputs_original = np.array(throughputs_original)

    ratios = throughputs_hase.mean(axis=0) / throughputs_original.mean(axis=0)

    for i in range(len(benchmarks)):
        print(f"{benchmarks[i]}:\t{ratios[i]:.2f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("n", type=int, help="The files to aggregate")
    parser.add_argument(
        "--name", type=str, default="nginx", help="The name of the benchmark"
    )
    args = parser.parse_args()
    main()
