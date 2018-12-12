"""
    Use this script to aggregate and analyze the data
"""

import argparse
import json
from pprint import pprint
from typing import List, Tuple, Any

import numpy as np
from scipy.stats import gmean


def parse(file: Any) -> Tuple[List[str], List[float]]:
    benchmarks = []
    throughputs = []
    for i, line in enumerate(file.readlines()):
        if i < 6:
            continue
        splitted = line.strip().split()
        benchmarks.append(splitted[0])
        throughputs.append(float(splitted[2]))

    return benchmarks, throughputs


def aggregate(results: Any) -> Any:
    if args.aggregation == "worst":
        return results.max(axis=0)
    if args.aggregation == "mean":
        return results.mean(axis=0)
    if args.aggregation == "median":
        return np.median(results, axis=0)
    if results.shape[0] <= 2:
        return results.max(axis=0)
    return np.median(results, axis=0)


def main() -> None:
    throughputs_hase = []
    throughputs_original = []
    for i in range(args.n):
        with open(f"{args.name}_{i}.out") as file:
            benchmarks, throughput = parse(file)
            throughputs_original.append(throughput)
        with open(f"{args.name}_hase_{i}.out") as file:
            benchmarks, throughput = parse(file)
            throughputs_hase.append(throughput)

    throughputs_hase = np.array(throughputs_hase)
    throughputs_original = np.array(throughputs_original)

    ratios = aggregate(throughputs_hase) / aggregate(throughputs_original)

    for i in range(len(benchmarks)):
        print(f"{benchmarks[i]}\t{ratios[i]:.4f}")

    print("GeoMean\t" + str(gmean(ratios)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("n", type=int, help="The files to aggregate")
    parser.add_argument(
        "--name", type=str, default="leveldb", help="The name of the benchmark"
    )
    parser.add_argument("--outdir", type=str, default=".", help="The output directory")
    parser.add_argument(
        "-a",
        "--aggregation",
        type=str,
        default="auto",
        choices=["auto", "median", "worst", "mean"],
        help="Choose a way to aggregate the data from different runs",
    )
    args = parser.parse_args()
    main()
