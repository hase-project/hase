from __future__ import absolute_import, division, print_function

import subprocess
import os
import sys
import pandas
import socket
from time import sleep

from typing import IO, Any, Optional

perf_cmd = [
    "perf", "record", "--no-buildid", "--no-buildid-cache", "-e",
    "raw_syscalls:*", "--switch-output", "--overwrite", "-a",
    "--tail-synthesize"
]

server_cmd = ["redis-server", "--port"]


def check_port_inuse(port):
    # type: (int) -> bool
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except socket.error:
        return False


def bench_redis(repeat=3, n=1000000):
    # type: (int, int) -> pandas.DataFrame

    def read_result(name, file):
        # type: (str, Optional[IO[Any]]) -> pandas.DataFrame
        df = pandas.read_csv(file, names=['Type', 'Req/s'])
        df["Name"] = name
        return df

    bench_cmd = [
        "redis-benchmark", "-r", "100000", "-t", "set,lpush", "-n",
        str(n), "--csv", "-p"
    ]

    init_port = 10000

    results = []

    with open(os.devnull, 'w') as fnull:
        for i in range(repeat):

            print("\nRunning the {}th benchmark\n".format(i + 1))
            print("Record performance with perf")

            while check_port_inuse(init_port):
                init_port += 1

            serv = subprocess.Popen(
                perf_cmd + server_cmd + [str(init_port)], stdout=fnull)
            sleep(1)  # for setup
            bench = subprocess.Popen(
                bench_cmd + [str(init_port)], stdout=subprocess.PIPE)
            bench.wait()
            serv.terminate()
            results.append(read_result("perf", bench.stdout))

            print("Record performance without perf")

            while check_port_inuse(init_port):
                init_port += 1

            serv = subprocess.Popen(
                server_cmd + [str(init_port)], stdout=fnull)
            sleep(1)  # for setup
            bench = subprocess.Popen(
                bench_cmd + [str(init_port)], stdout=subprocess.PIPE)
            bench.wait()
            serv.terminate()
            results.append(read_result("no-perf", bench.stdout))

    df = pandas.concat(results)
    path = os.path.join(os.path.dirname(__file__), "results", "syscall.tsv")
    print("wrote %s" % path)
    df.to_csv(path, sep="\t")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("needs root for perf", file=sys.stderr)
        sys.exit(1)
    bench_redis(10)
