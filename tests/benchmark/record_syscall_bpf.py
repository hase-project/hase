# NOTE: modify the example from https://github.com/iovisor/bcc/blob/master/examples/tracing/hello_perf_output.py
from __future__ import absolute_import, division, print_function

from bcc import BPF
import ctypes as ct
from time import sleep
import subprocess
import os
import sys
import pandas
import socket

from typing import IO, Any, Optional, List, Tuple


def read_syscall():
    # type: () -> Tuple[List[str], str]

    prog = """
    int dump(void *ctx) {
      return 0;
    }
    """

    syscalls = []

    with open("syscall_64.tbl") as sf:
        for line in sf:
            line = line.strip()
            if line.startswith("#"):
                continue
            args = line.split()
            if args:
                syscalls.append(args[-1])

    return syscalls, prog


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
        df = pandas.read_csv(file, names=["Type", "Req/s"])
        df["Name"] = name
        return df

    bench_cmd = [
        "redis-benchmark",
        "-r",
        "100000",
        "-t",
        "set,lpush",
        "-n",
        str(n),
        "--csv",
        "-p",
    ]

    init_port = 10000

    results = []

    syscalls, bpf_prog = read_syscall()

    with open(os.devnull, "w") as fnull:
        for i in range(repeat):
            print("Record {}th performance without bpf".format(i))

            while check_port_inuse(init_port):
                init_port += 1

            serv = subprocess.Popen(server_cmd + [str(init_port)], stdout=fnull)
            sleep(1)  # for setup
            bench = subprocess.Popen(
                bench_cmd + [str(init_port)], stdout=subprocess.PIPE
            )
            bench.wait()
            serv.terminate()
            results.append(read_result("no-bpf", bench.stdout))

        b = BPF(text=bpf_prog)
        for sysc in syscalls:
            try:
                b.attach_kprobe(event=sysc, fn_name="dump")
                b.attach_kretprobe(event=sysc, fn_name="dump")
            except Exception as e:
                print(str(e) + ", syscall: {}".format(sysc))

        for i in range(repeat):
            print("Record {}th performance with bpf".format(i))

            while check_port_inuse(init_port):
                init_port += 1

            serv = subprocess.Popen(server_cmd + [str(init_port)], stdout=fnull)
            sleep(1)  # for setup
            bench = subprocess.Popen(
                bench_cmd + [str(init_port)], stdout=subprocess.PIPE
            )
            bench.wait()
            serv.terminate()
            results.append(read_result("bpf", bench.stdout))

    df = pandas.concat(results)
    path = os.path.join(os.path.dirname(__file__), "results", "syscall.tsv")
    print("wrote %s" % path)
    df.to_csv(path, sep="\t")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("needs root for perf", file=sys.stderr)
        sys.exit(1)
    bench_redis(10)
