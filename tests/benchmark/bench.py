import subprocess
import os
import pandas
import socket
import errno
import tempfile
from time import sleep

from typing import IO

perf_cmd = [
    "perf",
    "record", 
    "-g", 
    "-e",
    "cycles",
    "-e",
    "raw_syscalls:*/call-graph=no/",
    "-e",
    "sched:sched_switch/call-graph=no/",
    "--switch-output",
    "--overwrite",
    "-a"
]

server_cmd = [
    "redis-server",
    "--port"
]

def check_port_inuse(port):
    # type: int -> bool
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except socket.error:
        return False


def bench_apache2(repeat = 3, n = 1000000):
    # type: (int, int) -> pandas.DataFrame

    bench_cmd = [
        "ab",
        "-n",
        str(n),
        "-c",
        "100",
        "-t",
        "20",
    ]



def bench_redis(repeat = 3, n = 1000000):
    # type: (int, int) -> pandas.DataFrame

    def read_result(file):
        # type: IO[Any] -> pandas.DataFrame
        df = pandas.read_csv(file, names=['Type', 'Req/s'])
        return df

    bench_cmd = [
        "redis-benchmark",
        "-r", 
        "100000",
        "-n",
        str(n),
        "--csv",
        "-p"
    ]


    df_allperf = None
    df_allnoperf = None

    init_port = 10000

    with open(os.devnull, 'w') as fnull:
        for i in range(repeat):

            print("\nRunning the {}th benchmark\n".format(i + 1))
            print("Record performance without perf")

            while check_port_inuse(init_port):
                init_port += 1

            serv = subprocess.Popen(server_cmd + [str(init_port)], stdout=fnull)
            sleep(1) # for setup
            bench = subprocess.Popen(bench_cmd + [str(init_port)], stdout=subprocess.PIPE)
            bench.wait()
            serv.terminate()
            if i == 0:
                df_allnoperf = read_result(bench.stdout)
            else:
                df_allnoperf = pandas.concat([df_allnoperf, read_result(bench.stdout)['Req/s']], axis=1)

            print("Record performance with perf")

            while check_port_inuse(init_port):
                init_port += 1

            serv = subprocess.Popen(perf_cmd + server_cmd + [str(init_port)], stdout=fnull)
            sleep(1) # for setup
            bench = subprocess.Popen(bench_cmd + [str(init_port)], stdout=subprocess.PIPE)
            bench.wait()
            serv.terminate()
            if i == 0:
                df_allperf = read_result(bench.stdout)
            else:
                df_allperf = pandas.concat([df_allperf, read_result(bench.stdout)['Req/s']], axis=1)
        
    df_type = df_allnoperf['Type']
    df_avgperf = df_allperf['Req/s'].mean(axis=1)
    df_avgnoperf = df_allnoperf['Req/s'].mean(axis=1)
    df_alloverhead = df_allperf['Req/s'] / df_allnoperf['Req/s']
    df_overhead = df_alloverhead.mean(axis=1)
    df_stddev = df_alloverhead.std(axis=1)
    
    print("\nTotal Repeat Time: {}".format(repeat))
    print("Repeat each instruction for {} times\n".format(n))

    result = pandas.concat([
        df_type,
        df_avgperf,
        df_avgnoperf,
        df_overhead,
        df_stddev
    ], axis = 1, keys=['Type', 'Avg Req/s w. perf', 'Avg Req/s w/o perf', '% of performance', 'Std. Dev'])
    
    print(result)
    return result

bench_redis(10)
