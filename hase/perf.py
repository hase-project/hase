import csv
import subprocess
import sys

TRACE_END = -1


def parse_row(row):
    return (int(row[0], 16), int(row[1], 16))


def read_trace(sample_path, loader):
    with open(sample_path) as f:
        reader = csv.reader(f, delimiter='\t')
        branches = []

        # record the entrypoint
        try:
            line = next(reader)
            branches.append(parse_row(line))
        except StopIteration:
            return

        for row in reader:
            (address, ip) = parse_row(row)
            # skip syscalls until we support it in tracer
            if address == 0 or ip == 0:
                continue
            branches.append((address, ip))
    # also append last instruction, if it was a syscall
    if ip == 0:
        branches.append((address, TRACE_END))
    return branches


def dump_trace(perf_data, tsv_path):
    args = [
        "perf",
        "script",
        "--input=%s" % perf_data,
        "--itrace=b",
        "--fields",
        "ip,addr"
    ]
    cmd = subprocess.Popen(args, stdout=subprocess.PIPE)
    with open(tsv_path, "w") as tsv_file:
        tsv_writer = csv.writer(tsv_file, delimiter='\t')
        for line in cmd.stdout:
            address = line.split()[0]
            ip = line.split()[2]
            tsv_writer.writerow((address, ip))


if __name__ == '__main__':
    sample_file = sys.argv[1] if len(sys.argv) > 1 else "perf.data"
    dump_trace(sample_file, "trace.tsv")
