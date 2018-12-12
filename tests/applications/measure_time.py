"""
    Use this script to monitor a running process.
"""
import argparse
import subprocess
import time


def main() -> None:
    if args.n:
        output = subprocess.getoutput(f"pgrep {args.n}")
        args.p = int(output.strip())

    result = "0"
    while True:
        time.sleep(1)
        status, output = subprocess.getstatusoutput(f"cat /proc/{args.p}/stat")
        if status:
            break

        result = output
        if args.v:
            result_list = result.strip().split()
            print(float(result_list[13]) + float(result_list[14]))

    if args.file:
        with open(args.file, "w") as file:
            file.write(result)
    else:
        print(result.strip())
        ru = result.strip().split()
        print(float(ru[13]) + float(ru[14]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", default=0, type=int, help="The pid to monitor usage.")
    parser.add_argument("-n", type=str, help="The name of the process to monitor.")
    parser.add_argument(
        "-f", "--file", default=None, help="The file to output the result."
    )
    parser.add_argument("-v", action="store_true", help="Print status every second.")
    args = parser.parse_args()
    main()
