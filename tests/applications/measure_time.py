"""
    Use this script to monitor a running process.
"""
import argparse
import subprocess
import time


def main():
    result = None
    while True:
        time.sleep(1)
        status, output = subprocess.getstatusoutput(f'cat /proc/{args.pid}/stat')
        if status:
            break

        result = output

    if args.file:
        with open(args.file, 'w') as file:
            file.write(result)
    else:
        print(result.strip())
        result = result.strip().split()
        print(float(result[13]) + float(result[14]))



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="The pid to monitor usage")
    parser.add_argument(
        "-f", "--file", default=None, help="The file to output the result"
    )
    args = parser.parse_args()
    main()
