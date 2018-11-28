"""
    Use this script to monitor a running process.
"""
import subprocess
import time
import argparse


def main():
    while True:
        time.sleep(1)
        output = subprocess.getoutput(f'ps -jH -p {args.pid} --noheaders')
        if not output:
            break

        if args.file:
            with open(args.file, 'w') as file:
                file.write(output)
        else:
            print(output.strip())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="The pid to monitor usage")
    parser.add_argument("file", default=None, help="The file to output the result")
    args = parser.parse_args()
    main()
