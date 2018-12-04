"""
    Use this script to get the commands to run
"""
import subprocess
import json
import traceback
import os

from config import *


def main():
    for suite in SUITE:
        try:
            SUITE[suite]["commands"].clear()
            os.chdir(SUITE_PATH + SUITE[suite]["name"] + RUN_PATH)
            # print(os.getcwd())
            output = subprocess.getoutput("specinvoke -n")
            # print(output)
            for line in output.split("\n"):
                if line.startswith(".."):
                    SUITE[suite]["commands"].append(line)

        except Exception as e:
            print(f"Error while processing {suite}")
            traceback.print_exc()
    print(json.dumps(SUITE))


if __name__ == "__main__":
    main()
