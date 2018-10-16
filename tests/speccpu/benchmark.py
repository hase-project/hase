"""
    Benchmarking SPECCPU with and without recording.
    Results written into a json(python dictionary) file.
"""
import os
import subprocess
import resource
import json

import logging
import argparse

from config import *

logging.basicConfig(
    format='%(asctime)s: %(levelname)s: %(message)s', level=logging.INFO)
LOGGER = logging.getLogger(__name__)


# TODO: check if result is valid
def measure(benchmark, result):
    result[benchmark] = {'original':[], 'hase':[]}
    os.chdir(SUITE_PATH + SUITE[benchmark]['name'] + RUN_PATH)
    for run in range(args.run):
        result[benchmark]['original'].append({'run':run, 'result':[]})
        result[benchmark]['hase'].append({'run':run, 'result':[]})
        for i, command in enumerate(SUITE[benchmark]['commands']):
            # print(subprocess.getoutput('pwd'))
            # print('sudo ' + HASE_BIN + ' record --rusage-file ' + USAGE + ' -- ' + command)
            LOGGER.info(f'Benchmark: {benchmark}, Run: {run}, Command: {i}, with hase')
            subprocess.run('sudo ' + HASE_BIN + ' record --rusage-file ' + USAGE + ' -- ' + command, shell=True)
            with open(USAGE) as file:
                result[benchmark]['hase'][run]['result'].append([float(x.strip()) for x in file.read().split(',')])
            # print('sudo python3 ' + RECORD_PY + ' -- ' + command)
            LOGGER.info(f'Benchmark: {benchmark}, Run: {run}, Command: {i}, without hase')
            subprocess.run('sudo python3 ' + RECORD_PY + ' -- "' + command + '"', shell=True)
            with open(USAGE) as file:
                result[benchmark]['original'][run]['result'].append([float(x.strip()) for x in file.read().split(',')])

    os.chdir(HOME_DIR)
    with open('result.json', 'w') as file:
        # print(file.name)
        json.dump(result, file)
        file.write('\n')


def main():
    result = {}
    if args.benchmark in SUITE:
        measure(args.benchmark, result)
    else:
        for benchmark in SUITE:
            measure(benchmark, result)

    os.chdir(HOME_DIR)
    print(result)
    with open('result.json', 'w') as file:
        json.dump(result, file)
        file.write('\n')
    return

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'benchmark',
        type=str,
        help='The benchmark (suite) to run'
    )
    parser.add_argument(
        '--run',
        type=int,
        default=3,
        help='The number of runs'
    )
    args = parser.parse_args()
    main()
