#!/bin/bash
n_run=3
name="redis"
outdir="."
# address="127.0.0.1:5254"
# timeout=40
# writes=10000
record_process="../../record_process.py"
python=/home/harveylu/Documents/Research/hase/venv/bin/python

show_help() {
cat << EOF
usage: run.sh [-h] [-r R] [-n NAME] [-o OUTDIR]

optional arguments:
  -h, --help         show this help message and exit
  -r R               The number of runs
  -n NAME        The name of the benchmark
  -o OUTDIR    The path of output files
EOF
}

OPTIND=1

while getopts ":r:n:o:h" arg; do
  case $arg in
    r) n_run=$OPTARG;;
    n) name=$OPTARG;;
    o) outdir=$OPTARG;;
    h)
      show_help
      exit 0
      ;;
    *)
      show_help >&2
      exit 1
      ;;
  esac
done

shift $((OPTIND-1))

echo "Remember to start redis by: sudo systemctl start redis-server"

for i in $(seq 0 $((n_run - 1)));
  do
    echo Run $i with hase
    sudo $python $record_process -n redis-server &
    RECORD_ID=$!
    redis-benchmark > $outdir/$name\_hase\_$i.out 2>/dev/null
    kill $RECORD_ID 2>/dev/null
    sleep 1
  done

for i in $(seq 0 $((n_run - 1)));
  do
    echo Run $i without hase
    redis-benchmark  > $outdir/$name\_$i.out 2>/dev/null
    sleep 1
  done
