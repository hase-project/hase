#!/bin/bash
n_run=3
name="logcabin"
outdir="."
address="127.0.0.1:5254"
timeout=40
writes=10000
record_process="../../record_process.py"
python=/home/harveylu/Documents/Research/hase/venv/bin/python

show_help() {
cat << EOF
usage: run.sh [-h] [-r R] [-n NAME] [-o OUTDIR] [-a ADDRESS]
              [-t TIMEOUT] [-w WRITES]
              config

positional arguments:
  config             The path to the config file

optional arguments:
  -h, --help         show this help message and exit
  -r R               The number of runs
  -n NAME        The name of the benchmark
  -o OUTDIR    The path of output files
  -a ADDRESS  The network address
  -t TIMEOUT  The timeout
  -w WRITES    The number of writes performed
EOF
}

OPTIND=1

while getopts ":r:n:o:a:t:w:h" arg; do
  case $arg in
    r) n_run=$OPTARG;;
    n) name=$OPTARG;;
    o) outdir=$OPTARG;;
    a) address=$OPTARG;;
    t) timeout=$OPTARG;;
    w) writes=$OPTARG;;
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

config=$1

logcabind --config $config --bootstrap &> /dev/null

for i in $(seq 0 $((n_run - 1)));
  do
    echo Run $i with hase

    logcabind --config $config &> /dev/null &
    LOGCABIN_ID=$!
    sleep 2
    sudo $python $record_process -p $LOGCABIN_ID &
    RECORD_ID=$!
    logcabin-benchmark -c $address --writes $writes --timeout $timeout > $outdir/$name\_hase\_$i.out 2>/dev/null
    kill $LOGCABIN_ID 2>/dev/null
    kill $RECORD_ID 2>/dev/null
    sleep 1
  done

for i in $(seq 0 $((n_run - 1)));
  do
    echo Run $i without hase
    logcabind --config $config &> /dev/null &
    LOGCABIN_ID=$!
    sleep 2
    logcabin-benchmark -c $address --writes $writes --timeout $timeout > $outdir/$name\_$i.out 2>/dev/null
    kill $LOGCABIN_ID 2>/dev/null
    sleep 1
  done
