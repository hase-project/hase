#!/bin/bash
n_run=3
name="redis"
outdir="."
url="http://localhost/"
n_threads="1"
n_connections="10"
duration="10"
record_process="../../record_process.py"
python=/home/harveylu/Documents/Research/hase/venv/bin/python

show_help() {
cat << EOF
usage: run.py [-h] [-r R] [-u URL] [-t T] [-c C] [-d D] [-o OUTDIR]
              [-n NAME] pid

positional arguments:
  pid             The pid of the nginx worker process

optional arguments:
  -h, --help       show this help message and exit
  -r R             The number of runs
  -u URL        The url to access
  -t T             The number of threads
  -c C             The number of connections
  -d D             The duration in seconds
  -o OUTDIR  The output directory
  -n NAME      The name of the benchmark
EOF
}

OPTIND=1

while getopts ":r:n:o:h:u:t:c:d" arg; do
  case $arg in
    r) n_run=$OPTARG;;
    n) name=$OPTARG;;
    o) outdir=$OPTARG;;
    u) url=$OPTARG;;
    t) n_threads=$OPTARG;;
    c) n_connections=$OPTARG;;
    d) duration=$OPTARG;;
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

pid=$1

echo "Remember to start nginx by: sudo systemctl start nginx"
sudo $python $record_process -p $pid &
RECORD_ID=$!

for i in $(seq 0 $((n_run - 1)));
  do
    echo Run $i with hase
    wrk -t $n_threads -d $duration -c $n_connections $url > $outdir/$name\_hase\_$i.out 2>/dev/null
    sleep 1
  done

kill $RECORD_ID 2>/dev/null

for i in $(seq 0 $((n_run - 1)));
  do
    echo Run $i without hase
    wrk -t $n_threads -d $duration -c $n_connections $url > $outdir/$name\_$i.out 2>/dev/null
    sleep 1
  done
