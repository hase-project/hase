# Redis Benchmarking
1. `$ sudo systemctl start redis-server`
1. `$ python measure_time.py -n redis-server -v`
1. (hase record) `$ sudo python record_process.py -n redis-server`
1. `$ redis-benchmark`
1. `$ python measure_time.py -n redis-server -v`
