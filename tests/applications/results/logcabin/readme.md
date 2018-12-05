# Logcabin Benchmarking
1. `$ logcabind --config <config> --bootstrap; logcabind --config <config>`
1. (hase record) `$ sudo python record_process.py -n logcabind`
1. `$ logcabin-benchmark -c 127.0.0.1:5254 --writes 10000 --timeout 40`
