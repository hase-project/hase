# HASE

[![Build Status](https://travis-ci.org/hase-project/hase.svg?branch=master)](https://travis-ci.org/hase-project/hase)

Hase provides record-replay debugging suitable for all-ways-on in-production recording.
It leverages [intel processor trace](https://software.intel.com/en-us/blogs/2013/09/18/processor-tracing)
and [core dumps](https://en.wikipedia.org/wiki/Core_dump) that can be recorded with
little overhead.
On top of that data it performs [symbolic execution](https://github.com/angr/angr)
to recover states prior to the crash.

[Workshop presentation on Klee Workshop 2018](https://docs.google.com/presentation/d/1QeJtKAtLsBbpX9U-llUe_zOLeJpCCq-p8frFMmj9cd4/edit?usp=sharing)

# INSTALL

1. Setup virtualenv

```console
$ virtualenv venv
$ . venv/bin/activate
```

2. Get the [Intel processor-trace decoder library](https://github.com/01org/processor-trace)

3. Install project into virtualenv

```console
$ pip install -e . --process-dependency-links
```

Note: you may need to upgrade your pip >= 9.0.1

Additionally pyqt5 is required and cannot be installed via pip. 

4. Install test dependencies

```console
$ pip install -e '.[test]' --process-dependency-links
```

5. Testing examples

The integration test needs root.

```console
make -C tests
sudo nosetests -w tests/test_record.py
```

The other tests work without root:
Note that the test traces are stored via [git-lfs](https://git-lfs.github.com/)

```console
nosetests -w tests/test_replay.py
```

# Record crashes

```console
$ sudo ./bin/hase record <some crash program> <args>
```

Example crash

```console
$ ./tests/bin/loopy/loopy
$ ls -la /var/lib/hase
.rw-rw-rw- 244 root  9 May  3:22 coredump.log
.rw-r--r--   4 root  9 May  3:22 hase-record.pid
.rw-r--r-- 41M root  9 May  3:22 loopy-20180509T022227.tar.gz
```

```console
$ sudo ./bin/hase record ls -al
```

# Benchmarks

Benchmarks require Pandas, which cannot be installed via pip.
Use https://pandas.pydata.org/pandas-docs/stable/install.html instead or install
it using your system package manager.
