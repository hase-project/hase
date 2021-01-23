# HASE

[![Build Status](https://travis-ci.org/hase-project/hase.svg?branch=master)](https://travis-ci.org/hase-project/hase)

Hase provides record-replay debugging suitable for all-ways-on in-production recording.
It leverages [intel processor trace](https://software.intel.com/en-us/blogs/2013/09/18/processor-tracing)
and [core dumps](https://en.wikipedia.org/wiki/Core_dump) that can be recorded with
little overhead.
On top of that data it performs [symbolic execution](https://github.com/angr/angr)
to recover states prior to the crash.

[System design figure](https://dl.thalheim.io/o-SUOvpks1NlMsggEjCfOQ/complete-design.html)

[Workshop presentation on Klee Workshop 2018](https://docs.google.com/presentation/d/1QeJtKAtLsBbpX9U-llUe_zOLeJpCCq-p8frFMmj9cd4/edit?usp=sharing)

# INSTALL

1. Setup virtual environment with python3.6 or pypy6

```console
$ python3 -m venv venv
$ . venv/bin/activate
```

or for pypy:

```
$ pypy3 -m venv venv
$ . venv/bin/activate
```

2. Get the [Intel processor-trace decoder library](https://github.com/01org/processor-trace)

3. Install project into the virtual environment

Make sure you pip is version >= 18.1 and setuptools >= 38.3:

```
$ ./venv/bin/pip install "pip>=18.1" "setuptools>=38.3"
```

```console
$ ./venv/bin/pip install -e .
```

Trouble Shooting:
New version of `make` may break the installation of pyvex, consult this [upstream commit](https://github.com/angr/pyvex/commit/5ed27fc213a20e2e9bec0131058ec4795c644d0f) to resolve the issue manually.

Additionally pyqt5 is required and cannot be installed via pip. 

4. Install test dependencies

```console
$ python3 -m pip install -e '.[test]'
```

5. Testing examples

The integration test needs root.

```console
make -C tests
sudo nosetests tests/test_record.py
```

The other tests work without root:
Note that the test traces are stored via [git-lfs](https://git-lfs.github.com/)

```console
nosetests tests/test_replay.py
```

# Record crashes

```console
$ sudo ./bin/hase record <some crash program> <args>
```

Example crash:

```console
$ sudo ./bin/hase record ./tests/bin/loopy
$ ls -la /var/lib/hase
.rw-rw-rw- 244 root  9 May  3:22 coredump.log
.rw-r--r--   4 root  9 May  3:22 hase-record.pid
.rw-r--r-- 41M root  9 May  3:22 loopy-20180509T022227.tar.gz
```

No crash:

```console
$ sudo ./bin/hase record -- ls -al
```

# Benchmarks

Benchmarks require Pandas, which cannot be installed via pip3.
Use https://pandas.pydata.org/pandas-docs/stable/install.html instead or install
it using your system package manager.

## Making changes

To avoid breaking mypy use the following steps:

1. Create a feature branch:

```console
$ git checkout -b <branch-name> 
$ git push origin <branch-name>
```

2. Make a pull request by visiting `https://github.com/hase-project/hase/pull/new/<branch-name>` or use [hub](https://hub.github.com):

```console
$ git pull-request
```
