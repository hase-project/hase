# HASE

# INSTALL

1. Setup virtualenv

```console
$ virtualenv venv
$ . venv/bin/activate
```

2. Install project into virtualenv

```console
$ pip install -e .
```

Additionally pyqt5 is required and cannot be installed via pip.

3. Install test dependencies

```console
$ pip install -e '.[test]'
```


# Record crashes


```console
$ sudo ./bin/hase record
```

Example crash
```console
$ ./tests/bin/loopy/loopy
$ ls -la /var/lib/hase
.rw-rw-rw- 244 root  9 May  3:22 coredump.log
.rw-r--r--   4 root  9 May  3:22 hase-record.pid
.rw-r--r-- 41M root  9 May  3:22 loopy-20180509T022227.tar.gz
```
