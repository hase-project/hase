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

Note: you may need to upgrade your pip >= 9.0.1

Additionally pyqt5 is required and cannot be installed via pip. 

3. Install test dependencies

```console
$ pip install -e '.[test]'
```

4. Patch the perf-script-sample-addr

```console
git clone https://github.com/torvalds/linux
cd ./linux/tools/perf
cp path-to-your-hase-folder/perf-script-sample-addr.patch .
patch -p3 < perf-script-sample-addr.patch
make
sudo cp perf /usr/bin
```

Note: some new parse rules are applied recent days, so if you have intel_pt//u parse error, check this patch https://lkml.org/lkml/2018/5/7/94 and solve by git checkout an-eariler-commit-id


5. Testing examples


```console
# Since we need sudo, we have to install the packages in system
pip install -r requirements_freeze.txt
sudo nosetests -w tests/test_record.py
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

```console
$ sudo ./bin/hase record ls -al
```