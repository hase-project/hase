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
