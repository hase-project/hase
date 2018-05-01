from __future__ import absolute_import, division, print_function

import os
import tempfile
import errno
import shutil

try:
    from typing import Union, AnyStr
except ImportError:
    pass




def which(program):
    # type: (str) -> Path
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return Path(os.path.abspath(program))
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = Path(path).join(program)
            if is_exe(str(exe_file)):
                return exe_file

    return None


class Path(object):
    """
    Poor mans pathlib
    """

    def __init__(self, path):
        # type: (AnyStr) -> None
        self._path = str(path)

    def join(self, *args):
        # type: (*AnyStr) -> Path
        return Path(os.path.join(self._path, *(map(str, args))))

    def relpath(self, path):
        # type: (AnyStr) -> Path
        return Path(os.path.relpath(path, self._path))

    def dirname(self):
        # type: () -> Path
        return Path(os.path.dirname(self._path))

    def mkdir_p(self):
        # type: () -> None
        try:
            os.makedirs(self._path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

    def __str__(self):
        # type: () -> str
        return self._path

    def __repr__(self):
        # type: () -> str
        return repr(self._path)


class Tempdir(Path):
    def __init__(self):
        super(Tempdir, self).__init__(tempfile.mkdtemp())

    def __enter__(self):
        # type: () -> Tempdir
        return self

    def __exit__(self, type, value, traceback):
        shutil.rmtree(str(self))


APP_ROOT = Path(os.path.dirname(os.path.realpath(__file__)))
