from __future__ import absolute_import, division, print_function

import os
import os.path
import tempfile
import errno
import shutil

try:
    # make typing optional so we can use it in bin/update-vendor
    from typing import Union, AnyStr, Optional, List
except ImportError:
    pass


def which(program):
    # type: (str) -> Optional[Path]
    def is_exe(fpath):
        # type: (str) -> bool
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

    def __add__(self, path):
        # type: (str) -> Path
        return self.join(path)

    def __iadd__(self, path):
        # type: (str) -> Path
        self._path = os.path.join(self._path, path)
        return self

    def join(self, *args):
        # type: (*AnyStr) -> Path
        return Path(os.path.join(self._path, *(map(str, args))))

    def exists(self):
        # type: () -> bool
        return os.path.exists(self._path)

    def relpath(self, path):
        # type: (str) -> Path
        return Path(os.path.relpath(path, self._path))

    def dirname(self):
        # type: () -> Path
        return Path(os.path.dirname(self._path))

    def basename(self):
        # type: () -> Path
        return Path(os.path.basename(self._path))

    def listdir(self):
        # type: () -> List[Path]
        if os.path.isdir(self._path):
            files = []
            for f in os.listdir(self._path):
                p = os.path.join(self._path, f)
                if os.path.isfile(p):
                    files.append(Path(p))
            return files
        return []

    def mkdir_p(self):
        # type: () -> None
        try:
            os.makedirs(self._path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

    @staticmethod
    def find_in_path(filename, relative_root):
        # type: (AnyStr, List[AnyStr]) -> AnyStr
        b = os.path.basename(filename)
        collected_root = []
        for path in relative_root:
            for root, _, files in os.walk(path):
                if b in files:
                    collected_root.append(root)

        def intersect_judge(root):
            elems_f = filename.split("/")
            elems_r = os.path.join(root, os.path.basename(filename)).split("/")
            return len([v for v in elems_f if v in elems_r])

        if collected_root != []:
            return os.path.join(
                max(collected_root, key=intersect_judge), os.path.basename(b)
            )
        return filename

    def __str__(self):
        # type: () -> str
        return self._path

    def __repr__(self):
        # type: () -> str
        return repr(self._path)

    def __cmp__(self, rhs):
        # type: (AnyStr) -> int
        return (str(self) > str(rhs)) - (str(self) < str(rhs))


class Tempdir(Path):
    def __init__(self):
        super(Tempdir, self).__init__(tempfile.mkdtemp())

    def __enter__(self):
        # type: () -> Tempdir
        return self

    def __exit__(self, type, value, traceback):
        shutil.rmtree(str(self))


APP_ROOT = Path(os.path.dirname(os.path.realpath(__file__)))
