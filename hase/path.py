import os


class Path(str):
    """
    Poor mans pathlib
    """

    def __init__(self, path):
        self._path = path

    def join(self, *args):
        return Path(os.path.join(self._path, *args))

    def str(self):
        return str(self._path)

    def __str__(self):
        return self._path

    def __repr__(self):
        return repr(self._path)


APP_ROOT = Path(os.path.dirname(os.path.realpath(__file__)))
