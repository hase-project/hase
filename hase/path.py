import os
import os.path
from pathlib import Path
from typing import Optional, List, AnyStr


def which(program: str) -> Optional[Path]:
    def is_exe(fpath: str) -> bool:
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return Path(os.path.abspath(program))
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = Path(path).joinpath(program)
            if is_exe(str(exe_file)):
                return exe_file

    return None


def find_in_path(filename: str, relative_root: List[str]) -> str:
    b = os.path.basename(filename)
    collected_root = []
    for path in relative_root:
        for root, _, files in os.walk(path):
            if b in files:
                collected_root.append(root)

    def intersect_judge(root: str) -> int:
        elems_f = filename.split("/")
        elems_r = os.path.join(root, os.path.basename(filename)).split("/")
        return len([v for v in elems_f if v in elems_r])

    if collected_root != []:
        return os.path.join(
            max(collected_root, key=intersect_judge), os.path.basename(b)
        )
    return filename


APP_ROOT = Path(os.path.dirname(os.path.realpath(__file__)))
