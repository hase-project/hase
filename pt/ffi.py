import glob
from pathlib import Path

from cffi import FFI

DIR = Path(__file__).parent.resolve()

with open(str(DIR.joinpath("ffi.h"))) as f, open(str(DIR.joinpath("pt.cpp"))) as f2:
    source_files = []
    for path in DIR.glob("*.cpp"):
        if path.name != "pt.cpp":
            source_files.append(str(path))

    header = f.read()
    source = f2.read()
    ffibuilder = FFI()
    ffibuilder.cdef(header)
    ffibuilder.set_source(
        module_name="hase._pt",
        source=source,
        sources=source_files,
        include_dirs=[str(DIR)],
        extra_compile_args=["-std=c++17", "-Wno-register", "-fvisibility=hidden"],
        extra_link_args=["-lipt"],
        source_extension=".cpp",
    )


if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
