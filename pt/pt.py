import glob
from pathlib import Path

from cffi import FFI

with open(Path(__file__).resolve().parent.joinpath("ffi.h")) as f:
    header = f.read()
    ffibuilder = FFI()
    ffibuilder.cdef(header)
    ffibuilder.set_source(
        "hase._pt",
        None,
        sources=glob.glob("*.cpp"),
        extra_compile_args=["-std=c++17", "-Wno-register", "-fvisibility=hidden"],
        extra_link_args=["-lipt"],
        source_extension=".cpp",
    )


if __name__ == "__main__":
    ffibuilder.compile()
