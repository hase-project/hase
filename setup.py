import glob

from setuptools import Extension, find_packages, setup

setup(
    name="hase",
    version="0.1",
    description="Time-travel failures",
    packages=find_packages(),
    install_requires=[
        "angr @ https://github.com/hase-project/angr/archive/a997996b2d6486e709ba09dd79cad4cd58113eb8.zip",
        "pwntools @ https://github.com/hase-project/pwntools/archive/74a98908a19e00df399abd4b8e956abeabbd62ae.zip",
        "monkeyhex",
        "ipython",
        "qtconsole",
        "ipdb",
        "pygdbmi",
        # how to add PyQt5 here?
        # 'pyqt5'
    ],
    tests_require=["nose"],
    test_suite="nose.collector",
    extras_require={"test": ["nose"]},
    ext_modules=[
        Extension(
            "hase._pt",
            sources=glob.glob("pt/*.cpp"),
            extra_compile_args=["-std=c++17", "-Wno-register", "-fvisibility=hidden"],
            extra_link_args=["-lipt"],
        )
    ],
    entry_points={
        "console_scripts": ["hase = hase:main", "hase-gui = hase.frontend:main"]
    },
)
