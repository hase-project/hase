import glob

from setuptools import Extension, find_packages, setup

setup(
    name="hase",
    version="0.1",
    description="Time-travel failures",
    packages=find_packages(),
    install_requires=[
        "angr @ https://github.com/hase-project/angr/archive/e1b66e2eebe0756ad5a06a686d8a086528ad7cf6.zip",
        "cle @ https://github.com/angr/cle/archive/cd39642d6532ac2908ab6aa510240e9397341c92.zip",
        "claripy @ https://github.com/angr/claripy/archive/ca524cb2af19952d247ff072b38140b4eb8d21c1.zip",
        "pyvex @ https://github.com/angr/pyvex/archive/44a8f41d960e108610144335dac4f852e050e2e7.zip",
        "archinfo @ https://github.com/angr/archinfo/archive/d3eb03b047847d55fec71c06e9d2a15bc2f28d7d.zip",

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
