from setuptools import setup, find_packages, Extension
import glob
import subprocess
import shutil
import os



setup(
    name='hase',
    version='0.1',
    description="Time-travel failures",
    packages=find_packages(),
    install_requires=[
      'angr',
      'pwntools>3.13.0',
      'monkeyhex',
      'qtconsole',
      'pry.py',
      'pygdbmi',
      'typing'
      # how to add PyQt5 here?
      # 'pyqt5'
    ],
    dependency_links=[
        "https://github.com/Mic92/pwntools/archive/0f479d27e18c37288c241112adf09d100ee2c001.tar.gz#egg=pwntools-3.14.0"
    ],
    tests_require=['nose'],
    test_suite='nose.collector',
    extras_require={"test": ["nose"]},
    ext_modules=[
        Extension(
            'hase._pt',
            sources=glob.glob('pt/*.cpp'),
            extra_compile_args=[
                '-std=c++17', '-Wno-register', '-fvisibility=hidden'
            ],
            extra_link_args=['-lipt'],
        ),
    ],
    entry_points={
        "console_scripts":
        ["hase = hase:main"
         "hase-gui = hase.frontend:main"],
    }
)
