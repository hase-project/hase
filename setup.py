import glob
import os
import shutil
import subprocess

from setuptools import Extension, find_packages, setup

setup(
    name='hase',
    version='0.1',
    description="Time-travel failures",
    packages=find_packages(),
    install_requires=[
      'angr @ https://github.com/hase-project/angr/archive/38730216ad2682f07d696ae24883fc4075559c45.zip',
      'pwntools @ https://github.com/Mic92/pwntools/archive/d93f557c8004eac3d34821e8eb11059082aed0e3.zip',
      'monkeyhex',
      'qtconsole',
      'pry.py',
      'pygdbmi',
      # how to add PyQt5 here?
      # 'pyqt5'
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
        ["hase = hase:main",
         "hase-gui = hase.frontend:main"],
    }
)
