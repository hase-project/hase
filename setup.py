import os
from setuptools import setup, find_packages

setup(
    name='hase',
    version='0.1',
    description="Time-travel failures",
    packages=find_packages(),
    install_requires=['angr', 'pwntools', 'r2pipe', 'monkeyhex'],
    entry_points={
        "console_scripts": ["hase = hase:main"],
    },
)
