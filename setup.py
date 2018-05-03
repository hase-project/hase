from setuptools import setup, find_packages

setup(
    name='hase',
    version='0.1',
    description="Time-travel failures",
    packages=find_packages(),
    install_requires=[
        'angr',
        'pwntools',
        'monkeyhex',
        'qtconsole',
        'pry.py',
        'pygdbmi',
        'typing'
        # how to add PyQt5 here?
        # 'pyqt5'
    ],
    tests_require=['nose'],
    test_suite='nose.collector',
    extras_require={
        "test": ["nose"]
    },
    entry_points={
        "console_scripts": ["hase = hase:main"],
    },
)
