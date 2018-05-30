from setuptools import setup, find_packages, Extension
from distutils.command.build import build as _build
from setuptools.command.develop import develop as _develop
import glob
import subprocess
import shutil
import os


def _build_exec_wrapper():
    cmd = ['make', '-C', 'exec-wrapper']
    subprocess.check_call(cmd)

    shutil.rmtree('hase/libexec', ignore_errors=True)
    os.mkdir('hase/libexec')
    shutil.copy(os.path.join('exec-wrapper/exec-wrapper'), 'hase/libexec')


class build(_build):
    def run(self, *args):
        self.execute(_build_exec_wrapper, (), msg='Building exec_wrapper')
        _build.run(self, *args)


# runs in `pip install -e`
class develop(_develop):
    def run(self, *args):
        self.execute(_build_exec_wrapper, (), msg='Building exec_wrapper')
        _develop.run(self, *args)


setup(
    name='hase',
    version='0.1',
    description="Time-travel failures",
    packages=find_packages(),
    cmdclass={
        'build': build,
        'develop': develop
    },
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
    extras_require={"test": ["nose"]},
    ext_modules=[
        Extension(
            'hase._pt',
            sources=glob.glob('pt/*.cpp'),
            extra_compile_args=[
                '-std=c++17', '-Wno-register', '-fvisibility=hidden'
            ],
            extra_link_args=['-lipt', '-lipt-sb'],
        ),
    ],
    entry_points={
        "console_scripts":
        ["hase = hase:main"
         "hase-gui = hase.frontend:main"],
    },
    package_data={
        'hase': ['libexec/*']
    }
)
