src = [
  'decode.cpp',
  'module.cpp',
  'config.cpp',
  'mmap.cpp',
]

add_global_arguments(['-std=c++17', '-I../inst/include', '-fvisibility=hidden', '-Wno-register'], language: 'cpp')

pyinstall = python_mod.find_installation('python2')
pyinstall.extension_module('hase._pt', src,
  dependencies : [python_dep, pt],
  install: true,
  install_dir: pyinstall.get_install_dir()
)

#pyinstall.extension_module('hase._pt', src,
#  dependencies : [python_dep],
#  install: true,
#  install_dir: pyinstall.get_install_dir(),
#  link_args: ['-lipt', '-lipt-sb', '-L../inst/lib', '-Wl,-rpath=/home/joerg/git/hase/inst/lib']
#)
