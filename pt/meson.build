src = [
  'decode.cpp',
  'module.cpp',
  'config.cpp',
  'mmap.cpp',
  'tsc.cpp',
]

add_global_arguments(['-std=c++17', '-I../inst/include', '-fvisibility=hidden', '-Wno-register'], language: 'cpp')

python_mod.extension_module('hase._pt', src,
  dependencies : [python_dep, pt],
  install: true,
  install_dir: python_mod.sysconfig_path('platlib')
)
