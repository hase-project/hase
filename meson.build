# only used to get compile_commands.json for pt module

project('pt', 'cpp',
  version: '0.1.0',
  license: 'LGPL-2.0',
)
python_mod = import('python')
python_dep = dependency('python2', required: true)

cc = meson.get_compiler('cpp')
cc.has_header('intel-pt.h', required: true)
ipt = cc.find_library('ipt', required: true)

pt = declare_dependency(dependencies: [ipt])

subdir('pt')
