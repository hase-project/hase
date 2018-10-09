# only used to get compile_commands.json for pt module

project('pt', 'cpp',
  version: '0.1.0',
  license: 'LGPL-2.0',
)
python_mod = import('python3')
python_dep = dependency('python3', required: true)

cc = meson.get_compiler('cpp')
if not cc.has_header('intel-pt.h')
  error('processor-trace library header "intel-pt.h" not found')
endif
ipt = cc.find_library('ipt', required: true)

pt = declare_dependency(dependencies: [ipt])

subdir('pt')
