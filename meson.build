project('seal-sandbox', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3',
                     'cpp_std=c++14'])

seal = dependency('seal')

sources = files([
  'src/vector.cpp'
])

incdir = include_directories('include')

catch2 = dependency('catch2', required : false)
if catch2.found()
  subdir('tests')
endif
