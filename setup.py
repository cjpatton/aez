from distutils.core import setup, Extension
import os

cc_args = ['-O3', '--std=c99', '-Wall'] 
a = os.environ.get('EXTRA_CC_ARGS')
if a is not None and a is not '':  
  a = a.split(' ')
  cc_args += a
else: a = []

sources = ['aez.i', 'aez.c'] 
if len(a) < 2: # 32-bit or 64-bit
  sources.append('rijndael-alg-fst.c')

a = os.environ.get('SWIG_OPT')
if a is not None and a is not '':
  swig_opt = a.split(' ')
else: swig_opt = []

setup (name="AEZ",
       version="3",
       author="Chris Patton",
       ext_modules=[Extension('aez._aez', sources=sources, 
                          extra_compile_args=cc_args,
                          swig_opts = swig_opt)
                   ],
       packages=['aez'],
       package_dir={"aez" : 'python'}
)
