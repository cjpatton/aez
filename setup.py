from distutils.core import setup, Extension

setup (name="AEZ",
       version="3",
       author="Chris Patton",
       ext_modules=[Extension('_aez', 
                     sources=['aez_wrap.c', 'aez.c', 'rijndael-alg-fst.c'],
                     extra_compile_args=['-std=c99', '-Wall'])
                  ],
       py_modules=['aez']
)
