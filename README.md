An implementation of AEZ v3, an authenticated encryption scheme designed by
Viet Tung Hoang, Ted Krovetz, and Phil Rogaway. AEZ is a submission in the
CAESAR crypto competition.

![#b8b8b8](https://placehold.it/15/b8b8b8/000000?text=+) **DEPRECATION NOTICE:**
The authors of the standard have deprecated this version of the AEZ standard.
See [Phil's website](http://web.cs.ucdavis.edu/~rogaway/aez) for the latest
version, including Ted's implementation.

The code builds for three different architectures: 32-bit x86 (default), 64-bit
x86, and 64-bit x86 with support for AES-NI. For example, to build benchmarks
for AES-NI, do
```
$ make bm arch=aes-ni
```

To build for 64-bit systems, use `arch=x64`. Running `make` without this
argument defaults to 32-bit.

This directory also contains a simple wrapper for Python based on Ctypes.  First
build a shared library and add it to the library path. On Linux:
```
$ make lib arch=aes-ni
$ sudo cp libaez.so /usr/local/lib
$ sudo ldconfig
```

Next, install the wrapper:
```
$ sudo python setup.py install
```

AEZ should now be accesible in Python:

```
$ python
>>> import aez
>>> K = 'This is a key.'; N = 'This is a nonce.'
>>> A = ['This', 'is', ('some', 'fancy'), 1.61803, 'data.']
>>> C = aez.Encrypt('Hello, world!', K, N, A, abytes=3)
>>> repr(C)
"'USb\\x0b\\x00+\\xecQ\\xa1\\x84K\\xb1q\\xe3\\xc5t'"
>>> aez.Decrypt(C, K, N, A, abytes=3)
'Hello, world!'
```

This code matches the spec and reference code precisely, except the vector-
valued additional data `A` has at most 10 elements. (See `MAX_DATA` in aez.h.)
This was just to prevent extra malloc()'s in aez_hash() and aez_encrypt(). Find
the spect at web.cs.ucdavis.edu/~rogaway/aez/.

Copyright notice
----------------
This code is dedicated to the public domain.
