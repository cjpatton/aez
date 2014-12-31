# aez.py - Python interface for AEZv3, using Ctypes to connect 
# dynamically with AEZ compiled as a shared library. Written by 
# Chris Patton <chrispatton@gmail.com> and dedicated to the 
# public domain.

# Last Modified 30 Dec 2014. 
# 
# Features to add: 
#  - Target formats for plaintexts and ciphtertexts.
#  - Length preserving? 

import ctypes
import ctypes.util

# Interface with AEZ library.
try: 
  lib = ctypes.util.find_library('aez')
  ctypes.cdll.LoadLibrary(lib) 
  _aez = ctypes.CDLL(lib)

except: 
  raise AEZError("Could not find library.")


### Constants. ################################################################

# Maximum length of data vector (A). 
MAX_DATA = _aez.get_max_data()

# Number of bytes used for authenticity tag. 
ABYTES = 16 


### High level calls. ######################################################### 

def Encrypt(M, K, N, A=[], abytes=ABYTES):
  return Context(K).Encrypt(M, N, A, abytes)

# Return None if plaintext is invalid.
def Decrypt(C, K, N, A=[], abytes=ABYTES): 
  return Context(K).Decrypt(C, N, A, abytes)

def Hash(K, A):
  return Context(K).Hash(A)

def PRF(K, A, abytes=ABYTES):
  return Context(K).PRF(A, abytes)

def Encipher(M, K, A=[]): 
  return Context(K).Encipher(M, A)

def Decipher(C, K, A=[]): 
  return Context(K).Decipher(M, A)


### Context object. ###########################################################

class Context (ctypes.Structure):

  # Extract a key schedule from user-defined key, an arbitrary byte 
  # string. This class has the same data layout as the internal key
  # schedule of the AEZ library code; if the library was compiled 
  # without AES-NI, then we must include additional key schedules 
  # for software AES. 

  _pack_ = 16
  _fields_ = [('L1', ctypes.c_ubyte * 16),
              ('K',  ctypes.c_ubyte * 16 * 4), 
              ('Js', ctypes.c_ubyte * 16 * 9)]

  if not _aez.using_aes_ni():
    _fields_ += [('k0', ctypes.c_ubyte * 16 * 5), 
                 ('k1', ctypes.c_ubyte * 16 * 5), 
                 ('k2', ctypes.c_ubyte * 16 * 5), 
                 ('Klong', ctypes.c_ubyte * 16 * 11)]

  def __init__(self, K):
    _aez.aez_extract(ctypes.pointer(self), K, len(K)); 
  
  def Encipher(self, M, A=[]): 
    (tags, tag_bytes, num_tags) = _format_ad(A)
    C = '0' * len(M)
    _aez.aez_encipher(C, M, len(M),
                      tags, num_tags, tag_bytes,
                      ctypes.pointer(self), 0)
    return C
  
  def Decipher(self, C, A=[]): 
    (tags, tag_bytes, num_tags) = _format_ad(A)
    M = '0' * len(C)
    _aez.aez_encipher(M, C, len(C),
                      tags, num_tags, tag_bytes,
                      ctypes.pointer(self), 1)
    return M

  def Encrypt(self, M, N, A=[], abytes=ABYTES): 
    (tags, tag_bytes, num_tags) = _format_ad(A)
    C = '0' * (len(M) + abytes)
    _aez.aez_encrypt(C, M, len(M), N, len(N), 
                     tags, tag_bytes, num_tags,
                     abytes, ctypes.pointer(self))
    return C
  
  def Decrypt(self, C, N, A=[], abytes=ABYTES):
    if len(C) < abytes: 
      raise AEZError('Ciphertext too short (%d < ABYTES)' % len(C))
    (tags, tag_bytes, num_tags) = _format_ad(A)
    M = '0' * (len(C) - abytes)
    res = _aez.aez_decrypt(M, C, len(C), N, len(N), 
                           tags, tag_bytes, num_tags,
                           abytes, ctypes.pointer(self))
    if res == _aez.get_invalid():
      return None
    return M

  def Hash(self, A=[]):
    (tags, tag_bytes, num_tags) = _format_ad(A)
    H = '0' * 16
    _aez.aez_hash(H, tags, num_tags, tag_bytes, ctypes.pointer(self))
    return H

  def PRF(self, A=[], abytes=ABYTES):
    (tags, tag_bytes, num_tags) = _format_ad(A)
    X = '0' * abytes
    _aez.aez_prf(X, tags, num_tags, tag_bytes, abytes, ctypes.pointer(self))
    return X


class AEZError(Exception): 
  
  # Exception class.  

  def __init__(self, msg):
    self.msg = msg

  def __str__(self):
    return self.msg


def _format_ad(A): 
  
  # Format data vector for encryption. We allow arbitrary datatypes
  # by applying str() to each datum in the list. Beware that these 
  # affect the ciphertext, so the default __str__() for user-defined
  # classes will likely produce a different string on either end 
  # of the communication channel. 

  if len(A) == 0:
    return (None, None, 0)
  
  elif len(A) > MAX_DATA:  
    raise AEZError("Too many data (MAX_DATA=%d)." % MAX_DATA)
  
  else: 
    tags = []; tag_bytes = []
    for tag in A:
      tags.append(str(tag))
      tag_bytes.append(len(tags[-1]))
    _tags = (ctypes.c_char_p * len(tags))()
    _tags[:] = tags
    _tag_bytes = (ctypes.c_uint * len(tag_bytes))()
    _tag_bytes[:] = tag_bytes
    return (_tags, _tag_bytes, len(tags))
