import _aez

ABYTES = 16

class AEZError(Exception): 
  
  def __init__(self, msg):
    self.msg = msg

  def __str__(self):
    return 'AEZError:', self.msg

def data2params(A): 
  if len(A) == 0:
    return (None, None, 0)
  
  elif len(A) > _aez.MAX_DATA:  
    raise AEZError("Too many data (MAX_DATA=%d)" % _aez.MAX_DATA)
  
  else: 
    tags = []; tag_bytes = []
    for tag in A:
      tags.append(str(tag))
      tag_bytes.append(len(tags[-1]))
    return (tags, tag_bytes, len(tags))


class Context:
  
  def __init__(self, K):
    self.x = _aez.new_Context()

  def __del__(self):
    _aez.delete_Context(self.x)

  def Encipher(self, M, A=[]): 
    (tags, tag_bytes, num_tags) = data2params(A)
    C = '0' * len(M)
    _aez.aez_encipher(C, M, len(M),
                      tags, num_tags, tag_bytes,
                      self.x, 0)
    return C
  
  def Encipher(self, C, A=[]): 
    (tags, tag_bytes, num_tags) = data2params(A)
    M = '0' * len(C)
    _aez.aez_encipher(M, C, len(C),
                      tags, num_tags, tag_bytes,
                      self.x, 1)
    return M

  def Encrypt(self, M, N, A=[], abytes=ABYTES): 
    (tags, tag_bytes, num_tags) = data2params(A)
    C = '0' * (len(M) + abytes)
    _aez.aez_encrypt(C, M, len(M), N, len(N), 
                     tags, tag_bytes, num_tags,
                     abytes, self.x)
    return C
  
  def Decrypt(self, C, N, A=[], abytes=ABYTES): 
    (tags, tag_bytes, num_tags) = data2params(A)
    M = '0' * (len(C) - abytes)
    res = _aez.aez_decrypt(M, C, len(C), N, len(N), 
                           tags, tag_bytes, num_tags,
                           abytes, self.x)
    if res == _aez.INVALID:
      return None
    return M

  def Hash(self, A=[]):
    (tags, tag_bytes, num_tags) = data2params(A)
    H = '0' * 16
    _aez.aez_hash(H, tags, num_tags, tag_bytes, self.x)
    return H

  def PRF(self, A=[], abytes=ABYTES):
    (tags, tag_bytes, num_tags) = data2params(A)
    X = '0' * abytes
    _aez.aez_prf(X, tags, num_tags, tag_bytes, abytes, self.x)
    return X

