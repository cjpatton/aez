import _aez

ABYTES = 16

class Context:
  
  def __init__(self, K):
    self.x = _aez.new_Context()

  def __del__(self):
    _aez.delete_Context(self.x)


  def encipher(self, M, A=[]): 
    C = '0' * len(M)
    _aez.aez_encipher(C, M, len(M),
                      None, 0, None,
                      #A, len(A), [len(a) for a in A],
                      self.x, 0)
    return C
  
  def decipher(self, C, A=[]): 
    M = '0' * len(C)
    _aez.aez_encipher(M, C, len(C),
                      None, 0, None,
                      #A, len(A), [len(a) for a in A],
                      self.x, 1)
    return M

  def encrypt(self, M, N, A=[], abytes=ABYTES): 
    C = '0' * (len(M) + abytes)
    _aez.aez_encrypt(C, M, len(M), N, len(N), 
                     None, None, 0,
                     #A, [len(a) for a in A], len(A), 
                     abytes, self.x)
    return C
  
  def decrypt(self, C, N, A=[], abytes=ABYTES): 
    M = '0' * (len(C) - abytes)
    res = _aez.aez_decrypt(M, C, len(C), N, len(N), 
                           None, None, 0,
                           #A, [len(a) for a in A], len(A), 
                           abytes, self.x)
    if res == _aez.INVALID:
      return None
    return M

  def hash(self, A=[]):
    H = '0' * 16
    _aez.aez_hash(H, None, 0, None, 
                  #A, len(A), [len(a) for a in A],
                  self.x)
    return H

  def prf(self, A=[], abytes=ABYTES):
    X = '0' * abytes
    _aez.aez_prf(X, None, 0, None, 
                 #A, len(A), [len(a) for a in A],
                 abytes, self.x)
    return X


def test():
  
  M = "This is an OK message."
  N = "This is a great nonce."
  context = Context('this is a great key')
  C = context.encipher(M, N)
  P = context.decipher(C, N)
  print P 
