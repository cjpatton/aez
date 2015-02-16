# Testing, testing ... 

import aez

K = "One day we will." 
N = "Things are occuring!"

ABYTES = 7

def xor_bytes(X, Y, n):
  X = X[:n] + (chr(0) * (n - len(X)))
  Y = Y[:n] + (chr(0) * (n - len(Y)))
  return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(X[:n], Y[:n]))

S = chr(0) * 16

for i in range(1024):
  M = chr(0) * i 
  C = aez.Encrypt(M, K, N, abytes=ABYTES)
  P = aez.Decrypt(C, K, N, abytes=ABYTES)
  if P is None or M != P: 
    print 'Uh Oh!'
  S = xor_bytes(S, C, 16)

print S.encode('hex') # Should be '30f73495bd6f5078b076ecf2ade0c131'. 
