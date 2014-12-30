import _aez


abytes = 16
K = "This is the key"
N = "This is the nonce"
M = "I just don't know what to do with myself"
C = '0' * (len(M) + abytes)
P = '0' * len(M)

try:
  context = _aez.new_Context()
  _aez.aez_extract(context, K, len(K))

  _aez.aez_encrypt(C, M, len(M), N, len(N), None, None, 0, abytes, context)
  _aez.aez_decrypt(P, C, len(M) + abytes, N, len(N), None, None, 0, abytes, context)
  print P

finally:
  _aez.delete_Context(context)
