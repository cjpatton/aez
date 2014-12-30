from _aez import new_Context, delete_Context
from _aez import aez_extract, aez_hash, aez_prf
from _aez import aez_encipher, aez_encrypt, aez_decrypt

def test():
  abytes = 16
  K = "This is the key"
  N = "This is the nonce"
  M = "I just don't know what to do with myself"
  C = '0' * (len(M) + abytes)
  P = '0' * len(M)

  try:
    context = new_Context()
    aez_extract(context, K, len(K))

    aez_encrypt(C, M, len(M), N, len(N), None, None, 0, abytes, context)
    aez_decrypt(P, C, len(M) + abytes, N, len(N), None, None, 0, abytes, context)
    print P

  finally:
    delete_Context(context)
